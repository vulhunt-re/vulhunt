use std::borrow::Cow;
use std::ops::Deref;

use bias_core::any::ProvidesStaticType;
use bias_core::arch::ContextUpdates;
use bias_core::arch::ErasedArch;
use bias_core::arch::arm::TMODE_CONTEXT;
use bias_core::kb::function::FunctionInfo;
use bias_core::kb::{Uuid, uuid};
use bias_core::lifter::Lifter;
use bias_core::loader::elf::ELFExternalSymbols;
use bias_core::loader::{
    LoadedBinary, LoaderAttribute, LoaderBlock, LoaderBytes, LoaderContainer, LoaderFunction,
    LoaderRegion,
};
use bias_core::prelude::Address;

use bias_core::loader::elf::ELFExternalSymbolsRef;
use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::rc::Ref;
use binaryninja::section::Semantics;
use smallvec::SmallVec;

use crate::util::{convert_endian, is_thumb_mode, normalise_arm_address};

#[derive(ProvidesStaticType)]
pub(crate) struct BinaryViewRef(pub(crate) Ref<BinaryView>);

impl LoaderAttribute<'_> for BinaryViewRef {
    const UUID: Uuid = uuid("BFB226A9-E077-4D38-805A-3C6C417D2838");
}

impl Deref for BinaryViewRef {
    type Target = Ref<BinaryView>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct BNDBLoadedBinary<'a> {
    view: Ref<BinaryView>,
    bytes: &'a [u8],
    externs: ELFExternalSymbols,
    arch: Box<dyn ErasedArch>,
}

unsafe impl Send for BNDBLoadedBinary<'_> {}
unsafe impl Sync for BNDBLoadedBinary<'_> {}

impl<'a> BNDBLoadedBinary<'a> {
    pub fn new(view: Ref<BinaryView>, bytes: &'a [u8], lifter: &Lifter) -> Self {
        let arch = lifter.arch().to_owned();
        let template = arch.external_thunk_template(lifter.translator());

        let sections = view.sections();
        let extern_section = sections
            .iter()
            .find(|s| s.name().to_string_lossy() == ".extern");

        let extern_base = extern_section
            .as_ref()
            .map(|s| Address::from(s.start()))
            .unwrap_or_else(|| {
                let addr_bytes = view.address_size() as u64;
                let max_end = sections
                    .iter()
                    .map(|s| s.start() + s.len() as u64)
                    .max()
                    .unwrap_or(0);
                Address::from((max_end + addr_bytes - 1) & !(addr_bytes - 1))
            });

        let mut externs = ELFExternalSymbols::with_base(extern_base, template);

        if let Some(section) = extern_section {
            let start = section.start();
            let end = start + section.len() as u64;

            let symbols = view.symbols();
            let mut extern_syms = symbols
                .iter()
                .filter(|sym| {
                    let addr = sym.address();
                    addr >= start && addr < end
                })
                .collect::<Vec<_>>();

            extern_syms.sort_by_key(|sym| sym.address());

            for (idx, sym) in extern_syms.into_iter().enumerate() {
                let addr = Address::from(sym.address());
                let name = bias_core::kb::ustr(&sym.full_name().to_string_lossy());
                externs.insert(idx, addr, Some(name));
            }
        }

        Self {
            view,
            bytes,
            externs,
            arch,
        }
    }

    pub fn view(&self) -> &BinaryView {
        &self.view
    }

    pub fn externs(&self) -> &ELFExternalSymbols {
        &self.externs
    }

    pub(crate) fn is_arm(&self) -> bool {
        self.arch.id() == bias_core::arch::arm::ARCH_ARM
    }

    fn extern_region(&self) -> Option<LoaderRegion<'static>> {
        if self.externs.is_empty() {
            return None;
        }

        let template = self.externs.template();
        let stub_size = self.view.address_size().max(self.externs.template().len());
        let extern_size = self.externs.len() * stub_size;
        let range = self.externs.base()..(self.externs.base() + extern_size);

        let mut mapping = Vec::with_capacity(extern_size);
        for _ in 0..self.externs.len() {
            mapping.extend_from_slice(template.bytes());
            if template.len() < stub_size {
                mapping.resize(mapping.len() + (stub_size - template.len()), 0);
            }
        }

        Some(LoaderRegion {
            name: Some(".extern".into()),
            code: true,
            read_only: true,
            uninitialised: None,
            bounds: range,
            endian: convert_endian(self.view.default_endianness()),
            bytes: Cow::Owned(mapping),
        })
    }
}

impl<'data> LoadedBinary for BNDBLoadedBinary<'data> {
    fn for_each_region<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
        for section in self.view.sections().iter() {
            let start = section.start();
            let len = section.len() as u64;

            if let Ok(buf) = self.view.read_buffer(start, len as usize) {
                let bytes = buf.get_data();
                let semantics = section.semantics();

                f(&LoaderRegion {
                    name: Some(section.name().to_string_lossy().into_owned().into()),
                    code: semantics == Semantics::ReadOnlyCode,
                    read_only: matches!(
                        semantics,
                        Semantics::ReadOnlyData | Semantics::ReadOnlyCode
                    ),
                    uninitialised: None,
                    bounds: Address::from(start)..Address::from(start + len),
                    endian: convert_endian(self.view.default_endianness()),
                    bytes: Cow::Owned(bytes.to_owned()),
                });
            }
        }

        if let Some(externs) = self.extern_region() {
            f(&externs);
        }
    }

    fn for_each_function<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderFunction<'a>),
    {
        let is_arm = self.is_arm();

        for func in self.view.functions().iter() {
            let raw_addr = func.start();
            let name = func.symbol().full_name();

            let context = if is_arm {
                ContextUpdates::single(TMODE_CONTEXT, is_thumb_mode(raw_addr) as u32)
            } else {
                ContextUpdates::default()
            };

            let entry = Address::from(normalise_arm_address(raw_addr, is_arm));
            let name = name.to_string_lossy();

            f(&LoaderFunction {
                entry,
                name: (!name.is_empty() && !name.starts_with("sub_"))
                    .then(|| Cow::Owned(name.into_owned())),
                context,
                properties: Default::default(),
            });
        }

        let context = self.externs.template().context();
        for (entry, sym) in self.externs.iter() {
            f(&LoaderFunction {
                entry,
                name: Some(Cow::Owned(sym.as_str().to_owned())),
                context: context.clone(),
                properties: FunctionInfo::EXTERN,
            });
        }
    }

    fn for_each_block<F>(&self, mut f: F)
    where
        F: FnMut(&LoaderBlock),
    {
        for func in self.view.functions().iter() {
            for block in func.basic_blocks().iter() {
                let start = block.start();
                let end = block.end();

                let mut targets = SmallVec::<[Address; 2]>::new();
                for edge in block.outgoing_edges().iter() {
                    targets.push(Address::from(edge.target.start()));
                }

                f(&LoaderBlock {
                    bounds: Address::from(start)..Address::from(end),
                    targets,
                });
            }
        }
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        LoaderBytes::Borrowed(self.bytes)
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        let mut c = LoaderContainer::new(self.bytes);

        c.set_attr(BinaryViewRef(self.view.clone()));
        c.set_attr(LoaderBytes::Borrowed(self.bytes));
        c.set_attr(ELFExternalSymbolsRef(&self.externs));

        c
    }

    fn entry_point(&self) -> Option<Address> {
        let entry = self.view.entry_point();
        if entry == 0 {
            None
        } else {
            Some(Address::from(entry))
        }
    }
}
