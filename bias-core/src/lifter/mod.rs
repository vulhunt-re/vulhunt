use std::borrow::Cow;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::iter::repeat;
use std::mem;
use std::path::Path;
use std::sync::{Arc, RwLock};

use ahash::{AHashMap, AHashSet};
use fugue::bytes::Endian;
use fugue::ir::compiler::CallFixup;
use fugue::ir::convention::{Convention, PrototypeEntry, PrototypeOperand, ReturnAddress};
use fugue::ir::disassembly::{ContextDatabase, IRBuilderArena, ParserContext};
use fugue::ir::error::Error;
use fugue::ir::language::LanguageBuilder;
use fugue::ir::{Address, AddressSpace, AddressSpaceId, AddressValue, LanguageDB, Translator};
use once_cell::sync::Lazy;
use ouroboros::self_referencing;
use thiserror::Error;
use ustr::{Ustr, UstrMap};

use crate::arch::{DefaultArch, ErasedArch};
use crate::ir::insn::{Insn, InsnText};
use crate::ir::{BitSize, FloatKind, Var, VarView};
use crate::kb::operand::Operand;
use crate::region::Memory;

static TRANSLATORS: Lazy<RwLock<AHashMap<String, Arc<Translator>>>> = Lazy::new(Default::default);

#[derive(Clone)]
pub struct LifterBuilder {
    language_db: LanguageDB,
}

#[derive(Debug, Error)]
pub enum LifterBuilderError {
    #[error(transparent)]
    ArchDef(#[from] fugue::arch::ArchDefParseError),
    #[error(transparent)]
    Backend(#[from] fugue::ir::error::Error),
    #[error("deserialisation failure")]
    Deserialisation,
    #[error(transparent)]
    FileIO(#[from] std::io::Error),
    #[error("serialisation failure")]
    Serialisation,
    #[error("unsupported architecture")]
    UnsupportedArch,
    #[error("unsupported architecture calling convention")]
    UnsupportedConv,
}

impl LifterBuilder {
    pub fn new_with(
        path: impl AsRef<Path>,
        ignore_errors: bool,
    ) -> Result<Self, LifterBuilderError> {
        let language_db = LanguageDB::from_directory_with(path, ignore_errors)?;
        Ok(Self { language_db })
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self, LifterBuilderError> {
        Self::new_with(path, true)
    }

    pub fn build_or_cached(
        builder: &LanguageBuilder,
    ) -> Result<Arc<Translator>, LifterBuilderError> {
        if let Some(translator) = TRANSLATORS.read().unwrap().get(builder.language().id()) {
            return Ok(translator.clone());
        }

        let cpath = builder
            .language()
            .sla_file()
            .with_file_name(format!("{}", builder.language().id()).replace(":", "-"))
            .with_extension("bin");

        let translator = if let Ok(cached) = File::open(&cpath) {
            let reader = BufReader::new(cached);

            let mut translator = bincode::deserialize_from::<_, Translator>(reader)
                .map_err(|_| LifterBuilderError::Deserialisation)?;

            if translator.compiler_conventions().is_empty() {
                tracing::trace!(
                    "building translator from {} (deserialised translator is corrupt)",
                    builder.language().sla_file().display()
                );

                builder.build().map_err(LifterBuilderError::from)
            } else {
                tracing::trace!("using cached translator from {}", cpath.display());

                builder.apply_context(&mut translator);

                Ok(translator)
            }
        } else {
            tracing::trace!(
                "building translator from {}",
                builder.language().sla_file().display()
            );

            builder.build().map_err(LifterBuilderError::from)
        }?;

        let translator = Arc::new(translator);

        TRANSLATORS
            .write()
            .unwrap()
            .insert(builder.language().id().to_owned(), translator.clone());

        Ok(translator)
    }

    pub fn build(
        &self,
        tag: impl Into<Cow<'static, str>>,
        convention: impl AsRef<str>,
    ) -> Result<Lifter, LifterBuilderError> {
        let tag = tag.into();
        let convention = convention.as_ref();

        let builder = self
            .language_db
            .lookup_str(&*tag)?
            .ok_or_else(|| LifterBuilderError::UnsupportedArch)?;
        let translator = Self::build_or_cached(&builder)?;

        if let Some(convention) = translator.compiler_conventions().get(&*convention).cloned() {
            Ok(Lifter::new(translator, convention))
        } else {
            Err(LifterBuilderError::UnsupportedConv)
        }
    }

    pub fn build_with(
        &self,
        processor: impl AsRef<str>,
        endian: Endian,
        bits: u32,
        variant: impl AsRef<str>,
        convention: impl AsRef<str>,
    ) -> Result<Lifter, LifterBuilderError> {
        let convention = convention.as_ref();

        let processor = processor.as_ref();
        let variant = variant.as_ref();

        let builder = self
            .language_db
            .lookup(processor, endian, bits as usize, variant)
            .ok_or_else(|| LifterBuilderError::UnsupportedArch)?;
        let translator = Self::build_or_cached(&builder)?;

        if let Some(convention) = translator.compiler_conventions().get(&*convention).cloned() {
            Ok(Lifter::new(translator, convention))
        } else {
            Err(LifterBuilderError::UnsupportedConv)
        }
    }

    pub fn cache_translator(
        &self,
        tag: impl Into<Cow<'static, str>>,
    ) -> Result<(), LifterBuilderError> {
        let tag = tag.into();

        let builder = self
            .language_db
            .lookup_str(&*tag)?
            .ok_or_else(|| LifterBuilderError::UnsupportedArch)?;

        let translator = builder.build_with(false)?;
        let cached = builder
            .language()
            .sla_file()
            .with_file_name(format!("{}", builder.language().id()).replace(":", "-"))
            .with_extension("bin");

        let writer = BufWriter::new(File::create(cached).map_err(LifterBuilderError::from)?);
        bincode::serialize_into(writer, &translator)
            .map_err(|_| LifterBuilderError::Serialisation)?;

        Ok(())
    }

    pub fn build_translator_cache(&self) -> Result<(), LifterBuilderError> {
        let mut processed = AHashSet::new();

        tracing::trace!(
            "language database contains {} entries",
            self.language_db.len()
        );

        for builder in self
            .language_db
            .iter()
            .filter(|builder| builder.language().compiler_specs().len() > 0)
        {
            let cached = builder
                .language()
                .sla_file()
                .with_file_name(format!("{}", builder.language().id()).replace(":", "-"))
                .with_extension("bin");

            if !processed.contains(&cached) {
                let translator = builder.build_with(false)?;

                let conventions = translator
                    .compiler_conventions()
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>();

                tracing::debug!(
                    path = %cached.display(),
                    ?conventions,
                    "creating cached translator"
                );

                let writer =
                    BufWriter::new(File::create(&cached).map_err(LifterBuilderError::from)?);
                bincode::serialize_into(writer, &translator)
                    .map_err(|_| LifterBuilderError::Serialisation)?;

                processed.insert(cached);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PrototypeResolver {
    address_bits: u32,
    global_space: AddressSpaceId,
    register_space: AddressSpaceId,
    return_: ReturnAddress,
}

impl PrototypeResolver {
    pub fn resolve(&self, operand: &PrototypeOperand, stack_base: Address) -> Option<Var> {
        match operand {
            PrototypeOperand::Register { varnode, .. } => Some(Var::new(
                self.register_space,
                varnode.offset(),
                varnode.size() as u32 * 8,
                0,
            )),
            PrototypeOperand::StackRelative(offset) => {
                let addr = stack_base + *offset;

                Some(Var::new(
                    self.global_space,
                    addr.into(),
                    self.address_bits,
                    0,
                ))
            }
            // other case is a join
            _ => None,
        }
    }

    pub fn resolve_register(&self, operand: &PrototypeOperand) -> Option<Var> {
        if let PrototypeOperand::Register { varnode, .. } = operand {
            Some(Var::new(
                self.register_space,
                varnode.offset(),
                varnode.size() as u32 * 8,
                0,
            ))
        } else {
            None
        }
    }

    pub fn resolve_return(&self, stack_base: Address) -> Var {
        match self.return_ {
            ReturnAddress::Register { varnode, .. } => Var::new(
                self.register_space,
                varnode.offset(),
                varnode.size() as u32 * 8,
                0,
            ),
            ReturnAddress::StackRelative { offset, .. } => {
                let addr = stack_base + offset;

                Var::new(self.global_space, addr.into(), self.address_bits, 0)
            }
        }
    }

    pub fn address_bytes(&self) -> usize {
        self.address_bits as usize / 8
    }

    pub fn address_bits(&self) -> u32 {
        self.address_bits
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DefaultPrototype {
    inputs: Vec<PrototypeEntry>,
    outputs: Vec<PrototypeEntry>,
    killed_by_call: Vec<PrototypeOperand>,
    likely_trashed: Vec<PrototypeOperand>,
    unaffected: Vec<PrototypeOperand>,
    extra_pop: u64,
    resolver: PrototypeResolver,
}

impl DefaultPrototype {
    pub fn input_operand(&self, index: usize) -> Option<Operand> {
        self.input_operand_with(index, None)
    }

    pub fn input_operand_with<T>(&self, index: usize, meta: T) -> Option<Operand>
    where
        T: Into<Option<String>>,
    {
        match self.input_with(index, meta)? {
            PrototypeOperand::Register { varnode, .. } => Some(Operand::Register(Var::new0(
                self.resolver.register_space,
                varnode.offset(),
                varnode.size() as u32 * 8,
            ))),
            PrototypeOperand::StackRelative(offset) => {
                Some(Operand::Stack(*offset as _, self.address_bytes()))
            }
            _ => None,
        }
    }

    pub fn output_operand(&self, index: usize) -> Option<Operand> {
        self.output_operand_with(index, None)
    }

    pub fn output_operand_with<T>(&self, index: usize, meta: T) -> Option<Operand>
    where
        T: Into<Option<String>>,
    {
        match self.output_with(index, meta)? {
            PrototypeOperand::Register { varnode, .. } => Some(Operand::Register(Var::new0(
                self.resolver.register_space,
                varnode.offset(),
                varnode.size() as u32 * 8,
            ))),
            PrototypeOperand::StackRelative(offset) => {
                Some(Operand::Stack(*offset as _, self.address_bytes()))
            }
            _ => None,
        }
    }

    pub fn input_with<T>(&self, index: usize, meta: T) -> Option<&PrototypeOperand>
    where
        T: Into<Option<String>>,
    {
        let meta = meta.into();
        self.inputs
            .iter()
            .filter(|mt| *mt.meta_type() == meta)
            .nth(index)
            .map(|t| t.operand())
    }

    pub fn input(&self, index: usize) -> Option<&PrototypeOperand> {
        self.input_with(index, None)
    }

    pub fn resolved_input_with<T>(&self, index: usize, meta: T, stack_base: Address) -> Option<Var>
    where
        T: Into<Option<String>>,
    {
        self.input_with(index, meta)
            .and_then(|t| self.resolver.resolve(t, stack_base))
    }

    pub fn resolved_input(&self, index: usize, stack_base: Address) -> Option<Var> {
        self.resolved_input_with(index, None, stack_base)
    }

    pub fn output_with<T>(&self, index: usize, meta: T) -> Option<&PrototypeOperand>
    where
        T: Into<Option<String>>,
    {
        let meta = meta.into();
        self.outputs
            .iter()
            .filter(|mt| *mt.meta_type() == meta)
            .nth(index)
            .map(|t| t.operand())
    }

    pub fn output(&self, index: usize) -> Option<&PrototypeOperand> {
        self.output_with(index, None)
    }

    pub fn resolved_output_with<T>(&self, index: usize, meta: T, stack_base: Address) -> Option<Var>
    where
        T: Into<Option<String>>,
    {
        self.output_with(index, meta)
            .and_then(|t| self.resolver.resolve(t, stack_base))
    }

    pub fn resolved_output(&self, index: usize, stack_base: Address) -> Option<Var> {
        self.resolved_output_with(index, None, stack_base)
    }

    pub fn output_registers<'a>(&'a self) -> impl Iterator<Item = Var> + 'a {
        self.outputs
            .iter()
            .map(|t| t.operand())
            .filter_map(|var| self.resolver.resolve_register(var))
    }

    pub fn likely_killed_registers<'a>(&'a self) -> impl Iterator<Item = Var> + 'a {
        self.likely_trashed
            .iter()
            .filter_map(|var| self.resolver.resolve_register(var))
    }

    pub fn killed_registers<'a>(&'a self) -> impl Iterator<Item = Var> + 'a {
        self.killed_by_call
            .iter()
            .filter_map(|var| self.resolver.resolve_register(var))
    }

    pub fn unaffected_registers<'a>(&'a self) -> impl Iterator<Item = Var> + 'a {
        self.unaffected
            .iter()
            .filter_map(|var| self.resolver.resolve_register(var))
    }

    pub fn extra_pop(&self) -> u64 {
        self.extra_pop
    }

    pub fn address_bytes(&self) -> usize {
        self.resolver.address_bytes()
    }

    pub fn address_bits(&self) -> u32 {
        self.resolver.address_bits()
    }

    pub fn resolver(&self) -> &PrototypeResolver {
        &self.resolver
    }

    pub fn into_resolver(self) -> PrototypeResolver {
        self.resolver
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Lifter {
    arch: Box<dyn ErasedArch>,
    translator: Arc<Translator>,
    convention: Convention,
    register_space: AddressSpaceId,
    register_map: Arc<VarView>,

    float_kinds: AHashMap<u32, FloatKind>,

    global_space: AddressSpaceId,
    //stack_space: AddressSpaceId,
    temporary_space: AddressSpaceId,

    program_counter: Var,
    stack_pointer: Var,
    frame_pointer: Option<Var>,

    call_fixups: UstrMap<usize>,
}

#[derive(Debug, Error)]
pub enum LifterError {
    #[error(transparent)]
    Disassembly(#[from] fugue::ir::error::Error),
}

impl Lifter {
    pub fn new<T>(translator: T, convention: Convention) -> Self
    where
        T: Into<Arc<Translator>>,
    {
        Self::new_with(translator, convention, Box::new(DefaultArch))
    }

    pub fn new_with<T>(translator: T, convention: Convention, arch: Box<dyn ErasedArch>) -> Self
    where
        T: Into<Arc<Translator>>,
    {
        let translator = translator.into();
        let register_map = VarView::registers(&*translator);
        let register_space = register_map.space();
        let default_space = translator.manager().default_space();
        let unique_space = translator.manager().unique_space();

        /*
        let global_space = translator
            .manager_mut()
            .add_space_like("global", &*default_space)
            .id();
        let stack_space = translator
            .manager_mut()
            .add_space_like("stack", &*default_space)
            .id();
        let temporary_space = translator
            .manager_mut()
            .add_space_like("tmp", &*default_space)
            .id();
        */

        let program_counter = Var::new(
            register_space,
            translator.program_counter().offset(),
            translator.program_counter().size() as u32 * 8,
            0,
        );

        let conv_sp = convention.stack_pointer();
        let stack_pointer = Var::new(
            register_space,
            conv_sp.varnode().offset(),
            conv_sp.varnode().size() as u32 * 8,
            0,
        );

        let frame_pointer = arch.frame_pointer(&translator);

        let float_kinds = translator
            .float_formats()
            .iter()
            .map(|(sz, fmt)| (*sz as u32, (**fmt).clone().into()))
            .collect();

        let call_fixups = convention
            .call_fixups()
            .iter()
            .enumerate()
            .flat_map(|(index, fixup)| {
                fixup
                    .targets()
                    .iter()
                    .map(|s| Ustr::from(s))
                    .zip(repeat(index))
            })
            .collect();

        Self {
            arch,
            translator,
            convention,
            call_fixups,
            register_space,
            register_map: Arc::new(register_map),
            float_kinds,
            global_space: default_space.id(),
            //stack_space,
            temporary_space: unique_space.id(),
            program_counter,
            stack_pointer,
            frame_pointer,
        }
    }

    pub fn arch(&self) -> &Box<dyn ErasedArch> {
        &self.arch
    }

    pub fn endian(&self) -> Endian {
        if self.translator.is_big_endian() {
            Endian::Big
        } else {
            Endian::Little
        }
    }

    pub fn program_counter(&self) -> Var {
        self.program_counter
    }

    pub fn stack_pointer(&self) -> Var {
        self.stack_pointer
    }

    pub fn frame_pointer(&self) -> Option<Var> {
        self.frame_pointer
    }

    pub fn address_bits(&self) -> u32 {
        self.program_counter.nbits()
    }

    pub fn address_bytes(&self) -> usize {
        self.program_counter.nbits() as usize / 8
    }

    pub fn address_value(&self, address: impl Into<Address>) -> AddressValue {
        self.translator.address(address.into().offset())
    }

    pub fn float_kind(&self, bits: u32) -> Option<&FloatKind> {
        self.float_kinds.get(&bits)
    }

    pub fn float_kinds(&self) -> &AHashMap<u32, FloatKind> {
        &self.float_kinds
    }

    pub fn call_fixup_for(&self, nm: impl AsRef<str>) -> Option<&CallFixup> {
        self.convention.call_fixups().get(
            self.call_fixups
                .get(&Ustr::from_existing(nm.as_ref())?)
                .copied()?,
        )
    }

    pub fn convention(&self) -> &Convention {
        &self.convention
    }

    pub fn context(&self) -> ContextDatabase {
        self.translator.context_database()
    }

    pub fn irb(&self, size: usize) -> IRBuilderArena {
        IRBuilderArena::with_capacity(size)
    }

    pub fn default_prototype(&self) -> DefaultPrototype {
        let prototype = self.convention().default_prototype();
        DefaultPrototype {
            inputs: prototype.inputs().to_vec(),
            outputs: prototype.outputs().to_vec(),
            unaffected: prototype.unaffected().to_vec(),
            killed_by_call: prototype.killed_by_call().to_vec(),
            likely_trashed: prototype.likely_trashed().to_vec(),
            extra_pop: prototype.extra_pop(),
            resolver: self.prototype_resolver(),
        }
    }

    pub fn prototype_resolver(&self) -> PrototypeResolver {
        PrototypeResolver {
            address_bits: self.address_bits(),
            global_space: self.global_space_id(),
            register_space: self.register_space_id(),
            return_: self.convention().return_address().clone(),
        }
    }

    pub fn prototype_register_var(&self, operand: &PrototypeOperand) -> Option<Var> {
        if let PrototypeOperand::Register { varnode, .. } = operand {
            Some(Var::new(
                self.register_space(),
                varnode.offset(),
                varnode.size() as u32 * 8,
                0,
            ))
        } else {
            None
        }
    }

    pub fn prototype_var(&self, operand: &PrototypeOperand, stack_base: Address) -> Option<Var> {
        match operand {
            PrototypeOperand::Register { varnode, .. } => Some(Var::new(
                self.register_space(),
                varnode.offset(),
                varnode.size() as u32 * 8,
                0,
            )),
            PrototypeOperand::StackRelative(offset) => {
                let addr = stack_base + *offset;
                let addr_bits = self.global_space().address_size() as u32 * 8;

                Some(Var::new(self.global_space(), addr.into(), addr_bits, 0))
            }
            // other case is a join
            _ => None,
        }
    }

    pub fn global_space(&self) -> &AddressSpace {
        self.translator().manager().space_by_id(self.global_space)
    }

    pub fn global_space_id(&self) -> AddressSpaceId {
        self.global_space
    }

    pub fn register_map(&self) -> &Arc<VarView> {
        &self.register_map
    }

    pub fn register_space(&self) -> &AddressSpace {
        self.translator().manager().space_by_id(self.register_space)
    }

    pub fn register_space_id(&self) -> AddressSpaceId {
        self.register_space
    }

    pub fn register_var(&self, name: &str) -> Option<Var> {
        self.translator
            .register_by_name(name)
            .map(|vnd| Var::new0(vnd.space(), vnd.offset(), vnd.size() as u32 * 8))
    }

    /*
    pub fn stack_space(&self) -> &AddressSpace {
        self.translator().manager().space_by_id(self.stack_space)
    }

    pub fn stack_space_id(&self) -> AddressSpaceId {
        self.stack_space
    }
    */

    pub fn temporary_space(&self) -> &AddressSpace {
        self.translator()
            .manager()
            .space_by_id(self.temporary_space)
    }

    pub fn temporary_space_id(&self) -> AddressSpaceId {
        self.temporary_space
    }

    pub fn translator(&self) -> &Translator {
        &self.translator
    }

    pub fn translator_ref(&self) -> Arc<Translator> {
        self.translator.clone()
    }

    pub fn translator_mut(&mut self) -> &mut Translator {
        Arc::make_mut(&mut self.translator)
    }
}

#[self_referencing]
struct DisassemblerInner<'a> {
    lifter: &'a Lifter,
    irb: IRBuilderArena,
    ctx: ContextDatabase,
    #[borrows(irb)]
    #[covariant]
    pctx: ParserContext<'a, 'this>,
}

#[repr(transparent)]
pub struct Disassembler<'a>(DisassemblerInner<'a>);

impl<'a> Clone for Disassembler<'a> {
    fn clone(&self) -> Self {
        // we recreate based on the current context database
        let lifter = *self.0.borrow_lifter();
        let ctx = self.0.borrow_ctx().clone();

        Self::new_with(lifter, ctx)
    }

    fn clone_from(&mut self, source: &Self) {
        // we only need to copy the context database
        let sctx = source.0.borrow_ctx().clone();
        self.0.with_ctx_mut(|ctx| *ctx = sctx);
    }
}

impl<'a> Disassembler<'a> {
    pub fn new(lifter: &'a Lifter) -> Self {
        let ctx = lifter.context();
        Self::new_with(lifter, ctx)
    }

    pub fn new_with(lifter: &'a Lifter, ctx: ContextDatabase) -> Self {
        let irb = lifter.irb(4096);

        Self(DisassemblerInner::new(lifter, irb, ctx, |irb| {
            ParserContext::empty(irb, lifter.translator().manager())
        }))
    }

    pub fn disassemble(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
    ) -> Result<InsnText, Error> {
        self.0.with_mut(|slf| {
            Insn::disassemble(slf.lifter, slf.irb, slf.ctx, slf.pctx, address, bytes)
        })
    }

    pub fn disassemble_at(
        &mut self,
        address: impl Into<Address>,
        memory: &Memory,
    ) -> Result<InsnText, Error> {
        let address = address.into();
        let Ok(bytes) = memory.view_bytes_from(address) else {
            return Err(Error::Disassembly(
                fugue::ir::disassembly::Error::Invariant("unmapped address".into()),
            ))?;
        };
        self.disassemble(address, bytes)
    }

    pub fn reset(&mut self) {
        let lifter = *self.0.borrow_lifter();
        let mut ctx = lifter.context();

        // we preserve the old context database
        self.0.with_ctx_mut(|old_ctx| mem::swap(old_ctx, &mut ctx));

        *self = Self::new_with(lifter, ctx);
    }
}

pub trait TranslatorExt {
    fn register_var(&self, name: &str) -> Option<Var>;
}

impl TranslatorExt for Translator {
    fn register_var(&self, name: &str) -> Option<Var> {
        self.register_by_name(name)
            .map(|vnd| Var::new0(vnd.space(), vnd.offset(), vnd.size() as u32 * 8))
    }
}
