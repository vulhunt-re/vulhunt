use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::iter::repeat;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use flate2::write::GzEncoder;
use fugue::arch::{ArchDefParseError, ArchitectureDef};
use fugue::bytes::Endian;
use fugue::lifter::dynamic::{Language as DynamicLanguage, LanguageBuildError};
use fugue::lifter::runtime::convention::{
    CallFixup, Convention, Prototype, PrototypeEntry, PrototypeOperand, ReturnAddress,
};
use fugue::lifter::runtime::language::{Language, LanguageId, LanguageParseError};
use fugue::lifter::runtime::ContextDatabase;
use fugue::lifter::{LanguageLoadError, LiftingContext};
use fugue::sleigh::language::language::{LanguageDefBuilder, LanguageError};
use fugue::sleigh::language::spaces::AddressSpaceId;
use fugue::sleigh::language::LanguageDB;
use thiserror::Error;
use ustr::{Ustr, UstrMap};

use crate::arch::{DefaultArch, ErasedArch};
use crate::ir::insn::{Insn, InsnText};
use crate::ir::{Address, BitSize, FloatKind, Var, VarView};
use crate::kb::operand::Operand;
use crate::region::Memory;

#[derive(Clone)]
pub struct LifterBuilder {
    language_db: LanguageDB,
}

#[derive(Debug, Error)]
pub enum LifterBuilderError {
    #[error(transparent)]
    ArchDef(#[from] ArchDefParseError),
    #[error("cannot write language package `{0}`: {1}")]
    FileIO(PathBuf, io::Error),
    #[error(transparent)]
    LanguageBuild(#[from] LanguageBuildError),
    #[error(transparent)]
    LanguageDB(#[from] LanguageError),
    #[error("invalid language identifier `{0}`: {1}")]
    LanguageId(String, LanguageParseError),
    #[error(transparent)]
    LanguageLoad(#[from] LanguageLoadError),
    #[error("calling convention `{0}` has no default prototype")]
    MissingDefaultPrototype(&'static str),
    #[error("cannot serialise language package `{0}`: {1}")]
    Serialisation(PathBuf, rkyv::rancor::Error),
    #[error("unsupported architecture")]
    UnsupportedArch,
    #[error("unsupported architecture calling convention")]
    UnsupportedConv,
}

impl LifterBuilderError {
    fn file_io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::FileIO(path.into(), source)
    }

    fn language_id(id: impl Into<String>, source: LanguageParseError) -> Self {
        Self::LanguageId(id.into(), source)
    }

    fn serialisation(path: impl Into<PathBuf>, source: rkyv::rancor::Error) -> Self {
        Self::Serialisation(path.into(), source)
    }
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

    pub fn language_db(&self) -> &LanguageDB {
        &self.language_db
    }

    fn language_package_path(builder: &LanguageDefBuilder) -> PathBuf {
        let language = builder.language();
        language
            .sla_file()
            .with_file_name(language.id().replace(':', "-"))
            .with_extension("flift")
    }

    pub fn language(builder: &LanguageDefBuilder) -> Result<&'static Language, LifterBuilderError> {
        let language = builder.language();
        let id = language
            .id()
            .parse::<LanguageId>()
            .map_err(|e| LifterBuilderError::language_id(language.id(), e))?;

        if let Some(installed) = Language::lookup(&id) {
            return Ok(installed);
        }

        let package = Self::language_package_path(builder);
        if package.is_file() {
            tracing::trace!("loading language from {}", package.display());
            return Ok(Language::from_file(&package)?);
        }

        let sla = language.sla_file();
        tracing::trace!("building language from {}", sla.display());

        let specs = sla.parent().unwrap_or_else(|| Path::new("."));
        Ok(Language::from_sleigh_with_sla(specs, language.id(), sla)?)
    }

    pub fn build(
        &self,
        tag: impl Into<Cow<'static, str>>,
        convention: impl AsRef<str>,
    ) -> Result<Lifter, LifterBuilderError> {
        let tag = tag.into();
        let builder = self
            .language_db
            .lookup_str(&*tag)?
            .ok_or(LifterBuilderError::UnsupportedArch)?;

        Lifter::from_language(Self::language(&builder)?, convention.as_ref())
    }

    pub fn build_with(
        &self,
        processor: impl AsRef<str>,
        endian: Endian,
        bits: u32,
        variant: impl AsRef<str>,
        convention: impl AsRef<str>,
    ) -> Result<Lifter, LifterBuilderError> {
        let builder = self
            .language_db
            .lookup(processor.as_ref(), endian, bits, variant.as_ref())
            .ok_or(LifterBuilderError::UnsupportedArch)?;

        Lifter::from_language(Self::language(&builder)?, convention.as_ref())
    }

    pub fn build_language_cache(&self) -> Result<(), LifterBuilderError> {
        let mut processed = AHashSet::new();

        tracing::trace!(
            "language database contains {} entries",
            self.language_db.len()
        );

        for builder in self
            .language_db
            .iter()
            .filter(|builder| !builder.language().compiler_defs().is_empty())
        {
            let package = Self::language_package_path(&builder);
            if !processed.insert(package.clone()) {
                continue;
            }

            let language = builder.language();
            let sla = language.sla_file();
            let specs = sla.parent().unwrap_or_else(|| Path::new("."));
            let dynamic = DynamicLanguage::build_with_sla(specs, language.id(), sla)?;

            tracing::debug!(path = %package.display(), "creating language package");

            let bytes = dynamic
                .to_bytes()
                .map_err(|e| LifterBuilderError::serialisation(&package, e))?;

            let file =
                File::create(&package).map_err(|e| LifterBuilderError::file_io(&package, e))?;
            let mut writer = GzEncoder::new(BufWriter::new(file), Default::default());
            writer
                .write_all(bytes.as_ref())
                .and_then(|_| writer.finish().map(|_| ()))
                .map_err(|e| LifterBuilderError::file_io(&package, e))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PrototypeResolver {
    address_bits: u32,
    global_space: AddressSpaceId,
    register_space: AddressSpaceId,
    return_: Option<ReturnAddress>,
}

impl PrototypeResolver {
    fn register(&self, offset: u64, size: usize) -> Var {
        Var::new(self.register_space, offset, size as u32 * 8, 0)
    }

    fn stack(&self, stack_base: Address, offset: u64) -> Var {
        let addr = stack_base + offset;
        Var::new(self.global_space, addr.into(), self.address_bits, 0)
    }

    pub fn resolve(&self, operand: &PrototypeOperand, stack_base: Address) -> Option<Var> {
        match operand {
            PrototypeOperand::Register(varnode) => {
                Some(self.register(varnode.offset(), varnode.size()))
            }
            PrototypeOperand::StackRelative { offset, .. } => Some(self.stack(stack_base, *offset)),
            _ => None,
        }
    }

    pub fn resolve_register(&self, operand: &PrototypeOperand) -> Option<Var> {
        if let PrototypeOperand::Register(varnode) = operand {
            Some(self.register(varnode.offset(), varnode.size()))
        } else {
            None
        }
    }

    pub fn resolve_return(&self, stack_base: Address) -> Option<Var> {
        match self.return_? {
            ReturnAddress::Register(varnode) => {
                Some(self.register(varnode.offset(), varnode.size()))
            }
            ReturnAddress::StackRelative { offset, .. } => Some(self.stack(stack_base, offset)),
        }
    }

    pub fn address_bytes(&self) -> usize {
        self.address_bits as usize / 8
    }

    pub fn address_bits(&self) -> u32 {
        self.address_bits
    }
}

#[derive(Debug, Clone)]
pub struct DefaultPrototype {
    prototype: &'static Prototype,
    resolver: PrototypeResolver,
}

impl DefaultPrototype {
    pub fn input_operand(&self, index: usize) -> Option<Operand> {
        self.input_operand_with(index, None)
    }

    pub fn input_operand_with<'a>(
        &self,
        index: usize,
        meta: impl Into<Option<&'a str>>,
    ) -> Option<Operand> {
        self.operand(self.input_with(index, meta)?)
    }

    pub fn output_operand(&self, index: usize) -> Option<Operand> {
        self.output_operand_with(index, None)
    }

    pub fn output_operand_with<'a>(
        &self,
        index: usize,
        meta: impl Into<Option<&'a str>>,
    ) -> Option<Operand> {
        self.operand(self.output_with(index, meta)?)
    }

    fn operand(&self, operand: &PrototypeOperand) -> Option<Operand> {
        match operand {
            PrototypeOperand::Register(varnode) => Some(Operand::Register(Var::new0(
                self.resolver.register_space,
                varnode.offset(),
                varnode.size() as u32 * 8,
            ))),
            PrototypeOperand::StackRelative { offset, .. } => {
                Some(Operand::Stack(*offset as _, self.address_bytes()))
            }
            _ => None,
        }
    }

    fn entry_with<'a>(
        entries: &'static [PrototypeEntry],
        index: usize,
        meta: impl Into<Option<&'a str>>,
    ) -> Option<&'static PrototypeOperand> {
        let meta = meta.into();
        entries
            .iter()
            .filter(|entry| entry.meta_type() == meta)
            .nth(index)
            .map(PrototypeEntry::operand)
    }

    pub fn input_with<'a>(
        &self,
        index: usize,
        meta: impl Into<Option<&'a str>>,
    ) -> Option<&'static PrototypeOperand> {
        Self::entry_with(self.prototype.inputs(), index, meta)
    }

    pub fn input(&self, index: usize) -> Option<&'static PrototypeOperand> {
        self.input_with(index, None)
    }

    pub fn resolved_input_with<'a>(
        &self,
        index: usize,
        meta: impl Into<Option<&'a str>>,
        stack_base: Address,
    ) -> Option<Var> {
        self.input_with(index, meta)
            .and_then(|operand| self.resolver.resolve(operand, stack_base))
    }

    pub fn resolved_input(&self, index: usize, stack_base: Address) -> Option<Var> {
        self.resolved_input_with(index, None, stack_base)
    }

    pub fn output_with<'a>(
        &self,
        index: usize,
        meta: impl Into<Option<&'a str>>,
    ) -> Option<&'static PrototypeOperand> {
        Self::entry_with(self.prototype.outputs(), index, meta)
    }

    pub fn output(&self, index: usize) -> Option<&'static PrototypeOperand> {
        self.output_with(index, None)
    }

    pub fn resolved_output_with<'a>(
        &self,
        index: usize,
        meta: impl Into<Option<&'a str>>,
        stack_base: Address,
    ) -> Option<Var> {
        self.output_with(index, meta)
            .and_then(|operand| self.resolver.resolve(operand, stack_base))
    }

    pub fn resolved_output(&self, index: usize, stack_base: Address) -> Option<Var> {
        self.resolved_output_with(index, None, stack_base)
    }

    pub fn output_registers(&self) -> impl Iterator<Item = Var> + '_ {
        self.prototype
            .outputs()
            .iter()
            .filter_map(|entry| self.resolver.resolve_register(entry.operand()))
    }

    pub fn likely_killed_registers(&self) -> impl Iterator<Item = Var> + '_ {
        self.prototype
            .likely_trashed()
            .iter()
            .filter_map(|operand| self.resolver.resolve_register(operand))
    }

    pub fn killed_registers(&self) -> impl Iterator<Item = Var> + '_ {
        self.prototype
            .killed_by_call()
            .iter()
            .filter_map(|operand| self.resolver.resolve_register(operand))
    }

    pub fn unaffected_registers(&self) -> impl Iterator<Item = Var> + '_ {
        self.prototype
            .unaffected()
            .iter()
            .filter_map(|operand| self.resolver.resolve_register(operand))
    }

    pub fn extra_pop(&self) -> Option<u64> {
        self.prototype.extra_pop()
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

#[derive(Clone)]
pub struct Lifter {
    arch: Box<dyn ErasedArch>,
    language: &'static Language,
    convention: &'static Convention,
    default_prototype: &'static Prototype,
    register_map: Arc<VarView>,

    float_kinds: AHashMap<u32, FloatKind>,

    program_counter: Var,
    stack_pointer: Var,
    frame_pointer: Option<Var>,

    call_fixups: UstrMap<usize>,
}

#[derive(Debug, Error)]
pub enum LifterError {
    #[error("cannot disassemble instruction at {0}")]
    Disassembly(Address),
    #[error("cannot format instruction at {0}")]
    Format(Address),
    #[error("instruction at {address} is not aligned to {alignment} bytes")]
    IncorrectAlignment { address: Address, alignment: usize },
    #[error("cannot lift instruction at {0}")]
    Lift(Address),
    #[error("address {0} is not mapped")]
    UnmappedAddress(Address),
}

impl Lifter {
    pub fn from_language(
        language: &'static Language,
        convention: &str,
    ) -> Result<Self, LifterBuilderError> {
        let convention = language
            .convention(convention)
            .ok_or(LifterBuilderError::UnsupportedConv)?;
        Self::new(language, convention)
    }

    pub fn new(
        language: &'static Language,
        convention: &'static Convention,
    ) -> Result<Self, LifterBuilderError> {
        Self::new_with(language, convention, Box::new(DefaultArch))
    }

    pub fn new_with(
        language: &'static Language,
        convention: &'static Convention,
        arch: Box<dyn ErasedArch>,
    ) -> Result<Self, LifterBuilderError> {
        let default_prototype =
            convention
                .default_prototype()
                .ok_or(LifterBuilderError::MissingDefaultPrototype(
                    convention.name(),
                ))?;

        let register_map = VarView::registers(language);
        let register_space = language.space_id(language.register_space());

        let program_counter = language.program_counter();
        let program_counter = Var::new(
            register_space,
            program_counter.offset(),
            program_counter.size() as u32 * 8,
            0,
        );

        let stack_pointer = convention.stack_pointer();
        let stack_pointer = Var::new(
            register_space,
            stack_pointer.offset(),
            stack_pointer.size() as u32 * 8,
            0,
        );

        let frame_pointer = arch.frame_pointer(language);

        let float_kinds = language
            .float_formats()
            .iter()
            .map(|format| (format.bits() as u32, format.clone().into()))
            .collect();

        let call_fixups = convention
            .call_fixups()
            .iter()
            .enumerate()
            .flat_map(|(index, fixup)| {
                fixup
                    .targets()
                    .iter()
                    .map(|target| Ustr::from(target))
                    .zip(repeat(index))
            })
            .collect();

        Ok(Self {
            arch,
            language,
            convention,
            default_prototype,
            call_fixups,
            register_map: Arc::new(register_map),
            float_kinds,
            program_counter,
            stack_pointer,
            frame_pointer,
        })
    }

    pub fn arch(&self) -> &Box<dyn ErasedArch> {
        &self.arch
    }

    pub fn endian(&self) -> Endian {
        self.language.endian()
    }

    pub fn architecture(&self) -> ArchitectureDef {
        ArchitectureDef::new(
            self.language.processor(),
            self.endian(),
            self.language.bits(),
            self.language.variant(),
        )
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

    pub fn float_kind(&self, bits: u32) -> Option<&FloatKind> {
        self.float_kinds.get(&bits)
    }

    pub fn float_kinds(&self) -> &AHashMap<u32, FloatKind> {
        &self.float_kinds
    }

    pub fn call_fixup_for(&self, name: impl AsRef<str>) -> Option<&'static CallFixup> {
        let index = self
            .call_fixups
            .get(&Ustr::from_existing(name.as_ref())?)
            .copied()?;
        self.convention.call_fixups().get(index)
    }

    pub fn convention(&self) -> &'static Convention {
        self.convention
    }

    pub fn context(&self) -> ContextDatabase {
        self.language.default_context()
    }

    pub fn lifting_context(&self) -> LiftingContext {
        self.lifting_context_with(self.context())
    }

    pub fn lifting_context_with(&self, context: ContextDatabase) -> LiftingContext {
        LiftingContext::new(self.language, 2, context, self.language.unique_mask())
    }

    pub fn default_prototype(&self) -> DefaultPrototype {
        DefaultPrototype {
            prototype: self.default_prototype,
            resolver: self.prototype_resolver(),
        }
    }

    pub fn prototype_resolver(&self) -> PrototypeResolver {
        PrototypeResolver {
            address_bits: self.address_bits(),
            global_space: self.global_space_id(),
            register_space: self.register_space_id(),
            return_: self.convention.return_address(),
        }
    }

    pub fn prototype_register_var(&self, operand: &PrototypeOperand) -> Option<Var> {
        self.prototype_resolver().resolve_register(operand)
    }

    pub fn prototype_var(&self, operand: &PrototypeOperand, stack_base: Address) -> Option<Var> {
        match operand {
            PrototypeOperand::Register(varnode) => Some(Var::new(
                self.register_space_id(),
                varnode.offset(),
                varnode.size() as u32 * 8,
                0,
            )),
            PrototypeOperand::StackRelative { offset, .. } => {
                let addr = stack_base + *offset;
                let addr_bits = self.language.address_size() as u32 * 8;

                Some(Var::new(self.global_space_id(), addr.into(), addr_bits, 0))
            }
            _ => None,
        }
    }

    pub fn global_space_id(&self) -> AddressSpaceId {
        self.language.space_id(self.language.default_space())
    }

    pub fn register_map(&self) -> &Arc<VarView> {
        &self.register_map
    }

    pub fn register_space_id(&self) -> AddressSpaceId {
        self.language.space_id(self.language.register_space())
    }

    pub fn register_var(&self, name: &str) -> Option<Var> {
        self.language.register_by_name(name).map(|varnode| {
            Var::new0(
                self.language.space_id(varnode.space()),
                varnode.offset(),
                varnode.size() as u32 * 8,
            )
        })
    }

    pub fn temporary_space_id(&self) -> AddressSpaceId {
        self.language.space_id(self.language.unique_space())
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }
}

#[derive(Clone)]
pub struct Disassembler<'a> {
    lifter: &'a Lifter,
    context: LiftingContext,
}

impl<'a> Disassembler<'a> {
    pub fn new(lifter: &'a Lifter) -> Self {
        Self::new_with(lifter, lifter.context())
    }

    pub fn new_with(lifter: &'a Lifter, context: ContextDatabase) -> Self {
        Self {
            lifter,
            context: lifter.lifting_context_with(context),
        }
    }

    pub fn disassemble(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
    ) -> Result<InsnText, LifterError> {
        Insn::disassemble(self.lifter, &mut self.context, address, bytes)
    }

    pub fn disassemble_at(
        &mut self,
        address: impl Into<Address>,
        memory: &Memory,
    ) -> Result<InsnText, LifterError> {
        let address = address.into();
        let Ok(bytes) = memory.view_bytes_from(address) else {
            return Err(LifterError::UnmappedAddress(address));
        };
        self.disassemble(address, bytes)
    }
}
