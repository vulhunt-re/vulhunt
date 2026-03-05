use std::borrow::Borrow;
use std::path::Path;

use fugue::ir::compiler::CallFixup;
use fugue::ir::{Address, Translator};
use thiserror::Error;
use uuid::Uuid;

use crate::cfg::icfg::{ICFGBuilder, ICFG};
use crate::cfg::insn::{InsnTable, InsnTerm, InsnTermTable};
use crate::cio::{Error as TypeError, TypeDB};
use crate::data::DataTypeDB;
use crate::eval::{Configuration, Error as EvalError, IREvaluator};
use crate::inject::{InjectionFixup, InjectionFixupError, InjectionManager};
use crate::kb::block::{CodeBlock, CodeBlockTable};
use crate::kb::function::{Function, FunctionId, FunctionTable};
use crate::kb::function_summary::FunctionSummaryTable;
use crate::kb::id::Identifiable;
use crate::lifter::Lifter;
use crate::loader::{
    ExternalsProvider, ExternalsProviderError, HasExternals, LoadedBinary, Loader,
};
use crate::region::{Memory, Region, RegionIOError};
use crate::symbols::{SymbolTable, Symbolise, SymboliseError};

pub mod analysis;
pub mod io;

use self::analysis::{Analysis, AnalysisContext, AnalysisError, AnalysisInfo, AnalysisManager};
#[deprecated = "use bias_core::project::ProjectConfig instead"]
pub use crate::cfg::icfg::Configuration as ICFGConfig;
pub use crate::cfg::icfg::Configuration as ProjectConfig;

#[derive(Debug, Error)]
pub enum Error<L>
where
    L: std::error::Error,
{
    #[error(transparent)]
    Loader(L),
    #[error("control-flow reconstruction failed: {0}")]
    ICFG(RegionIOError),
}

pub type ProjectError<L> = Error<L>;

#[derive(Debug, Error)]
pub enum ProjectIOError {
    #[error("file I/O error: {0}")]
    FileIO(#[from] std::io::Error),
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Project {
    id: Uuid,
    pub(crate) icfg: ICFG,
    pub(crate) itable: InsnTermTable,
    pub(crate) cbtable: CodeBlockTable,
    pub(crate) ftable: FunctionTable,
    pub(crate) fstable: FunctionSummaryTable,
    pub(crate) symtab: SymbolTable,
    pub(crate) entry: Option<Address>,
    pub(crate) lifter: Lifter,
    pub(crate) memory: Memory,
    pub(crate) datadb: DataTypeDB,
    pub(crate) typedb: TypeDB,
    #[serde(skip)]
    pub(crate) manager: AnalysisManager,
    pub(crate) injections: InjectionManager,
}

pub struct ProjectContext<'a, P: InsnTable + 'a = InsnTermTable> {
    pub lifter: &'a Lifter,
    pub icfg: &'a ICFG,
    pub datadb: &'a DataTypeDB,
    pub itable: &'a P,
    pub cbtable: &'a CodeBlockTable,
    pub ftable: &'a FunctionTable,
    pub fstable: &'a FunctionSummaryTable,
    pub symtab: &'a SymbolTable,
    pub memory: &'a Memory,
    pub typedb: &'a TypeDB,
    pub analyses: &'a AnalysisManager,
    pub injections: &'a InjectionManager,
}

impl<'a, P> Clone for ProjectContext<'a, P>
where
    P: InsnTable,
{
    fn clone(&self) -> Self {
        ProjectContext {
            lifter: self.lifter,
            icfg: self.icfg,
            datadb: self.datadb,
            itable: self.itable,
            cbtable: self.cbtable,
            ftable: self.ftable,
            fstable: self.fstable,
            symtab: self.symtab,
            memory: self.memory,
            typedb: self.typedb,
            analyses: self.analyses,
            injections: self.injections,
        }
    }
}

impl<'a, P> Copy for ProjectContext<'a, P> where P: InsnTable + 'a {}

impl<'a, P> ProjectContext<'a, P>
where
    P: InsnTable,
{
    pub fn evaluator(&self, config: Configuration) -> Result<IREvaluator, EvalError> {
        IREvaluator::new_with(*self, config)
    }
}

impl<'a> From<&'a Project> for ProjectContext<'a> {
    fn from(p: &'a Project) -> Self {
        p.tables()
    }
}

pub struct ProjectContextMut<'a, P: InsnTable = InsnTermTable> {
    pub lifter: &'a Lifter,
    pub icfg: &'a mut ICFG,
    pub datadb: &'a mut DataTypeDB,
    pub itable: &'a mut P,
    pub cbtable: &'a mut CodeBlockTable,
    pub ftable: &'a mut FunctionTable,
    pub fstable: &'a mut FunctionSummaryTable,
    pub symtab: &'a mut SymbolTable,
    pub memory: &'a Memory,
    pub typedb: &'a mut TypeDB,
    pub analyses: &'a AnalysisManager,
    pub injections: &'a InjectionManager,
}

impl<'a> From<&'a mut Project> for ProjectContextMut<'a> {
    fn from(p: &'a mut Project) -> Self {
        p.tables_mut()
    }
}

impl<'a> From<&'a ProjectContextMut<'_>> for ProjectContext<'a> {
    fn from(p: &'a ProjectContextMut) -> Self {
        p.tables()
    }
}

impl<'a> ProjectContextMut<'a> {
    pub fn evaluator(&self, config: Configuration) -> Result<IREvaluator, EvalError> {
        IREvaluator::new_with(self.tables(), config)
    }

    pub fn tables(&self) -> ProjectContext<'_> {
        ProjectContext {
            lifter: self.lifter,
            icfg: &*self.icfg,
            datadb: &*self.datadb,
            itable: &*self.itable,
            cbtable: &*self.cbtable,
            ftable: &*self.ftable,
            fstable: &*self.fstable,
            symtab: &*self.symtab,
            memory: &*self.memory,
            typedb: &*self.typedb,
            analyses: &*self.analyses,
            injections: &*self.injections,
        }
    }
}

impl Project {
    pub fn new<T>(binary: &T, lifter: Lifter) -> Self
    where
        T: LoadedBinary + ?Sized,
    {
        Self::new_with(binary, lifter, ProjectConfig::default())
    }

    pub fn new_with<'a, T, C>(binary: &T, lifter: Lifter, config: C) -> Self
    where
        T: LoadedBinary + ?Sized,
        C: AsRef<ProjectConfig<'a>>,
    {
        let mut memory = Memory::new();

        binary.for_each_region(|r| {
            let region = Region::new_with(
                r.name.as_deref().unwrap_or("unnamed"),
                r.bounds.start,
                r.uninitialised.clone(),
                r.endian,
                r.code,
                r.read_only,
                &*r.bytes,
            );

            tracing::trace!("mapping region: {}", region);

            memory.add_region(region);
        });

        let mut slf = Self {
            id: Uuid::new_v4(),
            icfg: Default::default(),
            itable: Default::default(),
            cbtable: Default::default(),
            ftable: Default::default(),
            fstable: Default::default(),
            symtab: Default::default(),
            entry: binary.entry_point(),
            datadb: DataTypeDB::new(&lifter),
            lifter,
            memory,
            typedb: Default::default(),
            manager: Default::default(),
            injections: Default::default(),
        };

        slf.build_icfg(binary, config.as_ref());

        slf
    }

    pub fn new_empty<T>(binary: &T, lifter: Lifter) -> Self
    where
        T: LoadedBinary,
    {
        let mut memory = Memory::new();

        binary.for_each_region(|r| {
            let region = Region::new_with(
                r.name.as_deref().unwrap_or("unnamed"),
                r.bounds.start,
                r.uninitialised.clone(),
                r.endian,
                r.code,
                r.read_only,
                &*r.bytes,
            );

            tracing::trace!("mapping region: {}", region);

            memory.add_region(region);
        });

        Self {
            id: Uuid::new_v4(),
            icfg: Default::default(),
            itable: Default::default(),
            cbtable: Default::default(),
            ftable: Default::default(),
            fstable: Default::default(),
            symtab: Default::default(),
            entry: binary.entry_point(),
            datadb: DataTypeDB::new(&lifter),
            lifter,
            memory,
            typedb: Default::default(),
            manager: Default::default(),
            injections: Default::default(),
        }
    }

    pub fn from_file<L, P>(loader: L, path: P) -> Result<Self, Error<L::Error>>
    where
        L: Loader,
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let (lifter, binary) = loader.load_file(path).map_err(Error::Loader)?;

        Ok(Self::new(&binary, lifter))
    }

    pub fn from_file_with<'a, L, P, C>(
        loader: L,
        path: P,
        config: C,
    ) -> Result<Self, Error<L::Error>>
    where
        L: Loader,
        P: AsRef<Path>,
        C: AsRef<ProjectConfig<'a>>,
    {
        let path = path.as_ref();
        let (lifter, binary) = loader.load_file(path).map_err(Error::Loader)?;

        Ok(Self::new_with(&binary, lifter, config))
    }

    #[inline(always)]
    pub fn tables(&self) -> ProjectContext<'_> {
        ProjectContext {
            lifter: &self.lifter,
            icfg: &self.icfg,
            datadb: &self.datadb,
            itable: &self.itable,
            cbtable: &self.cbtable,
            ftable: &self.ftable,
            fstable: &self.fstable,
            symtab: &self.symtab,
            memory: &self.memory,
            typedb: &self.typedb,
            analyses: &self.manager,
            injections: &self.injections,
        }
    }

    #[inline(always)]
    pub fn tables_mut(&mut self) -> ProjectContextMut<'_> {
        ProjectContextMut {
            lifter: &self.lifter,
            icfg: &mut self.icfg,
            datadb: &mut self.datadb,
            itable: &mut self.itable,
            cbtable: &mut self.cbtable,
            ftable: &mut self.ftable,
            fstable: &mut self.fstable,
            symtab: &mut self.symtab,
            memory: &self.memory,
            typedb: &mut self.typedb,
            analyses: &self.manager,
            injections: &mut self.injections,
        }
    }

    pub fn evaluator(&self, config: Configuration) -> Result<IREvaluator, EvalError> {
        IREvaluator::new_with(self.tables(), config)
    }

    pub fn entry_point(&self) -> Option<Address> {
        self.entry
    }

    pub fn lifter(&self) -> &Lifter {
        &self.lifter
    }

    pub fn lifter_mut(&mut self) -> &mut Lifter {
        &mut self.lifter
    }

    pub fn icfg(&self) -> &ICFG {
        &self.icfg
    }

    pub fn icfg_mut(&mut self) -> &mut ICFG {
        &mut self.icfg
    }

    pub fn instruction_at(&self, address: impl Into<Address>) -> Option<&InsnTerm> {
        self.instructions().get_point(address.into())
    }

    pub fn instructions(&self) -> &InsnTermTable {
        &self.itable
    }

    pub fn block_at(&self, address: impl Into<Address>) -> Option<&CodeBlock> {
        self.code_blocks().get_point(address.into())
    }

    pub fn code_blocks(&self) -> &CodeBlockTable {
        &self.cbtable
    }

    pub fn code_blocks_mut(&mut self) -> &mut CodeBlockTable {
        &mut self.cbtable
    }

    pub fn functions(&self) -> &FunctionTable {
        &self.ftable
    }

    pub fn functions_mut(&mut self) -> &mut FunctionTable {
        &mut self.ftable
    }

    pub fn function_named(&self, name: impl AsRef<str>) -> Option<&Function> {
        self.symtab
            .lookup_function(name)
            .and_then(|fid| self.functions().get(fid))
    }

    pub fn function_at(&self, address: impl Into<Address>) -> Option<&Function> {
        self.functions().get_point(address.into())
    }

    pub fn function_summaries(&self) -> &FunctionSummaryTable {
        &self.fstable
    }

    pub fn function_summaries_mut(&mut self) -> &mut FunctionSummaryTable {
        &mut self.fstable
    }

    pub fn symbols(&self) -> &SymbolTable {
        &self.symtab
    }

    pub fn symbols_mut(&mut self) -> &mut SymbolTable {
        &mut self.symtab
    }

    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut Memory {
        &mut self.memory
    }

    pub fn data_db(&self) -> &DataTypeDB {
        &self.datadb
    }

    pub fn data_db_mut(&mut self) -> &mut DataTypeDB {
        &mut self.datadb
    }

    pub fn type_db(&self) -> &TypeDB {
        &self.typedb
    }

    pub fn type_db_mut(&mut self) -> &mut TypeDB {
        &mut self.typedb
    }

    pub fn injections(&self) -> &InjectionManager {
        &self.injections
    }

    pub fn injections_mut(&mut self) -> &mut InjectionManager {
        &mut self.injections
    }

    pub fn analyses(&self) -> &AnalysisManager {
        &self.manager
    }

    pub fn analyses_mut(&mut self) -> &mut AnalysisManager {
        &mut self.manager
    }

    pub fn get_analysis<A: Analysis + AnalysisInfo>(&self) -> &A {
        self.analyses().get_by::<A>().unwrap()
    }

    pub fn try_get_analysis<A: Analysis + AnalysisInfo>(&self) -> Option<&A> {
        self.analyses().get_by::<A>()
    }

    pub fn get_analysis_mut<A: Analysis + AnalysisInfo>(&mut self) -> &mut A {
        self.analyses_mut().get_by_mut::<A>().unwrap()
    }

    pub fn try_get_analysis_mut<A: Analysis + AnalysisInfo>(&mut self) -> Option<&mut A> {
        self.analyses_mut().get_by_mut::<A>()
    }

    pub fn register_analysis_with<A: Analysis>(
        &mut self,
        analysis: A,
        force: bool,
    ) -> Result<Uuid, AnalysisError>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        self.manager.register_with(analysis, force)
    }

    pub fn register_analysis<A: Analysis>(&mut self, analysis: A) -> Result<Uuid, AnalysisError>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        self.manager.register(analysis)
    }

    pub fn analyse(&mut self) -> Result<(), AnalysisError> {
        AnalysisManager::analyse(self)
    }

    pub fn analyse_with(&mut self, context: &mut AnalysisContext) -> Result<(), AnalysisError> {
        AnalysisManager::analyse_with(context, self)
    }

    pub fn load_symbols<S>(&mut self, symboliser: &S) -> Result<(), SymboliseError>
    where
        S: Symbolise,
    {
        symboliser.apply_symbols(self)
    }

    pub fn load_types<P>(&mut self, file: P) -> Result<(), TypeError>
    where
        P: AsRef<Path>,
    {
        let file = file.as_ref();
        self.typedb.load_file(file)
    }

    pub fn load_externs<B, E>(
        &mut self,
        externs: &B,
        source_binary: E,
        source_lifter: Lifter,
    ) -> Result<(), ExternalsProviderError>
    where
        B: HasExternals + ?Sized,
        E: ExternalsProvider,
    {
        source_binary.apply_externs(source_lifter, self, externs)
    }

    pub fn fixups(&self) -> impl Iterator<Item = (FunctionId, &CallFixup)> {
        self.injections
            .fixups()
            .filter_map(|(fid, f)| self.lifter.call_fixup_for(&f.name()).map(|v| (fid, v)))
    }

    pub fn register_fixups(&mut self) -> Result<(), InjectionFixupError> {
        let lifter = &self.lifter;
        let symbols = &self.symtab;

        for fixup in lifter.convention().call_fixups() {
            if let Some(fid) = symbols.lookup_function(fixup.name()) {
                tracing::trace!(
                    "registering fixup override for {} at {} (fixup)",
                    fixup.name(),
                    self.ftable[fid].address(),
                );
                self.injections.add_function_stub(
                    fid,
                    InjectionFixup::new(lifter, fixup.name(), fixup.pcode(), fixup.shift())?,
                );
            }

            for alias in fixup.targets() {
                let Some(fid) = symbols.lookup_function(alias) else {
                    continue;
                };

                tracing::trace!(
                    "registering fixup override for {} at {} (fixup alias: {alias})",
                    fixup.name(),
                    self.ftable[fid].address()
                );

                self.injections.add_function_stub(
                    fid,
                    InjectionFixup::new(lifter, fixup.name(), fixup.pcode(), fixup.shift())?,
                );
            }
        }

        Ok(())
    }

    pub fn build_icfg<T>(&mut self, binary: &T, config: &ProjectConfig)
    where
        T: LoadedBinary + ?Sized,
    {
        tracing::trace!("building inter-procedural control-flow graph");
        ICFGBuilder::build_with(self, binary, config);
    }

    pub fn clear_icfg(&mut self) {
        self.icfg = ICFG::default();
    }
}

impl Identifiable for Project {
    type Key = Uuid;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

impl Borrow<Lifter> for Project {
    fn borrow(&self) -> &Lifter {
        self.lifter()
    }
}

impl Borrow<Translator> for Project {
    fn borrow(&self) -> &Translator {
        self.lifter().translator()
    }
}
