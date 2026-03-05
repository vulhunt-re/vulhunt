use crate::decompiler::ast::DecompilerAst;
use crate::decompiler::error::DecompilerError;
use crate::decompiler::{Decompiler, DecompilerConfig};
use crate::prelude::*;

pub mod switch;
pub use switch::{DecompilerSwitchTableRecovery, DECOMPILER_SWITCH_TABLE_RECOVERY};

pub const DECOMPILE_FUNCTIONS: Uuid = uuid("E33AD0C8-AF17-4E59-92C5-190A6CDD59C5");

#[derive(Debug, Clone)]
pub struct DecompileFunctions {
    config: DecompilerConfig,
    functions: AHashMap<FunctionId, DecompilerAst>,
}

impl Default for DecompileFunctions {
    fn default() -> Self {
        Self::new_with(DecompilerConfig::default())
    }
}

impl DecompileFunctions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(config: DecompilerConfig) -> Self {
        Self {
            config,
            functions: Default::default(),
        }
    }

    #[inline]
    pub fn get(&self, fid: FunctionId) -> Option<&DecompilerAst> {
        self.functions.get(&fid)
    }

    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (FunctionId, &DecompilerAst)> {
        self.functions.iter().map(|(&k, v)| (k, v))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.functions.len()
    }
}

impl AnalysisInfo for DecompileFunctions {
    const NAME: &'static str = "Decompile identified functions";
    const UUID: Uuid = DECOMPILE_FUNCTIONS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        AnalysisSchedule::before::<DecompilerSwitchTableRecovery>(),
        AnalysisSchedule::dynamic(),
    ];
}

#[inline(always)]
fn analysis_error(e: DecompilerError) -> AnalysisError {
    AnalysisError::Analysis(DECOMPILE_FUNCTIONS, Box::new(e))
}

impl Analysis for DecompileFunctions {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut decompiler = Decompiler::new(&*project).map_err(analysis_error)?;

        self.functions.reserve(project.functions().len());

        for f in project.functions().values() {
            match decompiler
                .try_decompile_ast(f, self.config.timeout)
                .map_err(analysis_error)
            {
                Ok(fd) => {
                    self.functions.insert(f.id(), fd);
                }
                Err(e) if self.config.fail_fast => return Err(e),
                _ => (),
            }
        }

        Ok(())
    }
}
