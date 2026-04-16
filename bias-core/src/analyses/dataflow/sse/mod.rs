pub mod analysis;

pub mod arena;
pub use arena::{SSEMatcher, SSEReplacer, SSESimplifier, SSExprArena};

pub mod clobbers;

pub mod context;
pub use context::SSEContext;

pub mod expr;
pub use expr::{BitVecRef, Cast, SSExpr, SSExprRef};

pub(crate) mod egraph;
pub(crate) mod validation;

pub mod trace;
pub use trace::{SSAVarMap, SSETrace, SSETraceContext, SSEVarMap, SSAVarSet};

pub mod validity;
pub use validity::{
    SSEValidity, SSEValidityLocation, SSEValiditySet, SSEValiditySource, SSEValidityState,
};

pub struct SSE<'a> {
    expr: SSExprRef<'a>,
    validity: SSEValidity,
    source: Option<SSEValiditySource<'a>>,
}

impl<'a> SSE<'a> {
    pub fn new(expr: SSExprRef<'a>, validity: SSEValidity) -> Self {
        Self {
            expr,
            validity,
            source: None,
        }
    }

    pub fn with_source(mut self, source: SSEValiditySource<'a>) -> Self {
        self.source = Some(source);
        self
    }

    pub fn expr(&self) -> SSExprRef<'a> {
        self.expr
    }

    pub fn validity(&self) -> &SSEValidity {
        &self.validity
    }

    pub fn source(&self) -> Option<&SSEValiditySource<'a>> {
        self.source.as_ref()
    }

    pub fn into_parts(self) -> (SSExprRef<'a>, SSEValidity, Option<SSEValiditySource<'a>>) {
        (self.expr, self.validity, self.source)
    }
}
