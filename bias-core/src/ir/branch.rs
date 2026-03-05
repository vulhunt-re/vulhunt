use std::borrow::Cow;
use std::fmt;

use crate::ir::term::arena::Arena;
use crate::ir::term::{Term, TermMut};
use crate::ir::traits::*;
use crate::ir::{Address, Expr, Location};
use crate::kb::function_summary::FunctionSummaryId;

thread_local! { static TRGT: Arena<BranchTarget> = Default::default(); }

pub(crate) fn collect_garbage() {
    TRGT.with(|v| v.shrink_to_fit());
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum BranchTarget {
    External(Term<Expr>, FunctionSummaryId),
    Location(Location),
    Computed(Term<Expr>),
}

impl<'target, 'trans> fmt::Display for BranchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BranchTarget::External(expr, id) => write!(f, "<{} ~ {}>", expr, id),
            BranchTarget::Location(loc) => write!(f, "{}", loc),
            BranchTarget::Computed(expr) => write!(f, "{}", expr),
        }
    }
}

pub struct BranchTargetFormatter<'target, 'trans> {
    target: &'target BranchTarget,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'target, 'trans> fmt::Display for BranchTargetFormatter<'target, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.target {
            BranchTarget::External(expr, id) => {
                write!(
                    f,
                    "<{} ~ {}>",
                    expr.display_full(Cow::Borrowed(&*self.fmt)),
                    id
                )
            }
            BranchTarget::Location(loc) => {
                write!(f, "{}", loc.display_full(Cow::Borrowed(&*self.fmt)))
            }
            BranchTarget::Computed(expr) => {
                write!(f, "{}", expr.display_full(Cow::Borrowed(&*self.fmt)))
            }
        }
    }
}

impl<'target, 'trans> TranslatorDisplay<'target, 'trans> for BranchTarget {
    type Target = BranchTargetFormatter<'target, 'trans>;

    fn display_full(&'target self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        BranchTargetFormatter { target: self, fmt }
    }
}

impl BranchTarget {
    pub fn canonical(&self) -> Term<Self> {
        if let Self::Computed(e) = self {
            Self::computed(e.canonical())
        } else {
            self.clone().into()
        }
    }

    pub fn computed<E: Into<Term<Expr>>>(expr: E) -> Term<Self> {
        Self::Computed(expr.into()).into()
    }

    pub fn is_fixed(&self) -> bool {
        !self.is_computed()
    }

    pub fn is_computed(&self) -> bool {
        matches!(self, Self::Computed(_))
    }

    pub fn is_computed_with<F>(&self, f: F) -> bool
    where
        F: FnOnce(&Term<Expr>) -> bool,
    {
        matches!(self, Self::Computed(ex) if f(ex))
    }

    pub fn location<L: Into<Location>>(location: L) -> Term<Self> {
        Self::Location(location.into()).into()
    }

    pub fn location_value(&self) -> Option<&Location> {
        if let Self::Location(ref loc) = self {
            Some(loc)
        } else {
            None
        }
    }
}

impl ToAddress for BranchTarget {
    fn to_address(&self) -> Option<Address> {
        match self {
            Self::Location(Location {
                address,
                position: 0,
            }) => Some(*address),
            Self::Computed(expr) => expr.constant().to_address(),
            _ => None,
        }
    }
}

impl From<BranchTarget> for Term<BranchTarget> {
    fn from(tgt: BranchTarget) -> Self {
        TRGT.with(|a| Term::new(a, tgt))
    }
}

crate::impl_term_mut!(TRGT for BranchTarget);

impl From<Location> for Term<BranchTarget> {
    fn from(t: Location) -> Self {
        TRGT.with(|a| Term::new(a, BranchTarget::Location(t)))
    }
}

impl TermMut<BranchTarget> for Term<BranchTarget> {
    fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<BranchTarget>),
    {
        TRGT.with(|a| self.update_with(a, |_, v| f(v)))
    }
}
