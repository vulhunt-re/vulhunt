use std::borrow::Cow;
use std::fmt;

use fugue::ir::il::traits::{TranslatorDisplay, TranslatorFormatter};
use smallvec::SmallVec;

use crate::ir::{Location, Var, Visit, VisitMut, VisitVars, VisitVarsMut};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Phi {
    target: Var,
    sources: SmallVec<[Var; 2]>,
}

impl Phi {
    pub fn new<I>(target: Var, sources: I) -> Self
    where
        I: Iterator<Item = Var>,
    {
        Self {
            target,
            sources: sources.into_iter().collect(),
        }
    }

    pub fn target(&self) -> &Var {
        &self.target
    }

    pub fn sources(&self) -> &[Var] {
        &self.sources
    }

    pub fn sources_mut(&mut self) -> &mut SmallVec<[Var; 2]> {
        &mut self.sources
    }

    pub fn visit<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        visitor.visit_phi(self.target(), self.sources());
    }

    pub fn visit_at<'ir, V>(&'ir self, at: Location, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        visitor.visit_location(at);
        visitor.visit_phi(self.target(), self.sources());
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        visitor.visit_phi_mut(&mut self.target, &mut self.sources);
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        for var in self.sources() {
            visitor.visit_use(var);
        }

        visitor.visit_def(self.target());
    }

    pub fn visit_vars_at<'ir, V>(&'ir self, at: Location, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        for var in self.sources() {
            visitor.visit_use_at(at, var);
        }

        visitor.visit_def_at(at, self.target());
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for var in self.sources_mut() {
            visitor.visit_use_mut(var);
        }

        visitor.visit_def_mut(&mut self.target);
    }
}

pub struct PhiFormatter<'phi, 'trans> {
    phi: &'phi Phi,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'phi, 'trans> fmt::Display for PhiFormatter<'phi, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} ← ϕ({}",
            self.phi.target().display_full(Cow::Borrowed(&*self.fmt)),
            self.phi.sources()[0].display_full(Cow::Borrowed(&*self.fmt)),
        )?;

        if self.phi.sources.len() > 1 {
            for phi in &self.phi.sources()[1..] {
                write!(f, ", {}", phi.display_full(Cow::Borrowed(&*self.fmt)))?;
            }
        }

        write!(f, ")")
    }
}

impl<'phi, 'trans> TranslatorDisplay<'phi, 'trans> for Phi {
    type Target = PhiFormatter<'phi, 'trans>;

    fn display_full(&'phi self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        PhiFormatter { phi: self, fmt }
    }
}
