use std::borrow::Cow;
use std::hash::Hash;

use fugue::bv::BitVec;
pub use fugue::ir::il::traits::{TranslatorDisplay, TranslatorFormatter};
use fugue::ir::AddressSpaceId;

use crate::ir::Address;
use crate::kb::phi::Phi;

pub mod visit;
pub use visit::{VarsVisitor, Visit, VisitVars};
pub mod visit_mut;
pub use visit_mut::{
    VarsMutVisitor, VarsSubst, VarsSubstVisitor, VisitMut, VisitOpVarsMut, VisitVarsMut,
};

use super::SimpleVar;

pub trait BitSize {
    fn nbits(&self) -> u32;
}

impl BitSize for BitVec {
    fn nbits(&self) -> u32 {
        self.bits() as u32
    }
}

pub trait Variable {
    fn space(&self) -> AddressSpaceId;
    fn generation(&self) -> u32;
    fn generation_mut(&mut self) -> &mut u32;
    fn with_generation(&self, generation: u32) -> Self;
}

pub trait MutableTerm {
    type T: Clone + Hash + Eq;

    fn update_with<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<Self::T>);

    fn set(&mut self, v: Self::T) {
        self.update_with(move |old_v| *old_v = Cow::Owned(v))
    }
}

pub trait ToAddress {
    fn to_address(&self) -> Option<Address>;
}

impl ToAddress for BitVec {
    fn to_address(&self) -> Option<Address> {
        self.to_u64().map(Address::from)
    }
}

impl ToAddress for Option<BitVec> {
    fn to_address(&self) -> Option<Address> {
        self.as_ref().and_then(|bv| bv.to_address())
    }
}

impl ToAddress for Option<&BitVec> {
    fn to_address(&self) -> Option<Address> {
        self.and_then(|bv| bv.to_address())
    }
}

impl<E> ToAddress for Result<BitVec, E> {
    fn to_address(&self) -> Option<Address> {
        self.as_ref().ok().to_address()
    }
}

pub trait PhiVarsMut {
    fn push_phi(&mut self, phi: Phi);
    fn clear_phis(&mut self);

    fn get_phi(&self, var: impl Into<SimpleVar>) -> Option<&Phi>;
    fn get_phi_mut(&mut self, var: impl Into<SimpleVar>) -> Option<&mut Phi>;
}
