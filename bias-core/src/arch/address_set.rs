use std::collections::{BTreeSet, HashSet};
use std::hash::BuildHasher;

use fugue::ir::Address;

pub trait AddressSet {
    fn contains_address(&self, address: impl Into<Address>) -> bool;
}

impl<S> AddressSet for HashSet<Address, S>
where
    S: BuildHasher,
{
    fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.contains(&address.into())
    }
}

impl AddressSet for BTreeSet<Address> {
    fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.contains(&address.into())
    }
}

impl AddressSet for Vec<Address> {
    fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.contains(&address.into())
    }
}
