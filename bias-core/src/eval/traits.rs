use fugue::bv::BitVec;
use fugue::ir::Address;

use super::IRContext;
use crate::ir::Var;
use crate::lifter::PrototypeResolver;

pub trait VarResolve {
    fn resolve(&self, resolver: &PrototypeResolver, sp: Address) -> Option<Var>;
}

pub trait VarOps {
    fn get_address(&self, context: &dyn IRContext) -> Option<Address>;

    fn get_address_or(&self, context: &dyn IRContext, address: Address) -> Address {
        self.get_address(context).unwrap_or(address)
    }

    fn get_address_or_else<F>(&self, context: &dyn IRContext, f: F) -> Address
    where
        F: FnOnce() -> Address,
    {
        self.get_address(context).unwrap_or_else(f)
    }

    fn get_value<T: TryFrom<BitVec>>(&self, context: &dyn IRContext) -> Option<T>;

    fn get_value_or<T: TryFrom<BitVec>>(&self, context: &dyn IRContext, value: T) -> T {
        self.get_value(context).unwrap_or(value)
    }

    fn get_value_or_else<T, F>(&self, context: &dyn IRContext, f: F) -> T
    where
        T: TryFrom<BitVec>,
        F: FnOnce() -> T,
    {
        self.get_value(context).unwrap_or_else(f)
    }

    fn get_value_or_default<T>(&self, context: &dyn IRContext) -> T
    where
        T: Default + From<BitVec>,
    {
        self.get_value(context).unwrap_or_default()
    }
}

impl VarOps for Address {
    fn get_address(&self, context: &dyn IRContext) -> Option<Address> {
        context.read_pointer(*self).ok()
    }

    fn get_value<T: TryFrom<BitVec>>(&self, context: &dyn IRContext) -> Option<T> {
        context
            .read_addr(*self, std::mem::size_of::<T>() as u32)
            .ok()
            .and_then(|bv| T::try_from(bv).ok())
    }
}

impl VarOps for Var {
    fn get_address(&self, context: &dyn IRContext) -> Option<Address> {
        context
            .read_var(self)
            .ok()
            .and_then(|bv| bv.to_u64())
            .map(Address::from)
    }

    fn get_value<T: TryFrom<BitVec>>(&self, context: &dyn IRContext) -> Option<T> {
        context
            .read_var(self)
            .ok()
            .and_then(|bv| T::try_from(bv).ok())
    }
}

impl VarOps for Option<Var> {
    fn get_address(&self, _context: &dyn IRContext) -> Option<Address> {
        None
    }

    fn get_value<T: TryFrom<BitVec>>(&self, _context: &dyn IRContext) -> Option<T> {
        None
    }
}
