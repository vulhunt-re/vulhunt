use fugue::lifter::runtime::pcode::Varnode;

use crate::eval::state::flat::FlatState;
use crate::eval::state::traits::{State, StateOps, StateValue};
use crate::ir::Address;

pub use crate::eval::state::flat::Error;

#[derive(Debug, Clone)]
pub struct RegisterState<T: StateValue> {
    program_counter: Varnode,
    stack_pointer: Varnode,
    inner: FlatState<T>,
}

impl<T: StateValue> RegisterState<T> {
    pub fn new(size: usize, program_counter: Varnode, stack_pointer: Varnode) -> Self {
        tracing::debug!("register space size: {} bytes", size);

        Self {
            program_counter,
            stack_pointer,
            inner: FlatState::new(size),
        }
    }

    pub fn program_counter(&self) -> Varnode {
        self.program_counter
    }

    pub fn stack_pointer(&self) -> Varnode {
        self.stack_pointer
    }
}

impl<V: StateValue> State for RegisterState<V> {
    type Error = Error;

    #[inline(always)]
    fn fork(&self) -> Self {
        Self {
            program_counter: self.program_counter,
            stack_pointer: self.stack_pointer,
            inner: self.inner.fork(),
        }
    }

    #[inline(always)]
    fn restore(&mut self, other: &Self) {
        self.inner.restore(&other.inner)
    }
}

impl<V: StateValue> StateOps for RegisterState<V> {
    type Value = V;

    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    fn view_values<A>(&self, address: A, size: usize) -> Result<&[Self::Value], Self::Error>
    where
        A: Into<Address>,
    {
        self.inner.view_values(address, size)
    }

    #[inline(always)]
    fn view_values_mut<A>(
        &mut self,
        address: A,
        size: usize,
    ) -> Result<&mut [Self::Value], Self::Error>
    where
        A: Into<Address>,
    {
        self.inner.view_values_mut(address, size)
    }
}
