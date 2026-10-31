use fugue::lifter::runtime::pcode::Varnode;

use crate::eval::state::flat::FlatState;
use crate::eval::state::traits::{State, StateOps};
use crate::ir::Address;

pub use crate::eval::state::flat::Error;

#[derive(Debug, Clone)]
pub struct RegisterState {
    program_counter: Varnode,
    stack_pointer: Varnode,
    inner: FlatState,
}

impl RegisterState {
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

impl State for RegisterState {
    type Error = Error;

    #[inline(always)]
    fn fork(&self) -> Self {
        self.clone()
    }

    #[inline(always)]
    fn restore(&mut self, other: &Self) {
        self.inner.restore(&other.inner)
    }
}

impl StateOps for RegisterState {
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    fn view_values<A>(&self, address: A, size: usize) -> Result<&[u8], Self::Error>
    where
        A: Into<Address>,
    {
        self.inner.view_values(address, size)
    }

    #[inline(always)]
    fn view_values_mut<A>(&mut self, address: A, size: usize) -> Result<&mut [u8], Self::Error>
    where
        A: Into<Address>,
    {
        self.inner.view_values_mut(address, size)
    }
}
