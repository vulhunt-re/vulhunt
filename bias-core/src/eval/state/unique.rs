use crate::eval::state::flat::FlatState;
use crate::eval::state::traits::{State, StateOps, StateValue};
use crate::ir::Address;

pub use crate::eval::state::flat::Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct UniqueState<T: StateValue>(FlatState<T>);

impl<T: StateValue> UniqueState<T> {
    pub fn new(size: usize) -> Self {
        tracing::debug!("unique space size: {} bytes", size);

        Self(FlatState::new(size))
    }
}

impl<V: StateValue> State for UniqueState<V> {
    type Error = Error;

    #[inline(always)]
    fn fork(&self) -> Self {
        Self(self.0.fork())
    }

    #[inline(always)]
    fn restore(&mut self, other: &Self) {
        self.0.restore(&other.0)
    }
}

impl<V: StateValue> StateOps for UniqueState<V> {
    type Value = V;

    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn view_values<A>(&self, address: A, size: usize) -> Result<&[Self::Value], Self::Error>
    where
        A: Into<Address>,
    {
        self.0.view_values(address, size)
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
        self.0.view_values_mut(address, size)
    }
}
