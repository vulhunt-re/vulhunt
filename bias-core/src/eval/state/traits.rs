use crate::ir::Address;

pub trait StateValue: Clone + Default {}

impl<V> StateValue for V where V: Clone + Default {}

pub trait State: Clone {
    type Error: std::error::Error;

    fn fork(&self) -> Self;
    fn restore(&mut self, other: &Self);
}

pub trait StateOps: State {
    type Value: StateValue;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn view_values<A>(&self, address: A, size: usize) -> Result<&[Self::Value], Self::Error>
    where
        A: Into<Address>;

    fn view_values_mut<A>(
        &mut self,
        address: A,
        size: usize,
    ) -> Result<&mut [Self::Value], Self::Error>
    where
        A: Into<Address>;
}
