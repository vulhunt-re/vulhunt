use crate::ir::Address;

pub trait State: Clone {
    type Error: std::error::Error;

    fn fork(&self) -> Self;
    fn restore(&mut self, other: &Self);
}

pub trait StateOps: State {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn view_values<A>(&self, address: A, size: usize) -> Result<&[u8], Self::Error>
    where
        A: Into<Address>;

    fn view_values_mut<A>(&mut self, address: A, size: usize) -> Result<&mut [u8], Self::Error>
    where
        A: Into<Address>;
}
