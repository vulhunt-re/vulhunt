use std::mem::size_of;

use thiserror::Error;

use crate::eval::state::traits::{State, StateOps};
use crate::ir::Address;

#[derive(Debug, Error)]
pub enum Error {
    #[error("out-of-bounds read of `{size}` bytes at {address}")]
    OOBRead { address: Address, size: usize },
    #[error("out-of-bounds write of `{size}` bytes at {address}")]
    OOBWrite { address: Address, size: usize },
}

impl Error {
    pub fn oob_read(address: Address, size: usize) -> Self {
        Self::OOBRead { address, size }
    }

    pub fn oob_write(address: Address, size: usize) -> Self {
        Self::OOBWrite { address, size }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct FlatState {
    backing: Vec<u8>,
    dirty: DirtyBacking,
}

impl FlatState {
    pub fn new(size: usize) -> Self {
        Self {
            backing: vec![0; size],
            dirty: DirtyBacking::new(size),
        }
    }

    fn range(&self, address: Address, size: usize) -> Option<(usize, usize)> {
        let start = usize::from(address);
        let end = start.checked_add(size)?;

        (start <= self.len() && end <= self.len()).then_some((start, end))
    }
}

impl State for FlatState {
    type Error = Error;

    fn fork(&self) -> Self {
        Self {
            backing: self.backing.clone(),
            dirty: self.dirty.fork(),
        }
    }

    fn restore(&mut self, other: &Self) {
        for block in self.dirty.indices.drain(..) {
            let start = usize::from(block.start_address());
            let end = usize::from(block.end_address());

            let real_end = self.backing.len().min(end);

            self.dirty.bitsmap[block.index()] = 0;
            self.backing[start..real_end].clone_from_slice(&other.backing[start..real_end]);
        }
        self.dirty.clone_from(&other.dirty);
    }
}

impl StateOps for FlatState {
    fn len(&self) -> usize {
        self.backing.len()
    }

    fn view_values<A>(&self, address: A, size: usize) -> Result<&[u8], Error>
    where
        A: Into<Address>,
    {
        let address = address.into();
        let Some((start, end)) = self.range(address, size) else {
            return Err(Error::oob_read(address, size));
        };

        Ok(&self.backing[start..end])
    }

    fn view_values_mut<A>(&mut self, address: A, size: usize) -> Result<&mut [u8], Error>
    where
        A: Into<Address>,
    {
        let address = address.into();
        let Some((start, end)) = self.range(address, size) else {
            return Err(Error::oob_read(address, size));
        };

        self.dirty.dirty_region(&address, size);

        Ok(&mut self.backing[start..end])
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
struct Block(u64);

const BLOCK_SIZE: u64 = 64;

impl From<&'_ Address> for Block {
    fn from(t: &Address) -> Block {
        Self(u64::from(*t) / BLOCK_SIZE)
    }
}

impl From<u64> for Block {
    fn from(t: u64) -> Block {
        Self(t)
    }
}

impl Block {
    #[inline]
    fn bit(&self) -> usize {
        self.0 as usize % size_of::<Self>()
    }

    #[inline]
    fn index(&self) -> usize {
        self.0 as usize / size_of::<Self>()
    }

    #[inline]
    fn start_address(&self) -> Address {
        (self.0 * BLOCK_SIZE).into()
    }

    #[inline]
    fn end_address(&self) -> Address {
        ((self.0 + 1) * BLOCK_SIZE).into()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct DirtyBacking {
    indices: Vec<Block>,
    bitsmap: Vec<u64>,
}

impl DirtyBacking {
    fn new(size: usize) -> Self {
        let backing_size = 1 + (size as u64 / BLOCK_SIZE) as usize;
        Self {
            indices: Vec::with_capacity(backing_size),
            bitsmap: vec![0; 1 + backing_size / size_of::<u64>()],
        }
    }

    #[inline]
    fn fork(&self) -> Self {
        self.clone()
    }

    #[inline]
    fn dirty<B: Into<Block>>(&mut self, block: B) {
        let block = block.into();
        let index = block.index();
        let check = 1 << block.bit();

        if self.bitsmap[index] & check == 0 {
            self.bitsmap[index] |= check;
            self.indices.push(block);
        }
    }

    #[inline]
    fn dirty_region(&mut self, start: &Address, size: usize) {
        let sblock = Block::from(start).0;
        let eblock = Block::from(&(*start + size as u64)).0;

        for block in sblock..=eblock {
            self.dirty(block);
        }
    }
}
