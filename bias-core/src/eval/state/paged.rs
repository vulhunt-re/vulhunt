use std::ops::Range;
use std::sync::Arc;

use fugue::core::storage::{OverlayTree, SegmentStorage, SegmentStorageError};
use iset::IntervalMap;
use thiserror::Error;
use ustr::Ustr;

use crate::eval::state::traits::State;
use crate::ir::Address;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Backing(SegmentStorageError),
    #[error("overlapped access from {address} byte access at {size}")]
    OverlappedAccess { address: Address, size: usize },
    #[error("overlapped mapping of {size} bytes from {address}")]
    OverlappedMapping { address: Address, size: usize },
    #[error("unmapped virtual address at {address}")]
    UnmappedAddress { address: Address, size: usize },
}

impl Error {
    pub fn backing(e: SegmentStorageError) -> Self {
        Self::Backing(e)
    }

    pub fn overlapped_access(address: Address, size: usize) -> Self {
        Self::OverlappedAccess { address, size }
    }

    pub fn overlapped_mapping(address: Address, size: usize) -> Self {
        Self::OverlappedMapping { address, size }
    }

    pub fn unmapped_address(address: Address, size: usize) -> Self {
        Self::UnmappedAddress { address, size }
    }
}

#[derive(Debug, Clone)]
pub enum Segment {
    Static { name: Ustr },
    StaticMapping { name: Ustr },
}

impl Segment {
    pub fn new<S: AsRef<str>>(name: S) -> Self {
        Self::Static {
            name: Ustr::from(name.as_ref()),
        }
    }

    pub fn static_mapping<S: AsRef<str>>(name: S) -> Self {
        Self::StaticMapping {
            name: Ustr::from(name.as_ref()),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Static { name } | Self::StaticMapping { name } => name,
        }
    }
}

#[derive(Clone)]
pub struct PagedState {
    segments: Arc<IntervalMap<Address, Segment>>,
    storage: Arc<SegmentStorage>,
    overlay: OverlayTree,
}

impl PagedState {
    pub fn new(
        storage: Arc<SegmentStorage>,
        mapping: impl IntoIterator<Item = (Range<Address>, Segment)>,
    ) -> Self {
        Self {
            segments: Arc::new(IntervalMap::from_iter(mapping)),
            storage,
            overlay: OverlayTree::new(),
        }
    }

    pub fn static_mapping<S, A>(
        &mut self,
        name: S,
        base_address: A,
        size: usize,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        A: Into<Address>,
    {
        let base_address = base_address.into();
        let range = base_address..base_address + size;

        if self.segments.has_overlap(range.clone()) {
            return Err(Error::overlapped_mapping(base_address, size));
        }

        Arc::make_mut(&mut self.segments).insert(range, Segment::static_mapping(name));
        Ok(())
    }

    pub fn segments(&self) -> &IntervalMap<Address, Segment> {
        &self.segments
    }

    pub fn read_values<A>(&self, address: A, values: &mut [u8]) -> Result<(), Error>
    where
        A: Into<Address>,
    {
        let address = address.into();
        match self.segment(address, values.len())? {
            Segment::Static { .. } => self
                .storage
                .read_bytes_exact(u64::from(address), values)
                .map_err(Error::backing)?,
            Segment::StaticMapping { .. } => values.fill(0),
        }
        self.overlay.read(u64::from(address), values);
        Ok(())
    }

    pub fn write_values<A>(&mut self, address: A, values: &[u8]) -> Result<(), Error>
    where
        A: Into<Address>,
    {
        let address = address.into();
        self.segment(address, values.len())?;
        self.overlay.write(u64::from(address), values);
        Ok(())
    }

    fn segment(&self, address: Address, access_size: usize) -> Result<&Segment, Error> {
        if address + 1usize < address {
            return Err(Error::unmapped_address(address, access_size));
        }
        let Some((interval, segment)) = self.segments.overlap(address).next() else {
            return Err(Error::unmapped_address(address, access_size));
        };

        if address + access_size > interval.end {
            return Err(Error::overlapped_access(address, access_size));
        }

        Ok(segment)
    }
}

impl State for PagedState {
    type Error = Error;

    fn fork(&self) -> Self {
        self.clone()
    }

    fn restore(&mut self, other: &Self) {
        self.segments.clone_from(&other.segments);
        self.overlay.clone_from(&other.overlay);
    }
}
