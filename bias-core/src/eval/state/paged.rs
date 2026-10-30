use std::mem::take;
use std::ops::Range;

use iset::IntervalMap;
use thiserror::Error;
use ustr::Ustr;

use crate::eval::state::flat::{self, FlatState};
use crate::eval::state::traits::{State, StateOps, StateValue};
use crate::ir::Address;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Backing(flat::Error),
    #[error("overlapped access from {address} byte access at {size}")]
    OverlappedAccess { address: Address, size: usize },
    #[error("overlapped mapping of {size} bytes from {address}")]
    OverlappedMapping { address: Address, size: usize },
    #[error("unmapped virtual address at {address}")]
    UnmappedAddress { address: Address, size: usize },
}

impl Error {
    pub fn overlapped_access(address: Address, size: usize) -> Self {
        Self::OverlappedAccess { address, size }
    }

    pub fn overlapped_mapping(address: Address, size: usize) -> Self {
        Self::OverlappedMapping { address, size }
    }

    pub fn unmapped_address(address: Address, size: usize) -> Self {
        Self::UnmappedAddress { address, size }
    }

    fn backing(base: Address, e: flat::Error) -> Self {
        Self::Backing(match e {
            flat::Error::OOBRead { address, size } => flat::Error::oob_read(address + base, size),
            flat::Error::OOBWrite { address, size } => flat::Error::oob_write(address + base, size),
        })
    }
}

#[derive(Debug, Clone)]
pub enum Segment<T: StateValue> {
    Static { name: Ustr, offset: usize },
    StaticMapping { name: Ustr, backing: FlatState<T> },
}

impl<T: StateValue> Segment<T> {
    pub fn new<S: AsRef<str>>(name: S, offset: usize) -> Self {
        Self::Static {
            name: Ustr::from(name.as_ref()),
            offset,
        }
    }

    pub fn static_mapping<S: AsRef<str>>(name: S, mapping: FlatState<T>) -> Self {
        Self::StaticMapping {
            name: Ustr::from(name.as_ref()),
            backing: mapping,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Static { name, .. } | Self::StaticMapping { name, .. } => name,
        }
    }

    pub fn fork(&self) -> Self {
        match self {
            Self::Static { .. } => self.clone(),
            Self::StaticMapping { name, backing } => Self::StaticMapping {
                name: *name,
                backing: backing.fork(),
            },
        }
    }

    pub fn restore(&mut self, other: &Self) {
        match (self, other) {
            (
                Self::Static { name, offset },
                Self::Static {
                    name: rname,
                    offset: roffset,
                },
            ) => {
                if name != rname || offset != roffset {
                    panic!("attempting to restore segment `{}` at {} from incompatible segment `{}` at {}",
                           name,
                           offset,
                           rname,
                           roffset
                    );
                }
            }
            (
                Self::StaticMapping { name, backing },
                Self::StaticMapping {
                    name: rname,
                    backing: rbacking,
                },
            ) => {
                if name != rname || backing.len() != rbacking.len() {
                    panic!("attempting to restore segment `{}` of size {} from incompatible segment `{}` of size {}",
                           name,
                           backing.len(),
                           rname,
                           rbacking.len(),
                    );
                }

                backing.restore(rbacking);
            }
            (slf, oth) => panic!(
                "attempting to restore segment `{}` from segment `{}` which have different kinds",
                slf.name(),
                oth.name()
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PagedState<T: StateValue> {
    segments: IntervalMap<Address, Segment<T>>,
    inner: FlatState<T>,
}

impl<T: StateValue> PagedState<T> {
    pub fn from_parts(
        mapping: impl IntoIterator<Item = (Range<Address>, Segment<T>)>,
        backing: FlatState<T>,
    ) -> Self {
        Self {
            segments: IntervalMap::from_iter(mapping),
            inner: backing,
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

        self.segments
            .insert(range, Segment::static_mapping(name, FlatState::new(size)));
        Ok(())
    }

    pub fn segments(&self) -> &IntervalMap<Address, Segment<T>> {
        &self.segments
    }

    #[inline(always)]
    fn with_flat<'a, F, O: 'a>(
        &'a self,
        address: Address,
        access_size: usize,
        f: F,
    ) -> Result<O, Error>
    where
        F: FnOnce(&'a FlatState<T>, Address, usize) -> Result<O, Error>,
    {
        if address + 1usize < address {
            return Err(Error::unmapped_address(address, access_size));
        }
        let Some((interval, value)) = self.segments.overlap(address).next() else {
            return Err(Error::unmapped_address(address, access_size));
        };

        if address + access_size > interval.end {
            return Err(Error::overlapped_access(address, access_size));
        }

        match value {
            Segment::StaticMapping { backing, .. } => {
                let translated = address - interval.start;
                f(backing, translated, access_size)
            }
            Segment::Static { offset, .. } => {
                let address = (address - interval.start) + *offset;
                f(&self.inner, address, access_size)
            }
        }
    }

    #[inline(always)]
    fn with_flat_mut<'a, F, O: 'a>(
        &'a mut self,
        address: Address,
        access_size: usize,
        f: F,
    ) -> Result<O, Error>
    where
        F: FnOnce(&'a mut FlatState<T>, Address, usize) -> Result<O, Error>,
    {
        if address + 1usize < address {
            return Err(Error::unmapped_address(address, access_size));
        }
        let Some((interval, value)) = self.segments.overlap_mut(address).next() else {
            return Err(Error::unmapped_address(address, access_size));
        };

        if address + access_size > interval.end {
            return Err(Error::overlapped_access(address, access_size));
        }

        match value {
            Segment::StaticMapping { backing, .. } => {
                let translated = address - interval.start;
                f(backing, translated, access_size)
            }
            Segment::Static { offset, .. } => {
                let address = (address - interval.start) + *offset;
                f(&mut self.inner, address, access_size)
            }
        }
    }
}

impl<V: StateValue> State for PagedState<V> {
    type Error = Error;

    fn fork(&self) -> Self {
        Self {
            segments: self.segments.iter(..).map(|(i, v)| (i, v.fork())).collect(),
            inner: self.inner.fork(),
        }
    }

    fn restore(&mut self, other: &Self) {
        self.inner.restore(&other.inner);

        self.segments = take(&mut self.segments)
            .unsorted_into_iter()
            .filter_map(|(i, mut v)| {
                let vo = other.segments.get(i.clone())?;
                v.restore(vo);
                Some((i, v))
            })
            .collect();
    }
}

impl<V: StateValue> StateOps for PagedState<V> {
    type Value = V;

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn view_values<A>(&self, address: A, n: usize) -> Result<&[Self::Value], Error>
    where
        A: Into<Address>,
    {
        self.with_flat(address.into(), n, |inner, address, n| {
            inner
                .view_values(address, n)
                .map_err(|e| Error::backing(address, e))
        })
    }

    fn view_values_mut<A>(&mut self, address: A, n: usize) -> Result<&mut [Self::Value], Error>
    where
        A: Into<Address>,
    {
        self.with_flat_mut(address.into(), n, |inner, address, n| {
            inner
                .view_values_mut(address, n)
                .map_err(|e| Error::backing(address, e))
        })
    }
}
