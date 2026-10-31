/// A region represents a mapping of some program segment. Regions
/// are indexed by addresses of a fixed size and are associated with
/// a particular endianness.
use std::borrow::Borrow;
use std::fmt::Display;
use std::io;
use std::ops::Range;
use std::sync::Arc;

use fugue::bytes::{ByteCast, Endian, BE, LE};
use fugue::core::storage::{
    MemoryMappedSegmentStorage, SegmentMappingBuilder, SegmentMappingCache, SegmentProperties,
    SegmentStorage, SegmentStorageError, SegmentView, DEFAULT_SPACE_ID, TRANSIENT,
};
use iset::IntervalMap;
use itertools::{Itertools, Position};
use tempfile::TempDir;
use thiserror::Error;
use ustr::Ustr;

use crate::arch::AddressRangeSet;
use crate::cfg::insn::InsnTable;
use crate::ir::Address;
use crate::loader::{LoadedBinary, LoaderRegion};
use crate::project::ProjectContext;

#[derive(Clone)]
pub struct Region {
    name: Ustr,
    range: Range<Address>,
    uninitialised_range: Option<Range<Address>>,
    endian: Endian,
    code: bool,
    read_only: bool,
    external: bool,
}

impl Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "name: {}, bounds: {}-{}, endian: {}",
            self.name,
            self.range.start,
            self.range.end,
            if self.endian().is_big() {
                "big"
            } else {
                "little"
            },
        )
    }
}

#[derive(Debug, Error)]
pub enum RegionIOError {
    #[error("range from {0} of size {1:x} does not correspond to a mapped region")]
    InvalidRegion(Address, usize),
    #[error("unsupported pointer size of {0} bits")]
    UnsupportedPointerSize(u32),
}

impl RegionIOError {
    pub fn invalid_region(address: Address, size: usize) -> Self {
        Self::InvalidRegion(address, size)
    }

    pub fn unsupported_pointer_size(bits: u32) -> Self {
        Self::UnsupportedPointerSize(bits)
    }
}

impl Region {
    pub fn interval(&self) -> &Range<Address> {
        &self.range
    }

    pub fn uninitialised_interval(&self) -> Option<&Range<Address>> {
        self.uninitialised_range.as_ref()
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn address(&self) -> &Address {
        &self.range.start
    }

    pub fn is_code(&self) -> bool {
        self.code
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn is_extern(&self) -> bool {
        self.external
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn contains(&self, address: impl Borrow<Address>) -> bool {
        self.interval().contains(address.borrow())
    }

    pub fn contains_range(&self, address: impl Borrow<Address>, count: usize) -> bool {
        let address = address.borrow();
        count > 0
            && self.interval().contains(address)
            && self.interval().contains(&(*address + (count - 1)))
    }

    pub fn bounds(&self) -> Range<Address> {
        self.interval().clone()
    }

    pub fn len(&self) -> usize {
        usize::from(self.range.end - self.range.start)
    }
}

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("failed to create memory storage directory: {0}")]
    Directory(io::Error),
    #[error("memory storage is shared and cannot be extended")]
    Shared,
    #[error(transparent)]
    Storage(#[from] SegmentStorageError),
}

impl MemoryError {
    pub fn directory(e: io::Error) -> Self {
        Self::Directory(e)
    }

    pub fn shared() -> Self {
        Self::Shared
    }
}

#[derive(Clone)]
pub struct Memory {
    segments: Arc<SegmentStorage>,
    mapping: IntervalMap<Address, Region>,
    directory: Arc<TempDir>,
}

impl Memory {
    pub fn new<T>(binary: &T) -> Result<Self, MemoryError>
    where
        T: LoadedBinary + ?Sized,
    {
        let mut memory = Self {
            segments: Arc::new(SegmentStorage::empty()),
            mapping: IntervalMap::default(),
            directory: Arc::new(TempDir::new().map_err(MemoryError::directory)?),
        };
        memory.map_binary(binary)?;
        Ok(memory)
    }

    pub fn map_binary<T>(&mut self, binary: &T) -> Result<(), MemoryError>
    where
        T: LoadedBinary + ?Sized,
    {
        let segments = Arc::get_mut(&mut self.segments).ok_or_else(MemoryError::shared)?;

        let mut size = 0u64;
        binary.for_each_region(|r| size += u64::from(r.bounds.end - r.bounds.start));

        if size == 0 {
            return Ok(());
        }

        let provider = MemoryMappedSegmentStorage::<{ TRANSIENT }>::with_size(
            self.directory.path().join(self.mapping.len().to_string()),
            size,
        )?;
        let provider = segments.open_provider(provider, SegmentProperties::PERM_ALL);

        let mut offset = 0u64;
        let mut map = |r: &LoaderRegion| -> Result<(), SegmentStorageError> {
            let size = r.bounds.end - r.bounds.start;
            let initialised = &r.bytes[..r.bytes.len().min(usize::from(size))];

            segments.write_bytes_direct(provider, offset, initialised)?;

            let mut properties = SegmentProperties::PERM_READ;
            properties.set(SegmentProperties::PERM_WRITE, !r.read_only);
            properties.set(SegmentProperties::PERM_EXECUTE, r.code);
            properties.set(SegmentProperties::BIG_ENDIAN, r.endian.is_big());
            properties.set(SegmentProperties::UNINITIALISED, initialised.is_empty());

            let name = r.name.as_deref().unwrap_or("unnamed");
            let mapping = segments.create_mapping_from_builder(
                SegmentMappingBuilder::new(r.bounds.start, u64::from(size), offset, provider)
                    .with_properties(properties)
                    .with_name(name),
            )?;
            segments.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;

            let region = Region {
                name: name.into(),
                range: r.bounds.clone(),
                uninitialised_range: r.uninitialised.clone(),
                endian: r.endian,
                code: r.code,
                read_only: r.read_only,
                external: false,
            };

            tracing::trace!("mapping region: {}", region);

            self.mapping.insert(region.bounds(), region);
            offset += u64::from(size);

            Ok(())
        };

        let mut result = Ok(());
        binary.for_each_region(|r| {
            if result.is_ok() {
                result = map(r);
            }
        });

        Ok(result?)
    }

    pub fn segments(&self) -> &Arc<SegmentStorage> {
        &self.segments
    }

    pub fn reader(&self) -> MemoryReader<'_> {
        MemoryReader {
            segments: &self.segments,
            cache: SegmentMappingCache::new(),
        }
    }

    pub fn contains<A>(&self, addr: A) -> bool
    where
        A: Borrow<Address>,
    {
        let start = *addr.borrow();
        let end = start + 1usize;

        start < end && self.mapping.has_overlap(start..end)
    }

    pub fn contains_range<A>(&self, addr: A, size: usize) -> bool
    where
        A: Borrow<Address>,
    {
        let addr = addr.borrow();
        if let Some(r) = self.find_region(addr) {
            r.contains_range(addr, size)
        } else {
            false
        }
    }

    pub fn find_region<A>(&self, addr: A) -> Option<&Region>
    where
        A: Borrow<Address>,
    {
        let start = *addr.borrow();
        let end = start + 1usize;

        if start >= end {
            None
        } else {
            self.mapping.values(start..end).next()
        }
    }

    pub fn regions(&self) -> &IntervalMap<Address, Region> {
        &self.mapping
    }

    pub fn free_regions<'a>(
        &'a self,
        max_address: Address,
    ) -> impl Iterator<Item = Range<Address>> + 'a {
        let mut last = Address::from(0u32);

        self.mapping
            .intervals(..)
            .with_position()
            .map(move |iv| match iv {
                (Position::First | Position::Middle, iv) => {
                    let res = if iv.start > last {
                        [Some(last..iv.start), None].into_iter()
                    } else {
                        [None, None].into_iter()
                    };
                    last = iv.end;
                    res
                }
                (Position::Last | Position::Only, iv) => {
                    let p1 = if iv.start > last {
                        Some(last..iv.start)
                    } else {
                        None
                    };

                    let p2 = if iv.end < max_address {
                        Some(iv.end..max_address)
                    } else {
                        None
                    };

                    [p1, p2].into_iter()
                }
            })
            .flatten()
            .filter_map(|iv| iv)
    }

    pub fn find_free_region(
        &self,
        size: usize,
        align: usize,
        max_address: impl Into<Address>,
    ) -> Option<Address> {
        let max_address = max_address.into();
        self.free_regions(max_address).find_map(|iv| {
            let nstart = iv.start;
            let align = (align as u64).next_multiple_of(2);
            let nalign = nstart + (align - u64::from(nstart) % align);

            if nalign > iv.end || nalign < iv.start {
                return None;
            }

            if usize::from(iv.end - nalign) >= size {
                Some(nalign)
            } else {
                None
            }
        })
    }
}

pub struct MemoryReader<'a> {
    segments: &'a SegmentStorage,
    cache: SegmentMappingCache,
}

impl<'a> MemoryReader<'a> {
    pub fn bytes_from(&mut self, address: Address) -> Option<SegmentView<'a>> {
        let view = self.cache.view_containing(self.segments, address.into())?;
        let remaining = view.range().remaining_from(address.into())?;
        view.bytes_at(address, usize::try_from(remaining).ok()?)
    }

    pub fn bytes_at(&mut self, address: Address, size: usize) -> Option<SegmentView<'a>> {
        let view = self.cache.view_containing(self.segments, address.into())?;
        let remaining = view.range().remaining_from(address.into())?;
        let size = size.min(usize::try_from(remaining).ok()?);
        let bytes = view.bytes_at(address, size)?;

        if bytes
            .as_contiguous()
            .is_some_and(|bytes| bytes.len() == size)
        {
            return Some(bytes);
        }

        let mut buffer = vec![0u8; size];
        bytes.read_into(&mut buffer);
        Some(SegmentView::contiguous(buffer))
    }

    pub fn read_bytes(
        &mut self,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<usize, RegionIOError> {
        let size = buffer.len();
        self.cache
            .read_bytes(self.segments, address.into(), buffer)
            .map_err(|_| RegionIOError::invalid_region(address, size))
    }

    pub fn read_bytes_exact(
        &mut self,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<(), RegionIOError> {
        let size = buffer.len();
        self.cache
            .read_bytes_exact(self.segments, address.into(), buffer)
            .map_err(|_| RegionIOError::invalid_region(address, size))
    }

    pub fn read_pointer(&mut self, address: Address, bits: u32) -> Result<Address, RegionIOError> {
        match bits {
            64 => self.read_value::<u64>(address).map(Address::from),
            32 => self.read_value::<u32>(address).map(Address::from),
            16 => self.read_value::<u16>(address).map(Address::from),
            _ => Err(RegionIOError::unsupported_pointer_size(bits)),
        }
    }

    fn read_value<T: ByteCast>(&mut self, address: Address) -> Result<T, RegionIOError> {
        let invalid = || RegionIOError::invalid_region(address, T::SIZEOF);
        let view = self
            .cache
            .view_containing(self.segments, address.into())
            .ok_or_else(invalid)?;

        let mut buffer = [0u8; 16];
        let buffer = buffer.get_mut(..T::SIZEOF).ok_or_else(invalid)?;
        if view.read_bytes(address, buffer).map_err(|_| invalid())? != T::SIZEOF {
            return Err(invalid());
        }

        Ok(if view.properties().endian().is_little() {
            T::read_bytes::<LE>(buffer)
        } else {
            T::read_bytes::<BE>(buffer)
        })
    }
}

#[derive(Debug, Error)]
#[error("configuration error: {configuration}")]
pub struct MemoryMappingError {
    configuration: &'static str,
}

impl MemoryMappingError {
    pub fn configuration(msg: &'static str) -> Self {
        Self { configuration: msg }
    }
}

#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
pub struct MemoryMappingConfig {
    pub ignore_zero_region: bool,

    pub stack_start: Address,
    pub stack_base: Address,
    pub stack_size: usize,

    pub free_region_base: Address,
}

impl Default for MemoryMappingConfig {
    fn default() -> Self {
        Self {
            ignore_zero_region: true,

            stack_start: Address::from(0x7ffe_f000u32),
            stack_base: Address::from(0x7ffe_0000u32),
            stack_size: 0x10000,

            free_region_base: Address::from(0u32),
        }
    }
}
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MemoryMapping {
    mapping: AddressRangeSet,
    max_address: Address,
    config: MemoryMappingConfig,
}

impl MemoryMapping {
    pub fn from_context<'a, C, P>(
        context: C,
        config: MemoryMappingConfig,
    ) -> Result<Self, MemoryMappingError>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        let context = context.into();

        // validate stack configuration
        let stack_last = config.stack_base + config.stack_size;
        if stack_last <= config.stack_base {
            return Err(MemoryMappingError::configuration("invalid stack bounds"));
        }

        let stack = config.stack_base..stack_last;
        if !stack.contains(&config.stack_start) {
            return Err(MemoryMappingError::configuration(
                "stack start is not a stack address",
            ));
        }

        let max_address = Address::from(
            1u64.checked_shl(context.lifter.address_bits())
                .unwrap_or(0)
                .wrapping_sub(1),
        );

        let mut mapping = AddressRangeSet::default();

        context
            .memory
            .regions()
            .iter(..)
            .filter_map(|(iv, _)| {
                if config.ignore_zero_region && iv.contains(&Address::from(0u64)) {
                    None
                } else {
                    let iv = iv.start..iv.end;
                    Some(iv.clone())
                }
            })
            .for_each(|r| mapping.insert_range(r));

        // validate stack does not overlap with any mapped regions
        for mapping_iv in mapping.ranges() {
            if stack.contains(&mapping_iv.start) || stack.contains(&(mapping_iv.end - 1usize)) {
                return Err(MemoryMappingError::configuration(
                    "stack overlaps with mapped region",
                ));
            }
        }

        mapping.insert_with_length(config.stack_base, config.stack_size);

        Ok(Self {
            mapping,
            max_address,
            config,
        })
    }

    pub fn mapped_regions<'a>(&'a self) -> impl ExactSizeIterator<Item = Range<Address>> + 'a {
        self.mapping.ranges()
    }

    pub fn free_regions<'a>(&'a self) -> impl Iterator<Item = Range<Address>> + 'a {
        let mut last = Address::from(0u32);

        self.mapping
            .ranges()
            .with_position()
            .map(move |iv| match iv {
                (Position::First | Position::Middle, iv) => {
                    let res = if iv.start > last {
                        [Some(last..iv.start), None].into_iter()
                    } else {
                        [None, None].into_iter()
                    };
                    last = iv.end;
                    res
                }
                (Position::Last | Position::Only, iv) => {
                    let p1 = if iv.start > last {
                        Some(last..iv.start)
                    } else {
                        None
                    };

                    let p2 = if iv.end < self.max_address {
                        Some(iv.end..self.max_address)
                    } else {
                        None
                    };

                    [p1, p2].into_iter()
                }
            })
            .flatten()
            .filter_map(|iv| iv)
    }

    pub fn find_free_region(&self, size: usize) -> Option<Address> {
        self.free_regions().find_map(|iv| {
            if iv.end < self.config.free_region_base {
                return None;
            }

            let nstart = iv.start.max(self.config.free_region_base);
            let align = u64::from(self.max_address).count_ones() as u64 / 8;
            let nalign = nstart + (align - u64::from(nstart) % align);

            if nalign > iv.end || nalign < iv.start {
                return None;
            }

            if usize::from(iv.end - nalign) >= size {
                Some(nalign)
            } else {
                None
            }
        })
    }

    pub fn insert_free_range(&mut self, size: usize) -> Option<Address> {
        if let Some(base) = self.find_free_region(size) {
            self.mapping.insert_with_length(base, size);

            Some(base)
        } else {
            None
        }
    }
}
