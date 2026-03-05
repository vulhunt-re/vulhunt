/// A region represents a mapping of some program segment. Regions
/// are indexed by addresses of a fixed size and are associated with
/// a particular endianness.
use std::borrow::Borrow;
use std::fmt::Display;
use std::ops::Range;

use fugue::bv::BitVec;
use fugue::bytes::{ByteCast, Endian, BE, LE};
use fugue::ir::Address;
use iset::IntervalMap;
use itertools::{Itertools, Position};
use thiserror::Error;
use ustr::Ustr;

use crate::arch::AddressRangeSet;
use crate::cfg::insn::InsnTable;
use crate::project::ProjectContext;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Region {
    name: Ustr,
    range: Range<Address>,
    uninitialised_range: Option<Range<Address>>,
    endian: Endian,
    code: bool,
    read_only: bool,
    external: bool,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
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
    #[error("read/write byte range is unrepresentable for region `{0}`")]
    Range(Ustr),
    #[error("out-of-bounds read from region `{0}`")]
    OOBRead(Ustr),
    #[error("out-of-bounds write into region `{0}`")]
    OOBWrite(Ustr),
    #[error("unsupported pointer size of {1} bits for region {0}")]
    UnsupportedPointerSize(Ustr, u32),
}

impl Region {
    pub fn new_with(
        name: impl Into<Ustr>,
        addr: impl Into<Address>,
        uninit: impl Into<Option<Range<Address>>>,
        endian: Endian,
        code: bool,
        read_only: bool,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        let address = addr.into();
        let bytes = bytes.into();
        if bytes.is_empty() {
            // check for zero
            panic!("region size cannot be zero");
        }
        let last_address = address + bytes.len();
        if last_address <= address {
            // check for potential overflow
            panic!(
                "address range not representable by addresses starting at {}",
                address
            );
        }

        Self {
            name: name.into(),
            range: address..last_address,
            uninitialised_range: uninit.into(),
            code,
            read_only,
            endian,
            external: false,
            bytes: bytes.into(),
        }
    }

    pub fn new(
        name: impl Into<Ustr>,
        addr: impl Into<Address>,
        endian: Endian,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new_with(name, addr, None, endian, false, false, bytes)
    }

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

    pub fn mark_extern(&mut self) {
        self.external = true;
    }

    pub fn is_extern(&self) -> bool {
        self.external
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn bytes(&self) -> &[u8] {
        &*self.bytes
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
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

    pub fn read_bits(
        &self,
        address: impl Borrow<Address>,
        bits: u32,
    ) -> Result<BitVec, RegionIOError> {
        let aligned = bits % 8 == 0;
        let count = bits / 8 + if aligned { 0 } else { 1 };
        let range = self.view_bytes(address, count as usize)?;
        let bv = if self.endian().is_little() {
            BitVec::from_le_bytes(range)
        } else {
            BitVec::from_be_bytes(range)
        };
        if aligned {
            Ok(bv)
        } else if self.endian().is_little() {
            // truncate msb bits
            Ok(bv.cast(bits as usize))
        } else {
            // shift out lsb bits and truncate
            Ok((bv >> (8 - (bits % 8))).cast(bits as usize))
        }
    }

    pub fn write_bits(
        &mut self,
        address: impl Borrow<Address>,
        bv: impl Borrow<BitVec>,
    ) -> Result<(), RegionIOError> {
        let bv = bv.borrow();
        let bits = bv.bits();

        let endian = self.endian();
        let aligned = bits % 8 == 0;
        let count = bits / 8 + if aligned { 0 } else { 1 };
        let range = self.view_bytes_mut(address, count as usize)?;

        if aligned {
            if endian.is_little() {
                bv.to_le_bytes(range)
            } else {
                bv.to_be_bytes(range)
            }
        } else {
            let nbits = count * 8;
            let shift = 8 - (bits as u32 % 8);

            if endian.is_little() {
                let mask = BitVec::max_value_with(nbits, false) >> shift;
                let orig = BitVec::from_le_bytes(range) & !&mask;
                let bv = (bv.unsigned_cast(nbits) & mask) | orig;

                bv.to_le_bytes(range)
            } else {
                let mask = BitVec::max_value_with(nbits, false) << shift;

                let orig = BitVec::from_be_bytes(range) & !&mask;
                let bv = ((bv.unsigned_cast(nbits) << shift) & mask) | orig;

                bv.to_be_bytes(range)
            }
        }
        Ok(())
    }

    pub fn read_value<T: ByteCast>(
        &self,
        address: impl Borrow<Address>,
    ) -> Result<T, RegionIOError> {
        let range = self.view_bytes(address, T::SIZEOF)?;
        Ok(if self.endian().is_little() {
            T::from_bytes::<LE>(range)
        } else {
            T::from_bytes::<BE>(range)
        })
    }

    pub fn read_pointer(
        &self,
        address: impl Borrow<Address>,
        bits: u32,
    ) -> Result<Address, RegionIOError> {
        if bits == 64 {
            self.read_value(address).map(|v: u64| v.into())
        } else if bits == 32 {
            self.read_value(address).map(|v: u32| v.into())
        } else if bits == 16 {
            self.read_value(address).map(|v: u16| v.into())
        } else {
            Err(RegionIOError::UnsupportedPointerSize(self.name, bits))
        }
    }

    pub fn write_value<T: ByteCast>(
        &mut self,
        address: impl Borrow<Address>,
        value: impl Borrow<T>,
    ) -> Result<(), RegionIOError> {
        let endian = self.endian();
        let range = self.view_bytes_mut(address, T::SIZEOF)?;
        let value = value.borrow();

        Ok(if endian.is_little() {
            value.into_bytes::<LE>(range)
        } else {
            value.into_bytes::<BE>(range)
        })
    }

    pub fn view_bytes_from<A>(&self, address: A) -> Result<&[u8], RegionIOError>
    where
        A: Borrow<Address>,
    {
        let address = address.borrow();
        if !self.range.contains(address) {
            return Err(RegionIOError::OOBRead(self.name));
        }

        let offset = u64::from(address)
            .checked_sub(u64::from(*self.address()))
            .ok_or_else(|| RegionIOError::Range(self.name))? as usize;

        Ok(&self.bytes[offset..])
    }

    pub fn view_bytes_from_mut(
        &mut self,
        address: impl Borrow<Address>,
    ) -> Result<&mut [u8], RegionIOError> {
        let address = address.borrow();
        if !self.range.contains(address) {
            return Err(RegionIOError::OOBRead(self.name));
        }

        let offset = u64::from(address)
            .checked_sub(u64::from(*self.address()))
            .ok_or_else(|| RegionIOError::Range(self.name))? as usize;

        Ok(&mut self.bytes[offset..])
    }

    pub fn view_bytes(
        &self,
        address: impl Borrow<Address>,
        count: usize,
    ) -> Result<&[u8], RegionIOError> {
        let address = address.borrow();
        if !self.contains_range(address, count) {
            return Err(RegionIOError::OOBRead(self.name));
        }

        let offset = u64::from(address)
            .checked_sub(u64::from(*self.address()))
            .ok_or_else(|| RegionIOError::Range(self.name))? as usize;

        Ok(&self.bytes()[offset..offset + count])
    }

    pub fn view_bytes_mut(
        &mut self,
        address: impl Borrow<Address>,
        count: usize,
    ) -> Result<&mut [u8], RegionIOError> {
        let address = address.borrow();
        if !self.contains_range(address, count) {
            return Err(RegionIOError::OOBWrite(self.name));
        }

        let offset = u64::from(address)
            .checked_sub(u64::from(*self.address()))
            .ok_or_else(|| RegionIOError::Range(self.name))? as usize;

        Ok(&mut self.bytes_mut()[offset..offset + count])
    }

    pub fn bounds(&self) -> Range<Address> {
        self.interval().clone()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Memory {
    mapping: IntervalMap<Address, Region>,
}

impl FromIterator<Region> for Memory {
    fn from_iter<T: IntoIterator<Item = Region>>(iter: T) -> Self {
        Self {
            mapping: IntervalMap::from_iter(iter.into_iter().map(|r| (r.interval().clone(), r))),
        }
    }
}

impl IntoIterator for Memory {
    type Item = (Range<Address>, Region);
    type IntoIter = iset::iter::UnsIntoIter<Address, Region, iset::DefaultIx>;

    fn into_iter(self) -> Self::IntoIter {
        self.mapping.unsorted_into_iter()
    }
}

impl Memory {
    pub fn new() -> Self {
        Self {
            mapping: IntervalMap::default(),
        }
    }

    pub fn add_region(&mut self, region: Region) {
        self.mapping.insert(region.interval().clone(), region);
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

    pub fn find_region_mut<A>(&mut self, addr: A) -> Option<&mut Region>
    where
        A: Borrow<Address>,
    {
        let start = *addr.borrow();
        let end = start + 1usize;

        if start < end {
            self.mapping.values_mut(start..end).next()
        } else {
            None
        }
    }

    pub fn regions(&self) -> &IntervalMap<Address, Region> {
        &self.mapping
    }

    pub fn view_bytes(
        &self,
        address: impl Borrow<Address>,
        count: usize,
    ) -> Result<&[u8], RegionIOError> {
        let address = address.borrow();
        let region = self
            .find_region(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, count))?;
        region.view_bytes(address, count)
    }

    pub fn view_bytes_mut(
        &mut self,
        address: impl Borrow<Address>,
        count: usize,
    ) -> Result<&mut [u8], RegionIOError> {
        let address = address.borrow();
        let region = self
            .find_region_mut(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, count))?;
        region.view_bytes_mut(address, count)
    }

    pub fn view_bytes_from(&self, address: impl Borrow<Address>) -> Result<&[u8], RegionIOError> {
        let address = address.borrow();
        let region = self
            .find_region(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, 1))?;
        region.view_bytes_from(address)
    }

    pub fn view_bytes_from_mut(
        &mut self,
        address: impl Borrow<Address>,
    ) -> Result<&mut [u8], RegionIOError> {
        let address = address.borrow();
        let region = self
            .find_region_mut(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, 1))?;
        region.view_bytes_from_mut(address)
    }

    pub fn read_value<T: ByteCast>(
        &self,
        address: impl Borrow<Address>,
    ) -> Result<T, RegionIOError> {
        let address = address.borrow();
        self.find_region(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, 1))?
            .read_value::<T>(address)
    }

    pub fn read_pointer(
        &self,
        address: impl Borrow<Address>,
        bits: u32,
    ) -> Result<Address, RegionIOError> {
        let address = address.borrow();
        self.find_region(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, 1))?
            .read_pointer(address, bits)
    }

    pub fn write_value<T: ByteCast>(
        &mut self,
        address: impl Borrow<Address>,
        value: impl Borrow<T>,
    ) -> Result<(), RegionIOError> {
        let address = address.borrow();
        self.find_region_mut(address)
            .ok_or_else(|| RegionIOError::InvalidRegion(*address, 1))?
            .write_value::<T>(address, value)
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
