pub mod strings;

use std::fmt::Display;
use std::ops::Range;

use bitflags::bitflags;
use fugue::bytes::{ByteCast, Endian, BE, LE};
use iset::IntervalMap;
use itertools::Itertools;

use self::strings::StringData;
use crate::ir::{Address, Term, Type};
use crate::lifter::Lifter;
use crate::region::{Memory, Region};
use crate::types::Confidence;

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PointerProvenance : u8 {
        const FROM_POINTER = 0x0000_0001;
        const FROM_DATA    = 0x0000_0010;
    }
}

impl Default for PointerProvenance {
    fn default() -> Self {
        PointerProvenance::FROM_POINTER
    }
}

impl From<Option<DataInfo>> for PointerProvenance {
    fn from(value: Option<DataInfo>) -> Self {
        if let Some(dt) = value {
            Self::from(dt)
        } else {
            PointerProvenance::FROM_POINTER
        }
    }
}

impl From<DataInfo> for PointerProvenance {
    fn from(value: DataInfo) -> Self {
        if matches!(value.kind(), TypeKind::Pointer | TypeKind::Unknown) {
            PointerProvenance::FROM_POINTER
        } else {
            PointerProvenance::FROM_DATA
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum TypeKind {
    Array,
    Numeric,
    Pointer,
    Struct,
    String(StringData),
    Typed(Term<Type>),
    Unknown,
}

impl Default for TypeKind {
    fn default() -> Self {
        Self::Unknown
    }
}

impl Display for TypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Array => f.write_str("array"),
            Self::Numeric => f.write_str("numeric"),
            Self::Pointer => f.write_str("pointer"),
            Self::Struct => f.write_str("struct"),
            Self::String(kind) => write!(f, "string<{kind}>"),
            Self::Typed(t) => t.fmt(f),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

impl TypeKind {
    pub fn type_of(&self) -> Option<&Term<Type>> {
        if let Self::Typed(tt) = self {
            Some(tt)
        } else {
            None
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct DataInfo {
    kind: TypeKind,
    confidence: Confidence,
    size: usize,
}

impl Display for DataInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} with size {} ({})",
            self.kind, self.size, self.confidence
        )
    }
}

impl DataInfo {
    pub fn kind(&self) -> &TypeKind {
        &self.kind
    }

    pub fn has_known_type(&self) -> bool {
        matches!(self.kind, TypeKind::Typed(_))
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl From<Term<Type>> for DataInfo {
    fn from(type_: Term<Type>) -> Self {
        Self {
            size: type_.nbytes(),
            kind: TypeKind::Typed(type_),
            confidence: Confidence::Certain,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DataTypeDB {
    endian: Endian,
    address_size: usize,
    ranges: IntervalMap<Address, DataInfo>,
}

pub struct Conflict<'a> {
    interval: Range<Address>,
    info: &'a DataInfo,
}

impl<'a> Conflict<'a> {
    pub fn interval(&self) -> &Range<Address> {
        &self.interval
    }

    pub fn data(&self) -> &'a DataInfo {
        self.info
    }
}

const MIN_STRING_LENGTH: usize = 2;
const MAX_STRING_LENGTH: usize = 256;

impl DataTypeDB {
    pub fn new(lifter: &Lifter) -> Self {
        Self {
            endian: if lifter.translator().is_big_endian() {
                Endian::Big
            } else {
                Endian::Little
            },
            address_size: lifter.global_space().address_size(),
            ranges: IntervalMap::default(),
        }
    }

    pub fn identify_data_via<'a, T, A>(
        &self,
        memory: &Memory,
        region: T,
        address: A,
    ) -> Option<DataInfo>
    where
        T: Into<Option<&'a Region>>,
        A: Into<Address>,
    {
        let address = address.into();
        let region = region.into().or_else(|| memory.find_region(&address))?;

        let bytes = region.view_bytes_from(address).ok()?;
        let range = &bytes[..MAX_STRING_LENGTH.min(bytes.len())];

        self.identify_data(memory, range)
    }

    pub fn identify_data(&self, memory: &Memory, bytes: &[u8]) -> Option<DataInfo> {
        // check for string-like
        let string_checks = if self.endian.is_big() {
            [StringData::Ascii, StringData::Utf8, StringData::Utf16Be]
        } else {
            [StringData::Ascii, StringData::Utf8, StringData::Utf16Le]
        };

        // take the longest string
        if let Some((_, blen, string_like)) = string_checks
            .into_iter()
            .filter_map(|chk| {
                chk.chars_with_nul(bytes).and_then(|(clen, blen)| {
                    if clen >= MIN_STRING_LENGTH {
                        Some((clen, blen, chk))
                    } else {
                        None
                    }
                })
            })
            .sorted_by_key(|(len, _, _)| *len)
            .rev()
            .next()
        {
            return Some(DataInfo {
                confidence: Confidence::Likely,
                kind: TypeKind::String(string_like),
                size: blen,
            });
        }

        if bytes.len() >= self.address_size {
            // possible address
            let view = &bytes[..self.address_size];
            let addr = if self.address_size == 8 {
                Address::from(if self.endian.is_big() {
                    u64::from_bytes::<BE>(view)
                } else {
                    u64::from_bytes::<LE>(view)
                })
            } else if self.address_size == 4 {
                Address::from(if self.endian.is_big() {
                    u32::from_bytes::<BE>(view)
                } else {
                    u32::from_bytes::<LE>(view)
                })
            } else {
                return None;
            };

            if memory.contains(addr) {
                return Some(DataInfo {
                    confidence: Confidence::Likely,
                    kind: TypeKind::Pointer,
                    size: self.address_size,
                });
            }
        }

        None
    }

    pub fn contains_data<R>(&self, loc: R) -> bool
    where
        R: Into<Range<Address>>,
    {
        let range = loc.into();
        self.ranges.has_overlap(range)
    }

    pub fn mark_data<'a, R>(&'a mut self, range: R) -> Option<Conflict<'a>>
    where
        R: Into<Range<Address>>,
    {
        let range = range.into();
        let size = usize::from(range.end - range.start);
        self.mark_data_with(
            range,
            DataInfo {
                kind: TypeKind::default(),
                confidence: Confidence::Possible,
                size,
            },
        )
    }

    pub fn mark_data_with<'a, R, I>(&'a mut self, range: R, info: I) -> Option<Conflict<'a>>
    where
        R: Into<Range<Address>>,
        I: Into<DataInfo>,
    {
        let iv = range.into();
        let range = iv.start..iv.end;
        if !self.ranges.has_overlap(range.clone()) {
            // fast path
            self.ranges.insert(range, info.into());
            None
        } else {
            if let Some(existing) = self.ranges.get_mut(range.clone()) {
                // exact match is OK to conflict -> we are overwriting it
                *existing = info.into();
                None
            } else {
                let (crange, cinfo) = self.ranges.iter(range).next().unwrap();
                Some(Conflict {
                    interval: crange.start..crange.end,
                    info: cinfo,
                })
            }
        }
    }

    pub fn invalidate_data<R>(&mut self, loc: R)
    where
        R: Into<Range<Address>>,
    {
        let range = loc.into();
        let ranges = self.ranges.intervals(range).collect_vec();
        for range in ranges {
            self.ranges.remove(range);
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::path::Path;

    use super::*;
    use crate::lifter::LifterBuilder;
    use crate::region::Region;

    #[test]
    fn test_mark_and_check() -> Result<(), Box<dyn std::error::Error>> {
        let data = env::var("BIAS_DATA")?;
        let processors = Path::new(&data).join("processors");

        let lifter = LifterBuilder::new(processors)?.build("x86:LE:64:default", "efi")?;
        let mut dt = DataTypeDB::new(&lifter);

        dt.mark_data(Address::from(0xf00u32)..Address::from(0xf04u32));

        assert!(dt.contains_data(Address::from(0xf00u32)..Address::from(0xf01u32)));
        assert!(dt.contains_data(Address::from(0xf01u32)..Address::from(0xf02u32)));
        assert!(dt.contains_data(Address::from(0xf02u32)..Address::from(0xf03u32)));
        assert!(dt.contains_data(Address::from(0xf03u32)..Address::from(0xf04u32)));

        assert!(!dt.contains_data(Address::from(0xf04u32)..Address::from(0xf05u32)));

        dt.invalidate_data(Address::from(0x0u32)..Address::from(0x1000u32));

        assert!(!dt.contains_data(Address::from(0xf00u32)..Address::from(0xf04u32)));

        Ok(())
    }

    #[test]
    fn test_identify() -> Result<(), Box<dyn std::error::Error>> {
        let data = env::var("BIAS_DATA")?;
        let processors = Path::new(&data).join("processors");

        let lifter = LifterBuilder::new(processors)?.build("x86:LE:64:default", "efi")?;
        let mut memory = Memory::new();

        memory.add_region(Region::new(
            "DATA",
            Address::from(0x1000u32),
            Endian::Little,
            vec![0u8; 0x1000],
        ));

        let dt = DataTypeDB::new(&lifter);

        assert_eq!(
            dt.identify_data(
                &memory,
                &[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            ),
            Some(DataInfo {
                confidence: Confidence::Likely,
                kind: TypeKind::Pointer,
                size: 8,
            },),
        );

        assert_eq!(
            dt.identify_data(&memory, b"foobar\0"),
            Some(DataInfo {
                confidence: Confidence::Likely,
                kind: TypeKind::String(StringData::Utf8),
                size: 6,
            },),
        );

        Ok(())
    }
}
