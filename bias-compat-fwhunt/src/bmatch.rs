use std::borrow::Borrow;
use std::fmt::Display;
use std::str::FromStr;

use bias_core::Project;
use memchr::memmem;
use serde::{Deserialize, Deserializer, Serializer};
use thiserror::Error;

use crate::matcher::MatchContext;
use crate::schema::*;
use crate::MatchesRule;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid pattern length (must be multiple of 2)")]
    InvalidLength,
    #[error("invalid hex-digit")]
    InvalidDigit,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BMatch {
    mask: u8,
    value: u8,
}

impl BMatch {
    #[inline(always)]
    pub const fn any() -> Self {
        Self::val_with(0, 0)
    }

    #[inline(always)]
    pub const fn val(value: u8) -> Self {
        Self::val_with(value, 0xff)
    }

    #[inline(always)]
    pub const fn val_with(value: u8, mask: u8) -> Self {
        Self { mask, value }
    }

    #[inline(always)]
    pub fn matches(&self, byte: u8) -> bool {
        if (self.value >> 4) > 0 {
            (self.mask & byte) == self.value
        } else {
            (self.mask & byte & 0x0f) == self.value
        }
    }

    #[inline(always)]
    fn parse_char(c: u8) -> Result<Self, Error> {
        match c {
            b'.' => Ok(Self::any()),
            b'0'..=b'9' => Ok(Self::val(c - b'0')),
            b'A'..=b'F' => Ok(Self::val(10 + c - b'A')),
            b'a'..=b'f' => Ok(Self::val(10 + c - b'a')),
            _ => Err(Error::InvalidDigit),
        }
    }

    #[inline(always)]
    fn combine(&mut self, other: Self) {
        self.mask = (self.mask << 4u32) | other.mask;
        self.value = (self.value << 4u32) | other.value;
    }

    #[inline(always)]
    pub fn to_fixed(&self) -> Option<u8> {
        if self.mask == 0xff {
            Some(self.value)
        } else {
            None
        }
    }
}

impl Display for BMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.mask & 0xf0 == 0 && self.value & 0xf0 == 0 {
            write!(f, ".")?;
        } else {
            write!(f, "{:1x}", self.value >> 4)?;
        }

        if self.mask & 0x0f == 0 && self.value & 0x0f == 0 {
            write!(f, ".")?;
        } else {
            write!(f, "{:1x}", self.value & 0x0f)?;
        }

        Ok(())
    }
}

impl From<u8> for BMatch {
    fn from(value: u8) -> Self {
        Self::val(value)
    }
}

impl FromStr for BMatch {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 2 {
            return Err(Error::InvalidLength);
        }

        let chars = s.as_bytes();
        let mut ph = Self::parse_char(chars[0])?;
        let pl = Self::parse_char(chars[1])?;

        ph.combine(pl);

        Ok(ph)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BMatcher {
    Fixed(Vec<u8>),
    Fuzzy(Vec<BMatch>),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum StrOrInt {
    Str(String),
    Int(u64),
}

impl From<StrOrInt> for String {
    fn from(si: StrOrInt) -> String {
        match si {
            StrOrInt::Str(s) => s,
            StrOrInt::Int(i) => i.to_string(),
        }
    }
}

impl BMatcher {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes)
    }

    pub fn from_parts(pattern: &[u8], mask: &[u8]) -> Result<Self, Error> {
        if pattern.len() != mask.len() {
            return Err(Error::InvalidLength);
        }

        Ok(Self::from_iter(
            pattern
                .iter()
                .copied()
                .zip(mask.iter().copied())
                .map(|(v, m)| {
                    // normalize the mask and pattern
                    let (vh, mh) = if m & 0xf0 != 0xf0 {
                        (0x0, 0x0)
                    } else {
                        (v & 0xf0, 0xf0)
                    };
                    let (vl, ml) = if m & 0x0f != 0x0f {
                        (0x0, 0x0)
                    } else {
                        (v & 0x0f, 0x0f)
                    };

                    BMatch::val_with(vh | vl, mh | ml)
                }),
        ))
    }

    pub fn de_from_str<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::from(StrOrInt::deserialize(deserializer)?);
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }

    pub fn ser_to_str<S>(slf: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&slf.to_string())
    }

    #[inline(always)]
    pub fn matches_prefix(&self, bytes: &[u8]) -> bool {
        self.len() <= bytes.len() && self.matches_partial(bytes)
    }

    #[inline(always)]
    pub fn matches_exact(&self, bytes: &[u8]) -> bool {
        self.len() == bytes.len() && self.matches_partial(bytes)
    }

    #[inline(always)]
    fn matches_partial(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Fixed(vs) => memmem::find(bytes, vs).is_some(),
            Self::Fuzzy(vs) => vs.iter().zip(bytes.iter()).all(|(p, b)| p.matches(*b)),
        }
    }

    #[inline(always)]
    pub fn position_from(&self, bytes: &[u8], offset: usize) -> Option<usize> {
        if offset < bytes.len() {
            match self {
                Self::Fixed(vs) => memmem::find(&bytes[offset..], vs),
                Self::Fuzzy(vs) => bytes[offset..]
                    .windows(self.len())
                    .position(|view| vs.iter().zip(view.iter()).all(|(p, b)| p.matches(*b))),
            }
            .map(|position| position + offset)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn position(&self, bytes: &[u8]) -> Option<usize> {
        self.position_from(bytes, 0)
    }

    #[inline(always)]
    pub fn matches_from(&self, bytes: &[u8], offset: usize) -> bool {
        self.position_from(bytes, offset).is_some()
    }

    #[inline(always)]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.position(bytes).is_some()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        match self {
            Self::Fixed(vs) => vs.len(),
            Self::Fuzzy(vs) => vs.len(),
        }
    }
}

impl From<&'_ [u8]> for BMatcher {
    fn from(values: &[u8]) -> Self {
        Self::Fixed(values.to_vec())
    }
}

impl From<Vec<u8>> for BMatcher {
    fn from(values: Vec<u8>) -> Self {
        Self::Fixed(values)
    }
}

impl From<Vec<BMatch>> for BMatcher {
    fn from(values: Vec<BMatch>) -> Self {
        if let Some(values) = values.iter().map(|v| v.to_fixed()).collect() {
            Self::Fixed(values)
        } else {
            Self::Fuzzy(values)
        }
    }
}

impl<P> FromIterator<P> for BMatcher
where
    P: Borrow<BMatch>,
{
    fn from_iter<T: IntoIterator<Item = P>>(iter: T) -> Self {
        Self::from(Vec::from_iter(iter.into_iter().map(|p| *p.borrow())))
    }
}

impl FromStr for BMatcher {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() % 2 != 0 {
            return Err(Error::InvalidLength);
        }

        let pairs = s
            .as_bytes()
            .chunks(2)
            .map(|lr| {
                let mut l = BMatch::parse_char(lr[0])?;
                let r = BMatch::parse_char(lr[1])?;
                l.combine(r);
                Ok(l)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(pairs.into())
    }
}

impl Display for BMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(vs) => vs.iter().try_for_each(|v| write!(f, "{v:02x}")),
            Self::Fuzzy(vs) => vs.iter().try_for_each(|p| p.fmt(f)),
        }
    }
}

impl MatchesRule for BMatcher {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        project.memory().regions().iter(..).any(|(_, r)| {
            tracing::trace!(
                "scanning for {self} in region {}-{}",
                r.bounds().start,
                r.bounds().end
            );
            if let Some(found) = self.position(r.bytes()) {
                let position = *r.address() + found;

                tracing::trace!("found {self} at {}", position);

                context.describe(FwHuntCheckMatch::Pattern {
                    value: self.to_string(),
                    length: self.len(),
                    location: FwHuntCheckLocation::Address {
                        value: position.offset(),
                    },
                });
                context.push_provenance(position);

                true
            } else {
                false
            }
        })
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        if let Some(position) = self.position(bytes) {
            context.describe(FwHuntCheckMatch::Pattern {
                value: self.to_string(),
                length: self.len(),
                location: FwHuntCheckLocation::Offset {
                    value: position as _,
                },
            });
            context.push_provenance(position as u64);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_matching() {
        let matcher = BMatcher::from_iter(
            [
                BMatch::val(0x10),
                BMatch::val_with(0, 0), // any
                BMatch::val(0x20),
            ]
            .into_iter(),
        );

        assert_eq!(matcher.matches(b"\x10\x88\x20"), true);
        assert_eq!(matcher.matches(b"\x10\x88\x40"), false);
        assert_eq!(matcher.matches(b"\x10\x88"), false);
        assert_eq!(matcher.matches_exact(b"\x99\x10\x88\x20"), false);
        assert_eq!(matcher.matches(b"\x99\x10\x88\x20"), true);
    }

    #[test]
    fn test_matching_parse() {
        let matcher = BMatcher::from_str(".0..20");

        assert!(matcher.is_ok());

        let matcher = matcher.unwrap();

        assert_eq!(matcher.matches(b"\x10\x88\x20"), true);
        assert_eq!(matcher.matches(b"\x10\x88\x40"), false);
        assert_eq!(matcher.matches(b"\x10\x88"), false);
        assert_eq!(matcher.matches_exact(b"\x99\x10\x88\x20"), false);
        assert_eq!(matcher.matches(b"\x99\x10\x88\x20"), true);
    }

    #[test]
    fn test_matching_parse_fixed() {
        let matcher = BMatcher::from_str("deadf00d");

        assert!(matcher.is_ok());

        let matcher = matcher.unwrap();

        assert!(matches!(matcher, BMatcher::Fixed(_)));

        assert_eq!(matcher.matches(b"\xde\xad\xf0\x0d"), true);

        assert_eq!(matcher.to_string(), "deadf00d");
    }
}
