use std::borrow::Borrow;
use std::fmt::Display;

use encode_unicode::error::{Utf16PairError, Utf8Error};
use encode_unicode::{IterExt, StrExt};
use thiserror::Error;

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum StringData {
    Ascii,
    Utf8,
    Utf16Be,
    Utf16Le,
}

impl Display for StringData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ascii => f.write_str("ascii"),
            Self::Utf8 => f.write_str("utf8"),
            Self::Utf16Be => f.write_str("utf16-be"),
            Self::Utf16Le => f.write_str("utf16-le"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(#[from] Utf8Error),
    #[error("invalid utf-16: {0}")]
    InvalidUtf16(#[from] Utf16PairError),
    #[error("cannot represent string using encoding")]
    ImpossibleEncode,
}

impl StringData {
    pub fn len(self, bytes: &[u8]) -> usize {
        self.nbytes_with(bytes, false).unwrap()
    }

    pub fn len_with_nul(self, bytes: &[u8]) -> Option<usize> {
        self.nbytes_with(bytes, true)
    }

    fn nbytes_with(self, bytes: &[u8], check_nul: bool) -> Option<usize> {
        let length = match self {
            Self::Ascii => bytes
                .iter()
                .to_utf8chars()
                .take_while(|v| matches!(v, Ok(c) if c.is_ascii() && c.to_char() != '\0'))
                .map(|v| v.unwrap().len())
                .sum(),
            Self::Utf8 => bytes
                .iter()
                .to_utf8chars()
                .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                .map(|v| v.unwrap().len())
                .sum(),
            Self::Utf16Le => bytes[..bytes.len() & !1]
                .chunks(2)
                .map(|chunk| (chunk[1] as u16) << 8 | chunk[0] as u16)
                .to_utf16chars()
                .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                .map(|v| v.unwrap().len() * 2)
                .sum(),
            Self::Utf16Be => bytes[..bytes.len() & !1]
                .chunks(2)
                .map(|chunk| (chunk[0] as u16) << 8 | chunk[1] as u16)
                .to_utf16chars()
                .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                .map(|v| v.unwrap().len() * 2)
                .sum(),
        };

        // check for NUL
        if check_nul && (bytes.len() == length || bytes[length] != 0) {
            None
        } else {
            Some(length)
        }
    }

    pub fn chars(self, bytes: &[u8]) -> (usize, usize) {
        self.nchars_with(bytes, false).unwrap()
    }

    pub fn chars_with_nul(self, bytes: &[u8]) -> Option<(usize, usize)> {
        self.nchars_with(bytes, true)
    }

    fn nchars_with(self, bytes: &[u8], check_nul: bool) -> Option<(usize, usize)> {
        let (count, length) = match self {
            Self::Ascii => bytes
                .iter()
                .to_utf8chars()
                .take_while(|v| matches!(v, Ok(c) if c.is_ascii() && c.to_char() != '\0'))
                .fold((0, 0), |(ac, ab), v| (ac + 1, ab + v.unwrap().len())),
            Self::Utf8 => bytes
                .iter()
                .to_utf8chars()
                .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                .fold((0, 0), |(ac, ab), v| (ac + 1, ab + v.unwrap().len())),
            Self::Utf16Le => bytes[..bytes.len() & !1]
                .chunks(2)
                .map(|chunk| (chunk[1] as u16) << 8 | chunk[0] as u16)
                .to_utf16chars()
                .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                .fold((0, 0), |(ac, ab), v| (ac + 1, ab + v.unwrap().len() * 2)),
            Self::Utf16Be => bytes[..bytes.len() & !1]
                .chunks(2)
                .map(|chunk| (chunk[0] as u16) << 8 | chunk[1] as u16)
                .to_utf16chars()
                .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                .fold((0, 0), |(ac, ab), v| (ac + 1, ab + v.unwrap().len() * 2)),
        };

        // check for NUL
        if check_nul && (bytes.len() == length || bytes[length] != 0) {
            None
        } else {
            Some((count, length))
        }
    }

    pub fn decode(self, bytes: &[u8]) -> Result<String, Error> {
        match self {
            Self::Ascii => {
                let s = bytes
                    .iter()
                    .to_utf8chars()
                    .take_while(|v| matches!(v, Ok(c) if c.is_ascii() && c.to_char() != '\0'))
                    .collect::<Result<String, _>>()?;
                Ok(s.into())
            }
            Self::Utf8 => {
                let s = bytes
                    .iter()
                    .to_utf8chars()
                    .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                    .collect::<Result<String, _>>()?;
                Ok(s.into())
            }
            Self::Utf16Le => {
                let s = bytes[..bytes.len() & !1]
                    .chunks(2)
                    .map(|chunk| (chunk[1] as u16) << 8 | chunk[0] as u16)
                    .to_utf16chars()
                    .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                    .collect::<Result<String, _>>()?;
                Ok(s.into())
            }
            Self::Utf16Be => {
                let s = bytes[..bytes.len() & !1]
                    .chunks(2)
                    .map(|chunk| (chunk[0] as u16) << 8 | chunk[1] as u16)
                    .to_utf16chars()
                    .take_while(|v| matches!(v, Ok(c) if c.to_char() != '\0'))
                    .collect::<Result<String, _>>()?;
                Ok(s.into())
            }
        }
    }

    pub fn encode<S>(self, s: S) -> Result<Vec<u8>, Error>
    where
        S: Borrow<str>,
    {
        let mut buf = Vec::with_capacity(0);
        self.encode_into(s, &mut buf)?;
        Ok(buf)
    }

    pub fn encode_with_nul<S>(self, s: S) -> Result<Vec<u8>, Error>
    where
        S: Borrow<str>,
    {
        let mut buf = Vec::with_capacity(0);
        self.encode_into_with_nul(s, &mut buf)?;
        Ok(buf)
    }

    pub fn encode_into<S>(self, s: S, bytes: &mut Vec<u8>) -> Result<(), Error>
    where
        S: Borrow<str>,
    {
        let s = s.borrow();
        match self {
            Self::Ascii => {
                if s.chars().any(|c| !c.is_ascii() || c == '\0') {
                    Err(Error::ImpossibleEncode)
                } else {
                    bytes.extend(s.as_bytes());
                    Ok(())
                }
            }
            Self::Utf8 => {
                bytes.extend(s.as_bytes());
                Ok(())
            }
            Self::Utf16Le => {
                s.utf16chars().for_each(|c| {
                    let (h1, h2) = c.to_tuple();
                    bytes.push((h1 & 0xff) as u8);
                    bytes.push((h1 >> 8) as u8);
                    if let Some(h2) = h2 {
                        bytes.push((h2 & 0xff) as u8);
                        bytes.push((h2 >> 8) as u8);
                    }
                });
                Ok(())
            }
            Self::Utf16Be => {
                s.utf16chars().for_each(|c| {
                    let (h1, h2) = c.to_tuple();
                    bytes.push((h1 >> 8) as u8);
                    bytes.push((h1 & 0xff) as u8);
                    if let Some(h2) = h2 {
                        bytes.push((h2 >> 8) as u8);
                        bytes.push((h2 & 0xff) as u8);
                    }
                });
                Ok(())
            }
        }
    }

    pub fn encode_into_with_nul<S>(self, s: S, bytes: &mut Vec<u8>) -> Result<(), Error>
    where
        S: Borrow<str>,
    {
        self.encode_into(s, bytes)?;
        bytes.push(0);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decode() {
        let not_wide = b"foo\0";
        let definitely_wide = b"f\0o\0o\0";
        let definitely_wide_be = b"\0f\0o\0o\0\0";

        assert_eq!(StringData::Ascii.decode(not_wide).as_deref(), Ok("foo"));
        assert_eq!(
            StringData::Utf16Le.decode(definitely_wide).as_deref(),
            Ok("foo")
        );
        assert_eq!(
            StringData::Utf16Be.decode(definitely_wide_be).as_deref(),
            Ok("foo")
        );
    }

    #[test]
    fn test_decode_len() {
        let not_wide = b"foo\0";
        let definitely_wide = b"f\0o\0o\0";
        let definitely_wide_be = b"\0f\0o\0o\0";

        assert_eq!(StringData::Ascii.len(not_wide), 3);
        assert_eq!(StringData::Utf16Le.len_with_nul(definitely_wide), None);
        assert_eq!(StringData::Utf16Le.len(definitely_wide), 6);
        assert_eq!(
            StringData::Utf16Be.len_with_nul(definitely_wide_be),
            Some(6)
        );
    }

    #[test]
    fn test_encode() {
        let not_wide = b"foo";
        let definitely_wide = b"f\0o\0o\0";
        let definitely_wide_be = b"\0f\0o\0o";

        assert_eq!(
            StringData::Ascii.encode("foo").as_deref(),
            Ok(&not_wide[..])
        );
        assert_eq!(
            StringData::Utf16Le.encode("foo").as_deref(),
            Ok(&definitely_wide[..])
        );
        assert_eq!(
            StringData::Utf16Be.encode("foo").as_deref(),
            Ok(&definitely_wide_be[..])
        );

        assert_eq!(
            StringData::Utf16Le.encode("$").as_deref(),
            Ok(&[0x24u8, 0x00][..])
        );
        assert_eq!(
            StringData::Utf16Be.encode("$").as_deref(),
            Ok(&[0x00u8, 0x24][..])
        );

        assert_eq!(
            StringData::Utf16Le.encode("€").as_deref(),
            Ok(&[0xacu8, 0x20][..])
        );
        assert_eq!(
            StringData::Utf16Be.encode("€").as_deref(),
            Ok(&[0x20u8, 0xac][..])
        );
    }
}
