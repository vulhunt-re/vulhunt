use std::borrow::Cow;

use crate::fugue::bytes::Endian;
use crate::ir::Address;
use crate::lifter::Lifter;
use crate::loader::{LoadedBinary, LoaderBytes, LoaderContainer, LoaderFunction, LoaderRegion};

#[derive(Debug, Clone)]
pub struct Shellcode {
    bytes: Vec<u8>,
    base: Address,
    endian: Endian,
    entry: Option<Address>,
}

impl Shellcode {
    pub fn new(lifter: &Lifter, addr: impl Into<Address>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            base: addr.into(),
            endian: lifter.endian(),
            entry: None,
        }
    }

    pub fn set_entry(&mut self, entry: impl Into<Address>) {
        let entry = entry.into();
        if entry >= self.base && entry < self.base + self.bytes.len() {
            self.entry = Some(entry.into());
        } else {
            self.entry = None;
        }
    }
}

impl LoadedBinary for Shellcode {
    fn for_each_region<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
        if self.bytes.is_empty() {
            return;
        }

        f(&LoaderRegion {
            name: Some("code".into()),
            code: true,
            read_only: true,
            uninitialised: None,
            bounds: self.base..self.base + self.bytes.len(),
            endian: self.endian,
            bytes: Cow::Borrowed(&self.bytes),
        })
    }

    fn for_each_function<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderFunction<'a>),
    {
        if let Some(entry) = self.entry {
            f(&LoaderFunction {
                entry,
                name: Some("entry".into()),
                ..Default::default()
            })
        }
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        LoaderBytes::Borrowed(&self.bytes)
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        LoaderContainer::new(self.bytes())
    }

    fn entry_point(&self) -> Option<Address> {
        if self.bytes.is_empty() {
            None
        } else {
            Some(self.entry.unwrap_or(self.base))
        }
    }
}
