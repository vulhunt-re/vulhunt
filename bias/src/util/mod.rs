use std::borrow::Cow;
use std::fmt::Debug;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Error;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;

pub mod tags;
pub mod version;

#[derive(Clone)]
pub enum OwnedOrRef<'a, T> {
    Owned(T),
    Ref(&'a T),
}

impl<'a, T> Debug for OwnedOrRef<'a, T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owned(ref t) => t.fmt(f),
            Self::Ref(t) => t.fmt(f),
        }
    }
}

impl<'a, T> PartialEq<T> for OwnedOrRef<'a, T>
where
    T: PartialEq,
{
    fn eq(&self, other: &T) -> bool {
        match self {
            Self::Owned(ref t) => t.eq(other),
            Self::Ref(t) => (&**t).eq(other),
        }
    }
}

impl<'a, T> PartialEq<OwnedOrRef<'a, T>> for OwnedOrRef<'a, T>
where
    T: PartialEq,
{
    fn eq(&self, other: &OwnedOrRef<'a, T>) -> bool {
        self.deref().eq(other.deref())
    }
}

impl<'a, T> Eq for OwnedOrRef<'a, T> where T: Eq {}

impl<'a, T> PartialOrd<T> for OwnedOrRef<'a, T>
where
    T: PartialOrd,
{
    fn partial_cmp(&self, other: &T) -> Option<std::cmp::Ordering> {
        self.deref().partial_cmp(other)
    }
}

impl<'a, T> PartialOrd<OwnedOrRef<'a, T>> for OwnedOrRef<'a, T>
where
    T: PartialOrd,
{
    fn partial_cmp(&self, other: &OwnedOrRef<'a, T>) -> Option<std::cmp::Ordering> {
        self.deref().partial_cmp(other.deref())
    }
}

impl<'a, T> Ord for OwnedOrRef<'a, T>
where
    T: Ord,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}

impl<T> Hash for OwnedOrRef<'_, T>
where
    T: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Owned(ref t) => t.hash(state),
            Self::Ref(t) => t.hash(state),
        }
    }
}

impl<'a, T> AsRef<T> for OwnedOrRef<'a, T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Owned(ref t) => t,
            Self::Ref(t) => t,
        }
    }
}

impl<'a, T> Deref for OwnedOrRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T> From<&'a T> for OwnedOrRef<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::Ref(value)
    }
}

impl<'a, T> From<T> for OwnedOrRef<'a, T> {
    fn from(value: T) -> Self {
        Self::Owned(value)
    }
}

pub enum BytesOrMapping<'a> {
    Bytes(Cow<'a, [u8]>),
    Mapping(Mmap),
}

impl<'a> AsRef<[u8]> for BytesOrMapping<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_ref(),
            Self::Mapping(mapping) => mapping.as_ref(),
        }
    }
}

impl<'a> Deref for BytesOrMapping<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T> From<T> for BytesOrMapping<'a>
where
    T: Into<Cow<'a, [u8]>> + 'a,
{
    fn from(value: T) -> Self {
        Self::Bytes(value.into())
    }
}

impl<'a> BytesOrMapping<'a> {
    pub fn from_bytes(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        BytesOrMapping::Bytes(bytes.into())
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(BytesOrMapping::Mapping(unsafe {
            Mmap::map(&File::open(&path)?)?
        }))
    }

    pub unsafe fn from_existing(file: &File) -> Result<Self, Error> {
        Ok(BytesOrMapping::Mapping(unsafe { Mmap::map(file)? }))
    }

    pub fn into_owned(self) -> BytesOrMapping<'static> {
        match self {
            Self::Bytes(bytes) => BytesOrMapping::Bytes(Cow::Owned(bytes.into_owned())),
            Self::Mapping(mapping) => BytesOrMapping::Mapping(mapping),
        }
    }

    pub fn into_shared(self) -> SharedBytesOrMapping<'a> {
        SharedBytesOrMapping(Arc::new(self))
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct SharedBytesOrMapping<'a>(Arc<BytesOrMapping<'a>>);

impl<'a> AsRef<[u8]> for SharedBytesOrMapping<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> Deref for SharedBytesOrMapping<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<'a, T> From<T> for SharedBytesOrMapping<'a>
where
    T: Into<Cow<'a, [u8]>> + 'a,
{
    fn from(value: T) -> Self {
        BytesOrMapping::Bytes(value.into()).into_shared()
    }
}

impl<'a> From<BytesOrMapping<'a>> for SharedBytesOrMapping<'a> {
    fn from(value: BytesOrMapping<'a>) -> Self {
        value.into_shared()
    }
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    #[test]
    fn test_owned_or_ref() {
        let owned = OwnedOrRef::Owned(42);
        let reference = OwnedOrRef::Ref(&42);

        assert_eq!(owned, 42);
        assert_eq!(reference, 42);
        assert_eq!(owned, reference);

        assert!(owned <= reference && owned >= reference);

        let mut bts = BTreeSet::new();
        bts.insert(owned);

        let mut bts2 = BTreeSet::new();
        bts2.insert(reference);

        assert_eq!(bts, bts2);

        let diff = bts.difference(&bts2).collect::<Vec<_>>();

        assert!(diff.is_empty());

        bts.insert(OwnedOrRef::Ref(&43));

        let diff = bts.difference(&bts2).collect::<Vec<_>>();

        assert_eq!(diff.len(), 1);

        let mut hs = HashSet::new();

        let owned = OwnedOrRef::Owned(42);
        let reference = OwnedOrRef::Ref(&42);

        hs.extend([owned, reference, OwnedOrRef::Ref(&43)]);

        assert_eq!(hs.len(), 2);
    }
}
