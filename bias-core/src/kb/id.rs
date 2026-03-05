use std::hash::Hash;

pub use slab;

use super::Uuid;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct UniqueId(Uuid, u64);

impl UniqueId {
    pub fn from_parts(uuid: Uuid, key: u64) -> Self {
        Self(uuid, key)
    }
}

pub trait MKey:
    Copy
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Hash
    + serde::Serialize
    + for<'de> serde::Deserialize<'de>
{
    const TID: Uuid;

    fn uid(&self) -> UniqueId;
    fn index(&self) -> usize;

    fn from_index(index: usize) -> Self;
}

#[macro_export]
macro_rules! define_mtable_key {
    ($name:ident, $uuid:tt) => {
        #[derive(
            Copy,
            Clone,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[repr(transparent)]
        pub struct $name(usize);

        impl Default for $name {
            fn default() -> Self {
                Self(usize::MAX)
            }
        }

        impl $crate::kb::id::MKey for $name {
            const TID: $crate::kb::Uuid = $crate::kb::uuid($uuid);

            fn uid(&self) -> $crate::kb::id::UniqueId {
                $crate::kb::id::UniqueId::from_parts(Self::TID, self.0 as u64)
            }

            fn index(&self) -> usize {
                self.0
            }

            fn from_index(index: usize) -> Self {
                Self(index)
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", <$name as $crate::kb::id::MKey>::index(self))
            }
        }
    };
}

pub trait Identifiable: Sized {
    type Key;

    fn id(&self) -> Self::Key;
    fn id_mut(&mut self) -> &mut Self::Key;

    fn update_id(&mut self, id: Self::Key) {
        *self.id_mut() = id;
    }
}
