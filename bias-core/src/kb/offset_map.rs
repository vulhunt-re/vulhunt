use std::borrow::Borrow;
use std::collections::BTreeMap;

use crate::cio::TypeDB;
use crate::ir::{Address, BitVec, Term, Type};

#[derive(Debug, Clone)]
enum OffsetOrValue<K, V>
where
    K: OffsetLike,
{
    Offset(K, usize),
    Value(V),
}

pub trait OffsetLike: PartialEq + Eq + PartialOrd + Ord {
    fn offset_at(&self, offset: usize) -> Self;
}

impl OffsetLike for i64 {
    fn offset_at(&self, offset: usize) -> Self {
        self.wrapping_add(offset as i64)
    }
}

impl OffsetLike for u64 {
    fn offset_at(&self, offset: usize) -> Self {
        self.wrapping_add(offset as u64)
    }
}

impl OffsetLike for Address {
    fn offset_at(&self, offset: usize) -> Self {
        *self + offset
    }
}

pub trait OffsetValue: Sized {
    fn value_at(&self, offset: usize) -> Option<Self>;
    fn value_size(&self) -> usize;
}

impl OffsetValue for BitVec {
    fn value_at(&self, offset: usize) -> Option<Self> {
        if offset == 0 {
            return Some(self.clone());
        }

        let nbits = self.bits() as u32;
        let shift = (offset * 8) as u32;

        if let Some(nsize) = nbits.checked_sub(shift) {
            Some((self >> shift).cast(nsize as usize))
        } else {
            None
        }
    }

    fn value_size(&self) -> usize {
        self.bits() / 8
    }
}

impl OffsetValue for Term<Type> {
    fn value_at(&self, offset: usize) -> Option<Self> {
        self.type_at_offset(offset)
    }

    fn value_size(&self) -> usize {
        self.nbytes()
    }
}

pub trait OffsetValueWith<T>: Sized {
    fn value_at_with(&self, offset: usize, with: &T) -> Option<Self>;
    fn value_size_with(&self, with: &T) -> usize;
}

impl OffsetValueWith<TypeDB> for Term<Type> {
    fn value_at_with(&self, offset: usize, with: &TypeDB) -> Option<Self> {
        self.resolve(with).type_at_offset(offset)
    }

    fn value_size_with(&self, _with: &TypeDB) -> usize {
        self.nbytes()
    }
}

#[derive(Debug, Clone)]
pub struct OffsetMap<K, V>
where
    K: OffsetLike,
{
    mapping: BTreeMap<K, OffsetOrValue<K, V>>,
}

impl<K, V> Default for OffsetMap<K, V>
where
    K: OffsetLike,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> OffsetMap<K, V>
where
    K: OffsetLike,
{
    pub fn new() -> Self {
        Self {
            mapping: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.mapping.iter().filter_map(|(k, v)| match v {
            OffsetOrValue::Value(ref v) => Some((k, v)),
            OffsetOrValue::Offset(_, _) => None,
        })
    }
}

impl<K, V> OffsetMap<K, V>
where
    K: OffsetLike,
    V: OffsetValue,
{
    #[inline]
    pub fn get_at<Q>(&self, offset: &Q) -> Option<V>
    where
        Q: Borrow<K>,
    {
        match self.mapping.get(offset.borrow())? {
            OffsetOrValue::Value(ref v) => v.value_at(0),
            OffsetOrValue::Offset(ref base, offset) => {
                if let Some(v) = self.get_at(base) {
                    v.value_at(*offset)
                } else {
                    None
                }
            }
        }
    }

    #[inline]
    pub fn set_at(&mut self, offset: K, value: V) {
        let sz = value.value_size();

        for off in 1..sz {
            self.mapping.insert(
                offset.offset_at(off),
                OffsetOrValue::Offset(offset.offset_at(0), off),
            );
        }

        self.mapping.insert(offset, OffsetOrValue::Value(value));
    }
}

impl<K, V> OffsetMap<K, V>
where
    K: OffsetLike,
{
    #[inline]
    pub fn get_at_with<Q, T>(&self, offset: &Q, with: &T) -> Option<V>
    where
        Q: Borrow<K>,
        V: OffsetValueWith<T>,
    {
        match self.mapping.get(offset.borrow())? {
            OffsetOrValue::Value(ref v) => v.value_at_with(0, with),
            OffsetOrValue::Offset(ref base, offset) => {
                if let Some(v) = self.get_at_with(base, with) {
                    v.value_at_with(*offset, with)
                } else {
                    None
                }
            }
        }
    }

    #[inline]
    pub fn set_at_with<T>(&mut self, offset: K, value: V, with: &T)
    where
        V: OffsetValueWith<T>,
    {
        let sz = value.value_size_with(with);

        for off in 1..sz {
            self.mapping.insert(
                offset.offset_at(off),
                OffsetOrValue::Offset(offset.offset_at(0), off),
            );
        }

        self.mapping.insert(offset, OffsetOrValue::Value(value));
    }
}
