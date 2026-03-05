use std::marker::PhantomData;
use std::str::FromStr;

use bias_core::prelude::ArchitectureDef;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) struct VecMapVisitor<K, V> {
    _marker: PhantomData<(K, V)>,
}

impl<K, V> VecMapVisitor<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<'de, K, V> Visitor<'de> for VecMapVisitor<K, V>
where
    K: Deserialize<'de>,
    V: Deserialize<'de>,
{
    type Value = Vec<(K, V)>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Map<K, V>")
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<Vec<(K, V)>, E> {
        Ok(Vec::new())
    }

    #[inline]
    fn visit_seq<T>(self, mut access: T) -> Result<Vec<(K, V)>, T::Error>
    where
        T: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_element::<(K, V)>()? {
            values.push((key, value));
        }

        Ok(values)
    }

    #[inline]
    fn visit_map<T>(self, mut access: T) -> Result<Vec<(K, V)>, T::Error>
    where
        T: MapAccess<'de>,
    {
        let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            values.push((key, value));
        }

        Ok(values)
    }
}

pub(crate) struct VecMapWrapper<K, V>(pub(crate) Vec<(K, V)>);

impl<'de, K, V> Deserialize<'de> for VecMapWrapper<K, V>
where
    K: Deserialize<'de>,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VecMapVisitor::new()).map(Self)
    }
}

impl<K, V> VecMapWrapper<K, V> {
    #[allow(unused)]
    pub(crate) fn into_inner(self) -> Vec<(K, V)> {
        self.0
    }
}

pub struct AsArchStr<'a>(&'a ArchitectureDef);

impl<'a> AsArchStr<'a> {
    pub fn new(arch: &'a ArchitectureDef) -> Self {
        Self(arch)
    }
}

impl<'a> Serialize for AsArchStr<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{}:{}:{}",
            self.0.processor(),
            if self.0.endian().is_big() { "BE" } else { "LE" },
            self.0.bits(),
        ))
    }
}

pub(crate) fn arch_deserialiser<'de, D>(
    deserialiser: D,
) -> Result<Option<ArchitectureDef>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let arch: Option<String> = Option::deserialize(deserialiser)?;

    Ok(arch
        .as_deref()
        .and_then(|arch| ArchitectureDef::from_str(arch).ok()))
}

pub(crate) fn arch_serialiser<S>(
    arch: &Option<ArchitectureDef>,
    serialiser: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match arch {
        Some(architecture) => serialiser.serialize_some(&format!(
            "{}:{}:{}",
            architecture.processor(),
            if architecture.endian().is_big() {
                "BE"
            } else {
                "LE"
            },
            architecture.bits(),
        )),
        None => serialiser.serialize_none(),
    }
}
