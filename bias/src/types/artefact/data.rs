use std::borrow::Cow;
use std::ops::{Bound, Index, Range, RangeBounds};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::common::{AttributeMap, Fingerprint};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RawData {
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    description: Option<Cow<'static, str>>,
    source: Option<String>,
    variant_of: Option<usize>,
    attributes: AttributeMap,
}

impl RawData {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            description: None,
            source: None,
            variant_of: None,
            attributes: AttributeMap::new(),
        }
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_description(&mut self, description: impl Into<Cow<'static, str>>) {
        self.description = Some(description.into());
    }

    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.set_description(description);
        self
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn set_data(&mut self, data: impl Into<Vec<u8>>) {
        self.data = data.into();
    }

    pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.set_data(data);
        self
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn set_source(&mut self, source: impl Into<String>) {
        self.source = Some(source.into());
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.set_source(source);
        self
    }

    pub fn variant_of(&self) -> Option<usize> {
        self.variant_of
    }

    pub fn set_variant_of(&mut self, index: usize) {
        self.variant_of = Some(index);
    }

    pub fn with_variant_of(mut self, index: usize) -> Self {
        self.set_variant_of(index);
        self
    }

    pub fn set_attr(&mut self, name: impl Into<Cow<'static, str>>, value: impl Serialize) {
        self.attributes
            .insert(name.into(), serde_json::json!(value));
    }

    pub fn get_attr<V: DeserializeOwned>(&self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .get(name.as_ref())
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }

    pub fn remove_attr(&mut self, name: impl AsRef<str>) -> Option<serde_json::Value> {
        self.attributes.remove(name.as_ref())
    }

    pub fn remove_attr_as<V: DeserializeOwned>(&mut self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .remove(name.as_ref())
            .and_then(|v| serde_json::from_value(v).ok())
    }

    pub fn set_attrs(&mut self, values: impl Serialize) {
        let serde_json::Value::Object(object) = serde_json::json!(values) else {
            return;
        };

        self.attributes
            .extend(object.into_iter().map(|(k, v)| (Cow::Owned(k), v)));
    }

    pub fn get_attrs<V: DeserializeOwned>(&self) -> Option<V> {
        let object = serde_json::Value::Object(
            self.attributes
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.to_owned()))
                .collect(),
        );

        serde_json::from_value(object).ok()
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        Some(Fingerprint::new_attrs(&self.attributes))
    }
}

impl Index<Range<usize>> for RawData {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<OffsetRange> for RawData {
    type Output = [u8];

    fn index(&self, index: OffsetRange) -> &Self::Output {
        &self.data[Range::<usize>::from(index)]
    }
}

#[derive(Debug, Error)]
pub enum RawDataError {
    #[error("invalid artefact variant index")]
    InvalidVariantIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct OffsetRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Error)]
#[error("empty range; start >= end")]
pub struct OffsetRangeError;

impl From<Range<usize>> for OffsetRange {
    fn from(value: Range<usize>) -> Self {
        Self {
            start: value.start as _,
            end: value.end as _,
        }
    }
}

impl From<OffsetRange> for Range<usize> {
    fn from(value: OffsetRange) -> Self {
        Self {
            start: value.start as _,
            end: value.end as _,
        }
    }
}

impl From<Range<u64>> for OffsetRange {
    fn from(value: Range<u64>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<OffsetRange> for Range<u64> {
    fn from(value: OffsetRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl RangeBounds<u64> for OffsetRange {
    fn start_bound(&self) -> Bound<&u64> {
        Bound::Included(&self.start)
    }

    fn end_bound(&self) -> Bound<&u64> {
        Bound::Excluded(&self.end)
    }
}

impl OffsetRange {
    pub fn new(start: u64, end: u64) -> Self {
        assert!(start < end);

        Self { start, end }
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }
}
