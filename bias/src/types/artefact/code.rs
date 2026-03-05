use std::borrow::Cow;
use std::ops::{Bound, Index, Range, RangeBounds};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::common::{AttributeMap, Fingerprint};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CodeListing {
    listing: String,
    description: Option<Cow<'static, str>>,
    source: Option<String>,
    variant_of: Option<usize>,
    attributes: AttributeMap,
}

impl CodeListing {
    pub fn new(listing: impl Into<String>) -> Self {
        Self {
            listing: listing.into(),
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

    pub fn listing(&self) -> &str {
        &self.listing
    }

    pub fn into_listing(self) -> String {
        self.listing
    }

    pub fn set_listing(&mut self, listing: impl Into<String>) {
        self.listing = listing.into();
    }

    pub fn with_listing(mut self, listing: impl Into<String>) -> Self {
        self.set_listing(listing);
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

impl Index<Range<usize>> for CodeListing {
    type Output = str;

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.listing[index]
    }
}

impl Index<CodeRange> for CodeListing {
    type Output = str;

    fn index(&self, index: CodeRange) -> &Self::Output {
        &self.listing[Range::<usize>::from(index)]
    }
}

#[derive(Debug, Error)]
pub enum CodeListingError {
    #[error("invalid artefact variant index")]
    InvalidVariantIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct CodeRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Error)]
#[error("empty range; start >= end")]
pub struct CodeRangeError;

impl From<Range<usize>> for CodeRange {
    fn from(value: Range<usize>) -> Self {
        Self {
            start: value.start as _,
            end: value.end as _,
        }
    }
}

impl From<CodeRange> for Range<usize> {
    fn from(value: CodeRange) -> Self {
        Self {
            start: value.start as _,
            end: value.end as _,
        }
    }
}

impl From<Range<u64>> for CodeRange {
    fn from(value: Range<u64>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<CodeRange> for Range<u64> {
    fn from(value: CodeRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl RangeBounds<u64> for CodeRange {
    fn start_bound(&self) -> Bound<&u64> {
        Bound::Included(&self.start)
    }

    fn end_bound(&self) -> Bound<&u64> {
        Bound::Excluded(&self.end)
    }
}

impl CodeRange {
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
