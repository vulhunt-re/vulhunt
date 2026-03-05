use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;

use bias_core::kb::Lazy;
use hex_display::HexDisplayExt;
use ordered_float::OrderedFloat;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::VariantNames;
use strum_macros::VariantNames;

use crate::platform::common::KeyValue;

pub use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Reference {
    #[serde(default)]
    description: String,
    #[serde(flatten)]
    value: ReferenceKind,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, VariantNames,
)]
#[non_exhaustive]
#[serde(tag = "kind")]
pub enum ReferenceKind {
    #[serde(rename = "url")]
    #[strum(serialize = "url")]
    Url { value: String },
}

impl ReferenceKind {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;
}

impl Reference {
    pub fn new(description: impl Into<String>, value: ReferenceKind) -> Self {
        Self {
            description: description.into(),
            value,
        }
    }

    pub fn new_url(description: impl Into<String>, url: impl Into<String>) -> Self {
        Self::new(description, ReferenceKind::Url { value: url.into() })
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn url(&self) -> Option<&str> {
        match self.value {
            ReferenceKind::Url { ref value } => Some(value),
        }
    }

    pub fn into_url(self) -> Option<String> {
        match self.value {
            ReferenceKind::Url { value } => Some(value),
        }
    }

    pub fn value(&self) -> &ReferenceKind {
        &self.value
    }

    pub fn into_value(self) -> ReferenceKind {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Note {
    title: String,
    content: String,
}

impl Note {
    pub fn new(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            content: content.into(),
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
    }

    pub fn into_parts(self) -> (String, String) {
        (self.title, self.content)
    }
}

pub type AttributeMap = BTreeMap<Cow<'static, str>, Value>;

impl FromIterator<KeyValue> for AttributeMap {
    fn from_iter<T: IntoIterator<Item = KeyValue>>(iter: T) -> Self {
        iter.into_iter()
            .map(|kv| {
                let (k, v) = kv.into_parts();
                (Cow::Owned(k), Value::String(v))
            })
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrderedNumber {
    PosInt(u64),
    NegInt(i64),
    Float(OrderedFloat<f64>),
}

impl OrderedNumber {
    pub(crate) fn new(value: &serde_json::Number) -> Self {
        if let Some(v) = value.as_u64() {
            Self::PosInt(v)
        } else if let Some(v) = value.as_i64() {
            Self::NegInt(v)
        } else {
            Self::Float(OrderedFloat(value.as_f64().unwrap()))
        }
    }

    pub(crate) fn to_builder(&self, builder: &mut FingerprintBuilder) {
        match self {
            Self::PosInt(v) => builder.push_field(b"posint$", v.to_le_bytes()),
            Self::NegInt(v) => builder.push_field(b"negint$", v.to_le_bytes()),
            Self::Float(v) => builder.push_field(b"float$", v.to_le_bytes()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrderedValue<'a> {
    Null,
    Bool(bool),
    Number(OrderedNumber),
    String(&'a str),
    Array(Vec<OrderedValue<'a>>),
    Object(BTreeMap<&'a str, OrderedValue<'a>>),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum OrderedValuePath<'a> {
    Field(&'a str),
    Index,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum OrderedValuePathFilterNode {
    #[allow(unused)]
    AnyField,
    Field(String),
    Index,
}

impl PartialEq<OrderedValuePath<'_>> for OrderedValuePathFilterNode {
    fn eq(&self, other: &OrderedValuePath<'_>) -> bool {
        match (self, other) {
            (Self::AnyField, OrderedValuePath::Field(_))
            | (Self::Index, OrderedValuePath::Index) => true,
            (Self::Field(a), OrderedValuePath::Field(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrderedValuePathFilter(Vec<OrderedValuePathFilterNode>);

impl From<Vec<OrderedValuePathFilterNode>> for OrderedValuePathFilter {
    fn from(path: Vec<OrderedValuePathFilterNode>) -> Self {
        Self(path)
    }
}

impl OrderedValuePathFilter {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn field(mut self, field: impl Into<String>) -> Self {
        self.0.push(OrderedValuePathFilterNode::Field(field.into()));
        self
    }

    pub(crate) fn index(mut self) -> Self {
        self.0.push(OrderedValuePathFilterNode::Index);
        self
    }

    pub(crate) fn matches_suffix(&self, path: &[OrderedValuePath<'_>]) -> bool {
        let slf = &self.0;

        if slf.len() > path.len() {
            return false;
        }

        let suffix = &path[(path.len() - slf.len())..];

        slf == suffix
    }
}

impl<'a> OrderedValue<'a> {
    #[allow(unused)]
    pub fn new(value: &'a Value) -> Self {
        Self::new_with(value, &mut Vec::with_capacity(3))
    }

    pub fn new_filtered(value: &'a Value, filters: &[OrderedValuePathFilter]) -> Self {
        Self::new_with_filtered(value, &mut Vec::with_capacity(3), filters)
    }

    #[allow(unused)]
    fn new_with(value: &'a Value, path: &mut Vec<OrderedValuePath<'a>>) -> Self {
        Self::new_with_filtered(value, path, &[])
    }

    fn new_with_filtered(
        value: &'a Value,
        path: &mut Vec<OrderedValuePath<'a>>,
        filters: &[OrderedValuePathFilter],
    ) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(v) => Self::Bool(*v),
            Value::Number(v) => Self::Number(OrderedNumber::new(v)),
            Value::String(v) => Self::String(v),
            Value::Array(vs) => {
                path.push(OrderedValuePath::Index);
                let mut vs = vs
                    .iter()
                    .filter_map(|v| {
                        if filters.iter().any(|f| f.matches_suffix(path)) {
                            None
                        } else {
                            Some(OrderedValue::new_with_filtered(v, path, filters))
                        }
                    })
                    .collect::<Vec<_>>();
                path.pop();
                vs.sort();
                Self::Array(vs)
            }
            Value::Object(vs) => Self::Object(
                vs.iter()
                    .filter_map(|(k, v)| {
                        path.push(OrderedValuePath::Field(k.as_ref()));
                        let kv = if filters.iter().any(|f| f.matches_suffix(path)) {
                            None
                        } else {
                            let v = OrderedValue::new_with_filtered(v, path, filters);
                            Some((k.as_ref(), v))
                        };
                        path.pop();
                        kv
                    })
                    .collect(),
            ),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut builder = FingerprintBuilder::new();
        self.to_builder(&mut builder);
        builder.build()
    }

    pub fn to_builder(&self, builder: &mut FingerprintBuilder) {
        match self {
            Self::Null => {
                builder.push(b"null");
            }
            Self::Bool(v) => {
                builder.push_field(
                    "bool$",
                    if *v {
                        b"true".as_slice()
                    } else {
                        b"false".as_slice()
                    },
                );
            }
            Self::Number(v) => {
                v.to_builder(builder);
            }
            Self::String(v) => builder.push_field("string$", v.as_bytes()),
            Self::Array(vs) => {
                let mut abuilder = FingerprintBuilder::new();
                vs.iter().for_each(|v| {
                    let mut ebuilder = FingerprintBuilder::new();
                    v.to_builder(&mut ebuilder);
                    abuilder.push_fingerprint_field("array-element$", ebuilder.build());
                });
                builder.push_fingerprint_field("array$", abuilder.build());
            }
            Self::Object(vs) => {
                let mut mbuilder = FingerprintBuilder::new();
                vs.iter().for_each(|(k, v)| {
                    let mut ebuilder = FingerprintBuilder::new();
                    v.to_builder(&mut ebuilder);
                    mbuilder.push_fingerprint_field(k.as_bytes(), ebuilder.build());
                });
                builder.push_fingerprint_field("object$", mbuilder.build());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Fingerprint(#[serde(with = "hex::serde")] [u8; 64]);

impl Default for Fingerprint {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hex().fmt(f)
    }
}

pub static DEFAULT_FILTERS: Lazy<Vec<OrderedValuePathFilter>> = Lazy::new(|| {
    vec![
        // FwHunt rule (due to non-deterministic order of fields)
        OrderedValuePathFilter::new().field("fwhunt-rule"),
        // table of functions with names (due to symbols)
        OrderedValuePathFilter::new()
            .field("functions")
            .index()
            .field("name"),
        // mitigation coverage summary tables (due to symbols)
        OrderedValuePathFilter::new()
            .field("found")
            .index()
            .field("name"),
        OrderedValuePathFilter::new()
            .field("missing")
            .index()
            .field("name"),
        // decompiler non-determinism
        OrderedValuePathFilter::new().field("rendered"),
    ]
});

impl Fingerprint {
    pub fn new(name: impl AsRef<str>, attrs: &AttributeMap) -> Self {
        let name = name.as_ref();
        let mut builder = FingerprintBuilder::new();

        builder.push_field("finding-name$", name);
        builder.push_fingerprint_field("attributes$", Self::new_attrs(attrs));
        builder.build()
    }

    pub fn new_attrs(attrs: &AttributeMap) -> Self {
        let mut mbuilder = FingerprintBuilder::new();

        for (k, v) in attrs.into_iter() {
            let mut ebuilder = FingerprintBuilder::new();
            let mut path = vec![OrderedValuePath::Field(&*k)];

            if DEFAULT_FILTERS.iter().any(|f| f.matches_suffix(&path)) {
                continue;
            }

            OrderedValue::new_with_filtered(v, &mut path, DEFAULT_FILTERS.as_ref())
                .to_builder(&mut ebuilder);

            mbuilder.push_fingerprint_field(k.as_bytes(), ebuilder.build());
        }

        mbuilder.build()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FingerprintBuilder {
    parts: Vec<[u8; 64]>,
}

impl FingerprintBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, part: impl AsRef<[u8]>) {
        self.parts
            .push(<sha2::Sha512 as sha2::Digest>::digest(part.as_ref()).into());
    }

    pub fn push_field(&mut self, field: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let mut data = Vec::new();
        data.extend(field.as_ref());
        data.extend(value.as_ref());
        self.push(data);
    }

    pub fn push_fingerprint_field(&mut self, id: impl AsRef<[u8]>, fingerprint: Fingerprint) {
        self.push_field(id, fingerprint.0.as_ref());
    }

    pub fn push_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.parts.push(fingerprint.0);
    }

    pub fn build(mut self) -> Fingerprint {
        use sha2::Digest;

        let mut hasher = <sha2::Sha512 as sha2::Digest>::new();

        self.parts.sort();

        let init = u64::to_le_bytes(self.parts.len() as u64);
        hasher.update(init.as_ref());

        for hash in self.parts {
            hasher.update(hash.as_ref());
        }

        Fingerprint(hasher.finalize().into())
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_reference_serde() -> Result<(), Box<dyn std::error::Error>> {
        let r = r#"{ "description": "My URL", "kind": "url", "value": "https://binarly.io" }"#;
        let p = serde_json::from_str::<Reference>(r)?;

        assert_eq!(p.description(), "My URL");
        assert_eq!(
            p.value(),
            &ReferenceKind::Url {
                value: String::from("https://binarly.io")
            }
        );

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_fingerprint_filters() -> Result<(), Box<dyn std::error::Error>> {
        let ov0 = json!({
            "my-var": [
                {
                    "functions": [
                        { "name": "some_name", "address": 0x1000 },
                        { "name": "other_name", "address": 0x1004 },
                    ]
                }
           ]
        });

        let ov1 = json!({
            "functions": [{
                   "functions": [
                        { "function_name": "hello", "address": 0x1000 },
                        { "function_name": "hello1", "address": 0x1004 },
                    ]
            }]
        });

        println!("{:#?}", OrderedValue::new(&ov0));
        println!("{:#?}", OrderedValue::new_filtered(&ov0, &DEFAULT_FILTERS));

        println!("{:#?}", OrderedValue::new(&ov1));
        println!("{:#?}", OrderedValue::new_filtered(&ov1, &DEFAULT_FILTERS));

        Ok(())
    }
}
