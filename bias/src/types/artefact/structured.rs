use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types::common::{AttributeMap, Fingerprint, FingerprintBuilder, OrderedValue, DEFAULT_FILTERS};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StructuredData {
    data: Value,
    description: Option<Cow<'static, str>>,
    attributes: AttributeMap,
}

impl StructuredData {
    pub fn new<T>(data: T) -> Self
    where
        T: Serialize,
    {
        Self {
            data: json!(data),
            description: None,
            attributes: AttributeMap::new(),
        }
    }

    pub fn data(&self) -> &Value {
        &self.data
    }

    pub fn into_data(self) -> Value {
        self.data
    }

    pub fn data_as<T: DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_value(self.data.clone()).ok()
    }

    pub fn data_into<T: DeserializeOwned>(self) -> Option<T> {
        serde_json::from_value(self.data).ok()
    }

    pub fn set_data<T>(&mut self, data: T)
    where
        T: Serialize,
    {
        self.data = json!(data);
    }

    pub fn with_data<T>(mut self, data: T) -> Self
    where
        T: Serialize,
    {
        self.set_data(data);
        self
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
        let mut builder = FingerprintBuilder::new();

        builder.push_fingerprint(Fingerprint::new_attrs(&self.attributes));
        builder.push_fingerprint(
            OrderedValue::new_filtered(self.data(), DEFAULT_FILTERS.as_ref()).fingerprint(),
        );

        Some(builder.build())
    }
}
