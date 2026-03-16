use std::borrow::Borrow;
use std::collections::BTreeMap;

use crate::types::common::AttributeMap;

pub mod analysis;
pub mod attrs;
pub mod data;
pub mod flirt;
pub mod fspec;
pub mod types;

pub use attrs::*;
pub use types::TypeManager;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PlatformAttributeMap(BTreeMap<String, serde_json::Value>);

impl From<PlatformAttributeMap> for BTreeMap<String, serde_json::Value> {
    fn from(value: PlatformAttributeMap) -> Self {
        value.0
    }
}

impl From<BTreeMap<String, serde_json::Value>> for PlatformAttributeMap {
    fn from(value: BTreeMap<String, serde_json::Value>) -> Self {
        Self(value)
    }
}

impl From<AttributeMap> for PlatformAttributeMap {
    fn from(value: AttributeMap) -> Self {
        Self(
            value
                .into_iter()
                .map(|(k, v)| (k.into_owned(), v))
                .collect(),
        )
    }
}

impl FromIterator<(String, String)> for PlatformAttributeMap {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        )
    }
}

impl FromIterator<(String, serde_json::Value)> for PlatformAttributeMap {
    fn from_iter<T: IntoIterator<Item = (String, serde_json::Value)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl FromIterator<KeyValue> for PlatformAttributeMap {
    fn from_iter<T: IntoIterator<Item = KeyValue>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|kv| {
                    let (k, v) = kv.into_parts();
                    (k, serde_json::Value::String(v))
                })
                .collect(),
        )
    }
}

impl PlatformAttributeMap {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn get_attr<T>(&self, key: impl Borrow<str>) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.0
            .get(key.borrow())
            .and_then(|val| serde_json::from_value(val.clone()).ok())
    }

    pub fn set_attr(&mut self, key: impl ToString, val: impl serde::Serialize) {
        self.0.insert(key.to_string(), serde_json::json!(val));
    }

    pub fn contains(&self, key: impl Borrow<str>) -> bool {
        self.0.contains_key(key.borrow())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<PlatformAttributeMap> for serde_json::Value {
    fn from(value: PlatformAttributeMap) -> Self {
        serde_json::Value::Object(value.0.into_iter().collect())
    }
}

#[macro_export]
macro_rules! attributes {
    ( $($key:expr => $value:expr),* $(,)? ) => {
        {
            #[allow(unused_mut)]
            let mut attrs = $crate::platform::common::PlatformAttributeMap::new();
            $(
                attrs.set_attr($key, $value);
            )*
            attrs
        }
    };
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use bias_core::efi::EFIModuleType;
    use uuid::Uuid;

    #[test]
    fn test_attrs_macro() {
        let uuid = Uuid::new_v4();
        let amap = attributes![
            "guid" => uuid,
            "kind" => "DxeCore",
            "path" => "/path/to/my/Module.efi",
        ];

        assert!(amap.contains("path"));
        assert_eq!(
            amap.get_attr::<PathBuf>("path"),
            Some(PathBuf::from("/path/to/my/Module.efi"))
        );

        assert_eq!(amap.get_attr::<Uuid>("guid"), Some(uuid));
        assert_eq!(
            amap.get_attr::<EFIModuleType>("kind"),
            Some(EFIModuleType::DxeCore)
        );
    }
}
