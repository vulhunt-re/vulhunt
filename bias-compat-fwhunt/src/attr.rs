use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{Error, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValWithAttr<T, A> {
    pub val: T,
    pub attr: A,
}

struct ValWithAttrVisitor<T, A>(PhantomData<(T, A)>);

impl<T, A> Default for ValWithAttrVisitor<T, A> {
    fn default() -> Self {
        ValWithAttrVisitor(PhantomData)
    }
}

impl<'de, T, A> Visitor<'de> for ValWithAttrVisitor<T, A>
where
    T: Deserialize<'de>,
    A: FromStr,
{
    type Value = ValWithAttr<T, A>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("attribute/value pair; e.g., key: value")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let attr = if let Some(attr) = map.next_key::<String>()?.as_deref() {
            attr.parse::<A>()
                .map_err(|_| Error::custom("cannot parse attribute"))?
        } else {
            return Err(Error::custom(format!("expected attribute")))?;
        };

        let val = map.next_value::<T>()?;

        Ok(ValWithAttr { attr, val })
    }
}

impl<'de, T, A> Deserialize<'de> for ValWithAttr<T, A>
where
    T: Deserialize<'de>,
    A: FromStr,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ValWithAttrVisitor::default())
    }
}

impl<T, A> Serialize for ValWithAttr<T, A>
where
    T: Serialize,
    A: ToString,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&self.attr.to_string(), &self.val)?;
        map.end()
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[serde(
    bound(deserialize = "T: Deserialize<'de>, A: FromStr"),
    bound(serialize = "T: Serialize, A: ToString"),
    untagged
)]
pub enum ValWithOptAttr<T, A>
where
    A: FromStr,
{
    Val(T),
    ValWith(ValWithAttr<T, A>),
}

impl<T, A> From<ValWithOptAttr<T, A>> for (T, A)
where
    A: Default + FromStr,
{
    fn from(v: ValWithOptAttr<T, A>) -> Self {
        match v {
            ValWithOptAttr::Val(v) => (v, Default::default()),
            ValWithOptAttr::ValWith(va) => (va.val, va.attr),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[serde(
    bound(deserialize = "T: Deserialize<'de>, U: Deserialize<'de>, A: FromStr"),
    bound(serialize = "T: Serialize, U: Serialize, A: ToString"),
    untagged
)]
pub enum ValWithOptAttrOr<T, U, A>
where
    A: FromStr,
{
    Val(T),
    ValWith(ValWithAttr<U, A>),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic_val_attr() -> Result<(), Box<dyn std::error::Error>> {
        use serde::Deserialize;

        let aval = "utf16: blah";
        let nval = "none";

        let aval_value: serde_json::Value = serde_yaml::from_str(aval)?;
        let aval_parse = ValWithAttr::<String, String>::deserialize(aval_value)?;

        assert_eq!(
            aval_parse,
            ValWithAttr {
                val: "blah".to_string(),
                attr: "utf16".to_string()
            },
        );

        let nval_value: serde_json::Value = serde_yaml::from_str(nval)?;
        let nval_parse = ValWithOptAttr::<String, String>::deserialize(nval_value)?;

        assert_eq!(nval_parse, ValWithOptAttr::Val("none".to_string()),);

        Ok(())
    }

    #[test]
    fn test_basic_val_attr_ser() -> Result<(), Box<dyn std::error::Error>> {
        let aval = ValWithAttr { val: "blah".to_string(), attr: "utf16".to_string() };
        let nval = ValWithOptAttr::<String, String>::Val("none".to_string());

        let aval_s = "utf16: blah";
        let nval_s = "none";

        assert_eq!(aval_s, serde_yaml::to_string(&aval)?.trim());
        assert_eq!(nval_s, serde_yaml::to_string(&nval)?.trim());

        Ok(())
    }
}
