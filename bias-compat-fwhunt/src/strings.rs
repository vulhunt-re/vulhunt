use std::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use bias_core::data::strings::StringData;
use bias_core::Project;
use serde::de::Error;
use serde::{Deserialize, Serialize};

use crate::attr::{ValWithAttr, ValWithOptAttr};
use crate::bmatch::BMatcher;
use crate::group::Groups;
use crate::matcher::MatchContext;
use crate::schema::*;
use crate::MatchesRule;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AsciiString {
    value: String,
}

impl AsciiString {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    pub fn group() -> Groups<AsciiString> {
        Groups::default()
    }
}

impl Display for AsciiString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl Deref for AsciiString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for AsciiString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl From<String> for AsciiString {
    fn from(value: String) -> Self {
        Self { value }
    }
}

impl From<AsciiString> for String {
    fn from(slf: AsciiString) -> Self {
        slf.value
    }
}

impl MatchesRule for AsciiString {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        if BMatcher::from(self.value.as_bytes()).matches_rule(context, project) {
            let prov = context.pending_provenance().unwrap();
            context.describe(FwHuntCheckMatch::AsciiString {
                value: self.value.to_string(),
                length: self.value.len(),
                location: FwHuntCheckLocation::Address {
                    value: prov.offset(),
                },
            });
            true
        } else {
            false
        }
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        if BMatcher::from(self.value.as_bytes()).matches_bytes(context, bytes) {
            let prov = context.pending_provenance().unwrap();
            context.describe(FwHuntCheckMatch::AsciiString {
                value: self.value.to_string(),
                length: self.value.len(),
                location: FwHuntCheckLocation::Offset {
                    value: prov.offset(),
                },
            });
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, getset::Getters, getset::MutGetters)]
pub struct WideString {
    #[getset(get = "pub", get_mut = "pub")]
    kind: StringData,
    #[getset(get = "pub", get_mut = "pub")]
    value: String,
}

impl WideString {
    pub fn new(value: impl Into<String>) -> Self {
        Self::new_with(value, None)
    }

    pub fn new_with(value: impl Into<String>, kind: impl Into<Option<StringData>>) -> Self {
        Self {
            value: value.into(),
            kind: kind.into().unwrap_or(StringData::Utf16Le),
        }
    }

    pub fn group() -> Groups<WideString> {
        Groups::default()
    }
}

impl<'de> Deserialize<'de> for WideString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (value, kind) = ValWithOptAttr::<String, String>::deserialize(deserializer)?.into();
        Ok(Self {
            kind: match &*kind {
                "ascii" => StringData::Ascii,
                "utf8" => StringData::Utf8,
                "" | "utf16" | "utf16-le" | "utf16le" => StringData::Utf16Le,
                "utf16-be" | "utf16be" => StringData::Utf16Be,
                enc => {
                    return Err(Error::custom(format!(
                        "unsupported string encoding `{enc}`"
                    )))?
                }
            },
            value,
        })
    }
}

impl Serialize for WideString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let kind = match self.kind {
            StringData::Ascii => "ascii",
            StringData::Utf8 => "utf8",
            StringData::Utf16Le => "utf16le",
            StringData::Utf16Be => "utf16be",
        };

        let value = ValWithOptAttr::ValWith(ValWithAttr {
            val: self.value.to_string(),
            attr: kind.to_string(),
        });

        value.serialize(serializer)
    }
}

impl Display for WideString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl Deref for WideString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for WideString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl From<String> for WideString {
    fn from(value: String) -> Self {
        Self {
            kind: StringData::Utf8,
            value,
        }
    }
}

impl From<WideString> for String {
    fn from(slf: WideString) -> Self {
        slf.value
    }
}

impl MatchesRule for WideString {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        self.kind()
            .encode(&*self.value)
            .map(|m| {
                let length = m.len();
                if BMatcher::from(m).matches_rule(context, project) {
                    let prov = context.pending_provenance().unwrap();
                    context.describe(FwHuntCheckMatch::WideString {
                        value: self.value.to_string(),
                        length,
                        location: FwHuntCheckLocation::Address {
                            value: prov.offset(),
                        },
                    });
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        self.kind()
            .encode(&*self.value)
            .map(|m| {
                let length = m.len();
                if BMatcher::from(m).matches_bytes(context, bytes) {
                    let prov = context.pending_provenance().unwrap();
                    context.describe(FwHuntCheckMatch::WideString {
                        value: self.value.to_string(),
                        length,
                        location: FwHuntCheckLocation::Offset {
                            value: prov.offset(),
                        },
                    });
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct HexString {
    #[serde(serialize_with = "crate::bmatch::BMatcher::ser_to_str")]
    #[serde(deserialize_with = "crate::bmatch::BMatcher::de_from_str")]
    value: BMatcher,
}

impl Deref for HexString {
    type Target = BMatcher;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for HexString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl From<BMatcher> for HexString {
    fn from(value: BMatcher) -> Self {
        Self { value }
    }
}

impl From<HexString> for BMatcher {
    fn from(slf: HexString) -> Self {
        slf.value
    }
}

impl From<HexString> for String {
    fn from(slf: HexString) -> Self {
        slf.value.to_string()
    }
}

impl Display for HexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl FromStr for HexString {
    type Err = crate::bmatch::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            value: BMatcher::from_str(s)?,
        })
    }
}

impl HexString {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            value: BMatcher::from_bytes(bytes.as_ref()),
        }
    }

    pub fn from_pattern(value: impl AsRef<str>) -> Result<Self, crate::bmatch::Error> {
        Ok(Self {
            value: value.as_ref().parse()?,
        })
    }

    pub fn from_pattern_parts(
        pattern: impl AsRef<[u8]>,
        mask: impl AsRef<[u8]>,
    ) -> Result<Self, crate::bmatch::Error> {
        Ok(Self {
            value: BMatcher::from_parts(pattern.as_ref(), mask.as_ref())?,
        })
    }

    pub fn group() -> Groups<HexString> {
        Groups::default()
    }
}

impl MatchesRule for HexString {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        if self.value.matches_rule(context, project) {
            let prov = context.pending_provenance().unwrap();
            context.describe(FwHuntCheckMatch::HexString {
                value: self.value.to_string(),
                length: self.value.len(),
                location: FwHuntCheckLocation::Address {
                    value: prov.offset(),
                },
            });
            true
        } else {
            false
        }
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        if self.value.matches_bytes(context, bytes) {
            let prov = context.pending_provenance().unwrap();
            context.describe(FwHuntCheckMatch::HexString {
                value: self.value.to_string(),
                length: self.value.len(),
                location: FwHuntCheckLocation::Offset {
                    value: prov.offset(),
                },
            });
            true
        } else {
            false
        }
    }
}
