use std::fmt;

use crate::data::strings::StringData;
use crate::kb::xref::XRef;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]

pub struct StringXRef {
    xref: XRef,
    content: String,
    kind: StringData,
}

impl StringXRef {
    pub fn new(xref: impl Into<XRef>, s: impl Into<String>, kind: StringData) -> Self {
        Self {
            xref: xref.into(),
            content: s.into(),
            kind: kind,
        }
    }

    #[inline]
    pub fn kind(&self) -> StringData {
        self.kind
    }

    #[inline]
    pub fn xref(&self) -> XRef {
        self.xref
    }

    #[inline]
    pub fn string(&self) -> &str {
        &self.content
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.content.len()
    }
}

impl fmt::Display for StringXRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StringXRef: {} -> {}",
            self.xref().target(),
            self.content
        )
    }
}
