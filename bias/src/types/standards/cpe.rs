use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::VariantNames;
use strum_macros::{Display, EnumString, VariantNames};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CPEError {
    #[error("invalid CPE component")]
    Component,
    #[error("invalid CPE identifier")]
    Identifier,
    #[error("inconsistent CPE components and identifier")]
    Inconsistent,
    #[error("invalid CPE part")]
    Part,
    #[error("invalid CPE version string")]
    Version,
    #[error("invalid CPE")]
    Undefined,
    #[error("unsupported CPE part")]
    UnsupportedPart,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CPE {
    v22: Option<CPEv22>,
    v23: Option<CPEv23>,
}

impl Display for CPE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(v23) = &self.v23 {
            write!(f, "{}", v23.identifier())?;
        }

        if let Some(v22) = &self.v22 {
            write!(f, "{}", v22.identifier())?;
        }

        // should be unreachable

        Ok(())
    }
}

impl FromStr for CPE {
    type Err = CPEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<CPEv23Components>()
            .map(CPE::from)
            .or_else(|_| s.parse::<CPEv22Components>().map(CPE::from))
    }
}

pub struct CPENVDDisplay<'a>(&'a CPE);

impl Display for CPENVDDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(components) = self.0.v23().and_then(|v23| v23.components()) {
            return components.nvd_display().fmt(f);
        }

        if let Some(components) = self.0.v22().and_then(|v22| v22.components()) {
            return components.nvd_display().fmt(f);
        }

        // should be unreachable

        Ok(())
    }
}

impl From<CPEv22> for CPE {
    fn from(value: CPEv22) -> Self {
        Self {
            v22: Some(value),
            v23: None,
        }
    }
}

impl From<CPEv23> for CPE {
    fn from(value: CPEv23) -> Self {
        Self {
            v22: None,
            v23: Some(value),
        }
    }
}

impl CPE {
    pub fn new_v22(identifier: impl Into<String>) -> Result<Self, CPEError> {
        Self::new_v22_with(identifier, None)
    }

    pub fn new_v22_with(
        identifier: impl Into<String>,
        components: impl Into<Option<CPEv22Components>>,
    ) -> Result<Self, CPEError> {
        let v22 = CPEv22::new_with(identifier, components)?;

        Ok(Self {
            // build CPE 2.3 from CPE 2.2
            v23: v22.components().map(|c| CPEv23::from(c.to_v23())),
            v22: Some(v22),
        })
    }

    pub fn new_v23(identifier: impl Into<String>) -> Result<Self, CPEError> {
        Self::new_v23_with(identifier, None)
    }

    pub fn new_v23_with(
        identifier: impl Into<String>,
        components: impl Into<Option<CPEv23Components>>,
    ) -> Result<Self, CPEError> {
        let v23 = CPEv23::new_with(identifier, components)?;

        Ok(Self {
            // build CPE 2.2 from CPE 2.3
            v22: v23.components().map(|c| CPEv22::from(c.to_v22())),
            v23: Some(v23),
        })
    }

    pub fn v22(&self) -> Option<&CPEv22> {
        self.v22.as_ref()
    }

    pub fn v23(&self) -> Option<&CPEv23> {
        self.v23.as_ref()
    }

    pub fn with(mut self, other: impl Into<CPE>) -> CPE {
        let other = other.into();
        self.v22 = other.v22.or(self.v22);
        self.v23 = other.v23.or(self.v23);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.v22.is_some() || self.v23.is_some()
    }

    pub fn identifier(&self) -> Option<&str> {
        self.v23()
            .map(|v23| v23.identifier())
            .or_else(|| self.v22().map(|v22| v22.identifier()))
    }

    pub fn nvd_display(&self) -> Option<impl Display + use<'_>> {
        if matches!(self.v22(), Some(v) if v.components.is_some())
            || matches!(self.v23(), Some(v) if v.components.is_some())
        {
            Some(CPENVDDisplay(self))
        } else {
            None
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    Display,
    EnumString,
    VariantNames,
)]
pub enum CPEPart {
    #[serde(rename = "a")]
    #[strum(serialize = "a")]
    Application,
    #[serde(rename = "o")]
    #[strum(serialize = "o")]
    OperatingSystem,
    #[serde(rename = "h")]
    #[strum(serialize = "h")]
    Hardware,
}

impl CPEPart {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CPEv22 {
    identifier: String,
    components: Option<CPEv22Components>,
}

impl CPEv22 {
    pub fn new(identifier: impl Into<String>) -> Result<Self, CPEError> {
        Self::new_with(identifier, None)
    }

    pub fn new_with(
        identifier: impl Into<String>,
        components: impl Into<Option<CPEv22Components>>,
    ) -> Result<Self, CPEError> {
        // TODO: full CPE 2.2 parsing support and validation
        let identifier = identifier.into();
        if identifier.trim().is_empty() {
            return Err(CPEError::Identifier);
        }

        let mut components = components.into();
        if components.is_none() {
            components = identifier.parse::<CPEv22Components>().ok();
        }

        Ok(Self {
            identifier,
            components,
        })
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn components(&self) -> Option<&CPEv22Components> {
        self.components.as_ref()
    }

    pub fn set_components(&mut self, components: CPEv22Components) {
        self.components = Some(components);
    }

    pub fn with_components(mut self, components: CPEv22Components) -> Self {
        self.set_components(components);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CPEv22Components {
    part: Option<CPEPart>,
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    update: Option<String>,
    edition: Option<String>,
    language: Option<String>,
}

impl Display for CPEv22Components {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let maybe_write = |v: &Option<String>, f: &mut std::fmt::Formatter<'_>| {
            if let Some(v) = v {
                f.write_str(v)?;
            }
            f.write_str(":")
        };

        f.write_str("cpe:/")?;

        if let Some(part) = &self.part {
            write!(f, "{part}:")?;
        } else {
            f.write_str(":")?;
        }

        maybe_write(&self.vendor, f)?;
        maybe_write(&self.product, f)?;
        maybe_write(&self.version, f)?;
        maybe_write(&self.update, f)?;
        maybe_write(&self.edition, f)?;

        if let Some(language) = &self.language {
            f.write_str(language)?;
        }

        Ok(())
    }
}

impl FromStr for CPEv22Components {
    type Err = CPEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: full CPE 2.2 parsing support

        let next_non_empty = |parts: &mut std::str::Split<char>| {
            let part = parts.next()?;
            let part = part.trim();
            if part.is_empty() {
                None
            } else {
                Some(part.to_owned())
            }
        };

        let Some(rest) = s.strip_prefix("cpe:/") else {
            return Err(CPEError::Identifier);
        };

        let mut parts = rest.split(':');

        let part = match parts.next() {
            None | Some("") => None,
            Some(part) => Some(CPEPart::from_str(part).map_err(|_| CPEError::Part)?),
        };

        let vendor = next_non_empty(&mut parts);
        let product = next_non_empty(&mut parts);
        let version = next_non_empty(&mut parts);
        let update = next_non_empty(&mut parts);
        let edition = next_non_empty(&mut parts);
        let language = next_non_empty(&mut parts);

        Ok(Self {
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        })
    }
}

pub struct CVEv22NVDDisplay<'a>(&'a CPEv22Components);

impl Display for CVEv22NVDDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let maybe_write = |v: &Option<String>, f: &mut std::fmt::Formatter<'_>| {
            if let Some(v) = v {
                f.write_str(v)?;
            }
            f.write_str(":")
        };

        f.write_str("cpe:/")?;

        if let Some(part) = &self.0.part {
            write!(f, "{part}:")?;
        } else {
            f.write_str(":")?;
        }

        maybe_write(&self.0.vendor, f)?;
        maybe_write(&self.0.product, f)?;
        maybe_write(&self.0.version, f)?;

        Ok(())
    }
}

impl From<CPEv22Components> for CPE {
    fn from(value: CPEv22Components) -> Self {
        Self {
            // build CPE 2.3 from CPE 2.2
            v23: Some(CPEv23::from(value.to_v23())),
            v22: Some(CPEv22::from(value)),
        }
    }
}

impl From<CPEv22Components> for CPEv22 {
    fn from(value: CPEv22Components) -> Self {
        Self {
            identifier: value.to_string(),
            components: Some(value),
        }
    }
}

impl CPEv22Components {
    pub fn new() -> Self {
        Self::new_with(None)
    }

    pub fn new_with(part: impl Into<Option<CPEPart>>) -> Self {
        Self {
            part: part.into(),
            vendor: None,
            product: None,
            version: None,
            update: None,
            edition: None,
            language: None,
        }
    }

    pub fn part(&self) -> Option<CPEPart> {
        self.part
    }

    pub fn set_part(&mut self, part: impl Into<CPEPart>) {
        self.part = Some(part.into());
    }

    pub fn with_part(mut self, part: impl Into<CPEPart>) -> Self {
        self.set_part(part);
        self
    }

    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    pub fn set_vendor(&mut self, vendor: impl Into<String>) {
        self.vendor = Some(vendor.into());
    }

    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.set_vendor(vendor);
        self
    }

    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    pub fn set_product(&mut self, product: impl Into<String>) {
        self.product = Some(product.into());
    }

    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.set_product(product);
        self
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = Some(version.into());
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.set_version(version);
        self
    }

    pub fn update(&self) -> Option<&str> {
        self.update.as_deref()
    }

    pub fn set_update(&mut self, update: impl Into<String>) {
        self.update = Some(update.into());
    }

    pub fn with_update(mut self, update: impl Into<String>) -> Self {
        self.set_update(update);
        self
    }

    pub fn edition(&self) -> Option<&str> {
        self.edition.as_deref()
    }

    pub fn set_edition(&mut self, edition: impl Into<String>) {
        self.edition = Some(edition.into());
    }

    pub fn with_edition(mut self, edition: impl Into<String>) -> Self {
        self.set_edition(edition);
        self
    }

    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    pub fn set_language(&mut self, language: impl Into<String>) {
        self.language = Some(language.into());
    }

    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.set_language(language);
        self
    }

    pub fn nvd_display(&self) -> impl Display + use<'_> {
        CVEv22NVDDisplay(self)
    }

    pub fn to_v23(&self) -> CPEv23Components {
        let mut components = CPEv23Components::new_with(self.part);

        if let Some(vendor) = self.vendor() {
            components.set_vendor(vendor);
        }

        if let Some(product) = self.product() {
            components.set_product(product);
        }

        if let Some(version) = self.version() {
            components.set_version(version);
        }

        if let Some(update) = self.update() {
            components.set_update(update);
        }

        if let Some(edition) = self.edition() {
            components.set_edition(edition);
        }

        if let Some(language) = self.language() {
            components.set_language(language);
        }

        components
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CPEv23 {
    identifier: String,
    components: Option<CPEv23Components>,
}

impl CPEv23 {
    pub fn new(identifier: impl Into<String>) -> Result<Self, CPEError> {
        Self::new_with(identifier, None)
    }

    pub fn new_with(
        identifier: impl Into<String>,
        components: impl Into<Option<CPEv23Components>>,
    ) -> Result<Self, CPEError> {
        // TODO: full CPE 2.3 parsing support and validation

        let identifier = identifier.into();
        if identifier.trim().is_empty() {
            return Err(CPEError::Identifier);
        }

        let mut components = components.into();
        if components.is_none() {
            components = identifier.parse::<CPEv23Components>().ok();
        }

        Ok(Self {
            identifier,
            components,
        })
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn components(&self) -> Option<&CPEv23Components> {
        self.components.as_ref()
    }

    pub fn set_components(&mut self, components: CPEv23Components) {
        self.components = Some(components);
    }

    pub fn with_components(mut self, components: CPEv23Components) -> Self {
        self.set_components(components);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CPEv23Components {
    part: Option<CPEPart>,
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    update: Option<String>,
    edition: Option<String>,
    language: Option<String>,
    sw_edition: Option<String>,
    target_sw: Option<String>,
    target_hw: Option<String>,
    other: Option<String>,
}

impl Display for CPEv23Components {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let maybe_write = |v: &Option<String>, f: &mut std::fmt::Formatter<'_>| {
            if let Some(v) = v {
                f.write_str(v)?;
            } else {
                f.write_str("*")?;
            }
            f.write_str(":")
        };

        f.write_str("cpe:2.3:")?;

        if let Some(part) = &self.part {
            write!(f, "{}:", part)?;
        } else {
            f.write_str("*:")?;
        }

        maybe_write(&self.vendor, f)?;
        maybe_write(&self.product, f)?;
        maybe_write(&self.version, f)?;
        maybe_write(&self.update, f)?;
        maybe_write(&self.edition, f)?;
        maybe_write(&self.language, f)?;
        maybe_write(&self.sw_edition, f)?;
        maybe_write(&self.target_sw, f)?;
        maybe_write(&self.target_hw, f)?;

        if let Some(other) = &self.other {
            f.write_str(other)
        } else {
            f.write_str("*")
        }
    }
}

impl FromStr for CPEv23Components {
    type Err = CPEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: full CPE 2.3 parsing support and validation
        //
        // NOTE: empty components are treated as wildcard "*" (ANY) and "-" (NA) are handled
        // and represented explicitly. That is, we assume that ANY is implicit (can be mapped
        // to/from `None`) and NA is explicit (mapped to/from `Some("-")`).
        //

        let next_non_empty = |parts: &mut std::str::Split<char>| {
            let part = parts.next()?;
            let part = part.trim();
            if part.is_empty() || part == "*" {
                None
            } else {
                Some(part.to_owned())
            }
        };

        let Some(rest) = s.strip_prefix("cpe:2.3:") else {
            return Err(CPEError::Identifier);
        };

        let mut parts = rest.split(':');
        let part = match parts.next() {
            None | Some("*") => None,
            Some(part) => Some(CPEPart::from_str(part).map_err(|_| CPEError::Part)?),
        };

        let vendor = next_non_empty(&mut parts);
        let product = next_non_empty(&mut parts);
        let version = next_non_empty(&mut parts);
        let update = next_non_empty(&mut parts);
        let edition = next_non_empty(&mut parts);
        let language = next_non_empty(&mut parts);
        let sw_edition = next_non_empty(&mut parts);
        let target_sw = next_non_empty(&mut parts);
        let target_hw = next_non_empty(&mut parts);
        let other = next_non_empty(&mut parts);

        Ok(Self {
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
            sw_edition,
            target_sw,
            target_hw,
            other,
        })
    }
}

impl From<CPEv23Components> for CPE {
    fn from(value: CPEv23Components) -> Self {
        Self {
            // build CPE 2.2 from CPE 2.3
            v22: Some(CPEv22::from(value.to_v22())),
            v23: Some(CPEv23::from(value)),
        }
    }
}

impl From<CPEv23Components> for CPEv23 {
    fn from(value: CPEv23Components) -> Self {
        Self {
            identifier: value.to_string(),
            components: Some(value),
        }
    }
}

impl CPEv23Components {
    pub fn new() -> Self {
        Self::new_with(None)
    }

    pub fn new_with(part: impl Into<Option<CPEPart>>) -> Self {
        Self {
            part: part.into(),
            vendor: None,
            product: None,
            version: None,
            update: None,
            edition: None,
            language: None,
            sw_edition: None,
            target_sw: None,
            target_hw: None,
            other: None,
        }
    }

    pub fn part(&self) -> Option<CPEPart> {
        self.part
    }

    pub fn set_part(&mut self, part: impl Into<CPEPart>) {
        self.part = Some(part.into());
    }

    pub fn with_part(mut self, part: impl Into<CPEPart>) -> Self {
        self.set_part(part);
        self
    }

    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    pub fn set_vendor(&mut self, vendor: impl Into<String>) {
        self.vendor = Some(vendor.into());
    }

    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.set_vendor(vendor);
        self
    }

    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    pub fn set_product(&mut self, product: impl Into<String>) {
        self.product = Some(product.into());
    }

    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.set_product(product);
        self
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = Some(version.into());
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.set_version(version);
        self
    }

    pub fn update(&self) -> Option<&str> {
        self.update.as_deref()
    }

    pub fn set_update(&mut self, update: impl Into<String>) {
        self.update = Some(update.into());
    }

    pub fn with_update(mut self, update: impl Into<String>) -> Self {
        self.set_update(update);
        self
    }

    pub fn edition(&self) -> Option<&str> {
        self.edition.as_deref()
    }

    pub fn set_edition(&mut self, edition: impl Into<String>) {
        self.edition = Some(edition.into());
    }

    pub fn with_edition(mut self, edition: impl Into<String>) -> Self {
        self.set_edition(edition);
        self
    }

    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    pub fn set_language(&mut self, language: impl Into<String>) {
        self.language = Some(language.into());
    }

    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.set_language(language);
        self
    }

    pub fn sw_edition(&self) -> Option<&str> {
        self.sw_edition.as_deref()
    }

    pub fn set_sw_edition(&mut self, sw_edition: impl Into<String>) {
        self.sw_edition = Some(sw_edition.into());
    }

    pub fn with_sw_edition(mut self, sw_edition: impl Into<String>) -> Self {
        self.set_sw_edition(sw_edition);
        self
    }

    pub fn target_sw(&self) -> Option<&str> {
        self.target_sw.as_deref()
    }

    pub fn set_target_sw(&mut self, target_sw: impl Into<String>) {
        self.target_sw = Some(target_sw.into());
    }

    pub fn with_target_sw(mut self, target_sw: impl Into<String>) -> Self {
        self.set_target_sw(target_sw);
        self
    }

    pub fn target_hw(&self) -> Option<&str> {
        self.target_hw.as_deref()
    }

    pub fn set_target_hw(&mut self, target_hw: impl Into<String>) {
        self.target_hw = Some(target_hw.into());
    }

    pub fn with_target_hw(mut self, target_hw: impl Into<String>) -> Self {
        self.set_target_hw(target_hw);
        self
    }

    pub fn other(&self) -> Option<&str> {
        self.other.as_deref()
    }

    pub fn set_other(&mut self, other: impl Into<String>) {
        self.other = Some(other.into());
    }

    pub fn with_other(mut self, other: impl Into<String>) -> Self {
        self.set_other(other);
        self
    }

    pub fn nvd_display(&self) -> impl Display + use<'_> {
        self
    }

    pub fn to_v22(&self) -> CPEv22Components {
        let mut components = CPEv22Components::new_with(self.part);

        if let Some(vendor) = self.vendor() {
            components.set_vendor(vendor);
        }

        if let Some(product) = self.product() {
            components.set_product(product);
        }

        if let Some(version) = self.version() {
            components.set_version(version);
        }

        if let Some(update) = self.update() {
            components.set_update(update);
        }

        if let Some(edition) = self.edition() {
            components.set_edition(edition);
        }

        if let Some(language) = self.language() {
            components.set_language(language);
        }

        components
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cpe_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let cpe = CPE::from(
            CPEv22Components::new_with(CPEPart::Application)
                .with_vendor("microsoft")
                .with_product("internet_explorer")
                .with_version("8.0.6001")
                .with_update("beta"),
        )
        .with(
            CPEv23Components::new_with(CPEPart::Application)
                .with_vendor("microsoft")
                .with_product("internet_explorer")
                .with_version("8.0.6001")
                .with_update("beta"),
        );

        assert_eq!(
            CPE::from(CPEv22Components {
                part: Some(CPEPart::Application),
                vendor: Some("microsoft".to_owned()),
                product: Some("internet_explorer".to_owned()),
                version: Some("8.0.6001".to_owned()),
                update: Some("beta".to_owned()),
                edition: None,
                language: None,
            }),
            cpe
        );

        assert_eq!(
            CPE::from(CPEv23Components {
                part: Some(CPEPart::Application),
                vendor: Some("microsoft".to_owned()),
                product: Some("internet_explorer".to_owned()),
                version: Some("8.0.6001".to_owned()),
                update: Some("beta".to_owned()),
                edition: None,
                language: None,
                sw_edition: None,
                target_sw: None,
                target_hw: None,
                other: None,
            }),
            cpe
        );

        let cpe_22_str = "cpe:/a:microsoft:internet_explorer:8.0.6001:beta::";
        assert_eq!(CPE::from_str(cpe_22_str)?, cpe);

        let cpe_23_str = "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*";
        assert_eq!(CPE::from_str(cpe_23_str)?, cpe);

        Ok(())
    }
}
