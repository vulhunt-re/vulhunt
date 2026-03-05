use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::VariantNames;
use strum_macros::{AsRefStr, Display, EnumString, VariantNames};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PURLError {
    #[error("invalid PURL component")]
    Component,
    #[error("invalid PURL identifier")]
    Identifier,
    #[error("inconsistent PURL components and identifier")]
    Inconsistent,
    #[error("invalid package type: {0}")]
    InvalidPackageType(strum::ParseError),
    #[error("missing prefix")]
    MissingPrefix,
    #[error("missing name")]
    MissingName,
    #[error("missing namespace")]
    MissingNamespace,
    #[error("missing version")]
    MissingVersion,
    #[error("invalid PURL package type")]
    PackageType,
    #[error("invalid PURL")]
    Undefined,
    #[error("unsupported PURL package type")]
    UnsupportedPackageType,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct PURL {
    identifier: String,
    components: Option<PURLComponents>,
}

impl FromStr for PURL {
    type Err = PURLError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for PURL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.identifier.fmt(f)
    }
}

impl PURL {
    pub fn new(identifier: impl Into<String>) -> Result<Self, PURLError> {
        let identifier = identifier.into();

        // TODO: validate that the identifier is a valid PURL and error out
        let components = identifier.parse::<PURLComponents>().ok();

        Ok(Self {
            identifier: identifier.into(),
            components,
        })
    }

    pub fn new_with(
        identifier: impl Into<String>,
        components: impl Into<Option<PURLComponents>>,
    ) -> Result<Self, PURLError> {
        let identifier = identifier.into();
        if identifier.is_empty() {
            return Err(PURLError::Undefined);
        }

        let mut components = components.into();
        if components.is_none() {
            // TODO: validate that the identifier is a valid PURL and error out
            components = identifier.parse::<PURLComponents>().ok();
        }

        Ok(Self {
            identifier,
            components,
        })
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn components(&self) -> Option<&PURLComponents> {
        self.components.as_ref()
    }

    pub fn display_package(&self) -> Option<PURLPackageDisplay<'_>> {
        self.components.as_ref().map(|c| c.display_package())
    }

    pub fn display_release(&self) -> Option<PURLReleaseDisplay<'_>> {
        self.components.as_ref().and_then(|c| c.display_release())
    }
}

// https://github.com/package-url/purl-spec/tree/1b67a73a0c4c372cd1cb64f4e24b26dc86fb2c92/types
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
    AsRefStr,
    Display,
    EnumString,
    VariantNames,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum PackageType {
    #[serde(rename = "alpm")]
    #[strum(serialize = "alpm")]
    ArchLinux,
    APK,
    Bitbucket,
    Bitnami,
    Cargo,
    CocoaPods,
    Composer,
    Conan,
    Conda,
    CPAN,
    CRAN,
    #[serde(rename = "deb")]
    #[strum(serialize = "deb")]
    Debian,
    Docker,
    #[serde(rename = "gem")]
    #[strum(serialize = "gem")]
    RubyGems,
    Generic,
    GitHub,
    #[serde(rename = "golang")]
    #[strum(serialize = "golang")]
    Go,
    #[serde(rename = "hackage")]
    #[strum(serialize = "hackage")]
    Haskell,
    Hex,
    HuggingFace,
    LuaRocks,
    Maven,
    MLflow,
    NPM,
    NuGet,
    OCI,
    Pub,
    PyPI,
    #[serde(rename = "qpkg")]
    #[strum(serialize = "qpkg")]
    QNX,
    RPM,
    SWID,
    Swift,
}

impl PackageType {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct PURLComponents {
    package_type: PackageType,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
    qualifiers: BTreeMap<String, String>,
    subpath: Option<String>,
}

impl FromStr for PURLComponents {
    type Err = PURLError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: full handle PURLs--this is enough for our current needs, however, it is woefully
        // incomplete.

        let s = s.strip_prefix("pkg:").ok_or(PURLError::MissingPrefix)?;
        let (ptype, rest) = s.split_once('/').ok_or(PURLError::MissingPrefix)?;
        let package_type = PackageType::from_str(ptype).map_err(PURLError::InvalidPackageType)?;

        let (namespace, rest) = rest.split_once('/').ok_or(PURLError::MissingNamespace)?;

        if namespace.is_empty() {
            return Err(PURLError::MissingNamespace);
        }

        if rest.is_empty() {
            return Err(PURLError::MissingName);
        }

        let purl = match rest.split_once('@') {
            None => Self::new_with_namespace(package_type, namespace, rest),
            Some((name, version)) => {
                if name.is_empty() {
                    return Err(PURLError::MissingName);
                }

                if version.is_empty() {
                    return Err(PURLError::MissingVersion);
                }

                Self::new_with_namespace_and_version(package_type, namespace, name, version)
            }
        };

        Ok(purl)
    }
}

pub struct PURLPackageDisplay<'a>(&'a PURLComponents);

impl Display for PURLPackageDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(namespace) = self.0.namespace.as_ref() {
            write!(
                f,
                "pkg:{}/{}/{}",
                self.0.package_type, namespace, self.0.name
            )
        } else {
            write!(f, "pkg:{}/{}", self.0.package_type, self.0.name)
        }
    }
}

pub struct PURLReleaseDisplay<'a>(&'a PURLComponents);

impl Display for PURLReleaseDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let version = self.0.version.as_ref().expect("version present");
        if let Some(namespace) = self.0.namespace.as_ref() {
            return write!(
                f,
                "pkg:{}/{}/{}@{}",
                self.0.package_type, namespace, self.0.name, version
            );
        } else {
            return write!(f, "pkg:{}/{}@{}", self.0.package_type, self.0.name, version);
        }
    }
}

impl Display for PURLComponents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pkg:")?;

        self.package_type.fmt(f)?;
        f.write_str("/")?;

        if let Some(namespace) = self.namespace.as_ref() {
            f.write_str(namespace)?;
            f.write_str("/")?;
        }

        f.write_str(&self.name)?;

        if let Some(version) = self.version.as_ref() {
            f.write_str("@")?;
            f.write_str(version)?;
        }

        if !self.qualifiers.is_empty() {
            f.write_str("?")?;
            let mut it = self.qualifiers.iter();

            let (key, value) = it.next().expect("not empty");
            write!(f, "{key}={value}")?;

            for (key, value) in it {
                write!(f, "&{key}={value}")?;
            }
        }

        if let Some(subpath) = self.subpath.as_ref() {
            f.write_str("#")?;
            f.write_str(subpath)?;
        }

        Ok(())
    }
}

impl From<PURLComponents> for PURL {
    fn from(value: PURLComponents) -> Self {
        Self {
            identifier: value.to_string(),
            components: Some(value),
        }
    }
}

impl PURLComponents {
    pub fn new(package_type: PackageType, name: impl Into<String>) -> Self {
        Self {
            package_type,
            namespace: None,
            name: name.into(),
            version: None,
            qualifiers: BTreeMap::new(),
            subpath: None,
        }
    }

    pub fn new_with_namespace(
        package_type: PackageType,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            package_type,
            namespace: Some(namespace.into()),
            name: name.into(),
            version: None,
            qualifiers: BTreeMap::new(),
            subpath: None,
        }
    }

    pub fn new_with_namespace_and_version(
        package_type: PackageType,
        namespace: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            package_type,
            namespace: Some(namespace.into()),
            name: name.into(),
            version: Some(version.into()),
            qualifiers: BTreeMap::new(),
            subpath: None,
        }
    }

    pub fn package_type(&self) -> PackageType {
        self.package_type
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn set_namespace(&mut self, namespace: impl Into<String>) {
        self.namespace = Some(namespace.into());
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.set_namespace(namespace);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
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

    pub fn qualifiers(&self) -> &BTreeMap<String, String> {
        &self.qualifiers
    }

    pub fn qualifiers_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.qualifiers
    }

    pub fn add_qualifier(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.qualifiers.insert(key.into(), value.into());
    }

    pub fn add_qualifiers<K, V>(&mut self, qualifiers: impl IntoIterator<Item = (K, V)>)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.qualifiers
            .extend(qualifiers.into_iter().map(|(k, v)| (k.into(), v.into())));
    }

    pub fn with_qualifier(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.qualifiers.insert(key.into(), value.into());
        self
    }

    pub fn with_qualifiers<K, V>(mut self, qualifiers: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.qualifiers
            .extend(qualifiers.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    pub fn subpath(&self) -> Option<&str> {
        self.subpath.as_deref()
    }

    pub fn set_subpath(&mut self, subpath: impl Into<String>) {
        self.subpath = Some(subpath.into());
    }

    pub fn with_subpath(mut self, subpath: impl Into<String>) -> Self {
        self.set_subpath(subpath);
        self
    }

    pub fn display_package(&self) -> PURLPackageDisplay<'_> {
        PURLPackageDisplay(self)
    }

    pub fn display_release(&self) -> Option<PURLReleaseDisplay<'_>> {
        self.version.as_ref().map(|_| PURLReleaseDisplay(self))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_purl_display() {
        let purl = PURLComponents::new(PackageType::NPM, "left-pad")
            .with_namespace("lodash")
            .with_version("1.3.0")
            .with_qualifier("arch", "x64")
            .with_qualifier("os", "linux")
            .with_subpath("lib");

        assert_eq!(
            purl.to_string(),
            "pkg:npm/lodash/left-pad@1.3.0?arch=x64&os=linux#lib"
        );

        let purl_no_namespace = PURLComponents::new(PackageType::PyPI, "requests")
            .with_version("2.25.1")
            .with_qualifier("python_version", "3.8");

        assert_eq!(
            purl_no_namespace.to_string(),
            "pkg:pypi/requests@2.25.1?python_version=3.8"
        );

        let purl_no_version = PURLComponents::new(PackageType::Docker, "nginx")
            .with_namespace("library")
            .with_qualifier("variant", "alpine");

        assert_eq!(
            purl_no_version.to_string(),
            "pkg:docker/library/nginx?variant=alpine"
        );

        let purl_minimal = PURLComponents::new(PackageType::Generic, "my-package");

        assert_eq!(purl_minimal.to_string(), "pkg:generic/my-package");
    }
}
