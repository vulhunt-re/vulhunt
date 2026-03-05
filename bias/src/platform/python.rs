use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};
use crate::types::Reference;
use serde::{Deserialize, Serialize};

use crate::platform::common::{PackageMetadata, PathMetadata, VCSMetadata};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PythonPackageInstallationProvenance {
    StandardLibrary,
    DistPackages,
    VirtualEnvironment,
    SitePackages,
    Cache,
    Wheel,
    #[default]
    Undetermined,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "kebab-case")]
pub enum PythonPackageSourceProvenance {
    PythonDistribution(PackageMetadata),
    PackageIndex(Reference),
    VCS(VCSMetadata),
    DirectURL(Reference),
    DistPackage(PackageMetadata),
    CondaChannel(Reference),
    Local(PathMetadata),
    #[default]
    Undetermined,
}

impl PythonPackageSourceProvenance {
    pub fn is_python_distribution(&self) -> bool {
        matches!(self, Self::PythonDistribution { .. })
    }

    pub fn is_package_index(&self) -> bool {
        matches!(self, Self::PackageIndex { .. })
    }

    pub fn is_vcs(&self) -> bool {
        matches!(self, Self::VCS { .. })
    }

    pub fn is_direct_url(&self) -> bool {
        matches!(self, Self::DirectURL { .. })
    }

    pub fn is_dist_package(&self) -> bool {
        matches!(self, Self::DistPackage { .. })
    }

    pub fn is_conda_channel(&self) -> bool {
        matches!(self, Self::CondaChannel { .. })
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    pub fn is_undetermined(&self) -> bool {
        matches!(self, Self::Undetermined { .. })
    }

    pub fn python_distribution(package: impl Into<PackageMetadata>) -> Self {
        Self::PythonDistribution(package.into())
    }

    pub fn package_index(information: impl Into<Reference>) -> Self {
        Self::PackageIndex(information.into())
    }

    pub fn vcs(vcs: impl Into<VCSMetadata>) -> Self {
        Self::VCS(vcs.into())
    }

    pub fn direct_url(url: impl Into<Reference>) -> Self {
        Self::DirectURL(url.into())
    }

    pub fn dist_package(package: impl Into<PackageMetadata>) -> Self {
        Self::DistPackage(package.into())
    }

    pub fn conda_channel(channel: impl Into<Reference>) -> Self {
        Self::CondaChannel(channel.into())
    }

    pub fn local(path: impl Into<PathMetadata>) -> Self {
        Self::Local(path.into())
    }

    pub fn undetermined() -> Self {
        Self::Undetermined
    }

    pub fn package_metadata(&self) -> Option<&PackageMetadata> {
        match self {
            Self::PythonDistribution(pm) | Self::DistPackage(pm) => Some(pm),
            _ => None,
        }
    }

    pub fn path_metadata(&self) -> Option<&PathMetadata> {
        match self {
            Self::Local(pm) => Some(pm),
            _ => None,
        }
    }

    pub fn reference(&self) -> Option<&Reference> {
        match self {
            Self::PackageIndex(r) | Self::DirectURL(r) | Self::CondaChannel(r) => Some(r),
            _ => None,
        }
    }

    pub fn vcs_metadata(&self) -> Option<&VCSMetadata> {
        match self {
            Self::VCS(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PythonPackage;

pub type PythonPackageBuilder = PlatformBuilder<PythonPackage>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PythonPackageAttribute {
    Name(String),
    Path(PathBuf),
    InstallationProvenance(PythonPackageInstallationProvenance),
    SourceProvenance(PythonPackageSourceProvenance),
}

impl PythonPackageAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn installation_provenance(
        provenance: impl Into<PythonPackageInstallationProvenance>,
    ) -> Self {
        Self::InstallationProvenance(provenance.into())
    }

    pub fn source_provenance(provenance: impl Into<PythonPackageSourceProvenance>) -> Self {
        Self::SourceProvenance(provenance.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct PythonPackageName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for PythonPackageName<'a> {
    const UUID: Uuid = uuid("3EE6458B-8496-4F60-9555-298FC7294873");
}

impl<'a> AsRef<str> for PythonPackageName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for PythonPackageName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct PythonPackagePath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for PythonPackagePath<'a> {
    const UUID: Uuid = uuid("44EABBA6-9704-4006-8660-684E40CBE50D");
}

impl<'a> AsRef<Path> for PythonPackagePath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for PythonPackagePath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct PythonPackageInstallationProvenanceRef<'a>(
    pub(crate) &'a PythonPackageInstallationProvenance,
);
impl<'a> LoaderAttribute<'a> for PythonPackageInstallationProvenanceRef<'a> {
    const UUID: Uuid = uuid("CDDF8E89-791D-449A-AB78-82A01EAC350F");
}

impl<'a> AsRef<PythonPackageInstallationProvenance> for PythonPackageInstallationProvenanceRef<'a> {
    fn as_ref(&self) -> &PythonPackageInstallationProvenance {
        self.0
    }
}

impl<'a> Deref for PythonPackageInstallationProvenanceRef<'a> {
    type Target = PythonPackageInstallationProvenance;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct PythonPackageSourceProvenanceRef<'a>(pub(crate) &'a PythonPackageSourceProvenance);
impl<'a> LoaderAttribute<'a> for PythonPackageSourceProvenanceRef<'a> {
    const UUID: Uuid = uuid("A7882F69-566E-4FF8-A367-9E05FD757452");
}

impl<'a> AsRef<PythonPackageSourceProvenance> for PythonPackageSourceProvenanceRef<'a> {
    fn as_ref(&self) -> &PythonPackageSourceProvenance {
        self.0
    }
}

impl<'a> Deref for PythonPackageSourceProvenanceRef<'a> {
    type Target = PythonPackageSourceProvenance;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for PythonPackage {
    type Attribute = PythonPackageAttribute;

    const NAME: &'static str = "python.package";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for PythonPackageAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(PythonPackageName(name));
            }
            Self::Path(path) => {
                container.set_attr(PythonPackagePath(path));
            }
            Self::InstallationProvenance(provenance) => {
                container.set_attr(PythonPackageInstallationProvenanceRef(provenance));
            }
            Self::SourceProvenance(provenance) => {
                container.set_attr(PythonPackageSourceProvenanceRef(provenance));
            }
        }
    }
}
