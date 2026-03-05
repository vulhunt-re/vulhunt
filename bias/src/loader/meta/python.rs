use crate::platform::python::{
    PythonPackageInstallationProvenance, PythonPackageSourceProvenance,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PythonPackageAttributes {
    #[serde(default)]
    magic_string: String,
    #[serde(default)]
    extension: String,
    #[serde(default)]
    installation_provenance: Option<PythonPackageInstallationProvenance>,
    #[serde(default)]
    source_provenance: Option<PythonPackageSourceProvenance>,
}

impl PythonPackageAttributes {
    pub fn new(magic_string: impl Into<String>, extension: impl Into<String>) -> Self {
        Self {
            magic_string: magic_string.into(),
            extension: extension.into(),
            ..Default::default()
        }
    }

    pub fn magic_string(&self) -> &str {
        &self.magic_string
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }

    pub fn installation_provenance(&self) -> Option<&PythonPackageInstallationProvenance> {
        self.installation_provenance.as_ref()
    }

    pub fn set_installation_provenance(
        &mut self,
        provenance: impl Into<Option<PythonPackageInstallationProvenance>>,
    ) {
        self.installation_provenance = provenance.into();
    }

    pub fn with_installation_provenance(
        mut self,
        provenance: impl Into<Option<PythonPackageInstallationProvenance>>,
    ) -> Self {
        self.set_installation_provenance(provenance);
        self
    }

    pub fn source_provenance(&self) -> Option<&PythonPackageSourceProvenance> {
        self.source_provenance.as_ref()
    }

    pub fn set_source_provenance(
        &mut self,
        provenance: impl Into<Option<PythonPackageSourceProvenance>>,
    ) {
        self.source_provenance = provenance.into();
    }

    pub fn with_source_provenance(
        mut self,
        provenance: impl Into<Option<PythonPackageSourceProvenance>>,
    ) -> Self {
        self.set_source_provenance(provenance);
        self
    }
}
