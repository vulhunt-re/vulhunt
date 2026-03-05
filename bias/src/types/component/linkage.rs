use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::types::artefact::{
    AddressRange, AddressRangeError, CodeRange, CodeRangeError, OffsetRange, OffsetRangeError,
};

pub type SearchPath = String;
pub type SearchPathSet = BTreeSet<SearchPath>;

pub type VersionRequirement = String;
pub type VersionRequirementRef<'a> = &'a str;
pub type VersionRequirementSet = BTreeSet<VersionRequirement>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Import {
    name: String,
    display_name: Option<String>,
    version: Option<VersionRequirement>,
}

impl Import {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: None,
            version: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn set_display_name(&mut self, display_name: impl Into<String>) {
        self.display_name = Some(display_name.into());
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.set_display_name(display_name);
        self
    }

    pub fn version(&self) -> Option<VersionRequirementRef<'_>> {
        self.version.as_deref()
    }

    pub fn set_version(&mut self, version: impl Into<VersionRequirement>) {
        self.version = Some(version.into());
    }

    pub fn with_version(mut self, version: impl Into<VersionRequirement>) -> Self {
        self.set_version(version);
        self
    }
}

impl From<&'_ str> for Import {
    fn from(value: &'_ str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Import {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ImportExportIndex(u64);

impl ImportExportIndex {
    const SELECTOR: u64 = 0x8000_0000_0000_0000;

    pub fn function(index: usize) -> Self {
        assert!((index as u64) & Self::SELECTOR == 0, "invalid index");
        Self(index as u64)
    }

    pub fn global(index: usize) -> Self {
        assert!((index as u64) & Self::SELECTOR == 0, "invalid index");
        Self((index as u64) | Self::SELECTOR)
    }

    pub fn is_function(&self) -> bool {
        (self.0 & Self::SELECTOR) == 0
    }

    pub fn is_global(&self) -> bool {
        (self.0 & Self::SELECTOR) != 0
    }

    pub fn index(&self) -> usize {
        (self.0 & !Self::SELECTOR) as usize
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum ImportResolution {
    #[serde(rename = "direct")]
    #[default]
    Direct,
    #[serde(rename = "indirect")]
    Indirect,
}

impl ImportResolution {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn is_indirect(&self) -> bool {
        matches!(self, Self::Indirect)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Imports {
    globals: Vec<Import>,
    functions: Vec<Import>,
    resolution: ImportResolution,
    #[serde(skip)]
    names: BTreeMap<String, ImportExportIndex>,
}

#[derive(Debug, Error)]
#[error("imports must have unique names")]
pub enum ImportsError {
    #[error("imports must have unique names")]
    DuplicateName,
    #[error("unsupported import resolution kind")]
    UnsupportedResolutionKind,
}

impl Imports {
    pub fn new() -> Self {
        Self::new_with(ImportResolution::default())
    }

    pub fn new_with(resolution: ImportResolution) -> Self {
        Self {
            globals: Vec::new(),
            functions: Vec::new(),
            resolution,
            names: BTreeMap::new(),
        }
    }

    pub fn direct() -> Self {
        Self::new_with(ImportResolution::Direct)
    }

    pub fn indirect() -> Self {
        Self::new_with(ImportResolution::Indirect)
    }

    pub fn is_direct(&self) -> bool {
        self.resolution.is_direct()
    }

    pub fn is_indirect(&self) -> bool {
        self.resolution.is_indirect()
    }

    pub fn resolution(&self) -> ImportResolution {
        self.resolution
    }

    pub fn set_resolution(&mut self, resolution: ImportResolution) {
        self.resolution = resolution;
    }

    pub fn with_resolution(mut self, resolution: ImportResolution) -> Self {
        self.set_resolution(resolution);
        self
    }

    pub fn contains(&self, name: impl AsRef<str>) -> bool {
        self.names.contains_key(name.as_ref())
    }

    pub fn contains_function(&self, name: impl AsRef<str>) -> bool {
        self.names
            .get(name.as_ref())
            .map(|index| index.is_function())
            .unwrap_or_default()
    }

    pub fn contains_global(&self, name: impl AsRef<str>) -> bool {
        self.names
            .get(name.as_ref())
            .map(|index| index.is_global())
            .unwrap_or_default()
    }

    pub fn get_function(&self, name: impl AsRef<str>) -> Option<&Import> {
        self.names.get(name.as_ref()).and_then(|index| {
            if index.is_function() {
                self.functions.get(index.index())
            } else {
                None
            }
        })
    }

    pub fn get_global(&self, name: impl AsRef<str>) -> Option<&Import> {
        self.names.get(name.as_ref()).and_then(|index| {
            if index.is_global() {
                self.globals.get(index.index())
            } else {
                None
            }
        })
    }

    pub fn insert_global(&mut self, import: impl Into<Import>) -> Result<(), ImportsError> {
        let import = import.into();

        let Entry::Vacant(entry) = self.names.entry(import.name.clone()) else {
            return Err(ImportsError::DuplicateName);
        };

        entry.insert(ImportExportIndex::global(self.globals.len()));

        self.globals.push(import);

        Ok(())
    }

    pub fn insert_function(&mut self, import: impl Into<Import>) -> Result<(), ImportsError> {
        let import = import.into();

        let Entry::Vacant(entry) = self.names.entry(import.name.clone()) else {
            return Err(ImportsError::DuplicateName);
        };

        entry.insert(ImportExportIndex::function(self.functions.len()));

        self.functions.push(import);

        Ok(())
    }

    pub fn extend_globals(
        &mut self,
        imports: impl IntoIterator<Item = impl Into<Import>>,
    ) -> Result<(), ImportsError> {
        for import in imports {
            self.insert_global(import)?;
        }

        Ok(())
    }

    pub fn extend_functions(
        &mut self,
        imports: impl IntoIterator<Item = impl Into<Import>>,
    ) -> Result<(), ImportsError> {
        for import in imports {
            self.insert_function(import)?;
        }

        Ok(())
    }

    pub fn with_globals(
        mut self,
        imports: impl IntoIterator<Item = impl Into<Import>>,
    ) -> Result<Self, ImportsError> {
        self.extend_globals(imports)?;
        Ok(self)
    }

    pub fn with_functions(
        mut self,
        imports: impl IntoIterator<Item = impl Into<Import>>,
    ) -> Result<Self, ImportsError> {
        self.extend_functions(imports)?;
        Ok(self)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Import> {
        self.globals.iter().chain(self.functions.iter())
    }

    pub fn iter_globals(&self) -> impl Iterator<Item = &Import> {
        self.globals.iter()
    }

    pub fn iter_functions(&self) -> impl Iterator<Item = &Import> {
        self.functions.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }
}

impl<'de> Deserialize<'de> for Imports {
    fn deserialize<D>(deserialiser: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ImportsT {
            globals: Vec<Import>,
            functions: Vec<Import>,
            #[serde(default)]
            resolution: ImportResolution,
        }

        let imports = ImportsT::deserialize(deserialiser)?;
        let names =
            imports
                .globals
                .iter()
                .enumerate()
                .map(|(index, import)| (import.name.clone(), ImportExportIndex::global(index)))
                .chain(imports.functions.iter().enumerate().map(|(index, import)| {
                    (import.name.clone(), ImportExportIndex::function(index))
                }))
                .collect::<BTreeMap<_, _>>();

        if names.len() != imports.globals.len() + imports.functions.len() {
            return Err(serde::de::Error::custom(
                "duplicate import names are not allowed",
            ));
        }

        Ok(Self {
            globals: imports.globals,
            functions: imports.functions,
            resolution: imports.resolution,
            names,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Export {
    name: String,
    display_name: Option<String>,
    version: Option<String>,
    location: Option<ExportLocation>,
}

impl From<&'_ str> for Export {
    fn from(value: &'_ str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Export {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl Export {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: None,
            version: None,
            location: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn set_display_name(&mut self, display_name: impl Into<String>) {
        self.display_name = Some(display_name.into());
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.set_display_name(display_name);
        self
    }

    pub fn version(&self) -> Option<VersionRequirementRef<'_>> {
        self.version.as_deref()
    }

    pub fn set_version(&mut self, version: impl Into<VersionRequirement>) {
        self.version = Some(version.into());
    }

    pub fn with_version(mut self, version: impl Into<VersionRequirement>) -> Self {
        self.set_version(version);
        self
    }

    pub fn location(&self) -> Option<&ExportLocation> {
        self.location.as_ref()
    }

    pub fn set_location(&mut self, location: impl Into<ExportLocation>) {
        self.location = Some(location.into());
    }

    pub fn with_location(mut self, location: impl Into<ExportLocation>) -> Self {
        self.set_location(location);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum ExportLocation {
    #[serde(rename = "offset")]
    Offset { value: u64 },
    #[serde(rename = "offset-range")]
    OffsetRange { value: OffsetRange },
    #[serde(rename = "address")]
    Address { value: u64 },
    #[serde(rename = "address-range")]
    AddressRange { value: AddressRange },
    #[serde(rename = "code-offset")]
    CodeOffset { value: u64 },
    #[serde(rename = "code-range")]
    CodeRange { value: CodeRange },
}

#[derive(Debug, Error)]
pub enum ExportLocationError {
    #[error(transparent)]
    InvalidAddressRange(#[from] AddressRangeError),
    #[error(transparent)]
    InvalidCodeRange(#[from] CodeRangeError),
    #[error(transparent)]
    InvalidOffsetRange(#[from] OffsetRangeError),
}

impl ExportLocation {
    pub fn new_offset(value: impl Into<u64>) -> Self {
        Self::Offset {
            value: value.into(),
        }
    }

    pub fn new_offset_range(value: impl Into<OffsetRange>) -> Self {
        Self::OffsetRange {
            value: value.into(),
        }
    }

    pub fn new_address(value: impl Into<u64>) -> Self {
        Self::Address {
            value: value.into(),
        }
    }

    pub fn new_address_range(value: impl Into<AddressRange>) -> Self {
        Self::AddressRange {
            value: value.into(),
        }
    }

    pub fn new_code_offset(value: impl Into<u64>) -> Self {
        Self::CodeOffset {
            value: value.into(),
        }
    }

    pub fn new_code_range(value: impl Into<CodeRange>) -> Self {
        Self::CodeRange {
            value: value.into(),
        }
    }

    pub fn offset(&self) -> Option<u64> {
        match self {
            Self::Offset { value } => Some(*value),
            _ => None,
        }
    }

    pub fn offset_range(&self) -> Option<&OffsetRange> {
        match self {
            Self::OffsetRange { value } => Some(value),
            _ => None,
        }
    }

    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Address { value } => Some(*value),
            _ => None,
        }
    }

    pub fn address_range(&self) -> Option<&AddressRange> {
        match self {
            Self::AddressRange { value } => Some(value),
            _ => None,
        }
    }

    pub fn code_offset(&self) -> Option<u64> {
        match self {
            Self::CodeOffset { value } => Some(*value),
            _ => None,
        }
    }

    pub fn code_range(&self) -> Option<&CodeRange> {
        match self {
            Self::CodeRange { value } => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Exports {
    globals: Vec<Export>,
    functions: Vec<Export>,
    #[serde(skip)]
    names: BTreeMap<String, ImportExportIndex>,
}

#[derive(Debug, Error)]
pub enum ExportsError {
    #[error("exports must have unique names")]
    DuplicateName,
    #[error(transparent)]
    Location(#[from] ExportLocationError),
}

impl Exports {
    pub fn new() -> Self {
        Self {
            globals: Vec::new(),
            functions: Vec::new(),
            names: BTreeMap::new(),
        }
    }

    pub fn contains_global(&self, name: impl AsRef<str>) -> bool {
        self.names
            .get(name.as_ref())
            .map(|index| index.is_global())
            .unwrap_or_default()
    }

    pub fn contains_function(&self, name: impl AsRef<str>) -> bool {
        self.names
            .get(name.as_ref())
            .map(|index| index.is_function())
            .unwrap_or_default()
    }

    pub fn get_global(&self, name: impl AsRef<str>) -> Option<&Export> {
        self.names.get(name.as_ref()).and_then(|index| {
            if index.is_global() {
                self.globals.get(index.index())
            } else {
                None
            }
        })
    }

    pub fn get_function(&self, name: impl AsRef<str>) -> Option<&Export> {
        self.names.get(name.as_ref()).and_then(|index| {
            if index.is_function() {
                self.functions.get(index.index())
            } else {
                None
            }
        })
    }

    pub fn insert_global(&mut self, export: impl Into<Export>) -> Result<(), ExportsError> {
        let export = export.into();

        let Entry::Vacant(entry) = self.names.entry(export.name.clone()) else {
            return Err(ExportsError::DuplicateName);
        };

        entry.insert(ImportExportIndex::global(self.globals.len()));

        self.globals.push(export);

        Ok(())
    }

    pub fn insert_function(&mut self, export: impl Into<Export>) -> Result<(), ExportsError> {
        let export = export.into();

        let Entry::Vacant(entry) = self.names.entry(export.name.clone()) else {
            return Err(ExportsError::DuplicateName);
        };

        entry.insert(ImportExportIndex::function(self.functions.len()));

        self.functions.push(export);

        Ok(())
    }

    pub fn extend_globals(
        &mut self,
        exports: impl IntoIterator<Item = impl Into<Export>>,
    ) -> Result<(), ExportsError> {
        for export in exports {
            self.insert_global(export)?;
        }

        Ok(())
    }

    pub fn extend_functions(
        &mut self,
        exports: impl IntoIterator<Item = impl Into<Export>>,
    ) -> Result<(), ExportsError> {
        for export in exports {
            self.insert_function(export)?;
        }

        Ok(())
    }

    pub fn with_globals(
        mut self,
        exports: impl IntoIterator<Item = impl Into<Export>>,
    ) -> Result<Self, ExportsError> {
        self.extend_globals(exports)?;
        Ok(self)
    }

    pub fn with_functions(
        mut self,
        exports: impl IntoIterator<Item = impl Into<Export>>,
    ) -> Result<Self, ExportsError> {
        self.extend_functions(exports)?;
        Ok(self)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Export> {
        self.globals.iter().chain(self.functions.iter())
    }

    pub fn iter_globals(&self) -> impl Iterator<Item = &Export> {
        self.globals.iter()
    }

    pub fn iter_functions(&self) -> impl Iterator<Item = &Export> {
        self.functions.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }
}

impl<'de> Deserialize<'de> for Exports {
    fn deserialize<D>(deserialiser: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ExportsT {
            globals: Vec<Export>,
            functions: Vec<Export>,
        }

        let exports = ExportsT::deserialize(deserialiser)?;
        let names =
            exports
                .globals
                .iter()
                .enumerate()
                .map(|(index, export)| (export.name.clone(), ImportExportIndex::global(index)))
                .chain(exports.functions.iter().enumerate().map(|(index, export)| {
                    (export.name.clone(), ImportExportIndex::function(index))
                }))
                .collect::<BTreeMap<_, _>>();

        if names.len() != exports.globals.len() + exports.functions.len() {
            return Err(serde::de::Error::custom(
                "duplicate export names are not allowed",
            ));
        }

        Ok(Self {
            globals: exports.globals,
            functions: exports.functions,
            names,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct ImportedDependency {
    name: String,
    version_requirements: BTreeSet<VersionRequirement>,
    search_paths: BTreeSet<String>,
}

impl ImportedDependency {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version_requirements(&self) -> &VersionRequirementSet {
        &self.version_requirements
    }

    pub fn add_version_requirement(&mut self, requirement: impl Into<VersionRequirement>) {
        self.version_requirements.insert(requirement.into());
    }

    pub fn with_version_requirement(mut self, requirement: impl Into<VersionRequirement>) -> Self {
        self.add_version_requirement(requirement);
        self
    }

    pub fn add_version_requirements(
        &mut self,
        requirements: impl IntoIterator<Item = impl Into<VersionRequirement>>,
    ) {
        self.version_requirements
            .extend(requirements.into_iter().map(Into::into));
    }

    pub fn with_version_requirements(
        mut self,
        requirements: impl IntoIterator<Item = impl Into<VersionRequirement>>,
    ) -> Self {
        self.add_version_requirements(requirements);
        self
    }

    pub fn search_paths(&self) -> &SearchPathSet {
        &self.search_paths
    }

    pub fn add_search_path(&mut self, path: impl Into<SearchPath>) {
        self.search_paths.insert(path.into());
    }

    pub fn with_search_path(mut self, path: impl Into<SearchPath>) -> Self {
        self.add_search_path(path);
        self
    }

    pub fn add_search_paths(&mut self, paths: impl IntoIterator<Item = impl Into<SearchPath>>) {
        self.search_paths.extend(paths.into_iter().map(Into::into));
    }

    pub fn with_search_paths(
        mut self,
        paths: impl IntoIterator<Item = impl Into<SearchPath>>,
    ) -> Self {
        self.add_search_paths(paths);
        self
    }
}
