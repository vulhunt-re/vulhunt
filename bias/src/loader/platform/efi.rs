use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Seek, Write};
use std::iter;
use std::path::Path;

use bias_core::prelude::efi::image::*;

use crate::component::{
    ComponentIdentity, ComponentIdentityBuilder, HasComponentIdentity,
};
use crate::package::{
    Package, PackageBuilder, PackageComponentData, PackageData, PackageHashes,
};
use crate::pipeline::source::{
    AnalysisGroupFilter, PackageComponentItemQueue, PackageDependencyGraph, PackageDependencyKind,
    PackageItem, PackageItemQueue, Source,
};
use crate::pipeline::types::standards::EnvironmentKind;
use crate::pipeline::{
    Component, PackageComponentItem, PipelineAnalysisGroups, PipelineError,
};
use crate::platform::common::BinaryLoaderMetadata;
use crate::platform::efi::{
    EFIAmdMicrocode, EFIFirmwareImage, EFIIntelMicrocode, EFIModule, EFIRawSection, EFIVariable,
};
use crate::platform::PlatformProvider;
use crate::util::BytesOrMapping;

use bitflags::bitflags;
use hex_display::HexDisplayExt;
use uuid::Uuid;

use crate::loader::builder::{BA2BuilderError, BA2Writer};
use crate::loader::meta::util::input_architecture;
use crate::loader::meta::{
    BA2ComponentAttributes, BA2ComponentHashes, BA2ComponentMetadata, BA2ComponentMetadataBuilder,
    BA2ComponentMetadataSource, BA2ComponentMetadataWith, EFIAmdMicrocodeAttributes,
    EFIFirmwareImageAttributes, EFIIntelMicrocodeAttributes, EFIModuleAttributes,
    EFIRawSectionAttributes, EFIVariableAttributes,
};
use crate::loader::platform::common::PrimaryComponents;
use super::{BA2LoaderConfig, BA2PackageLoader};

pub struct EFINamedImage {
    name: String,
    data: Vec<u8>,
}

impl EFINamedImage {
    pub fn new(parsed: &ParsedImage<'_>) -> Self {
        Self::from_parts(parsed.name(), parsed.bytes())
    }

    pub fn from_parts(name: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

pub struct EFIFirmwareSource {
    package: Package,
    modules: BTreeMap<Uuid, BA2ComponentMetadataWith<UefiModule<'static>>>,
    microcode: BTreeMap<Uuid, BA2ComponentMetadataWith<MicrocodeInfo<'static>>>,
    raw_sections: BTreeMap<Uuid, BA2ComponentMetadataWith<UefiData<'static>>>,
    vars: BTreeMap<Uuid, BA2ComponentMetadataWith<UefiNvramVar<'static>>>,
    firmware: BTreeMap<Uuid, BA2ComponentMetadataWith<EFINamedImage>>,
    dependencies: PackageDependencyGraph,
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct EFIFirmwareSourceFilter: u16 {
        const MODULES         = 0x0001;
        const MICROCODE       = 0x0002;
        const RAW_SECTIONS    = 0x0004;
        const NVRAM_VARIABLES = 0x0008;
        // NOTE: if firmware images are omitted, then we will store a placeholder
        // with metadata, but the firmware byte representation will not be stored.
        const FIRMWARE_IMAGES = 0x0010;

        const ALL = Self::MODULES.bits() | Self::MICROCODE.bits() |
                    Self::RAW_SECTIONS.bits() | Self::NVRAM_VARIABLES.bits() |
                    Self::FIRMWARE_IMAGES.bits();
    }
}

impl Default for EFIFirmwareSourceFilter {
    fn default() -> Self {
        Self::ALL
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIFirmwareSourceConfig {
    pub deduplicate: bool,
    pub unpack: bool,
    pub filter: EFIFirmwareSourceFilter,
}

impl Default for EFIFirmwareSourceConfig {
    fn default() -> Self {
        Self {
            deduplicate: true,
            unpack: false,
            filter: EFIFirmwareSourceFilter::default(),
        }
    }
}

impl EFIFirmwareSource {
    pub fn new(bytes: &[u8]) -> Result<Self, PipelineError> {
        Self::new_with_config(bytes, EFIFirmwareSourceConfig::default())
    }

    pub fn new_with_config(
        bytes: &[u8],
        config: EFIFirmwareSourceConfig,
    ) -> Result<Self, PipelineError> {
        Self::new_with_config_and_id(bytes, config, Uuid::new_v4())
    }

    pub fn new_with_config_and_id(
        bytes: &[u8],
        config: EFIFirmwareSourceConfig,
        id: Uuid,
    ) -> Result<Self, PipelineError> {
        let mut modules = BTreeMap::new();
        let mut microcode = BTreeMap::new();
        let mut raw_sections = BTreeMap::new();
        let mut vars = BTreeMap::new();
        let mut firmware = BTreeMap::new();

        let mut package = PackageBuilder::new()
            .with_id(id)
            .with_hashes(PackageHashes::new(bytes))
            .build()
            .map_err(PipelineError::source)?;

        // add package attributes
        package.set_attr("environment", EnvironmentKind::firmware_image());

        let mut seen = PrimaryComponents::new();
        let mut dependencies = PackageDependencyGraph::new();

        let bytes = if config.unpack {
            try_unpack(bytes).map_err(PipelineError::source)?
        } else {
            Cow::Borrowed(bytes)
        };

        let images = UefiMulti::new(bytes.as_ref()).map_err(PipelineError::source)?;

        for (loader, image) in images.iter_full() {
            let iid = Uuid::new_v4();
            dependencies.add_entity::<EFIFirmwareImage>(iid);

            let hashes = BA2ComponentHashes::new(image.bytes());
            let (global_id, primary_id) =
                seen.get_or_insert_full::<EFIFirmwareImage>(iid, &ImageIdentity(image, &hashes));
            let is_primary = primary_id == iid;

            let path = format!("firmware/{}-{}.bin", image.name(), hashes.sha256().hex());

            // NOTE: this will never fail
            let mut builder = BA2ComponentMetadataBuilder::new(
                BA2ComponentAttributes::EFIFirmwareImage(EFIFirmwareImageAttributes::new()),
            )
            .with_id(iid)
            .with_name(image.name())
            .with_path(path)
            .with_virtual_path(image.name())
            .with_hashes(hashes);

            if !is_primary {
                // TODO: maybe dedup?
                builder.set_primary_component_id(primary_id);
            }

            builder.set_global_component_id(global_id);

            let meta = builder.build().unwrap();

            firmware.insert(
                iid,
                BA2ComponentMetadataWith::new(
                    meta,
                    if config
                        .filter
                        .contains(EFIFirmwareSourceFilter::FIRMWARE_IMAGES)
                    {
                        EFINamedImage::new(image)
                    } else {
                        EFINamedImage::from_parts(image.name(), [])
                    },
                ),
            );

            if config.filter.contains(EFIFirmwareSourceFilter::MODULES) {
                loader.for_each(|module| {
                    let Ok(guid) = Uuid::parse_str(module.guid()) else {
                        return;
                    };

                    let hashes = BA2ComponentHashes::new(module.bytes());

                    let id = Uuid::new_v4();
                    let (global_id, primary_id) =
                        seen.get_or_insert_full::<EFIModule>(id, &ModuleIdentity(&module, &hashes));
                    let is_primary = primary_id == id;

                    // this is a duplicate and we are opting to discard them
                    if config.deduplicate && !is_primary {
                        return;
                    }

                    dependencies.add_entity::<EFIModule>(id);
                    dependencies
                        .add_dependency(iid, id, PackageDependencyKind::Contains)
                        .ok();

                    let attrs =
                        EFIModuleAttributes::new_with(guid, module.module_type(), module.depex())
                            .with_architecture(input_architecture(module.bytes()))
                            .with_loader_metadata(BinaryLoaderMetadata::from_bytes(module.bytes()));

                    let mut builder = BA2ComponentMetadataBuilder::new(if module.is_pe() {
                        BA2ComponentAttributes::EFIModulePE(attrs)
                    } else {
                        BA2ComponentAttributes::EFIModuleTE(attrs)
                    })
                    .with_id(id)
                    .with_name(module.real_name())
                    .with_path(format!("module/{}-{}.efi", module.guid(), module.name()))
                    .with_virtual_path(module.real_name())
                    .with_hashes(hashes);

                    if !is_primary {
                        builder.set_primary_component_id(primary_id);
                    }

                    builder.set_global_component_id(global_id);

                    // NOTE: this will never fail
                    let meta = builder.build().unwrap();

                    modules.insert(id, BA2ComponentMetadataWith::new(meta, module.into_owned()));
                });
            }

            if config
                .filter
                .contains(EFIFirmwareSourceFilter::RAW_SECTIONS)
            {
                loader.for_each_raw_section(|data| {
                    let Ok(guid) = Uuid::parse_str(data.guid()) else {
                        return;
                    };

                    let hashes = BA2ComponentHashes::new(data.bytes());

                    let id = Uuid::new_v4();
                    let (global_id, primary_id) = seen.get_or_insert_full::<EFIRawSection>(
                        id,
                        &RawSectionIdentity(&data, &hashes),
                    );
                    let is_primary = primary_id == id;

                    // this is a duplicate and we are opting to discard them
                    if config.deduplicate && !is_primary {
                        return;
                    }

                    dependencies.add_entity::<EFIRawSection>(id);
                    dependencies
                        .add_dependency(iid, id, PackageDependencyKind::Contains)
                        .ok();

                    let attrs = EFIRawSectionAttributes::new(data.name(), guid);

                    let path = format!("raw-section/{}-{}.bin", data.guid(), data.name());

                    // NOTE: will never fail
                    let mut builder = BA2ComponentMetadataBuilder::new(
                        BA2ComponentAttributes::EFIRawSection(attrs),
                    )
                    .with_id(id)
                    .with_name(data.real_name())
                    .with_path(path)
                    .with_virtual_path(data.real_name())
                    .with_hashes(hashes);

                    if !is_primary {
                        builder.set_primary_component_id(primary_id);
                    }

                    builder.set_global_component_id(global_id);

                    // NOTE: this will never fail
                    let meta = builder.build().unwrap();

                    raw_sections.insert(id, BA2ComponentMetadataWith::new(meta, data.into_owned()));
                });
            }

            if config.filter.contains(EFIFirmwareSourceFilter::MICROCODE) {
                loader.for_each_microcode(|data| {
                    let id = Uuid::new_v4();

                    match data.vendor() {
                        UefiMicrocodeVendor::Intel => {
                            let hashes = BA2ComponentHashes::new(&[][..]);
                            let (global_id, primary_id) = seen
                                .get_or_insert_full::<EFIIntelMicrocode>(
                                    id,
                                    &MicrocodeIdentity(&data, &hashes),
                                );
                            let is_primary = primary_id == id;

                            if config.deduplicate && !is_primary {
                                return;
                            }

                            dependencies.add_entity::<EFIIntelMicrocode>(id);

                            dependencies
                                .add_dependency(iid, id, PackageDependencyKind::Contains)
                                .ok();

                            let attrs = EFIIntelMicrocodeAttributes::new(
                                data.cpu_signature(),
                                data.date(),
                                data.update_revision(),
                                data.processor_flags(),
                            );

                            let name = format!(
                                "{}-{:x}-{:x}-{:x}",
                                data.date(),
                                data.cpu_signature(),
                                data.update_revision(),
                                data.processor_flags(),
                            );

                            let path = format!("microcode/{name}.bin");

                            let mut builder = BA2ComponentMetadataBuilder::new(
                                BA2ComponentAttributes::EFIIntelMicrocode(attrs),
                            )
                            .with_id(id)
                            .with_name(name)
                            .with_path(path)
                            .with_hashes(hashes);

                            if !is_primary {
                                builder.set_primary_component_id(primary_id);
                            }

                            builder.set_global_component_id(global_id);

                            let meta = builder.build().expect("valid metadata");

                            microcode
                                .insert(id, BA2ComponentMetadataWith::new(meta, data.into_owned()));
                        }
                        UefiMicrocodeVendor::Amd => {
                            let hashes = BA2ComponentHashes::new(&[][..]);
                            let (global_id, primary_id) = seen
                                .get_or_insert_full::<EFIIntelMicrocode>(
                                    id,
                                    &MicrocodeIdentity(&data, &hashes),
                                );
                            let is_primary = primary_id == id;

                            if config.deduplicate && !is_primary {
                                return;
                            }

                            dependencies.add_entity::<EFIAmdMicrocode>(id);

                            dependencies
                                .add_dependency(iid, id, PackageDependencyKind::Contains)
                                .ok();

                            let attrs = EFIAmdMicrocodeAttributes::new(
                                data.cpu_signature(),
                                data.date(),
                                data.update_revision(),
                            );

                            let name = format!(
                                "{}-{:x}-{:x}",
                                data.date(),
                                data.cpu_signature(),
                                data.update_revision(),
                            );

                            let path = format!("microcode/{name}.bin");

                            let mut builder = BA2ComponentMetadataBuilder::new(
                                BA2ComponentAttributes::EFIAmdMicrocode(attrs),
                            )
                            .with_id(id)
                            .with_name(name)
                            .with_path(path)
                            .with_hashes(hashes);

                            if !is_primary {
                                builder.set_primary_component_id(primary_id);
                            }

                            builder.set_global_component_id(global_id);

                            let meta = builder.build().expect("valid metadata");

                            microcode
                                .insert(id, BA2ComponentMetadataWith::new(meta, data.into_owned()));
                        }
                        _ => (),
                    }
                });
            }

            if config
                .filter
                .contains(EFIFirmwareSourceFilter::NVRAM_VARIABLES)
            {
                loader.for_each_var(|nvar| {
                    let Ok(guid) = Uuid::parse_str(nvar.guid()) else {
                        return;
                    };

                    let hashes = BA2ComponentHashes::new(nvar.data());

                    let id = Uuid::new_v4();
                    let (global_id, primary_id) =
                        seen.get_or_insert_full::<EFIVariable>(id, &VarIdentity(&nvar, &hashes));
                    let is_primary = primary_id == id;

                    dependencies.add_entity::<EFIVariable>(id);
                    dependencies
                        .add_dependency(iid, id, PackageDependencyKind::Contains)
                        .ok();

                    let attrs = EFIVariableAttributes::new(
                        nvar.name(),
                        guid,
                        nvar.attributes(),
                        nvar.var_type(),
                    );

                    let path = format!("nvram/{}-{}.bin", nvar.guid(), nvar.name());

                    let mut builder = BA2ComponentMetadataBuilder::new(
                        BA2ComponentAttributes::EFIVariable(attrs),
                    )
                    .with_id(id)
                    .with_name(nvar.name())
                    .with_path(path)
                    .with_hashes(hashes);

                    if !is_primary {
                        builder.set_primary_component_id(primary_id);
                    }

                    builder.set_global_component_id(global_id);

                    let meta = builder.build().unwrap();

                    vars.insert(id, BA2ComponentMetadataWith::new(meta, nvar.into_owned()));
                });
            }
        }

        Ok(Self {
            package,
            modules,
            microcode,
            raw_sections,
            vars,
            dependencies,
            firmware,
        })
    }

    pub fn modules(&self) -> &BTreeMap<Uuid, BA2ComponentMetadataWith<UefiModule<'static>>> {
        &self.modules
    }

    pub fn microcode(&self) -> &BTreeMap<Uuid, BA2ComponentMetadataWith<MicrocodeInfo<'static>>> {
        &self.microcode
    }

    pub fn raw_sections(&self) -> &BTreeMap<Uuid, BA2ComponentMetadataWith<UefiData<'static>>> {
        &self.raw_sections
    }

    pub fn nvram_variables(
        &self,
    ) -> &BTreeMap<Uuid, BA2ComponentMetadataWith<UefiNvramVar<'static>>> {
        &self.vars
    }

    pub fn firmware(&self) -> &BTreeMap<Uuid, BA2ComponentMetadataWith<EFINamedImage>> {
        &self.firmware
    }

    pub fn dependencies(&self) -> &PackageDependencyGraph {
        &self.dependencies
    }

    pub fn to_ba2<W>(&self, writer: W) -> Result<(), BA2BuilderError>
    where
        W: Write + Seek,
    {
        let mut builder = BA2Writer::new_v3_writer(writer);

        for c in self.firmware().values() {
            builder.add_component(c.meta().to_owned(), c.data().data())?;
        }

        for (&id, c) in self.modules().iter() {
            builder.add_component(c.meta().to_owned(), c.data().bytes())?;

            for (p, k) in self.dependencies.parents(id) {
                builder.add_dependency(p, id, k)?;
            }
        }

        for (&id, c) in self.microcode().iter() {
            builder.add_component(c.meta().to_owned(), &[])?;

            for (p, k) in self.dependencies.parents(id) {
                builder.add_dependency(p, id, k)?;
            }
        }

        for (&id, c) in self.nvram_variables().iter() {
            builder.add_component(c.meta().to_owned(), c.data().data())?;

            for (p, k) in self.dependencies.parents(id) {
                builder.add_dependency(p, id, k)?;
            }
        }

        for (&id, c) in self.raw_sections().iter() {
            builder.add_component(c.meta().to_owned(), c.data().bytes())?;

            for (p, k) in self.dependencies.parents(id) {
                builder.add_dependency(p, id, k)?;
            }
        }

        builder.build().map(|_| ())
    }
}

#[async_trait::async_trait]
impl Source for EFIFirmwareSource {
    async fn fetch_component_if(
        &self,
        cid: PackageComponentItem,
        f: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData>, PipelineError> {
        if cid.package().id() != self.package.id() {
            return Ok(None);
        }

        let component = self.component_by_uuid(&cid.package().id(), &cid.id())?;

        Ok(component.filter(|p| f.should_analyse(p.platform())))
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        if pid.id() != self.package.id() {
            return Ok(None);
        }

        let package = PackageData::new(self.package.clone(), Cow::Borrowed(&self.dependencies));

        Ok(Some(package))
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        queue
            .send_async(PackageItem::new(self.package.id()))
            .await
            .map_err(PipelineError::source)
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        if pid.id() != self.package.id() {
            return Ok(());
        }

        for (&uuid, meta) in self
            .dependencies
            .entities()
            .filter(|(_, meta)| analysis_groups.should_analyse(meta))
        {
            queue
                .send_async(PackageComponentItem::new(uuid, pid.clone(), meta))
                .await
                .map_err(PipelineError::source)?;
        }

        Ok(())
    }
}

impl<'a> BA2PackageLoader<'a> for EFIFirmwareSource {
    fn from_file_and_config(
        path: impl AsRef<Path>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, PipelineError> {
        let path = path.as_ref();
        let file = BytesOrMapping::from_file(path).map_err(PipelineError::source)?;

        let mut loaded =
            if let Some(id) = config.into().and_then(|config| config.package_identifier) {
                EFIFirmwareSource::new_with_config_and_id(file.as_ref(), Default::default(), id)?
            } else {
                EFIFirmwareSource::new(file.as_ref())?
            };

        loaded.package.set_path(path.to_string_lossy());

        Ok(loaded)
    }

    fn should_analyse(_path: impl AsRef<Path>) -> bool {
        true
    }

    fn package_by_uuid<'loader>(&'loader self, pid: &Uuid) -> Option<Cow<'loader, Package>> {
        if *pid != self.package.id() {
            None
        } else {
            Some(Cow::Borrowed(&self.package))
        }
    }

    fn component_by_uuid(
        &self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<PackageComponentData>, PipelineError> {
        if *pid != self.package.id() {
            return Ok(None);
        }

        let id = *cid;
        let pid = *pid;

        if let Some(module) = self.modules.get(&id) {
            let platform = module.meta().platform().unwrap();

            return Ok(Some(
                PackageComponentData::new(
                    id,
                    Component::try_from(module.meta())
                        .map_err(PipelineError::source)?
                        .with_package_id(pid),
                    module.data().bytes(),
                    platform,
                )
                .with_package(pid),
            ));
        }

        if let Some(microcode) = self.microcode.get(&id) {
            let platform = microcode.meta().platform().unwrap();

            return Ok(Some(
                PackageComponentData::new(
                    id,
                    Component::try_from(microcode.meta())
                        .map_err(PipelineError::source)?
                        .with_package_id(pid),
                    &[][..],
                    platform,
                )
                .with_package(pid),
            ));
        }

        if let Some(nvar) = self.vars.get(&id) {
            let platform = nvar.meta().platform().unwrap();

            return Ok(Some(
                PackageComponentData::new(
                    id,
                    Component::try_from(nvar.meta())
                        .map_err(PipelineError::source)?
                        .with_package_id(pid),
                    nvar.data().data(),
                    platform,
                )
                .with_package(pid),
            ));
        }

        if let Some(raw_section) = self.raw_sections.get(&id) {
            let platform = raw_section.meta().platform().unwrap();

            return Ok(Some(
                PackageComponentData::new(
                    id,
                    Component::try_from(raw_section.meta())
                        .map_err(PipelineError::source)?
                        .with_package_id(pid),
                    raw_section.data().bytes(),
                    platform,
                )
                .with_package(pid),
            ));
        }

        if let Some(image) = self.firmware.get(&id) {
            let platform = image.meta().platform().unwrap();

            return Ok(Some(
                PackageComponentData::new(
                    id,
                    Component::try_from(image.meta())
                        .map_err(PipelineError::source)?
                        .with_package_id(pid),
                    image.data().data(),
                    platform,
                )
                .with_package(pid),
            ));
        }

        Ok(None)
    }

    fn components<'loader>(&'loader self, pid: &Uuid) -> impl Iterator<Item = Uuid> + 'loader {
        if self.package.id() != *pid {
            Box::new(iter::empty()) as Box<dyn Iterator<Item = Uuid> + 'loader>
        } else {
            Box::new(
                self.firmware()
                    .keys()
                    .copied()
                    .chain(self.modules().keys().copied())
                    .chain(self.microcode().keys().copied())
                    .chain(self.raw_sections().keys().copied())
                    .chain(self.nvram_variables().keys().copied()),
            ) as _
        }
    }
}

impl BA2ComponentMetadataSource for EFIFirmwareSource {
    fn component_meta_by_uuid<'a>(
        &'a self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'a, BA2ComponentMetadata>>, PipelineError> {
        if *pid != self.package.id() {
            return Ok(None);
        }

        let id = cid;

        if let Some(module) = self.modules().get(id) {
            return Ok(Some(Cow::Borrowed(module.meta())));
        }

        if let Some(microcode) = self.microcode().get(id) {
            return Ok(Some(Cow::Borrowed(microcode.meta())));
        }

        if let Some(nvar) = self.nvram_variables().get(id) {
            return Ok(Some(Cow::Borrowed(nvar.meta())));
        }

        if let Some(raw_section) = self.raw_sections().get(id) {
            return Ok(Some(Cow::Borrowed(raw_section.meta())));
        }

        if let Some(image) = self.firmware().get(id) {
            return Ok(Some(Cow::Borrowed(image.meta())));
        }

        Ok(None)
    }
}

struct ImageIdentity<'a, 'b>(&'b ParsedImage<'a>, &'b BA2ComponentHashes);

impl HasComponentIdentity for ImageIdentity<'_, '_> {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity {
        builder.update(EFIFirmwareImage::NAME);
        builder.update(self.1.md5());
        builder.update(self.1.sha1());
        builder.update(self.1.sha256());

        builder.update(self.0.name().as_bytes());
        builder.build()
    }
}

struct ModuleIdentity<'a, 'b>(&'b UefiModule<'a>, &'b BA2ComponentHashes);

impl HasComponentIdentity for ModuleIdentity<'_, '_> {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity {
        builder.update(EFIModule::NAME);
        builder.update(self.1.md5());
        builder.update(self.1.sha1());
        builder.update(self.1.sha256());

        builder.update(self.0.guid().as_bytes());

        for dguid in self.0.depex().iter().filter_map(|op| op.guid()) {
            builder.update(dguid);
        }

        builder.build()
    }
}

struct RawSectionIdentity<'a, 'b>(&'b UefiData<'a>, &'b BA2ComponentHashes);

impl HasComponentIdentity for RawSectionIdentity<'_, '_> {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity {
        builder.update(EFIRawSection::NAME);
        builder.update(self.1.md5());
        builder.update(self.1.sha1());
        builder.update(self.1.sha256());

        builder.update(self.0.guid().as_bytes());

        builder.build()
    }
}

struct MicrocodeIdentity<'a, 'b>(&'b MicrocodeInfo<'a>, &'b BA2ComponentHashes);

impl HasComponentIdentity for MicrocodeIdentity<'_, '_> {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity {
        let kind = match self.0.vendor() {
            UefiMicrocodeVendor::Amd => EFIAmdMicrocode::NAME,
            UefiMicrocodeVendor::Intel => EFIIntelMicrocode::NAME,
            _ => panic!("unsupported microcode vendor"),
        };

        builder.update(kind);
        builder.update(self.1.md5());
        builder.update(self.1.sha1());
        builder.update(self.1.sha256());

        builder.update(self.0.cpu_signature().to_be_bytes());
        builder.update(self.0.date().as_bytes());
        builder.update(self.0.update_revision().to_be_bytes());

        if self.0.vendor().is_intel() {
            builder.update(self.0.processor_flags().to_be_bytes());
        }

        builder.build()
    }
}

struct VarIdentity<'a, 'b>(&'b UefiNvramVar<'a>, &'b BA2ComponentHashes);

impl HasComponentIdentity for VarIdentity<'_, '_> {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity {
        builder.update(EFIVariable::NAME);
        builder.update(self.1.md5());
        builder.update(self.1.sha1());
        builder.update(self.1.sha256());

        builder.update(self.0.name().as_bytes());
        builder.update(self.0.guid().as_bytes());
        builder.update(self.0.attributes().to_be_bytes());
        builder.update([self.0.var_type() as u8]);
        builder.build()
    }
}
