use std::path::Path;

use bias::loader::meta::{
    BA2ComponentAttributes, EFIStandaloneAttributes, PosixELFAttributes, WindowsPEAttributes,
};
use bias::pipeline::PipelineError;
use bias::platform::common::{BinaryLoaderMetadata, ComponentArch, PlatformAttributeMap};
use bias::platform::efi::{EFIStandalone, EFIStandaloneAttribute, EFIStandaloneBuilder};
use bias::platform::posix::{PosixBinary, PosixBinaryAttribute};
use bias::platform::windows::{WindowsBinary, WindowsBinaryAttribute};
use bias::platform::{Platform, PlatformError, PlatformProvider};
use bias_core::arch::aarch64::AARCH64;
use bias_core::arch::arm::ARM;
use bias_core::arch::x86::X86;
use bias_core::efi::EFIModuleType;
use bias_core::lifter::{Lifter, LifterBuilder};
use bias_core::prelude::{Endian, LanguageDB};

use binaryninja::binary_view::{BinaryView, BinaryViewExt};

use crate::loader::BNDBBinaryLoader;
use crate::util::infer_efi_module_kind;

pub(crate) fn build_lifter_for_platform(
    ldb: &LanguageDB,
    platform: &Platform,
) -> Result<Lifter, PipelineError> {
    let attrs = platform.attributes();
    let arch = attrs.get_attr::<ComponentArch>().ok_or_else(|| {
        PipelineError::source_with("missing architecture attribute for BNDB component platform")
    })?;

    let arch_info = match (arch.processor(), arch.bits()) {
        ("AARCH64", 64) => AARCH64::new(),
        ("ARM", 32) => ARM::new(),
        ("x86", 32) => X86::new(false),
        ("x86", 64) => X86::new(true),
        _ => {
            return Err(PipelineError::source_with(
                "unsupported architecture for BNDB component platform",
            ));
        }
    };

    let convention = match platform.name() {
        EFIStandalone::NAME => "efi",
        PosixBinary::NAME => "gcc",
        WindowsBinary::NAME => "windows",
        _ => "default",
    };

    let builder = ldb
        .lookup(
            arch.processor(),
            if arch.endian().is_little() {
                Endian::Little
            } else {
                Endian::Big
            },
            arch.bits(),
            arch.variant(),
        )
        .ok_or_else(|| {
            PipelineError::source_with("unsupported architecture for BNDB component platform")
        })?;

    let translator = LifterBuilder::build_or_cached(&builder).map_err(PipelineError::source)?;

    let convention = translator
        .compiler_conventions()
        .get(convention)
        .cloned()
        .or_else(|| translator.compiler_conventions().get("default").cloned())
        .ok_or_else(|| {
            PipelineError::source_with("no suitable convention found for BNDB component platform")
        })?;

    let lifter = Lifter::new_with(translator, convention, arch_info);

    Ok(lifter)
}

pub(crate) fn infer_platform(
    view: &BinaryView,
    bytes: &[u8],
    path: &Path,
    attrs: Option<&PlatformAttributeMap>,
) -> Result<(Platform, BA2ComponentAttributes), PlatformError> {
    let platform_name = view.default_platform().map(|p| p.name().to_string());

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());

    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();

    let architecture = ComponentArch::from_bytes(bytes);
    let loader_meta = BinaryLoaderMetadata::from_bytes(bytes);

    match platform_name.as_deref() {
        Some(n) if n.starts_with("efi-") => {
            let kind = infer_efi_module_kind(bytes, attrs);
            let is_te = matches!(kind, EFIModuleType::PeiModule);

            let mut builder = EFIStandaloneBuilder::new();
            builder.push(EFIStandaloneAttribute::name(file_name.clone()));
            builder.push(EFIStandaloneAttribute::path(path.to_path_buf()));
            builder.push(EFIStandaloneAttribute::kind(kind));

            if let Some(ref arch) = architecture {
                builder.push(EFIStandaloneAttribute::architecture(arch.clone()));
            }
            builder.push(EFIStandaloneAttribute::loader_metadata(loader_meta.clone()));

            let component_attrs = EFIStandaloneAttributes::new(kind)
                .with_architecture(architecture)
                .with_loader_metadata(loader_meta);

            let attrs = if is_te {
                BA2ComponentAttributes::EFIStandaloneTE(component_attrs)
            } else {
                BA2ComponentAttributes::EFIStandalonePE(component_attrs)
            };
            Ok((
                builder
                    .build_with(BNDBBinaryLoader::platform_loader())
                    .into(),
                attrs,
            ))
        }
        Some(n) if n.starts_with("linux-") => {
            let mut builder = bias::platform::posix::PosixBinaryBuilder::new();
            builder.push(PosixBinaryAttribute::name(file_name.clone()));
            builder.push(PosixBinaryAttribute::path(path.display().to_string()));

            if let Some(ref arch) = architecture {
                builder.push(PosixBinaryAttribute::architecture(arch.clone()));
            }
            builder.push(PosixBinaryAttribute::loader_metadata(loader_meta.clone()));

            let attrs = BA2ComponentAttributes::PosixELF(
                PosixELFAttributes::new("ELF", extension)
                    .with_architecture(architecture)
                    .with_loader_metadata(loader_meta),
            );

            Ok((
                builder
                    .build_with(BNDBBinaryLoader::platform_loader())
                    .into(),
                attrs,
            ))
        }
        Some(n) if n.starts_with("windows-") => {
            let mut builder = bias::platform::windows::WindowsBinaryBuilder::new();
            builder.push(WindowsBinaryAttribute::name(file_name.clone()));
            builder.push(WindowsBinaryAttribute::path(path.display().to_string()));

            if let Some(ref arch) = architecture {
                builder.push(WindowsBinaryAttribute::architecture(arch.clone()));
            }
            builder.push(WindowsBinaryAttribute::loader_metadata(loader_meta.clone()));

            let attrs = BA2ComponentAttributes::WindowsPE(
                WindowsPEAttributes::new("PE", extension)
                    .with_architecture(architecture)
                    .with_loader_metadata(loader_meta),
            );

            Ok((
                builder
                    .build_with(BNDBBinaryLoader::platform_loader())
                    .into(),
                attrs,
            ))
        }
        _ => Err(PlatformError::UnsupportedFormat),
    }
}
