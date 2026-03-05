use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bias_core::kb::Lazy;
use bias_core::prelude::{ArchitectureDef, Endian};
use bias_core::Project;

use bias::component::LoadedBinaryComponent;
use bias::platform::common::flirt::FLIRTSymbolManager;
use bias::platform::common::TypeManager;

use bias::util::tags::{BlobTag, TagBuilder};
use bias::util::version::{FuzzyVersionBuilder, VersionMatchConfig};

use itertools::Itertools;
use walkdir::WalkDir;

pub mod analysis;
pub mod engine;
pub mod lua;

use self::lua::project::PlatformApi;

pub use self::engine::Engine;
pub use self::lua::scope::{SignatureEntry, SignatureRange, SignatureVersion};
pub use self::lua::{Checker, CheckerError};

#[derive(Debug, Clone, Default)]
pub struct VulHuntModuleDir(Option<PathBuf>);

impl VulHuntModuleDir {
    #[inline]
    pub fn none() -> Self {
        Self(None)
    }
}

impl Deref for VulHuntModuleDir {
    type Target = Option<PathBuf>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: AsRef<Path>> From<&T> for VulHuntModuleDir {
    fn from(p: &T) -> Self {
        Self(Some(p.as_ref().to_owned()))
    }
}

impl From<PathBuf> for VulHuntModuleDir {
    fn from(p: PathBuf) -> Self {
        Self(Some(p))
    }
}

impl From<String> for VulHuntModuleDir {
    fn from(s: String) -> Self {
        Self(Some(PathBuf::from(s)))
    }
}

impl From<Option<PathBuf>> for VulHuntModuleDir {
    fn from(opt: Option<PathBuf>) -> Self {
        Self(opt)
    }
}

impl<'a> From<Option<&'a Path>> for VulHuntModuleDir {
    fn from(opt: Option<&'a Path>) -> Self {
        Self(opt.map(Path::to_owned))
    }
}

impl From<&VulHuntModuleDir> for VulHuntModuleDir {
    fn from(other: &VulHuntModuleDir) -> Self {
        other.clone()
    }
}

pub static DEFAULT_ARCH_VARIANTS: Lazy<BTreeMap<&'static str, &'static [&'static str]>> =
    Lazy::new(|| {
        [
            ("ARM", ["v7", "v8T"].as_slice()),
            ("AARCH64", ["v8A"].as_slice()),
        ]
        .into_iter()
        .collect()
    });

#[derive(Clone)]
pub struct CheckerDB {
    checkers: Arc<[Checker]>,
    signature_files: Arc<BTreeMap<BlobTag, BTreeSet<String>>>,
    module_dir: VulHuntModuleDir,
}

impl CheckerDB {
    pub fn from_checkers(
        iter: impl IntoIterator<Item = Checker>,
        symbols: &FLIRTSymbolManager,
        module_dir: impl Into<VulHuntModuleDir>,
    ) -> Result<Self, CheckerError> {
        let mut checkers = iter.into_iter().collect();
        let signature_files = Self::load_signatures(&mut checkers, symbols)?;
        Ok(Self {
            checkers: Arc::from(checkers.into_boxed_slice()),
            signature_files: Arc::new(signature_files),
            module_dir: module_dir.into(),
        })
    }

    pub fn from_directory_with(
        path: impl AsRef<Path>,
        symbols: &FLIRTSymbolManager,
        ignore_errors: bool,
    ) -> Result<Self, CheckerError> {
        let path = path.as_ref();
        Self::from_directory_and_module_directory(
            path,
            symbols,
            ignore_errors,
            VulHuntModuleDir::none(),
        )
    }

    pub fn from_directory_and_module_directory(
        path: impl AsRef<Path>,
        symbols: &FLIRTSymbolManager,
        ignore_errors: bool,
        module_dir: impl Into<VulHuntModuleDir>,
    ) -> Result<Self, CheckerError> {
        let path = path.as_ref();
        let module_dir = module_dir.into();

        let walker = WalkDir::new(path).follow_links(true);
        let mut checkers = Vec::new();

        for entry in walker.into_iter() {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }

            if !entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "vh" || ext == "lua")
            {
                continue;
            }

            match Checker::from_file(entry.path(), module_dir.as_deref()) {
                Ok(checker) => {
                    tracing::trace!(
                        "loaded checker `{}` from {}",
                        checker.name(),
                        entry.path().display()
                    );
                    checkers.push(checker);
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to load checker from {}: {e}",
                        entry.path().display()
                    );

                    if !ignore_errors {
                        return Err(e);
                    }
                }
            }
        }

        if checkers.is_empty() {
            tracing::warn!("no checkers loaded from {}", path.display());
        }

        let signature_files = Self::load_signatures(&mut checkers, symbols)?;

        Ok(Self {
            checkers: Arc::from(checkers),
            signature_files: Arc::new(signature_files),
            module_dir,
        })
    }

    pub fn from_directory(
        path: impl AsRef<Path>,
        symbols: &FLIRTSymbolManager,
    ) -> Result<Self, CheckerError> {
        Self::from_directory_with(path, symbols, true)
    }

    pub fn iter<'a>(&'a self) -> impl ExactSizeIterator<Item = &'a Checker> {
        self.checkers.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.checkers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.checkers.len()
    }

    fn load_signatures(
        checkers: &mut Vec<Checker>,
        symbols: &FLIRTSymbolManager,
    ) -> Result<BTreeMap<BlobTag, BTreeSet<String>>, CheckerError> {
        let mut result = BTreeMap::new();

        for checker in checkers {
            let mut per_arch_sig_files = BTreeMap::<ArchitectureDef, BTreeSet<String>>::new();

            for signature in checker.signatures() {
                let arch_map = flirt_arch_lib_lookup(signature, symbols)?;
                for (arch, files) in arch_map {
                    per_arch_sig_files.entry(arch).or_default().extend(files);
                }
            }

            for (arch, paths) in per_arch_sig_files {
                let mut tb = TagBuilder::new();
                for path in paths.iter() {
                    tb.insert(BlobTag::new(path));
                }
                let tag = tb.build();
                result.entry(tag).or_insert(paths);
                checker.signature_arch_tags_mut().insert(arch, tag);
            }
        }
        Ok(result)
    }

    pub fn engine<'a, P>(
        &'a self,
        component: &'a LoadedBinaryComponent<'a>,
        project: &'a Project,
        symbols: FLIRTSymbolManager,
        types: TypeManager,
    ) -> Engine<'a, P>
    where
        P: for<'engine> PlatformApi<'engine>,
    {
        Engine::<P>::new(
            component,
            project,
            self,
            symbols,
            types,
            self.module_dir.as_deref(),
        )
    }
}

pub fn flirt_arch_lib_lookup(
    entry: &SignatureEntry,
    symbols: &FLIRTSymbolManager,
) -> Result<BTreeMap<ArchitectureDef, BTreeSet<String>>, CheckerError> {
    match entry {
        SignatureEntry::Range(r) => {
            fuzzy_match_symbol_files(symbols, r.project(), r.from(), r.to())
        }
        SignatureEntry::Version(v) => {
            fuzzy_match_symbol_files(symbols, v.project(), Some(v.version()), Some(v.version()))
        }
        SignatureEntry::File(path_str) => {
            let mut map = BTreeMap::new();
            for arch in extract_arch(Path::new(path_str))? {
                map.entry(arch)
                    .or_insert_with(BTreeSet::new)
                    .insert(path_str.clone());
            }
            Ok(map)
        }
    }
}

fn fuzzy_match_symbol_files(
    symbols: &FLIRTSymbolManager,
    project: &str,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<BTreeMap<ArchitectureDef, BTreeSet<String>>, CheckerError> {
    let mut matches = BTreeMap::<ArchitectureDef, BTreeSet<String>>::new();

    let match_config = VersionMatchConfig::new().with_strip_prefix();
    let mut builder = None;
    if let Some(from) = from {
        builder = Some(FuzzyVersionBuilder::new().inclusive_from(from));
    }
    if let Some(to) = to {
        builder = Some(
            builder
                .take()
                .unwrap_or_else(FuzzyVersionBuilder::new)
                .inclusive_to(to),
        );
    }
    let fuzzy_version = builder
        .map(|fvb| {
            fvb.build_with(&match_config)
                .map_err(CheckerError::SignatureVersionFormat)
        })
        .transpose()?;

    /*
    Assuming dir and file name structure of below where `project` = perl
    └── perl
        ├── v5.18.2
        │   ├── perl-AARCH64-LE-64.sig.gz
        │   ├── perl-ARM-LE-32.sig.gz
    */
    for full_path in symbols.signature_paths() {
        if let Some((file_name, version_path, project_path)) =
            full_path.components().rev().next_tuple()
        {
            if project_path.as_os_str().to_string_lossy() != project {
                continue;
            }
            let file_name = file_name.as_os_str().to_string_lossy();

            let arches = extract_arch(full_path)?;

            let version_path = version_path.as_os_str().to_string_lossy();

            if fuzzy_version.as_ref().map_or(false, |fv| {
                !fv.matches_with(version_path.as_ref(), &match_config)
            }) {
                continue;
            }

            let path_relative =
                PathBuf::from_iter([project, version_path.as_ref(), file_name.as_ref()])
                    .to_string_lossy()
                    .into_owned();

            for arch in arches {
                matches
                    .entry(arch)
                    .or_default()
                    .insert(path_relative.clone());
            }

            tracing::trace!("loaded flirt db {}", full_path.display());
        } else {
            Err(CheckerError::SignaturePathFormat(
                full_path.display().to_string(),
            ))?;
        };
    }
    Ok(matches)
}

fn extract_arch(full_path: &Path) -> Result<Vec<ArchitectureDef>, CheckerError> {
    let Some(arch_string) = full_path.file_name().and_then(|s| {
        let (_, rest) = s.to_str()?.split_once('-')?;
        rest.split('.').next()
    }) else {
        return Err(CheckerError::SignatureArch(full_path.display().to_string()));
    };

    let parse_endian = |s: &str| match s {
        "LE" => Some(Endian::Little),
        "BE" => Some(Endian::Big),
        _ => None,
    };

    let mut arch_parts = arch_string.split('-').rev();
    let Some((variant_or_bits, bits_or_endian, endian_or_proc)) = arch_parts.next_tuple() else {
        return Err(CheckerError::SignatureArch(full_path.display().to_string()));
    };

    let proc_or_else = arch_parts.next();

    let (variant, bits, endian, processor) = if let Some(proc_or_else) = proc_or_else {
        if let Some(endian) = parse_endian(bits_or_endian) {
            (None, variant_or_bits, endian, endian_or_proc)
        } else if let Some(endian) = parse_endian(endian_or_proc) {
            (Some(variant_or_bits), bits_or_endian, endian, proc_or_else)
        } else {
            return Err(CheckerError::SignatureArch(full_path.display().to_string()));
        }
    } else {
        let endian = parse_endian(bits_or_endian)
            .ok_or_else(|| CheckerError::SignatureArch(full_path.display().to_string()))?;
        (None, variant_or_bits, endian, endian_or_proc)
    };

    let bits = bits
        .parse::<usize>()
        .map_err(|_| CheckerError::SignatureArch(full_path.display().to_string()))?;

    if let Some(variant) = variant {
        Ok(vec![ArchitectureDef::new(processor, endian, bits, variant)])
    } else {
        let arches = DEFAULT_ARCH_VARIANTS
            .get(processor)
            .copied()
            .unwrap_or_else(|| ["default"].as_slice())
            .iter()
            .map(|variant| ArchitectureDef::new(processor, endian, bits, *variant))
            .collect();
        Ok(arches)
    }
}
