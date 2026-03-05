use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::util::tags::{BlobTag, TagBuilder};
use ahash::HashMapExt;
use bias_compat_flirt::{FLIRTError, FLIRTMatches, FLIRTSymbols, FrozenFLIRTDB, FLIRTDB};
use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::prelude::*;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use thiserror::Error;
use ustr::UstrMap;

use crate::platform::common::data::{PlatformDataProvider, PlatformDataProviderError};

use super::types::FunctionTypeMapping;

const PLATFORM_SIGS_PATH: &'static str = "/sigs";

#[derive(Clone)]
pub struct FLIRTSymbolManager {
    databases: Arc<DashMap<String, FrozenFLIRTDB>>,
    sig_paths: Vec<PathBuf>,
    platform_data: PlatformDataProvider,
}

#[derive(Debug, Error)]
pub enum FLIRTSymbolManagerError {
    #[error("FLIRT pattern/signature database `{0}` could not be loaded: {1}")]
    DatabaseLoad(String, FLIRTError),
    #[error("platform directory does not exist")]
    InvalidPlatformDirectory,
    #[error("FLIRT pattern/signature database `{0}` does not exist")]
    InvalidFLIRTDB(String),
    #[error(transparent)]
    PlatformData(#[from] PlatformDataProviderError),
    #[error("failed to resolve path `{0}`")]
    Io(#[from] io::Error),
}

pub struct FunctionSymbolMapping {
    tag: BlobTag,
    matches: FLIRTMatches,
    symbols: FLIRTSymbols,
    fmapping: BTreeMap<FunctionId, Ustr>,
    smapping: UstrMap<FunctionId>,
}

impl FunctionSymbolMapping {
    pub fn from_project(project: &Project) -> Self {
        let mut smapping = UstrMap::new();
        let mut fmapping = BTreeMap::new();

        for (id, name) in project
            .functions()
            .values()
            .filter_map(|f| f.name().map(|name| (f.id(), name)))
        {
            fmapping.insert(id, name);
            smapping.insert(name, id);
        }

        Self {
            tag: BlobTag::default(),
            matches: FLIRTMatches::default(),
            symbols: FLIRTSymbols::default(),
            fmapping,
            smapping,
        }
    }

    pub fn tag(&self) -> BlobTag {
        self.tag
    }

    pub fn function_mapping(&self) -> &BTreeMap<FunctionId, Ustr> {
        &self.fmapping
    }

    pub fn symbol_mapping(&self) -> &UstrMap<FunctionId> {
        &self.smapping
    }

    pub fn matches(&self) -> &FLIRTMatches {
        &self.matches
    }

    pub fn symbols(&self) -> &FLIRTSymbols {
        &self.symbols
    }

    pub fn insert(&mut self, name: impl Into<Ustr>, id: FunctionId) {
        let name = name.into();
        self.fmapping.insert(id, name);
        self.smapping.insert(name, id);
    }

    pub fn rebind(&mut self, old_name: Option<Ustr>, new_name: impl Into<Ustr>, id: FunctionId) {
        let new_name = new_name.into();

        if let Some((old_id, old_name)) =
            old_name.and_then(|n| self.smapping.get(&n).copied().map(|id| (id, n)))
        {
            self.fmapping.remove(&old_id);
            self.smapping.remove(&old_name);
        }

        self.fmapping.insert(id, new_name);
        self.smapping.insert(new_name, id);
    }

    pub fn update_type_mapping(&self, mapping: &mut FunctionTypeMapping) {
        let bits = mapping.address_bits();
        let typedb = mapping.types().to_owned();

        let tmap = mapping.mapping_mut();

        for (&id, nm) in self.symbols().iter() {
            let Entry::Vacant(entry) = tmap.entry(id) else {
                continue;
            };

            let nm = nm.last().unwrap();
            if let Some(t) = typedb.get_prototype_for(&**nm, bits) {
                entry.insert(t);
            }
        }
    }
}

impl FLIRTSymbolManager {
    pub fn new(platform_data: PlatformDataProvider) -> Result<Self, FLIRTSymbolManagerError> {
        if !platform_data.exists(PLATFORM_SIGS_PATH) {
            return Err(FLIRTSymbolManagerError::InvalidPlatformDirectory);
        }
        let allowed_exts = [".pat", ".sig", ".pat.gz", ".sig.gz"];

        let sig_paths = platform_data
            .iter_files(PLATFORM_SIGS_PATH)?
            .filter_map(|path| {
                let path = match path.map_err(FLIRTSymbolManagerError::Io) {
                    Ok(p) => p,
                    Err(e) => {
                        return Some(Err(e));
                    }
                };

                let path = path.to_str()?;

                for ext in allowed_exts {
                    if let Some(p) = path.strip_suffix(ext) {
                        return Some(Ok(PathBuf::from(p)));
                    }
                }

                None
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            platform_data,
            sig_paths,
            databases: Arc::new(DashMap::new()),
        })
    }

    pub fn get_ref(
        &self,
        prefix: impl AsRef<str>,
    ) -> Result<Ref<'_, String, FrozenFLIRTDB>, FLIRTSymbolManagerError> {
        let prefix = prefix.as_ref();
        let (database, ext) = ["pat", "sig", "pat.gz", "sig.gz"]
            .into_iter()
            .find_map(|ext| {
                let database = Path::new(PLATFORM_SIGS_PATH)
                    .join(prefix)
                    .with_extension(ext);

                self.platform_data.resolve(database).map(|d| (d, ext)).ok()
            })
            .ok_or_else(|| FLIRTSymbolManagerError::InvalidFLIRTDB(prefix.to_owned()))?;

        self.databases
            .entry(prefix.to_owned())
            .or_try_insert_with(|| match ext {
                "sig" | "sig.gz" => FLIRTDB::from_sig_file(&database)
                    .map(FLIRTDB::freeze)
                    .map_err(|e| FLIRTSymbolManagerError::DatabaseLoad(prefix.to_owned(), e)),
                "pat" | "pat.gz" => FLIRTDB::from_pat_file(&database)
                    .map(FLIRTDB::freeze)
                    .map_err(|e| FLIRTSymbolManagerError::DatabaseLoad(prefix.to_owned(), e)),
                _ => unreachable!("extension is checked above"),
            })
            .map(|r| r.downgrade())
    }

    pub fn get(&self, prefix: impl AsRef<str>) -> Result<FrozenFLIRTDB, FLIRTSymbolManagerError> {
        Ok(self.get_ref(prefix)?.value().to_owned())
    }

    pub fn signature_paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.sig_paths.iter().map(|p| p.as_path())
    }

    pub fn function_symbol_mapping(
        &self,
        prefixes: impl IntoIterator<Item = impl AsRef<str>>,
        project: &Project,
    ) -> Result<FunctionSymbolMapping, FLIRTSymbolManagerError> {
        self.function_symbol_mapping_with(prefixes, project, false)
    }

    pub fn function_symbol_mapping_with(
        &self,
        prefixes: impl IntoIterator<Item = impl AsRef<str>>,
        project: &Project,
        ignore_existing_symbols: bool,
    ) -> Result<FunctionSymbolMapping, FLIRTSymbolManagerError> {
        let mut tbuilder = TagBuilder::new();

        let databases = prefixes.into_iter().map(|prefix| {
            let prefix = prefix.as_ref();
            let database = self.get(prefix)?;
            tbuilder.insert(BlobTag::new(prefix));
            Ok::<_, FLIRTSymbolManagerError>(database)
        });

        let mut matches = FLIRTMatches::new();
        let mut symbols = FLIRTSymbols::new();

        let bounds = project
            .try_get_analysis::<CodeBlockBounds>()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(CodeBlockBounds::new_with(project)));

        for database in databases {
            let database = database?;
            database.matches_into(project, &*bounds, &mut matches, &mut symbols);
            matches.clear();
        }

        let tag = tbuilder.build();

        let mut smapping = UstrMap::new();
        let mut fmapping = BTreeMap::new();

        let fiter = project
            .functions()
            .values()
            .filter_map(|f| {
                let name = f.name()?;
                Some((f.id(), name))
            })
            .chain(symbols.iter().filter_map(|(&id, names)| {
                if ignore_existing_symbols || project.functions()[id].name().is_none() {
                    Some((id, Ustr::from(names.last().unwrap())))
                } else {
                    None
                }
            }));

        for (id, name) in fiter {
            fmapping.insert(id, name);
            smapping.insert(name, id);
        }

        Ok(FunctionSymbolMapping {
            tag,
            matches,
            symbols,
            fmapping,
            smapping,
        })
    }

    pub fn ensure_available(&self, prefix: impl AsRef<str>) -> Result<(), FLIRTSymbolManagerError> {
        drop(self.get_ref(prefix)?);
        Ok(())
    }
}
