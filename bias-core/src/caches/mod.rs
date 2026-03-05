use std::path::{Path, PathBuf};

use thiserror::Error;
#[cfg(feature = "import-c")]
use walkdir::WalkDir;

use crate::cio::TypeError;
#[cfg(feature = "import-c")]
use crate::cio::TypeInfoDB;
use crate::lifter::{LifterBuilder, LifterBuilderError};

#[derive(Debug, Clone)]
pub struct CacheBuilder {
    root: PathBuf,
}

#[derive(Debug, Error)]
pub enum CacheBuilderError {
    #[error(transparent)]
    LifterCache(#[from] LifterBuilderError),
    #[error(transparent)]
    TypeCache(#[from] TypeError),
}

impl CacheBuilder {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            root: path.as_ref().to_owned(),
        }
    }

    pub fn build_caches(&self) -> Result<(), CacheBuilderError> {
        let lb = LifterBuilder::new(&self.root)?;
        lb.build_translator_cache()?;

        #[cfg(feature = "import-c")]
        {
            let walker = WalkDir::new(&self.root).into_iter();

            for entry in walker
                .filter_entry(|e| {
                    !e.file_type().is_file()
                        || e.file_name()
                            .to_str()
                            .map(|s| {
                                s.ends_with(".h")
                                    || s.ends_with(".H")
                                    || s.ends_with(".hh")
                                    || s.ends_with(".hpp")
                            })
                            .unwrap_or(false)
                })
                .filter_map(|entry| entry.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }

                let tdb = TypeInfoDB::from_file_with(entry.path(), true)?;
                let cached = entry.path().with_extension("bin");
                tdb.cache(cached)?;
            }
        }

        Ok(())
    }
}
