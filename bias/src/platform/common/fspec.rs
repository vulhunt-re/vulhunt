use std::ffi::OsStr;
use std::io;
use std::path::Path;

use bias_core::fugue::fspec::{FunctionSpecError, FunctionSpecs};
use thiserror::Error;

use super::data::{PlatformDataProvider, PlatformDataProviderError};

#[derive(Clone, Default)]
pub struct FunctionSpecDB {
    fspecs: Vec<FunctionSpecs>,
}

#[derive(Debug, Error)]
pub enum FunctionSpecDBError {
    #[error("cannot parse specification: {0}")]
    ParseSpec(#[from] FunctionSpecError),
    #[error("cannot read specification(s): {0}")]
    ReadSpec(#[from] io::Error),
    #[error("cannot read from specification directory: {0}")]
    ReadSpecDir(#[from] PlatformDataProviderError),
}

impl FunctionSpecDB {
    fn from_platform_data_aux(
        provider: &PlatformDataProvider,
        root: impl AsRef<Path>,
        ignore_errors: bool,
    ) -> Result<Self, FunctionSpecDBError> {
        let paths = provider
            .iter_files(root.as_ref())
            .map_err(FunctionSpecDBError::ReadSpecDir)?
            .filter_map(|entry| {
                let path = entry.ok()?;

                if !matches!(path.extension().and_then(OsStr::to_str), Some(ext) if ["yml", "yaml"].contains(&ext)) {
                    return None;
                }

                Some(path)
            });

        let mut fspecs = Vec::new();

        for path in paths {
            tracing::trace!(
                "loading function specification from `{}`...",
                path.display()
            );
            match FunctionSpecs::from_file(&path) {
                Ok(spec) => {
                    fspecs.push(spec);
                }
                Err(e) if ignore_errors => {
                    tracing::trace!(
                        "failed to load function specification from `{}`: {e}; skipping...",
                        path.display()
                    );
                }
                Err(e) => {
                    tracing::trace!(
                        "failed to load function specification from `{}`: {e}",
                        path.display()
                    );
                    return Err(FunctionSpecDBError::ParseSpec(e));
                }
            }
        }

        Ok(Self { fspecs })
    }

    pub fn from_platform_data_with(
        provider: &PlatformDataProvider,
        root: impl AsRef<Path>,
        ignore_errors: bool,
    ) -> Result<Self, FunctionSpecDBError> {
        match Self::from_platform_data_aux(provider, root, ignore_errors) {
            Err(_) if ignore_errors => Ok(Self::default()),
            res @ _ => res,
        }
    }

    pub fn from_platform_data(
        provider: &PlatformDataProvider,
        root: impl AsRef<Path>,
    ) -> Result<Self, FunctionSpecDBError> {
        Self::from_platform_data_with(provider, root, false)
    }

    pub fn specifications(&self) -> &[FunctionSpecs] {
        &self.fspecs
    }
}
