use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::{fs, io};

use itertools::{Itertools, Position};
use thiserror::Error;
use vfs::{AltrootFS, FileSystem, OverlayFS, PhysicalFS, VfsFileType, VfsPath};

#[derive(Debug, Error)]
pub enum PlatformDataProviderBuilderError {
    #[error("no paths provided")]
    EmptyPaths,
    #[error("no valid paths found for platform data")]
    NoValidPaths,
    #[error("platform data path `{0}` is not a directory")]
    NotADirectory(PathBuf),
    #[error("platform data path `{0}` is not readable")]
    NotReadable(PathBuf),
    #[error("platform data path `{0}` used as root is not writable")]
    NotWritable(PathBuf),
}

impl PlatformDataProviderBuilderError {
    pub fn not_a_directory(path: impl AsRef<Path>) -> Self {
        Self::NotADirectory(path.as_ref().to_path_buf())
    }

    pub fn not_readable(path: impl AsRef<Path>) -> Self {
        Self::NotReadable(path.as_ref().to_path_buf())
    }

    pub fn not_writable(path: impl AsRef<Path>) -> Self {
        Self::NotWritable(path.as_ref().to_path_buf())
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct PlatformDataProviderBuilder {
    paths: Vec<PathBuf>,
}

impl FromStr for PlatformDataProviderBuilder {
    type Err = PlatformDataProviderBuilderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let paths = s.split(':').filter_map(|path| {
            let path = path.trim();

            (!path.is_empty()).then_some(PathBuf::from(path))
        });

        Self::new(paths)
    }
}

impl PlatformDataProviderBuilder {
    pub fn new(
        paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Result<Self, PlatformDataProviderBuilderError> {
        let paths = paths.into_iter().map(|p| p.into()).collect::<Vec<_>>();

        if paths.is_empty() {
            return Err(PlatformDataProviderBuilderError::EmptyPaths);
        }

        Ok(Self { paths })
    }

    pub fn build(
        &self,
        platform_dir: &str,
    ) -> Result<PlatformDataProvider, PlatformDataProviderBuilderError> {
        let paths = self
            .paths
            .iter()
            .with_position()
            .filter_map(|(pos, path)| {
                if !path.is_dir() {
                    return Some(Err(PlatformDataProviderBuilderError::not_a_directory(path)));
                }

                let path = path.join("platforms").join(platform_dir);

                // User directories may contain only one platform-specific subdirectory
                // (e.g. `/platform/posix` or `/platform/uefi`). We skip paths that are
                // not valid directories, except for the first one (bias-data).
                if !path.is_dir() {
                    if matches!(pos, Position::First | Position::Only) {
                        return Some(Err(PlatformDataProviderBuilderError::not_a_directory(
                            &path,
                        )));
                    }

                    tracing::warn!(
                        "skipping platform data path `{}` as it is not a directory",
                        path.display()
                    );

                    return None;
                }

                // Check that the last path is writable
                if pos == Position::Last {
                    let Ok(meta) = fs::metadata(&path) else {
                        return Some(Err(PlatformDataProviderBuilderError::not_readable(&path)));
                    };

                    let permissions = meta.permissions();

                    if permissions.readonly() {
                        return Some(Err(PlatformDataProviderBuilderError::not_writable(&path)));
                    }
                }

                Some(Ok(path))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if paths.is_empty() {
            return Err(PlatformDataProviderBuilderError::NoValidPaths);
        }

        let overlay = Self::build_overlay(&paths);

        Ok(PlatformDataProvider {
            paths: Arc::from(paths),
            overlay,
        })
    }

    fn build_overlay(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> OverlayFS {
        let mut vfs_paths = paths
            .into_iter()
            .map(|path| AltrootFS::new(PhysicalFS::new(path).into()).into())
            .collect::<Vec<_>>();

        vfs_paths.reverse();

        OverlayFS::new(&vfs_paths)
    }

    pub fn root_dir(&self) -> &Path {
        self.paths.first().expect("at least one path")
    }
}

#[derive(Debug, Error)]
pub enum PlatformDataProviderError {
    #[error("path `{0}` is not readable")]
    NotReadable(PathBuf),
    #[error("path `{0}` is not valid UTF-8")]
    InvalidUtf8Path(PathBuf),
}

impl PlatformDataProviderError {
    pub fn not_readable(path: impl AsRef<Path>) -> Self {
        Self::NotReadable(path.as_ref().to_path_buf())
    }

    pub fn invalid_utf8(path: impl AsRef<Path>) -> Self {
        Self::InvalidUtf8Path(path.as_ref().to_path_buf())
    }
}

#[derive(Debug, Clone)]
pub struct PlatformDataProvider {
    paths: Arc<[PathBuf]>,
    overlay: OverlayFS,
}

impl PlatformDataProvider {
    pub fn platform_root_dir(&self) -> &Path {
        self.paths.first().expect("at least one path")
    }

    pub fn platform_user_dirs(&self) -> impl Iterator<Item = &Path> {
        self.paths.iter().skip(1).map(PathBuf::as_path)
    }

    pub fn iter_files(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<impl Iterator<Item = Result<PathBuf, io::Error>>, PlatformDataProviderError> {
        // NOTE: OverlayFS is cheap to clone, as it uses Arc internally
        let path = path.as_ref();

        let Some(path) = path.to_str() else {
            return Err(PlatformDataProviderError::invalid_utf8(path));
        };

        let vpath = VfsPath::new(self.overlay.clone())
            .join(path)
            .map_err(|_| PlatformDataProviderError::not_readable(path))?;

        let iter = vpath
            .walk_dir()
            .map_err(|_| PlatformDataProviderError::not_readable(path))?
            .map(move |entry| {
                let entry = entry.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        PlatformDataProviderError::not_readable(vpath.as_str()),
                    )
                })?;

                let metadata = entry.metadata().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        PlatformDataProviderError::not_readable(vpath.as_str()),
                    )
                })?;

                Ok((entry, metadata))
            })
            .filter_map(|res| {
                res.map(|(entry, metadata)| {
                    (metadata.file_type == VfsFileType::File).then(|| PathBuf::from(entry.as_str()))
                })
                .transpose()
            });

        Ok(iter)
    }

    pub fn resolve(&self, path: impl AsRef<Path>) -> Result<PathBuf, PlatformDataProviderError> {
        let path = path.as_ref().to_string_lossy();

        self.overlay
            .real_path(path.as_ref())
            .map_err(|_| PlatformDataProviderError::not_readable(path.as_ref()))
    }

    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        let Some(path) = path.as_ref().to_str() else {
            return false;
        };

        self.overlay.exists(path.as_ref()).unwrap_or(false)
    }
}
