use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use bias::component::ComponentLoader;
use bias::platform::common::PlatformAttributeMap;
use bias::platform::common::data::{PlatformDataProviderBuilder, PlatformDataProviderBuilderError};

use bias_core::decompiler;

use bias_vulhunt_engine::VulHuntProjectError;
use bias_vulhunt_engine::project::VulHuntProject;

use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use super::VulHuntServerError;

static INIT_PLATFORM_DATA: Once = Once::new();

#[derive(Debug, Error)]
pub enum VulHuntHandlerError {
    #[error("session `{0}` not found")]
    SessionNotFound(Uuid),
    #[error(transparent)]
    Project(#[from] VulHuntProjectError),
    #[error("task panicked: {0}")]
    Join(#[from] tokio::task::JoinError),
}

pub(crate) struct VulHuntSessionState {
    project: VulHuntProject,
}

impl VulHuntSessionState {
    pub(crate) fn new(project: VulHuntProject) -> Self {
        Self { project }
    }

    pub(crate) fn project(&self) -> &VulHuntProject {
        &self.project
    }

    pub(crate) fn project_mut(&mut self) -> &mut VulHuntProject {
        &mut self.project
    }
}

pub(crate) struct VulHuntSession {
    pub(crate) state: Arc<RwLock<VulHuntSessionState>>,
    pub(crate) path: PathBuf,
    pub(crate) created_at: Instant,
    pub(crate) last_accessed_at: Arc<RwLock<Instant>>,
}

impl VulHuntSession {
    fn new(project: VulHuntProject, path: impl Into<PathBuf>) -> Self {
        let now = Instant::now();
        Self {
            state: Arc::new(RwLock::new(VulHuntSessionState::new(project))),
            path: path.into(),
            created_at: now,
            last_accessed_at: Arc::new(RwLock::new(now)),
        }
    }

    pub(crate) async fn touch(&self) {
        *self.last_accessed_at.write().await = Instant::now();
    }
}

pub struct VulHuntSessionInfo {
    session_id: Uuid,
    path: PathBuf,
    created_at: Instant,
    last_accessed_at: Instant,
}

impl VulHuntSessionInfo {
    pub fn new(
        session_id: Uuid,
        path: impl Into<PathBuf>,
        created_at: Instant,
        last_accessed_at: Instant,
    ) -> Self {
        Self {
            session_id,
            path: path.into(),
            created_at,
            last_accessed_at,
        }
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    pub fn last_accessed_at(&self) -> Instant {
        self.last_accessed_at
    }
}

pub struct VulHuntHandler {
    loader: Arc<ComponentLoader<'static>>,
    data_provider: PlatformDataProviderBuilder,
    modules: Option<PathBuf>,
    sessions: Arc<Mutex<BTreeMap<Uuid, VulHuntSession>>>,
}

impl VulHuntHandler {
    pub fn new() -> Result<Self, VulHuntServerError> {
        let platform_data = env::var("BIAS_PLATFORM_DATA_DIR").map_err(|_| {
            VulHuntServerError::PlatformDataProvider(PlatformDataProviderBuilderError::NoValidPaths)
        })?;

        let data_provider = platform_data.parse::<PlatformDataProviderBuilder>()?;

        INIT_PLATFORM_DATA.call_once(|| {
            let root = data_provider.root_dir();
            tracing::info!(
                "initialising decompiler with platform data from `{}`",
                root.display()
            );
            if let Err(e) = decompiler::add_search_paths(root) {
                tracing::error!("failed to initialise decompiler with platform data: {e}");
            }
        });

        Self::new_with(data_provider)
    }

    pub fn new_with(
        data_provider: PlatformDataProviderBuilder,
    ) -> Result<Self, VulHuntServerError> {
        let root = data_provider.root_dir();
        Ok(Self {
            loader: Arc::new(ComponentLoader::new_with(root)?),
            data_provider,
            modules: None,
            sessions: Default::default(),
        })
    }

    pub fn set_module_directory(&mut self, modules: impl AsRef<Path>) {
        self.modules = Some(modules.as_ref().to_path_buf());
    }

    pub async fn open_project(
        &self,
        path: impl AsRef<Path>,
        attributes: Option<PlatformAttributeMap>,
    ) -> Result<Uuid, VulHuntHandlerError> {
        let path = path.as_ref();
        let data_provider = self.data_provider.clone();
        let modules = self.modules.clone();
        let loader = self.loader.clone();

        let mut attrs = attributes.unwrap_or_default();

        if !attrs.contains("modules")
            && let Some(modules) = modules
        {
            attrs.set_attr("modules", modules);
        }

        let path_clone = path.to_owned();
        let project = tokio::task::spawn_blocking(move || {
            VulHuntProject::new(&data_provider, &loader, &path_clone, attrs)
        })
        .await??;

        let session_id = Uuid::now_v7();
        let session = VulHuntSession::new(project, path);

        self.sessions.lock().await.insert(session_id, session);

        Ok(session_id)
    }

    pub async fn close_session(&self, session_id: Uuid) -> Result<(), VulHuntHandlerError> {
        self.sessions
            .lock()
            .await
            .remove(&session_id)
            .ok_or(VulHuntHandlerError::SessionNotFound(session_id))?;
        Ok(())
    }

    pub(crate) async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<Arc<RwLock<VulHuntSessionState>>, VulHuntHandlerError> {
        let sessions = self.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or(VulHuntHandlerError::SessionNotFound(session_id))?;

        session.touch().await;

        Ok(session.state.clone())
    }

    pub async fn list_sessions(&self) -> Vec<VulHuntSessionInfo> {
        let sessions = self.sessions.lock().await;
        let mut result = Vec::with_capacity(sessions.len());

        for (id, session) in sessions.iter() {
            let last_accessed_at = *session.last_accessed_at.read().await;
            result.push(VulHuntSessionInfo::new(
                *id,
                &session.path,
                session.created_at,
                last_accessed_at,
            ));
        }

        result
    }

    pub(crate) fn sessions_handle(&self) -> Arc<Mutex<BTreeMap<Uuid, VulHuntSession>>> {
        self.sessions.clone()
    }
}

pub(crate) async fn reap_expired(sessions: &Mutex<BTreeMap<Uuid, VulHuntSession>>, ttl: Duration) {
    let now = Instant::now();
    let mut sessions = sessions.lock().await;
    let mut expired = Vec::new();

    for (id, session) in sessions.iter() {
        let last_accessed = *session.last_accessed_at.read().await;
        if now.duration_since(last_accessed) > ttl {
            expired.push(*id);
        }
    }

    for id in &expired {
        tracing::info!("reaping expired session `{id}`");
        sessions.remove(id);
    }
}
