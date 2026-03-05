use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcstr::ArcStr;
use async_trait::async_trait;
use dyn_clone::DynClone;

use bias_core::prelude::graph::graph::{DiGraph, NodeIndex};
use bias_core::prelude::*;

use futures::Future;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::component::{ComponentLoader, LoadedComponent};
use crate::package::{PackageComponentData, PackageData};
use crate::pipeline::analysis::AnalysisGroup;
use crate::pipeline::types::property::{METADATA_CONTAINS, METADATA_DUPLICATE};
use crate::pipeline::{ClonableSink, PipelineAnalysisGroups, PipelineError};
use crate::platform::{Platform, PlatformProvider};
use crate::util::BytesOrMapping;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error(transparent)]
    Custom(anyhow::Error),
    #[error("package source has a dependency cycle")]
    DependencyCycle,
    #[error("package component `{0}` not in dependency graph")]
    EntityNotInGraph(Uuid),
}

impl SourceError {
    pub fn custom<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Custom(anyhow::Error::new(e))
    }
}

#[derive(Default)]
pub struct AnalysisGroupFilter<'b>(Option<&'b dyn AnalysisGroup>);

impl<'b> AnalysisGroupFilter<'b> {
    pub fn new(group: &'b dyn AnalysisGroup) -> Self {
        Self(Some(group))
    }

    pub fn should_analyse(&self, platform: &Platform) -> bool {
        let Some(group) = self.0 else { return true };
        group.should_analyse(&platform.attributes())
    }
}

pub type PackageItemQueue = flume::Sender<PackageItem>;

#[derive(Clone)]
pub struct PackageComponentItemQueue {
    channel: flume::Sender<PackageComponentItem>,
    events: Arc<AtomicUsize>,
}

impl PackageComponentItemQueue {
    pub async fn send_async(
        &self,
        item: PackageComponentItem,
    ) -> Result<(), flume::SendError<PackageComponentItem>> {
        self.channel.send_async(item).await?;
        self.events.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[async_trait]
pub trait Source: Send + Sync {
    async fn fetch_component_if<'a>(
        &'a self,
        cid: PackageComponentItem,
        filter: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError>;

    async fn fetch_component<'a>(
        &'a self,
        cid: PackageComponentItem,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.fetch_component_if(cid, Default::default()).await
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError>;

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError>;

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError>;

    fn load_component<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
        pid: Uuid,
        cid: Uuid,
        bytes: BytesOrMapping<'a>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        let _ = pid;
        loader
            .load_with(cid, bytes, platform)
            .map_err(PipelineError::source)
    }
}

#[async_trait]
impl Source for Box<dyn Source> {
    async fn fetch_component_if<'a>(
        &'a self,
        cid: PackageComponentItem,
        filter: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.deref().fetch_component_if(cid, filter).await
    }

    async fn fetch_component<'a>(
        &'a self,
        cid: PackageComponentItem,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.deref().fetch_component(cid).await
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        self.deref().fetch_package(pid).await
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        self.deref().stream_packages(queue).await
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        self.deref()
            .stream_package_components(pid, analysis_groups, queue)
            .await
    }

    fn load_component<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
        pid: Uuid,
        cid: Uuid,
        bytes: BytesOrMapping<'a>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        self.deref()
            .load_component(loader, pid, cid, bytes, platform)
    }
}

pub trait ClonableSource: Source + DynClone + 'static {}

dyn_clone::clone_trait_object!(ClonableSource);

impl<T> ClonableSource for T where T: Source + Clone + 'static {}

#[async_trait]
impl<T> Source for Arc<T>
where
    T: Source + ?Sized,
{
    async fn fetch_component_if<'a>(
        &'a self,
        cid: PackageComponentItem,
        filter: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.deref().fetch_component_if(cid, filter).await
    }

    async fn fetch_component<'a>(
        &'a self,
        cid: PackageComponentItem,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.deref().fetch_component(cid).await
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        self.deref().fetch_package(pid).await
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        self.deref().stream_packages(queue).await
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        self.deref()
            .stream_package_components(pid, analysis_groups, queue)
            .await
    }

    fn load_component<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
        pid: Uuid,
        cid: Uuid,
        bytes: BytesOrMapping<'a>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        self.deref()
            .load_component(loader, pid, cid, bytes, platform)
    }
}

#[repr(transparent)]
pub struct DataSource<T>
where
    T: Source,
{
    source: T,
}

impl<T> DataSource<T>
where
    T: Source,
{
    pub fn new(source: T) -> Self {
        Self { source }
    }
}

impl<T> DataSource<T>
where
    T: Source,
{
    pub fn into_inner(self) -> T {
        self.source
    }
}

impl<T> AsRef<T> for DataSource<T>
where
    T: Source,
{
    fn as_ref(&self) -> &T {
        &self.source
    }
}

impl<T> Deref for DataSource<T>
where
    T: Source,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

#[async_trait]
impl<T> Source for DataSource<T>
where
    T: Source,
{
    async fn fetch_component_if<'a>(
        &'a self,
        cid: PackageComponentItem,
        filter: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        Ok(self
            .deref()
            .fetch_component_if(cid, filter)
            .await?
            .map(PackageComponentData::into_data))
    }

    async fn fetch_component<'a>(
        &'a self,
        cid: PackageComponentItem,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        Ok(self
            .deref()
            .fetch_component(cid)
            .await?
            .map(PackageComponentData::into_data))
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        self.deref().fetch_package(pid).await
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        self.deref().stream_packages(queue).await
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        self.deref()
            .stream_package_components(pid, analysis_groups, queue)
            .await
    }

    fn load_component<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
        pid: Uuid,
        cid: Uuid,
        bytes: BytesOrMapping<'a>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        self.deref()
            .load_component(loader, pid, cid, bytes, platform)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum PackageDependencyKind {
    #[serde(
        rename = "metadata/relation/contains", // METADATA_CONTAINS
        alias = "Contains",
        alias = "contains"
    )]
    Contains,
    #[serde(
        rename = "metadata/relation/duplicate-of", // METADATA_DUPLICATE
        alias = "Duplicate",
        alias = "duplicate"
    )]
    Duplicate,
}

impl Display for PackageDependencyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Contains => METADATA_CONTAINS,
            Self::Duplicate => METADATA_DUPLICATE,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PackageDependencyGraph {
    graph: DiGraph<Uuid, PackageDependencyKind>,
    uuids: BTreeMap<Uuid, PackageComponentMeta>,
}

#[derive(Debug, Clone)]
pub struct PackageComponentMeta {
    node: NodeIndex,
    platform: &'static str,
}

impl PackageComponentMeta {
    pub fn platform_name(&self) -> &'static str {
        self.platform
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct PackageComponentVisitor {
    components: flume::Receiver<PackageComponentItem>,
}

struct PackageComponentVisitorTask {
    packages: flume::Receiver<PackageItem>,
    components_sender: flume::Sender<PackageComponentItem>,
}

impl PackageComponentVisitorTask {
    fn new(
        packages: flume::Receiver<PackageItem>,
        components_sender: flume::Sender<PackageComponentItem>,
    ) -> Self {
        Self {
            packages,
            components_sender,
        }
    }

    async fn stream_packages<T, U>(
        self,
        source: T,
        sink: U,
        groups: PipelineAnalysisGroups,
    ) -> Result<(), PipelineError>
    where
        T: ClonableSource,
        U: ClonableSink,
    {
        loop {
            let Some(pid) = self.fetch_next_package_id().await else {
                return Ok(());
            };

            let Some((package, fut)) = self
                .fetch_package(pid, dyn_clone::clone(&source), groups.clone())
                .await?
            else {
                return Ok(());
            };

            let PackageData {
                package,
                dependencies,
            } = package;

            let pid = package.id();

            // announce package to sink
            sink.push_package(package, dependencies.into_owned())
                .await?;

            // stream components
            let components = fut.await?;

            // inform analysis event
            sink.push_package_status(pid, components).await?;
        }
    }

    async fn fetch_next_package_id(&self) -> Option<PackageItem> {
        self.packages.recv_async().await.ok()
    }

    async fn fetch_package<T>(
        &self,
        pid: PackageItem,
        source: T,
        groups: PipelineAnalysisGroups,
    ) -> Result<
        Option<(
            PackageData<'static>,
            Pin<Box<dyn Future<Output = Result<usize, PipelineError>> + Send + 'static>>,
        )>,
        PipelineError,
    >
    where
        T: ClonableSource,
    {
        let Some(package) = source.fetch_package(pid.clone()).await? else {
            return Ok(None);
        };

        let components_sender = self.components_sender.clone();
        Ok(Some((
            package.into_owned(),
            Box::pin(async move {
                let events = Arc::new(AtomicUsize::new(0));
                let queue = PackageComponentItemQueue {
                    events: events.clone(),
                    channel: components_sender,
                };

                source.stream_package_components(pid, groups, queue).await?;

                Ok(events.load(Ordering::SeqCst))
            }),
        )))
    }
}

impl PackageComponentVisitor {
    pub fn bounded<T, U>(
        source: T,
        sink: U,
        groups: PipelineAnalysisGroups,
        bound: usize,
    ) -> (
        Self,
        Pin<Box<dyn Future<Output = Result<(), PipelineError>> + Send + 'static>>,
    )
    where
        T: ClonableSource,
        U: ClonableSink,
    {
        let (ctx, crx) = flume::bounded(bound);
        let (ptx, prx) = flume::bounded(bound);
        let source_for_visitor = dyn_clone::clone(&source);
        (
            Self { components: crx },
            Box::pin(async move {
                let _ = futures::try_join!(
                    source.stream_packages(ptx),
                    PackageComponentVisitorTask::new(prx, ctx).stream_packages(
                        source_for_visitor,
                        sink,
                        groups
                    ),
                )?;

                Ok(())
            }),
        )
    }

    pub fn unbounded<T, U>(
        source: T,
        sink: U,
        groups: PipelineAnalysisGroups,
    ) -> (
        Self,
        Pin<Box<dyn Future<Output = Result<(), PipelineError>> + Send + 'static>>,
    )
    where
        T: ClonableSource,
        U: ClonableSink,
    {
        let (ctx, crx) = flume::unbounded();
        let (ptx, prx) = flume::unbounded();
        let source_for_visitor = dyn_clone::clone(&source);
        (
            Self { components: crx },
            Box::pin(async move {
                let _ = futures::try_join!(
                    source.stream_packages(ptx),
                    PackageComponentVisitorTask::new(prx, ctx).stream_packages(
                        source_for_visitor,
                        sink,
                        groups
                    ),
                )?;

                Ok(())
            }),
        )
    }

    pub async fn fetch_next_component<'source, T>(
        &self,
        source: &'source T,
        groups: &PipelineAnalysisGroups,
    ) -> Result<Option<PackageComponentData<'source>>, PipelineError>
    where
        T: Source + 'source,
    {
        loop {
            let Ok(cid) = self.components.recv_async().await else {
                return Ok(None);
            };

            let Some(group) = groups.get(cid.platform()) else {
                continue;
            };

            if let Some(component) = source
                .fetch_component_if(cid, AnalysisGroupFilter::new(group))
                .await?
            {
                return Ok(Some(component));
            }
        }
    }

    pub async fn fetch_next_component_id(
        &self,
        groups: &PipelineAnalysisGroups,
    ) -> Option<PackageComponentItem> {
        loop {
            let Ok(cid) = self.components.recv_async().await else {
                return None;
            };

            if groups.supports_platform(cid.platform()) {
                return Some(cid);
            }
        }
    }

    pub async fn fetch_component<'source, T>(
        cid: PackageComponentItem,
        source: &'source T,
        groups: &PipelineAnalysisGroups,
    ) -> Result<Option<PackageComponentData<'source>>, PipelineError>
    where
        T: Source + 'source,
    {
        let Some(group) = groups.get(cid.platform()) else {
            return Ok(None);
        };

        if let Some(component) = source
            .fetch_component_if(cid, AnalysisGroupFilter::new(group))
            .await?
        {
            return Ok(Some(component));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageItem {
    id: Uuid,
    location: Option<ArcStr>,
}

impl PackageItem {
    pub fn new(id: Uuid) -> Self {
        Self { id, location: None }
    }

    pub fn new_with(id: Uuid, location: impl Into<ArcStr>) -> Self {
        Self {
            id,
            location: Some(location.into()),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageComponentItem {
    id: Uuid,
    package: PackageItem,
    platform: Cow<'static, str>,
}

impl PackageComponentItem {
    pub fn new(id: Uuid, package: PackageItem, meta: &PackageComponentMeta) -> Self {
        Self {
            id,
            package,
            platform: Cow::Borrowed(meta.platform),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn package(&self) -> &PackageItem {
        &self.package
    }

    pub fn platform(&self) -> &str {
        self.platform.as_ref()
    }
}

impl PackageDependencyGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            uuids: BTreeMap::new(),
        }
    }

    pub fn add_entity<P: PlatformProvider>(&mut self, id: Uuid) {
        self.add_entity_with_platform(id, P::NAME)
    }

    pub fn add_entity_with(&mut self, id: Uuid, platform: &Platform) {
        self.add_entity_with_platform(id, platform.name())
    }

    pub fn add_entity_with_platform(&mut self, id: Uuid, platform: &'static str) {
        self.uuids
            .entry(id)
            .or_insert_with_key(|&id| PackageComponentMeta {
                node: self.graph.add_node(id),
                platform,
            });
    }

    pub fn add_dependency(
        &mut self,
        from: Uuid,
        to: Uuid,
        kind: PackageDependencyKind,
    ) -> Result<(), SourceError> {
        let sid = self
            .uuids
            .get(&from)
            .ok_or_else(|| SourceError::EntityNotInGraph(from))?
            .node;
        let tid = self
            .uuids
            .get(&to)
            .ok_or_else(|| SourceError::EntityNotInGraph(from))?
            .node;

        self.graph.add_edge(sid, tid, kind);

        Ok(())
    }

    pub fn platform(&self, id: Uuid) -> Option<&'static str> {
        self.uuids.get(&id).map(|meta| meta.platform)
    }

    pub fn parents<'a>(
        &'a self,
        id: Uuid,
    ) -> impl Iterator<Item = (Uuid, PackageDependencyKind)> + 'a {
        self.uuids
            .get(&id)
            .map(|entity| {
                self.graph
                    .edges_directed(entity.node, Direction::Incoming)
                    .map(|e| (self.graph[e.source()], *e.weight()))
            })
            .into_iter()
            .flatten()
    }

    pub fn children<'a>(
        &'a self,
        id: Uuid,
    ) -> impl Iterator<Item = (Uuid, PackageDependencyKind)> + 'a {
        self.uuids
            .get(&id)
            .map(|entity| {
                self.graph
                    .edges_directed(entity.node, Direction::Outgoing)
                    .map(|e| (self.graph[e.target()], *e.weight()))
            })
            .into_iter()
            .flatten()
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), SourceError> {
        for (&id, entity) in other.entities() {
            self.uuids
                .entry(id)
                .or_insert_with_key(|&id| PackageComponentMeta {
                    node: self.graph.add_node(id),
                    platform: entity.platform,
                });
        }

        for edge in other.graph.raw_edges().iter() {
            let sid = other.graph[edge.source()];
            let tid = other.graph[edge.target()];

            self.add_dependency(sid, tid, edge.weight)?;
        }

        Ok(())
    }

    pub fn entities(&self) -> impl ExactSizeIterator<Item = (&Uuid, &PackageComponentMeta)> {
        self.uuids.iter()
    }
}
