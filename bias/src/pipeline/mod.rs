use std::borrow::Cow;
use std::collections::VecDeque;
use std::env;
use std::sync::Arc;
use std::time::Instant;

use ahash::AHashMap;

use bias_core::fugue::ir::LanguageDB;
use bias_core::inject::InjectionFixupError;
use bias_core::project::analysis::AnalysisError;
use bias_core::Project;

use either::Either;

use serde::{Deserialize, Serialize};

use thiserror::Error;
use tokio::task::JoinSet;

use ustr::{Ustr, UstrMap};
use uuid::Uuid;

use crate::component::{ComponentLoader, LoadedComponent};
use crate::package::PackageComponentData;
use crate::platform::common::ComponentBinaryLoaderMetadata;
use crate::platform::PlatformProvider;

use self::analysis::*;
use self::types::property::{Property, METADATA_ANALYSIS_CODE_SIZE_LIMIT, METADATA_DUPLICATE};

pub use self::property::{ComponentsAndProperties, Properties, PropertySet, PropertyTransformer};
pub use self::sink::{ClonableSink, Sink};
pub use self::source::{
    ClonableSource, PackageComponentItem, PackageComponentMeta, PackageComponentVisitor, Source,
};
pub use self::types::component::Component;

pub mod analysis;
pub mod property;
pub mod sink;
pub mod source;
pub use crate::types;

const BIAS_ANALYSIS_RUNTIME_WARNING_THRESHOLD_DEFAULT: u128 = 600000; // 10 mins in milliseconds

#[derive(Clone, Copy, Debug)]
struct PipelineConfig {
    code_size_limit: Option<usize>,
    component_deduplication: bool,
    analysis_runtime_warning_threshold: u128,
}

impl PipelineConfig {
    fn exceeds_code_size_limit(&self, component: &PackageComponentData) -> Option<usize> {
        if !component.platform().is_binary() {
            return None;
        }

        self.code_size_limit.and_then(|code_size| {
            // NOTE: if BIAS_CODE_SIZE_LIMIT is used as a threshold, only components with
            // code_size in the range 0..BIAS_CODE_SIZE_LIMIT will be analysed
            component
                .platform()
                .attributes()
                .get_attr::<ComponentBinaryLoaderMetadata>()
                .and_then(|metadata| {
                    if !(0..code_size).contains(&metadata.code_size()) {
                        Some(metadata.code_size())
                    } else {
                        None
                    }
                })
        })
    }

    fn predetermined_analysis_outcome<'source>(
        &self,
        component: PackageComponentData<'source>,
    ) -> Either<
        PackageComponentData<'source>,
        WithIdentity<Result<ComponentsAndPropertiesWith, ComponentAndError>>,
    > {
        let cid = component.id();

        if let Some(actual) = self.exceeds_code_size_limit(&component) {
            let pid = component
                .component
                .package_id()
                .expect("component metadata within a pipeline missing a package identifier");

            tracing::warn!(
                package = %pid,
                component = %cid,
                "skipping component due to code size limit",
            );

            let limit = self.code_size_limit.expect("code size limit missing");

            let property = Property::new_metadata(
                cid,
                METADATA_ANALYSIS_CODE_SIZE_LIMIT,
                serde_json::json!({
                    "actual": actual,
                    "limit": limit,
                }),
            );

            return Either::Right(WithIdentity {
                cid,
                pid,
                value: Ok(ComponentsAndPropertiesWith::for_skipped(
                    component, property,
                )),
            });
        }

        if !self.component_deduplication {
            return Either::Left(component);
        }

        if let Some(pcid) = component.component.primary_component_id() {
            // NOTE: here we handle case where we see a primary_component, and it's our
            // component. Ideally, we won't hit such a case, but this behaviour depends
            // on arbitrary Source implementations, and we have no mechanism to enforce
            // this contract.

            if pcid == cid {
                return Either::Left(component);
            }

            let pid = component
                .component
                .package_id()
                .expect("component metadata within a pipeline missing a package identifier");

            tracing::info!(
                package = %pid,
                component = %cid,
                primary_component = %pcid,
                "skipping component as it is a duplicate",
            );

            let property = Property::new_component_ref(cid, METADATA_DUPLICATE, pcid);

            return Either::Right(WithIdentity {
                cid,
                pid,
                value: Ok(ComponentsAndPropertiesWith::for_skipped(
                    component, property,
                )),
            });
        }

        Either::Left(component)
    }

    #[inline(always)]
    fn warn_if_analysis_threshold_exceeded(
        &self,
        start: Instant,
        component_size: usize,
        component_meta: &Component,
    ) {
        let elapsed_time = start.elapsed();
        let analysis_time = elapsed_time.as_millis();

        let package_id = component_meta
            .package_id()
            .expect("component metadata within a pipeline missing a package identifier");
        let component_id = component_meta.id();

        if analysis_time >= self.analysis_runtime_warning_threshold {
            tracing::warn!(
                package = %package_id,
                component = %component_id,
                component_size = %component_size,
                duration = %analysis_time,
                "analysis runtime exceeded threshold",
            );
        }
    }
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("analysis group for platform `{0}` already registered")]
    AlreadyRegistered(&'static str),
    #[error(transparent)]
    Analysis(Box<AnalysisError>),
    #[error(transparent)]
    AnalysisGroup(anyhow::Error),
    #[error(transparent)]
    Fixups(Box<InjectionFixupError>),
    #[error("analysis group incompatible with `{0}` platform")]
    IncompatibleAnalysisGroup(&'static str),
    #[error(transparent)]
    Io(anyhow::Error),
    #[error(transparent)]
    Runtime(anyhow::Error),
    #[error(transparent)]
    Sink(anyhow::Error),
    #[error(transparent)]
    Source(anyhow::Error),
    #[error(transparent)]
    Symbols(anyhow::Error),
    #[error("one or more errors occurred during pipeline execution; consumers: {consumers:#?}, producers: {producers:#?}, analysers: {analysers:#?}")]
    Tasks {
        consumers: Vec<Self>,
        producers: Vec<Self>,
        analysers: Vec<Self>,
    },
}

impl From<AnalysisError> for PipelineError {
    fn from(e: AnalysisError) -> Self {
        PipelineError::Analysis(Box::new(e))
    }
}

impl From<InjectionFixupError> for PipelineError {
    fn from(e: InjectionFixupError) -> Self {
        PipelineError::Fixups(Box::new(e))
    }
}

impl PipelineError {
    pub fn analysis<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::AnalysisGroup(anyhow::Error::new(e))
    }

    pub fn analysis_with<M>(msg: M) -> Self
    where
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        Self::AnalysisGroup(anyhow::Error::msg(msg))
    }

    pub fn io<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Io(anyhow::Error::new(e))
    }

    pub fn io_with<M>(msg: M) -> Self
    where
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        Self::Io(anyhow::Error::msg(msg))
    }

    pub fn runtime<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Runtime(anyhow::Error::new(e))
    }

    pub fn runtime_with<M>(msg: M) -> Self
    where
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        Self::Runtime(anyhow::Error::msg(msg))
    }

    pub fn sink<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Sink(anyhow::Error::new(e))
    }

    pub fn sink_with<M>(msg: M) -> Self
    where
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        Self::Sink(anyhow::Error::msg(msg))
    }

    pub fn source<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Source(anyhow::Error::new(e))
    }

    pub fn source_with<M>(msg: M) -> Self
    where
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        Self::Source(anyhow::Error::msg(msg))
    }

    pub fn symbols<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Symbols(anyhow::Error::new(e))
    }

    pub fn symbols_with<M>(msg: M) -> Self
    where
        M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        Self::Symbols(anyhow::Error::msg(msg))
    }
}

pub struct Pipeline {
    loader: Arc<ComponentLoader<'static>>,
    code_groups: Arc<UstrMap<AnalysisGroupForCode>>,
    data_groups: Arc<UstrMap<AnalysisGroupForData>>,
    property_transformers: Arc<AHashMap<String, Vec<Box<dyn PropertyTransformer>>>>,
    analysis_threads: usize,
    consumer_threads: usize,
    producer_threads: usize,
    producer_thread_io_limit: usize,
    config: PipelineConfig,
}

#[derive(Clone)]
pub struct PipelineAnalysisGroups {
    code_groups: Arc<UstrMap<AnalysisGroupForCode>>,
    data_groups: Arc<UstrMap<AnalysisGroupForData>>,
}

impl PipelineAnalysisGroups {
    pub fn get(&self, platform: impl AsRef<str>) -> Option<&dyn AnalysisGroup> {
        let id = Ustr::from_existing(platform.as_ref())?;

        self.code_groups
            .get(&id)
            .map(|group| group as &dyn AnalysisGroup)
            .or_else(|| {
                self.data_groups
                    .get(&id)
                    .map(|group| group as &dyn AnalysisGroup)
            })
    }

    pub fn should_analyse(&self, component: &PackageComponentMeta) -> bool {
        self.supports_platform(component.platform_name())
    }

    pub fn supports_platform(&self, platform: impl AsRef<str>) -> bool {
        let Some(id) = Ustr::from_existing(platform.as_ref()) else {
            return false;
        };
        self.code_groups.contains_key(&id) || self.data_groups.contains_key(&id)
    }
}

#[derive(Deserialize, Serialize)]
struct ComponentsAndPropertiesWith {
    results: ComponentsAndProperties,
}

impl ComponentsAndPropertiesWith {
    fn for_skipped(component: PackageComponentData<'_>, property: impl Into<Property>) -> Self {
        Self {
            results: ComponentsAndProperties::for_skipped(component, property),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct WithIdentity<T> {
    pid: Uuid,
    cid: Uuid,
    value: T,
}

#[derive(Deserialize, Serialize)]
struct ComponentWith<T> {
    component: Component,
    value: T,
}

type ComponentAndError = ComponentWith<PipelineError>;
type ComponentAndErrorString = ComponentWith<String>;

#[allow(dead_code)]
impl WithIdentity<Result<ComponentsAndProperties, ComponentAndErrorString>> {
    fn to_bytes(&self) -> Result<Vec<u8>, PipelineError> {
        rmp_serde::to_vec(self).map_err(PipelineError::io)
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PipelineError> {
        rmp_serde::from_slice(bytes.as_ref()).map_err(PipelineError::io)
    }
}

impl From<WithIdentity<Result<ComponentsAndPropertiesWith, ComponentAndError>>>
    for WithIdentity<Result<ComponentsAndProperties, ComponentAndErrorString>>
{
    fn from(
        slf: WithIdentity<Result<ComponentsAndPropertiesWith, ComponentAndError>>,
    ) -> WithIdentity<Result<ComponentsAndProperties, ComponentAndErrorString>> {
        WithIdentity {
            pid: slf.pid,
            cid: slf.cid,
            value: match slf.value {
                Ok(ComponentsAndPropertiesWith { results, .. }) => Ok(results),
                Err(ComponentAndError { component, value }) => Err(ComponentAndErrorString {
                    component,
                    value: value.to_string(),
                }),
            },
        }
    }
}

impl Pipeline {
    pub fn new(loader: ComponentLoader<'static>) -> Self {
        Self {
            loader: Arc::new(loader),
            code_groups: Arc::new(Default::default()),
            data_groups: Arc::new(Default::default()),
            property_transformers: Arc::new(Default::default()),
            analysis_threads: num_cpus::get(),
            consumer_threads: 1,
            producer_threads: 1,
            producer_thread_io_limit: num_cpus::get(),
            config: PipelineConfig {
                code_size_limit: env::var("BIAS_CODE_SIZE_LIMIT")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok()),
                component_deduplication: true,
                analysis_runtime_warning_threshold: env::var(
                    "BIAS_ANALYSIS_RUNTIME_WARNING_THRESHOLD",
                )
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(BIAS_ANALYSIS_RUNTIME_WARNING_THRESHOLD_DEFAULT),
            },
        }
    }

    pub fn new_data() -> Self {
        let mut slf = Self::new(ComponentLoader::new(Cow::Owned(LanguageDB::default())));

        slf.configure_as_data_workload();
        slf
    }

    pub fn set_code_size_limit(&mut self, code_size: usize) {
        self.config.code_size_limit = Some(code_size);
    }

    pub fn enable_component_deduplication(&mut self) {
        self.config.component_deduplication = true;
    }

    pub fn disable_component_deduplication(&mut self) {
        self.config.component_deduplication = false;
    }

    pub fn set_analysis_threads(&mut self, n: usize) {
        self.analysis_threads = n.max(1);
    }

    pub fn set_consumer_threads(&mut self, n: usize) {
        self.consumer_threads = n.max(1);
    }

    pub fn set_producer_threads(&mut self, n: usize) {
        self.producer_threads = n.max(1);
    }

    pub fn set_producer_thread_io_limit(&mut self, n: usize) {
        self.producer_thread_io_limit = n.max(1);
    }

    pub fn configure_for_remote_caching(&mut self) {
        // NOTE: depending on the network speed and latency, we may want to set these
        // defaults for local vs. cloud execution.
        self.consumer_threads = num_cpus::get();
        self.producer_threads = num_cpus::get();
        self.producer_thread_io_limit = num_cpus::get();
    }

    pub fn configure_as_data_workload(&mut self) {
        self.consumer_threads = num_cpus::get();
        self.producer_threads = num_cpus::get();
        self.analysis_threads = num_cpus::get();
        self.producer_thread_io_limit = 2;
    }

    pub fn configure_as_cpu_workload(&mut self) {
        self.consumer_threads = 2;
        self.producer_threads = 2;
        self.analysis_threads = num_cpus::get();
        self.producer_thread_io_limit = num_cpus::get();
    }

    pub fn register_group_for_code<P: PlatformProvider>(
        &mut self,
        group: AnalysisGroupForCode,
    ) -> Result<(), PipelineError> {
        if !P::LOADER.is_binary() {
            return Err(PipelineError::IncompatibleAnalysisGroup(P::NAME));
        }

        if self.code_groups.contains_key(&Ustr::from(P::NAME)) {
            return Err(PipelineError::AlreadyRegistered(P::NAME));
        }

        Arc::get_mut(&mut self.code_groups)
            .expect("cannot register group after pipeline has been shared")
            .insert(Ustr::from(P::NAME), group);
        Ok(())
    }

    pub fn register_group_for_data<P: PlatformProvider>(
        &mut self,
        group: AnalysisGroupForData,
    ) -> Result<(), PipelineError> {
        if !P::LOADER.is_data() {
            return Err(PipelineError::IncompatibleAnalysisGroup(P::NAME));
        }

        if self.data_groups.contains_key(&Ustr::from(P::NAME)) {
            return Err(PipelineError::AlreadyRegistered(P::NAME));
        }

        Arc::get_mut(&mut self.data_groups)
            .expect("cannot register group after pipeline has been shared")
            .insert(Ustr::from(P::NAME), group);
        Ok(())
    }

    pub fn register_property_transformer(
        &mut self,
        name: impl Into<String>,
        transformer: impl PropertyTransformer,
    ) {
        Arc::get_mut(&mut self.property_transformers)
            .expect("cannot register transformer after pipeline has been shared")
            .entry(name.into())
            .or_default()
            .push(Box::new(transformer));
    }

    fn analysis_groups(&self) -> PipelineAnalysisGroups {
        PipelineAnalysisGroups {
            code_groups: self.code_groups.clone(),
            data_groups: self.data_groups.clone(),
        }
    }

    pub async fn run<S, K>(&self, source: S, sink: K) -> Result<(), PipelineError>
    where
        S: ClonableSource,
        K: ClonableSink,
    {
        let (component_tx, component_rx) =
            flume::bounded::<PackageComponentData<'static>>(self.analysis_threads);
        let (result_tx, result_rx) = flume::unbounded::<
            WithIdentity<Result<ComponentsAndPropertiesWith, ComponentAndError>>,
        >();

        let loader = self.loader.clone();

        let mut producers = JoinSet::new();
        let mut consumers = JoinSet::new();
        let mut analysers = JoinSet::new();

        let groups = self.analysis_groups();

        let (queue, generator) = PackageComponentVisitor::bounded(
            dyn_clone::clone(&source),
            dyn_clone::clone(&sink),
            groups.clone(),
            self.analysis_threads,
        );

        producers.spawn(generator);

        let config = self.config;

        for _ in 0..self.producer_threads {
            let source = dyn_clone::clone(&source);
            let queue = queue.clone();
            let component_tx = component_tx.clone();
            let result_tx = result_tx.clone();
            let groups = groups.clone();

            producers.spawn(async move {
                while let Some(component) = queue.fetch_next_component(&source, &groups).await? {
                    match config.predetermined_analysis_outcome(component) {
                        Either::Left(component) => {
                            component_tx
                                .send_async(component.into_owned())
                                .await
                                .map_err(PipelineError::source)?;
                        }
                        Either::Right(predetermined) => {
                            result_tx
                                .send_async(predetermined)
                                .await
                                .map_err(PipelineError::source)?;
                        }
                    }
                }

                Ok::<(), PipelineError>(())
            });
        }

        for _ in 0..self.consumer_threads {
            let sink = dyn_clone::clone_box(&sink);
            let result_rx = result_rx.clone();
            let property_transformers = self.property_transformers.clone();

            consumers.spawn(async move {
                let mut workq = VecDeque::new();

                while let Ok(WithIdentity { pid, cid, value }) = result_rx.recv_async().await {
                    let ComponentsAndPropertiesWith { results } = match value {
                        Ok(r) => r,
                        Err(ComponentAndError { component, value }) => {
                            tracing::warn!(
                                package = %pid,
                                component = %cid,
                                "component analysis failed: {value}",
                            );
                            sink.push_component(pid, component).await?;
                            sink.push_component_status(pid, cid, Some(value)).await?;
                            continue;
                        }
                    };

                    let (components, results) = results.into_parts();

                    for component in components {
                        sink.push_component(pid, component)
                            .await
                            .map_err(PipelineError::sink)?;
                    }

                    for PropertySet { target, properties } in results {
                        workq.extend(properties);

                        while let Some(mut property) = workq.pop_front() {
                            if let Some(transforms) = property_transformers.get(property.name()) {
                                for transform in transforms {
                                    let (nproperty, derived) = transform
                                        .transform_property(target, property)
                                        .await
                                        .map_err(PipelineError::sink)?
                                        .into_parts();

                                    property = nproperty;
                                    workq.extend(derived);
                                }
                            }

                            sink.push_component_property(pid, target, property)
                                .await
                                .map_err(PipelineError::sink)?;
                        }
                    }

                    sink.push_component_status(pid, cid, None).await?;
                }

                Ok::<(), PipelineError>(())
            });
        }

        for _ in 0..self.analysis_threads {
            let component_rx = component_rx.clone();
            let result_tx = result_tx.clone();
            let loader = loader.clone();
            let code_groups = self.code_groups.clone();
            let data_groups = self.data_groups.clone();
            let source = dyn_clone::clone(&source);

            analysers.spawn(async move {
                while let Ok(component) = component_rx.recv_async().await {
                    let loader = loader.clone();
                    let code_groups = code_groups.clone();
                    let data_groups = data_groups.clone();
                    let result_tx = result_tx.clone();
                    let source = dyn_clone::clone(&source);

                    let result = tokio::task::spawn_blocking(move || {
                        let cid = component.id();
                        let pid = component.component.package_id().expect(
                            "component metadata within a pipeline missing a package identifier",
                        );

                        let start = Instant::now();
                        let size = component.bytes.len();
                        let component_meta = component.component.into_owned();

                        let result =
                            || -> Result<Option<ComponentsAndProperties>, PipelineError> {
                                let component = source.load_component(
                                    &loader,
                                    pid,
                                    cid,
                                    component.bytes,
                                    component.platform.into_owned(),
                                )?;

                                match component {
                                    LoadedComponent::Data(component) => data_groups
                                        .get(&Ustr::from(component.platform()))
                                        .map(|group| group.analyse_and_check(component))
                                        .transpose(),
                                    LoadedComponent::Binary(lifter, mut component) => code_groups
                                        .get(&Ustr::from(component.platform()))
                                        .map(|group| {
                                            let result = group
                                                .analyse_and_prefilter(&mut component, &lifter)?;

                                            if result.should_filter() {
                                                return Ok(result.into_components_and_properties());
                                            }

                                            let config = group.configuration(&component);
                                            let project =
                                                if let Some(loader) = component.project_loader() {
                                                    loader
                                                        .load_project(&component, lifter, &*config)
                                                        .map_err(PipelineError::source)?
                                                } else {
                                                    Project::new_with(&component, lifter, config)
                                                };

                                            let nresult =
                                                group.analyse_and_check(component, project)?;

                                            Ok(result
                                                .into_components_and_properties()
                                                .merge(nresult))
                                        })
                                        .transpose(),
                                }
                            }();

                        config.warn_if_analysis_threshold_exceeded(start, size, &component_meta);

                        result_tx
                            .send(WithIdentity {
                                pid,
                                cid,
                                value: match result {
                                    Ok(results) => Ok(ComponentsAndPropertiesWith {
                                        results: results
                                            .unwrap_or_default()
                                            .with_component(component_meta),
                                    }),
                                    Err(e) => Err(ComponentAndError {
                                        component: component_meta,
                                        value: e,
                                    }),
                                },
                            })
                            .ok();
                    })
                    .await;

                    if let Err(e) = result {
                        tracing::warn!("analysis task failed: {e}");
                    }
                }

                Ok::<(), PipelineError>(())
            });
        }

        drop(component_tx);
        drop(result_tx);

        let mut producer_errors = Vec::new();
        let mut consumer_errors = Vec::new();
        let mut analyser_errors = Vec::new();

        loop {
            tokio::select! {
                Some(res) = producers.join_next() => {
                    match res {
                        Ok(Err(e)) => producer_errors.push(e),
                        Err(e) => producer_errors.push(PipelineError::runtime(e)),
                        _ => (),
                    }
                }
                Some(res) = analysers.join_next() => {
                    match res {
                        Ok(Err(e)) => analyser_errors.push(e),
                        Err(e) => analyser_errors.push(PipelineError::runtime(e)),
                        _ => (),
                    }
                }
                Some(res) = consumers.join_next() => {
                    match res {
                        Ok(Err(e)) => consumer_errors.push(e),
                        Err(e) => consumer_errors.push(PipelineError::runtime(e)),
                        _ => (),
                    }
                }
                else => break,
            }
            tokio::task::yield_now().await;
        }

        if producer_errors.is_empty() && analyser_errors.is_empty() && consumer_errors.is_empty() {
            Ok(())
        } else {
            Err(PipelineError::Tasks {
                consumers: consumer_errors,
                producers: producer_errors,
                analysers: analyser_errors,
            })
        }
    }
}
