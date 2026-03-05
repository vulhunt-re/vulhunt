use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use async_trait::async_trait;

use crate::component::Component;
use crate::package::Package;
use crate::pipeline::property::Property;
use crate::pipeline::sink::Sink;
use crate::pipeline::source::PackageDependencyGraph;
use crate::pipeline::PipelineError;

use dashmap::mapref::entry::{Entry, OccupiedEntry};
use dashmap::DashMap;

use uuid::Uuid;

#[derive(Debug)]
pub struct ComponentAnalysisState {
    component: Component,
    status: Option<PipelineError>,
}

impl Deref for ComponentAnalysisState {
    type Target = Component;

    fn deref(&self) -> &Self::Target {
        self.component()
    }
}

impl DerefMut for ComponentAnalysisState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.component_mut()
    }
}

impl ComponentAnalysisState {
    pub fn new(component: Component) -> Self {
        Self::new_with(component, None)
    }

    pub fn new_with(component: Component, status: impl Into<Option<PipelineError>>) -> Self {
        Self {
            component,
            status: status.into(),
        }
    }

    pub fn component(&self) -> &Component {
        &self.component
    }

    pub fn component_mut(&mut self) -> &mut Component {
        &mut self.component
    }

    pub fn error_status(&self) -> Option<&PipelineError> {
        self.status.as_ref()
    }

    pub fn error_status_mut(&mut self) -> Option<&mut PipelineError> {
        self.status.as_mut()
    }
}

pub struct PackageAnalysisState<'a> {
    pub package: &'a mut Package,
    pub package_properties: &'a mut Vec<Property>,
    pub components: &'a mut BTreeMap<Uuid, ComponentAnalysisState>,
    pub component_properties: &'a mut BTreeMap<Uuid, Vec<Property>>,
    pub dependencies: &'a PackageDependencyGraph,
}

impl<'a> PackageAnalysisState<'a> {
    pub fn package(&self) -> &Package {
        self.package
    }

    pub fn package_mut(&mut self) -> &mut Package {
        self.package
    }

    pub fn components(&self) -> &BTreeMap<Uuid, ComponentAnalysisState> {
        self.components
    }

    pub fn components_mut(&mut self) -> &mut BTreeMap<Uuid, ComponentAnalysisState> {
        self.components
    }

    pub fn component(&self, id: &Uuid) -> Option<&ComponentAnalysisState> {
        self.components.get(id)
    }

    pub fn component_mut(&mut self, id: &Uuid) -> Option<&mut ComponentAnalysisState> {
        self.components.get_mut(id)
    }

    #[deprecated(
        since = "2.0.17",
        note = "deprecated in favour of `component_properties`"
    )]
    pub fn properties(&self) -> &BTreeMap<Uuid, Vec<Property>> {
        self.component_properties
    }

    #[deprecated(
        since = "2.0.17",
        note = "deprecated in favour of `component_properties_mut`"
    )]
    pub fn properties_mut(&mut self) -> &mut BTreeMap<Uuid, Vec<Property>> {
        self.component_properties
    }

    pub fn component_properties(&self) -> &BTreeMap<Uuid, Vec<Property>> {
        self.component_properties
    }

    pub fn component_properties_mut(&mut self) -> &mut BTreeMap<Uuid, Vec<Property>> {
        self.component_properties
    }

    pub fn package_properties(&self) -> &[Property] {
        self.package_properties
    }

    pub fn package_properties_mut(&mut self) -> &mut Vec<Property> {
        self.package_properties
    }

    pub fn dependencies(&self) -> &PackageDependencyGraph {
        self.dependencies
    }
}

#[async_trait]
pub trait PackageAnalyser<'a>: Send + Sync + 'a {
    async fn analyse_package<'state>(
        &self,
        state: PackageAnalysisState<'state>,
    ) -> Result<(), PipelineError>;
}

#[derive(Debug, Default)]
struct PendingPackageAnalysisState {
    package: Option<Package>,
    package_properties: Vec<Property>,
    components: BTreeMap<Uuid, ComponentAnalysisState>,
    component_properties: BTreeMap<Uuid, Vec<Property>>,
    dependencies: Option<PackageDependencyGraph>,
    status: PackageAnalysisStatus,
    component_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PackageAnalysisStatus {
    #[default]
    Pending,
    ExpectingComponents(usize),
}

pub struct PackageAnalysisSink<'a, T: Sink> {
    analyses: Vec<Box<dyn PackageAnalyser<'a>>>,
    pending: DashMap<Uuid, PendingPackageAnalysisState>,
    inner: T,
}

impl<'a, T> PackageAnalysisSink<'a, T>
where
    T: Sink,
{
    pub fn new(sink: T) -> Self {
        Self {
            analyses: Vec::new(),
            inner: sink,
            pending: DashMap::new(),
        }
    }

    pub fn register_analysis(&mut self, analysis: impl PackageAnalyser<'a>) {
        self.analyses.push(Box::new(analysis));
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    async fn try_emit(
        &self,
        pkg: OccupiedEntry<'_, Uuid, PendingPackageAnalysisState>,
    ) -> Result<(), PipelineError> {
        let pkg_ref = pkg.get();

        // NOTE: this should be on n == |components|; if n < |components| we have a problem
        if !matches!(pkg_ref.status, PackageAnalysisStatus::ExpectingComponents(n) if n <= pkg_ref.component_events)
        {
            // not ready
            return Ok(());
        }

        let (pid, mut pkg) = pkg.remove_entry();

        let mut package = pkg.package.ok_or_else(|| {
            PipelineError::sink_with(
                "event ordering invariant violation: package status before package metadata (emit ready)",
            )
        })?;

        let dependencies = pkg.dependencies.ok_or_else(|| {
            PipelineError::sink_with(
                "event ordering invariant violation: package status before package metadata (emit ready)",
            )
        })?;

        for analysis in self.analyses.iter() {
            analysis
                .analyse_package(PackageAnalysisState {
                    package: &mut package,
                    package_properties: &mut pkg.package_properties,
                    components: &mut pkg.components,
                    component_properties: &mut pkg.component_properties,
                    dependencies: &dependencies,
                })
                .await?;
        }

        self.inner.push_package(package, dependencies).await?;

        for property in pkg.package_properties.into_iter() {
            self.inner.push_package_property(pid, property).await?;
        }

        self.inner
            .push_package_status(pid, pkg.components.len())
            .await?;

        for (cid, ComponentAnalysisState { component, status }) in pkg.components.into_iter() {
            self.inner.push_component(pid, component).await?;

            for property in pkg.component_properties.remove(&cid).into_iter().flatten() {
                self.inner
                    .push_component_property(pid, cid, property)
                    .await?;
            }

            self.inner.push_component_status(pid, cid, status).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl<'a, T> Sink for PackageAnalysisSink<'a, T>
where
    T: Sink,
{
    async fn push_package(
        &self,
        package: Package,
        dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError> {
        let mut pkg = self.pending.entry(package.id()).or_default();

        pkg.package = Some(package);
        pkg.dependencies = Some(dependencies);

        Ok(())
    }

    async fn push_component(&self, pid: Uuid, component: Component) -> Result<(), PipelineError> {
        let Entry::Occupied(mut pkg) = self.pending.entry(pid) else {
            // should never happen!
            return Err(PipelineError::sink_with(
                "event ordering invariant violation: component metadata before package metadata",
            ));
        };

        let pkg_ref = pkg.get_mut();

        pkg_ref.components.insert(
            component.id(),
            ComponentAnalysisState {
                component,
                status: None,
            },
        );

        Ok(())
    }

    async fn push_component_property(
        &self,
        pid: Uuid,
        cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        let Entry::Occupied(mut pkg) = self.pending.entry(pid) else {
            // should never happen!
            return Err(PipelineError::sink_with(
                "event ordering invariant violation: component property before package metadata",
            ));
        };

        let pkg_ref = pkg.get_mut();

        pkg_ref
            .component_properties
            .entry(cid)
            .or_default()
            .push(property);

        Ok(())
    }

    async fn push_package_property(
        &self,
        pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        let Entry::Occupied(mut pkg) = self.pending.entry(pid) else {
            // should never happen!
            return Err(PipelineError::sink_with(
                "event ordering invariant violation: package property before package metadata",
            ));
        };

        let pkg_ref = pkg.get_mut();

        pkg_ref.package_properties.push(property);

        Ok(())
    }

    async fn push_package_status(&self, pid: Uuid, components: usize) -> Result<(), PipelineError> {
        let Entry::Occupied(mut pkg) = self.pending.entry(pid) else {
            // should never happen!
            return Err(PipelineError::sink_with(
                "event ordering invariant violation: package status before package metadata",
            ));
        };

        let pkg_ref = pkg.get_mut();

        pkg_ref.status = PackageAnalysisStatus::ExpectingComponents(components);

        self.try_emit(pkg).await?;

        Ok(())
    }

    async fn push_component_status(
        &self,
        pid: Uuid,
        cid: Uuid,
        err: Option<PipelineError>,
    ) -> Result<(), PipelineError> {
        let Entry::Occupied(mut pkg) = self.pending.entry(pid) else {
            // should never happen!
            return Err(PipelineError::sink_with(
                "event ordering invariant violation: component status before package metadata",
            ));
        };

        let pkg_ref = pkg.get_mut();

        let component_ref = pkg_ref.components.get_mut(&cid).ok_or_else(|| {
            PipelineError::sink_with(
                "event ordering invariant violation: component status before component metadata",
            )
        })?;

        component_ref.status = err;
        pkg_ref.component_events += 1;

        self.try_emit(pkg).await?;

        Ok(())
    }
}
