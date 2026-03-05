use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::ops::{Deref, DerefMut};

use ahash::AHashMap;
use downcast_rs::{impl_downcast, DowncastSync};
use dyn_clone::{clone_trait_object, DynClone};
use petgraph::algo::toposort;
use petgraph::graph::DiGraph;
pub use semver::{self as version, Version as AnalysisVersion, VersionReq as AnalysisVersionReq};
use thiserror::Error;

use crate::any::AnyLifetime;
use crate::kb::Uuid;
use crate::Project;

#[derive(Debug, Error)]
pub enum Error {
    #[error("analysis {0} failed with error: {1}")]
    Analysis(uuid::Uuid, Box<dyn std::error::Error + Send + Sync>),
    #[error("dependent analysis {1} for {0} is not scheduled")]
    Dependency(uuid::Uuid, uuid::Uuid),
    #[error("analyses form a dependency cycle on {0}")]
    DependencyCycle(uuid::Uuid),
    #[error("duplicate analysis {0}")]
    Duplicate(uuid::Uuid),
    #[error("missing analysis context")]
    MissingContext,
}

pub type AnalysisError = Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Schedule {
    Before(uuid::Uuid),
    After(uuid::Uuid),
    PreferAfter(uuid::Uuid),
    Dynamic,
}

pub type AnalysisSchedule = Schedule;

impl Schedule {
    pub const fn after<A: AnalysisInfo>() -> Self {
        Schedule::After(A::UUID)
    }

    pub const fn prefer_after<A: AnalysisInfo>() -> Self {
        Schedule::PreferAfter(A::UUID)
    }

    pub const fn before<A: AnalysisInfo>() -> Self {
        Schedule::Before(A::UUID)
    }

    pub const fn dynamic() -> Self {
        Schedule::Dynamic
    }

    pub fn uuid(&self) -> Option<&uuid::Uuid> {
        match self {
            Self::After(uuid) | Self::Before(uuid) | Self::PreferAfter(uuid) => Some(uuid),
            Self::Dynamic => None,
        }
    }

    pub fn schedule_after(&self) -> bool {
        matches!(self, Self::After(_))
    }

    pub fn prefer_schedule_after(&self) -> bool {
        matches!(self, Self::PreferAfter(_))
    }

    pub fn schedule_before(&self) -> bool {
        matches!(self, Self::Before(_))
    }
}

pub trait AnalysisInfo {
    const NAME: &'static str;
    const UUID: Uuid;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
    const PROVIDES: &'static [Uuid] = &[];
    const VERSION: AnalysisVersion = AnalysisVersion::new(0, 0, 0);
}

pub trait AnalysisUuid: Send + Sync + 'static {
    const UUID: Uuid;
}

pub struct AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    analysis: A,
    _marker: std::marker::PhantomData<ID>,
}

impl<A, ID> Clone for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    fn clone(&self) -> Self {
        Self {
            analysis: dyn_clone::clone(&self.analysis),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<A, ID> Deref for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    type Target = A;

    fn deref(&self) -> &Self::Target {
        &self.analysis
    }
}

impl<A, ID> DerefMut for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.analysis
    }
}

impl<A, ID> AsRef<A> for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    fn as_ref(&self) -> &A {
        &self.analysis
    }
}

impl<A, ID> AsMut<A> for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    fn as_mut(&mut self) -> &mut A {
        &mut self.analysis
    }
}

impl<A, ID> AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    pub fn new(analysis: A) -> Self {
        Self {
            analysis,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn into_inner(self) -> A {
        self.analysis
    }
}

impl<A, ID> AnalysisInfo for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    const NAME: &'static str = A::NAME;
    const UUID: Uuid = ID::UUID;
    const DEPENDENCIES: &'static [AnalysisSchedule] = A::DEPENDENCIES;
    const PROVIDES: &'static [Uuid] = A::PROVIDES;
    const VERSION: AnalysisVersion = A::VERSION;
}

impl<A, ID> Analysis for AnalysisWithId<A, ID>
where
    A: Analysis + AnalysisInfo,
    ID: AnalysisUuid,
{
    fn id(&self) -> &Uuid {
        &ID::UUID
    }

    fn dependencies(&self) -> &[Schedule] {
        A::DEPENDENCIES
    }

    fn provides(&self) -> &[Uuid] {
        A::PROVIDES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), Error> {
        self.analysis.analyse(project)
    }
}

pub trait Analysis: DowncastSync + DynClone {
    fn id(&self) -> &Uuid;
    fn dependencies(&self) -> &[Schedule] {
        &[]
    }
    fn provides(&self) -> &[Uuid] {
        &[]
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), Error>;
    fn analyse_with(
        &mut self,
        _context: &mut AnalysisContext,
        project: &mut Project,
    ) -> Result<(), Error> {
        self.analyse(project)
    }
}
impl_downcast!(Analysis);
clone_trait_object!(Analysis);

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AnalysisId(usize);

impl From<usize> for AnalysisId {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl AnalysisId {
    pub fn index(&self) -> usize {
        self.0
    }
}

#[derive(Default)]
pub struct AnalysisContext<'a> {
    mapping: AHashMap<uuid::Uuid, AnalysisId>,
    context: Vec<Option<Box<dyn AnyLifetime<'a>>>>,
}

pub trait AnalysisState<'a>: AnyLifetime<'a> {
    fn id(&self) -> &uuid::Uuid;
}

pub trait AnalysisStateInfo<'a>: AnalysisState<'a> {
    const UUID: Uuid;
    const VERSION: AnalysisVersion = AnalysisVersion::new(0, 0, 0);
}

impl<'a> AnalysisContext<'a> {
    pub fn get<S>(&self, id: uuid::Uuid) -> Option<&S>
    where
        S: AnalysisState<'a>,
    {
        self.mapping
            .get(&id)
            .and_then(|id| self.context.get(id.index()))
            .and_then(|st| st.as_ref())
            .and_then(|st| st.downcast_ref::<S>())
    }

    pub fn get_by<S>(&self) -> Option<&S>
    where
        S: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        self.get::<S>(S::UUID)
    }

    pub fn get_mut<S>(&mut self, id: uuid::Uuid) -> Option<&mut S>
    where
        S: AnalysisState<'a>,
    {
        self.mapping
            .get(&id)
            .and_then(|id| self.context.get_mut(id.index()))
            .and_then(|st| st.as_mut())
            .and_then(|st| st.downcast_mut::<S>())
    }

    pub fn get_by_mut<S>(&mut self) -> Option<&mut S>
    where
        S: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        self.get_mut::<S>(S::UUID)
    }

    pub fn set<S>(&mut self, id: uuid::Uuid, state: S)
    where
        S: AnalysisState<'a>,
    {
        let id = *self
            .mapping
            .entry(id)
            .or_insert(AnalysisId::from(self.context.len()));
        if id.index() == self.context.len() {
            self.context.push(Some(Box::new(state)));
        } else {
            self.context[id.index()] = Some(Box::new(state));
        }
    }

    pub fn set_by<S>(&mut self, state: S)
    where
        S: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        self.set::<S>(S::UUID, state)
    }

    pub fn clear(&mut self) {
        self.mapping.clear();
        self.context.clear();
    }

    pub fn len(&self) -> usize {
        self.mapping.len()
    }
}

pub struct AnalysisRef<'a, A>
where
    A: Analysis,
{
    analysis: &'a A,
    session: u64,
    order: u64,
    provided: bool,
}

impl<'a, A> AnalysisRef<'a, A>
where
    A: Analysis,
{
    pub fn analysis(&self) -> &'a A {
        self.analysis
    }

    pub fn session(&self) -> u64 {
        self.session
    }

    pub fn order(&self) -> u64 {
        self.order
    }

    pub fn provided(&self) -> bool {
        self.provided
    }
}

#[derive(Clone)]
pub struct AnalysisBox {
    analysis: Box<dyn Analysis>,
    name: Cow<'static, str>,
    session: u64,
    order: u64,
    provided: bool,
}

impl Deref for AnalysisBox {
    type Target = Box<dyn Analysis>;

    fn deref(&self) -> &Self::Target {
        &self.analysis
    }
}

impl DerefMut for AnalysisBox {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.analysis
    }
}

impl AnalysisBox {
    #[inline]
    pub fn new<A>(analysis: A, session: u64, order: u64) -> Self
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        Self {
            analysis: Box::new(analysis),
            name: Cow::Borrowed(A::NAME),
            session,
            order,
            provided: false,
        }
    }

    #[inline]
    pub fn provided<A>(analysis: A) -> Self
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        Self {
            analysis: Box::new(analysis),
            name: Cow::Borrowed(A::NAME),
            session: 0,
            order: 0,
            provided: true,
        }
    }

    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    #[inline]
    pub fn should_run(&self, session: u64) -> bool {
        !self.provided && self.session >= session
    }
}

#[derive(Clone)]
pub struct AnalysisManager {
    analyses: AHashMap<uuid::Uuid, AnalysisBox>,
    session: u64,
    order: u64,
}

impl Default for AnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisManager {
    pub fn new() -> Self {
        Self::from_parts(0, 0)
    }

    pub(crate) fn from_parts(session: u64, order: u64) -> Self {
        Self {
            analyses: AHashMap::new(),
            session,
            order,
        }
    }

    #[inline(always)]
    pub fn finalise_session(&mut self) {
        self.session += 1;
    }

    pub(crate) fn session(&self) -> u64 {
        self.session
    }

    pub(crate) fn order(&self) -> u64 {
        self.order
    }

    pub(crate) fn insert<A>(&mut self, analysis: A, order: u64, session: u64, provided: bool)
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        if session > self.session {
            for existing in self.analyses.values_mut() {
                if existing.session == self.session {
                    existing.session = session;
                }
            }
            self.session = session;
        }

        self.order = self.order.max(order);
        self.analyses.insert(
            *analysis.id(),
            AnalysisBox {
                analysis: Box::new(analysis),
                name: Cow::Borrowed(A::NAME),
                session,
                order,
                provided,
            },
        );
    }

    pub(crate) fn reconfigure_schedule(&mut self, order: u64, session: u64) {
        if session > self.session {
            for existing in self.analyses.values_mut() {
                if existing.session == self.session {
                    existing.session = session;
                }
            }

            self.session = session;
            self.order = self.order.max(order);
        }
    }

    pub fn register<A>(&mut self, analysis: A) -> Result<uuid::Uuid, Error>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        let uuid = *analysis.id();

        tracing::debug!("registering analysis {}/{}", A::NAME, A::UUID);

        if self.analyses.contains_key(&uuid) {
            // ignore duplicates
            return Ok(uuid);
        }

        self.analyses
            .insert(uuid, AnalysisBox::new(analysis, self.session, self.order));
        self.order += 1;

        Ok(uuid)
    }

    pub fn register_with<A>(&mut self, analysis: A, force: bool) -> Result<Uuid, Error>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        let uuid = *analysis.id();
        if !force && self.analyses.contains_key(&uuid) {
            return Err(Error::Duplicate(uuid));
        }

        self.analyses
            .insert(uuid, AnalysisBox::new(analysis, self.session, self.order));
        self.order += 1;

        Ok(uuid)
    }

    #[inline]
    pub fn provide<A>(&mut self, analysis: A)
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        let uuid = *analysis.id();
        self.analyses.insert(uuid, AnalysisBox::provided(analysis));
    }

    #[inline]
    pub fn get<A>(&self, id: Uuid) -> Option<&A>
    where
        A: Analysis + 'static,
    {
        self.analyses.get(&id).and_then(|a| a.downcast_ref::<A>())
    }

    #[inline]
    pub fn get_mut<A>(&mut self, id: Uuid) -> Option<&mut A>
    where
        A: Analysis + 'static,
    {
        self.analyses
            .get_mut(&id)
            .and_then(|a| a.downcast_mut::<A>())
    }

    #[inline]
    pub fn get_by<A>(&self) -> Option<&A>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        self.analyses
            .get(&A::UUID)
            .and_then(|a| a.downcast_ref::<A>())
    }

    #[inline]
    pub fn get_by_mut<A>(&mut self) -> Option<&mut A>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        self.analyses
            .get_mut(&A::UUID)
            .and_then(|a| a.downcast_mut::<A>())
    }

    #[inline]
    pub fn get_ref<'a, A>(&'a self) -> Option<AnalysisRef<'a, A>>
    where
        A: Analysis + AnalysisInfo + 'static,
    {
        self.analyses.get(&A::UUID).and_then(|a| {
            Some(AnalysisRef {
                analysis: a.downcast_ref::<A>()?,
                session: a.session,
                order: a.order,
                provided: a.provided,
            })
        })
    }

    pub fn analyse(project: &mut Project) -> Result<(), Error> {
        let mut context = Default::default();
        Self::analyse_with(&mut context, project)
    }

    pub fn analyse_with(context: &mut AnalysisContext, project: &mut Project) -> Result<(), Error> {
        let mut schedule = DiGraph::<_, ()>::new();

        let analyses = &project.manager.analyses;
        let mut uuids = AHashMap::with_capacity(analyses.len());

        for (&id, a) in analyses.iter() {
            if uuids.insert(id, schedule.add_node(id)).is_some() {
                return Err(Error::Duplicate(id));
            }

            for &id in a.provides() {
                if uuids.insert(id, schedule.add_node(id)).is_some() {
                    return Err(Error::Duplicate(id));
                }
            }
        }

        for (&id, analysis) in analyses.iter() {
            let nx = uuids[analysis.id()];

            for provides in analysis.provides() {
                if let Some(dx) = uuids.get(provides) {
                    schedule.add_edge(nx, *dx, ());
                }
            }

            for dep in analysis.dependencies() {
                if dep.schedule_after() {
                    if let Some(dx) = uuids.get(dep.uuid().unwrap()) {
                        schedule.add_edge(*dx, nx, ());
                    } else {
                        return Err(Error::Dependency(id, *dep.uuid().unwrap()));
                    }
                } else if dep.schedule_before() {
                    if let Some(dx) = uuids.get(dep.uuid().unwrap()) {
                        schedule.add_edge(nx, *dx, ());
                    }
                } else if dep.prefer_schedule_after() {
                    if let Some(dx) = uuids.get(dep.uuid().unwrap()) {
                        schedule.add_edge(*dx, nx, ());
                    }
                } else {
                    for (id, &dx) in uuids.iter() {
                        if analysis.provided {
                            continue;
                        }
                        if id != analysis.id()
                            && analyses
                                .get(id)
                                .map(|a| {
                                    !a.provided
                                        && (!a
                                            .dependencies()
                                            .iter()
                                            .any(|v| matches!(v, Schedule::Dynamic))
                                            || a.order < analysis.order)
                                })
                                .unwrap_or(false)
                        {
                            schedule.add_edge(dx, nx, ());
                        }
                    }
                }
            }
        }

        match toposort(&schedule, None) {
            Ok(sched) => {
                for id in sched.into_iter().map(|nx| schedule[nx]) {
                    let mut analysis = match project.manager.analyses.entry(id) {
                        Entry::Vacant(_) => continue, // provides
                        Entry::Occupied(e) => {
                            if !e.get().should_run(project.manager.session) {
                                tracing::debug!(
                                    "session {:02} not running analysis: {}/{}",
                                    project.manager.session,
                                    e.get().name(),
                                    e.get().id()
                                );
                                continue;
                            }

                            e.remove()
                        }
                    };
                    tracing::debug!(
                        "session {:02} running analysis: {}/{}",
                        project.manager.session,
                        analysis.name(),
                        analysis.id()
                    );
                    let result = analysis.analyse_with(context, project);
                    project.manager.analyses.insert(id, analysis);
                    result?;
                }
                project.manager.finalise_session();
                Ok(())
            }
            Err(cycle) => {
                let nx = cycle.node_id();
                let uuid = schedule[nx];
                Err(Error::DependencyCycle(uuid))
            }
        }
    }
}
