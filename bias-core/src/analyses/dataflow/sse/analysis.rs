use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;
use std::rc::Rc;

use crate::cfg::ssa::{DefaultSSACallSummariser, SSACallSummariser, SSAReachingDefinitionSet};
use crate::cfg::{SSAGraph, StableDiGraph};
use crate::ir::{SimpleVar, VisitVars};
use crate::kb::block::EmptyOrChunkedCodeBlock;
use crate::prelude::graph::Direction;
use crate::prelude::graph::visit::IntoNodeReferences;
use crate::prelude::*;

use fxhash::FxBuildHasher;
use hashbrown::HashMap;
use hashbrown::hash_map::Entry;
use smallvec::SmallVec;
use thiserror::Error;

use super::validation::{
    validate_handler_consistency, validate_handler_monotonicity, validate_widening,
    validate_widening_sanity,
};
use super::{
    SSAVarMap, SSETrace, SSETraceContext, SSEValidity, SSEValiditySource, SSEValidityState,
    SSExprArena, SSExprRef,
};

pub const DEFAULT_COMPLEXITY_LIMIT: Option<usize> = Some(8);
pub const DEFAULT_CALL_STRING_SIZE: usize = 3;
pub const DEFAULT_CALL_DEPTH_LIMIT: Option<usize> = Some(DEFAULT_CALL_STRING_SIZE);
pub const DEFAULT_FUNCTION_ANALYSIS_LIMIT: Option<usize> = None;

pub type NodeMap<T> = HashMap<NodeIndex, T, FxBuildHasher>;
pub type FunctionMap<T> = HashMap<FunctionId, T, FxBuildHasher>;

#[derive(Debug, Error)]
pub enum SSEAnalysisError {
    #[error("failed to analyse function {0} due to incomplete control flow recovery")]
    IncompleteControlFlowRecovery(FunctionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum BoundaryValidationPolicy {
    Off,
    #[default]
    Warn,
    Panic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SSEAnalysisConfig {
    pub complexity_limit: Option<usize>,
    pub call_depth_limit: Option<usize>,
    pub function_analysis_limit: Option<usize>,
    pub boundary_validation: BoundaryValidationPolicy,
}

impl Default for SSEAnalysisConfig {
    fn default() -> Self {
        Self {
            complexity_limit: DEFAULT_COMPLEXITY_LIMIT,
            call_depth_limit: DEFAULT_CALL_DEPTH_LIMIT,
            function_analysis_limit: DEFAULT_FUNCTION_ANALYSIS_LIMIT,
            boundary_validation: BoundaryValidationPolicy::default(),
        }
    }
}

impl SSEAnalysisConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn complexity_limit(&self) -> Option<usize> {
        self.complexity_limit
    }

    pub fn with_complexity_limit(self, limit: usize) -> Self {
        Self {
            complexity_limit: Some(limit),
            ..self
        }
    }

    pub fn call_depth_limit(&self) -> Option<usize> {
        self.call_depth_limit
    }

    pub fn with_call_depth_limit(self, limit: usize) -> Self {
        Self {
            call_depth_limit: Some(limit),
            ..self
        }
    }

    pub fn function_analysis_limit(&self) -> Option<usize> {
        self.function_analysis_limit
    }

    pub fn with_function_analysis_limit(self, limit: usize) -> Self {
        Self {
            function_analysis_limit: Some(limit),
            ..self
        }
    }

    pub fn boundary_validation(&self) -> BoundaryValidationPolicy {
        self.boundary_validation
    }

    pub fn with_boundary_validation(self, policy: BoundaryValidationPolicy) -> Self {
        Self {
            boundary_validation: policy,
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SSECallString {
    sites: SmallVec<[Address; DEFAULT_CALL_STRING_SIZE]>,
}

impl Display for SSECallString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(first) = self.sites.first() else {
            return write!(f, "<empty>");
        };

        write!(f, "{}", first)?;

        for site in self.sites.iter().skip(1) {
            write!(f, " -> {}", site)?;
        }

        Ok(())
    }
}

impl FromIterator<Address> for SSECallString {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        Self {
            sites: SmallVec::from_iter(iter),
        }
    }
}

impl SSECallString {
    pub fn empty() -> Self {
        Self {
            sites: SmallVec::new(),
        }
    }

    pub fn push(&mut self, address: Address) {
        self.sites.push(address);
    }

    pub fn parent(&self) -> Option<Self> {
        let mut sites = self.sites.clone();
        sites.pop()?;
        Some(Self { sites })
    }

    pub fn child(&self, address: Address) -> Self {
        let mut sites = self.sites.clone();
        sites.push(address);
        Self { sites }
    }

    pub fn len(&self) -> usize {
        self.sites.len()
    }
}

pub type SSECallStringMap<T> = HashMap<SSECallString, T, FxBuildHasher>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SSEAnalysisAction {
    Call(SSECallString),
    CallHandler(SSECallString),
    CallFixedPoint(SSECallString),
    CallForwardPass(SSECallString),
    CallBackwardPass(SSECallString),
    CallMerge(SSECallString, SSECallString, NodeIndex),
    CallMergeBackward(SSECallString, NodeIndex),

    BlockFixedPoint(SSECallString, NodeIndex),
    BlockForwardPass(SSECallString, NodeIndex),
    BlockBackwardPass(SSECallString, NodeIndex),
    BlockMergeForward(SSECallString, NodeIndex),
    BlockMergeBackward(SSECallString, NodeIndex),
}

type SSEAnalysisActionWorklist = Vec<SSEAnalysisAction>;

pub type SSEFunctionGraphRef = Rc<SSEFunctionGraph>;
pub type SSAFunctionGraph = StableDiGraph<EmptyOrChunkedCodeBlock, FlowKind>;

pub struct SSEFunctionGraph {
    function: FunctionId,
    graph: SSAGraph<EmptyOrChunkedCodeBlock>,
    order: Vec<NodeIndex>,
    incoming_rdefs_mapping: NodeMap<SSAVarMap>,
    outgoing_pre_call_rdefs_mapping: NodeMap<SSAVarMap>,
    outgoing_rdefs_mapping: NodeMap<SSAVarMap>,
}

impl Deref for SSEFunctionGraph {
    type Target = StableDiGraph<EmptyOrChunkedCodeBlock, FlowKind>;

    fn deref(&self) -> &Self::Target {
        self.graph.graph()
    }
}

impl SSEFunctionGraph {
    pub fn new<'a, T>(
        project: &'a Project,
        f: &'a Function,
        summariser: &T,
    ) -> Result<SSEFunctionGraphRef, SSEAnalysisError>
    where
        T: SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + ?Sized,
    {
        let graph = f.ssa_iicfg_with(project, summariser);

        let mut order = Vec::with_capacity(graph.graph().node_count());
        let mut visit = graph.post_ordered();

        let mut incoming_rdefs_mapping = NodeMap::default();
        let mut outgoing_pre_call_rdefs_mapping = NodeMap::default();
        let mut outgoing_rdefs_mapping = NodeMap::default();

        while let Some(nx) = visit.next(graph.graph()) {
            let incoming_rdefs = graph
                .incoming_reaching_definitions_at(nx)
                .map(Self::build_reaching_definitions_mapping)
                .ok_or_else(|| SSEAnalysisError::IncompleteControlFlowRecovery(f.id()))?;

            incoming_rdefs_mapping.insert(nx, incoming_rdefs);

            let outgoing_pre_call_rdefs = graph
                .outgoing_pre_call_reaching_definitions_at(nx)
                .map(Self::build_reaching_definitions_mapping)
                .ok_or_else(|| SSEAnalysisError::IncompleteControlFlowRecovery(f.id()))?;

            outgoing_pre_call_rdefs_mapping.insert(nx, outgoing_pre_call_rdefs);

            if graph.clobbers_at(nx).is_some() {
                let rdefs = graph
                    .outgoing_reaching_definitions_at(nx)
                    .map(Self::build_reaching_definitions_mapping)
                    .ok_or_else(|| SSEAnalysisError::IncompleteControlFlowRecovery(f.id()))?;
                outgoing_rdefs_mapping.insert(nx, rdefs);
            }

            order.push(nx);
        }

        Ok(SSEFunctionGraphRef::new(Self {
            function: f.id(),
            graph,
            order,
            incoming_rdefs_mapping,
            outgoing_pre_call_rdefs_mapping,
            outgoing_rdefs_mapping,
        }))
    }

    fn build_reaching_definitions_mapping(rdefs: &SSAReachingDefinitionSet) -> SSAVarMap {
        let mut mapping = SSAVarMap::with_capacity(rdefs.len());

        for var in rdefs.iter() {
            mapping.insert(SimpleVar(*var), var.generation());
        }

        mapping
    }

    pub fn function(&self) -> FunctionId {
        self.function
    }

    pub fn entry(&self) -> NodeIndex {
        self.graph.entry()
    }

    pub fn exit(&self) -> Option<NodeIndex> {
        self.graph.exit()
    }

    pub fn graph(&self) -> &SSAFunctionGraph {
        self.graph.graph()
    }

    pub fn order(&self) -> &[NodeIndex] {
        &self.order
    }

    pub fn incoming_reaching_definitions_at(
        &self,
        nx: NodeIndex,
    ) -> Option<&SSAReachingDefinitionSet> {
        self.graph.incoming_reaching_definitions_at(nx)
    }

    pub fn incoming_reaching_definitions_mapping_at(&self, nx: NodeIndex) -> Option<&SSAVarMap> {
        self.incoming_rdefs_mapping.get(&nx)
    }

    pub fn outgoing_pre_call_reaching_definitions_at(
        &self,
        node: NodeIndex,
    ) -> Option<&SSAReachingDefinitionSet> {
        self.graph.outgoing_pre_call_reaching_definitions_at(node)
    }

    pub fn outgoing_pre_call_reaching_definitions_mapping_at(
        &self,
        nx: NodeIndex,
    ) -> Option<&SSAVarMap> {
        self.outgoing_pre_call_rdefs_mapping.get(&nx)
    }

    pub fn outgoing_reaching_definitions_at(
        &self,
        nx: NodeIndex,
    ) -> Option<&SSAReachingDefinitionSet> {
        self.graph.outgoing_reaching_definitions_at(nx)
    }

    pub fn outgoing_reaching_definitions_mapping_at(&self, nx: NodeIndex) -> Option<&SSAVarMap> {
        self.outgoing_rdefs_mapping
            .get(&nx)
            .or_else(|| self.outgoing_pre_call_reaching_definitions_mapping_at(nx))
    }

    pub fn analysis_context_from<'a>(
        self: &SSEFunctionGraphRef,
        tctx: &mut SSETraceContext<'a>,
        project: &'a Project,
        incoming: &SSETrace<'a>,
        outgoing: Option<&SSETrace<'a>>,
    ) -> SSEFunctionContext<'a> {
        let function_addr = incoming.project().functions()[self.function()].address();
        let mut sses = incoming.sses().clone();

        if let Some(outgoing) = outgoing {
            let exit = self.exit().expect("function has exit state");
            let exit_rdefs = self
                .outgoing_reaching_definitions_mapping_at(exit)
                .expect("valid exit block");
            let outgoing_sses = tctx.remap_boundary_sses(outgoing.sses(), exit_rdefs);
            for (var, remapped_sses) in outgoing_sses {
                let entry = sses.entry(var).or_default();
                for (sse, validity) in remapped_sses {
                    let target = entry.entry(sse).or_default();
                    target.extend_from(&validity);
                }
            }
        }

        tracing::trace!(
            "creating analysis context for function {};\nincoming: {incoming}\noutgoing: {}",
            function_addr,
            outgoing
                .as_ref()
                .map_or(&"-" as &dyn Display, |o| o as &dyn Display)
        );

        let blocks = self
            .order
            .iter()
            .copied()
            .map(|nx| {
                (
                    nx,
                    SSETrace::new_from_reaching_definitions(tctx, self, nx, project, &sses),
                )
            })
            .collect();

        SSEFunctionContext {
            graph: self.clone(),
            blocks,
            boundary_incoming: None,
            boundary_outgoing: None,
            calls: NodeMap::default(),
            changed: false,
        }
    }
}

struct SSEFunctionVisitor {
    target: SimpleVar,
    kind: SSEAnalysisTargetKind,
    found: Option<(Location, Var)>,
}

impl<'ir> VisitVars<'ir> for SSEFunctionVisitor {
    fn visit_def_at(&mut self, loc: Location, var: &'ir Var) {
        if self.found.is_none()
            && self.kind == SSEAnalysisTargetKind::Def
            && SimpleVar(*var) == self.target
        {
            self.found = Some((loc, *var));
        }
    }

    fn visit_use_at(&mut self, loc: Location, var: &'ir Var) {
        if self.found.is_none()
            && self.kind == SSEAnalysisTargetKind::Use
            && SimpleVar(*var) == self.target
        {
            self.found = Some((loc, *var));
        }
    }
}

struct SSEAnalysisTarget {
    graph: SSEFunctionGraphRef,
    location: Location,
    origin: NodeIndex,
    kind: SSEAnalysisTargetKind,
    validity: SSEValidity,
    variable: Var,
}

impl SSEAnalysisTarget {
    pub fn new<'a, T>(
        project: &'a Project,
        f: &'a Function,
        loc: Address,
        target: Var,
        kind: SSEAnalysisTargetKind,
        summariser: &T,
    ) -> Result<Self, SSEAnalysisError>
    where
        T: SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + ?Sized,
    {
        let graph = SSEFunctionGraph::new(project, f, summariser)?;
        Ok(Self::new_with(f, graph, loc, target, kind))
    }

    pub fn new_with(
        f: &Function,
        graph: SSEFunctionGraphRef,
        loc: Address,
        target: Var,
        kind: SSEAnalysisTargetKind,
    ) -> Self {
        let (location, origin, variable) = graph
            .graph()
            .node_references()
            .filter_map(|(nx, blk)| Some(nx).zip(blk.as_chunked()))
            .find_map(|(nx, chunk)| Some(nx).zip(chunk.find_chunk(loc)))
            .and_then(|(nx, chunk)| {
                if kind.is_output() {
                    let clobbers = graph.graph.clobbers_at(nx)?;
                    return clobbers.iter().find_map(|var| {
                        (SimpleVar(target) == SimpleVar(*var))
                            .then(|| (chunk.last_location(), nx, *var))
                    });
                }

                let mut visitor = SSEFunctionVisitor {
                    target: SimpleVar(target),
                    kind,
                    found: None,
                };

                chunk.visit_vars(&mut visitor);
                let (loc, var) = visitor.found?;
                Some((loc, nx, var))
            })
            .unwrap_or_else(|| (f.address().into(), graph.entry(), target.with_generation(0)));

        let validity = if kind.is_use() {
            SSEValidity::backward_unbounded()
        } else {
            // NOTE: if we set Both here, we will allow backward propagation of the
            // the SSEs, which in some cases, is exactly what we want (but not always)...
            // SSEValidity::forward(SSEValidityState::ForwardOnly, location)
            SSEValidity::forward(SSEValidityState::Both, location)
        };

        Self {
            graph,
            location,
            kind,
            origin,
            validity,
            variable,
        }
    }

    pub fn analysis_context<'a>(
        &self,
        project: &'a Project,
        arena: &'a SSExprArena,
    ) -> SSEFunctionContext<'a> {
        let blocks = self
            .graph
            .order()
            .iter()
            .copied()
            .map(|nx| {
                (
                    nx,
                    if nx == self.origin && !self.kind.is_output() && !self.kind.is_auto() {
                        SSETrace::new_with_validity(
                            project,
                            arena,
                            self.variable,
                            self.validity.clone(),
                            Some(SSEValiditySource::new(
                                self.location,
                                arena.var(self.variable),
                            )),
                        )
                    } else {
                        SSETrace::new_tracking(project, self.variable)
                    },
                )
            })
            .collect();

        SSEFunctionContext {
            graph: self.graph.clone(),
            blocks,
            boundary_incoming: None,
            boundary_outgoing: None,
            calls: NodeMap::default(),
            changed: false,
        }
    }
}

pub struct SSEFunctionContext<'a> {
    graph: SSEFunctionGraphRef,
    blocks: NodeMap<SSETrace<'a>>,
    boundary_incoming: Option<SSETrace<'a>>,
    boundary_outgoing: Option<SSETrace<'a>>,
    calls: NodeMap<SSECallSite<'a>>,
    changed: bool,
}

impl<'a> SSEFunctionContext<'a> {
    pub fn function(&self) -> FunctionId {
        self.graph.function()
    }

    pub fn graph(&self) -> &SSEFunctionGraphRef {
        &self.graph
    }

    pub fn blocks(&self) -> &NodeMap<SSETrace<'a>> {
        &self.blocks
    }

    pub fn calls(&self) -> &NodeMap<SSECallSite<'a>> {
        &self.calls
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    pub fn set_changed(&mut self, changed: bool) {
        self.changed = changed;
    }

    pub fn update_changed(&mut self, changed: bool) {
        self.changed |= changed;
    }

    pub fn update_context_from(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        incoming: &SSETrace<'a>,
        outgoing: &SSETrace<'a>,
    ) {
        let exit_nx = self.graph.exit().expect("function has exit state");
        let exit_rdefs = self
            .graph
            .outgoing_reaching_definitions_mapping_at(exit_nx)
            .expect("valid exit block");

        // Prepare outgoing SSEs remapped to exit block's reaching definitions.
        // These should only be placed at the exit block for backward propagation.
        let outgoing_sses = tctx.remap_boundary_sses(outgoing.sses(), exit_rdefs);

        let incoming_sses = incoming.sses();
        let entry_nx = self.graph.entry();
        self.boundary_incoming = (entry_nx == exit_nx).then(|| incoming.clone());
        self.boundary_outgoing = (entry_nx == exit_nx).then(|| outgoing.clone());
        let mut combined_sses = incoming_sses.clone();
        for (var, sses) in outgoing_sses.iter() {
            let entry = combined_sses.entry(*var).or_default();
            for (sse, validity) in sses.iter() {
                let target = entry.entry(*sse).or_default();
                target.extend_from(validity);
            }
        }

        for (nx, ntrace) in self.blocks.iter_mut() {
            let loc = self.graph.graph()[*nx].location().unwrap_or_default();

            tracing::trace!("updating block {loc} with incoming trace:\n{ntrace}");
            let block_incoming = self
                .graph
                .incoming_reaching_definitions_at(*nx)
                .expect("valid block");
            let block_outgoing = self
                .graph
                .outgoing_reaching_definitions_at(*nx)
                .expect("valid block");

            // Refresh each block from the current boundary snapshot instead of
            // monotonically accumulating stale aliases/validities from prior rounds.
            // Single-block functions need both incoming and outgoing seeds.
            if *nx == exit_nx && *nx == entry_nx {
                ntrace.rebuild_with_reaching_definitions(
                    tctx,
                    block_incoming,
                    block_outgoing,
                    &combined_sses,
                );
            } else if *nx == exit_nx {
                ntrace.rebuild_with_reaching_definitions(
                    tctx,
                    block_incoming,
                    block_outgoing,
                    &outgoing_sses,
                );
            } else {
                ntrace.rebuild_with_reaching_definitions(
                    tctx,
                    block_incoming,
                    block_outgoing,
                    incoming_sses,
                );
            }

            tracing::trace!("new state for block {loc}:\n{ntrace}");
        }

        self.changed = true;
    }
}

pub struct SSEAnalysisAlert<'a> {
    message: String,
    context: Vec<SSEAnalysisAlertContext<'a>>,
}

pub struct SSEAnalysisAlertContext<'a> {
    context: String,
    variable: SimpleVar,
    expression: SSExprRef<'a>,
}

impl<'a> SSEAnalysisAlert<'a> {
    pub fn new(message: String) -> Self {
        Self {
            message,
            context: Vec::new(),
        }
    }

    pub fn add_context(&mut self, context: String, variable: SimpleVar, expression: SSExprRef<'a>) {
        self.context.push(SSEAnalysisAlertContext {
            context,
            variable,
            expression,
        });
    }

    pub fn with_context(
        mut self,
        context: String,
        variable: SimpleVar,
        expression: SSExprRef<'a>,
    ) -> Self {
        self.add_context(context, variable, expression);
        self
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn context(&self) -> &[SSEAnalysisAlertContext<'a>] {
        &self.context
    }
}

impl<'a> SSEAnalysisAlertContext<'a> {
    pub fn new(context: String, variable: SimpleVar, expression: SSExprRef<'a>) -> Self {
        Self {
            context,
            variable,
            expression,
        }
    }

    pub fn context(&self) -> &str {
        &self.context
    }

    pub fn variable(&self) -> SimpleVar {
        self.variable
    }

    pub fn expression(&self) -> SSExprRef<'a> {
        self.expression
    }
}

#[derive(Default)]
pub struct SSEFunctionOutcome<'a> {
    incoming: Option<SSETrace<'a>>,
    outgoing: Option<SSETrace<'a>>,
    alert: Option<SSEAnalysisAlert<'a>>,
}

impl<'a> From<(SSETrace<'a>, SSETrace<'a>)> for SSEFunctionOutcome<'a> {
    fn from(traces: (SSETrace<'a>, SSETrace<'a>)) -> Self {
        Self::new(traces.0, traces.1)
    }
}

impl<'a> SSEFunctionOutcome<'a> {
    pub fn new(incoming: SSETrace<'a>, outgoing: SSETrace<'a>) -> Self {
        Self::new_with(incoming, outgoing, None)
    }

    pub fn new_with(
        incoming: SSETrace<'a>,
        outgoing: SSETrace<'a>,
        alert: impl Into<Option<SSEAnalysisAlert<'a>>>,
    ) -> Self {
        Self {
            incoming: Some(incoming),
            outgoing: Some(outgoing),
            alert: alert.into(),
        }
    }

    pub fn set_incoming(&mut self, incoming: SSETrace<'a>) {
        self.incoming = Some(incoming);
    }

    pub fn with_incoming(mut self, incoming: SSETrace<'a>) -> Self {
        self.set_incoming(incoming);
        self
    }

    pub fn clear_incoming(&mut self) {
        self.incoming = None;
    }

    pub fn set_outgoing(&mut self, outgoing: SSETrace<'a>) {
        self.outgoing = Some(outgoing);
    }

    pub fn with_outgoing(mut self, outgoing: SSETrace<'a>) -> Self {
        self.set_outgoing(outgoing);
        self
    }

    pub fn clear_outgoing(&mut self) {
        self.outgoing = None;
    }

    pub fn incoming(&self) -> Option<&SSETrace<'a>> {
        self.incoming.as_ref()
    }

    pub fn outgoing(&self) -> Option<&SSETrace<'a>> {
        self.outgoing.as_ref()
    }

    pub fn alert(&self) -> Option<&SSEAnalysisAlert<'a>> {
        self.alert.as_ref()
    }

    pub fn set_alert(&mut self, alert: SSEAnalysisAlert<'a>) {
        self.alert = Some(alert);
    }

    pub fn clear_alert(&mut self) {
        self.alert = None;
    }

    pub fn with_alert(mut self, alert: SSEAnalysisAlert<'a>) -> Self {
        self.set_alert(alert);
        self
    }

    pub fn into_parts(
        self,
    ) -> (
        Option<SSETrace<'a>>,
        Option<SSETrace<'a>>,
        Option<SSEAnalysisAlert<'a>>,
    ) {
        (self.incoming, self.outgoing, self.alert)
    }
}

/// Handler covergence:
/// - returned traces must stay in canonical prototype space (no temporaries,
///   no non-zero SSA generations)
/// - every materialised SSE must carry at least one validity
/// - handlers should preserve existing validities when carrying aliases across
///   unchanged keys, rather than recreating key-only traces
/// - handlers should be idempotent for identical `(incoming, outgoing)` inputs
///   so the call-site fixed point can converge
pub trait SSEFunctionHandler<'a> {
    fn update_state(
        &mut self,
        loc: Location,
        cs: SSECallString,
        incoming: &SSETrace<'a>,
        outgoing: &SSETrace<'a>,
        trace_context: &mut SSETraceContext<'a>,
    ) -> SSEFunctionOutcome<'a>;
}

impl<'a, F> SSEFunctionHandler<'a> for F
where
    F: FnMut(
            Location,
            SSECallString,
            &SSETrace<'a>,
            &SSETrace<'a>,
            &mut SSETraceContext<'a>,
        ) -> SSEFunctionOutcome<'a>
        + 'a,
{
    fn update_state(
        &mut self,
        loc: Location,
        cs: SSECallString,
        incoming: &SSETrace<'a>,
        outgoing: &SSETrace<'a>,
        trace_context: &mut SSETraceContext<'a>,
    ) -> SSEFunctionOutcome<'a> {
        (*self)(loc, cs, incoming, outgoing, trace_context)
    }
}

pub struct SSEBlockState<'a, 'ctx> {
    pub call_string: &'ctx SSECallString,
    pub function: FunctionId,
    pub block: NodeIndex,
    pub location: Option<Location>,
    pub previous_trace: Option<&'ctx SSETrace<'a>>,
    pub trace: &'ctx mut SSETrace<'a>,
    pub trace_context: &'ctx mut SSETraceContext<'a>,
}

impl<'a, 'ctx> SSEBlockState<'a, 'ctx> {
    pub fn new(
        call_string: &'ctx SSECallString,
        function: FunctionId,
        block: NodeIndex,
        location: Option<Location>,
        trace: &'ctx mut SSETrace<'a>,
        trace_context: &'ctx mut SSETraceContext<'a>,
    ) -> Self {
        Self {
            call_string,
            function,
            block,
            location,
            previous_trace: None,
            trace,
            trace_context,
        }
    }
}

pub trait SSEWideningOperator<'a> {
    fn widen(&mut self, state: SSEBlockState<'a, '_>);
    fn clear(&mut self);
}

struct SSEWideningState<'a> {
    policy: BoundaryValidationPolicy,
    operator: Box<dyn SSEWideningOperator<'a> + 'a>,
    states: SSECallStringMap<NodeMap<SSETrace<'a>>>,
}

impl<'a> SSEWideningState<'a> {
    fn new(policy: BoundaryValidationPolicy, operator: impl SSEWideningOperator<'a> + 'a) -> Self {
        Self {
            policy,
            operator: Box::new(operator),
            states: SSECallStringMap::default(),
        }
    }

    fn widen(&mut self, state: SSEBlockState<'a, '_>) -> bool {
        let previous_trace = self
            .states
            .get(state.call_string)
            .and_then(|block_states| block_states.get(&state.block));

        self.operator.widen(SSEBlockState {
            call_string: state.call_string,
            function: state.function,
            block: state.block,
            location: state.location,
            previous_trace,
            trace: state.trace,
            trace_context: state.trace_context,
        });

        validate_widening_sanity(self.policy, state.location, state.call_string, &state.trace);

        let block_states = self.states.entry(state.call_string.clone()).or_default();

        match block_states.entry(state.block) {
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                if !existing.has_equivalent_sses(&state.trace)
                    || !existing.has_equivalent_validity(&state.trace)
                {
                    validate_widening(
                        self.policy,
                        state.location,
                        state.call_string,
                        existing,
                        state.trace,
                    );
                    *existing = state.trace.clone();
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(state.trace.clone());
                true
            }
        }
    }

    pub fn clear(&mut self) {
        self.operator.clear();
        self.states.clear();
    }
}

pub struct SSEAnalysis<'a> {
    config: SSEAnalysisConfig,
    project: &'a Project,
    contexts: SSECallStringMap<SSEFunctionContext<'a>>,
    function_analysis_limit: SSECallStringMap<usize>,
    functions: FunctionMap<SSEFunctionGraphRef>,
    interprocedural_clobbers: Box<dyn SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + 'a>,
    handlers: FunctionMap<Box<dyn SSEFunctionHandler<'a> + 'a>>,
    widening: Option<SSEWideningState<'a>>,
    alerts: SSECallStringMap<SSEAnalysisAlert<'a>>,
    kind: Option<SSEAnalysisTargetKind>,
    location: Option<Location>,
    origin: Option<NodeIndex>,
    validity: Option<SSEValidity>,
    variable: Option<Var>,
    trace_context: SSETraceContext<'a>,
    worklist: SSEAnalysisActionWorklist,
}

impl<'a> SSEAnalysis<'a> {
    pub fn new(arena: &'a SSExprArena, project: &'a Project) -> Self {
        Self::new_with(arena, project, SSEAnalysisConfig::default())
    }

    pub fn new_with(
        arena: &'a SSExprArena,
        project: &'a Project,
        config: SSEAnalysisConfig,
    ) -> Self {
        Self {
            config,
            project,
            contexts: SSECallStringMap::default(),
            function_analysis_limit: SSECallStringMap::default(),
            functions: FunctionMap::default(),
            interprocedural_clobbers: Box::new(DefaultSSACallSummariser::new()),
            handlers: FunctionMap::default(),
            widening: None,
            alerts: SSECallStringMap::default(),
            kind: None,
            origin: None,
            location: None,
            validity: None,
            variable: None,
            trace_context: SSETraceContext::new_with(arena, project, config.complexity_limit),
            worklist: SSEAnalysisActionWorklist::new(),
        }
    }

    pub fn config(&self) -> &SSEAnalysisConfig {
        &self.config
    }

    pub fn project(&self) -> &'a Project {
        self.project
    }

    pub fn contexts(&self) -> &SSECallStringMap<SSEFunctionContext<'a>> {
        &self.contexts
    }

    pub fn function_analysis_limit(&self) -> &SSECallStringMap<usize> {
        &self.function_analysis_limit
    }

    pub fn primary_context(&self) -> Option<&SSEFunctionContext<'a>> {
        self.contexts.get(&SSECallString::empty())
    }

    pub fn functions(&self) -> &FunctionMap<SSEFunctionGraphRef> {
        &self.functions
    }

    pub fn alerts(&self) -> &SSECallStringMap<SSEAnalysisAlert<'a>> {
        &self.alerts
    }

    pub fn has_alerts(&self) -> bool {
        !self.alerts.is_empty()
    }

    pub fn location(&self) -> Option<Location> {
        self.location
    }

    pub fn variable(&self) -> Option<Var> {
        self.variable
    }

    pub fn set_handler<T>(&mut self, fid: FunctionId, handler: T)
    where
        T: SSEFunctionHandler<'a> + 'a,
    {
        self.handlers.insert(fid, Box::new(handler));
    }

    pub fn set_handler_fn<F>(&mut self, fid: FunctionId, handler: F)
    where
        F: FnMut(
                Location,
                SSECallString,
                &SSETrace<'a>,
                &SSETrace<'a>,
                &mut SSETraceContext<'a>,
            ) -> SSEFunctionOutcome<'a>
            + 'a,
    {
        self.set_handler(fid, handler);
    }

    pub fn with_handler<T>(mut self, fid: FunctionId, handler: T) -> Self
    where
        T: SSEFunctionHandler<'a> + 'a,
    {
        self.set_handler(fid, handler);
        self
    }

    pub fn set_widening_operator<T>(&mut self, operator: T)
    where
        T: SSEWideningOperator<'a> + 'a,
    {
        self.widening = Some(SSEWideningState::new(
            self.config.boundary_validation(),
            operator,
        ));
    }

    pub fn with_widening_operator<T>(mut self, operator: T) -> Self
    where
        T: SSEWideningOperator<'a> + 'a,
    {
        self.set_widening_operator(operator);
        self
    }

    pub fn set_summariser<T>(&mut self, summariser: T)
    where
        T: SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + 'a,
    {
        self.interprocedural_clobbers = Box::new(summariser);
    }

    pub fn with_summariser<T>(mut self, summariser: T) -> Self
    where
        T: SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + 'a,
    {
        self.set_summariser(summariser);
        self
    }

    fn has_exceeded_function_analysis_limit(&mut self, cs: &SSECallString) -> bool {
        let Some(limit) = self.config.function_analysis_limit() else {
            return false;
        };

        let count = self
            .function_analysis_limit
            .entry(cs.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);

        if *count <= limit {
            return false;
        }

        let state = self.contexts.get(cs).expect("valid state");
        let function_addr = self.project.functions()[state.function()].address();

        tracing::warn!(
            "function analysis limit reached for {}, skipping further analysis",
            function_addr
        );

        true
    }

    fn apply_call_action(&mut self, cs: SSECallString) {
        if self.has_exceeded_function_analysis_limit(&cs) {
            return;
        }

        self.contexts
            .get_mut(&cs)
            .expect("valid state")
            .mark_changed();
        self.worklist.push(SSEAnalysisAction::CallFixedPoint(cs));
    }

    fn apply_call_handler_action(&mut self, cs: SSECallString) {
        if self.has_exceeded_function_analysis_limit(&cs) {
            return;
        }

        let state = self.contexts.get_mut(&cs).expect("valid state");

        tracing::trace!(
            "applying call handler action for call string: {cs} (changed: {})",
            state.changed()
        );

        let entry = state.graph.entry();
        let exit = state.graph.exit().expect("function has exit state");
        let same_block = entry == exit;

        let handler = self
            .handlers
            .get_mut(&state.function())
            .expect("valid handler");

        let mut incoming = if same_block {
            state
                .boundary_incoming
                .clone()
                .unwrap_or_else(|| state.blocks[&entry].clone())
        } else {
            state.blocks[&entry].clone()
        };
        let mut outgoing = if same_block {
            state
                .boundary_outgoing
                .clone()
                .unwrap_or_else(|| state.blocks[&exit].clone())
        } else {
            state.blocks[&exit].clone()
        };

        // NOTE: handlers work in canonical prototype space. Normalise any block-local generations
        // before passing traces across the handler boundary to avoid reintroducing fresh
        // generation-0 SSEs each round.
        incoming.reset_ssa_generations(&mut self.trace_context);
        outgoing.reset_ssa_generations(&mut self.trace_context);

        let loc = state.graph.graph()[entry]
            .location()
            .expect("entry block has location");

        let (n_incoming, n_outgoing, alert) = handler
            .update_state(
                loc,
                cs.clone(),
                &incoming,
                &outgoing,
                &mut self.trace_context,
            )
            .into_parts();

        // ensure the temporary context is cleaned up correctly
        self.trace_context.clear();

        let policy = self.config.boundary_validation;
        let mut changed = false;

        if same_block {
            if let Some(mut n_incoming) = n_incoming {
                n_incoming.reset_ssa_generations(&mut self.trace_context);

                validate_handler_consistency(policy, "incoming", loc, &cs, &incoming, &n_incoming);

                if !incoming.has_equivalent_validity(&n_incoming) {
                    tracing::trace!("incoming changed");

                    changed = true;

                    validate_handler_monotonicity(
                        policy,
                        "incoming",
                        loc,
                        &cs,
                        &incoming,
                        &n_incoming,
                    );
                }
                state.boundary_incoming = Some(n_incoming);
            }

            if let Some(mut n_outgoing) = n_outgoing {
                n_outgoing.reset_ssa_generations(&mut self.trace_context);

                validate_handler_consistency(policy, "outgoing", loc, &cs, &outgoing, &n_outgoing);

                if !outgoing.has_equivalent_validity(&n_outgoing) {
                    tracing::trace!("outgoing changed");
                    tracing::debug!("old outgoing:\n{outgoing}");
                    tracing::debug!("new outgoing:\n{n_outgoing}");

                    changed = true;

                    validate_handler_monotonicity(
                        policy,
                        "outgoing",
                        loc,
                        &cs,
                        &outgoing,
                        &n_outgoing,
                    );
                }
                state.boundary_outgoing = Some(n_outgoing.clone());
                *state.blocks.get_mut(&exit).expect("valid exit block") = n_outgoing;
            }
        } else {
            if let Some(mut n_incoming) = n_incoming {
                n_incoming.reset_ssa_generations(&mut self.trace_context);

                validate_handler_consistency(policy, "incoming", loc, &cs, &incoming, &n_incoming);

                let incoming = state.blocks.get_mut(&entry).expect("valid entry block");
                if !incoming.has_equivalent_validity(&n_incoming) {
                    tracing::trace!("incoming changed");

                    changed = true;

                    validate_handler_monotonicity(
                        policy,
                        "incoming",
                        loc,
                        &cs,
                        incoming,
                        &n_incoming,
                    );
                }
                *incoming = n_incoming;
            }

            if let Some(mut n_outgoing) = n_outgoing {
                n_outgoing.reset_ssa_generations(&mut self.trace_context);

                validate_handler_consistency(policy, "outgoing", loc, &cs, &outgoing, &n_outgoing);

                let outgoing = state.blocks.get_mut(&exit).expect("valid exit block");
                if !outgoing.has_equivalent_validity(&n_outgoing) {
                    tracing::trace!("outgoing changed");
                    tracing::debug!("old outgoing:\n{outgoing}");
                    tracing::debug!("new outgoing:\n{n_outgoing}");

                    changed = true;

                    validate_handler_monotonicity(
                        policy,
                        "outgoing",
                        loc,
                        &cs,
                        outgoing,
                        &n_outgoing,
                    );
                }
                *outgoing = n_outgoing;
            }
        }

        if let Some(alert) = alert {
            self.alerts.insert(cs, alert);
        } else {
            self.alerts.remove(&cs);
        }

        state.update_changed(changed);
    }

    fn apply_call_fixed_point_action(&mut self, cs: SSECallString) {
        let state = self.contexts.get_mut(&cs).expect("valid state");
        let changed = state.changed();

        tracing::trace!("applying fixed point action for call string: {cs} (changed: {changed})");

        if changed {
            state.clear_changed();

            self.worklist
                .push(SSEAnalysisAction::CallFixedPoint(cs.clone()));
            self.worklist
                .push(SSEAnalysisAction::CallBackwardPass(cs.clone()));
            self.worklist.push(SSEAnalysisAction::CallForwardPass(cs));
        }
    }

    fn apply_call_forward_pass_action(&mut self, cs: SSECallString) {
        let state = self.contexts.get_mut(&cs).expect("valid state");

        for blk in state.graph.order().iter().copied() {
            self.worklist
                .push(SSEAnalysisAction::BlockForwardPass(cs.clone(), blk));
        }
    }

    fn apply_call_backward_pass_action(&mut self, cs: SSECallString) {
        let state = self.contexts.get_mut(&cs).expect("valid state");

        for blk in state.graph.order().iter().rev().copied() {
            self.worklist
                .push(SSEAnalysisAction::BlockBackwardPass(cs.clone(), blk));
        }
    }

    fn apply_call_merge_action(&mut self, ncs: SSECallString, cs: SSECallString, blk: NodeIndex) {
        {
            let state = self.contexts.get_mut(&cs).expect("valid state");
            let call_state = state.calls.get_mut(&blk).expect("valid call site");

            if call_state.is_summary() {
                tracing::trace!(
                    "call site {} is a summary, skipping merge",
                    state.graph.graph()[blk].last_location().unwrap_or_default()
                );
                state.update_changed(false);
                return;
            }

            if call_state.is_non_returning() {
                tracing::trace!(
                    "call site {} is non-returning, skipping merge",
                    state.graph.graph()[blk].last_location().unwrap_or_default()
                );
                state.update_changed(false);
                return;
            }

            if ncs == cs {
                tracing::trace!(
                    "call site {} is the same as the current call string, skipping merge",
                    state.graph.graph()[blk].last_location().unwrap_or_default()
                );
                return;
            }
        }

        let [Some(ncs_state), Some(cs_state)] = self.contexts.get_many_mut([&ncs, &cs]) else {
            panic!("valid states for call-site merge");
        };

        let block = &cs_state.graph.graph()[blk];
        let block_rdefs = cs_state
            .graph
            .outgoing_reaching_definitions_at(blk)
            .expect("valid block");
        let block_rdefs_mapping = cs_state
            .graph
            .outgoing_reaching_definitions_mapping_at(blk)
            .expect("valid block");

        let call_source = block.last_location().expect("not empty");
        let call_state = cs_state.calls.get_mut(&blk).expect("valid call site");
        let block_clobbers = cs_state.graph.graph.clobbers_at(blk);

        let exit_nx = ncs_state.graph.exit().expect("function returns");
        let callee_exit_rdefs = ncs_state
            .graph
            .outgoing_reaching_definitions_at(exit_nx)
            .expect("valid exit block");
        let callee_exit_rdefs_mapping = ncs_state
            .graph
            .outgoing_reaching_definitions_mapping_at(exit_nx)
            .expect("valid exit block");
        let mut exit_state = ncs_state
            .blocks
            .get(&exit_nx)
            .expect("valid exit block")
            .to_owned();

        exit_state.purge_locally_bounded_variables(&mut self.trace_context);
        exit_state.map_generations(&mut self.trace_context, &call_source, block_rdefs_mapping);

        // NOTE: we inject the output variable into the exit state
        if block.location().is_some()
            && block.last_location().expect("valid location")
                == self.location.expect("valid location")
            && self.kind.expect("valid analysis kind").is_output()
            && self.origin.expect("valid origin") == blk
        {
            let var = self.variable.expect("valid variable");
            let sse = self.trace_context.arena().var(var);
            let has_output_sses = exit_state
                .sses()
                .get(&SimpleVar(var))
                .is_some_and(|sses| !sses.is_empty());

            // FIXME: we need a stronger check here
            if !has_output_sses && (block_rdefs.contains(&var) || var.generation() == 0) {
                tracing::trace!(
                    "adding output variable {} to return state at {}",
                    var.display(self.project),
                    block.last_location().unwrap_or_default()
                );

                let location = self.location.expect("valid location");
                let validity = self.validity.as_ref().expect("valid validity");

                exit_state.add_alias_with_source(
                    SimpleVar(var),
                    sse,
                    validity.clone(),
                    SSEValiditySource::new(location, sse),
                );
            } else {
                tracing::warn!(
                    "output variable {} not found in callee exit reaching definitions at {}",
                    var.display(self.project),
                    block.last_location().unwrap_or_default()
                );
            }
        }

        let return_state = exit_state.return_site_trace(
            &mut self.trace_context,
            block_rdefs,
            block_rdefs_mapping,
            block_clobbers,
            callee_exit_rdefs,
            callee_exit_rdefs_mapping,
            call_source,
        );

        tracing::trace!("exit state:\n{exit_state}");
        tracing::trace!("return state:\n{return_state}");

        let changed = call_state.update_outgoing_analysis_state(return_state);
        if !changed {
            tracing::trace!("call site already has the same outgoing state, skipping merge");
        }

        cs_state.update_changed(changed);
    }

    fn apply_block_forward_pass_action(
        &mut self,
        cs: SSECallString,
        blk: NodeIndex,
    ) -> Result<(), SSEAnalysisError> {
        self.worklist
            .push(SSEAnalysisAction::BlockMergeForward(cs.clone(), blk));

        self.handle_call_target(cs.clone(), blk, true)?;

        self.worklist
            .push(SSEAnalysisAction::BlockFixedPoint(cs, blk));

        Ok(())
    }

    fn apply_block_backward_pass_action(
        &mut self,
        cs: SSECallString,
        blk: NodeIndex,
    ) -> Result<(), SSEAnalysisError> {
        self.worklist
            .push(SSEAnalysisAction::BlockFixedPoint(cs.clone(), blk));

        self.handle_call_target(cs.clone(), blk, false)?;

        self.worklist
            .push(SSEAnalysisAction::BlockMergeBackward(cs, blk));

        Ok(())
    }

    fn handle_call_target(
        &mut self,
        cs: SSECallString,
        blk: NodeIndex,
        forward: bool,
    ) -> Result<(), SSEAnalysisError> {
        use SSEAnalysisAction::*;

        let state = self.contexts.get_mut(&cs).expect("valid state");

        let Some(fid) = state.graph.graph()[blk].call_target() else {
            return Ok(()); // no call target, nothing to do
        };

        if cs.len() >= self.config.call_depth_limit().unwrap_or(usize::MAX) {
            return Ok(()); // call depth limit reached, skip further analysis
        }

        let ncs = cs.child(
            state.graph.graph()[blk]
                .last_location()
                .expect("valid block")
                .address(),
        );

        self.worklist.push(CallMerge(ncs.clone(), cs.clone(), blk));

        if !forward {
            self.worklist.push(CallMergeBackward(cs.clone(), blk));
        }

        let f = &self.project.functions()[fid];
        let f_addr = f.address();
        let has_handler = self.handlers.contains_key(&fid);

        let block = &state.graph.graph()[blk];
        let block_rdefs = state
            .graph
            // .outgoing_reaching_definitions_at(blk)
            .outgoing_pre_call_reaching_definitions_at(blk)
            .expect("valid block");
        let block_rdefs_mapping = state
            .graph
            .outgoing_pre_call_reaching_definitions_mapping_at(blk)
            .expect("valid block");
        let block_state = &state.blocks[&blk];

        let call_source = block.last_location().expect("not empty");
        let call_state = block_state.call_site_trace(
            &mut self.trace_context,
            block_rdefs,
            block_rdefs_mapping,
            call_source,
        );

        let mut fblk = state
            .graph
            .graph()
            .edges_directed(blk, Direction::Outgoing)
            .find_map(|e| e.weight().is_fall().then_some(e.target()));

        if fblk.is_none() {
            tracing::trace!(
                "call site {} has no fall-through block",
                block.last_location().unwrap_or_default()
            );
            // if there is no fall-through block, we set the fall to the exit block
            // if the call returns
            if !f.is_non_returning() {
                fblk = state.graph.exit();
            }
        }

        let return_state = fblk
            .and_then(|fblk| {
                // let fblock = &state.graph.graph()[fblk];

                // NOTE: we could use the post-call reaching definitions here,
                // which might be a little safer. It may be the case that we
                // hit some phi-nodes at the start of the incoming block, and
                // therefore end up with a mismatch.
                /*
                let fblock_rdefs = state
                    .graph
                    .incoming_reaching_definitions_at(blk)
                    .expect("valid block");
                */
                let block_rdefs = state
                    .graph
                    .outgoing_reaching_definitions_at(blk)
                    .expect("valid block");
                let block_rdefs_mapping = state
                    .graph
                    .outgoing_reaching_definitions_mapping_at(blk)
                    .expect("valid block");
                let block_clobbers = state.graph.graph.clobbers_at(blk);

                let fblock_state = &state.blocks[&fblk];

                tracing::trace!(
                    "building return state for call site {} from:\n{fblock_state}",
                    block.last_location().unwrap_or_default()
                );

                let callee = match self.functions.entry(fid) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        match SSEFunctionGraph::new(
                            &self.project,
                            f,
                            &*self.interprocedural_clobbers,
                        ) {
                            Ok(g) => entry.insert(g),
                            Err(e) => {
                                return Some(Err(e));
                            }
                        }
                    }
                };

                if callee.exit().is_none() {
                    tracing::debug!("callee {f_addr} has no exit block");
                }

                let callee_exit = callee.exit()?;
                let callee_exit_rdefs = callee
                    .outgoing_reaching_definitions_at(callee_exit)
                    .expect("valid exit block");
                let callee_exit_rdefs_mapping = callee
                    .outgoing_reaching_definitions_mapping_at(callee_exit)
                    .expect("valid exit block");

                let state = fblock_state.return_site_trace(
                    &mut self.trace_context,
                    block_rdefs,
                    block_rdefs_mapping,
                    block_clobbers,
                    callee_exit_rdefs,
                    callee_exit_rdefs_mapping,
                    call_source, // NOTE: this needs to be the call site location, otherwise
                                 // we run into complications at phi nodes.
                                 // fblock.location().unwrap_or_default(),
                );

                tracing::trace!(
                    "return state for call site {}: {}",
                    block.last_location().unwrap_or_default(),
                    state
                );

                Some(Ok(state))
            })
            .transpose()?;

        tracing::trace!(
            "analysing function call at {}: {}",
            block.last_location().unwrap_or_default(),
            f_addr
        );

        if f.is_extern() {
            state
                .calls
                .insert(blk, SSECallSite::new_summary(ncs, call_state));
            return Ok(()); // skip external calls
        }

        match state.calls.entry(blk) {
            Entry::Occupied(mut entry) => {
                let current = entry.get_mut();

                if current.is_non_returning() || fblk.is_none() {
                    tracing::trace!("function {} is non-returning, skipping analysis", f_addr);
                    return Ok(()); // skip non-returning calls
                }

                let return_state = return_state.expect("valid return state (returning call)");

                tracing::trace!("return_state keys:");
                for (var, sses) in return_state.sses().iter() {
                    for (sse, _) in sses.iter() {
                        tracing::trace!(
                            "  {} -> {}",
                            var.display(self.project),
                            sse.display(self.project)
                        );
                    }
                }

                if let Some(prev_outgoing) = current.outgoing() {
                    tracing::trace!("current.outgoing() keys:");
                    for (var, sses) in prev_outgoing.sses().iter() {
                        for (sse, _) in sses.iter() {
                            tracing::trace!(
                                "  {} -> {}",
                                var.display(self.project),
                                sse.display(self.project)
                            );
                        }
                    }

                    tracing::trace!("Keys in return_state but NOT in prev:");
                    for (var, sses) in return_state.sses().iter() {
                        for (sse, _) in sses.iter() {
                            if !prev_outgoing
                                .sses()
                                .get(var)
                                .map_or(false, |s| s.contains_key(sse))
                            {
                                tracing::trace!(
                                    "  NEW: {} -> {}",
                                    var.display(self.project),
                                    sse.display(self.project)
                                );
                            }
                        }
                    }

                    tracing::trace!("Keys in prev but NOT in return_state:");
                    for (var, sses) in prev_outgoing.sses().iter() {
                        for (sse, _) in sses.iter() {
                            if !return_state
                                .sses()
                                .get(var)
                                .map_or(false, |s| s.contains_key(sse))
                            {
                                tracing::trace!(
                                    "  LOST: {} -> {}",
                                    var.display(self.project),
                                    sse.display(self.project)
                                );
                            }
                        }
                    }
                }

                let in_sub = call_state.is_subset_of(current.incoming());
                let out_sub = current
                    .outgoing()
                    .map_or(true, |o| return_state.is_subset_of(o));
                tracing::warn!(
                    "{}: in_sub={}, out_sub={}",
                    state.graph.graph()[blk].last_location().unwrap_or_default(),
                    in_sub,
                    out_sub
                );

                if in_sub && !current.outgoing().is_none() && out_sub {
                    let incoming_validity_subset =
                        call_state.validity_is_subset_of(current.incoming().sses());
                    let outgoing_validity_subset = current
                        .outgoing()
                        .map_or(true, |o| return_state.validity_is_subset_of(o.sses()));

                    if incoming_validity_subset && outgoing_validity_subset {
                        tracing::trace!(
                            "call site {} SSE keys and validities stable, skipping",
                            state.graph.graph()[blk].last_location().unwrap_or_default()
                        );
                        return Ok(());
                    }

                    tracing::trace!(
                        "call site {} SSE keys stable but validities differ, updating state only",
                        state.graph.graph()[blk].last_location().unwrap_or_default()
                    );
                    let incoming_changed = current.update_incoming_analysis_state(call_state);
                    let outgoing_changed = current.update_outgoing_analysis_state(return_state);
                    state.update_changed(incoming_changed || outgoing_changed);
                    return Ok(());
                }

                let incoming_changed = current.update_incoming_analysis_state(call_state);
                let outgoing_changed = current.update_outgoing_analysis_state(return_state);

                tracing::trace!("new outgoing state:\n{}", current.outgoing().unwrap());

                // we need to refetch the current and new contexts to satisfy the borrow checker...
                let [Some(state), Some(n_state)] = self.contexts.get_many_mut([&cs, &ncs]) else {
                    unreachable!("valid states for call site merge");
                };

                let call_state = state.calls[&blk].incoming();
                let return_state = state.calls[&blk].outgoing().expect("valid outgoing state");

                // update the trace context with the new state
                n_state.update_context_from(&mut self.trace_context, call_state, return_state);

                // schedule analysis of the call site as incoming changed
                let should_analyse_callee =
                    !call_state.sses().is_empty() || !return_state.sses().is_empty() || has_handler;

                if incoming_changed || outgoing_changed {
                    if should_analyse_callee {
                        self.worklist.push(if has_handler {
                            CallHandler(ncs)
                        } else {
                            Call(ncs)
                        });
                    }
                }
            }
            Entry::Vacant(entry) => {
                let callee = match self.functions.entry(fid) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let g = SSEFunctionGraph::new(
                            &self.project,
                            f,
                            &*self.interprocedural_clobbers,
                        )?;
                        entry.insert(g)
                    }
                };

                let n_state = callee.analysis_context_from(
                    &mut self.trace_context,
                    self.project,
                    &call_state,
                    return_state.as_ref(), // NOTE: needs to be remapped to the callee's context
                );

                if n_state.graph.exit().is_none() || fblk.is_none() {
                    tracing::trace!(
                        "call site {} is non-returning, skipping analysis",
                        state.graph.graph()[blk].last_location().unwrap_or_default()
                    );
                    entry.insert(SSECallSite::new_non_returning(ncs, call_state));
                    return Ok(());
                }

                let should_analyse_callee = !call_state.sses().is_empty()
                    || return_state
                        .as_ref()
                        .is_some_and(|outgoing| !outgoing.sses().is_empty())
                    || has_handler;

                entry.insert(SSECallSite::new_analysis(
                    ncs.clone(),
                    call_state,
                    return_state,
                ));

                self.contexts.insert(ncs.clone(), n_state);

                if should_analyse_callee {
                    self.worklist.push(if has_handler {
                        CallHandler(ncs)
                    } else {
                        Call(ncs)
                    });
                }
            }
        }

        Ok(())
    }

    fn apply_block_merge_forward_action(&mut self, cs: SSECallString, curr: NodeIndex) {
        let state = self.contexts.get_mut(&cs).expect("valid state");
        let reaching_defs = state
            .graph
            .outgoing_reaching_definitions_at(curr)
            .expect("valid block");
        let reaching_defs_mapping = state
            .graph
            .outgoing_reaching_definitions_mapping_at(curr)
            .expect("valid block");

        let mut changed = false;

        for succ in state
            .graph
            .graph()
            .edges_directed(curr, Direction::Outgoing)
        {
            let succ = succ.target();
            if curr == succ {
                // TODO: handle self-loops?
                continue;
            }

            let (curr_state, succ_state) = if let Some(curr_state) = state.calls.get(&curr) {
                let succ_state = state
                    .blocks
                    .get_mut(&succ)
                    .expect("valid successor block for forward merge");
                (
                    curr_state
                        .outgoing()
                        .map(Cow::Borrowed)
                        .unwrap_or_else(|| Cow::Owned(SSETrace::empty(&self.project))),
                    succ_state,
                )
            } else if state.graph.graph()[curr].call_target().is_some() {
                // the current block is a call site, but it has not been analysed yet
                let succ_state = state
                    .blocks
                    .get_mut(&succ)
                    .expect("valid successor block for forward merge");
                (Cow::Owned(SSETrace::empty(&self.project)), succ_state)
            } else {
                let [Some(curr_state), Some(succ_state)] =
                    state.blocks.get_many_mut([&curr, &succ])
                else {
                    panic!("valid blocks for forward merge");
                };
                (Cow::Borrowed(curr_state), succ_state)
            };

            tracing::trace!(
                "merging forward from block {} to {}",
                state.graph.graph()[curr].location().unwrap_or_default(),
                state.graph.graph()[succ].location().unwrap_or_default()
            );

            tracing::trace!("merge state:\n{curr_state}");

            tracing::trace!("before merge:\n{succ_state}");

            changed |= succ_state.merge_forward(
                &mut self.trace_context,
                reaching_defs,
                reaching_defs_mapping,
                curr_state.sses(),
            );

            tracing::trace!("after merge:\n{succ_state}");
        }

        state.update_changed(changed);
    }

    fn apply_call_merge_backward_action(&mut self, cs: SSECallString, curr: NodeIndex) {
        // this takes the incoming call state and merges it backward into the
        // current block, which is its caller.

        let state = self.contexts.get_mut(&cs).expect("valid state");

        let loc = state.graph.graph()[curr]
            .last_location()
            .unwrap_or_default();

        let Some(call_state) = state.calls.get(&curr) else {
            tracing::warn!("call site {loc} has no call state, skipping backward merge");
            return;
        };

        let reaching_defs = state
            .graph
            .outgoing_pre_call_reaching_definitions_at(curr)
            .expect("valid block");
        let reaching_defs_mapping = state
            .graph
            .outgoing_pre_call_reaching_definitions_mapping_at(curr)
            .expect("valid block");

        let current = state.blocks.get_mut(&curr).expect("valid block");
        let mut incoming = call_state.incoming().clone();

        incoming.purge_locally_bounded_variables(&mut self.trace_context);
        incoming.map_generations(&mut self.trace_context, &loc, reaching_defs_mapping);

        tracing::trace!(
            "merging backward from call site at {loc} ({})",
            call_state.call_string(),
        );

        tracing::trace!("merge state:\n{incoming}");

        tracing::trace!("before merge:\n{current}");

        let changed = current.merge_backward(
            &mut self.trace_context,
            reaching_defs,
            reaching_defs_mapping,
            incoming.sses(),
        );

        tracing::trace!("after merge:\n{current}");

        state.update_changed(changed);
    }

    fn apply_block_merge_backward_action(&mut self, cs: SSECallString, curr: NodeIndex) {
        let state = self.contexts.get_mut(&cs).expect("valid state");
        let reaching_defs = state
            .graph
            .incoming_reaching_definitions_at(curr)
            .expect("valid block");
        let reaching_defs_mapping = state
            .graph
            .incoming_reaching_definitions_mapping_at(curr)
            .expect("valid block");

        let mut changed = false;

        for pred in state
            .graph
            .graph()
            .edges_directed(curr, Direction::Incoming)
        {
            let pred = pred.source();
            if curr == pred {
                // TODO: handle self-loops?
                continue;
            }

            let [Some(curr_state), Some(pred_state)] = state.blocks.get_many_mut([&curr, &pred])
            else {
                panic!("valid blocks for backward merge");
            };

            tracing::trace!(
                "merging backward from block {} to {}",
                state.graph.graph()[curr].location().unwrap_or_default(),
                state.graph.graph()[pred].location().unwrap_or_default()
            );

            tracing::trace!("merge state:\n{curr_state}");

            tracing::trace!("before merge:\n{pred_state}");

            changed |= pred_state.merge_backward(
                &mut self.trace_context,
                reaching_defs,
                reaching_defs_mapping,
                curr_state.sses(),
            );

            tracing::trace!("after merge:\n{pred_state}");
        }

        state.update_changed(changed);
    }

    fn apply_block_fixed_point_action(&mut self, cs: SSECallString, blk: NodeIndex) {
        let Self {
            contexts,
            widening,
            trace_context,
            ..
        } = self;

        let state = contexts.get_mut(&cs).expect("valid state");
        let chunked = &state.graph.graph()[blk];

        if let Some(loc) = chunked.location() {
            tracing::trace!("applying fixed point action for block: {loc}");
        }

        let function = state.function();
        let location = chunked.location();
        let block = state.blocks.get_mut(&blk).expect("valid block");
        let mut changed = block.fixpoint_pass(trace_context, chunked);

        block.purge_locally_bounded_variables(trace_context);

        if let Some(clobbers) = state.graph.graph.clobbers_at(blk) {
            let loc = chunked.last_location().unwrap_or_default();

            tracing::trace!(
                "killing clobbered variables at block {}: {clobbers:?}",
                chunked.last_location().unwrap_or_default()
            );

            block.kill_and_bound_clobbered_variables(trace_context, &loc, clobbers);
        }

        if changed {
            if let Some(widening) = widening {
                changed = widening.widen(SSEBlockState::new(
                    &cs,
                    function,
                    blk,
                    location,
                    block,
                    trace_context,
                ));
            }
        }

        state.update_changed(changed);
    }

    pub fn analyse(
        &mut self,
        f: &'a Function,
        loc: Address,
        target: Var,
        kind: SSEAnalysisTargetKind,
    ) -> Result<(), SSEAnalysisError> {
        use SSEAnalysisAction::*;

        self.contexts.clear();
        self.function_analysis_limit.clear();
        self.trace_context.clear();
        self.worklist.clear();
        if let Some(widening) = &mut self.widening {
            widening.clear();
        }

        let target = match self.functions.entry(f.id()) {
            Entry::Occupied(entry) => {
                SSEAnalysisTarget::new_with(f, entry.get().clone(), loc, target, kind)
            }
            Entry::Vacant(entry) => {
                let target = SSEAnalysisTarget::new(
                    self.project,
                    f,
                    loc,
                    target,
                    kind,
                    self.interprocedural_clobbers.as_ref(),
                )?;
                entry.insert(target.graph.clone());
                target
            }
        };

        let state = target.analysis_context(self.project, self.trace_context.arena());

        // NOTE: we should refactor this to avoid all the unwraps and expects

        self.kind = Some(target.kind);
        self.origin = Some(target.origin);
        self.location = Some(target.location);
        self.validity = Some(target.validity);
        self.variable = Some(target.variable);

        self.contexts.insert(SSECallString::empty(), state);

        self.worklist.push(Call(SSECallString::empty()));

        while let Some(action) = self.worklist.pop() {
            tracing::trace!("action: {:?}", action);
            match action {
                Call(cs) => {
                    self.apply_call_action(cs);
                }
                CallHandler(cs) => {
                    self.apply_call_handler_action(cs);
                }
                CallFixedPoint(cs) => {
                    self.apply_call_fixed_point_action(cs);
                }
                CallForwardPass(cs) => {
                    self.apply_call_forward_pass_action(cs);
                }
                CallBackwardPass(cs) => {
                    self.apply_call_backward_pass_action(cs);
                }
                CallMerge(ncs, cs, blk) => {
                    self.apply_call_merge_action(ncs, cs, blk);
                }
                CallMergeBackward(cs, blk) => {
                    self.apply_call_merge_backward_action(cs, blk);
                }
                BlockForwardPass(cs, blk) => {
                    self.apply_block_forward_pass_action(cs, blk)?;
                }
                BlockBackwardPass(cs, blk) => {
                    self.apply_block_backward_pass_action(cs, blk)?;
                }
                BlockMergeForward(cs, curr) => {
                    self.apply_block_merge_forward_action(cs, curr);
                }
                BlockMergeBackward(cs, curr) => {
                    self.apply_block_merge_backward_action(cs, curr);
                }
                BlockFixedPoint(cs, blk) => {
                    self.apply_block_fixed_point_action(cs, blk);
                }
            }
        }

        Ok(())
    }
}

/*
pub struct SSEFunctionAnalysis<'a> {
    config: SSEAnalysisConfig,
    graph: SSAGraph<EmptyOrChunkedCodeBlock>,
    order: Vec<NodeIndex>,
    blocks: NodeMap<SSETrace<'a>>,
    calls: NodeMap<SSECallSite<'a>>,
    location: Option<Location>,
    variable: Option<Var>,
    changed: bool,
}

impl<'a> SSEFunctionAnalysis<'a> {
    pub fn new(
        arena: &'a SSExprArena,
        project: &'a Project,
        f: &'a Function,
        loc: Address,
        target: Var,
        kind: SSEAnalysisTargetKind,
    ) -> Self {
        Self::new_with(
            arena,
            project,
            f,
            loc,
            target,
            kind,
            SSEAnalysisConfig::default(),
        )
    }

    pub fn new_with(
        arena: &'a SSExprArena,
        project: &'a Project,
        f: &'a Function,
        loc: Address,
        target: Var,
        kind: SSEAnalysisTargetKind,
        config: SSEAnalysisConfig,
    ) -> Self {
        let mut order = Vec::new();
        let mut blocks = NodeMap::default();

        struct Visitor {
            target: SimpleVar,
            kind: SSEAnalysisTargetKind,
            found: Option<(Location, Var)>,
        }

        impl<'ir> VisitVars<'ir> for Visitor {
            fn visit_def_at(&mut self, loc: Location, var: &'ir Var) {
                if self.found.is_none()
                    && self.kind == SSEAnalysisTargetKind::Def
                    && SimpleVar(*var) == self.target
                {
                    self.found = Some((loc, *var));
                }
            }

            fn visit_use_at(&mut self, loc: Location, var: &'ir Var) {
                if self.found.is_none()
                    && self.kind == SSEAnalysisTargetKind::Use
                    && SimpleVar(*var) == self.target
                {
                    self.found = Some((loc, *var));
                }
            }
        }

        let graph = f.ssa_iicfg(&project);

        let (location, origin, variable) = graph
            .graph()
            .node_references()
            .filter_map(|(nx, blk)| Some(nx).zip(blk.as_chunked()))
            .find_map(|(nx, chunk)| Some(nx).zip(chunk.find_chunk(loc)))
            .and_then(|(nx, chunk)| {
                let mut visitor = Visitor {
                    target: SimpleVar(target),
                    kind,
                    found: None,
                };

                chunk.visit_vars(&mut visitor);
                let (loc, var) = visitor.found?;
                Some((loc, nx, var))
            })
            .unwrap_or_else(|| (f.address().into(), graph.entry(), target.with_generation(0)));

        let validity = SSEValidity::forward(SSEValidityState::Both, location);

        let mut visit = graph.post_ordered();

        while let Some(nx) = visit.next(graph.graph()) {
            order.push(nx);
            blocks.insert(
                nx,
                if nx == origin {
                    SSETrace::new_with_validity(project, arena, variable, validity.clone())
                } else {
                    SSETrace::new_tracking(project, variable)
                },
            );
        }

        Self {
            config,
            graph,
            order,
            blocks,
            calls: NodeMap::default(),
            variable: Some(variable),
            location: Some(location),
            changed: false,
        }
    }

    pub fn new_callee(project: &'a Project, f: &'a Function, state: &SSETrace<'a>) -> Self {
        Self::new_callee_with(project, f, state, SSEAnalysisConfig::default())
    }

    pub fn new_callee_with(
        project: &'a Project,
        f: &'a Function,
        state: &SSETrace<'a>,
        config: SSEAnalysisConfig,
    ) -> Self {
        let mut order = Vec::new();
        let mut blocks = NodeMap::default();

        let graph = f.ssa_iicfg(project);

        let mut visit = graph.post_ordered();

        while let Some(nx) = visit.next(graph.graph()) {
            order.push(nx);
            blocks.insert(
                nx,
                SSETrace::new_with(project, state.tracked_set().clone(), state.sses().clone()),
            );
        }

        Self {
            config,
            graph,
            order,
            blocks,
            calls: NodeMap::default(),
            location: None,
            variable: None,
            changed: false,
        }
    }

    pub fn location(&self) -> Option<Location> {
        self.location
    }

    pub fn variable(&self) -> Option<Var> {
        self.variable
    }

    pub fn graph(&self) -> &SSAGraph<EmptyOrChunkedCodeBlock> {
        &self.graph
    }

    pub fn blocks(&self) -> &NodeMap<SSETrace> {
        &self.blocks
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    pub fn update_changed(&mut self, changed: bool) {
        self.changed |= changed;
    }

    pub fn analyse(&mut self, arena: &'a SSExprArena, project: &'a Project) {
        let mut changed = true;
        let mut tctx = SSETraceContext::new_with(arena, project, self.config.complexity_limit);

        while changed {
            changed = false;

            changed |= self.forward_pass(&mut tctx);
            changed |= self.backward_pass(&mut tctx);
        }
    }

    fn analyse_call(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        nx: NodeIndex,
        fid: FunctionId,
    ) -> (bool, SSETrace<'a>) {
        let block = &self.graph.graph()[nx];
        let rdefs = self
            .graph
            .outgoing_reaching_definitions_at(nx)
            .expect("valid block");

        let last_location = block.last_location().expect("not empty");
        let block_state = &self.blocks[&nx];

        let project = block_state.project();

        let f = &project.functions()[fid];
        let target = f.address();

        tracing::debug!("analysing function call; target: {target}");

        let incoming_state = block_state.call_site_trace(tctx, rdefs, last_location, target);

        if f.is_extern() {
            tracing::trace!("external function call encountered; target: {target}");

            self.calls
                .insert(nx, SSECallSite::new_summary(incoming_state));

            // NOTE: this is essentially a no-op for now...
            return (false, block_state.clone());
        }

        match self.calls.entry(nx) {
            Entry::Occupied(mut entry) => {
                tracing::debug!("already analysed call site, checking if additional analysis required; target: {target}");

                let current = entry.get_mut();

                if current.is_non_returning() {
                    tracing::debug!("non-returning call site encountered; target: {target}");
                    return (false, SSETrace::empty(project));
                }

                if current.incoming().sses() == incoming_state.sses() {
                    tracing::debug!("call site already analysed (no changes); target: {target}");
                    return (
                        false,
                        current.outgoing().expect("analysed function").clone(),
                    );
                }

                let mut fstate = Self::new_callee_with(project, f, &incoming_state, self.config);

                fstate.analyse(tctx.arena(), project);

                let exit_nx = fstate.graph.exit().expect("function may return");
                let mut exit_state = fstate.blocks.get(&exit_nx).expect("valid block").to_owned();

                exit_state.purge_unique_variables();
                exit_state.map_generations(tctx, &last_location, rdefs);

                // exit_state -> map to current function

                if exit_state.sses() == current.outgoing().expect("analysed function").sses() {
                    tracing::debug!("call site already analysed (no changes); target: {target}");
                    return (false, exit_state);
                }

                current
                    .update_analysis_state(/* fstate, */ incoming_state, exit_state.clone());

                (true, exit_state)
            }
            Entry::Vacant(entry) => {
                let mut fstate = Self::new_callee_with(project, f, &incoming_state, self.config);

                let Some(exit_nx) = fstate.graph().exit() else {
                    tracing::debug!("call site skipped; function does not return");

                    entry.insert(SSECallSite::new_non_returning(incoming_state));

                    return (false, SSETrace::empty(project));
                };

                fstate.analyse(tctx.arena(), project);

                let mut exit_state = fstate.blocks.get(&exit_nx).expect("valid block").to_owned();

                exit_state.purge_unique_variables();
                exit_state.map_generations(tctx, &last_location, rdefs);

                entry.insert(SSECallSite::new_analysis(
                    // fstate,
                    incoming_state,
                    exit_state.clone(),
                ));

                (true, exit_state)
            }
        }
    }

    fn forward_pass(&mut self, tctx: &mut SSETraceContext<'a>) -> bool {
        let mut changed = false;

        // NOTE: we do this to satisfy the borrow checker
        let order = mem::take(&mut self.order);

        for nx in order.iter().copied().rev() {
            let block = &self.graph.graph()[nx];
            let trace = self.blocks.get_mut(&nx).expect("valid block");

            trace.fixpoint_pass(tctx, block);

            if let Some(fid) = block.call_target() {
                // TODO: store call traces within the structure
                let (changed_in_call, call_trace) = self.analyse_call(tctx, nx, fid);
                changed |= changed_in_call;

                let reaching_defs = self
                    .graph
                    .outgoing_reaching_definitions_at(nx)
                    .expect("valid block");

                for succ in self.graph.graph().edges_directed(nx, Direction::Outgoing) {
                    let succ = succ.target();
                    let succ_trace = self.blocks.get_mut(&succ).expect("valid block");

                    changed |= succ_trace.merge_forward(tctx, reaching_defs, call_trace.sses());
                }
            } else {
                let reaching_defs = self
                    .graph
                    .outgoing_reaching_definitions_at(nx)
                    .expect("valid block");

                for succ in self.graph.graph().edges_directed(nx, Direction::Outgoing) {
                    let succ = succ.target();
                    if succ == nx {
                        continue; // skip self-loops
                    }

                    let [curr_trace, succ_trace] = self.blocks.get_many_mut([&nx, &succ]);

                    let curr_trace = curr_trace.expect("valid block");
                    let succ_trace = succ_trace.expect("valid successor");

                    changed |= succ_trace.merge_forward(tctx, reaching_defs, curr_trace.sses());
                }
            }
        }

        self.order = order;

        changed
    }

    fn backward_pass(&mut self, tctx: &mut SSETraceContext<'a>) -> bool {
        let mut changed = false;

        // NOTE: we do this to satisfy the borrow checker
        let order = mem::take(&mut self.order);

        for nx in order.iter().copied().rev() {
            let block = &self.graph.graph()[nx];
            let trace = self.blocks.get_mut(&nx).expect("valid block");

            trace.fixpoint_pass(tctx, block);

            if let Some(fid) = block.call_target() {
                let (changed_in_call, call_trace) = self.analyse_call(tctx, nx, fid);
                changed |= changed_in_call;

                let reaching_defs = self
                    .graph
                    .incoming_reaching_definitions_at(nx)
                    .expect("valid block");

                for pred in self.graph.graph().edges_directed(nx, Direction::Incoming) {
                    let pred = pred.source();
                    let pred_trace = self.blocks.get_mut(&pred).expect("valid block");

                    changed |= pred_trace.merge_backward(tctx, reaching_defs, call_trace.sses());
                }
            } else {
                let reaching_defs = self
                    .graph
                    .incoming_reaching_definitions_at(nx)
                    .expect("valid block");

                for pred in self.graph.graph().edges_directed(nx, Direction::Incoming) {
                    let pred = pred.source();
                    if pred == nx {
                        continue; // skip self-loops
                    }

                    let [curr_trace, pred_trace] = self.blocks.get_many_mut([&nx, &pred]);

                    let curr_trace = curr_trace.expect("valid block");
                    let pred_trace = pred_trace.expect("valid predecessor");

                    changed |= pred_trace.merge_backward(tctx, reaching_defs, curr_trace.sses());
                }
            }
        }

        self.order = order;

        changed
    }
}
*/

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SSEAnalysisTargetKind {
    Def,
    Use,
    Output,
    Auto,
}

impl SSEAnalysisTargetKind {
    pub fn is_def(&self) -> bool {
        matches!(self, Self::Def)
    }

    pub fn is_use(&self) -> bool {
        matches!(self, Self::Use)
    }

    pub fn is_output(&self) -> bool {
        matches!(self, Self::Output)
    }

    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto)
    }
}

pub struct SSECallSiteAnalysis<'a> {
    call_string: SSECallString,
    incoming: SSETrace<'a>,
    // NOTE: this gets updated after analysis
    outgoing: Option<SSETrace<'a>>,
}

impl<'a> SSECallSiteAnalysis<'a> {
    pub fn call_string(&self) -> &SSECallString {
        &self.call_string
    }

    pub fn incoming(&self) -> &SSETrace<'a> {
        &self.incoming
    }

    pub fn outgoing(&self) -> Option<&SSETrace<'a>> {
        self.outgoing.as_ref()
    }
}

pub struct SSECallSiteSummary<'a> {
    call_string: SSECallString,
    incoming: SSETrace<'a>,
    outgoing: Option<SSETrace<'a>>,
}

impl<'a> SSECallSiteSummary<'a> {
    pub fn call_string(&self) -> &SSECallString {
        &self.call_string
    }

    pub fn incoming(&self) -> &SSETrace<'a> {
        &self.incoming
    }

    pub fn outgoing(&self) -> Option<&SSETrace<'a>> {
        self.outgoing.as_ref()
    }
}

pub struct SSENonReturningCallSite<'a> {
    call_string: SSECallString,
    incoming: SSETrace<'a>,
}

impl<'a> SSENonReturningCallSite<'a> {
    pub fn incoming(&self) -> &SSETrace<'a> {
        &self.incoming
    }
}

pub enum SSECallSite<'a> {
    Analysis(SSECallSiteAnalysis<'a>),
    Summary(SSECallSiteSummary<'a>),
    NonReturning(SSENonReturningCallSite<'a>),
}

impl<'a> SSECallSite<'a> {
    pub fn new_analysis(
        call_string: SSECallString,
        incoming: SSETrace<'a>,
        outgoing: impl Into<Option<SSETrace<'a>>>,
    ) -> Self {
        Self::Analysis(SSECallSiteAnalysis {
            call_string,
            incoming,
            outgoing: outgoing.into(),
        })
    }

    pub fn new_summary(call_string: SSECallString, incoming: SSETrace<'a>) -> Self {
        Self::new_summary_with(call_string, incoming, None)
    }

    pub fn new_summary_with(
        call_string: SSECallString,
        incoming: SSETrace<'a>,
        outgoing: impl Into<Option<SSETrace<'a>>>,
    ) -> Self {
        Self::Summary(SSECallSiteSummary {
            call_string,
            incoming,
            outgoing: outgoing.into(),
        })
    }

    pub fn new_non_returning(call_string: SSECallString, incoming: SSETrace<'a>) -> Self {
        Self::NonReturning(SSENonReturningCallSite {
            call_string,
            incoming,
        })
    }

    pub fn call_string(&self) -> &SSECallString {
        match self {
            Self::Analysis(call) => &call.call_string,
            Self::NonReturning(call) => &call.call_string,
            Self::Summary(call) => &call.call_string,
        }
    }

    pub fn incoming(&self) -> &SSETrace<'a> {
        match self {
            Self::Analysis(call) => &call.incoming,
            Self::NonReturning(call) => &call.incoming,
            Self::Summary(call) => &call.incoming,
        }
    }

    pub fn outgoing(&self) -> Option<&SSETrace<'a>> {
        match self {
            Self::Analysis(call) => call.outgoing(),
            Self::NonReturning(_) => None,
            Self::Summary(call) => call.outgoing(),
        }
    }

    pub fn is_non_returning(&self) -> bool {
        matches!(self, Self::NonReturning(_))
    }

    pub fn as_non_returning(&self) -> Option<&SSENonReturningCallSite<'a>> {
        match self {
            Self::NonReturning(call) => Some(call),
            Self::Summary(_) => None,
            Self::Analysis(_) => None,
        }
    }

    // NOTE: we should handle fix-ups using this mechanism
    pub fn is_summary(&self) -> bool {
        matches!(self, Self::Summary(_))
    }

    pub fn as_summary(&self) -> Option<&SSECallSiteSummary<'a>> {
        match self {
            Self::Summary(call) => Some(call),
            Self::NonReturning(_) => None,
            Self::Analysis(_) => None,
        }
    }

    pub fn is_analysis(&self) -> bool {
        matches!(self, Self::Analysis(_))
    }

    pub fn update_incoming_analysis_state(&mut self, incoming: SSETrace<'a>) -> bool {
        let Self::Analysis(call) = self else {
            panic!("cannot update analysis state on a non-returning/summary call site");
        };

        let changed = !call.incoming.has_equivalent_sses(&incoming)
            || !call.incoming.has_equivalent_validity(&incoming);
        if changed {
            call.incoming = incoming;
        }
        changed
    }

    pub fn update_outgoing_analysis_state(&mut self, outgoing: SSETrace<'a>) -> bool {
        let Self::Analysis(call) = self else {
            panic!("cannot update analysis state on a non-returning/summary call site");
        };

        tracing::trace!(
            "updating outgoing analysis state for call site {}",
            call.call_string
        );

        match &call.outgoing {
            Some(existing) => {
                let changed = !existing.has_equivalent_sses(&outgoing)
                    || !existing.has_equivalent_validity(&outgoing);
                if changed {
                    call.outgoing = Some(outgoing);
                }
                changed
            }
            None => {
                let changed = !outgoing.sses().is_empty();
                call.outgoing = Some(outgoing);
                changed
            }
        }
    }

    pub fn update_analysis_state(&mut self, incoming: SSETrace<'a>, outgoing: SSETrace<'a>) {
        let Self::Analysis(call) = self else {
            panic!("cannot update analysis state on a non-returning/summary call site");
        };

        call.incoming = incoming;
        call.outgoing = Some(outgoing);
    }
}
