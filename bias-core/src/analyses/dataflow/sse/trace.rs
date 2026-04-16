use std::fmt::Display;
use std::mem::swap;

use crate::cfg::ssa::{SSAClobberSet, SSAReachingDefinitionSet};
use crate::ir::SimpleVar;
use crate::kb::block::{ChunkedCodeBlock, CodeBlockInsnChunk, EmptyOrChunkedCodeBlock};
use crate::prelude::*;

use super::SSE;

use super::analysis::SSEFunctionGraph;
use super::validity::{SSEValidityLocation, SSEValiditySource};
use super::{
    SSEContext, SSEMatcher, SSEReplacer, SSEValidity, SSEValiditySet, SSExprArena, SSExprRef,
};

pub type SSESet<'a> = AHashSet<SSExprRef<'a>>;
pub type SSETrackedSet = AHashSet<SimpleVar>;
pub type SSEValidityMap<'a> = AHashMap<SSExprRef<'a>, SSEValiditySet<'a>>;
pub type SSAVarMap = AHashMap<SimpleVar, u32>;
pub type SSAVarSet = AHashMap<SimpleVar, (u32, u32)>;
pub type SSEVarMap<'a> = AHashMap<SimpleVar, SSEValidityMap<'a>>;

#[derive(Clone)]
pub struct SSETrace<'a> {
    tracked_set: SSETrackedSet,
    sses: SSEVarMap<'a>,
    all_sses: SSESet<'a>,
    project: &'a Project,
}

pub struct SSETraceContext<'a> {
    pub(crate) ctxt: SSEContext<'a>,
    gprs: AHashSet<Var>,
    pub(crate) rdmap: SSAVarMap,
    pub(crate) rdmap2: SSAVarMap,
    pub(crate) rdsets: SSAVarSet,
    pub(crate) sses: SSEVarMap<'a>,
    tracked_set: SSETrackedSet,
    inputs: Vec<SSExprRef<'a>>,
    outputs: Vec<SSExprRef<'a>>,
}

impl<'a> From<SSEContext<'a>> for SSETraceContext<'a> {
    fn from(ctxt: SSEContext<'a>) -> Self {
        let lifter = ctxt.project().lifter();

        let proto = lifter.default_prototype();
        let address_bits = lifter.address_bits();
        let register_space = lifter.register_space();
        let stack_pointer = lifter.stack_pointer();

        let prototype_to_sses = |operand: &PrototypeOperand| match operand {
            PrototypeOperand::Register { varnode, .. } => {
                let var = Var::new0(register_space, varnode.offset(), varnode.size() as u32 * 8);
                Some(ctxt.arena().var(var))
            }
            PrototypeOperand::StackRelative(offset) => {
                // offset will be positive
                let arena = ctxt.arena();
                let sp = arena.var(stack_pointer);
                let offset = if address_bits == 64 {
                    arena.val(*offset as u64)
                } else {
                    // 32-bit
                    arena.val(*offset as u32)
                };
                Some(arena.store(arena.binop(BinOp::ADD, sp, offset), address_bits))
            }
            // other case is a join
            _ => None,
        };

        let inputs = (0..10)
            .into_iter()
            .map_while(|i| prototype_to_sses(proto.input(i)?))
            .collect::<Vec<_>>();

        let outputs = (0..2)
            .into_iter()
            .map_while(|i| prototype_to_sses(proto.output(i)?))
            .collect::<Vec<_>>();

        Self {
            gprs: ctxt
                .project()
                .lifter()
                .arch()
                .gprs(ctxt.project().lifter().translator())
                .into_iter()
                .collect(),
            ctxt,
            rdmap: SSAVarMap::new(),
            rdmap2: SSAVarMap::new(),
            rdsets: SSAVarSet::new(),
            sses: SSEVarMap::new(),
            tracked_set: SSETrackedSet::new(),
            inputs,
            outputs,
        }
    }
}

impl<'a> SSETraceContext<'a> {
    pub fn new(arena: &'a SSExprArena, project: &'a Project) -> Self {
        Self::from(SSEContext::new(arena, project))
    }

    pub fn new_with(
        arena: &'a SSExprArena,
        project: &'a Project,
        complexity_limit: impl Into<Option<usize>>,
    ) -> Self {
        Self::from(SSEContext::new_with(arena, project, complexity_limit))
    }

    pub fn arena(&self) -> &'a SSExprArena {
        self.ctxt.arena()
    }

    pub fn matcher(&mut self) -> &mut SSEMatcher<'a> {
        self.ctxt.matcher()
    }

    pub fn replacer(&mut self) -> &mut SSEReplacer<'a> {
        self.ctxt.replacer()
    }

    pub fn forward_pass_substitute(
        &mut self,
        loc: &Location,
        op: &Term<Stmt>,
        sse: SSExprRef<'a>,
    ) -> Option<(SSExprRef<'a>, SSEValidity, Option<SSEValiditySource<'a>>)> {
        // rules 1-7
        tracing::trace!(
            "applying rules 1-7 (forward) for {}",
            sse.display(self.ctxt.project())
        );
        self.ctxt.substitute_defs(loc, op, sse).map(SSE::into_parts)
    }

    pub fn backward_pass_substitute(
        &mut self,
        loc: &Location,
        lower_validity: SSEValidityLocation,
        upper_validity: SSEValidityLocation,
        op: &Term<Stmt>,
        sse: SSExprRef<'a>,
    ) -> Option<(SSExprRef<'a>, SSEValidity, Option<SSEValiditySource<'a>>)> {
        // rules 1-6
        tracing::trace!(
            "applying rules 1-6 (backward) for {}",
            sse.display(self.ctxt.project())
        );
        self.ctxt
            .substitute_defs_backward(loc, lower_validity, upper_validity, op, sse)
            // rules 8-13
            .or_else(|| {
                tracing::trace!(
                    "applying rules 8-13 (backward) for {}",
                    sse.display(self.ctxt.project())
                );
                self.ctxt
                    .substitute_uses(loc, lower_validity, upper_validity, op, sse)
            })
            .map(SSE::into_parts)
    }

    pub fn sses(&mut self) -> &SSEVarMap<'a> {
        &self.sses
    }

    pub fn inputs(&self) -> &[SSExprRef<'a>] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[SSExprRef<'a>] {
        &self.outputs
    }

    fn is_call_boundary_sse_allowed(
        &mut self,
        sse: SSExprRef<'a>,
        reaching_defs: &SSAReachingDefinitionSet,
        reaching_defs_mapping: &SSAVarMap,
    ) -> bool {
        let gprs = &self.gprs;
        self.ctxt.matcher().all_variables_match(sse, |var| {
            !var.is_temporary()
                && gprs.contains(&var.with_generation(0))
                && (reaching_defs.contains(var)
                    || !reaching_defs_mapping.contains_key(&SimpleVar(*var)))
        })
    }

    fn prepare_return_boundary(&mut self, clobbers: Option<&SSAClobberSet>) {
        self.clear();

        if let Some(clobbers) = clobbers {
            self.rdmap.reserve(clobbers.len());

            for var in clobbers.iter() {
                self.rdmap.insert(SimpleVar(*var), 0);
            }
        }
    }

    fn is_return_boundary_sse_allowed(
        &mut self,
        sse: SSExprRef<'a>,
        exit_reaching_defs_mapping: &SSAVarMap,
    ) -> bool {
        let rdmap = &self.rdmap;
        let gprs = &self.gprs;
        self.ctxt.matcher().all_variables_match(sse, |var| {
            !var.is_temporary()
                && gprs.contains(&var.with_generation(0))
                && (exit_reaching_defs_mapping.contains_key(&SimpleVar(*var))
                    || (!exit_reaching_defs_mapping.contains_key(&SimpleVar(*var))
                        && !rdmap.contains_key(&SimpleVar(*var))))
        })
    }

    fn remap_to_callee_boundary_space(&mut self, sse: SSExprRef<'a>) -> SSExprRef<'a> {
        self.replacer().reset_generations(sse)
    }

    fn remap_to_call_site_generations(
        &mut self,
        tracked_var: SimpleVar,
        sse: SSExprRef<'a>,
        next_incoming_reaching_defs_mapping: &SSAVarMap,
    ) -> SSExprRef<'a> {
        let mut nsse = self.ctxt.replacer().map_generations(sse, |&var| {
            next_incoming_reaching_defs_mapping
                .get(&SimpleVar(var))
                .copied()
                .unwrap_or(0)
        });

        let nsse_vars = self.matcher().variables(nsse);
        if nsse_vars.len() == 1 {
            let nsse_var = *nsse_vars.iter().next().expect("single variable");
            if nsse == self.arena().var(nsse_var) && SimpleVar(nsse_var) != tracked_var {
                let mapped_generation = next_incoming_reaching_defs_mapping
                    .get(&tracked_var)
                    .copied()
                    .unwrap_or(0);
                nsse = self
                    .arena()
                    .var(tracked_var.with_generation(mapped_generation));
            }
        }

        nsse
    }

    fn prepare_reaching_definition_window(
        &mut self,
        incoming: &SSAReachingDefinitionSet,
        outgoing: &SSAReachingDefinitionSet,
    ) {
        self.clear();

        for var in incoming.iter().chain(outgoing.iter()) {
            let generation = var.generation();
            self.rdsets
                .entry(SimpleVar(*var))
                .and_modify(|(min, max)| {
                    *min = (*min).min(generation);
                    *max = (*max).max(generation);
                })
                .or_insert((generation, generation));
        }
    }

    fn matches_reaching_definition_window(&mut self, sse: SSExprRef<'a>) -> bool {
        let gprs = &self.gprs;
        let rdsets = &self.rdsets;
        self.ctxt.matcher().all_variables_match(sse, |var| {
            let generation = var.generation();
            !var.is_temporary()
                && gprs.contains(&var.with_generation(0))
                && rdsets.get(&SimpleVar(*var)).map_or_else(
                    || generation == 0,
                    |(min, max)| generation >= *min && generation <= *max,
                )
        })
    }

    pub(crate) fn remap_boundary_sses(
        &mut self,
        sses: &SSEVarMap<'a>,
        rdefs_mapping: &SSAVarMap,
    ) -> SSEVarMap<'a> {
        let mut remapped = SSEVarMap::new();

        for (var, sses) in sses.iter() {
            let entry = remapped.entry(*var).or_default();
            for (sse, validity) in sses.iter() {
                let nsse = self.ctxt.replacer().map_generations(*sse, |var| {
                    rdefs_mapping.get(&SimpleVar(*var)).copied().unwrap_or(0)
                });

                let target = entry.entry(nsse).or_default();
                target.extend_from(validity);
            }
        }

        remapped
    }

    pub fn context(&self) -> &SSEContext<'a> {
        &self.ctxt
    }

    pub fn clear(&mut self) {
        self.rdmap.clear();
        self.rdmap2.clear();
        self.rdsets.clear();
        self.sses.clear();
        self.tracked_set.clear();
    }
}

impl<'a> PartialEq for SSETrace<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.has_equivalent_sses(other) && self.has_equivalent_validity(&other)
    }
}

impl<'a> SSETrace<'a> {
    fn ensure_boundary_projection_target(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        var: SimpleVar,
        sse: SSExprRef<'a>,
    ) -> &mut SSEValiditySet<'a> {
        for var in tctx.matcher().variables(sse).iter().copied().map(SimpleVar) {
            self.tracked_set.insert(var);
            self.sses.entry(var).or_default();
        }

        self.tracked_set.insert(var);
        self.all_sses.insert(sse);

        self.sses.entry(var).or_default().entry(sse).or_default()
    }

    fn project_boundary_with(
        &self,
        tctx: &mut SSETraceContext<'a>,
        mut allow_sse: impl FnMut(&mut SSETraceContext<'a>, SSExprRef<'a>) -> bool,
        mut remap_sse: impl FnMut(&mut SSETraceContext<'a>, SimpleVar, SSExprRef<'a>) -> SSExprRef<'a>,
        mut keep_validity: impl FnMut(&SSEValidity) -> bool,
    ) -> Self {
        let mut projected = Self::empty(self.project);

        for (var, sses) in self.sses.iter() {
            for (sse, validity) in sses.iter() {
                if !allow_sse(tctx, *sse) {
                    continue;
                }

                if !validity.iter().any(|validity| keep_validity(validity)) {
                    continue;
                }

                let nsse = remap_sse(tctx, *var, *sse);
                let nvalidity = projected.ensure_boundary_projection_target(tctx, *var, nsse);
                nvalidity.extend(validity.iter().filter(|v| keep_validity(v)).copied());
                nvalidity.sources_mut().extend(validity.sources().cloned());
            }
        }

        projected
    }

    fn rebuild_from_boundary_snapshot(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        incoming: &SSAReachingDefinitionSet,
        outgoing: &SSAReachingDefinitionSet,
        sses: &SSEVarMap<'a>,
    ) -> &mut Self {
        self.clear();
        tctx.prepare_reaching_definition_window(incoming, outgoing);

        for (var, sses) in sses.iter() {
            for (sse, validity) in sses.iter() {
                if !tctx.matches_reaching_definition_window(*sse) {
                    continue;
                }

                let nvalidity = self.ensure_boundary_projection_target(tctx, *var, *sse);
                nvalidity.extend(validity.iter().copied());
                nvalidity.sources_mut().extend(validity.sources().cloned());
            }
        }

        self
    }

    pub fn new(project: &'a Project, arena: &'a SSExprArena, target: Var) -> Self {
        let mut sses = SSEVarMap::new();
        let mut tracked_set = SSETrackedSet::new();

        let target = SimpleVar(target);

        sses.entry(target)
            .or_default()
            .entry(arena.var(*target))
            .or_default()
            .insert(SSEValidity::default());

        tracked_set.insert(target);

        Self::new_with(project, tracked_set, sses)
    }

    pub fn new_tracking(project: &'a Project, target: Var) -> Self {
        let mut sses = SSEVarMap::new();
        let mut tracked_set = SSETrackedSet::new();

        let target = SimpleVar(target);

        sses.insert(target, Default::default());
        tracked_set.insert(target);

        Self::new_with(project, tracked_set, sses)
    }

    pub fn new_with_validity(
        project: &'a Project,
        arena: &'a SSExprArena,
        target: Var,
        validity: SSEValidity,
        source: Option<SSEValiditySource<'a>>,
    ) -> Self {
        let mut sses = SSEVarMap::new();
        let mut tracked_set = SSETrackedSet::new();

        let target = SimpleVar(target);

        let vset = sses
            .entry(target)
            .or_default()
            .entry(arena.var(*target))
            .or_default();
        vset.insert(validity);
        if let Some(source) = source {
            vset.add_source(source);
        }

        tracked_set.insert(target);

        Self::new_with(project, tracked_set, sses)
    }

    pub fn new_with(project: &'a Project, tracked_set: SSETrackedSet, sses: SSEVarMap<'a>) -> Self {
        Self {
            tracked_set,
            sses,
            all_sses: SSESet::new(),
            project,
        }
    }

    pub fn new_from_reaching_definitions(
        tctx: &mut SSETraceContext<'a>,
        graph: &SSEFunctionGraph,
        nx: NodeIndex,
        project: &'a Project,
        sses: &SSEVarMap<'a>,
    ) -> Self {
        let mut trace = Self::empty(project);
        trace.rebuild_from_boundary_snapshot(
            tctx,
            graph
                .incoming_reaching_definitions_at(nx)
                .expect("valid incoming reaching definitions"),
            graph
                .outgoing_reaching_definitions_at(nx)
                .expect("valid outgoing reaching definitions"),
            sses,
        );
        trace
    }

    pub(crate) fn empty(project: &'a Project) -> Self {
        Self {
            tracked_set: SSETrackedSet::new(),
            sses: SSEVarMap::new(),
            all_sses: SSESet::new(),
            project,
        }
    }

    pub fn from_incoming(trace: &SSETrace<'a>) -> Self {
        let mut state = Self::empty(trace.project);

        for (var, sses) in trace.sses.iter() {
            let nsses = state.sses.entry(*var).or_default();
            for sse in sses.keys() {
                nsses.entry(sse.clone()).or_default();
                state.all_sses.insert(sse.clone());
            }
            state.tracked_set.insert(*var);
        }

        state
    }

    pub fn has_equivalent_sses(&self, other: &Self) -> bool {
        if self.sses.len() != other.sses.len() {
            return false;
        }

        for (var, sses) in self.sses.iter() {
            if let Some(other_sses) = other.sses.get(var) {
                if sses.len() != other_sses.len() {
                    return false;
                }

                for sse in sses.keys() {
                    if !other_sses.contains_key(sse) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        true
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        for (var, sses) in self.sses.iter() {
            if let Some(other_sses) = other.sses.get(var) {
                for sse in sses.keys() {
                    if !other_sses.contains_key(sse) {
                        return false;
                    }
                }
            } else if !sses.is_empty() {
                return false;
            }
        }
        true
    }

    pub fn has_equivalent_validity(&self, other: &Self) -> bool {
        let other = other.sses();

        if self.sses.len() != other.len() {
            return false;
        }
        for (var, sses) in self.sses.iter() {
            let Some(other_sses) = other.get(var) else {
                return false;
            };
            if sses.len() != other_sses.len() {
                return false;
            }
            for (sse, validity) in sses.iter() {
                let Some(other_validity) = other_sses.get(sse) else {
                    return false;
                };
                if !validity.equivalent_validity(other_validity) {
                    return false;
                }
            }
        }
        true
    }

    pub fn validity_is_subset_of(&self, other: &SSEVarMap<'a>) -> bool {
        for (var, sses) in self.sses.iter() {
            let Some(other_sses) = other.get(var) else {
                return sses.is_empty();
            };

            for (sse, validity) in sses.iter() {
                let Some(other_validity) = other_sses.get(sse) else {
                    return false;
                };

                if !validity.is_subset_of(other_validity) {
                    return false;
                }
            }
        }

        true
    }

    pub fn would_change_with(&self, other: &Self) -> bool {
        for (var, sses) in other.sses.iter() {
            let Some(current_sses) = self.sses.get(var) else {
                if !sses.is_empty() {
                    return true;
                }
                continue;
            };

            for (sse, validity) in sses.iter() {
                let Some(current_validity) = current_sses.get(sse) else {
                    return true;
                };

                if !validity.is_subset_of(current_validity) {
                    return true;
                }
            }
        }

        false
    }

    pub fn purge_locally_bounded_variables(&mut self, tctx: &mut SSETraceContext<'a>) {
        let matcher = tctx.ctxt.matcher();

        self.tracked_set
            .retain(|v| !v.is_temporary() && tctx.gprs.contains(&v.with_generation(0)));
        self.sses.retain(|v, sse| {
            if !v.is_temporary() && tctx.gprs.contains(&v.with_generation(0)) {
                sse.retain(|sse, _validity| {
                    matcher.all_variables_match(*sse, |var| {
                        !var.is_temporary() && tctx.gprs.contains(&var.with_generation(0))
                    })
                });
                true
            } else {
                false
            }
        });
    }

    pub fn kill_and_bound_clobbered_variables(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        loc: &Location,
        clobbers: &SSAClobberSet,
    ) {
        let arena = tctx.arena();
        let matcher = tctx.ctxt.matcher();

        for var in clobbers.iter() {
            let var0 = arena.var(*var);
            let var1 = arena.var(var.with_generation(var.generation() - 1));

            tracing::trace!("killing clobber for {}", var.display(self.project));

            for sses in self.sses.values_mut() {
                for (sse, validity) in sses.iter_mut() {
                    if matcher.contains(*sse, var0) {
                        validity.map_validities(|mut v| {
                            if v.is_backward_live(loc) || v.is_forward_live(loc) {
                                tracing::trace!(
                                    "defining validity for {} via clobber {}",
                                    sse.display(self.project),
                                    var.display(self.project)
                                );
                                v.define(loc);
                            }
                            v
                        });
                    } else if matcher.contains(*sse, var1) {
                        validity.map_validities(|mut v| {
                            if v.is_backward_live(loc) || v.is_forward_live(loc) {
                                tracing::trace!(
                                    "killing validity for {} via clobber {}",
                                    sse.display(self.project),
                                    var.display(self.project)
                                );
                                v.kill(loc);
                            }
                            v
                        });
                    }
                }
            }
        }
    }

    pub fn kill(&mut self, tctx: &mut SSETraceContext<'a>, loc: &Location, op: &Term<Stmt>) {
        let arena = tctx.arena();
        let matcher = tctx.matcher();

        let defs = match op.value() {
            Stmt::Assign(var, _) => &[arena.var(var.with_generation(var.generation() - 1))][..],
            Stmt::Store(exp, _, sz, _) => {
                let Some(var) = exp.variable() else {
                    return;
                };
                let var = arena.var(*var);
                &[arena.load(var, *sz), arena.store(var, *sz)]
            }
            _ => {
                return;
            }
        };

        for sses in self.sses.values_mut() {
            for (sse, validity) in sses.iter_mut() {
                let contains_defs = defs.iter().any(|def| matcher.contains(*sse, *def));
                if !contains_defs {
                    continue;
                }
                validity.map_validities(|mut v| {
                    if v.is_backward_live(loc) || v.is_forward_live(loc) {
                        tracing::trace!("{loc} killing validity for {}", sse.display(self.project));
                        v.kill(loc);
                    }
                    v
                });
            }
        }
    }

    pub fn fixpoint_pass(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        blk: &EmptyOrChunkedCodeBlock,
    ) -> bool {
        let mut changed = true;
        let mut changed_in_any_iteration = false;

        while changed {
            let Some(chunked) = blk.as_chunked() else {
                changed = false;
                continue;
            };

            tracing::trace!("working on block: {}", chunked.location());

            changed = self.single_block_pass(tctx, chunked);
            changed_in_any_iteration |= changed;
        }

        changed_in_any_iteration
    }

    pub fn merge_forward(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        reaching_defs: &SSAReachingDefinitionSet,
        reaching_defs_mapping: &SSAVarMap,
        sses: &SSEVarMap<'a>,
    ) -> bool {
        let mut changed = false;

        let matcher = tctx.ctxt.matcher();

        tracing::trace!(
            "sses: {}",
            sses.iter()
                .map(|(var, _)| var.display(self.project).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        for (var, sses) in sses.iter() {
            tracing::trace!(
                "merging forward for variable: {}",
                var.display(self.project)
            );

            for (sse, validity) in sses.iter() {
                tracing::trace!("working on SSE: {}", sse.display(self.project));
                for validity in validity.iter() {
                    tracing::trace!("validity: {}", validity);
                }

                if !validity
                    .iter()
                    .any(|validity| validity.is_forward_unbounded())
                {
                    tracing::trace!("skipping SSE; not forward unbounded");
                    continue;
                }

                if !matcher.all_variables_match(*sse, |var| {
                    !var.is_temporary()
                        && tctx.gprs.contains(&var.with_generation(0))
                        && (reaching_defs.contains(var)
                            || (var.generation() == 0
                                && !reaching_defs_mapping.contains_key(&SimpleVar(*var))))
                }) {
                    tracing::trace!("skipping SSE; contains variables not live at this point");
                    continue;
                }

                let var_nsses = self.sses.entry(*var).or_default();
                let nvalidity = var_nsses.entry(sse.clone()).or_default();

                if !nvalidity.is_empty() {
                    nvalidity.sources_mut().extend(validity.sources().cloned());
                    continue;
                }

                nvalidity.extend(
                    validity
                        .iter()
                        .filter_map(|v| v.is_forward_unbounded().then_some(*v)),
                );

                nvalidity.sources_mut().extend(validity.sources().cloned());

                changed = true;

                tracing::trace!(
                    "merging forward for variable: {} ({})",
                    var.display(self.project),
                    sse.display(self.project)
                );

                self.all_sses.insert(sse.clone());
                self.tracked_set.insert(*var);

                for nvar in matcher.variables(*sse).iter().copied().map(SimpleVar) {
                    self.tracked_set.insert(nvar);
                    self.sses.entry(nvar).or_default();
                }
            }
        }

        changed
    }

    pub fn merge_backward(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        reaching_defs: &SSAReachingDefinitionSet,
        reaching_defs_mapping: &SSAVarMap,
        sses: &SSEVarMap<'a>,
    ) -> bool {
        let mut changed = false;

        let matcher = tctx.ctxt.matcher();

        for (var, sses) in sses.iter() {
            for (sse, validity) in sses.iter() {
                if !validity
                    .iter()
                    .any(|validity| validity.is_backward_unbounded())
                {
                    continue;
                }

                if !matcher.all_variables_match(*sse, |var| {
                    !var.is_temporary()
                        && tctx.gprs.contains(&var.with_generation(0))
                        && (reaching_defs.contains(var)
                            || (var.generation() == 0
                                && !reaching_defs_mapping.contains_key(&SimpleVar(*var))))
                }) {
                    continue;
                }

                let var_nsses = self.sses.entry(*var).or_default();
                let nvalidity = var_nsses.entry(sse.clone()).or_default();

                if !nvalidity.is_empty() {
                    nvalidity.sources_mut().extend(validity.sources().cloned());
                    continue;
                }

                nvalidity.extend(validity.iter().filter_map(|v| {
                    v.is_backward_unbounded()
                        .then(|| SSEValidity::backward_unbounded())
                }));

                nvalidity.sources_mut().extend(validity.sources().cloned());

                changed = true;

                self.all_sses.insert(sse.clone());
                self.tracked_set.insert(*var);

                for nvar in matcher.variables(*sse).iter().copied().map(SimpleVar) {
                    self.tracked_set.insert(nvar);
                    self.sses.entry(nvar).or_default();
                }
            }
        }

        changed
    }

    pub fn single_block_pass(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        blk: &ChunkedCodeBlock,
    ) -> bool {
        let mut changed = false;

        for chunk in blk.iter() {
            changed |= self.single_chunk_pass(tctx, chunk);
        }

        changed
    }

    pub fn single_chunk_pass(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        chunk: &CodeBlockInsnChunk,
    ) -> bool {
        let fc = self.forward_pass(tctx, chunk);
        let bc = self.backward_pass(tctx, chunk);
        fc || bc
    }

    pub fn forward_pass(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        chunk: &CodeBlockInsnChunk,
    ) -> bool {
        let loc = chunk.location();
        let operations = chunk.operations();

        let mut changed = false;

        for (j, op) in operations.iter().enumerate() {
            let loc = loc + j;

            tctx.clear();

            for var in self.tracked_set.iter() {
                tracing::trace!(
                    "{loc} working on {} from tracked set",
                    var.display(self.project)
                );
                for (sse, validity) in self.sses[var].iter() {
                    tracing::trace!(
                        "{loc} (forward) working on SSE: {}",
                        sse.display(self.project)
                    );

                    if !validity
                        .iter()
                        .any(|validity| validity.is_forward_live(&loc))
                    {
                        tracing::trace!("{loc} skipping SSE; killed");
                        for validity in validity.iter() {
                            tracing::trace!("{loc} validity: {}", validity);
                        }
                        continue;
                    }

                    let Some((nsse, mut nvalidity, nsource)) =
                        tctx.forward_pass_substitute(&loc, op, *sse)
                    else {
                        continue;
                    };

                    tracing::trace!(
                        "{loc} new SSE produced: {} ({})",
                        nsse.display(self.project),
                        nvalidity,
                    );

                    let mut has_locally_bounded = false;

                    for nvar in tctx
                        .ctxt
                        .matcher()
                        .variables(nsse)
                        .iter()
                        .copied()
                        .map(SimpleVar)
                    {
                        tracing::trace!("{loc}: new variable: {}", nvar.display(self.project));
                        has_locally_bounded |= nvar.is_temporary();
                        tctx.tracked_set.insert(nvar);
                        tctx.sses.entry(nvar).or_default();
                    }

                    if has_locally_bounded {
                        tracing::trace!("{loc} bounding SSE; contains instruction local temporaries");
                        nvalidity.bound_to(loc.address());
                    } else {
                        changed |= self.all_sses.insert(nsse);
                    }

                    let vset = tctx.sses.entry(*var).or_default().entry(nsse).or_default();
                    tracing::debug!("{loc} inserting forward validity: {}", nvalidity);
                    vset.insert(nvalidity);
                    if let Some(source) = nsource {
                        vset.add_source(source);
                    }
                }
            }

            self.kill(tctx, &loc, op);

            self.tracked_set.extend(tctx.tracked_set.drain());

            for (&var, sses) in tctx.sses.iter_mut() {
                let entry = self.sses.entry(var).or_default();
                for (&sse, validity) in sses.iter_mut() {
                    let target = entry.entry(sse).or_default();
                    let before = target.len();
                    target.extend(validity.drain());
                    target.sources_mut().extend(validity.drain_sources());
                    if target.len() > before && target.len() > 4 {
                        tracing::debug!(
                            "(forward) validity set for SSE now has {} validities (was {})",
                            target.len(),
                            before
                        );
                    }
                }
            }
        }

        changed
    }

    pub fn backward_pass(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        chunk: &CodeBlockInsnChunk,
    ) -> bool {
        let loc = chunk.location();
        let operations = chunk.operations();

        let mut changed = false;

        for (j, op) in operations.iter().enumerate().rev() {
            let loc = loc + j;

            tctx.clear();

            for var in self.tracked_set.iter() {
                for (sse, validity) in self.sses[var].iter() {
                    tracing::trace!(
                        "{loc} (backward) working on SSE: {}",
                        sse.display(self.project)
                    );

                    if !validity
                        .iter()
                        .any(|validity| validity.is_backward_live(&loc))
                    {
                        tracing::trace!("{loc} skipping SSE; killed");
                        for validity in validity.iter() {
                            tracing::trace!("{loc} validity: {}", validity);
                        }
                        continue;
                    }

                    let (lower_validity, upper_validity) = SSEValidity::bounds(loc, validity);

                    if validity.len() > 4 {
                        tracing::debug!(
                            "{loc} (backward) validity count: {}, bounds: {} - {}",
                            validity.len(),
                            lower_validity,
                            upper_validity
                        );
                    }

                    tracing::trace!(
                        "{loc} validity bounds: {} - {}",
                        lower_validity,
                        upper_validity,
                    );

                    let Some((nsse, mut nvalidity, nsource)) = tctx.backward_pass_substitute(
                        &loc,
                        lower_validity,
                        upper_validity,
                        op,
                        *sse,
                    ) else {
                        continue;
                    };

                    tracing::trace!(
                        "{loc} new SSE produced: {} ({})",
                        nsse.display(self.project),
                        nvalidity,
                    );

                    let mut has_locally_bounded = false;

                    for nvar in tctx
                        .ctxt
                        .matcher()
                        .variables(nsse)
                        .iter()
                        .copied()
                        .map(SimpleVar)
                    {
                        has_locally_bounded |= nvar.is_temporary();
                        tctx.tracked_set.insert(nvar);
                        tctx.sses.entry(nvar).or_default();
                    }

                    if has_locally_bounded {
                        tracing::trace!("{loc} bounding SSE; contains instruction local temporaries");
                        nvalidity.bound_to(loc.address());
                    } else {
                        changed |= self.all_sses.insert(nsse);
                    }

                    let vset = tctx.sses.entry(*var).or_default().entry(nsse).or_default();
                    tracing::debug!("{loc} inserting backward validity: {}", nvalidity);
                    vset.insert(nvalidity);
                    if let Some(source) = nsource {
                        vset.add_source(source);
                    }
                }
            }

            self.tracked_set.extend(tctx.tracked_set.drain());

            for (&var, sses) in tctx.sses.iter_mut() {
                let entry = self.sses.entry(var).or_default();
                for (&sse, validity) in sses.iter_mut() {
                    let target = entry.entry(sse).or_default();
                    let before = target.len();
                    target.extend(validity.drain());
                    target.sources_mut().extend(validity.drain_sources());
                    if target.len() > before && target.len() > 4 {
                        tracing::debug!(
                            "validity set for SSE now has {} validities (was {})",
                            target.len(),
                            before
                        );
                    }
                }
            }
        }

        changed
    }

    pub fn call_site_trace(
        &self,
        tctx: &mut SSETraceContext<'a>,
        reaching_defs: &SSAReachingDefinitionSet,
        reaching_defs_mapping: &SSAVarMap,
        source: Location,
    ) -> Self {
        let tsource = source + 1usize;
        let trace = self.project_boundary_with(
            tctx,
            |tctx, sse| {
                tctx.is_call_boundary_sse_allowed(sse, reaching_defs, reaching_defs_mapping)
            },
            |tctx, _, sse| tctx.remap_to_callee_boundary_space(sse),
            |validity| validity.is_forward_live(&tsource),
        );

        for tracked in trace.tracked_set.iter() {
            tracing::trace!(
                "call site trace: adding tracked variable {}",
                tracked.display(self.project)
            );
        }

        for sse in trace.sses.keys() {
            tracing::trace!("call site trace: adding sse {}", sse.display(self.project));
        }

        trace
    }

    pub fn return_site_trace(
        &self,
        tctx: &mut SSETraceContext<'a>,
        next_incoming_reaching_defs: &SSAReachingDefinitionSet,
        next_incoming_reaching_defs_mapping: &SSAVarMap,
        clobbers: Option<&SSAClobberSet>,
        exit_reaching_defs: &SSAReachingDefinitionSet,
        exit_reaching_defs_mapping: &SSAVarMap,
        tsource: Location,
    ) -> Self {
        tctx.prepare_return_boundary(clobbers);

        tracing::trace!("return site trace; next incoming rds");
        for var in next_incoming_reaching_defs.iter() {
            tracing::trace!("{}", var.display(self.project));
        }

        tracing::trace!("return site trace; exit rds");
        for var in exit_reaching_defs.iter() {
            tracing::trace!("{}", var.display(self.project));
        }

        let trace = self.project_boundary_with(
            tctx,
            |tctx, sse| tctx.is_return_boundary_sse_allowed(sse, exit_reaching_defs_mapping),
            |tctx, tracked_var, sse| {
                let nsse = tctx.remap_to_call_site_generations(
                    tracked_var,
                    sse,
                    next_incoming_reaching_defs_mapping,
                );
                for var in tctx.matcher().variables(nsse) {
                    tracing::trace!(
                        "mapping {} to {}",
                        var.display(self.project),
                        next_incoming_reaching_defs_mapping
                            .get(&SimpleVar(*var))
                            .copied()
                            .unwrap_or(0)
                    );
                }
                nsse
            },
            |validity| validity.is_backward_live(&tsource) || validity.is_forward_live(&tsource),
        );

        for tracked in trace.tracked_set.iter() {
            tracing::trace!(
                "call site trace: adding tracked variable {}",
                tracked.display(self.project)
            );
        }

        for sse in trace.sses.keys() {
            tracing::trace!("call site trace: adding sse {}", sse.display(self.project));
        }

        trace
    }

    pub fn map_generations(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        _loc: &Location,
        rdefs_mapping: &SSAVarMap,
    ) {
        self.tracked_set.clear();
        self.all_sses.clear();

        for (var, sses) in self.sses.drain() {
            self.tracked_set.insert(var);

            tctx.sses
                .entry(var)
                .or_default()
                .extend(sses.into_iter().map(|(sse, validity)| {
                    let sse = tctx.ctxt.replacer().map_generations(sse, |&var| {
                        rdefs_mapping.get(&SimpleVar(var)).copied().unwrap_or(0)
                    });

                    for var in tctx
                        .ctxt
                        .matcher()
                        .variables(sse)
                        .iter()
                        .copied()
                        .map(SimpleVar)
                    {
                        self.tracked_set.insert(var);
                    }
                    self.all_sses.insert(sse);

                    (sse, validity)
                }));
        }

        for var in self.tracked_set.iter() {
            tctx.sses.entry(*var).or_default();
        }

        swap(&mut self.sses, &mut tctx.sses);
    }

    pub fn reset_ssa_generations(&mut self, tctx: &mut SSETraceContext<'a>) {
        self.tracked_set.clear();
        self.all_sses.clear();

        let mut nsses = SSEVarMap::new();

        for (var, sses) in self.sses.drain() {
            self.tracked_set.insert(var);

            let entry = nsses.entry(var).or_default();
            for (sse, mut validity) in sses {
                let nsse = tctx.ctxt.replacer().reset_generations(sse);

                for var in tctx
                    .ctxt
                    .matcher()
                    .variables(nsse)
                    .iter()
                    .copied()
                    .map(SimpleVar)
                {
                    self.tracked_set.insert(var);
                }

                self.all_sses.insert(nsse);

                let target = entry.entry(nsse).or_default();
                target.extend(validity.drain());
                target.sources_mut().extend(validity.drain_sources());
            }
        }

        self.sses = nsses;
    }

    pub fn clear(&mut self) {
        self.tracked_set.clear();
        self.sses.clear();
        self.all_sses.clear();
    }

    pub fn update_with(
        &mut self,
        tracked_set: &SSETrackedSet,
        sses: &SSEVarMap<'a>,
        clear: bool,
    ) -> &mut Self {
        if clear {
            self.clear();
        }

        for (var, sses) in sses.iter() {
            let nsses = self.sses.entry(*var).or_default();
            for (sse, validity) in sses.iter() {
                let target = nsses.entry(sse.clone()).or_default();
                target.extend(validity.iter().copied());
                target.sources_mut().extend(validity.sources().cloned());
            }
        }

        self.tracked_set.extend(tracked_set.iter().cloned());
        self.all_sses
            .extend(sses.values().flat_map(|sses| sses.keys().cloned()));

        self
    }

    pub fn rebuild_with_reaching_definitions(
        &mut self,
        tctx: &mut SSETraceContext<'a>,
        incoming: &SSAReachingDefinitionSet,
        outgoing: &SSAReachingDefinitionSet,
        sses: &SSEVarMap<'a>,
    ) -> &mut Self {
        self.rebuild_from_boundary_snapshot(tctx, incoming, outgoing, sses)
    }

    pub fn merge(&mut self, other: &SSETrace<'a>) {
        self.update_with(other.tracked_set(), other.sses(), false);
    }

    pub fn merged(&self, other: &SSETrace<'a>) -> Self {
        let mut merged = self.clone();
        merged.merge(other);
        merged
    }

    pub fn add_alias(&mut self, var: SimpleVar, sse: SSExprRef<'a>, validity: SSEValidity) {
        self.tracked_set.insert(var);
        self.sses
            .entry(var)
            .or_default()
            .entry(sse)
            .or_default()
            .insert(validity);
        self.all_sses.insert(sse);
    }

    pub fn add_alias_with_source(
        &mut self,
        var: SimpleVar,
        sse: SSExprRef<'a>,
        validity: SSEValidity,
        source: SSEValiditySource<'a>,
    ) {
        self.tracked_set.insert(var);
        let vset = self.sses.entry(var).or_default().entry(sse).or_default();
        vset.insert(validity);
        vset.add_source(source);
        self.all_sses.insert(sse);
    }

    pub fn project(&self) -> &'a Project {
        self.project
    }

    pub fn sses(&self) -> &SSEVarMap<'a> {
        &self.sses
    }

    pub fn sses_mut(&mut self) -> &mut SSEVarMap<'a> {
        &mut self.sses
    }

    pub fn into_sses(self) -> SSEVarMap<'a> {
        self.sses
    }

    pub fn tracked_set(&self) -> &SSETrackedSet {
        &self.tracked_set
    }

    pub fn tracked_set_mut(&mut self) -> &mut SSETrackedSet {
        &mut self.tracked_set
    }
}

impl Display for SSETrace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sses = self.all_sses.iter();

        if let Some(first) = sses.next() {
            write!(f, "SSEs:\n\t{}", first.display(self.project))?;
        } else {
            write!(f, "SSEs: <none>")?;
        }

        for sse in sses {
            write!(f, "\n\t{}", sse.display(self.project))?;
        }

        writeln!(f)?;

        if self.sses.is_empty() {
            write!(f, "SSE validities: <none>")?;
        } else {
            write!(f, "SSE validities:")?;
        }

        for (var, sses) in self.sses.iter() {
            write!(f, "\n\t{}:", var.display(self.project))?;
            for (sse, validity) in sses.iter() {
                writeln!(f)?;
                if validity.is_empty() {
                    write!(f, "\t\t{}: <none>", sse.display(self.project))?;
                } else {
                    write!(f, "\t\t{}: ", sse.display(self.project))?;
                    let mut validity_iter = validity.iter();
                    if let Some(first) = validity_iter.next() {
                        write!(f, "{}", first)?;
                    }
                    for validity in validity_iter {
                        write!(f, ", {}", validity)?;
                    }
                }
                for source in validity.sources() {
                    write!(
                        f,
                        "; source: {} via {}",
                        source.sse().display(self.project),
                        source.location()
                    )?;
                }
            }
        }

        writeln!(f)?;

        let mut tracked = self.tracked_set.iter();

        if let Some(first) = tracked.next() {
            write!(f, "Tracked:\n\t{}", first.display(self.project))?;
        } else {
            write!(f, "Tracked: <none>")?;
        }

        for tracked in tracked {
            write!(f, "\n\t{}", tracked.display(self.project))?;
        }

        Ok(())
    }
}
