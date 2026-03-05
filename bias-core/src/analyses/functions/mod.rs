use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use bias_core_derive::ProvidesStaticType;
use itertools::Itertools;
use petgraph::algo::dominators;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::{EdgeRef, IntoEdgesDirected, IntoNeighborsDirected, IntoNodeReferences};
use petgraph::Direction;

use crate::analyses::stack::aliases::StackRefs;
use crate::analyses::stack::possibly_uninit::UninitUses;
use crate::analyses::stack::reaching_constants::ReachingStackConsts;
use crate::analyses::stack::reaching_definitions::ReachingStackDefs;
use crate::analyses::stack::reaching_uninit::ReachingUninitValues;
use crate::cfg::non_returning::{
    NonReturningFunctions, NonReturningPropagator, PropagatedNonReturning,
};
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::{Bound, IRContext, IREvalConfig, ObserverContext, ObserverState};
use crate::ir::{BinRel, BitVec, Expr, Location, Term, ValHint, Var};
use crate::kb::function::{Function, FunctionId};
use crate::kb::function_summary::FunctionSummary;
use crate::kb::id::Identifiable;
use crate::kb::operand::Operand;
use crate::kb::{uuid, AHashMap, AHashSet, Uuid};
use crate::prelude::{CodeBlock, DefaultTypeResolver, FunctionCFG, TypedAliases};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule, Schedule};
use crate::Project;

pub const FUNCTION_SPLIT: Uuid = uuid("B8C904CF-FB8C-4F71-9A04-7D3D709EB21A");

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct FunctionSplit {
    new_functions: Vec<FunctionId>,
}

impl AnalysisInfo for FunctionSplit {
    const NAME: &'static str = "Function Splitting";
    const UUID: Uuid = FUNCTION_SPLIT;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[Schedule::Before(FUNCTION_SUMMARIES)];
}

impl Analysis for FunctionSplit {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[Schedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let tables = project.tables_mut();
        let mut to_add = Vec::with_capacity(0);

        for f in tables.ftable.values_mut() {
            let chunks = f.split_chunks_with(tables.icfg, tables.cbtable);
            if chunks.len() > 1 {
                for chunk in chunks.into_iter() {
                    if chunk.address() == f.address() {
                        *f = chunk;
                    } else {
                        to_add.push(chunk);
                    }
                }
            }
        }

        self.new_functions.reserve(to_add.len());

        for mut new_f in to_add {
            let id = tables.ftable.insert_with(new_f.address(), |_addr, fid| {
                new_f.update_id(fid);
                new_f.for_blocks_mut(tables.cbtable, |_, cb| {
                    cb.update_function(fid);
                });
                new_f
            });
            self.new_functions.push(id);
        }

        Ok(())
    }
}

pub const FUNCTION_ARGUMENT_COUNTS: Uuid = uuid("12465B3B-BADE-495F-8F77-50A3E1366FAF");

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct FunctionArgumentCounts {
    counts: BTreeMap<FunctionId, usize>,
}

impl FunctionArgumentCounts {
    pub fn get(&self, fid: impl AsRef<FunctionId>) -> Option<usize> {
        self.counts.get(fid.as_ref()).copied()
    }
}

impl AnalysisInfo for FunctionArgumentCounts {
    const NAME: &'static str = "Function argument counts";
    const UUID: Uuid = FUNCTION_ARGUMENT_COUNTS;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::prefer_after::<FunctionSummaries>()];
}

impl Analysis for FunctionArgumentCounts {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        for f in project.functions().values() {
            self.counts
                .insert(f.id(), Self::analyse_function(project, f)?);
        }
        Ok(())
    }
}

impl FunctionArgumentCounts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyse_function(project: &Project, f: &Function) -> Result<usize, AnalysisError> {
        if let Some(summary) = project.function_summaries().get_for_function(f.id()) {
            return Ok(summary.arguments().len());
        }

        let (refs, accesses) = StackRefs::analyse_function_full(project, f);
        let rdefs = ReachingStackDefs::analyse_function_with(project, f, &refs, &accesses);
        let uninit_uses = UninitUses::analyse_function_with(project, f, &rdefs, &refs, &accesses);

        let possible_arguments = uninit_uses.possible_arguments(project.lifter());

        Ok(possible_arguments.len())
    }
}

pub const FUNCTION_CLOBBERS: Uuid = uuid("746D7438-FD3B-4D2C-8CDA-813A4D5488AC");

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct FunctionClobbers {
    clobbers: BTreeMap<FunctionId, Vec<Operand>>,
}

impl FunctionClobbers {
    pub fn get(&self, fid: impl AsRef<FunctionId>) -> Option<&[Operand]> {
        self.clobbers.get(fid.as_ref()).map(|opnds| opnds.as_ref())
    }
}

impl AnalysisInfo for FunctionClobbers {
    const NAME: &'static str = "Function clobbers";
    const UUID: Uuid = FUNCTION_CLOBBERS;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::prefer_after::<FunctionSummaries>()];
}

impl Analysis for FunctionClobbers {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        for f in project.functions().values() {
            self.clobbers
                .insert(f.id(), Self::analyse_function(project, f).into_owned());
        }
        Ok(())
    }
}

impl FunctionClobbers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyse_function<'a>(project: &'a Project, f: &'a Function) -> Cow<'a, Vec<Operand>> {
        if let Some(summary) = project.function_summaries().get_for_function(f.id()) {
            return Cow::Borrowed(summary.definitely_killed());
        }

        let (refs, accesses) = StackRefs::analyse_function_full(project, f);
        let uninit_vals = ReachingUninitValues::analyse_function_with(project, f, &refs, &accesses);

        let definitely_killed = uninit_vals.definitely_killed_with(project.code_blocks(), true);

        Cow::Owned(definitely_killed.into_iter().map(Operand::from).collect())
    }
}

pub const FUNCTION_SUMMARIES: Uuid = uuid("C4E9A217-D4A7-4227-85A3-BF927AF55D79");

impl AnalysisInfo for FunctionSummaries {
    const NAME: &'static str = "Function Summaries";
    const UUID: Uuid = FUNCTION_SUMMARIES;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct FunctionSummaries;

impl FunctionSummaries {
    pub fn analyse_function(project: &Project, f: &Function) -> FunctionSummary {
        let (refs, accesses) = StackRefs::analyse_function_full(project, f);
        let csts = ReachingStackConsts::analyse_function_with(project, f, &refs, &accesses);
        let rdefs = ReachingStackDefs::analyse_function_with(project, f, &refs, &accesses);
        let uninit_values =
            ReachingUninitValues::analyse_function_with(project, f, &refs, &accesses);
        let uninit_uses = UninitUses::analyse_function_with(project, f, &rdefs, &refs, &accesses);

        let possible_arguments = uninit_uses.possible_arguments(project.lifter());
        let preserved_or_restored = uninit_values.preserved_or_restored(project.code_blocks());
        let definitely_killed = uninit_values.definitely_killed_with(project.code_blocks(), true);

        let stack_shift = accesses
            .blocks()
            .values()
            .map(|acc| {
                let v1 = acc
                    .loads()
                    .values()
                    .map(|a| a.iter())
                    .flatten()
                    .map(|a| a.offset())
                    .min()
                    .unwrap_or(0);
                let v2 = acc
                    .stores()
                    .values()
                    .map(|a| a.iter())
                    .flatten()
                    .map(|a| a.offset())
                    .min()
                    .unwrap_or(0);

                v1.min(v2)
            })
            .min()
            .unwrap_or(0);

        let mut s = FunctionSummary::for_function(Default::default(), f.id());

        *s.stack_accesses_mut() = Some(accesses);
        *s.stack_references_mut() = Some(refs);
        *s.reaching_constants_mut() = Some(csts);
        *s.reaching_definitions_mut() = Some(rdefs);
        *s.reaching_uninit_values_mut() = Some(uninit_values);
        *s.uninit_uses_mut() = Some(uninit_uses);

        s.set_stack_shift(stack_shift);

        let args = s.arguments_mut();

        args.clear();
        args.extend(possible_arguments.into_iter().map(Operand::from));

        let pres = s.preserved_or_restored_mut();

        pres.clear();
        pres.extend(preserved_or_restored.into_iter().map(Operand::from));

        let kills = s.definitely_killed_mut();

        kills.clear();
        kills.extend(definitely_killed.into_iter().map(Operand::from));

        s
    }
}

impl Analysis for FunctionSummaries {
    fn id(&self) -> &Uuid {
        &FUNCTION_SUMMARIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut summaries = BTreeMap::new();

        for f in project
            .functions()
            .values()
            .filter(|f| !project.function_summaries().contains_function(f.id()))
        {
            summaries.insert(f.id(), Self::analyse_function(&project, f));
        }

        for (fid, mut fs) in summaries {
            project
                .function_summaries_mut()
                .insert_for_function(fid, |fsid, _| {
                    fs.update_id(fsid);
                    fs
                });
        }

        Ok(())
    }
}

#[derive(ProvidesStaticType)]
struct LoopObserverContext<'a> {
    current: &'a CodeBlock,
    found: bool,
}

const LOOP_OBSERVER_CONTEXT: Uuid = uuid("1D423A06-75C9-4446-B6E6-F43AE370A3ED");

impl<'a> ObserverState<'a> for LoopObserverContext<'a> {
    fn id(&self) -> &Uuid {
        &LOOP_OBSERVER_CONTEXT
    }
}

impl<'a> LoopObserverContext<'a> {
    fn new(current: &'a CodeBlock) -> Self {
        Self {
            current,
            found: false,
        }
    }

    fn current(&self) -> &CodeBlock {
        self.current
    }

    fn mark(&mut self) {
        self.found = true
    }

    fn is_infinite(&self) -> bool {
        self.found
    }
}

#[derive(Default)]
struct LoopObserver;

impl Observer for LoopObserver {
    fn observe_post_var_write_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        _var: &Var,
        val: &BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        let ctx = observer_context
            .get_mut::<LoopObserverContext>(LOOP_OBSERVER_CONTEXT)
            .expect("invalid context");

        // previous block that contains the initialisation
        // of the variable related to the loop condition:
        //
        // str     xzr, [sp, #0x18 {var_8}]  {0x0}
        //
        // current block that contains the loop condition:
        //
        // ldr     x0, [sp, #0x18 {var_8}]  {0x0}
        // cbz     x0, 0x6488  {0x1}

        if location.address() != ctx.current().last_address() || !val.is_one() {
            return Ok(());
        };

        let Expr::BinRel(BinRel::EQ, _, e) = sexpr.as_ref() else {
            return Ok(());
        };

        let Expr::Val(bv, ValHint::CONSTANT) = e.as_ref() else {
            return Ok(());
        };

        if bv.is_zero() {
            ctx.mark();
        }

        Ok(())
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct MaybeNonReturning {
    functions: NonReturningFunctions,
}

impl MaybeNonReturning {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn functions(&self) -> &NonReturningFunctions {
        &self.functions
    }

    pub fn contains(&self, f: FunctionId) -> bool {
        self.functions.contains(&f)
    }

    pub fn iter<'a>(&'a self) -> impl ExactSizeIterator<Item = FunctionId> + 'a {
        self.functions.iter().copied()
    }

    fn infinite_loop(&self, project: &Project, cfg: &FunctionCFG, current: NodeIndex) -> bool {
        // make sure that there are only two incoming nodes:
        // - one block outside of the loop
        // - one block inside the loop
        let it = cfg.neighbors_directed(current, Direction::Incoming);

        let blocks = project.code_blocks();
        let icfg = project.icfg();

        let prev = if let Some((n1, n2)) = it.collect_tuple() {
            // we should filter node that have jump to current
            if blocks[icfg[n1]].is_jump() {
                n2
            } else {
                n1
            }
        } else {
            return false;
        };

        let cblock = &blocks[icfg[current]];
        let pblock = &blocks[icfg[prev]];

        let mut eval = project
            .evaluator(IREvalConfig {
                enable_restores: true,
                ignore_unimplemented_ops: true,
                ignore_divide_by_zero: true,
                ignore_failures: true,
                ignore_invalid_accesses: true,
                ..Default::default()
            })
            .expect("evaluator initialisation failed");

        eval.register_observer(LoopObserver::default());

        let mut obs_ctx = ObserverContext::default();
        obs_ctx.set(LOOP_OBSERVER_CONTEXT, LoopObserverContext::new(cblock));

        eval.eval_full(
            project.tables(),
            &mut obs_ctx,
            pblock.address(),
            Bound::StopAfterOr(cblock.last_address(), 40),
        )
        .ok();

        eval.restore().ok();

        let ctx = obs_ctx
            .get::<LoopObserverContext>(LOOP_OBSERVER_CONTEXT)
            .expect("invalid context");

        ctx.is_infinite()
    }
}

pub const MAYBE_NON_RETURNING: Uuid = uuid("DAD7569C-46E3-4342-98C3-DBC4CA5F880E");

impl AnalysisInfo for MaybeNonReturning {
    const NAME: &'static str = "Non-returning function identification";
    const UUID: Uuid = MAYBE_NON_RETURNING;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::before::<PropagatedNonReturning<Self>>()];
}

impl Analysis for MaybeNonReturning {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut checked = AHashSet::new();

        let blocks = project.code_blocks();
        let functions = project.functions();
        let icfg = project.icfg();

        for blk in blocks.values().filter(|blk| blk.is_call()) {
            let mut it = icfg
                .edges_directed(blk.node(), Direction::Outgoing)
                .filter_map(|e| {
                    if !e.weight().is_fall() {
                        Some(e.target())
                    } else {
                        None
                    }
                });

            // H1: call to function terminates a block
            let Some(nx) = it.next() else { continue };
            if it.next().is_some() {
                continue;
            }

            let f = &functions[blocks[icfg[nx]].function()];

            if !checked.insert(f.id()) {
                continue;
            }

            // H2: no exits that return
            let mut no_ret = true;
            let mut no_xflow = true;

            for blk in f.blocks_with(blocks) {
                // returns
                if blk.is_return() {
                    no_ret = false;
                    break;
                }

                // cross-function flow
                if blk.is_indirect_jump()
                    || icfg
                        .neighbors_directed(blk.node(), Direction::Outgoing)
                        .any(|nx| blocks[icfg[nx]].function() != f.id())
                {
                    no_xflow = false;
                    break;
                }
            }

            if no_ret && no_xflow {
                Arc::make_mut(&mut self.functions).insert(f.id());
                continue;
            }

            // H3: no exits that return after const/type propagation to branches
            let constp = TypedAliases::analyse_function::<DefaultTypeResolver>(&project, f);

            let fcfg = f.cfg(icfg, blocks);
            let doms = dominators::simple_fast(&*fcfg, nx);

            let mut dtree = StableDiGraph::new();
            let mut dmapping = AHashMap::new();

            for node in fcfg.node_references() {
                dmapping.insert(node.0, dtree.add_node(node.0));
            }

            for node in fcfg.node_references() {
                let node = node.0;
                if let Some(idom) = doms.immediate_dominator(node) {
                    dtree.add_edge(dmapping[&idom], dmapping[&node], ());
                }
            }

            let mut filtered_blocks = AHashSet::new();

            for blk in f.blocks_with(blocks) {
                let bid = blk.id();
                let Some(ff) = constp.blocks().get(&bid) else {
                    continue;
                };
                let Some(vt) = ff.condition().and_then(|vt| vt.v.is_true()) else {
                    continue;
                };

                let mut edges = fcfg.edges_directed(blk.node(), Direction::Outgoing);
                let killed = if vt {
                    edges.find_map(|e| {
                        if e.weight().is_fall() {
                            Some(e.target())
                        } else {
                            None
                        }
                    })
                } else {
                    edges.find_map(|e| {
                        if e.weight().is_branch() {
                            Some(e.target())
                        } else {
                            None
                        }
                    })
                };

                let Some(killed) = killed else { continue };

                let mut killq = vec![killed];
                let mut filtered = AHashSet::new();

                while let Some(killed) = killq.pop() {
                    if killed == blk.node() {
                        // killed node should not dominate blk node
                        filtered.clear();
                        break;
                    }

                    if !filtered.insert(killed) {
                        continue;
                    }

                    for killed in dtree.neighbors_directed(dmapping[&killed], Direction::Outgoing) {
                        killq.push(dtree[killed]);
                    }
                }

                filtered_blocks.extend(filtered);
            }

            // Try H2 again without filtered blocks
            no_ret = true;
            no_xflow = true;

            for blk in f
                .blocks_with(blocks)
                .filter(|blk| !filtered_blocks.contains(&blk.node()))
            {
                // returns
                if blk.is_return() {
                    no_ret = false;
                    break;
                }

                // cross-function flow
                if blk.is_indirect_jump()
                    || icfg
                        .neighbors_directed(blk.node(), Direction::Outgoing)
                        .any(|nx| blocks[icfg[nx]].function() != f.id())
                {
                    no_xflow = false;
                    break;
                }
            }

            if no_ret && no_xflow {
                Arc::make_mut(&mut self.functions).insert(f.id());
            }
        }

        // analyse all trivial functions: if trivial function is called
        // in tight loop, we assume that the parent function is non returning
        let mut checked = AHashSet::new();

        for f in functions.values().filter(|f| {
            !f.blocks().keys().any(|&cid| {
                let blk = &blocks[cid];
                blk.is_call() || blk.is_jump()
            })
        }) {
            let target = blocks[functions[f.id()].entry()].node();
            for source in icfg
                .edges_directed(target, Direction::Incoming)
                .map(|nx| nx.source())
            {
                let cblk = &blocks[icfg[source]];

                if !checked.insert(cblk.id()) {
                    continue;
                }

                let parent = &functions[cblk.function()];
                let cfg = &parent.cfg(icfg, blocks);

                let mut it = cfg.neighbors_directed(cblk.node(), Direction::Incoming);
                let Some(start) = it.next() else { continue };
                if it.next().is_some() {
                    continue;
                };

                if !cfg.edges_directed(start, Direction::Outgoing).count() == 2 {
                    continue;
                }

                if cfg.has_tight_loop_with(start) && self.infinite_loop(project, cfg, start) {
                    Arc::make_mut(&mut self.functions).insert(parent.id());
                }
            }
        }

        Ok(())
    }
}

pub type PropagatedMaybeNonReturning = PropagatedNonReturning<MaybeNonReturning>;

impl NonReturningPropagator for MaybeNonReturning {
    fn non_returning_functions(&self) -> NonReturningFunctions {
        self.functions.clone()
    }
}
