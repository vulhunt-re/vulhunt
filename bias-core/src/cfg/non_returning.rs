use std::collections::{BTreeSet, VecDeque};
use std::ops::Deref;
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use once_cell::sync::OnceCell;
use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use super::cg::CallGraph;
use crate::analyses::functions::MAYBE_NON_RETURNING;
use crate::cfg::FlowKind;
use crate::kb::block::CodeBlock;
use crate::kb::function::FunctionId;
use crate::kb::{uuid, Uuid};
use crate::prelude::{Function, Identifiable, Schedule};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub type NonReturningFunctions = Arc<BTreeSet<FunctionId>>;

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[repr(transparent)]
pub struct PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    functions: NonReturningFunctions,
    _marker: std::marker::PhantomData<T>,
}

pub trait NonReturningPropagator: Clone + Default {
    fn non_returning_functions(&self) -> NonReturningFunctions;
}

pub struct DefaultNonReturningPropagator;

impl<T> PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    pub fn new() -> Self {
        Self {
            functions: Default::default(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn contains(&self, fid: &FunctionId) -> bool {
        self.functions.contains(fid)
    }

    pub fn functions(&self) -> &NonReturningFunctions {
        &self.functions
    }

    fn mark_non_returning_flows(project: &mut Project, fid: FunctionId) {
        let Some(blk) = project.cbtable.get_point(&project.ftable[fid].address()) else {
            return;
        };

        // mark every incoming call edge as tailcall to signal that we are not returning
        let mut override_flows_for = Vec::<(NodeIndex, NodeIndex)>::new();
        for edge in project
            .icfg
            .edges_directed(blk.node(), Direction::Incoming)
            .filter(|edge| edge.weight().is_call())
        {
            override_flows_for.push((edge.source(), edge.target()));
        }

        let mut fall_edges = Vec::<EdgeIndex>::new();
        let mut disconnected_blocks = Vec::new();

        for (source_node, target_node) in override_flows_for {
            project
                .icfg
                .update_edge(source_node, target_node, FlowKind::TailCallBranch);

            let Some(edge) = project
                .icfg
                .edges_directed(source_node, Direction::Outgoing)
                .find(|e| e.weight().is_fall())
            else {
                continue;
            };

            let source = edge.source();
            let target = edge.target();

            let count_in = project
                .icfg
                .edges_directed(target, Direction::Incoming)
                .count();
            let count_out = project
                .icfg
                .edges_directed(target, Direction::Outgoing)
                .count();

            if count_in == 1 && count_out == 0 {
                let target_block = &project.cbtable[project.icfg[target]];
                let source_block = &project.cbtable[project.icfg[source]];
                if source_block.function() == target_block.function() {
                    // we consider a block to be disconnected if it belongs to
                    // the same function as a source block and has no incoming
                    // or outgoing edges after the fall edge is removed
                    disconnected_blocks.push(target_block);
                }
            }

            fall_edges.push(edge.id());
        }

        // remove fall edge for caller block
        for fe in fall_edges {
            let (sx, tx) = project.icfg().edge_endpoints(fe).unwrap();
            let source = &project.code_blocks()[project.icfg()[sx]];
            let target = &project.code_blocks()[project.icfg()[tx]];

            tracing::trace!(
                "removing fall edge from {} to {}",
                source.address(),
                target.address(),
            );

            project.icfg.remove_edge(fe);
        }

        // handle disconnected blocks
        //
        // as part of this logic, we will:
        // 1. remove the disconnected block from the current function
        // 2. create a new function from the disconnected block
        let mut to_update = AHashMap::new();

        for block in disconnected_blocks {
            // remove block from current function
            project.ftable[block.function()]
                .blocks_mut()
                .remove(&block.id());

            // create new function from disconnected block
            project.ftable.insert_with(block.address(), |addr, id| {
                let mut blocks = AHashMap::new();
                blocks.insert(block.id(), block.address());

                let f = Function::new(id, *addr, block.id(), None, blocks);

                tracing::trace!(
                    "adding new function at {} (created from disconnected block)",
                    f.address()
                );

                to_update.insert(f.id(), block.id());

                f
            });
        }

        // 3. update the function ID for all previously disconnected blocks
        for (nfid, bid) in to_update {
            project.cbtable[bid].update_function(nfid);
        }
    }

    fn returning(blk: &CodeBlock) -> bool {
        blk.is_return() || blk.is_indirect_jump()
    }

    fn is_same_scc(
        current: FunctionId,
        child: FunctionId,
        sccgs: &Vec<AHashSet<FunctionId>>,
    ) -> bool {
        sccgs
            .iter()
            .any(|sccg| sccg.contains(&current) && sccg.contains(&child))
    }

    fn is_tail_call_to_returning(
        project: &Project,
        blk: &CodeBlock,
        to_remove: &AHashSet<FunctionId>,
        group: &AHashSet<FunctionId>,
    ) -> bool {
        project
            .icfg
            .edges_directed(blk.node(), Direction::Outgoing)
            .any(|edge| {
                matches!(edge.weight(), FlowKind::TailCallBranch) && {
                    let child = &project.cbtable[project.icfg[edge.target()]].function();
                    to_remove.contains(child) || !group.contains(child)
                }
            })
    }

    fn is_tail_call_to_returning_with(
        project: &Project,
        blk: &CodeBlock,
        non_returning: &BTreeSet<FunctionId>,
        sccgs: &Vec<AHashSet<FunctionId>>,
    ) -> bool {
        project
            .icfg
            .edges_directed(blk.node(), Direction::Outgoing)
            .any(|edge| {
                matches!(edge.weight(), FlowKind::TailCallBranch) && {
                    let child = &project.cbtable[project.icfg[edge.target()]].function();
                    !non_returning.contains(&project.ftable[*child].id())
                        && !Self::is_same_scc(blk.function(), *child, sccgs)
                }
            })
    }

    fn strongly_connected_functions_with(project: &Project) -> Vec<AHashSet<FunctionId>> {
        let cg = CallGraph::new_with_icfg(&project.icfg, &project.ftable, &project.cbtable);

        // get strongly connected functions
        let sccs = cg.scc();

        // collect strongly connected functions with prelimitary
        // filtering of potentially returning functions
        let mut sccgs = Vec::new();

        let mut group = AHashSet::new();
        let mut to_remove = AHashSet::new();
        let mut worklist = Vec::new();

        for scc in sccs {
            group.clear();
            to_remove.clear();
            worklist.clear();

            for f in scc.iter().filter_map(|nx| {
                cg[*nx]
                    .into_function()
                    .and_then(|fid| project.ftable.get(fid))
            }) {
                // keep only functions without returns and indirect jumps
                if f.blocks_with(&project.cbtable).any(Self::returning) {
                    to_remove.insert(f.id());
                } else {
                    group.insert(f.id());
                }
            }

            // if we found the returning functions -- remove all parents from the
            // current group containing the tail call/branch to it
            let mut sccg = group.clone();
            worklist.extend(group.iter().cloned());

            while let Some(fid) = worklist.pop() {
                let f = &project.ftable[fid];
                if f.blocks_with(&project.cbtable)
                    .any(|blk| Self::is_tail_call_to_returning(project, blk, &to_remove, &group))
                {
                    continue;
                }

                if sccg.remove(&fid) {
                    to_remove.insert(fid);
                    for &other_fid in &sccg {
                        worklist.push(other_fid);
                    }
                }
            }

            if sccg.len() > 1 {
                sccgs.push(sccg);
            }
        }

        sccgs
    }
}

impl<T> AsRef<BTreeSet<FunctionId>> for PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    fn as_ref(&self) -> &BTreeSet<FunctionId> {
        &self.functions
    }
}

impl<T> Deref for PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    type Target = BTreeSet<FunctionId>;

    fn deref(&self) -> &Self::Target {
        &self.functions
    }
}

impl<'a, T> IntoIterator for &'a PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    type Item = FunctionId;
    type IntoIter = PropagatedNonReturningIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PropagatedNonReturningIter {
            iter: self.functions.iter(),
        }
    }
}

#[repr(transparent)]
pub struct PropagatedNonReturningIter<'a> {
    iter: std::collections::btree_set::Iter<'a, FunctionId>,
}

impl<'a> Iterator for PropagatedNonReturningIter<'a> {
    type Item = FunctionId;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for PropagatedNonReturningIter<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

pub const PROPAGATED_NON_RETURNING: Uuid = uuid("A68FB62F-CC94-4F6B-B1BD-FBE78AD71467");

impl<T> AnalysisInfo for PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    const NAME: &'static str = "Non-returning functions identification and propagation";
    const UUID: Uuid = PROPAGATED_NON_RETURNING;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[Schedule::PreferAfter(MAYBE_NON_RETURNING)];
}

impl<T> Analysis for PropagatedNonReturning<T>
where
    T: AnalysisInfo + Analysis + NonReturningPropagator,
{
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let functions = match project.try_get_analysis::<T>() {
            Some(a) => a.non_returning_functions(),
            None => {
                let mut a = T::default();
                a.analyse(project)?;
                a.non_returning_functions()
            }
        };

        if functions.is_empty() {
            // nothing to propagate
            return Ok(());
        }

        self.functions = functions;

        // for each known non-returning function, check its callers,
        // if the caller has no returns, but has tail calls to a function
        // that is already known to be non-returning, or to a function in
        // the same SCC group, consider it to be non-returning as well
        let initial = self.functions.clone();
        let mut worklist = self.functions.iter().cloned().collect::<VecDeque<_>>();
        let mut checked = AHashSet::new();

        let sccgs_cell = OnceCell::new();

        while let Some(fid) = worklist.pop_front() {
            if !checked.insert(fid) {
                continue;
            }

            let Some(blk) = project.cbtable.get_point(&project.ftable[fid].address()) else {
                continue;
            };

            // check all parents
            for caller in project
                .icfg
                .edges_directed(blk.node(), Direction::Incoming)
                .filter(|edge| edge.weight().is_call())
            {
                // check that:
                // 1. caller function doesn't have returns or indirect jumps
                // 2. if it has tail calls, it's calling an already known non-returning
                //    function or a function from the same SCC group (obtained earlier)
                let fid = &project.cbtable[project.icfg[caller.source()]].function();
                let f = &project.ftable[*fid];
                if f.blocks_with(&project.cbtable).any(|blk| {
                    Self::returning(blk) || {
                        let sccgs = sccgs_cell
                            .get_or_init(|| Self::strongly_connected_functions_with(project));
                        Self::is_tail_call_to_returning_with(&project, blk, &self.functions, &sccgs)
                    }
                }) {
                    continue;
                }

                // propagate non-returning function
                if Arc::make_mut(&mut self.functions).insert(f.id()) {
                    tracing::trace!("found additional non-returning function: {}", f.address());
                    worklist.push_back(f.id());
                }
            }
        }

        for fid in self.functions.as_ref().difference(initial.as_ref()) {
            project.ftable[*fid].mark_non_returning();
            Self::mark_non_returning_flows(project, *fid);
        }

        Ok(())
    }
}
