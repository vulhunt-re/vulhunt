use std::collections::VecDeque;
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::sync::Arc;

use ahash::{AHashMap as Map, AHashSet as Set};
use fugue::ir::Address;
use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::dot::{Config, Dot};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{Dfs, EdgeRef, IntoNodeReferences, NodeRef};
use petgraph::EdgeDirection;
use smallvec::SmallVec;

use crate::analyses::graph::traversal::{PostOrderVisitor, PreOrderVisitor, TraversalIterator};
use crate::cfg::flow::FlowKind;
use crate::cfg::{DominanceFrontier, DominatorTree};
use crate::ir::insn::{Insn, InsnChunk};
use crate::ir::traits::*;
use crate::ir::var::{LocalVars, SimpleVar, Var};
use crate::kb::block::{ChunkedCodeBlock, CodeBlock, CodeBlockId, EmptyOrChunkedCodeBlock};
use crate::kb::function::{Function, FunctionId};
use crate::kb::id::Identifiable;
use crate::kb::phi::Phi;
use crate::kb::table::MPointTable;
use crate::lifter::DefaultPrototype;
use crate::Project;

type SSAMapping = Map<SimpleVar, u32>;

#[derive(Clone, Default)]
struct SSAScope(SSAMapping);

impl SSAScope {
    fn new() -> Self {
        Self::default()
    }

    fn current(&self, operand: &SimpleVar) -> Option<u32> {
        self.0.get(operand).copied()
    }

    fn current_mapping(&self) -> impl Iterator<Item = Var> + use<'_> {
        self.0.iter().filter_map(|(var, gen)| {
            if var.is_temporary() {
                None
            } else {
                Some(var.with_generation(*gen))
            }
        })
    }

    fn define(&mut self, mapping: &mut SSAMapping, operand: SimpleVar) -> u32 {
        let generation = *mapping.entry(operand).and_modify(|v| *v += 1).or_insert(1);

        self.0.insert(operand, generation);
        generation
    }
}

struct SSAScopeStack(Vec<SSAScope>);

impl SSAScopeStack {
    fn new() -> (SSAMapping, Self) {
        (SSAMapping::new(), Self(vec![SSAScope::new()]))
    }

    fn push(&mut self, scope: &SSAScope) {
        self.0.push(scope.clone());
    }

    fn pop(&mut self) -> SSAScope {
        self.0.pop().unwrap()
    }
}

pub type SSAReachingDefinitionSet = Set<Var>;
pub type SSAClobberSet = Set<Var>;

#[derive(Clone, Debug)]
pub struct SSAGraph<V> {
    id: FunctionId,
    entry: NodeIndex,
    exit: Option<NodeIndex>, // canonical exit node
    graph: StableDiGraph<V, FlowKind>,
    clobbers: Map<NodeIndex, SSAClobberSet>,
    reaching_pre: Map<NodeIndex, SSAReachingDefinitionSet>,
    reaching_pre_call: Map<NodeIndex, SSAReachingDefinitionSet>,
    reaching_post: Map<NodeIndex, SSAReachingDefinitionSet>,
    dominators: Dominators<NodeIndex>,
    dominator_tree: DominatorTree,
    dominance_frontier: DominanceFrontier,
}

impl<V> Identifiable for SSAGraph<V> {
    type Key = FunctionId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

pub struct SSAGraphDot<'a, V> {
    graph: &'a SSAGraph<V>,
    project: &'a Project,
}

impl<'a, V> fmt::Debug for SSAGraphDot<'a, V>
where
    V: Debug + for<'t> TranslatorDisplay<'t, 't>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl<'a, V> fmt::Display for SSAGraphDot<'a, V>
where
    V: Debug + for<'t> TranslatorDisplay<'t, 't>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let translator = Some(self.project.lifter().translator());
        write!(
            f,
            "{:?}",
            Dot::with_attr_getters(
                self.graph.graph(),
                &[Config::NodeNoLabel],
                &|_, _| String::new(),
                &|_, nr| format!(
                    "shape = box, label = \"{}\\l\"",
                    nr.weight()
                        .display_with(translator)
                        .to_string()
                        .replace("\n", "\\l")
                ),
            )
        )
    }
}

impl<V> SSAGraph<V> {
    pub fn entry(&self) -> NodeIndex {
        self.entry
    }

    pub fn exit(&self) -> Option<NodeIndex> {
        self.exit
    }

    pub fn post_ordered(&self) -> PostOrderVisitor {
        let mut starts = SmallVec::<[NodeIndex; 4]>::new();

        for (node, _) in self.graph.node_references() {
            if self
                .graph
                .neighbors_directed(node, EdgeDirection::Incoming)
                .next()
                .is_none()
            {
                starts.push(node);
            }
        }

        PostOrderVisitor::post_order_with(&self.graph, self.entry, starts.into_iter())
    }

    pub fn rev_post_ordered(&self) -> PostOrderVisitor {
        let mut ends = SmallVec::<[NodeIndex; 4]>::new();

        for (node, _) in self.graph.node_references() {
            if self
                .graph
                .neighbors_directed(node, EdgeDirection::Outgoing)
                .next()
                .is_none()
            {
                ends.push(node);
            }
        }

        let end = ends.pop().unwrap_or(self.entry);

        PostOrderVisitor::post_order_with(&self.graph, end, ends.into_iter())
    }

    pub fn graph(&self) -> &StableDiGraph<V, FlowKind> {
        &self.graph
    }

    pub fn graph_mut(&mut self) -> &mut StableDiGraph<V, FlowKind> {
        &mut self.graph
    }

    pub fn clobbers(&self) -> &Map<NodeIndex, Set<Var>> {
        &self.clobbers
    }

    pub fn clobbers_at(&self, node: NodeIndex) -> Option<&SSAClobberSet> {
        self.clobbers.get(&node)
    }

    pub fn incoming_reaching_definitions_at(
        &self,
        node: NodeIndex,
    ) -> Option<&SSAReachingDefinitionSet> {
        self.reaching_pre.get(&node)
    }

    pub fn outgoing_pre_call_reaching_definitions_at(
        &self,
        node: NodeIndex,
    ) -> Option<&SSAReachingDefinitionSet> {
        self.reaching_pre_call.get(&node)
    }

    pub fn outgoing_reaching_definitions_at(
        &self,
        node: NodeIndex,
    ) -> Option<&SSAReachingDefinitionSet> {
        self.reaching_post
            .get(&node)
            .or_else(|| self.reaching_pre_call.get(&node))
    }

    pub fn dominators(&self) -> &Dominators<NodeIndex> {
        &self.dominators
    }

    pub fn dominator_tree(&self) -> &DominatorTree {
        &self.dominator_tree
    }

    pub fn dominance_frontier(&self) -> &DominanceFrontier {
        &self.dominance_frontier
    }

    pub fn dot<'a>(&'a self, project: &'a Project) -> SSAGraphDot<'a, V> {
        SSAGraphDot {
            graph: self,
            project,
        }
    }
}

pub type SSAGraphTable<V> = MPointTable<Address, SSAGraph<V>>;

#[derive(Debug, Clone, Copy)]
pub struct SSAConfig {
    pub handle_invalid_functions: bool,
    pub filter_unreachable_blocks: bool,
}

impl SSAConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle_invalid_functions(&self) -> bool {
        self.handle_invalid_functions
    }

    pub fn set_handle_invalid_functions(&mut self, handle: bool) {
        self.handle_invalid_functions = handle;
    }

    pub fn with_handle_invalid_functions(mut self, handle: bool) -> Self {
        self.set_handle_invalid_functions(handle);
        self
    }

    pub fn filter_unreachable_blocks(&self) -> bool {
        self.filter_unreachable_blocks
    }

    pub fn set_filter_unreachable_blocks(&mut self, filter: bool) {
        self.filter_unreachable_blocks = filter;
    }

    pub fn with_filter_unreachable_blocks(mut self, filter: bool) -> Self {
        self.set_filter_unreachable_blocks(filter);
        self
    }
}

impl Default for SSAConfig {
    fn default() -> Self {
        Self {
            handle_invalid_functions: false,
            filter_unreachable_blocks: true,
        }
    }
}

pub trait SSA<V> {
    fn ssa(&self, project: &Project) -> SSAGraph<V> {
        self.ssa_with(project, &DefaultSSACallSummariser::new())
    }

    fn ssa_with<'a, T>(&'a self, project: &'a Project, summariser: &T) -> SSAGraph<V>
    where
        T: SSACallSummariser<'a, V> + ?Sized,
    {
        self.ssa_with_config(project, summariser, SSAConfig::default())
    }

    fn ssa_with_config<'a, T>(
        &'a self,
        project: &'a Project,
        summariser: &T,
        config: SSAConfig,
    ) -> SSAGraph<V>
    where
        T: SSACallSummariser<'a, V> + ?Sized;
}

pub trait SSACallSummariser<'a, V> {
    fn apply_clobbers(&self, loc: Address, block: &V, clobbers: &mut SSAClobbers);
}

impl<'a, T, V> SSACallSummariser<'a, V> for Arc<T>
where
    T: SSACallSummariser<'a, V> + ?Sized,
{
    fn apply_clobbers(&self, loc: Address, block: &V, clobbers: &mut SSAClobbers) {
        self.as_ref().apply_clobbers(loc, block, clobbers)
    }
}

impl<'a, T, V> SSACallSummariser<'a, V> for Box<T>
where
    T: SSACallSummariser<'a, V> + ?Sized,
{
    fn apply_clobbers(&self, loc: Address, block: &V, clobbers: &mut SSAClobbers) {
        self.as_ref().apply_clobbers(loc, block, clobbers)
    }
}

impl<'a, T, V> SSACallSummariser<'a, V> for &T
where
    T: SSACallSummariser<'a, V> + ?Sized,
{
    fn apply_clobbers(&self, loc: Address, block: &V, clobbers: &mut SSAClobbers) {
        (*self).apply_clobbers(loc, block, clobbers)
    }
}

#[derive(Default)]
pub struct DefaultSSACallSummariser<V> {
    _marker: PhantomData<V>,
}

impl<V> DefaultSSACallSummariser<V> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<'a, V> SSACallSummariser<'a, V> for DefaultSSACallSummariser<V> {
    #[allow(unused)]
    fn apply_clobbers(&self, address: Address, block: &V, clobbers: &mut SSAClobbers) {}
}

pub struct SSASimpleCallSummariser<'a> {
    clobbers: Map<Address, Set<Var>>,
    resolver: DefaultPrototype,
    project: &'a Project,
}

impl<'a> SSASimpleCallSummariser<'a> {
    pub fn new(project: &'a Project) -> Self {
        Self {
            clobbers: Map::new(),
            resolver: project.lifter().default_prototype(),
            project,
        }
    }

    pub fn add_clobber(&mut self, address: impl Into<Address>, var: Var) {
        self.clobbers.entry(address.into()).or_default().insert(var);
    }

    pub fn add_default_clobbers(&mut self, address: impl Into<Address>) {
        let address = address.into();
        let entry = self.clobbers.entry(address).or_default();
        for var in self.resolver.killed_registers() {
            entry.insert(var);
        }
        for var in self.resolver.output_registers() {
            entry.insert(var);
        }
    }

    pub fn add_output_clobbers(&mut self, address: impl Into<Address>) {
        let address = address.into();
        let entry = self.clobbers.entry(address).or_default();
        for var in self.resolver.output_registers() {
            entry.insert(var);
        }
    }

    pub fn has_clobbers(&self, address: impl Into<Address>) -> bool {
        self.clobbers.contains_key(&address.into())
    }

    pub fn clobbers_for(&self, address: impl Into<Address>) -> Option<&Set<Var>> {
        self.clobbers.get(&address.into())
    }
}

impl<'a> SSACallSummariser<'a, EmptyOrChunkedCodeBlock> for SSASimpleCallSummariser<'a> {
    fn apply_clobbers(
        &self,
        _loc: Address,
        block: &EmptyOrChunkedCodeBlock,
        clobbers: &mut SSAClobbers,
    ) {
        let Some(blk) = block.as_chunked() else {
            // skip empty blocks
            return;
        };

        let Some(target) = blk
            .call_target()
            .map(|fid| self.project.functions()[fid].address())
        else {
            // skip non-call chunks
            return;
        };

        let Some(to_apply) = self.clobbers.get(&target) else {
            // skip if no clobbers for this target
            return;
        };

        for var in to_apply.iter() {
            clobbers.clobber(var);
        }
    }
}

pub struct SSAClobbers<'clobbers, 'vars> {
    defs: Set<SimpleVar>,
    locals: &'clobbers mut LocalVars<'vars>,
}

impl<'clobbers, 'vars> SSAClobbers<'clobbers, 'vars> {
    pub fn clobber(&mut self, var: &Var) {
        self.locals.visit_var(var);
        let var = self.locals.enclosing(var);
        self.defs.insert(var);
    }
}

struct VisitUD<'a, 'v> {
    node: NodeIndex,
    defs: &'a mut Map<SimpleVar, Set<NodeIndex>>,
    free: &'a mut Set<SimpleVar>,
    locals: &'v LocalVars<'v>,
}

impl<'a, 'v> VisitUD<'a, 'v> {
    fn merge_clobbers(&mut self, clobbers: &Set<SimpleVar>) {
        clobbers.iter().for_each(|var| {
            self.defs.entry(*var).or_default().insert(self.node);
        });
    }
}

impl<'a, 'v, 'ir> VisitVars<'ir> for VisitUD<'a, 'v> {
    fn visit_def(&mut self, var: &'ir Var) {
        let def = self.locals.enclosing(var);
        self.defs.entry(def).or_default().insert(self.node);
    }

    fn visit_use(&mut self, var: &'ir Var) {
        let var = self.locals.enclosing(var);
        self.free.insert(var);
    }
}

impl<'a> SSA<InsnChunk<'a>> for &'a Insn {
    #[allow(unused)]
    fn ssa_with_config<'b, T>(
        &'b self,
        project: &'b Project,
        summariser: &T,
        config: SSAConfig,
    ) -> SSAGraph<InsnChunk<'a>>
    where
        T: SSACallSummariser<'b, InsnChunk<'a>> + ?Sized,
    {
        let (root, local) = self.local_cfg();
        let mut g = StableDiGraph::<InsnChunk, FlowKind>::new();
        todo!()
    }
}

impl SSA<EmptyOrChunkedCodeBlock> for Function {
    fn ssa_with_config<'a, T>(
        &'a self,
        project: &'a Project,
        summariser: &T,
        config: SSAConfig,
    ) -> SSAGraph<EmptyOrChunkedCodeBlock>
    where
        T: SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + ?Sized,
    {
        let mut g = StableDiGraph::<EmptyOrChunkedCodeBlock, FlowKind>::new();
        let mut ids = Map::<NodeIndex, NodeIndex>::new();

        let mut locals = LocalVars::new(&project.lifter, self, &project.cbtable);
        let mut clobbers = Map::<NodeIndex, Set<SimpleVar>>::new();

        let icfg = project.icfg();
        let blocks = project.code_blocks();
        let functions = project.functions();

        let (entry, iicfg) = self.iicfg_full(project.icfg(), project.code_blocks());

        for (nx, chunk) in iicfg
            .node_references()
            .map(|(nx, blk)| (nx, ChunkedCodeBlock::from(blk.clone())))
        {
            let mut chunk_clobbers = SSAClobbers {
                defs: Default::default(),
                locals: &mut locals,
            };

            let origin = blocks[chunk.origin()].node();

            let loc = chunk.last_chunk().location().address();
            let mut chunk = EmptyOrChunkedCodeBlock::new_chunked(chunk);

            // add call target to the chunk if applicable
            for e in icfg
                .edges_directed(origin, EdgeDirection::Outgoing)
                .filter(|e| e.weight().is_call())
            {
                let target = blocks[icfg[e.target()]].function();
                chunk.update_call_target(target);
            }

            // get summary of this flow in terms of clobbers
            summariser.apply_clobbers(loc, &chunk, &mut chunk_clobbers);

            // add new node
            let nnx = g.add_node(chunk);

            // associate clobbers with new node
            clobbers.insert(nnx, chunk_clobbers.defs);

            ids.insert(nx, nnx);
        }

        let mut exits = Vec::new();

        for (&old, &new) in ids.iter() {
            let mut is_exit = true;

            for e in iicfg.edges_directed(old, EdgeDirection::Outgoing) {
                if let Some(snew) = ids.get(&e.target()) {
                    g.add_edge(new, *snew, *e.weight());
                    is_exit = false;
                }
            }

            g[new].update_node(new);

            if !is_exit {
                continue;
            }

            let blk = iicfg[old].last().expect("at least one chunk");
            let non_ret = project
                .icfg()
                .edges_directed(blocks[blk.origin].node(), EdgeDirection::Outgoing)
                .any(|tx| {
                    let blk = &blocks[icfg[tx.target()]];
                    let fcn = &functions[blk.function()];

                    fcn.is_non_returning()
                });

            if !non_ret {
                exits.push(new);
            }
        }

        let entry = ids[&entry];
        let exit = if exits.len() > 1 {
            let merge = EmptyOrChunkedCodeBlock::new_empty();
            let mx = g.add_node(merge);
            for exit in exits.iter() {
                g.add_edge(*exit, mx, FlowKind::Return);
            }
            clobbers.insert(mx, Default::default());
            Some(mx)
        } else {
            exits.pop()
        };

        let mut defs = Map::new();
        let mut free = Set::new();

        let dominators = simple_fast(&g, entry);

        let mut dtree = DominatorTree::new();
        let mut dfrontier = DominanceFrontier::new();

        for _ in 0..g.node_count() {
            dtree.add_node(());
        }

        for node in g.node_references() {
            // defined + used
            let mut visitor = VisitUD {
                node: node.id(),
                defs: &mut defs,
                free: &mut free,
                locals: &locals,
            };

            // visit explicit defs and uses
            node.weight().visit_vars_with(&mut visitor, true);

            // merge implicit defs (clobbers) via summarisation
            visitor.merge_clobbers(&clobbers[&node.id()]);

            // build dtree + dfrontier
            let node = node.id();
            if let Some(idom) = dominators.immediate_dominator(node) {
                dtree.add_edge(idom, node, ());
                for p in g.neighbors_directed(node, EdgeDirection::Incoming) {
                    let mut np = p;
                    while np != idom {
                        dfrontier.entry(np).or_default().insert(node);
                        if let Some(np_dom) = dominators.immediate_dominator(np) {
                            np = np_dom;
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        let mut phi_locs = Map::new();
        for (def, blks) in defs.into_iter().filter(|(def, _)| free.contains(&def)) {
            let mut phis = Set::new();
            let mut work = blks.iter().copied().collect::<VecDeque<_>>();

            while let Some(node) = work.pop_front() {
                if let Some(df_nodes) = dfrontier.get(&node) {
                    for df_node in df_nodes.iter() {
                        if phis.contains(df_node) {
                            continue;
                        }

                        let preds = g
                            .neighbors_directed(*df_node, EdgeDirection::Incoming)
                            .collect::<Set<_>>();

                        phi_locs
                            .entry(*df_node)
                            .or_insert_with(Map::new)
                            .entry(def)
                            .or_insert((preds, Set::<Var>::new()));

                        phis.insert(df_node);

                        if !blks.contains(df_node) {
                            work.push_back(*df_node);
                        }
                    }
                }
            }
        }

        let mut ssa_graph = SSAGraph {
            id: self.id(),
            entry,
            exit,
            clobbers: Default::default(),
            reaching_pre: Default::default(),
            reaching_pre_call: Default::default(),
            reaching_post: Default::default(),
            dominators,
            dominator_tree: dtree,
            dominance_frontier: dfrontier,
            graph: g,
        };

        if config.handle_invalid_functions {
            let pre_order = PreOrderVisitor::pre_order(&ssa_graph.dominator_tree, ssa_graph.entry);
            transform_rename(&mut phi_locs, &mut ssa_graph, pre_order, &locals, &clobbers);
        } else {
            let pre_order = Dfs::new(&ssa_graph.dominator_tree, ssa_graph.entry);
            transform_rename(&mut phi_locs, &mut ssa_graph, pre_order, &locals, &clobbers);
        }

        // populate phi assignments for each block
        for (nx, mut phim) in phi_locs.into_iter() {
            let blk = &mut ssa_graph.graph[nx];
            for phi in blk.phis_mut() {
                let (_, ns) = phim.remove(&SimpleVar(*phi.target())).unwrap();
                phi.sources_mut().extend(ns.into_iter());
            }
        }

        if config.filter_unreachable_blocks {
            // filter out unreachable blocks
            ssa_graph
                .graph
                .retain_nodes(|_, nx| ssa_graph.reaching_pre.contains_key(&nx));
        }

        ssa_graph
    }
}

impl SSA<CodeBlock> for Function {
    fn ssa_with_config<'a, T>(
        &'a self,
        project: &'a Project,
        summariser: &T,
        config: SSAConfig,
    ) -> SSAGraph<CodeBlock>
    where
        T: SSACallSummariser<'a, CodeBlock> + ?Sized,
    {
        let mut g = StableDiGraph::<CodeBlock, FlowKind>::new();
        let mut ids = Map::<CodeBlockId, (NodeIndex, NodeIndex)>::new();

        let mut clobbers = Map::<NodeIndex, Set<SimpleVar>>::new();
        let mut locals = LocalVars::new(&project.lifter, self, &project.cbtable);

        for blk in self.blocks_with(project.code_blocks()).cloned() {
            let mut blk_clobbers = SSAClobbers {
                defs: Default::default(),
                locals: &mut locals,
            };

            // get summary of this flow in terms of clobbers
            summariser.apply_clobbers(blk.last_address(), &blk, &mut blk_clobbers);

            // add new node
            let bid = blk.id();
            let nx = blk.node();
            let nnx = g.add_node(blk);

            // associate clobbers with new node
            clobbers.insert(nnx, blk_clobbers.defs);

            ids.insert(bid, (nx, nnx));
        }

        let icfg = project.icfg();

        let mut exits = Vec::new();

        for &(old, new) in ids.values() {
            let mut is_exit = true;
            for e in icfg.edges_directed(old, EdgeDirection::Outgoing) {
                let sid = &icfg[e.target()];
                if let Some(&(_, snew)) = ids.get(sid) {
                    g.add_edge(new, snew, *e.weight());
                    is_exit = false;
                }
            }

            // update node id to SSAgraph
            g.node_weight_mut(new).unwrap().update_node(new);

            if !is_exit {
                continue;
            }

            let non_ret = project
                .icfg()
                .edges_directed(old, EdgeDirection::Outgoing)
                .any(|tx| {
                    let blk = &project.code_blocks()[project.icfg()[tx.target()]];
                    let fcn = &project.functions()[blk.function()];

                    fcn.is_non_returning()
                });

            if !non_ret {
                exits.push(new);
            }
        }

        let entry = ids[&self.entry()].1;
        let exit = if exits.len() > 1 { None } else { exits.pop() };

        let mut defs = Map::new();
        let mut free = Set::new();

        let dominators = simple_fast(&g, entry);

        let mut dtree = DominatorTree::new();
        let mut dfrontier = DominanceFrontier::new();

        for _ in 0..g.node_count() {
            dtree.add_node(());
        }

        for node in g.node_references() {
            // defined + used
            let mut visitor = VisitUD {
                node: node.id(),
                defs: &mut defs,
                free: &mut free,
                locals: &locals,
            };

            // visit explicit defs and uses
            node.weight().visit_vars_with(&mut visitor, true);

            // merge implicit defs (clobbers) via summarisation
            visitor.merge_clobbers(&clobbers[&node.id()]);

            // build dtree + dfrontier
            let node = node.id();
            if let Some(idom) = dominators.immediate_dominator(node) {
                dtree.add_edge(idom, node, ());
                for p in g.neighbors_directed(node, EdgeDirection::Incoming) {
                    let mut np = p;
                    while np != idom {
                        dfrontier.entry(np).or_default().insert(node);
                        if let Some(np_dom) = dominators.immediate_dominator(np) {
                            np = np_dom;
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        let mut phi_locs = Map::new();

        for (def, blks) in defs.into_iter().filter(|(def, _)| free.contains(&def)) {
            let mut phis = Set::new();
            let mut work = blks.iter().copied().collect::<VecDeque<_>>();

            while let Some(node) = work.pop_front() {
                if let Some(df_nodes) = dfrontier.get(&node) {
                    for df_node in df_nodes.iter() {
                        if phis.contains(df_node) {
                            continue;
                        }

                        let preds = g
                            .neighbors_directed(*df_node, EdgeDirection::Incoming)
                            .collect::<Set<_>>();

                        phi_locs
                            .entry(*df_node)
                            .or_insert_with(Map::new)
                            .entry(def)
                            .or_insert((preds, Set::<Var>::new()));

                        phis.insert(df_node);

                        if !blks.contains(df_node) {
                            work.push_back(*df_node);
                        }
                    }
                }
            }
        }

        let mut ssa_graph = SSAGraph {
            id: self.id(),
            entry,
            exit,
            dominators,
            clobbers: Default::default(),
            reaching_pre: Default::default(),
            reaching_pre_call: Default::default(),
            reaching_post: Default::default(),
            dominator_tree: dtree,
            dominance_frontier: dfrontier,
            graph: g,
        };

        if config.handle_invalid_functions {
            let pre_order = PreOrderVisitor::pre_order(&ssa_graph.dominator_tree, ssa_graph.entry);
            transform_rename(&mut phi_locs, &mut ssa_graph, pre_order, &locals, &clobbers);
        } else {
            let pre_order = Dfs::new(&ssa_graph.dominator_tree, ssa_graph.entry);
            transform_rename(&mut phi_locs, &mut ssa_graph, pre_order, &locals, &clobbers);
        }

        // populate phi assignments for each block
        for (nx, mut phim) in phi_locs.into_iter() {
            let blk = &mut ssa_graph.graph[nx];
            for phi in blk.phis_mut() {
                let (_, ns) = phim.remove(&SimpleVar(*phi.target())).unwrap();
                phi.sources_mut().extend(ns.into_iter());
            }
        }

        if config.filter_unreachable_blocks {
            // filter out unreachable blocks
            ssa_graph
                .graph
                .retain_nodes(|_, nx| ssa_graph.reaching_pre.contains_key(&nx));
        }

        ssa_graph
    }
}

struct VarRenamer<'a, 'v> {
    renamer: &'a mut SSAScope,
    mapping: &'a mut SSAMapping,
    locals: &'v LocalVars<'v>,
}

impl<'a, 'v> VisitVarsMut for VarRenamer<'a, 'v> {
    fn visit_def_mut(&mut self, var: &mut Var) {
        let simple = self.locals.enclosing(&*var);
        *var = var.with_generation(self.renamer.define(self.mapping, simple));
    }

    fn visit_use_mut(&mut self, var: &mut Var) {
        let simple = self.locals.enclosing(&*var);
        if let Some(generation) = self.renamer.current(&simple) {
            *var = var.with_generation(generation);
        }
    }
}

fn transform_rename<'v, V, T>(
    phi_locs: &mut Map<NodeIndex, Map<SimpleVar, (Set<NodeIndex>, Set<Var>)>>,
    g: &mut SSAGraph<V>,
    mut pre_order: T,
    locals: &'v LocalVars<'v>,
    clobbers: &Map<NodeIndex, Set<SimpleVar>>,
) where
    V: PhiVarsMut + VisitOpVarsMut,
    T: TraversalIterator<NodeIndex>,
{
    let (mut gmapping, mut ssa_stack) = SSAScopeStack::new();

    while let Some(node) = pre_order.next(&g.dominator_tree) {
        let mut renamer = ssa_stack.pop();

        g.reaching_pre
            .entry(node)
            .or_default()
            .extend(renamer.current_mapping());

        let block = &mut g.graph[node];
        if let Some(phi) = phi_locs.get(&node) {
            for (var, _) in phi.iter() {
                let generation = renamer.define(&mut gmapping, *var);
                let nvar = var.with_generation(generation);
                block.push_phi(Phi::new(nvar, std::iter::empty()));
            }
        }

        block.visit_vars_mut(&mut VarRenamer {
            renamer: &mut renamer,
            mapping: &mut gmapping,
            locals,
        });

        g.reaching_pre_call
            .entry(node)
            .or_default()
            .extend(renamer.current_mapping());

        let mut walker = g
            .graph
            .neighbors_directed(node, EdgeDirection::Outgoing)
            .detach();

        // for the current scope, we now insert implicit defs
        let nclobbers = g.clobbers.entry(node).or_default();

        clobbers[&node].iter().for_each(|var| {
            let generation = renamer.define(&mut gmapping, *var);
            let nvar = var.with_generation(generation);
            nclobbers.insert(nvar);
        });

        // for each variable that could reach this point, we
        // preserve the reaching definitions (post-call)
        if !nclobbers.is_empty() {
            g.reaching_post
                .entry(node)
                .or_default()
                .extend(renamer.current_mapping());
        }

        while let Some((_, succ)) = walker.next(&g.graph) {
            if let Some(phi) = phi_locs.get_mut(&succ) {
                for (var, (_, ns)) in phi
                    .iter_mut()
                    .filter(|(_, (preds, _))| preds.contains(&node))
                {
                    let generation = renamer.current(var).unwrap_or(0);
                    ns.insert(var.with_generation(generation));
                }
            }
        }

        for _ in g
            .dominator_tree
            .neighbors_directed(node, EdgeDirection::Outgoing)
        {
            ssa_stack.push(&renamer);
        }
    }
}
