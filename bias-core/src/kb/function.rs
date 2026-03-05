use std::ops::{Deref, DerefMut, Index, Range};

use ahash::{AHashMap, AHashSet};
use indexmap::IndexSet;
use iset::IntervalSet;
use itertools::Itertools;
use petgraph::algo::dominators::{self, Dominators};
use petgraph::algo::{has_path_connecting, kosaraju_scc, DfsSpace};
use petgraph::graph::NodeIndex;
use petgraph::prelude::DiGraph;
use petgraph::visit::{
    Data, Dfs, EdgeCount, EdgeRef, GraphBase, IntoEdgeReferences, IntoEdges, IntoEdgesDirected,
    IntoNeighbors, IntoNeighborsDirected, IntoNodeIdentifiers, IntoNodeReferences, NodeCount,
    NodeFiltered, Visitable,
};
use petgraph::Direction;
use smallvec::SmallVec;
use ustr::Ustr;

use crate::analyses::graph::traversal::PostOrderVisitor;
use crate::cfg::icfg::{ICFGRepr, ICFG};
use crate::cfg::normalise::VariableAliasNormaliserVisitor;
use crate::cfg::ssa::{SSACallSummariser, SSAGraph, SSA};
use crate::cfg::FlowKind;
use crate::ir::insn::{InsnChunk, InsnChunkBuilder, InsnChunks, InsnTarget, IntraInsnCFG};
use crate::ir::{Address, BitVec, Insn, Location, Stmt, Term, Var, Visit, VisitMut};
use crate::kb::block::{CodeBlock, CodeBlockId, CodeBlockTable, EmptyOrChunkedCodeBlock};
use crate::kb::debug::file_info::SourceFileInfo;
use crate::kb::id::Identifiable;
use crate::kb::table::MPointTable;
use crate::region::Memory;
use crate::{define_mtable_key, Project};

define_mtable_key!(FunctionId, "A36B28D5-AC14-4B40-9F6E-F1EF4504B9E5");

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
    pub struct FunctionInfo: u16 {
        // Generic (lower 8 bits)
        const NON_RETURNING = 0b0000_0000_0000_0001;
        const TAIL          = 0b0000_0000_0000_0010;
        const EXTERN        = 0b0000_0000_0000_0100;

        // Arch-specific (upper 8 bits)
        const TMODE         = 0b0000_0001_0000_0000;
    }
}

impl FunctionInfo {
    pub fn apply(&self, fcn: &mut Function) {
        let properties = fcn.properties | *self;
        fcn.properties = properties;
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Function {
    id: FunctionId,
    address: Address,
    entry: CodeBlockId,
    name: Option<Ustr>,
    blocks: AHashMap<CodeBlockId, Address>,
    properties: FunctionInfo,
    file_info: Option<SourceFileInfo>,
}

impl Default for Function {
    fn default() -> Self {
        Self {
            id: Default::default(),
            address: Address::from(0u32),
            entry: Default::default(),
            name: None,
            blocks: Default::default(),
            properties: FunctionInfo::empty(),
            file_info: None,
        }
    }
}

pub type FunctionCFGRepr<'a> = NodeFiltered<&'a ICFGRepr, Box<dyn Fn(NodeIndex) -> bool + 'a>>;

pub struct FunctionCFG<'a> {
    graph: FunctionCFGRepr<'a>,
    blocks: &'a CodeBlockTable,
    entry: NodeIndex,
    node_count: usize,
}

impl<'a> Deref for FunctionCFG<'a> {
    type Target = FunctionCFGRepr<'a>;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl<'a> DerefMut for FunctionCFG<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

impl<'a> GraphBase for FunctionCFG<'a> {
    type NodeId = <FunctionCFGRepr<'a> as GraphBase>::NodeId;
    type EdgeId = <FunctionCFGRepr<'a> as GraphBase>::EdgeId;
}

impl<'a> Data for FunctionCFG<'a> {
    type NodeWeight = <FunctionCFGRepr<'a> as Data>::NodeWeight;
    type EdgeWeight = <FunctionCFGRepr<'a> as Data>::EdgeWeight;
}

impl<'a, 'g> IntoNodeIdentifiers for &'g FunctionCFG<'a> {
    type NodeIdentifiers = <&'g FunctionCFGRepr<'a> as IntoNodeIdentifiers>::NodeIdentifiers;

    #[inline(always)]
    fn node_identifiers(self) -> Self::NodeIdentifiers {
        self.graph.node_identifiers()
    }
}

impl<'a, 'g> IntoNodeReferences for &'g FunctionCFG<'a> {
    type NodeRef = <&'g FunctionCFGRepr<'a> as IntoNodeReferences>::NodeRef;
    type NodeReferences = <&'g FunctionCFGRepr<'a> as IntoNodeReferences>::NodeReferences;

    #[inline(always)]
    fn node_references(self) -> Self::NodeReferences {
        self.graph.node_references()
    }
}

impl<'a, 'g> IntoNeighbors for &'g FunctionCFG<'a> {
    type Neighbors = <&'g FunctionCFGRepr<'a> as IntoNeighbors>::Neighbors;

    #[inline(always)]
    fn neighbors(self, nx: Self::NodeId) -> Self::Neighbors {
        self.graph.neighbors(nx)
    }
}

impl<'a, 'g> IntoNeighborsDirected for &'g FunctionCFG<'a> {
    type NeighborsDirected = <&'g FunctionCFGRepr<'a> as IntoNeighborsDirected>::NeighborsDirected;

    #[inline(always)]
    fn neighbors_directed(self, nx: Self::NodeId, d: Direction) -> Self::NeighborsDirected {
        self.graph.neighbors_directed(nx, d)
    }
}

impl<'a, 'g> IntoEdgeReferences for &'g FunctionCFG<'a> {
    type EdgeRef = <&'g FunctionCFGRepr<'a> as IntoEdgeReferences>::EdgeRef;
    type EdgeReferences = <&'g FunctionCFGRepr<'a> as IntoEdgeReferences>::EdgeReferences;

    #[inline(always)]
    fn edge_references(self) -> Self::EdgeReferences {
        self.graph.edge_references()
    }
}

impl<'a, 'g> IntoEdges for &'g FunctionCFG<'a> {
    type Edges = <&'g FunctionCFGRepr<'a> as IntoEdges>::Edges;

    #[inline(always)]
    fn edges(self, nx: Self::NodeId) -> Self::Edges {
        self.graph.edges(nx)
    }
}

impl<'a, 'g> IntoEdgesDirected for &'g FunctionCFG<'a> {
    type EdgesDirected = <&'g FunctionCFGRepr<'a> as IntoEdgesDirected>::EdgesDirected;

    #[inline(always)]
    fn edges_directed(self, nx: Self::NodeId, d: Direction) -> Self::EdgesDirected {
        self.graph.edges_directed(nx, d)
    }
}

impl<'a> Index<NodeIndex> for FunctionCFG<'a> {
    type Output = CodeBlockId;

    #[inline(always)]
    fn index(&self, index: NodeIndex) -> &Self::Output {
        &self.graph.0[index]
    }
}

impl<'a> Visitable for FunctionCFG<'a> {
    type Map = <FunctionCFGRepr<'a> as Visitable>::Map;

    #[inline(always)]
    fn visit_map(&self) -> Self::Map {
        self.graph.visit_map()
    }

    #[inline(always)]
    fn reset_map(&self, map: &mut Self::Map) {
        self.graph.reset_map(map)
    }
}

impl<'a> NodeCount for FunctionCFG<'a> {
    #[inline(always)]
    fn node_count(&self) -> usize {
        self.node_count
    }
}

impl<'a> EdgeCount for FunctionCFG<'a> {
    #[inline(always)]
    fn edge_count(&self) -> usize {
        self.graph.edge_references().count()
    }
}

pub type FunctionSCCs = Vec<Vec<NodeIndex>>;

pub struct FunctionDominance<'a> {
    dominators: Dominators<NodeIndex>,
    blocks: &'a CodeBlockTable,
}

impl<'a> FunctionDominance<'a> {
    pub fn dominates(&self, b1: CodeBlockId, b2: CodeBlockId) -> bool {
        let Some(nx1) = self.blocks.get(b1).map(|b| b.node()) else {
            return false;
        };
        let Some(nx2) = self.blocks.get(b2).map(|b| b.node()) else {
            return false;
        };

        let Some(mut doms) = self.dominators.dominators(nx2) else {
            return false;
        };

        doms.contains(&nx1)
    }

    pub fn dominators<'b>(
        &'b self,
        cfg: &'b FunctionCFG<'a>,
        b1: CodeBlockId,
    ) -> impl Iterator<Item = &'a CodeBlock> + 'b {
        let nx = self.blocks.get(b1).map(|b| b.node());

        nx.into_iter()
            .map(|nx| {
                self.dominators
                    .dominators(nx)
                    .into_iter()
                    .map(|dxs| {
                        dxs.map(|dx| {
                            let d = cfg[dx];
                            let block = &self.blocks[d];
                            block
                        })
                    })
                    .flatten()
            })
            .flatten()
    }

    pub fn dominator_with<F>(
        &self,
        cfg: &FunctionCFG<'a>,
        b1: CodeBlockId,
        mut f: F,
    ) -> Option<CodeBlockId>
    where
        F: FnMut(&'a CodeBlock) -> bool,
    {
        let nx = self.blocks.get(b1).map(|b| b.node())?;
        for dom in self.dominators.dominators(nx)? {
            let b2 = cfg[dom];
            let block = &self.blocks[b2];

            if f(block) {
                return Some(b2);
            }
        }
        None
    }
}

impl<'a> FunctionCFG<'a> {
    pub fn new(icfg: &'a ICFG, blocks: &'a CodeBlockTable, f: &Function) -> Self {
        let nodes = f
            .blocks_with(blocks)
            .map(|blk| blk.node())
            .collect::<AHashSet<_>>();

        Self {
            entry: blocks[f.entry()].node(),
            blocks,
            node_count: nodes.len(),
            graph: FunctionCFGRepr::from_fn(icfg.deref(), Box::new(move |nx| nodes.contains(&nx))),
        }
    }

    #[inline]
    pub fn entry(&self) -> NodeIndex {
        self.entry
    }

    pub fn dominators(&self) -> FunctionDominance<'a> {
        FunctionDominance {
            dominators: dominators::simple_fast(self, self.entry),
            blocks: self.blocks,
        }
    }

    #[inline]
    pub fn inside_loop(&self, block: &CodeBlock) -> bool {
        let nx = block.node();

        self.neighbors(nx).any(|ax| nx == ax) || {
            let mut space = DfsSpace::default();
            self.neighbors_directed(nx, Direction::Outgoing)
                .any(|sx| has_path_connecting(&self.graph, nx, sx, Some(&mut space)))
        }
    }

    #[inline]
    pub fn strongly_connected_components(&self) -> FunctionSCCs {
        kosaraju_scc(self)
    }

    #[inline]
    pub fn has_loop_with(&self, sccs: &FunctionSCCs) -> bool {
        sccs.iter()
            .any(|c| c.len() > 1 || (c.len() == 1 && self.neighbors(c[0]).any(|n| n == c[0])))
    }

    #[inline]
    pub fn has_loop(&self) -> bool {
        let sccs = self.strongly_connected_components();
        self.has_loop_with(&sccs)
    }

    pub fn has_tight_loop_with(&self, block: NodeIndex) -> bool {
        let mut head = block;

        loop {
            let mut count = 0;
            let mut edges = self.edges_directed(head, Direction::Incoming);
            let mut nhead = head;

            while let Some(edge) = edges.next() {
                nhead = edge.source();

                if self.0.contains_edge(block, nhead) {
                    return true;
                }

                let mut phead = nhead;
                loop {
                    let mut pedges = self.edges_directed(phead, Direction::Incoming);
                    if let Some(pedge) = pedges.next() {
                        if pedges.next().is_none() {
                            let pphead = pedge.source();
                            if pphead == block {
                                return true;
                            } else if self.edges_directed(pphead, Direction::Outgoing).count() == 1
                            {
                                phead = pphead;
                                continue;
                            }
                        }
                    }
                    break;
                }

                count += 1;
            }

            if count == 1
                && self.edges_directed(nhead, Direction::Outgoing).count() == 1
                && head != nhead
            {
                head = nhead;
            } else {
                return false;
            }
        }
    }

    #[inline]
    pub fn has_tight_loop(&self) -> bool {
        // For each block that has out degree > 1, we simulate merging
        // preceding blocks based on non-strict bounds to find a
        // possible tight loop header, which will have an incoming edge
        // from the block with out degree > 1, if it is contained within
        // a tight loop.

        let mut candidates = Vec::new();

        for block in self.node_identifiers() {
            if self.edges_directed(block, Direction::Outgoing).count() == 2 {
                candidates.push(block);
            }
        }

        candidates
            .iter()
            .any(|&block| self.has_tight_loop_with(block))
    }

    pub fn post_ordered(
        icfg: &'a ICFG,
        blocks: &'a CodeBlockTable,
        f: &Function,
    ) -> (Self, PostOrderVisitor) {
        let mut nodes = AHashSet::with_capacity(f.blocks().len());
        let mut starts = SmallVec::<[NodeIndex; 4]>::new();

        'outer: for blk in f.blocks_with(blocks) {
            let node = blk.node();
            nodes.insert(node);

            let mut count = 0;
            for e in icfg.edges_directed(node, Direction::Incoming) {
                count += 1;

                if e.weight().is_call() {
                    starts.push(node);
                    continue 'outer;
                }
            }

            if count == 0 {
                starts.push(node);
            }
        }

        let cfg = Self {
            entry: blocks[f.entry()].node(),
            blocks,
            node_count: nodes.len(),
            graph: FunctionCFGRepr::from_fn(icfg.deref(), Box::new(move |nx| nodes.contains(&nx))),
        };

        let pot =
            PostOrderVisitor::post_order_with(&cfg, blocks[f.entry].node(), starts.into_iter());

        (cfg, pot)
    }

    pub fn rev_post_ordered(
        icfg: &'a ICFG,
        blocks: &'a CodeBlockTable,
        f: &Function,
    ) -> (Self, PostOrderVisitor) {
        let mut nodes = AHashSet::with_capacity(f.blocks().len());
        let mut ends = SmallVec::<[NodeIndex; 4]>::new();

        'outer: for blk in f.blocks_with(blocks) {
            let node = blk.node();
            nodes.insert(node);

            let mut count = 0;
            for e in icfg.edges_directed(node, Direction::Outgoing) {
                count += 1;

                if e.weight().is_return() {
                    ends.push(node);
                    continue 'outer;
                }
            }

            if count == 0 {
                ends.push(node);
            }
        }

        let end = ends.pop().unwrap_or_else(|| blocks[f.entry].node());

        let cfg = Self {
            entry: blocks[f.entry()].node(),
            blocks,
            node_count: nodes.len(),
            graph: FunctionCFGRepr::from_fn(icfg.deref(), Box::new(move |nx| nodes.contains(&nx))),
        };

        let rpot = PostOrderVisitor::rev_post_order_with(&cfg, end, ends.into_iter());

        (cfg, rpot)
    }
}

#[derive(Clone)]
pub struct FunctionDFG<T> {
    graph: DiGraph<Location, T>,
    nodes: AHashMap<Location, NodeIndex>,
}

impl<T> Default for FunctionDFG<T> {
    fn default() -> Self {
        Self {
            graph: DiGraph::new(),
            nodes: AHashMap::default(),
        }
    }
}

impl<T> FunctionDFG<T> {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn get_or_insert(&mut self, loc: impl Into<Location>) -> NodeIndex {
        *self
            .nodes
            .entry(loc.into())
            .or_insert_with_key(|loc| self.graph.add_node(*loc))
    }

    #[inline]
    pub fn add_dependency(&mut self, from: impl Into<Location>, to: impl Into<Location>, d: T) {
        let f = self.get_or_insert(from);
        let t = self.get_or_insert(to);
        self.graph.add_edge(f, t, d);
    }

    #[inline]
    pub fn dependencies(&self, loc: impl Into<Location>) -> impl Iterator<Item = (&Location, &T)> {
        self.nodes
            .get(&loc.into())
            .map(|&nx| {
                self.graph
                    .edges_directed(nx, Direction::Incoming)
                    .map(|edge| (&self.graph[edge.source()], edge.weight()))
            })
            .into_iter()
            .flatten()
    }

    #[inline]
    pub fn dependents(&self, loc: impl Into<Location>) -> impl Iterator<Item = (&Location, &T)> {
        self.nodes
            .get(&loc.into())
            .map(|&nx| {
                self.graph
                    .edges_directed(nx, Direction::Outgoing)
                    .map(|edge| (&self.graph[edge.target()], edge.weight()))
            })
            .into_iter()
            .flatten()
    }
}

impl<T> AsRef<DiGraph<Location, T>> for FunctionDFG<T> {
    fn as_ref(&self) -> &DiGraph<Location, T> {
        &self.graph
    }
}

impl<T> AsMut<DiGraph<Location, T>> for FunctionDFG<T> {
    fn as_mut(&mut self) -> &mut DiGraph<Location, T> {
        &mut self.graph
    }
}

impl<T> Deref for FunctionDFG<T> {
    type Target = DiGraph<Location, T>;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl<T> DerefMut for FunctionDFG<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

impl Function {
    pub fn new(
        id: FunctionId,
        address: Address,
        entry: CodeBlockId,
        name: Option<Ustr>,
        blocks: AHashMap<CodeBlockId, Address>,
    ) -> Self {
        Self {
            id,
            address,
            entry,
            name,
            blocks,
            properties: FunctionInfo::empty(),
            file_info: None,
        }
    }

    pub fn entry(&self) -> CodeBlockId {
        self.entry
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn update_entry(&mut self, block: CodeBlockId) {
        self.address = self.blocks[&block];
        self.entry = block;
    }

    pub fn name(&self) -> Option<Ustr> {
        self.name
    }

    pub fn update_name<N>(&mut self, name: N)
    where
        N: Into<Ustr>,
    {
        self.name = Some(name.into());
    }

    pub fn source_info(&self) -> Option<&SourceFileInfo> {
        self.file_info.as_ref()
    }

    pub fn update_source_info(&mut self, info: SourceFileInfo) {
        self.file_info = Some(info);
    }

    pub fn is_tail(&self) -> bool {
        self.properties.contains(FunctionInfo::TAIL)
    }

    pub fn mark_tail(&mut self) {
        self.properties |= FunctionInfo::TAIL;
    }

    pub fn set_tail(&mut self, tail: bool) {
        if tail {
            self.properties |= FunctionInfo::TAIL;
        } else {
            self.properties &= !FunctionInfo::TAIL;
        }
    }

    pub fn is_non_returning(&self) -> bool {
        self.properties.contains(FunctionInfo::NON_RETURNING)
    }

    pub fn mark_non_returning(&mut self) {
        self.properties |= FunctionInfo::NON_RETURNING;
    }

    pub fn is_extern(&self) -> bool {
        self.properties.contains(FunctionInfo::EXTERN)
    }

    pub fn mark_extern(&mut self) {
        self.properties |= FunctionInfo::EXTERN;
    }

    pub fn set_extern(&mut self, external: bool) {
        if external {
            self.properties |= FunctionInfo::EXTERN;
        } else {
            self.properties &= !FunctionInfo::EXTERN;
        }
    }

    pub fn is_tmode(&self) -> bool {
        self.properties.contains(FunctionInfo::TMODE)
    }

    pub fn mark_tmode(&mut self) {
        self.properties |= FunctionInfo::TMODE;
    }

    pub fn set_tmode(&mut self, thumb: bool) {
        if thumb {
            self.properties |= FunctionInfo::TMODE;
        } else {
            self.properties &= !FunctionInfo::TMODE;
        }
    }

    pub fn properties(&self) -> FunctionInfo {
        self.properties
    }

    pub fn blocks(&self) -> &AHashMap<CodeBlockId, Address> {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut AHashMap<CodeBlockId, Address> {
        &mut self.blocks
    }

    pub fn blocks_with<'a>(
        &'a self,
        cbtable: &'a CodeBlockTable,
    ) -> impl ExactSizeIterator<Item = &'a CodeBlock> {
        self.blocks.keys().map(|id| &cbtable[*id])
    }

    pub fn for_blocks_mut<F>(&self, cbtable: &mut CodeBlockTable, mut f: F)
    where
        F: FnMut(&Self, &mut CodeBlock),
    {
        self.blocks.keys().for_each(|id| f(self, &mut cbtable[*id]))
    }

    pub fn visit<'a, V>(&self, cbtable: &'a CodeBlockTable, visitor: &mut V)
    where
        V: Visit<'a>,
    {
        for blk in self.blocks.keys().map(|id| &cbtable[*id]) {
            blk.visit(visitor);
        }
    }

    pub fn visit_mut<V>(&self, cbtable: &mut CodeBlockTable, visitor: &mut V)
    where
        V: VisitMut,
    {
        for id in self.blocks.keys() {
            let blk = &mut cbtable[*id];
            blk.visit_mut(visitor);
        }
    }

    pub fn iicfg<'a>(
        &'a self,
        icfg: &'a ICFG,
        blocks: &'a CodeBlockTable,
    ) -> IntraInsnCFG<'a, CodeBlockId> {
        self.iicfg_full(icfg, blocks).1
    }

    pub fn iicfg_full<'a>(
        &'a self,
        icfg: &'a ICFG,
        blocks: &'a CodeBlockTable,
    ) -> (NodeIndex, IntraInsnCFG<'a, CodeBlockId>) {
        #[inline(always)]
        fn splice_block<'b>(
            builder: &mut InsnChunkBuilder,
            block_cfg: &mut IntraInsnCFG<'b, CodeBlockId>,
            block: &'b CodeBlock,
        ) -> (NodeIndex, SmallVec<[(NodeIndex, InsnTarget); 2]>) {
            let mut current_chunk = None;
            let mut current_nx = None;

            let mut entry = None;
            let mut exits = SmallVec::new();

            // NOTE: if outgoing part of a split

            // Process CodeBlock instruction-by-instruction and build InsnChunks
            for insn in block.insns().iter() {
                if !insn.has_local_flow() {
                    let current_chunk = current_chunk.get_or_insert_with(InsnChunks::new);
                    current_chunk.push(InsnChunk::new_with(
                        insn.address(),
                        block.id(),
                        insn.operations(),
                    ));
                    continue;
                }

                // We have insn-local flow
                let (incoming_nx, outgoing) = insn.splice_local_cfg(builder, block.id(), block_cfg);

                if let Some(current_chunk) = current_chunk.take() {
                    // We will start a new chunk
                    let curr_nx = block_cfg.add_node(current_chunk);

                    // We fall from last_nx into curr_nx and last chunk is now current
                    if let Some(last_nx) = current_nx.replace(curr_nx) {
                        if block_cfg[last_nx].should_fall() {
                            block_cfg.add_edge(last_nx, curr_nx, FlowKind::Fall);
                        }
                    }
                }

                entry.get_or_insert(current_nx.unwrap_or(incoming_nx));

                if let Some(current_nx) = current_nx.replace(incoming_nx) {
                    // We fall from current_nx into incoming_nx
                    if block_cfg[current_nx].should_fall() {
                        block_cfg.add_edge(current_nx, incoming_nx, FlowKind::Fall);
                    }
                }

                if !outgoing.is_empty() {
                    // We may have many exits from this chunk
                    exits.extend(insn.branch_targets().into_iter().filter_map(|(ii, t)| {
                        match t {
                            InsnTarget::IntraIns(_, _) | InsnTarget::Intrinsic => None,
                            InsnTarget::IntraBlk(_, true) => {
                                // Emit anyway, since while this fall might remain within the same
                                // block, we may have a branch to the fall address that causes the
                                // block to be split.
                                //
                                let outgoing_nx = outgoing
                                    .iter()
                                    .find_map(|(ie, nx)| if ii == *ie { Some(*nx) } else { None })
                                    .unwrap();

                                current_nx = Some(outgoing_nx);

                                Some((outgoing_nx, t))
                            }
                            _ => Some((
                                outgoing
                                    .iter()
                                    .find_map(|(ie, nx)| if ii == *ie { Some(*nx) } else { None })
                                    .unwrap(),
                                t,
                            )),
                        }
                    }));
                }
            }

            // Process final InsnChunk; (if we end up here, we know that
            // we only have a single exit from this chunk, and it's a fall
            if let Some(current_chunk) = current_chunk.take() {
                let curr_nx = block_cfg.add_node(current_chunk);

                if let Some(last_nx) = current_nx {
                    if block_cfg[last_nx].should_fall() {
                        block_cfg.add_edge(last_nx, curr_nx, FlowKind::Fall);
                    }
                } else {
                    entry.get_or_insert(curr_nx);
                }

                let last_insn = block.insns().last().unwrap();
                let last_oper = last_insn.operations().len();
                let last_targets = last_insn.branch_targets();

                exits.extend(last_targets.into_iter().filter_map(|(i, t)| match t {
                    InsnTarget::IntraIns(_, _) | InsnTarget::Intrinsic => None,
                    _ => (i + 1 == last_oper).then_some((curr_nx, t)),
                }));
            }

            exits.sort();
            exits.dedup();

            (entry.unwrap(), exits)
        }

        let mut block_cfg = IntraInsnCFG::new();
        let mut builder = InsnChunkBuilder::new();

        let mut mapping = AHashMap::new();

        for block in self.blocks_with(blocks) {
            mapping.insert(
                block.node(),
                splice_block(&mut builder, &mut block_cfg, block),
            );
        }

        let entry = mapping[&blocks[self.entry].node()].0;

        for (&bx, (_, iexs)) in mapping.iter() {
            // TODO: Ideally we should track edge claims; this would reduce the chance
            // of spurious edges being added to the ICFG.
            for (a, &isx, &e) in icfg
                .edges_directed(bx, Direction::Outgoing)
                .filter_map(|e| {
                    mapping
                        .get(&e.target())
                        .map(|(isx, _)| (blocks[icfg[e.target()]].address(), isx, e.weight()))
                })
            {
                // Find the right connectors in iexs, and build the connections
                for (iex, kind) in iexs.iter() {
                    // We avoid adding duplicates, where we have each branch from bx duplicated for
                    // each local block by checking edges agree with kinds.
                    if kind.is_fall_to(a) && e.is_fall() {
                        block_cfg.add_edge(*iex, isx, e);
                    } else if kind.is_branch_to_with(a, false) && e.is_branch() {
                        block_cfg.add_edge(*iex, isx, e);
                    } else if kind.is_call_to(a) {
                        // Local (self-)call
                        block_cfg.add_edge(*iex, isx, e);
                    } else if kind.indirect_or_unresolved_branch() {
                        // No local target; treat as switch or indirect
                        block_cfg.add_edge(*iex, isx, e);
                    }
                }
            }
        }

        (entry, block_cfg)
    }

    pub fn cfg<'a>(&self, icfg: &'a ICFG, blocks: &'a CodeBlockTable) -> FunctionCFG<'a> {
        FunctionCFG::new(icfg, blocks, self)
    }

    pub fn ssa_cfg(&self, project: &Project) -> SSAGraph<CodeBlock> {
        SSA::<CodeBlock>::ssa(self, project)
    }

    pub fn ssa_cfg_with<'a>(
        &'a self,
        project: &'a Project,
        summariser: &'a impl SSACallSummariser<'a, CodeBlock>,
    ) -> SSAGraph<CodeBlock> {
        SSA::<CodeBlock>::ssa_with(self, project, summariser)
    }

    pub fn ssa_iicfg(&self, project: &Project) -> SSAGraph<EmptyOrChunkedCodeBlock> {
        SSA::<EmptyOrChunkedCodeBlock>::ssa(self, project)
    }

    pub fn ssa_iicfg_with<'a, T>(
        &'a self,
        project: &'a Project,
        summariser: &T,
    ) -> SSAGraph<EmptyOrChunkedCodeBlock>
    where
        T: SSACallSummariser<'a, EmptyOrChunkedCodeBlock> + ?Sized,
    {
        SSA::<EmptyOrChunkedCodeBlock>::ssa_with(self, project, summariser)
    }

    pub fn post_ordered_visitor<'a>(
        &self,
        icfg: &'a ICFG,
        blocks: &'a CodeBlockTable,
    ) -> (FunctionCFG<'a>, PostOrderVisitor) {
        FunctionCFG::post_ordered(icfg, blocks, self)
    }

    pub fn rev_post_ordered_visitor<'a>(
        &self,
        icfg: &'a ICFG,
        blocks: &'a CodeBlockTable,
    ) -> (FunctionCFG<'a>, PostOrderVisitor) {
        FunctionCFG::rev_post_ordered(icfg, blocks, self)
    }

    pub fn normalised_blocks_with<'a, F>(&'a self, project: &'a Project, f: F)
    where
        F: FnMut(CodeBlock),
    {
        VariableAliasNormaliserVisitor::transform_each(self, project, f);
    }

    pub fn possible_entries<'a>(
        &'a self,
        project: &'a Project,
    ) -> impl Iterator<Item = &'a CodeBlockId> {
        self.blocks.keys().filter(|block| {
            let node = project.cbtable[**block].node();
            let mut count = 0;
            for pred in project.icfg.edges_directed(node, Direction::Incoming) {
                if pred.weight().is_call() {
                    return true;
                }
                count += 1;
            }
            count == 0
        })
    }

    pub fn possible_switch_target<'a>(
        &'a self,
        project: &'a Project,
    ) -> impl Iterator<Item = &'a CodeBlockId> {
        self.blocks.keys().filter(|block| {
            let node = project.cbtable[**block].node();
            project
                .icfg
                .edges_directed(node, Direction::Incoming)
                .next()
                .is_none()
        })
    }

    pub fn possible_unresolved_branches<'a>(
        &'a self,
        project: &'a Project,
    ) -> impl Iterator<Item = &'a CodeBlockId> {
        self.blocks.keys().filter(|block| {
            let block = &project.cbtable[**block];
            let node = block.node();

            let count = project
                .icfg
                .edges_directed(node, Direction::Outgoing)
                .count();
            if count <= 1 {
                for (_, target) in block.branch_targets() {
                    if target.indirect_or_unresolved_branch() {
                        return true;
                    }
                }
            }
            false
        })
    }

    pub fn has_possible_unresolved_branches(&self, project: &Project) -> bool {
        self.blocks.keys().any(|block| {
            let block = &project.cbtable[*block];
            let node = block.node();

            let count = project
                .icfg
                .edges_directed(node, Direction::Outgoing)
                .count();
            if count <= 1 {
                for (_, target) in block.branch_targets() {
                    if target.indirect_or_unresolved_branch() {
                        return true;
                    }
                }
            }
            false
        })
    }

    pub fn bytes<'a>(&self, code_blocks: &CodeBlockTable, memory: &'a Memory) -> &'a [u8] {
        let start = self.address();
        let Some(end) = self
            .blocks()
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| code_blocks[*k].next_address())
        else {
            return Default::default();
        };

        let size = usize::from(end - start);

        memory.view_bytes(start, size).unwrap_or_default()
    }

    pub fn entries<'a>(&'a self, project: &'a Project) -> impl Iterator<Item = CodeBlockId> + 'a {
        // 1. no incoming
        // 2. incoming from something not in this function
        // 3. incoming from this function (if call)
        self.blocks_with(project.code_blocks()).filter_map(|blk| {
            let icfg = project.icfg();
            let blocks = project.code_blocks();
            let mut edge_count = 0;

            for edge in icfg.edges_directed(blk.node(), Direction::Incoming) {
                if edge.weight().is_call() {
                    return Some(blk.id());
                }

                if blocks[icfg[edge.source()]].function() != self.id() {
                    return Some(blk.id());
                }

                edge_count += 1;
            }

            if edge_count == 0 {
                Some(blk.id())
            } else {
                None
            }
        })
    }

    pub fn entries_chunks_with<'a>(
        &'a self,
        icfg: &'a ICFG,
        code_blocks: &'a CodeBlockTable,
    ) -> impl Iterator<Item = CodeBlockId> + 'a {
        // TODO: we should implement a method Function::partition that
        // builds equivalence classes for all blocks

        // This finds entries as above with an additional criteria that we consider
        // internal jump targets to also be entries if they exist in a non-contiguous
        // chunk of memory (see Function::chunks below).
        let chunks = self.chunks(code_blocks);
        let contiguous = chunks.len() == 1;
        let intervals = IntervalSet::from_iter(chunks.into_iter());

        // 1. no incoming
        // 2. incoming from something not in this function
        // 3. incoming from this function (if call)
        // 4. incoming from block not in same contiguous chunk of memory
        self.blocks_with(code_blocks).filter_map(move |blk| {
            let mut edge_count = 0;

            for edge in icfg.edges_directed(blk.node(), Direction::Incoming) {
                if edge.weight().is_call() {
                    return Some(blk.id());
                }

                let sblk = &code_blocks[icfg[edge.source()]];
                if sblk.function() != self.id() {
                    return Some(blk.id());
                }

                if !contiguous {
                    // slt: an envelops function would be ideal here
                    let iv1 = intervals.overlap(blk.address()).next();
                    let iv2 = intervals.overlap(sblk.address()).next();
                    if iv1 != iv2 {
                        return Some(blk.id());
                    }
                }

                edge_count += 1;
            }

            if edge_count == 0 {
                Some(blk.id())
            } else {
                None
            }
        })
    }

    pub fn entries_chunks<'a>(
        &'a self,
        project: &'a Project,
    ) -> impl Iterator<Item = CodeBlockId> + 'a {
        self.entries_chunks_with(project.icfg(), project.code_blocks())
    }

    fn split_with<I>(&self, icfg: &ICFG, blocks: &CodeBlockTable, entries: I) -> Vec<Function>
    where
        I: Iterator<Item = CodeBlockId>,
    {
        let entries = entries.collect::<AHashSet<_>>();

        entries
            .iter()
            .map(|entry| {
                let ffcfg = NodeFiltered::from_fn(icfg.deref(), |nx| {
                    let blk = &icfg[nx];
                    self.blocks.contains_key(blk) && (blk == entry || !entries.contains(blk))
                });

                let eblock = &blocks[*entry];
                let mut visit = Dfs::new(&ffcfg, eblock.node());

                let mut fblocks = AHashMap::new();
                while let Some(bid) = visit.next(&ffcfg) {
                    let blk = &blocks[icfg[bid]];
                    fblocks.insert(blk.id(), blk.address());
                }

                Function::new(self.id(), eblock.address(), *entry, None, fblocks)
            })
            .collect()
    }

    pub fn split(&self, project: &Project) -> Vec<Function> {
        // For each entry, we explore forward within the current function's
        // code blocks.
        //
        // This splits a function into all possible functions that potentially
        // overlap.
        //
        // NOTE: we do not compute new function identities for the new functions,
        // this is because we do not store blocks and blocks may only belong to
        // a single function in our general model. This function allows us to derive
        // views of a function that more strongly corresponds to what IDA Pro's view
        // of functions.
        //
        self.split_with(project.icfg(), project.code_blocks(), self.entries(project))
    }

    pub fn split_chunks(&self, project: &Project) -> Vec<Function> {
        // This splits a function as above with entries computed using
        // Function::entries_chunks. If we have a branch to a block in
        // entries, then we do not include the target block in the
        // current function
        self.split_with(
            project.icfg(),
            project.code_blocks(),
            self.entries_chunks_with(project.icfg(), project.code_blocks()),
        )
    }

    pub fn split_chunks_with(&self, icfg: &ICFG, blocks: &CodeBlockTable) -> Vec<Function> {
        // This splits a function as above with entries computed using
        // Function::entries_chunks. If we have a branch to a block in
        // entries, then we do not include the target block in the
        // current function
        self.split_with(icfg, blocks, self.entries_chunks_with(icfg, blocks))
    }

    pub fn chunks(&self, cbtable: &CodeBlockTable) -> Vec<Range<Address>> {
        let mut chunks = Vec::<Range<Address>>::new();

        for (start, end) in self
            .blocks_with(cbtable)
            .map(|block| (block.address(), block.next_address()))
            .sorted()
        {
            if let Some(last) = chunks.last_mut() {
                if last.contains(&start) || last.end == start {
                    *last = last.start..end;
                } else {
                    chunks.push(start..end);
                }
            } else {
                chunks.push(start..end);
            }
        }

        chunks
    }

    pub fn callers(&self, icfg: &ICFG, blocks: &CodeBlockTable) -> AHashSet<FunctionId> {
        let mut ids = AHashSet::default();
        if let Some(blk) = blocks.get(self.entry()) {
            let node = blk.node();
            ids.extend(
                icfg.edges_directed(node, Direction::Incoming)
                    .filter_map(|edge| {
                        if edge.weight().is_call() {
                            Some(blocks[icfg[edge.source()]].function())
                        } else {
                            None
                        }
                    }),
            );
        }
        ids
    }

    pub fn callers_count(&self, icfg: &ICFG, blocks: &CodeBlockTable) -> usize {
        self.callers(icfg, blocks).len()
    }

    pub fn callees(&self, icfg: &ICFG, blocks: &CodeBlockTable) -> AHashSet<FunctionId> {
        let mut ids = AHashSet::default();
        for blk in self.blocks_with(blocks) {
            let node = blk.node();
            ids.extend(
                icfg.edges_directed(node, Direction::Outgoing)
                    .filter_map(|edge| {
                        if edge.weight().is_call() {
                            Some(blocks[icfg[edge.target()]].function())
                        } else {
                            None
                        }
                    }),
            );
        }
        ids
    }

    pub fn callees_count(&self, icfg: &ICFG, blocks: &CodeBlockTable) -> usize {
        self.callees(icfg, blocks).len()
    }

    pub fn operations(&self, cbtable: &CodeBlockTable) -> Vec<(Location, Term<Stmt>)> {
        let mut ops = self
            .blocks_with(cbtable)
            .map(|blk| {
                blk.insns()
                    .iter()
                    .map(|insn| {
                        let addr = insn.address();
                        insn.operations().iter().enumerate().map(move |(i, op)| {
                            let loc = Location::new(addr, i);
                            (loc, op.clone())
                        })
                    })
                    .flatten()
            })
            .flatten()
            .collect_vec();
        ops.sort_unstable_by_key(|(loc, _)| *loc);
        ops
    }

    pub fn operations_count(&self, cbtable: &CodeBlockTable) -> usize {
        self.blocks_with(cbtable)
            .map(|block| -> usize {
                block
                    .insns()
                    .iter()
                    .map(|insn| insn.operations().len())
                    .sum()
            })
            .sum()
    }

    pub fn insns(&self, blocks: &CodeBlockTable) -> Vec<Term<Insn>> {
        let mut insns = self
            .blocks_with(blocks)
            .map(|blk| blk.insns().iter().cloned())
            .flatten()
            .collect_vec();
        insns.sort_unstable_by_key(|insn| insn.address());
        insns
    }

    pub fn insns_count(&self, blocks: &CodeBlockTable) -> usize {
        self.insns(blocks).len()
    }

    #[inline]
    pub fn constants_into<'ir>(
        &'ir self,
        blocks: &'ir CodeBlockTable,
        into: &mut AHashSet<&'ir BitVec>,
    ) {
        for block in self.blocks_with(blocks) {
            block.constants_into(into)
        }
    }

    pub fn constants<'ir>(&'ir self, blocks: &'ir CodeBlockTable) -> AHashSet<&'ir BitVec> {
        let mut consts = AHashSet::new();
        self.constants_into(blocks, &mut consts);
        consts
    }

    pub fn variables(&self, blocks: &CodeBlockTable) -> IndexSet<Var> {
        struct Collector {
            vars: IndexSet<Var>,
        }

        impl<'ir> Visit<'ir> for Collector {
            fn visit_var(&mut self, var: &'ir Var) {
                self.vars.insert(*var);
            }
        }

        let mut collector = Collector {
            vars: IndexSet::default(),
        };

        self.blocks_with(blocks)
            .for_each(|blk| blk.visit(&mut collector));

        collector.vars
    }

    pub fn variables_count(&self, blocks: &CodeBlockTable) -> usize {
        self.variables(blocks).len()
    }

    pub fn registers_count(&self, blocks: &CodeBlockTable) -> usize {
        self.variables(blocks)
            .into_iter()
            .filter(|var| var.is_register())
            .count()
    }

    pub fn temporaries_count(&self, blocks: &CodeBlockTable) -> usize {
        self.variables(blocks)
            .into_iter()
            .filter(|var| var.is_temporary())
            .count()
    }
}

impl Identifiable for Function {
    type Key = FunctionId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

pub type FunctionTable = MPointTable<Address, Function>;

pub trait FunctionEntryStrategy {
    type T: Copy + Ord;

    fn priority(&mut self, block: CodeBlockId, f: FunctionId) -> Self::T;
    fn entry(&mut self, block: CodeBlockId, f: FunctionId, priority: Self::T) -> Address;

    fn compute_entry(&mut self, f: &Function) -> Option<(CodeBlockId, Address)> {
        let fid = f.id();
        f.blocks()
            .keys()
            .map(|id| (*id, self.priority(*id, fid)))
            .sorted_by_key(|kv| kv.1)
            .next()
            .map(|(id, t)| (id, self.entry(id, fid, t)))
    }
}

struct DefaultEntryStrategy<'a>(&'a mut CodeBlockTable);

impl<'a> FunctionEntryStrategy for DefaultEntryStrategy<'a> {
    type T = ();

    fn priority(&mut self, _block: CodeBlockId, _f: FunctionId) -> Self::T {
        unimplemented!("never used")
    }

    fn entry(&mut self, _block: CodeBlockId, _f: FunctionId, _priority: Self::T) -> Address {
        unimplemented!("never used")
    }

    fn compute_entry(&mut self, f: &Function) -> Option<(CodeBlockId, Address)> {
        f.for_blocks_mut(self.0, |f, blk| {
            blk.update_function(f.id());
        });
        Some((f.entry(), f.address()))
    }
}

impl FunctionTable {
    // merges the two functions; returns (old_address, new_address) if entry changed
    pub fn merge_with<S>(
        &mut self,
        d: FunctionId,
        s: Function,
        mut strategy: S,
    ) -> Option<(Address, Address)>
    where
        S: FunctionEntryStrategy,
    {
        // Find function containing overlap and merge with current
        let ofcn = &mut self[d];

        // Merge blocks
        ofcn.blocks_mut().extend(s.blocks);

        // Update all blocks to belong to original function and recompute
        // entry.
        let (bid, nfentry) = strategy.compute_entry(&ofcn).unwrap();

        // Current entry
        let ofentry = ofcn.address();

        // Update start if changed (also need to update point mapping for d)
        if nfentry != ofentry {
            ofcn.update_entry(bid);
            self.update_point(ofentry, nfentry);
            Some((ofentry, nfentry))
        } else {
            None
        }
    }

    pub fn merge<S>(
        &mut self,
        d: FunctionId,
        s: FunctionId,
        strategy: S,
    ) -> Option<(Address, Address)>
    where
        S: FunctionEntryStrategy,
    {
        if let Some(sf) = self.remove_point(self[s].address()) {
            self.merge_with(d, sf, strategy)
        } else {
            None
        }
    }

    pub fn merge_default(
        &mut self,
        blocks: &mut CodeBlockTable,
        d: FunctionId,
        s: FunctionId,
    ) -> Option<(Address, Address)> {
        self.merge(d, s, DefaultEntryStrategy(blocks))
    }
}
