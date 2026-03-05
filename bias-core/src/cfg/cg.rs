use std::collections::BTreeMap;
use std::ops::Deref;

use graph::visit::IntoEdgeReferences;
use petgraph::algo::kosaraju_scc;
use petgraph::prelude::{DiGraph, NodeIndex};

use crate::analyses::graph::traversal::PostOrderVisitor;
use crate::prelude::*;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct CallInfo {
    delta: Option<i64>,
    multiplicity: usize,
}

impl CallInfo {
    #[inline]
    pub fn address_delta(&self) -> Option<i64> {
        self.delta
    }

    #[inline]
    pub fn multiplicity(&self) -> usize {
        self.multiplicity
    }
}

#[derive(Clone)]
pub struct CallGraph {
    graph: DiGraph<FunctionRef, CallInfo>, // delta between source and target and multiplicity
    nodes: BTreeMap<(Option<Address>, FunctionRef), NodeIndex>,
}

impl Default for CallGraph {
    fn default() -> Self {
        Self {
            graph: DiGraph::new(),
            nodes: BTreeMap::new(),
        }
    }
}

impl AsRef<DiGraph<FunctionRef, CallInfo>> for CallGraph {
    fn as_ref(&self) -> &DiGraph<FunctionRef, CallInfo> {
        &self.graph
    }
}

impl Deref for CallGraph {
    type Target = DiGraph<FunctionRef, CallInfo>;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct CallGraphNode {
    id: FunctionRef,
    index: usize,
    incoming_edges: usize,
    outgoing_edges: usize,
}

impl CallGraphNode {
    #[inline]
    pub fn id(&self) -> FunctionRef {
        self.id
    }

    #[inline]
    pub fn index(&self) -> usize {
        self.index
    }

    #[inline]
    pub fn incoming_edges(&self) -> usize {
        self.incoming_edges
    }

    #[inline]
    pub fn outgoing_edges(&self) -> usize {
        self.outgoing_edges
    }

    #[inline]
    pub fn is_external(&self) -> bool {
        self.id.is_external()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct CallGraphEdge {
    source_id: FunctionRef,
    source_index: usize,
    target_id: FunctionRef,
    target_index: usize,
    order_delta: i64,
    address_delta: Option<i64>,
    multiplicity: usize,
}

impl CallGraphEdge {
    #[inline]
    pub fn source_id(&self) -> FunctionRef {
        self.source_id
    }

    #[inline]
    pub fn target_id(&self) -> FunctionRef {
        self.target_id
    }

    #[inline]
    pub fn source_index(&self) -> usize {
        self.source_index
    }

    #[inline]
    pub fn target_index(&self) -> usize {
        self.target_index
    }

    #[inline]
    pub fn order_delta(&self) -> i64 {
        self.order_delta
    }

    #[inline]
    pub fn address_delta(&self) -> Option<i64> {
        self.address_delta
    }

    #[inline]
    pub fn multiplicity(&self) -> usize {
        self.multiplicity
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct CallGraphProperties {
    nodes: Vec<CallGraphNode>,
    edges: Vec<CallGraphEdge>,
}

impl CallGraphProperties {
    #[inline]
    pub fn nodes(&self) -> &[CallGraphNode] {
        &self.nodes
    }

    #[inline]
    pub fn edges(&self) -> &[CallGraphEdge] {
        &self.edges
    }
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_icfg(icfg: &ICFG, ftable: &FunctionTable, cbtable: &CodeBlockTable) -> Self {
        let mut g = Self::new();

        for f in ftable.values() {
            g.get_or_insert(f.id().into(), Some(f.address()));
        }

        for edge in icfg
            .edge_references()
            .filter(|edge| edge.weight().is_call())
        {
            let source = &ftable[cbtable[icfg[edge.source()]].function()];
            let target = &ftable[cbtable[icfg[edge.target()]].function()];

            g.add_call(source, target);
        }

        g
    }

    pub fn new_with(project: &Project) -> Self {
        let icfg = project.icfg();
        let ftable = project.functions();
        let cbtable = project.code_blocks();

        Self::new_with_icfg(icfg, ftable, cbtable)
    }

    pub fn view_with(project: &Project, mut f: impl FnMut(&Function) -> bool) -> Self {
        let icfg = project.icfg();
        let ftable = project.functions();
        let cbtable = project.code_blocks();

        let mut g = Self::new();

        for f in ftable.values().filter(|&fcn| f(fcn)) {
            g.get_or_insert(f.id().into(), Some(f.address()));
        }

        for edge in icfg
            .edge_references()
            .filter(|edge| edge.weight().is_call())
        {
            let source = &ftable[cbtable[icfg[edge.source()]].function()];
            let target = &ftable[cbtable[icfg[edge.target()]].function()];

            if f(source) && f(target) {
                g.add_call(source, target);
            }
        }

        g
    }

    pub fn nodes<'a>(
        &'a self,
    ) -> impl ExactSizeIterator<Item = (NodeIndex, FunctionRef, Option<Address>)> + 'a {
        self.nodes.iter().map(|(&(addr, fid), &nx)| (nx, fid, addr))
    }

    pub fn properties(&self) -> CallGraphProperties {
        let mut order = AHashMap::<NodeIndex, usize>::with_capacity(self.graph.node_count());

        let nodes = self
            .nodes
            .iter()
            .enumerate()
            .map(|(index, (&(_, id), &nx))| {
                order.insert(nx, index);
                CallGraphNode {
                    id,
                    index,
                    incoming_edges: self
                        .graph
                        .edges_directed(nx, Direction::Incoming)
                        .map(|e| e.weight().multiplicity())
                        .sum(),
                    outgoing_edges: self
                        .graph
                        .edges_directed(nx, Direction::Outgoing)
                        .map(|e| e.weight().multiplicity())
                        .sum(),
                }
            })
            .collect();

        let edges = self
            .graph
            .edge_references()
            .map(|edge| {
                let source_index = order[&edge.source()];
                let target_index = order[&edge.target()];

                CallGraphEdge {
                    source_id: self.graph[edge.source()],
                    source_index,
                    target_id: self.graph[edge.target()],
                    target_index,
                    address_delta: edge.weight().address_delta(),
                    order_delta: {
                        let i = source_index;
                        let j = target_index;

                        if i > j {
                            -((i - j) as i64)
                        } else {
                            (j - i) as i64
                        }
                    },
                    multiplicity: edge.weight().multiplicity(),
                }
            })
            .collect();

        CallGraphProperties { nodes, edges }
    }

    #[inline]
    pub fn get(&self, f: &Function) -> Option<NodeIndex> {
        self.nodes.get(&(Some(f.address()), f.id().into())).copied()
    }

    #[inline]
    pub fn get_external(&self, f: Ustr) -> Option<NodeIndex> {
        self.nodes.get(&(None, f.into())).copied()
    }

    #[inline]
    fn get_or_insert(&mut self, fid: FunctionRef, addr: Option<Address>) -> NodeIndex {
        *self
            .nodes
            .entry((addr, fid))
            .or_insert_with(|| self.graph.add_node(fid))
    }

    #[inline]
    fn add_call_aux(
        &mut self,
        from: FunctionRef,
        faddr: Option<Address>,
        to: FunctionRef,
        taddr: Option<Address>,
    ) {
        let f = self.get_or_insert(from, faddr);
        let t = self.get_or_insert(to, taddr);

        if let Some(edge) = self.graph.find_edge(f, t) {
            self.graph[edge].multiplicity += 1;
        } else {
            let diff = faddr.and_then(|faddr| {
                taddr.map(|taddr| {
                    if faddr > taddr {
                        -(usize::from(faddr - taddr) as i64)
                    } else {
                        usize::from(taddr - faddr) as i64
                    }
                })
            });
            self.graph.add_edge(
                f,
                t,
                CallInfo {
                    delta: diff,
                    multiplicity: 1,
                },
            );
        }
    }

    #[inline]
    pub fn add_call(&mut self, from: &Function, to: &Function) {
        self.add_call_aux(
            from.id().into(),
            Some(from.address()),
            to.id().into(),
            Some(to.address()),
        )
    }

    #[inline]
    pub fn add_external_call(&mut self, from: &Function, to: Ustr) {
        self.add_call_aux(from.id().into(), Some(from.address()), to.into(), None)
    }

    #[inline]
    pub fn post_ordered(&self, project: &Project) -> PostOrderVisitor {
        if let Some(entry) = project
            .entry_point()
            .and_then(|addr| project.functions().get_point(addr))
            .and_then(|f| self.get(f))
        {
            let other_starts = self
                .nodes
                .values()
                .filter(|&&node| {
                    node != entry
                        && self
                            .graph
                            .neighbors_directed(node, Direction::Incoming)
                            .count()
                            == 0
                })
                .copied();

            PostOrderVisitor::post_order_with(&self.graph, entry, other_starts)
        } else if let Some(&entry) = self.nodes.values().find(|&&node| {
            self.graph
                .neighbors_directed(node, Direction::Incoming)
                .count()
                == 0
        }) {
            let other_starts = self
                .nodes
                .values()
                .filter(|&&node| {
                    self.graph
                        .neighbors_directed(node, Direction::Incoming)
                        .count()
                        == 0
                })
                .copied();

            PostOrderVisitor::post_order_with(&self.graph, entry, other_starts)
        } else if let Some(&entry) = self.nodes.values().next() {
            PostOrderVisitor::post_order(&self.graph, entry)
        } else {
            PostOrderVisitor::empty::<&DiGraph<FunctionId, CallInfo>, _>(Direction::Outgoing)
        }
    }

    #[inline]
    pub fn rev_post_ordered(&self) -> PostOrderVisitor {
        if let Some(&entry) = self.nodes.values().find(|&&node| {
            self.graph
                .neighbors_directed(node, Direction::Outgoing)
                .count()
                == 0
        }) {
            let other_starts = self
                .nodes
                .values()
                .filter(|&&node| {
                    self.graph
                        .neighbors_directed(node, Direction::Outgoing)
                        .count()
                        == 0
                })
                .copied();

            PostOrderVisitor::rev_post_order_with(&self.graph, entry, other_starts)
        } else if let Some(&entry) = self.nodes.values().next() {
            PostOrderVisitor::rev_post_order(&self.graph, entry)
        } else {
            PostOrderVisitor::empty::<&DiGraph<FunctionId, CallInfo>, _>(Direction::Incoming)
        }
    }

    pub fn remove(&mut self, f: &Function) -> bool {
        let fkv = (Some(f.address()), f.id().into());
        let Some(nx) = self.nodes.remove(&fkv) else {
            return false;
        };
        self.graph.remove_node(nx);
        true
    }

    pub fn remove_external(&mut self, f: Ustr) -> bool {
        let fkv = (None, f.into());
        let Some(nx) = self.nodes.remove(&fkv) else {
            return false;
        };
        self.graph.remove_node(nx);
        true
    }

    pub fn scc(&self) -> Vec<Vec<NodeIndex>> {
        kosaraju_scc(&self.graph)
    }
}
