use std::collections::VecDeque;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use fixedbitset::FixedBitSet;
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{IndexType, NodeIndex};
use petgraph::visit::{
    Dfs, DfsPostOrder, GraphRef, IntoNeighborsDirected, IntoNodeIdentifiers, NodeCount, VisitMap,
    Visitable,
};
use petgraph::Direction;

pub trait TraversalOrder<N>
where
    N: IndexType,
{
    fn next<G, E>(state: &mut TraversalState<N, Self>, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        Self: Sized;
}

#[derive(Debug, Clone, Copy)]
pub struct PreOrder;

impl<N> TraversalOrder<N> for PreOrder
where
    N: IndexType,
{
    fn next<G, E>(state: &mut TraversalState<N, Self>, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        'outer: loop {
            while let Some(nx) = state.stack.pop() {
                if state.discovered.visit(nx) && state.finished.visit(nx) {
                    // first discovery of and finalisation
                    // schedule its neighbors for exploration
                    for succ in graph.neighbors_directed(nx, state.direction) {
                        if !state.discovered.is_visited(&succ) {
                            state.stack.push(succ);
                        }
                    }
                    return Some(nx);
                }
            }

            if state.finished.count_ones(..) != graph.node_count() {
                while let Some(cs) = state.starts.pop() {
                    if !state.discovered.is_visited(&cs) {
                        state.stack.push(cs);
                        continue 'outer;
                    }
                }

                // NOTE: if we reach this point, then the whole graph hasn't yet been explored,
                // but we have no viable points to explore from. To get around this, we compute
                // the SCC of the graph, and choose a candidate from each to repopulate starts.
                if !state.finished_exploration {
                    state.starts.extend(
                        kosaraju_scc(graph)
                            .into_iter()
                            .filter_map(|mut scc| scc.pop()),
                    );

                    state.finished_exploration = true;

                    continue 'outer;
                }
            }

            break;
        }

        state.remainder.pop_front()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PostOrder;

impl<N> TraversalOrder<N> for PostOrder
where
    N: IndexType,
{
    fn next<G, E>(state: &mut TraversalState<N, Self>, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        'outer: loop {
            while let Some(&nx) = state.stack.last() {
                if state.discovered.visit(nx) {
                    // First time visiting `nx`: Push neighbors, don't pop `nx`
                    for succ in graph.neighbors_directed(nx, state.direction) {
                        if !state.discovered.is_visited(&succ) {
                            state.stack.push(succ);
                        }
                    }
                } else {
                    state.stack.pop();
                    if state.finished.visit(nx) {
                        // Second time: All reachable nodes must have been finished
                        return Some(nx);
                    }
                }
            }

            if state.finished.count_ones(..) != graph.node_count() {
                while let Some(cs) = state.starts.pop() {
                    if !state.discovered.is_visited(&cs) {
                        state.stack.push(cs);
                        continue 'outer;
                    }
                }

                // NOTE: if we reach this point, then the whole graph hasn't yet been explored,
                // but we have no viable points to explore from. To get around this, we compute
                // the SCC of the graph, and choose a candidate from each to repopulate starts.
                if !state.finished_exploration {
                    state.starts.extend(
                        kosaraju_scc(graph)
                            .into_iter()
                            .filter_map(|mut scc| scc.pop()),
                    );

                    state.finished_exploration = true;

                    continue 'outer;
                }
            }

            break;
        }

        state.remainder.pop_front()
    }
}

#[derive(Clone, Debug)]
pub struct TraversalState<N, O> {
    direction: Direction,
    stack: Vec<N>,
    starts: Vec<N>,
    discovered: FixedBitSet,
    finished: FixedBitSet,
    finished_exploration: bool,
    remainder: VecDeque<N>,
    scratch: FixedBitSet,
    _marker: PhantomData<O>,
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct PostOrderTraversal<N> {
    state: TraversalState<N, PostOrder>,
}

impl<N> AsRef<TraversalState<N, PostOrder>> for PostOrderTraversal<N> {
    fn as_ref(&self) -> &TraversalState<N, PostOrder> {
        &self.state
    }
}

impl<N> AsMut<TraversalState<N, PostOrder>> for PostOrderTraversal<N> {
    fn as_mut(&mut self) -> &mut TraversalState<N, PostOrder> {
        &mut self.state
    }
}

impl<N> Deref for PostOrderTraversal<N> {
    type Target = TraversalState<N, PostOrder>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<N> DerefMut for PostOrderTraversal<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl<N> PostOrderTraversal<N>
where
    N: IndexType,
{
    pub fn empty<G, E>(direction: Direction) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self {
            state: TraversalState::empty::<G, E>(direction),
        }
    }

    pub fn new<G, E>(graph: G, direction: Direction, start: N) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::new_with(graph, direction, start, std::iter::empty())
    }

    pub fn new_with<G, E, I>(graph: G, direction: Direction, start: N, other_starts: I) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        I: Iterator<Item = N>,
    {
        Self {
            state: TraversalState::new_with(graph, direction, start, other_starts),
        }
    }

    #[inline]
    pub fn post_order<G, E>(graph: G, start: N) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::new(graph, Direction::Outgoing, start)
    }

    #[inline]
    pub fn post_order_with<G, E, I>(graph: G, start: N, other_starts: I) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        I: Iterator<Item = N>,
    {
        Self::new_with(graph, Direction::Outgoing, start, other_starts)
    }

    #[inline]
    pub fn rev_post_order<G, E>(graph: G, end: N) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::new(graph, Direction::Incoming, end)
    }

    #[inline]
    pub fn rev_post_order_with<G, E, I>(graph: G, end: N, other_ends: I) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        I: Iterator<Item = N>,
    {
        Self::new_with(graph, Direction::Incoming, end, other_ends)
    }
}

pub type PostOrderVisitor = PostOrderTraversal<NodeIndex>;

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct PreOrderTraversal<N> {
    state: TraversalState<N, PreOrder>,
}

impl<N> AsRef<TraversalState<N, PreOrder>> for PreOrderTraversal<N> {
    fn as_ref(&self) -> &TraversalState<N, PreOrder> {
        &self.state
    }
}

impl<N> AsMut<TraversalState<N, PreOrder>> for PreOrderTraversal<N> {
    fn as_mut(&mut self) -> &mut TraversalState<N, PreOrder> {
        &mut self.state
    }
}

impl<N> Deref for PreOrderTraversal<N> {
    type Target = TraversalState<N, PreOrder>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<N> DerefMut for PreOrderTraversal<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl<N> PreOrderTraversal<N>
where
    N: IndexType,
{
    pub fn empty<G, E>(direction: Direction) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self {
            state: TraversalState::empty::<G, E>(direction),
        }
    }

    pub fn new<G, E>(graph: G, direction: Direction, start: N) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::new_with(graph, direction, start, std::iter::empty())
    }

    pub fn new_with<G, E, I>(graph: G, direction: Direction, start: N, other_starts: I) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        I: Iterator<Item = N>,
    {
        Self {
            state: TraversalState::new_with(graph, direction, start, other_starts),
        }
    }

    #[inline]
    pub fn pre_order<G, E>(graph: G, start: N) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::new(graph, Direction::Outgoing, start)
    }

    #[inline]
    pub fn pre_order_with<G, E, I>(graph: G, start: N, other_starts: I) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        I: Iterator<Item = N>,
    {
        Self::new_with(graph, Direction::Outgoing, start, other_starts)
    }
}

pub type PreOrderVisitor = PreOrderTraversal<NodeIndex>;

impl<N, O> TraversalState<N, O>
where
    N: IndexType,
    O: TraversalOrder<N>,
{
    pub fn empty<G, E>(direction: Direction) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self {
            direction,
            stack: Vec::with_capacity(0),
            starts: Vec::with_capacity(0),
            discovered: FixedBitSet::with_capacity(0),
            finished: FixedBitSet::with_capacity(0),
            finished_exploration: true,
            remainder: VecDeque::with_capacity(0),
            scratch: FixedBitSet::with_capacity(0),
            _marker: PhantomData,
        }
    }

    pub fn new<G, E>(graph: G, direction: Direction, start: N) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::new_with(graph, direction, start, std::iter::empty())
    }

    pub fn new_with<G, E, I>(graph: G, direction: Direction, start: N, other_starts: I) -> Self
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        I: Iterator<Item = N>,
    {
        Self {
            direction,
            stack: vec![start],
            starts: other_starts.into_iter().collect(),
            discovered: graph.visit_map(),
            finished: graph.visit_map(),
            finished_exploration: false,
            remainder: VecDeque::with_capacity(0),
            scratch: graph.visit_map(),
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn next_with<G, E, F, T>(&mut self, graph: G, mut f: F) -> Option<T>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        F: FnMut(G, N) -> Option<T>,
    {
        self.next(graph).and_then(|nx| f(graph, nx))
    }

    #[inline]
    pub fn next_filter_map<G, E, F, T>(&mut self, graph: G, mut f: F) -> Option<T>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        F: FnMut(G, N) -> Option<T>,
    {
        while let Some(nx) = self.next(graph) {
            let t = f(graph, nx);
            if t.is_some() {
                return t;
            }
        }
        None
    }

    #[inline]
    pub fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        O::next(self, graph)
    }

    #[inline]
    pub fn push(&mut self, node: N) {
        self.remainder.push_back(node);
    }

    #[inline]
    pub fn push_neighbors<G, E>(&mut self, graph: G, node: N, direction: Direction)
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        for succ in graph.neighbors_directed(node, direction) {
            self.push(succ)
        }
    }

    #[inline]
    pub fn push_unique_neighbors<G, E>(&mut self, graph: G, node: N, direction: Direction)
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        self.scratch.clear();
        for succ in graph.neighbors_directed(node, direction) {
            if self.scratch.visit(succ) {
                self.push(succ);
            }
        }
    }
}

pub trait TraversalIterator<N>
where
    N: IndexType,
{
    fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>;

    fn next_with<G, E, F, T>(&mut self, graph: G, mut f: F) -> Option<T>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        F: FnMut(G, N) -> Option<T>,
    {
        self.next(graph).and_then(|nx| f(graph, nx))
    }

    fn next_filter_map<G, E, F, T>(&mut self, graph: G, mut f: F) -> Option<T>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
        F: FnMut(G, N) -> Option<T>,
    {
        while let Some(nx) = self.next(graph) {
            let t = f(graph, nx);
            if t.is_some() {
                return t;
            }
        }
        None
    }
}

impl<N, O> TraversalIterator<N> for TraversalState<N, O>
where
    N: IndexType,
    O: TraversalOrder<N>,
{
    fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::next(self, graph)
    }
}

impl<N> TraversalIterator<N> for PreOrderTraversal<N>
where
    N: IndexType,
{
    fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        self.deref_mut().next(graph)
    }
}

impl<N> TraversalIterator<N> for PostOrderTraversal<N>
where
    N: IndexType,
{
    fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        self.deref_mut().next(graph)
    }
}

impl<N> TraversalIterator<N> for Dfs<N, FixedBitSet>
where
    N: IndexType,
{
    fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::next(self, graph)
    }
}

impl<N> TraversalIterator<N> for DfsPostOrder<N, FixedBitSet>
where
    N: IndexType,
{
    fn next<G, E>(&mut self, graph: G) -> Option<N>
    where
        G: GraphRef<EdgeId = E, NodeId = N>
            + IntoNeighborsDirected<NodeId = N, EdgeId = E>
            + IntoNodeIdentifiers<NodeId = N, EdgeId = E>
            + NodeCount
            + Visitable<Map = FixedBitSet, EdgeId = E, NodeId = N>,
    {
        Self::next(self, graph)
    }
}
