use ahash::{AHashMap, AHashSet};
pub use petgraph::graph::NodeIndex;
pub use petgraph::stable_graph::StableDiGraph;

pub mod block;
pub mod cg;
pub mod context;
pub mod flow;
pub mod function;
pub mod guided;
pub mod icfg;
pub mod insn;
pub mod non_returning;
pub(crate) mod normalise;
pub mod specs;
pub mod ssa;
pub mod tables;

pub type DominatorTree = StableDiGraph<(), ()>;
pub type DominanceFrontier = AHashMap<NodeIndex, AHashSet<NodeIndex>>;

pub use flow::FlowKind;
pub use guided::{GuidedFunctionEntry, GuidedICFGBuilder};
pub use icfg::{ICFGBuilder, ICFG};
pub use ssa::{SSAGraph, SSA};
