use std::collections::VecDeque;

use crate::cfg::ssa::{SSACallSummariser, SSAClobbers, SSASimpleCallSummariser};
use crate::ir::{SimpleVar, VisitVars};
use crate::kb::block::EmptyOrChunkedCodeBlock;
use crate::prelude::*;

use fxhash::FxBuildHasher;
use hashbrown::hash_map::Entry as MapEntry;
use hashbrown::{HashMap, HashSet};

type SimpleVarSet = HashSet<SimpleVar, FxBuildHasher>;
type FunctionSet = HashSet<FunctionId, FxBuildHasher>;
type FunctionClobberMap = HashMap<FunctionId, SimpleVarSet, FxBuildHasher>;
type FunctionCallMap = HashMap<Address, FunctionSet, FxBuildHasher>;

pub struct ClobberedRegisters<'a> {
    functions: FunctionClobberMap,
    calls: FunctionCallMap,
    overrides: SSASimpleCallSummariser<'a>,
    project: &'a Project,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClobberedRegistesTarget {
    #[default]
    Gprs,
    Outputs,
}

impl ClobberedRegistesTarget {
    pub fn is_gprs(&self) -> bool {
        matches!(self, Self::Gprs)
    }

    pub fn is_outputs(&self) -> bool {
        matches!(self, Self::Outputs)
    }

    pub fn vars(&self, lifter: &Lifter) -> SimpleVarSet {
        match self {
            Self::Gprs => lifter
                .arch()
                .gprs(lifter.translator())
                .into_iter()
                .map(SimpleVar::from)
                .collect(),
            Self::Outputs => lifter
                .default_prototype()
                .output_registers()
                .map(SimpleVar::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClobberedRegistersConfig {
    pub target: ClobberedRegistesTarget,
    pub depth: Option<usize>,
    pub use_extern_types: bool,
    pub use_types: bool,
}

impl Default for ClobberedRegistersConfig {
    fn default() -> Self {
        Self {
            target: ClobberedRegistesTarget::Gprs,
            depth: Some(3),
            use_extern_types: true,
            use_types: true,
        }
    }
}

struct FunctionDefVisitor<'a> {
    targets: &'a SimpleVarSet,
    clobbers: SimpleVarSet,
}

impl<'a> FunctionDefVisitor<'a> {
    fn new(targets: &'a SimpleVarSet) -> Self {
        Self {
            targets,
            clobbers: SimpleVarSet::default(),
        }
    }
}

impl<'a> VisitVars<'_> for FunctionDefVisitor<'a> {
    fn visit_def(&mut self, var: &Var) {
        let var = SimpleVar::from(*var);
        if self.targets.contains(&var) {
            self.clobbers.insert(var);
        }
    }
}

impl<'a> FunctionDefVisitor<'a> {
    fn compute_clobbers(project: &Project, gprs: &'a SimpleVarSet, f: &Function, use_types: bool) -> SimpleVarSet {
        tracing::trace!("computing clobbers for function: {} (extern: {})", f.address(), f.is_extern());

        if f.is_extern() || (use_types && project.type_db().get_code_type_at(f.address()).is_some()) {
            let mut clobbers = SimpleVarSet::default();

            let Some(t) = project.type_db().get_code_type_at(f.address()) else {
                return clobbers;
            };

            let Some((args, ret)) = t.function_args().zip(t.function_return()) else {
                return clobbers;
            };

            let lifter = project.lifter();
            let prototype = lifter.default_prototype();

            tracing::trace!("applying clobbers for extern function: {}", f.address());

            if !ret.is_void() {
                if let Some(output) = prototype
                    .output(0)
                    .and_then(|opnd| lifter.prototype_register_var(opnd))
                {
                    clobbers.insert(SimpleVar::from(output));
                }
            }

            for i in args
                .iter()
                .enumerate()
                .filter_map(|(i, arg)| arg.is_output().then_some(i))
            {
                if let Some(input) = prototype
                    .input(i)
                    .and_then(|opnd| lifter.prototype_register_var(opnd))
                {
                    clobbers.insert(SimpleVar::from(input));
                }
            }

            return clobbers;
        }

        let mut visitor = Self::new(gprs);

        for blk in f.blocks_with(project.code_blocks()) {
            blk.visit_vars(&mut visitor);
        }

        visitor.clobbers
    }
}

enum Action {
    Call(FunctionId, usize),
    Merge(FunctionId, FunctionId),
}

impl<'a> ClobberedRegisters<'a> {
    pub fn new(project: &'a Project, start: FunctionId) -> Self {
        Self::new_with(project, start, &ClobberedRegistersConfig::default())
    }

    pub fn new_with(
        project: &'a Project,
        start: FunctionId,
        config: &ClobberedRegistersConfig,
    ) -> Self {
        // We find all functions called from the start function up to a given depth
        // bound, and use the types of externals to propagate clobbers.

        let depth = config.depth.unwrap_or(usize::MAX);
        let targets = config.target.vars(project.lifter());

        let mut functions = FunctionClobberMap::default();
        let mut calls = FunctionCallMap::default();
        let mut merges = FunctionSet::default();

        let mut worklist = VecDeque::new();

        worklist.push_back(Action::Call(start, 0));

        while let Some(action) = worklist.pop_front() {
            match action {
                Action::Call(fid, d) => {
                    let MapEntry::Vacant(entry) = functions.entry(fid) else {
                        // we've already processed this function
                        continue;
                    };

                    let function = &project.functions()[fid];
                    let clobbers = (!function.is_extern() || config.use_extern_types)
                        .then(|| FunctionDefVisitor::compute_clobbers(project, &targets, function, config.use_types))
                        .unwrap_or_default();

                    entry.insert(clobbers);

                    if d > depth {
                        // at depth, we stop processing
                        continue;
                    }

                    for blk in function.blocks_with(project.code_blocks()) {
                        for call in project
                            .icfg()
                            .edges_directed(blk.node(), Direction::Outgoing)
                            .filter(|e| e.weight().is_call())
                        {
                            let db = project.icfg()[call.target()];
                            let df = project.code_blocks()[db].function();

                            calls.entry(blk.last_address()).or_default().insert(df);
                            merges.insert(df);
                            worklist.push_back(Action::Call(df, d + 1));
                        }
                    }

                    // merge from callees to caller
                    worklist.extend(merges.drain().map(|fid2| Action::Merge(fid, fid2)));
                }
                Action::Merge(fid1, fid2) => {
                    if fid1 == fid2 {
                        continue;
                    }

                    let [Some(tgt), Some(src)] = functions.get_many_mut([&fid1, &fid2]) else {
                        // NOTE: since we operate from a given function within the binary, rather
                        // than from the entry point, it's possible that when we trigger a merge,
                        // we will trigger it to callers that are outside of the slice we're
                        // operating on, and hence reach this point. We can safely skip such
                        // merges.
                        continue;
                    };

                    let current_size = tgt.len();

                    tgt.extend(src.iter());

                    if tgt.len() == current_size {
                        continue; // no new clobbers
                    }

                    let function = &project.functions()[fid1];

                    // we need to update all callers of fid1
                    for blk in function.blocks_with(project.code_blocks()) {
                        for call in project
                            .icfg()
                            .edges_directed(blk.node(), Direction::Incoming)
                            .filter(|e| e.weight().is_call())
                        {
                            let sb = project.icfg()[call.source()];
                            let sf = project.code_blocks()[sb].function();

                            // merge from callee to caller
                            worklist.push_back(Action::Merge(sf, fid1));
                        }
                    }
                }
            }
        }

        Self {
            functions,
            calls,
            overrides: SSASimpleCallSummariser::new(project),
            project,
        }
    }

    pub fn clobbers(&self, function: FunctionId) -> Option<&SimpleVarSet> {
        self.functions.get(&function)
    }

    pub fn overrides(&self) -> &SSASimpleCallSummariser<'a> {
        &self.overrides
    }

    pub fn overrides_mut(&mut self) -> &mut SSASimpleCallSummariser<'a> {
        &mut self.overrides
    }
}

impl<'a> SSACallSummariser<'a, EmptyOrChunkedCodeBlock> for ClobberedRegisters<'a> {
    fn apply_clobbers(
        &self,
        loc: Address,
        block: &EmptyOrChunkedCodeBlock,
        clobbers: &mut SSAClobbers,
    ) {
        let Some(fid) = block.call_target() else {
            // this is not a call block, so we can't apply clobbers
            return;
        };

        if let Some(cs) = self
            .overrides()
            .clobbers_for(self.project.functions()[fid].address())
        {
            for c in cs.iter() {
                clobbers.clobber(c);
            }
            // we have clobbers from the override, so we don't need to look further
            return;
        }

        let Some(fcs) = self
            .calls
            .get(&loc)
            .map(|fids| fids.iter().flat_map(|fid| self.functions[fid].iter()))
        else {
            // we resolve the call to the map of functions called from this address
            return;
        };

        for c in fcs {
            clobbers.clobber(&**c);
        }
    }
}
