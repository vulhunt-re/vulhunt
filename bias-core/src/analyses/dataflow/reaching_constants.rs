use std::collections::hash_map::Entry;

use petgraph::visit::{EdgeRef, IntoEdgesDirected, VisitMap, Visitable};
use petgraph::EdgeDirection;

use crate::cfg::non_returning::PROPAGATED_NON_RETURNING;
use crate::prelude::visit::Visit;
use crate::prelude::{AHashMap as Map, AHashSet as Set, *};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};

pub const DATAFLOW_REACHING_CONSTS: uuid::Uuid = uuid("F4D7E42F-31C0-4F7D-A2CF-E8E4F6FCE3E8");
pub const DATAFLOW_REACHING_CONSTS_MAX_BLOCKS: usize = 0x10_000;

struct GenKillBuilder<'a> {
    gen_sets: &'a mut Map<Var, Option<BitVec>>,
    aliases: &'a VarView,
    injections: &'a InjectionManager,
    functions: &'a FunctionTable,
}

impl<'a, 'ir> Visit<'ir> for GenKillBuilder<'a> {
    fn visit_call(
        &mut self,
        target: &'ir Term<BranchTarget>,
        _args: &'ir [Term<Expr>],
        _bits: u32,
    ) {
        let Some(fixup) = target.to_address().and_then(|addr| {
            self.functions.get_point(&addr).and_then(|f| {
                self.injections
                    .get_function_stub(f.id())
                    .and_then(InjectionStub::fixup)
            })
        }) else {
            return;
        };

        for op in fixup.operations() {
            self.visit_stmt(op);
        }
    }

    fn visit_stmt_assign(&mut self, var: &'ir Var, expr: &'ir Term<Expr>) {
        if var.is_temporary() || var.is_address() {
            return;
        }

        let avar = self.aliases.parent(var).unwrap_or(*var);
        let value = expr
            .constant()
            .map(|cst| cst.unsigned_cast(avar.nbits() as usize));

        self.gen_sets.insert(avar, value);
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ReachingConstsConfig {
    pub starts: Set<Address>,
}

impl Default for ReachingConstsConfig {
    fn default() -> Self {
        Self { starts: Set::new() }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct BlockReachingConsts {
    incoming: Map<Var, Option<BitVec>>,
    outgoing: Map<Var, Option<BitVec>>,
}

impl BlockReachingConsts {
    pub fn incoming(&self) -> &Map<Var, Option<BitVec>> {
        &self.incoming
    }

    pub fn incoming_values(&self) -> impl Iterator<Item = (&Var, &BitVec)> {
        self.incoming.iter().filter_map(|(var, val)| {
            if let Some(ref val) = val {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn outgoing(&self) -> &Map<Var, Option<BitVec>> {
        &self.outgoing
    }

    pub fn outgoing_values(&self) -> impl Iterator<Item = (&Var, &BitVec)> {
        self.outgoing.iter().filter_map(|(var, val)| {
            if let Some(ref val) = val {
                Some((var, val))
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct FunctionReachingConsts {
    blocks: Map<CodeBlockId, BlockReachingConsts>,
}

impl FunctionReachingConsts {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &Map<CodeBlockId, BlockReachingConsts> {
        &self.blocks
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct ReachingConsts {
    config: ReachingConstsConfig,
    mapping: Map<FunctionId, FunctionReachingConsts>,
}

impl ReachingConsts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(config: ReachingConstsConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn mapping(&self) -> &Map<FunctionId, FunctionReachingConsts> {
        &self.mapping
    }
}

impl AnalysisInfo for ReachingConsts {
    const NAME: &'static str = "Reaching Constants";
    const UUID: uuid::Uuid = DATAFLOW_REACHING_CONSTS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        // if we run an xref analysis, ensure that this analysis will run before it
        AnalysisSchedule::Before(XREF_ANALYSIS),
        AnalysisSchedule::Before(FOLDED_XREF_ANALYSIS),
        AnalysisSchedule::PreferAfter(PROPAGATED_NON_RETURNING),
    ];
}

impl Analysis for ReachingConsts {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let register_aliases = project.lifter.register_map();

        if !self.config.starts.is_empty() {
            let starts = std::mem::take(&mut self.config.starts);

            for addr in starts.into_iter() {
                if let Some(f) = project.ftable.get_point(&addr) {
                    let mapping =
                        ReachingConstsVisitor::analyse_function(&project, register_aliases, f);
                    self.mapping.insert(f.id(), mapping);
                }
            }
        } else {
            for f in project.ftable.values() {
                let mapping =
                    ReachingConstsVisitor::analyse_function(&project, register_aliases, f);
                self.mapping.insert(f.id(), mapping);
            }
        }

        Ok(())
    }
}

pub struct ReachingConstsVisitor;

impl ReachingConstsVisitor {
    fn incoming_state(
        injections: &InjectionManager,
        aliases: &VarView,
        fid: FunctionId,
        entry: bool,
    ) -> Map<Var, Option<BitVec>> {
        let mut consts = Map::new();
        if entry {
            for (reg, val) in injections
                .global_values()
                .chain(injections.function_values(fid))
                .filter_map(|(opnd, val)| opnd.register().map(|r| (r, val)))
            {
                let avar = aliases.parent(&reg).unwrap_or(reg);
                let value = (reg != avar)
                    .then(|| {
                        let mut val = val.unsigned_cast(avar.nbits() as _);
                        let voff = (reg.offset() - avar.offset()) as u32 * 8;
                        if voff != 0 {
                            val <<= voff;
                        }
                        val
                    })
                    .unwrap_or_else(|| val.to_owned());

                consts.insert(avar, Some(value));
            }
        }
        consts
    }

    pub fn analyse_function(
        project: &Project,
        register_aliases: &VarView,
        f: &Function,
    ) -> FunctionReachingConsts {
        tracing::trace!(
            "analysing function constants for {} / {} blocks",
            f.address(),
            f.blocks().len()
        );

        let mut gkmap = Map::new();
        let functions = project.functions();
        let injections = project.injections();

        for blk in f.blocks_with(project.code_blocks()) {
            let consts = BlockReachingConsts {
                incoming: Self::incoming_state(
                    injections,
                    register_aliases,
                    f.id(),
                    f.entry() == blk.id(),
                ),
                ..Default::default()
            };

            gkmap.insert(blk.id(), consts);
        }

        if gkmap.len() > DATAFLOW_REACHING_CONSTS_MAX_BLOCKS {
            tracing::debug!(
                "function at {} contains > {DATAFLOW_REACHING_CONSTS_MAX_BLOCKS} ({})",
                f.address(),
                gkmap.len()
            );
            return FunctionReachingConsts { blocks: gkmap };
        }

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());
        let mut edge_visitor = cfg.visit_map();

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut nincoming =
                Self::incoming_state(injections, register_aliases, f.id(), f.entry() == blk.id());

            edge_visitor.clear();

            for pred in cfg
                .edges_directed(blk.node(), EdgeDirection::Incoming)
                .filter_map(|e| {
                    if edge_visitor.visit(e.source()) {
                        gkmap.get(&project.icfg()[e.source()])
                    } else {
                        None
                    }
                })
            {
                for (k, v) in pred.outgoing.iter() {
                    match nincoming.entry(*k) {
                        Entry::Occupied(mut e) => {
                            if e.get() != v {
                                e.insert(None);
                            }
                        }
                        Entry::Vacant(e) => {
                            e.insert(v.to_owned());
                        }
                    }
                }
            }

            let mut noutgoing = nincoming.clone();

            let mut builder = GenKillBuilder {
                gen_sets: &mut noutgoing,
                aliases: register_aliases,
                functions,
                injections,
            };

            blk.visit(&mut builder);

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing != current.outgoing;

            current.incoming = nincoming;
            current.outgoing = noutgoing;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionReachingConsts { blocks: gkmap }
    }
}
