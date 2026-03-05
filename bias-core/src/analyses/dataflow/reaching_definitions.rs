use std::collections::VecDeque;
use std::sync::Arc;

use ahash::{AHashMap as Map, AHashSet as Set};
use fixedbitset::FixedBitSet;
use fugue::ir::Address;
use indexmap::IndexMap;
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;

use crate::ir::{Location, Var, VarView, Variable, VarsVisitor, VisitVars};
use crate::kb::block::CodeBlockId;
use crate::kb::function::{Function, FunctionId};
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub const DATAFLOW_REACHING_DEFS: uuid::Uuid = uuid("34E4473B-D4A9-47BA-ABA6-1AD269256925");

#[derive(Clone, Debug)]
pub struct ReachingDefsConfig {
    pub starts: Set<Address>,
    pub assume_no_aliases: bool,
}

impl Default for ReachingDefsConfig {
    fn default() -> Self {
        Self {
            starts: Set::new(),
            assume_no_aliases: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockReachingDefs {
    incoming: FixedBitSet,
    outgoing: FixedBitSet,
}

impl BlockReachingDefs {
    pub fn incoming(&self) -> &FixedBitSet {
        &self.incoming
    }

    pub fn outgoing(&self) -> &FixedBitSet {
        &self.outgoing
    }
}

#[derive(Clone, Debug, Default)]
pub struct FunctionReachingDefs {
    defs: IndexMap<Location, Var>, // actually this is a map of all defs
    blocks: Map<CodeBlockId, BlockReachingDefs>,
    global_aliases: Option<VarView>,
    stack_aliases: Option<VarView>,
}

impl FunctionReachingDefs {
    pub fn defs(&self) -> &IndexMap<Location, Var> {
        &self.defs
    }

    pub fn blocks(&self) -> &Map<CodeBlockId, BlockReachingDefs> {
        &self.blocks
    }

    pub fn global_aliases(&self) -> &Option<VarView> {
        &self.global_aliases
    }

    pub fn stack_aliases(&self) -> &Option<VarView> {
        &self.stack_aliases
    }
}

struct Aliases<'a> {
    global: VarView,
    stack: VarView,
    register: &'a VarView,
}

impl<'a> Aliases<'a> {
    fn alias_for(&self, var: Var) -> Var {
        if var.space() == self.global.space() {
            self.global.parent(&var).unwrap_or(var)
        } else if var.space() == self.stack.space() {
            self.stack.parent(&var).unwrap_or(var)
        } else if var.is_register() {
            self.register.parent(&var).unwrap_or(var)
        } else {
            var
        }
    }
}

struct GKBuilder<'a> {
    gen_sets: &'a mut IndexMap<Location, Var>,
    kill_sets: &'a mut Map<Var, FixedBitSet>,
    aliases: Option<&'a Aliases<'a>>,
}

impl<'a, 'ir> VisitVars<'ir> for GKBuilder<'a> {
    fn visit_def_at(&mut self, current: Location, var: &'ir Var) {
        if var.is_temporary() {
            return;
        }

        let avar = self
            .aliases
            .map(|aliases| aliases.alias_for(*var))
            .unwrap_or(*var);

        self.gen_sets.insert(current, avar);
        self.kill_sets.entry(avar).or_default();
    }
}

struct RDBuilder<'a> {
    gen_sets: &'a IndexMap<Location, Var>,
    kill_sets: &'a Map<Var, FixedBitSet>,
    aliases: Option<&'a Aliases<'a>>,
    rd_set: FixedBitSet,
}

impl<'a, 'ir> VisitVars<'ir> for RDBuilder<'a> {
    fn visit_def_at(&mut self, current: Location, var: &'ir Var) {
        if var.is_temporary() {
            return;
        }

        let avar = self
            .aliases
            .map(|aliases| aliases.alias_for(*var))
            .unwrap_or(*var);

        self.rd_set.difference_with(&self.kill_sets[&avar]);
        self.rd_set
            .insert(self.gen_sets.get_index_of(&current).unwrap());
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReachingDefs {
    config: ReachingDefsConfig,
    mapping: Map<FunctionId, FunctionReachingDefs>,
}

impl ReachingDefs {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(config: ReachingDefsConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn mapping(&self) -> &Map<FunctionId, FunctionReachingDefs> {
        &self.mapping
    }
}

impl AnalysisInfo for ReachingDefs {
    const NAME: &'static str = "Reaching Definitions";
    const UUID: uuid::Uuid = DATAFLOW_REACHING_DEFS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for ReachingDefs {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let register_aliases = if self.config.assume_no_aliases {
            Some(project.lifter.register_map())
        } else {
            None
        };

        if !self.config.starts.is_empty() {
            let starts = std::mem::take(&mut self.config.starts);

            for addr in starts.into_iter() {
                if let Some(f) = project.ftable.get_point(&addr) {
                    let mapping =
                        ReachingDefsVisitor::analyse_function(&project, register_aliases, f);
                    self.mapping.insert(f.id(), mapping);
                }
            }
        } else {
            for f in project.ftable.values() {
                let mapping = ReachingDefsVisitor::analyse_function(&project, register_aliases, f);
                self.mapping.insert(f.id(), mapping);
            }
        }

        Ok(())
    }
}

pub struct ReachingDefsVisitor;

impl ReachingDefsVisitor {
    pub fn analyse_function(
        project: &Project,
        register_aliases: Option<&Arc<VarView>>,
        f: &Function,
    ) -> FunctionReachingDefs {
        let aliases = if let Some(register) = register_aliases {
            let mut global = VarView::new(project.lifter.translator().manager().default_space_id());
            let mut stack = VarView::new(project.lifter.translator().manager().default_space_id());

            let mut adapt = VarsVisitor::new(&mut global);
            f.visit(project.code_blocks(), &mut adapt);

            let mut adapt = VarsVisitor::new(&mut stack);
            f.visit(project.code_blocks(), &mut adapt);

            Some(Aliases {
                global,
                stack,
                register,
            })
        } else {
            None
        };

        let mut gen_sets = Default::default();
        let mut kill_sets = Default::default();

        // build gen/kill information for the whole function
        f.visit(
            project.code_blocks(),
            &mut VarsVisitor::new(&mut GKBuilder {
                gen_sets: &mut gen_sets,
                kill_sets: &mut kill_sets,
                aliases: aliases.as_ref(),
            }),
        );

        let mut gkmap = Map::new();
        let mut worklist = VecDeque::new();

        let rd_len = gen_sets.len();

        // build initial RD sets for each block
        for blk in f.blocks_with(project.code_blocks()) {
            let mut builder = RDBuilder {
                gen_sets: &gen_sets,
                kill_sets: &kill_sets,
                aliases: aliases.as_ref(),
                rd_set: FixedBitSet::with_capacity(rd_len),
            };

            blk.visit(&mut VarsVisitor::new(&mut builder));

            let incoming = FixedBitSet::with_capacity(rd_len);
            let outgoing = builder.rd_set;

            gkmap.insert(blk.id(), BlockReachingDefs { incoming, outgoing });

            worklist.push_back(blk);
        }

        while let Some(blk) = worklist.pop_front() {
            let mut nincoming = FixedBitSet::with_capacity(rd_len);

            for pred in project
                .icfg()
                .edges_directed(blk.node(), EdgeDirection::Incoming)
                .filter_map(|e| gkmap.get(&project.icfg()[e.source()]))
            {
                nincoming.union_with(&pred.outgoing);
            }

            let mut builder = RDBuilder {
                gen_sets: &gen_sets,
                kill_sets: &kill_sets,
                aliases: aliases.as_ref(),
                rd_set: nincoming.clone(),
            };

            blk.visit(&mut VarsVisitor::new(&mut builder));

            let noutgoing = builder.rd_set;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = nincoming != current.incoming || noutgoing != current.outgoing;

            current.incoming = nincoming;
            current.outgoing = noutgoing;

            if did_change {
                for succ in project
                    .icfg()
                    .edges_directed(blk.node(), EdgeDirection::Outgoing)
                    .filter_map(|e| {
                        let succ = project.icfg()[e.target()];
                        if f.blocks().contains_key(&succ) {
                            project.code_blocks().get(succ)
                        } else {
                            None
                        }
                    })
                {
                    worklist.push_back(succ);
                }
            }
        }

        let (global_aliases, stack_aliases) = match aliases {
            Some(aliases) => (Some(aliases.global), Some(aliases.stack)),
            None => (None, None),
        };

        FunctionReachingDefs {
            defs: gen_sets,
            blocks: gkmap,
            global_aliases,
            stack_aliases,
        }
    }
}
