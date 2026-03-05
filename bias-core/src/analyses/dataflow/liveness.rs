use std::collections::VecDeque;
use std::sync::Arc;

use ahash::{AHashMap as Map, AHashSet as Set};
use fixedbitset::FixedBitSet;
use fugue::ir::Address;
use indexmap::IndexSet;
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;

use crate::ir::{Var, VarView, Variable, VarsVisitor, VisitVars};
use crate::kb::block::CodeBlockId;
use crate::kb::function::{Function, FunctionId};
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub const DATAFLOW_LIVENESS: uuid::Uuid = uuid("BECB2DB1-8F1C-4FC2-ABBA-B66508BEA490");

#[derive(Clone, Debug)]
pub struct LivenessConfig {
    pub starts: Set<Address>,
    pub assume_no_aliases: bool,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            starts: Set::new(),
            assume_no_aliases: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockLiveness {
    incoming: FixedBitSet,
    outgoing: FixedBitSet,
}

impl BlockLiveness {
    pub fn incoming(&self) -> &FixedBitSet {
        &self.incoming
    }

    pub fn outgoing(&self) -> &FixedBitSet {
        &self.outgoing
    }
}

#[derive(Clone, Debug, Default)]
pub struct FunctionLiveness {
    var_set: IndexSet<Var>,
    blocks: Map<CodeBlockId, BlockLiveness>,
    global_aliases: Option<VarView>,
    stack_aliases: Option<VarView>,
}

impl FunctionLiveness {
    pub fn var_set(&self) -> &IndexSet<Var> {
        &self.var_set
    }

    pub fn blocks(&self) -> &Map<CodeBlockId, BlockLiveness> {
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

struct DUBuilder<'a> {
    var_set: &'a mut IndexSet<Var>,
    aliases: Option<&'a Aliases<'a>>,
}

impl<'a, 'ir> VisitVars<'ir> for DUBuilder<'a> {
    fn visit_use(&mut self, var: &'ir Var) {
        if var.is_temporary() {
            return;
        }

        let avar = self
            .aliases
            .map(|aliases| aliases.alias_for(*var))
            .unwrap_or(*var);

        self.var_set.insert(avar);
    }

    fn visit_def(&mut self, var: &'ir Var) {
        if var.is_temporary() {
            return;
        }

        let avar = self
            .aliases
            .map(|aliases| aliases.alias_for(*var))
            .unwrap_or(*var);

        self.var_set.insert(avar);
    }
}

struct LivenessBuilder<'a> {
    var_set: &'a IndexSet<Var>,
    aliases: Option<&'a Aliases<'a>>,
    gen_set: FixedBitSet,
    kill_set: FixedBitSet,
}

impl<'a, 'ir> VisitVars<'ir> for LivenessBuilder<'a> {
    fn visit_def(&mut self, var: &'ir Var) {
        if var.is_temporary() {
            return;
        }

        let avar = self
            .aliases
            .map(|aliases| aliases.alias_for(*var))
            .unwrap_or(*var);

        self.kill_set
            .insert(self.var_set.get_index_of(&avar).unwrap());
    }

    fn visit_use(&mut self, var: &'ir Var) {
        if var.is_temporary() {
            return;
        }

        let avar = self
            .aliases
            .map(|aliases| aliases.alias_for(*var))
            .unwrap_or(*var);

        self.gen_set
            .insert(self.var_set.get_index_of(&avar).unwrap());
    }
}

#[derive(Clone, Debug, Default)]
pub struct Liveness {
    config: LivenessConfig,
    mapping: Map<FunctionId, FunctionLiveness>,
}

impl Liveness {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(config: LivenessConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn mapping(&self) -> &Map<FunctionId, FunctionLiveness> {
        &self.mapping
    }
}

impl AnalysisInfo for Liveness {
    const NAME: &'static str = "Liveness";
    const UUID: uuid::Uuid = DATAFLOW_LIVENESS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for Liveness {
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
                    let mapping = LivenessVisitor::analyse_function(&project, register_aliases, f);
                    self.mapping.insert(f.id(), mapping);
                }
            }
        } else {
            for f in project.ftable.values() {
                let mapping = LivenessVisitor::analyse_function(&project, register_aliases, f);
                self.mapping.insert(f.id(), mapping);
            }
        }

        Ok(())
    }
}

pub struct LivenessVisitor;

impl LivenessVisitor {
    pub fn analyse_function(
        project: &Project,
        register_aliases: Option<&Arc<VarView>>,
        f: &Function,
    ) -> FunctionLiveness {
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

        let mut var_set = Default::default();

        // build def/use information for the whole function
        f.visit(
            project.code_blocks(),
            &mut VarsVisitor::new(&mut DUBuilder {
                var_set: &mut var_set,
                aliases: aliases.as_ref(),
            }),
        );

        let mut dumap = Map::new();
        let mut worklist = VecDeque::new();

        let du_len = var_set.len();
        let mut builder = LivenessBuilder {
            var_set: &var_set,
            aliases: aliases.as_ref(),
            gen_set: FixedBitSet::with_capacity(du_len),
            kill_set: FixedBitSet::with_capacity(du_len),
        };

        // build initial state for each block
        for blk in f.blocks_with(project.code_blocks()) {
            blk.visit(&mut VarsVisitor::new(&mut builder));

            let outgoing = FixedBitSet::with_capacity(du_len);
            let incoming = builder.gen_set.clone();

            dumap.insert(blk.id(), BlockLiveness { incoming, outgoing });

            builder.gen_set.clear();
            builder.kill_set.clear();

            worklist.push_back(blk);
        }

        while let Some(blk) = worklist.pop_front() {
            let mut noutgoing = FixedBitSet::with_capacity(du_len);

            for succ in project
                .icfg()
                .edges_directed(blk.node(), EdgeDirection::Outgoing)
                .filter_map(|e| dumap.get(&project.icfg()[e.target()]))
            {
                noutgoing.union_with(&succ.incoming);
            }

            blk.visit(&mut VarsVisitor::new(&mut builder));

            let mut nincoming = noutgoing.clone();
            nincoming.difference_with(&builder.kill_set);
            nincoming.union_with(&builder.gen_set);

            builder.gen_set.clear();
            builder.kill_set.clear();

            let current = dumap.get_mut(&blk.id()).unwrap();
            let did_change = nincoming != current.incoming || noutgoing != current.outgoing;

            current.incoming = nincoming;
            current.outgoing = noutgoing;

            if did_change {
                for pred in project
                    .icfg()
                    .edges_directed(blk.node(), EdgeDirection::Incoming)
                    .filter_map(|e| {
                        let pred = project.icfg()[e.source()];
                        if f.blocks().contains_key(&pred) {
                            project.code_blocks().get(pred)
                        } else {
                            None
                        }
                    })
                {
                    worklist.push_back(pred);
                }
            }
        }

        let (global_aliases, stack_aliases) = match aliases {
            Some(aliases) => (Some(aliases.global), Some(aliases.stack)),
            None => (None, None),
        };

        FunctionLiveness {
            var_set,
            blocks: dumap,
            global_aliases,
            stack_aliases,
        }
    }
}
