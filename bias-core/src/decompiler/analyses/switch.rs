use std::borrow::Cow;

use crate::analyses::blocks::CodeBlockBounds;
use crate::decompiler::analyses::DecompileFunctions;
use crate::decompiler::ast::DecompilerAst;
use crate::decompiler::error::DecompilerError;
use crate::decompiler::{Decompiler, DecompilerConfig};
use crate::prelude::*;

pub const DECOMPILER_SWITCH_TABLE_RECOVERY: Uuid = uuid("7B7B1AB2-97CC-4D95-95B3-C17ED2F136E3");

#[derive(Debug, Clone)]
pub struct DecompilerSwitchTableRecovery {
    config: DecompilerConfig,
}

impl Default for DecompilerSwitchTableRecovery {
    fn default() -> Self {
        Self::new_with(Default::default())
    }
}

impl DecompilerSwitchTableRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(config: DecompilerConfig) -> Self {
        Self { config }
    }

    #[inline]
    fn analyse_function(
        &self,
        icfg: &mut ICFG,
        ftable: &mut FunctionTable,
        cbtable: &mut CodeBlockTable,
        bounds: &CodeBlockBounds,
        candidates: &AHashMap<FunctionId, Cow<DecompilerAst>>,
        merges: &mut AHashSet<FunctionId>,
        fid: FunctionId,
        decompiled: &Cow<DecompilerAst>,
    ) -> Result<(), AnalysisError> {
        if !ftable.contains(fid) {
            return Ok(());
        }

        let mut group = vec![decompiled];
        let mut changed = true;

        while changed {
            changed = false;

            let mut ngroup = Vec::new();

            for table in group.iter().map(|g| g.jump_tables()).flatten() {
                let Some((_, &bid)) = bounds.get(table.branch()) else {
                    continue;
                };

                let blk = &cbtable[bid];

                if icfg
                    .neighbors_directed(blk.node(), Direction::Outgoing)
                    .next()
                    .is_some()
                {
                    continue;
                }

                let call = blk.is_call();

                if blk.function() != fid {
                    if !call {
                        changed |= candidates.contains_key(&blk.function());
                    }
                    continue;
                }

                let blk_node = blk.node();

                for dest in table.entries() {
                    let Some(dest) = cbtable.get_point(dest) else {
                        continue;
                    };

                    let dest_func = dest.function();
                    let dest_node = dest.node();

                    if icfg.contains_edge(blk_node, dest_node) {
                        continue;
                    }

                    if !call && dest_func != fid {
                        ftable.merge_default(cbtable, fid, dest_func);
                        merges.insert(dest_func);

                        if let Some(dest_f) = candidates.get(&dest_func) {
                            ngroup.push(dest_f);
                            changed = true;
                        }
                    }

                    icfg.add_edge(
                        blk_node,
                        dest_node,
                        if call {
                            FlowKind::SwitchCall
                        } else {
                            FlowKind::SwitchBranch
                        },
                    );
                }
            }

            group.extend(ngroup);
        }

        Ok(())
    }
}

impl AnalysisInfo for DecompilerSwitchTableRecovery {
    const NAME: &'static str = "Switch table recovery based on function decompilation";
    const UUID: Uuid = DECOMPILER_SWITCH_TABLE_RECOVERY;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[AnalysisSchedule::dynamic()];
}

#[inline(always)]
fn analysis_error(e: DecompilerError) -> AnalysisError {
    AnalysisError::Analysis(DECOMPILER_SWITCH_TABLE_RECOVERY, Box::new(e))
}

#[inline]
fn is_candidate(icfg: &ICFG, cbtable: &CodeBlockTable, f: &Function) -> bool {
    f.blocks().keys().any(|block| {
        let block = &cbtable[*block];
        let node = block.node();

        let count = icfg.edges_directed(node, Direction::Outgoing).count();
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

impl Analysis for DecompilerSwitchTableRecovery {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut bounds = CodeBlockBounds::default();
        bounds.analyse(project)?;

        let project = project.tables_mut();
        let candidates = if let Some(decompiled) = project.analyses.get_by::<DecompileFunctions>() {
            project
                .ftable
                .values()
                .filter_map(|f| {
                    if is_candidate(project.icfg, project.cbtable, f) {
                        decompiled.get(f.id()).map(|fd| (f.id(), Cow::Borrowed(fd)))
                    } else {
                        None
                    }
                })
                .collect::<AHashMap<_, _>>()
        } else {
            let mut decompiler =
                Decompiler::minimal(project.lifter, project.memory, project.typedb)
                    .map_err(analysis_error)?;
            project
                .ftable
                .values()
                .filter_map(|f| {
                    if is_candidate(project.icfg, project.cbtable, f) {
                        match decompiler.try_decompile_ast(f, self.config.timeout) {
                            Ok(fd) => Some(Ok((f.id(), Cow::Owned(fd)))),
                            Err(e) if self.config.fail_fast => Some(Err(analysis_error(e))),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
                .collect::<Result<AHashMap<_, _>, _>>()?
        };

        let mut merges = AHashSet::new();

        for (fid, decompiled) in candidates.iter() {
            if merges.contains(fid) {
                continue;
            }

            self.analyse_function(
                project.icfg,
                project.ftable,
                project.cbtable,
                &bounds,
                &candidates,
                &mut merges,
                *fid,
                decompiled,
            )?;
        }

        Ok(())
    }
}
