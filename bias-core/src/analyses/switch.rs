use fugue::ir::il::traits::TranslatorDisplay;
use itertools::Itertools;
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;

use super::dataflow::constants::ConstFoldVisitor;
use crate::analyses::dataflow::assumptions::BlockAssumptions;
use crate::cfg::non_returning::PROPAGATED_NON_RETURNING;
use crate::cfg::FlowKind;
use crate::eval::observer::common::{
    OverrideLoadCond, OverrideLoadCtx, OverrideVarCond, OVERRIDE_LOAD,
};
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::{Bound, Configuration, IRContext, ObserverContext};
use crate::ir::expr::rewriter::{ExprRewriter, DEFAULT_RULES};
use crate::ir::{Address, Location};
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub const SWITCH_TABLE_RECOVERY: uuid::Uuid = uuid("B9E9F657-25E2-4E45-891E-C899C862D646");

#[derive(Default)]
pub(crate) struct SwitchBranchObserver {
    destination: Option<Address>,
}

impl SwitchBranchObserver {
    pub(crate) fn destination(&self) -> Option<Address> {
        self.destination
    }
}

impl Observer for SwitchBranchObserver {
    fn restore(&mut self) -> Result<(), ObserverError> {
        self.destination = None;
        Ok(())
    }

    fn observe_pre_branch(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        _location: Location,
        target: Location,
    ) -> Result<(), ObserverError> {
        if target.position() == 0 {
            self.destination = Some(target.address());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SwitchTableRecovery {
    max_table_size: usize,
}

impl Default for SwitchTableRecovery {
    fn default() -> Self {
        Self::new(512)
    }
}

impl SwitchTableRecovery {
    pub fn new(max_table_size: usize) -> Self {
        Self { max_table_size }
    }
}

impl AnalysisInfo for SwitchTableRecovery {
    const NAME: &'static str = "Switch Table Recovery";
    const UUID: uuid::Uuid = SWITCH_TABLE_RECOVERY;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::PreferAfter(PROPAGATED_NON_RETURNING)];
}

impl Analysis for SwitchTableRecovery {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut eval = project
            .evaluator(Configuration {
                enable_restores: true,
                ignore_invalid_accesses: true,
                ignore_unimplemented_ops: true,
                ..Default::default()
            })
            .unwrap();
        let mut simplifier = ExprRewriter::default();

        let switch_observer = eval.register_observer(SwitchBranchObserver::default());
        let loado_observer = eval.register_observer(OverrideLoadCond::default());
        let varo_observer = eval.register_observer(OverrideVarCond::default());

        let mut observer_ctx = ObserverContext::default();
        observer_ctx.set(OVERRIDE_LOAD, OverrideLoadCtx::new(&project.lifter));

        let mut wl = project
            .ftable
            .values()
            .filter_map(|f| {
                let fid = f.id();
                if f.has_possible_unresolved_branches(project) {
                    Some(fid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        while let Some(fid) = wl.pop() {
            let f = match project.ftable.get(fid) {
                Some(f) => f,
                None => continue,
            };

            tracing::info!("analysing function at {}", f.address());

            let unresolved = f
                .possible_unresolved_branches(project)
                .cloned()
                .collect_vec();

            tracing::info!("{} unresolved branches identified", unresolved.len());

            // In this case, we have some blocks that have unresolved outgoing edges.
            //
            // We first construct a set of reaching constants for each block using
            // intra-procedural constant folding. This is an optimistic analysis in that
            // it assumes that callees do not clobber constant assignments.
            //
            // Next, we compute the range of the switch table's index by analysing the
            // assumptions of the predecessor blocks to our suspected switch block.
            //
            // Finally, we fold constants forward to determine the link for each index
            // of our switch table.
            //

            let consts = ConstFoldVisitor::analyse_function(project, &Default::default(), f);

            'outer: for (bid, cs) in unresolved
                .into_iter()
                .filter_map(|bid| consts.get(&bid).map(|cs| (bid, cs)))
            {
                let mut assume = BlockAssumptions::default();

                // find incoming blocks for assumptions about current block
                let mut cond = None;
                let blk = &project.cbtable[bid];
                let blk_addr = blk.address();
                let blk_last_addr = blk.last_address();
                let blk_func = blk.function();
                let blk_node = blk.node();

                for pred in project
                    .icfg
                    .edges_directed(blk.node(), EdgeDirection::Incoming)
                {
                    if !(pred.weight().is_fall() || pred.weight().is_conditional()) {
                        continue 'outer;
                    }

                    let f = &project.ftable[fid];
                    let pblk = &project.cbtable[project.icfg[pred.source()]];
                    if !f.blocks().contains_key(&pblk.id()) {
                        continue 'outer;
                    }

                    let mut starts = pblk.address();

                    tracing::trace!("analysing block: {starts}");

                    if let Some((saddr, addr, nvar, ncond)) = assume.analyse_condition_bb_with(
                        pblk.insns().iter(),
                        pred.weight().is_fall(),
                        |expr| simplifier.simplify_expr(&expr, &*DEFAULT_RULES),
                    ) {
                        tracing::trace!("variable originates from: {:?}", addr);
                        if let Some(nstarts) = addr {
                            starts = nstarts.max(starts);
                        } else {
                            starts = saddr.max(starts);
                        }
                        cond = match cond {
                            None => Some((starts, nvar, ncond)),
                            Some((_, ovar, ocond)) => {
                                if ovar == nvar {
                                    Some((starts, ovar, ocond.union(&ncond)))
                                } else {
                                    // on clash: this cannot be the bound?
                                    None
                                }
                            }
                        };
                    }
                }

                let (nstart, cond_var, mv, va, cond_vals) = match cond {
                    Some((start, var, vals)) => {
                        let it = vals.iter();
                        let hint = it.size_hint().1;

                        if hint.is_none()
                            || matches!(hint, Some(v) if v <= 1 || v > self.max_table_size)
                        {
                            tracing::debug!(
                                "skipping switch as table size estimate exceeds {} or is <= 1",
                                self.max_table_size
                            );
                            continue;
                        } else {
                            let mv = if let Some((expr, bits)) = assume.memory_expr(&var) {
                                tracing::trace!("table bound is via memory load");
                                Some((expr.clone(), bits))
                            } else {
                                None
                            };

                            tracing::info!(
                                "switch bound estimated to be {vals} for {}",
                                var.display_with(Some(project.lifter.translator()))
                            );
                            (start, var, mv, false, it)
                        }
                    }
                    // find the load, scan backwards from there
                    None => {
                        if let Some((start, var, vals)) = assume
                            .analyse_implicit_condition_bb_with(blk.insns().iter(), |expr| {
                                simplifier.simplify_expr(&expr, &*DEFAULT_RULES)
                            })
                        {
                            let it = vals.iter();
                            let hint = it.size_hint().1;

                            if hint.is_none()
                                || matches!(hint, Some(v) if v <= 1 || v > self.max_table_size)
                            {
                                tracing::debug!(
                                    "skipping switch as table size estimate exceeds {} or is <= 1",
                                    self.max_table_size
                                );
                                continue;
                            } else {
                                (start, var, None, true, it)
                            }
                        } else {
                            continue;
                        }
                    }
                };

                // collect all constants to be set on each iteration
                let constants = cs
                    .incoming()
                    .iter()
                    .filter_map(|(c, bv)| bv.as_ref().map(|bv| (c, bv)))
                    .collect::<Vec<_>>();

                for init in cond_vals {
                    if let Some((expr, bits)) = &mv {
                        tracing::trace!(
                            "overriding load via {} with {:x}",
                            expr.display_with(Some(project.lifter.translator())),
                            init
                        );

                        let obs = eval
                            .get_observer_mut::<OverrideLoadCond>(loado_observer)
                            .unwrap();

                        obs.enable(expr.clone(), *bits, init.clone());
                    } else if !va {
                        tracing::trace!(
                            "setting {} to {:x}",
                            cond_var.display_with(Some(project.lifter.translator())),
                            init
                        );

                        eval.context_mut().write_var(&cond_var, &init).ok();
                    }

                    eval.eval_full(
                        &*project,
                        &mut observer_ctx,
                        nstart,
                        Bound::StopBeforeOr(blk_addr, 40),
                    )
                    .ok();

                    for (c, bv) in constants.iter() {
                        tracing::trace!(
                            "setting {} to {:x}",
                            c.display_with(Some(project.lifter.translator())),
                            bv
                        );
                        eval.context_mut().write_var(c, bv).ok();
                    }

                    if va {
                        tracing::trace!(
                            "overriding assign to {} with {:x}",
                            cond_var.display_with(Some(project.lifter.translator())),
                            init
                        );

                        let obs = eval
                            .get_observer_mut::<OverrideVarCond>(varo_observer)
                            .unwrap();

                        obs.enable(nstart, cond_var, init.clone());
                    }

                    eval.eval(&*project, blk_addr, Bound::StopAfterOr(blk_last_addr, 40))
                        .ok();

                    if let Some(address) = eval
                        .get_observer::<SwitchBranchObserver>(switch_observer)
                        .and_then(|obs| obs.destination)
                    {
                        tracing::info!(
                            "switch branch from {} to {} (index {init})",
                            blk_addr,
                            address
                        );

                        if let Some(dest) = project.cbtable.get_point(address) {
                            let dest_addr = dest.address();
                            let dest_func = dest.function();
                            let dest_node = dest.node();

                            if dest_func != blk_func {
                                tracing::debug!(
                                    "switch branches to a block in a different function"
                                );

                                project.ftable.merge_default(
                                    &mut project.cbtable,
                                    blk_func,
                                    dest_func,
                                );

                                wl.push(blk_func);
                            }
                            tracing::info!(
                                "adding new connection in ICFG between {} and {}",
                                blk_addr,
                                dest_addr
                            );
                            project
                                .icfg
                                .add_edge(blk_node, dest_node, FlowKind::SwitchBranch);
                        } else {
                            tracing::debug!("switch branches to an unmarked block");
                            break;
                        }
                    }

                    // undo changes
                    eval.restore().ok();
                }
            }
        }
        Ok(())
    }
}
