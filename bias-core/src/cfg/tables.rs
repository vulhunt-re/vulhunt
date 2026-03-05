use ahash::{AHashMap, AHashSet};
use fugue::bv::BitVec;
use fugue::ir::il::traits::TranslatorDisplay;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::analyses::dataflow::assumptions::BlockAssumptions;
use crate::analyses::switch::SwitchBranchObserver;
use crate::cfg::block::{BlockInfo, BlockInfoTable};
use crate::cfg::context::ICFGProjectContext;
use crate::cfg::function::FunctionStarts;
use crate::cfg::icfg::Configuration;
use crate::cfg::insn::{InsnInfo, InsnInfoTable};
use crate::cfg::FlowKind;
use crate::domains::interval::BitVecIntervalIter;
use crate::eval::observer::common::{
    CallObserver, OverrideLoadCond, OverrideLoadCtx, OVERRIDE_LOAD,
};
use crate::eval::observer::ObserverId;
use crate::eval::{
    Access, AccessKind, Bound, Configuration as EvalConfiguration, IREvaluator, ObserverContext,
};
use crate::ir::expr::rewriter::{ExprRewriter, DEFAULT_RULES};
use crate::ir::{Address, BitSize, Expr, Location, Term, Var};
use crate::kb::block::CodeBlockId;
use crate::kb::function::FunctionInfo;
use crate::kb::id::Identifiable;
use crate::kb::table::MPointTable;
use crate::project::ProjectContext;

// Switch recovery
//
// To perform switch recovery, we have three steps:
// 1. Locating candidate switches
// 2. Inferring switch index bounds
// 3. Computing switch targets
//
// In general, we encounter switches where we have a construct like this:
// ```
// cond <- index <op> #val
// jumpX <default> if cond == true
// ...
// jump [base + index * 4]
// ```
// And this appears as two blocks:
//
// 1. The first block contains the jump to an undetermined location (expression), and the first
//    stage finds these blocks as candidates.
//
// 2. The second block is a predecessor of the first block that is guarded by a condition that can
//    be translated into a range. In simple terms, the general idea is that if we perform symbolic
//    folding of expressions from the top of this block to the bottom, and then check the variable
//    representing the condition to determining if we should jump, we will have a condition
//    variable of a form that can be matched against a small number of variants (these variants can
//    be found in e.g., Hackers Delight). Depending on how the predecessor block reaches the first
//    block, we may need to invert the condition to correctly recover the switch (e.g., if we fall
//    into the block, then we should invert the condition, whereas if we branch to the block, then
//    we shouldn't).
//
// Once we have this condition and the variable compared to, we emulate the first block N times,
// once for each value in the range derived from the condition variable. E.g., let's assume we have
// the second block as `cmp eax, 5; ja <default>`, then we will learn that at the end of the block,
// that our condition variable is an unsigned comparison that must be inverted, so we end up with a
// range of 0 <= ... <= 5 for our index variable (eax). We therefore need to emulate the first block
// 6 times to learn all of the cases.
//
// As expected, the above procedure does not cover all possible switch types, for example, we found
// some ARM binaries that have a different flavour of switch (see below), where the whole switch
// construct is contained within a single block. Fortunately the above algorithm works in this case
// if we apply both bounds inference and emulation to the single block, and slightly modify the
// conditions for branch condition inversion. As an example, consider:
//
// ```
// cond <- reg > 5
// jump <default> if cond == true
// target <- base + reg * 4
// jump [target]
// ```
//
// In the above snippet, we see that taking the condition `reg > 5` and using it for the
// remainder of the block will lead us to the `<default>` case each time, therefore, we need to
// invert the condition when inferring the possible bounds for `reg`. To identify this kind of
// behaviour, we attempt to determine if the destination of any intra-instruction conditionals
// are constant (rather than undetermined).
//

pub(super) struct TableRecovery<'a> {
    config: &'a Configuration<'a>,
    max_table_size: usize,
}

impl<'a> TableRecovery<'a> {
    pub(super) fn new(config: &'a Configuration<'a>) -> Self {
        Self::new_with(config, 512)
    }

    pub(super) fn new_with(config: &'a Configuration<'a>, max_table_size: usize) -> Self {
        Self {
            config,
            max_table_size,
        }
    }

    fn backward_block_merging<'b, 'c>(
        project: &ProjectContext<InsnInfoTable>,
        blocks: &'b BlockInfoTable<'c>,
        blk: &'b BlockInfo<'c>,
    ) -> Vec<&'b BlockInfo<'c>>
    where
        'c: 'b,
    {
        let mut merged = vec![blk];
        let mut last_id = blk.node();

        // fall into: if get pred if outgoing from pred is only fall
        let only_fall = |blk: NodeIndex| -> Option<NodeIndex> {
            let mut next = None;
            let mut count = 0;

            for out in project.icfg.edges_directed(blk, Direction::Incoming) {
                if out.weight().is_fall() {
                    next = Some(out.source());
                } else if out.weight().is_branch() && out.target() == blk {
                    let block = &blocks[project.icfg[blk]];
                    let nblock = &blocks[project.icfg[out.source()]];

                    if nblock.end() == block.start() {
                        next = Some(out.source())
                    }
                }
                count += 1;
            }

            if count == 1 {
                next
            } else {
                None
            }
        };

        while let Some(nx) = only_fall(last_id) {
            merged.push(&blocks[project.icfg[nx]]);
            last_id = nx;
        }

        merged.reverse();
        merged
    }

    fn incoming_assumptions<'b, 'c>(
        &self,
        project: ProjectContext<InsnInfoTable>,
        blocks: &'c MPointTable<Address, BlockInfo<'b>>,
        blk: &'c BlockInfo<'b>,
    ) -> Option<(Address, Var, Option<(Term<Expr>, u32)>, BitVecIntervalIter)>
    where
        'b: 'c,
    {
        self.incoming_assumptions_via_pred(project, blocks, blk)
            .or_else(|| self.incoming_assumptions_via_self(project, blocks, blk))
    }

    fn incoming_assumptions_via_self<'b, 'c>(
        &self,
        project: ProjectContext<InsnInfoTable>,
        blocks: &'c MPointTable<Address, BlockInfo<'b>>,
        blk: &'c BlockInfo<'b>,
    ) -> Option<(Address, Var, Option<(Term<Expr>, u32)>, BitVecIntervalIter)>
    where
        'b: 'c,
    {
        // NOTE: for ARM, we may have the condition and jump computed in the same
        // block. For example:
        //
        // CMP     R4, #5           ; switch 6 cases
        // ADDLS   PC, PC, R4,LSL#2 ; switch jump
        //

        let last = blk.last_insn();

        if last.is_call() {
            return None;
        }

        let mut assume = BlockAssumptions::default();
        let mut simplifier = ExprRewriter::default();

        let next_address = last.next_address();

        // NOTE: with ARM, we may need to simulate some block merging;

        let blocks = Self::backward_block_merging(&project, blocks, blk);

        let mut starts = blocks[0].start();

        if let Some((saddr, addr, var, vals)) = assume.analyse_condition_bb_with(
            blocks
                .into_iter()
                .flat_map(|blk| blk.insns().map(InsnInfo::insn)),
            // For the above construct, we don't have a fall--we have a jump to the
            // expected fall address (it will be the default). So we need to check
            // for this conditional, and mark it accordingly.
            //
            !last.has_fall()
                && last
                    .target_addresses_with()
                    .any(|(op, addr)| addr == next_address && op.is_cond()),
            |expr| simplifier.simplify_expr(&expr, &*DEFAULT_RULES),
        ) {
            tracing::trace!("variable originates from: {:?}", addr);
            if let Some(nstarts) = addr {
                starts = nstarts.max(starts);
            } else {
                starts = saddr.max(starts);
            }

            let it = vals.iter();
            let hint = it.size_hint().1;

            if hint.is_none() || matches!(hint, Some(v) if v <= 1 || v > self.max_table_size) {
                tracing::debug!(
                    "skipping as table size estimate exceeds {} or is <= 1",
                    self.max_table_size
                );
                None
            } else {
                let mv = if let Some((expr, bits)) = assume.memory_expr(&var) {
                    tracing::trace!("table bound is via memory load");
                    Some((expr.clone(), bits))
                } else {
                    None
                };

                tracing::info!(
                    "table bound estimated to be {vals} for {} (size: {})",
                    var.display_with(Some(project.lifter.translator())),
                    hint.unwrap(),
                );
                Some((starts, var, mv, it))
            }
        } else {
            None
        }
    }

    fn incoming_assumptions_via_pred(
        &self,
        project: ProjectContext<InsnInfoTable>,
        blocks: &MPointTable<Address, BlockInfo>,
        blk: &BlockInfo,
    ) -> Option<(Address, Var, Option<(Term<Expr>, u32)>, BitVecIntervalIter)> {
        let mut assume = BlockAssumptions::default();
        let mut simplifier = ExprRewriter::default();

        // find incoming blocks for assumptions about current block
        let mut cond = None;

        for pred in project.icfg.edges_directed(blk.node(), Direction::Incoming) {
            if !(pred.weight().is_fall() || pred.weight().is_conditional()) {
                return None;
            }

            let pblk = &blocks[project.icfg[pred.source()]];

            if !pblk.last_insn().is_branch() || pblk.last_insn().is_call() {
                return None;
            }

            tracing::trace!(
                "analysing conditions imposed by {}-{}",
                pblk.start(),
                pblk.end()
            );

            let mut starts = pblk.start();

            if let Some((saddr, addr, nvar, ncond)) = assume.analyse_condition_bb_with(
                pblk.insns().map(InsnInfo::insn),
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

        cond.and_then(|(addr, var, vals)| {
            let it = vals.iter();
            let hint = it.size_hint().1;

            if hint.is_none() || matches!(hint, Some(v) if v <= 1 || v > self.max_table_size) {
                tracing::debug!(
                    "skipping as table size estimate exceeds {} or is <= 1",
                    self.max_table_size
                );
                None
            } else {
                let mv = if let Some((expr, bits)) = assume.memory_expr(&var) {
                    tracing::trace!("table bound is via memory load");
                    Some((expr.clone(), bits))
                } else {
                    None
                };

                tracing::info!(
                    "table bound estimated to be {vals} for {} (size: {})",
                    var.display_with(Some(project.lifter.translator())),
                    hint.unwrap(),
                );
                Some((addr, var, mv, it))
            }
        })
    }

    pub(super) fn find_simple_indirect_call_target<'ctx, 'insn, 'icfg>(
        &self,
        context: ProjectContext<InsnInfoTable>,
        functions: &mut FunctionStarts,
        icfg_blocks: &mut AHashMap<Address, (NodeIndex, CodeBlockId)>,
        evaluator: &mut IREvaluator,
        observer_ctx: &mut ObserverContext,
        observer: ObserverId,
        block: &BlockInfo<'insn>,
    ) -> Option<(Address, NodeIndex)> {
        let first = block.first_insn().address();
        let last = block.last_insn().address();

        evaluator
            .eval_full(context, observer_ctx, first, Bound::StopAfterOr(last, 40))
            .ok();

        let addr = evaluator
            .get_observer_mut::<CallObserver>(observer)
            .expect("registered observer")
            .take()?;

        tracing::trace!("indirect call target resolved to {addr}");

        let region = context.memory.find_region(addr)?;

        if region.name() != "extern" {
            return None;
        }

        if functions.contains_key(&addr) {
            icfg_blocks
                .get(&addr)
                .copied()
                .map(|(index, _)| (addr, index))
        } else {
            None
        }
    }

    pub(super) fn find_edges_simplified<'ctx, 'insn, 'icfg>(
        &self,
        context: ICFGProjectContext<'ctx, 'insn, 'icfg>,
        functions: &mut FunctionStarts,
        blocks: &mut BlockInfoTable<'insn>,
        icfg_blocks: &mut AHashMap<Address, (NodeIndex, CodeBlockId)>,
        candidates: &mut Vec<CodeBlockId>,
    ) {
        let mut eval = context
            .evaluator(EvalConfiguration {
                enable_restores: true,
                ignore_invalid_accesses: true,
                ignore_unimplemented_ops: true,
                treat_branches_via_pc_as_calls: false,
                ..Default::default()
            })
            .unwrap();

        let call_observer = eval.register_observer(CallObserver::default());
        let table_observer = eval.register_observer(SwitchBranchObserver::default());
        let loado_observer = eval.register_observer(OverrideLoadCond::default());

        let mut observer_ctx = ObserverContext::default();
        observer_ctx.set(OVERRIDE_LOAD, OverrideLoadCtx::new(context.lifter));

        while let Some(blk) = candidates.pop() {
            let blk = &blocks[blk];
            let start = blk.start();
            let blknx = blk.node();
            let last = blk.last_insn();
            let end = last.address();
            let is_call = last.is_call();

            tracing::trace!("running indirect/table recovery for {}", start);

            if is_call {
                tracing::trace!("indirect is a call; attempting to perform external linking");
                if let Some((addr, nx)) = self.find_simple_indirect_call_target(
                    context.tables(),
                    functions,
                    icfg_blocks,
                    &mut eval,
                    &mut observer_ctx,
                    call_observer,
                    blk,
                ) {
                    tracing::trace!(
                        "adding new connection in ICFG between {} and {}",
                        blk.start(),
                        addr,
                    );
                    context.icfg.add_edge(blknx, nx, FlowKind::ICall);
                }
                eval.restore().ok();
                continue;
            }

            tracing::trace!(
                "resolving {}-{} (call: {})",
                blk.start(),
                blk.end(),
                is_call
            );

            let (nstart, cond_var, mv, cond_vals) = if let Some((nstart, cond_var, mv, cond_vals)) =
                self.incoming_assumptions(context.tables(), blocks, blk)
            {
                (nstart, cond_var, mv, cond_vals)
            } else {
                tracing::trace!("could not determine incoming assumptions");
                continue;
            };

            tracing::trace!("assumptions resolved at address {nstart}");

            for init in cond_vals {
                if let Some((expr, bits)) = &mv {
                    tracing::trace!(
                        "overriding load via {} with {:x}",
                        expr.display_with(Some(context.lifter.translator())),
                        init
                    );

                    let obs = eval
                        .get_observer_mut::<OverrideLoadCond>(loado_observer)
                        .unwrap();

                    obs.enable(expr.clone(), *bits, init.clone());
                } else {
                    tracing::trace!(
                        "setting {} to {:x}",
                        cond_var.display_with(Some(context.lifter.translator())),
                        init
                    );

                    eval.context_mut().write_var(&cond_var, &init).ok();
                }

                eval.eval_full(
                    context.tables(),
                    &mut observer_ctx,
                    nstart,
                    Bound::StopAfterOr(end, 40),
                )
                .ok();

                if let Some(address) = eval
                    .get_observer::<SwitchBranchObserver>(table_observer)
                    .and_then(|obs| obs.destination())
                {
                    tracing::info!("switch branch from {} to {} (index {init})", start, address);

                    if let Some(dest) = context.itable.insn(address) {
                        tracing::info!(
                            "adding new connection in ICFG between {} and {}",
                            start,
                            dest.address()
                        );

                        dest.mark_in_table();
                        dest.mark_branch_target();

                        let dblknx = if let Some(dblk) = icfg_blocks
                            .get(&address)
                            .and_then(|(_, id)| blocks.get(*id))
                        {
                            dblk.node()
                        } else {
                            let mut nx = Default::default();
                            let did = blocks.insert_with(address, |_addr, id| {
                                nx = context.icfg.add_node(id);
                                icfg_blocks.insert(address, (nx, id));

                                let mut block = BlockInfo::default();
                                block.update_id(id);
                                block.update_node(nx);

                                block.update_with(
                                    address,
                                    &*context.itable,
                                    &icfg_blocks,
                                    context.icfg,
                                );
                                block
                            });

                            // push to worklist if new
                            candidates.push(did);

                            nx
                        };

                        context.icfg.add_edge(
                            blknx,
                            dblknx,
                            if is_call {
                                FlowKind::SwitchCall
                            } else {
                                FlowKind::SwitchBranch
                            },
                        );

                        if is_call {
                            functions
                                .entry(address)
                                .or_insert_with(FunctionInfo::default);
                        }
                    } else {
                        tracing::debug!("switch branches to an unknown instruction");
                    }
                }

                // undo changes
                eval.restore().ok();
            }
        }
    }

    #[allow(unused)]
    #[deprecated(note = "use Table::Recovery::find_edges_simplified")]
    pub(super) fn find_edges<'ctx, 'insn, 'icfg>(
        &self,
        context: ICFGProjectContext<'ctx, 'insn, 'icfg>,
        functions: &mut AHashSet<Address>,
        blocks: &mut MPointTable<Address, BlockInfo<'insn>>,
        icfg_blocks: &mut AHashMap<Address, (NodeIndex, CodeBlockId)>,
        candidates: &mut Vec<CodeBlockId>,
    ) {
        let config = EvalConfiguration {
            track_accesses_all: true,
            enable_restores: true,
            ..Default::default()
        };

        let mut conflicts = AHashSet::default();
        let mut eval = context.evaluator(config).unwrap();
        let mut assume = BlockAssumptions::default();
        let mut observer_state = ObserverContext::default();

        // TODO: refactor
        while let Some(blk) = candidates.pop() {
            let blk = blocks.get(blk).unwrap();
            let blknx = blk.node();

            let last = blk.last_insn();
            let is_call = last.is_call();

            tracing::trace!(
                "resolving {}-{} (call: {})",
                blk.start(),
                blk.end(),
                is_call
            );

            let _ = eval.eval_full(
                context.tables(),
                &mut observer_state,
                blk.start(),
                Bound::StopAfterOr(last.address(), 40),
            );

            let all_tracked = eval.tracked();
            conflicts.clear();

            tracing::trace!("{} tracked accesses", all_tracked.len());

            for (i, tracked) in all_tracked.iter().enumerate() {
                if let Access {
                    kind: AccessKind::Branch(_),
                    location: Location { address, .. },
                    variable,
                    ..
                } = tracked
                {
                    if let Some(naddress) = variable.address() {
                        tracing::trace!(
                            "resolved branch at {} to {} (is call: {})",
                            address,
                            naddress,
                            is_call
                        );

                        let mut j = i;
                        while j > 0 {
                            j -= 1;

                            if !all_tracked[j].variable.is_address() {
                                continue;
                            }

                            if let AccessKind::Load(ref bv) = all_tracked[j].kind {
                                let conv = |bv: &BitVec| {
                                    bv.signed_cast(context.lifter.global_space().address_size() * 8)
                                        .to_u64()
                                };

                                if let Some(sbv) = conv(bv) {
                                    let maddr = Address::from(sbv);
                                    let jaddr = all_tracked[j].variable.address().unwrap();

                                    if maddr == naddress {
                                        if context.itable.insn(naddress).is_some() {
                                            tracing::trace!(
                                                "possible jump table found at: {} (direct)",
                                                jaddr
                                            );
                                            let tblk = if let Some(tblk) = icfg_blocks
                                                .get(&naddress)
                                                .and_then(|(_, id)| blocks.get(*id))
                                            {
                                                tblk
                                            } else {
                                                let tid =
                                                    blocks.insert_with(naddress, |_addr, id| {
                                                        let nx = context.icfg.add_node(id);
                                                        icfg_blocks.insert(naddress, (nx, id));

                                                        let mut block = BlockInfo::default();
                                                        block.update_id(id);
                                                        block.update_node(nx);

                                                        block.update_with(
                                                            naddress,
                                                            &*context.itable,
                                                            &icfg_blocks,
                                                            context.icfg,
                                                        );
                                                        block
                                                    });
                                                blocks.get(tid).unwrap()
                                            };

                                            let kind = if is_call {
                                                functions.insert(naddress);
                                                FlowKind::ICall
                                            } else {
                                                FlowKind::IBranch
                                            };
                                            context.icfg.add_edge(blknx, tblk.node(), kind);
                                        }
                                    } else if (maddr + jaddr) == naddress {
                                        if let Some(insn) = context.itable.insn(naddress) {
                                            tracing::trace!(
                                                "possible jump table found at: {} (relative)",
                                                jaddr
                                            );

                                            // find incoming blocks for assumptions about
                                            // switch index bound
                                            let mut cond = None;
                                            for pred in context
                                                .icfg
                                                .edges_directed(blknx, Direction::Incoming)
                                            {
                                                let pblk = &blocks[context.icfg[pred.source()]];
                                                if let Some(ncond) = assume
                                                    .analyse_condition(
                                                        pblk.insns().map(|info| info.insn()),
                                                        pred.weight().is_fall(),
                                                    )
                                                    .map(|(_, iv)| iv)
                                                {
                                                    cond = match cond {
                                                        None => Some(ncond),
                                                        Some(ocond) => Some(ocond.union(&ncond)),
                                                    };
                                                }
                                            }

                                            if let Some(cond) = cond.as_ref() {
                                                tracing::trace!(
                                                    "switch bound estimated to be {}",
                                                    cond
                                                );
                                            }

                                            // NOTE: check for table conflicts
                                            if conflicts.contains(&jaddr) {
                                                // TODO: break incoming indirects
                                                tracing::trace!("address target is conflicted");
                                            }

                                            let mut ok_conflicts = AHashSet::default();
                                            ok_conflicts.insert(jaddr);

                                            insn.mark_in_table();
                                            insn.mark_branch_target();

                                            let max_bound = cond.as_ref().and_then(|iv| {
                                                iv.iter().max().and_then(|v| v.to_usize())
                                            });

                                            // TODO: check for contiguous regions!
                                            if (max_bound.is_none()
                                                || matches!(max_bound, Some(i) if i > ok_conflicts.len()))
                                                && self.config.resolve_switch_tables_greedily
                                            {
                                                let shift = bv.bits() / 8;
                                                let mut ntaddr = jaddr + shift;

                                                // NOTE: we assume that the jump table is fixed
                                                while let Ok(Some(tval)) = eval
                                                    .context()
                                                    .read_addr(ntaddr, bv.nbits())
                                                    .map(|nbv| conv(&nbv))
                                                {
                                                    let taddr = jaddr + tval;
                                                    if let Some(insn) = context.itable.insn(taddr) {
                                                        // we assume we're at index + 1: stop on conflicts
                                                        if conflicts.contains(&ntaddr) {
                                                            tracing::trace!("possible jump target at: {} (conflict)", taddr);
                                                            break;
                                                        } else {
                                                            tracing::trace!(
                                                                "possible jump target at: {}",
                                                                taddr
                                                            );

                                                            ok_conflicts.insert(ntaddr);

                                                            insn.mark_in_table();
                                                            insn.mark_branch_target();

                                                            let tblk = if let Some(tblk) =
                                                                icfg_blocks.get(&taddr).and_then(
                                                                    |(_, id)| blocks.get(*id),
                                                                ) {
                                                                tblk
                                                            } else {
                                                                let tid = blocks.insert_with(
                                                                    taddr,
                                                                    |_addr, id| {
                                                                        let nx = context
                                                                            .icfg
                                                                            .add_node(id);
                                                                        icfg_blocks.insert(
                                                                            taddr,
                                                                            (nx, id),
                                                                        );

                                                                        let mut block =
                                                                            BlockInfo::default();
                                                                        block.update_id(id);
                                                                        block.update_node(nx);

                                                                        block.update_with(
                                                                            taddr,
                                                                            &*context.itable,
                                                                            &icfg_blocks,
                                                                            context.icfg,
                                                                        );
                                                                        block
                                                                    },
                                                                );
                                                                blocks.get(tid).unwrap()
                                                            };

                                                            context.icfg.add_edge(
                                                                blknx,
                                                                tblk.node(),
                                                                if is_call {
                                                                    FlowKind::SwitchCall
                                                                } else {
                                                                    FlowKind::SwitchBranch
                                                                },
                                                            );

                                                            ntaddr = ntaddr + shift;

                                                            if matches!(max_bound, Some(i) if ok_conflicts.len() > i)
                                                            {
                                                                break;
                                                            }
                                                        }
                                                    } else {
                                                        break;
                                                    }
                                                }
                                            }

                                            let tblk = if let Some(tblk) = icfg_blocks
                                                .get(&naddress)
                                                .and_then(|(_, id)| blocks.get(*id))
                                            {
                                                tblk
                                            } else {
                                                let tid =
                                                    blocks.insert_with(naddress, |_addr, id| {
                                                        let nx = context.icfg.add_node(id);
                                                        icfg_blocks.insert(naddress, (nx, id));

                                                        let mut block = BlockInfo::default();
                                                        block.update_id(id);
                                                        block.update_node(nx);

                                                        block.update_with(
                                                            naddress,
                                                            &*context.itable,
                                                            &icfg_blocks,
                                                            context.icfg,
                                                        );
                                                        block
                                                    });
                                                blocks.get(tid).unwrap()
                                            };

                                            if ok_conflicts.len() > 1 {
                                                context.icfg.add_edge(
                                                    blknx,
                                                    tblk.node(),
                                                    if is_call {
                                                        FlowKind::SwitchCall
                                                    } else {
                                                        FlowKind::SwitchBranch
                                                    },
                                                );
                                            } else {
                                                let kind = if is_call {
                                                    functions.insert(naddress);
                                                    FlowKind::ICall
                                                } else {
                                                    FlowKind::IBranch
                                                };
                                                context.icfg.add_edge(blknx, tblk.node(), kind);
                                            }

                                            conflicts.extend(ok_conflicts);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            eval.restore().ok();
        }
    }
}
