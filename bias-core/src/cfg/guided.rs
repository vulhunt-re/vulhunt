use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
use std::ops::Range;

use fugue::ir::disassembly::{ContextDatabase, IRBuilderArena, ParserContext};
use iset::IntervalMap;
use petgraph::graph::NodeIndex;

use crate::arch::ContextUpdates;
use crate::cfg::block::BlockInfo;
use crate::cfg::icfg::ICFGBuilderContext;
use crate::cfg::insn::{InsnTable, InsnTermTable};
use crate::ir::stmt::StmtCache;
use crate::kb::function::{FunctionEntryStrategy, FunctionInfo};
use crate::kb::table::MPointTable;
use crate::prelude::*;

#[derive(Debug, Clone, Default)]
pub struct GuidedFunctionEntry {
    properties: FunctionInfo,
    context: ContextUpdates,
}

impl GuidedFunctionEntry {
    pub fn new(properties: FunctionInfo, context: ContextUpdates) -> Self {
        Self {
            properties,
            context,
        }
    }

    pub fn properties(&self) -> FunctionInfo {
        self.properties
    }

    pub fn context(&self) -> &ContextUpdates {
        &self.context
    }
}

pub struct S0<'a, 's> {
    ctx: ContextDatabase,
    irb: IRBuilderArena,
    cache: StmtCache,
    itable: &'a mut InsnTermTable,
    blocks: AHashMap<Address, (NodeIndex, CodeBlockId)>,
    worklist: VecDeque<(Range<Address>, &'s [u8])>,
    block_contexts: BTreeMap<Address, ContextUpdates>,
}

impl<'a, 's> S0<'a, 's> {
    pub fn blocks(&self) -> &AHashMap<Address, (NodeIndex, CodeBlockId)> {
        &self.blocks
    }
}

pub struct S1<'a> {
    ctx: ContextDatabase,
    itable: &'a mut InsnTermTable,
    blocks: AHashMap<Address, (NodeIndex, CodeBlockId)>,
    functions: BTreeMap<Address, GuidedFunctionEntry>,
}

impl<'a> S1<'a> {
    pub fn blocks(&self) -> &AHashMap<Address, (NodeIndex, CodeBlockId)> {
        &self.blocks
    }

    pub fn functions(&self) -> &BTreeMap<Address, GuidedFunctionEntry> {
        &self.functions
    }
}

pub struct S2<'a> {
    ctx: ContextDatabase,
    itable: &'a mut InsnTermTable,
    block_ranges: IntervalMap<Address, NodeIndex>,
    functions: BTreeMap<Address, GuidedFunctionEntry>,
    block_assoc: BTreeMap<Address, Address>,
}

impl<'a> S2<'a> {
    pub fn block_ranges(&self) -> &IntervalMap<Address, NodeIndex> {
        &self.block_ranges
    }

    pub fn functions(&self) -> &BTreeMap<Address, GuidedFunctionEntry> {
        &self.functions
    }
}

pub type Stage0<'a, 's> = S0<'a, 's>;
pub type Stage1<'a> = S1<'a>;
pub type Stage2<'a> = S2<'a>;

pub struct GuidedICFGBuilder<'a, S> {
    context: ICFGBuilderContext<'a>,
    state: S,
}

struct FunctionBuilder<'a> {
    blocks: &'a mut MPointTable<Address, CodeBlock>,
    icfg: &'a ICFG,
    function_addrs: &'a BTreeSet<Address>,
}

impl<'a> FunctionEntryStrategy for FunctionBuilder<'a> {
    type T = (bool, bool, Address);

    fn priority(&mut self, block: CodeBlockId, f: FunctionId) -> Self::T {
        let block = self.blocks.get_mut(block).unwrap();
        block.update_function(f);
        (
            !self.function_addrs.contains(&block.address()),
            self.icfg
                .edges_directed(block.node(), Direction::Incoming)
                .next()
                .is_some(),
            block.address(),
        )
    }

    fn entry(&mut self, _block: CodeBlockId, _f: FunctionId, priority: Self::T) -> Address {
        priority.2
    }
}

fn expand_function_block(
    slf: &mut Function,
    id: CodeBlockId,
    blocks: &mut MPointTable<Address, CodeBlock>,
    functions: &BTreeSet<Address>,
    block_assoc: &BTreeMap<Address, Address>,
    icfg: &ICFG,
) -> Option<FunctionId> {
    let function_addr = blocks.get(id).unwrap().address();
    let mut worklist = VecDeque::new();
    let mut overlaps = None;

    worklist.push_back(id);

    while let Some(id) = worklist.pop_front() {
        if slf.blocks().contains_key(&id) {
            continue;
        }

        let block = blocks.get_mut(id).unwrap();

        if block.function() != FunctionId::default() && block.function() != slf.id() {
            tracing::debug!(
                "already inside function: {} (seen: {:?}, found {})",
                block.address(),
                overlaps,
                block.function(),
            );
            overlaps = overlaps.or(Some(block.function()));
            continue;
        }

        slf.blocks_mut().insert(id, block.address());
        block.update_function(slf.id());

        let block = blocks.get(id).unwrap();

        if !functions.contains(&block.address()) {
            for pred in icfg.edges_directed(block.node(), Direction::Incoming) {
                if pred.weight().is_call() || pred.weight().is_return() {
                    continue;
                }

                let nblock = icfg[pred.source()];
                let nblk = blocks.get(nblock).unwrap();

                if let Some(&assoc_fn) = block_assoc.get(&nblk.address()) {
                    if assoc_fn != function_addr {
                        continue;
                    }
                }

                tracing::debug!(
                    "adding incoming (expand): {} -> {} ({:?})",
                    nblk.address(),
                    block.address(),
                    pred
                );

                if overlaps.is_none() {
                    worklist.push_back(nblock);
                }
            }
        }

        for succ in icfg.edges_directed(block.node(), Direction::Outgoing) {
            if succ.weight().is_call() || succ.weight().is_return() {
                continue;
            }

            let nblock = icfg[succ.target()];
            let nblk = blocks.get(nblock).unwrap();

            if let Some(&assoc_fn) = block_assoc.get(&nblk.address()) {
                if assoc_fn != function_addr {
                    continue;
                }
            }

            if !functions.contains(&nblk.address()) {
                tracing::debug!(
                    "adding outgoing (expand): {} -> {} ({:?})",
                    block.address(),
                    nblk.address(),
                    succ
                );

                if overlaps.is_none() {
                    worklist.push_back(nblock);
                }
            }
        }
    }

    overlaps
}

fn unlink_forward_unreachable_blocks(
    func: &mut Function,
    blocks: &mut MPointTable<Address, CodeBlock>,
    icfg: &ICFG,
) {
    let mut seen = BTreeSet::new();
    let mut worklist = VecDeque::new();

    worklist.push_back(func.entry());

    while let Some(id) = worklist.pop_front() {
        if !seen.insert(id) {
            continue;
        }

        if let Some(blk) = blocks.get(id) {
            for succ in icfg
                .neighbors_directed(blk.node(), Direction::Outgoing)
                .filter(|nx| func.blocks().contains_key(&icfg[*nx]))
            {
                let succ_id = icfg[succ];
                if !seen.contains(&succ_id) {
                    worklist.push_back(succ_id);
                }
            }
        }
    }

    let faddr = func.address();

    for (blk, _) in func.blocks_mut().extract_if(|id, _| !seen.contains(id)) {
        if let Some(block) = blocks.get_mut(blk) {
            tracing::debug!(
                "unlinking unreachable block {} from {faddr}",
                block.address()
            );
            block.update_function(FunctionId::default());
        }
    }
}

impl<'a, 's> GuidedICFGBuilder<'a, S0<'a, 's>> {
    pub fn new(project: &'a mut Project) -> GuidedICFGBuilder<'a, S0<'a, 's>> {
        let itable = mem::take(&mut project.itable).into();

        GuidedICFGBuilder {
            context: ICFGBuilderContext {
                lifter: &project.lifter,
                icfg: &mut project.icfg,
                datadb: &mut project.datadb,
                itable,
                cbtable: &mut project.cbtable,
                ftable: &mut project.ftable,
                fstable: &mut project.fstable,
                symtab: &mut project.symtab,
                memory: &project.memory,
                typedb: &project.typedb,
                analyses: &project.manager,
                injections: &project.injections,
            },
            state: S0 {
                ctx: project.lifter.context(),
                irb: project.lifter.irb(4096),
                itable: &mut project.itable,
                cache: StmtCache::default(),
                blocks: Default::default(),
                worklist: Default::default(),
                block_contexts: Default::default(),
            },
        }
    }

    #[inline]
    pub fn schedule_block(&mut self, range: impl Into<Range<Address>>, bytes: &'s [u8]) {
        self.schedule_block_with_context(range, bytes, None);
    }

    #[inline]
    pub fn schedule_block_with_context(
        &mut self,
        range: impl Into<Range<Address>>,
        bytes: &'s [u8],
        context: impl Into<Option<ContextUpdates>>,
    ) {
        let range = range.into();
        if let Some(ctx) = context.into() {
            self.state.block_contexts.insert(range.start, ctx);
        }
        self.state.worklist.push_back((range, bytes));
    }

    #[inline]
    pub fn set_context(&mut self, addr: impl Into<Address>, var: impl AsRef<str>, val: u32) {
        let addr = self
            .context
            .lifter
            .translator()
            .address(u64::from(addr.into()));
        self.state.ctx.set_variable(var.as_ref(), addr, val);
    }

    #[inline]
    pub fn set_context_range(
        &mut self,
        range: impl Into<Range<Address>>,
        var: impl AsRef<str>,
        val: u32,
    ) {
        let Range { start, end } = range.into();
        let start = self.context.lifter.translator().address(u64::from(start));
        let end = self.context.lifter.translator().address(u64::from(end));
        self.state
            .ctx
            .set_variable_region(var.as_ref(), start, Some(end), val);
    }

    #[inline]
    pub fn execute_with(&mut self, ir_allocator_reset_period: usize) {
        let mut worklist = mem::take(&mut self.state.worklist);
        let ir_allocator_reset_period = if ir_allocator_reset_period == 0 {
            10_000
        } else {
            ir_allocator_reset_period
        };

        'sweep: while !worklist.is_empty() {
            self.state.irb.reset();

            let mut pctx =
                ParserContext::empty(&self.state.irb, self.context.lifter.translator().manager());

            while let Some((Range { start, end }, bytes)) = worklist.pop_front() {
                self.state.blocks.insert(start, Default::default());

                if let Some(ctx_updates) = self.state.block_contexts.get(&start) {
                    let addr_val = self.context.lifter.address_value(start);
                    ctx_updates.apply(addr_val, &mut self.state.ctx);
                }

                let mut offset = 0;
                let roffset = usize::from(end - start);

                while offset < roffset {
                    let start = start + offset;
                    if self.context.itable.contains(start) {
                        break;
                    }

                    let ilink = match InsnInfo::new(
                        self.context.lifter,
                        &self.state.irb,
                        &mut self.state.ctx,
                        &mut pctx,
                        &mut self.state.cache,
                        start,
                        &bytes[offset..],
                    ) {
                        Ok(ilink) if ilink.len() > 0 => ilink,
                        _ => {
                            break;
                        }
                    };

                    offset += ilink.len();

                    if ilink.is_flow() && offset < roffset {
                        let next = ilink.next_address();
                        self.state.blocks.insert(next, Default::default());
                    }

                    self.context.itable.insert(ilink);
                }

                if self.context.itable.len() % ir_allocator_reset_period == 0 {
                    continue 'sweep;
                }
            }
        }
    }

    #[inline]
    pub fn execute(&mut self) {
        self.execute_with(10_000usize);
    }

    #[inline]
    pub fn finalise(mut self) -> GuidedICFGBuilder<'a, S1<'a>> {
        if !self.state.worklist.is_empty() {
            self.execute();
        }
        GuidedICFGBuilder {
            context: self.context,
            state: S1 {
                ctx: self.state.ctx,
                blocks: self.state.blocks,
                itable: self.state.itable,
                functions: Default::default(),
            },
        }
    }
}

impl<'a> GuidedICFGBuilder<'a, S0<'a, 'a>> {
    #[inline]
    pub fn schedule_mapped_block(&mut self, start: impl Into<Address>, size: usize) {
        self.schedule_mapped_block_with_context(start, size, None);
    }

    #[inline]
    pub fn schedule_mapped_block_with_context(
        &mut self,
        start: impl Into<Address>,
        size: usize,
        context: impl Into<Option<ContextUpdates>>,
    ) {
        let start = start.into();
        let end = start + size;

        let Ok(bytes) = self.context.memory.view_bytes(start, size) else {
            return;
        };

        if let Some(ctx) = context.into() {
            self.state.block_contexts.insert(start, ctx);
        }
        self.state.worklist.push_back((start..end, bytes));
    }
}

impl<'a, 's> GuidedICFGBuilder<'a, S1<'a>> {
    #[inline]
    pub fn mark_block(&mut self, address: impl Into<Address>) {
        if let Some(tinfo) = self.context.itable.insn(address.into()) {
            tinfo.mark_branch_target();
            self.state.blocks.entry(tinfo.address()).or_default();
        }
    }

    #[inline]
    pub fn mark_function(&mut self, address: impl Into<Address>) {
        self.mark_function_with(address, GuidedFunctionEntry::default());
    }

    #[inline]
    pub fn mark_function_with(&mut self, address: impl Into<Address>, entry: GuidedFunctionEntry) {
        if let Some(tinfo) = self.context.itable.insn(address.into()) {
            tinfo.mark_call_target();
            self.state.blocks.entry(tinfo.address()).or_default();
            self.state.functions.insert(tinfo.address(), entry);
        }
    }

    #[inline]
    pub fn finalise(mut self) -> GuidedICFGBuilder<'a, S2<'a>> {
        let mut block_ranges = IntervalMap::new();
        let mut cbtable = MPointTable::<Address, BlockInfo<'_>>::default();

        cbtable.reserve(self.state.blocks.len());

        for (addr, (nx, bid)) in self.state.blocks.iter_mut() {
            if !self.context.itable.contains(addr) {
                continue;
            }

            cbtable.insert_with(*addr, |_addr, id| {
                *bid = id;
                *nx = self.context.icfg.add_node(id);

                let mut block = BlockInfo::default();

                block.update_id(id);
                block.update_node(*nx);

                block
            });
        }

        cbtable.for_each_mut(|addr, blk| {
            blk.update_with(
                *addr,
                &self.context.itable,
                &self.state.blocks,
                self.context.icfg,
            );

            let start = blk.first_insn().address();
            let end = blk.last_insn().next_address();

            block_ranges.force_insert(start..end, blk.node());
        });

        *self.context.cbtable = cbtable
            .map(|bid, blk| CodeBlock::new(bid, FunctionId::default(), blk.node(), blk.insns()));

        GuidedICFGBuilder {
            context: self.context,
            state: S2 {
                ctx: self.state.ctx,
                block_ranges,
                itable: self.state.itable,
                functions: self.state.functions,
                block_assoc: Default::default(),
            },
        }
    }
}

impl<'a> GuidedICFGBuilder<'a, S2<'a>> {
    #[inline]
    pub fn force_block_assoc(
        &mut self,
        function_addr: impl Into<Address>,
        block_addr: impl Into<Address>,
    ) {
        self.state
            .block_assoc
            .insert(block_addr.into(), function_addr.into());
    }

    #[inline]
    pub fn mark_flow(&mut self, from: impl Into<Address>, to: impl Into<Address>, kind: FlowKind) {
        let from = from.into();
        let to = to.into();

        let Some(&s) = self
            .state
            .block_ranges
            .iter(from..from + 1usize)
            .map(|v| v.1)
            .next()
        else {
            return;
        };

        let Some(&d) = self
            .state
            .block_ranges
            .iter(to..to + 1usize)
            .map(|v| v.1)
            .next()
        else {
            return;
        };

        let from_blk = &self.context.cbtable[self.context.icfg[s]];
        let from_insn = self.context.itable.insn(from_blk.last_address()).unwrap();

        if kind.is_branch() && matches!(from_insn.fall_address(), Some(fall) if fall == to) {
            return;
        }

        if !kind.is_switch() && from_insn.target_addresses().any(|addr| addr == to) {
            return;
        }

        if kind.is_call() && !from_insn.is_call() {
            return;
        }

        let indirect = from_insn
            .targets()
            .iter()
            .any(|tgt| tgt.1.indirect_or_unresolved());

        let kind = match kind {
            FlowKind::Call if indirect => FlowKind::ICall,
            FlowKind::Branch if indirect => FlowKind::IBranch,
            _ => kind,
        };

        let e = self.context.icfg.find_edge(s, d);
        if e.is_none() || e.is_some_and(|e| self.context.icfg[e] != kind) {
            self.context.icfg.add_edge(s, d, kind);
        }
    }

    #[inline]
    pub fn finalise(mut self) {
        let function_addrs = self
            .state
            .functions
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let arch = self.context.lifter.arch();

        for &addr in function_addrs.iter() {
            let entry = self.state.functions.get(&addr).unwrap();
            let fblk = self.context.cbtable.get_point(addr).unwrap().id();
            let mut f = Function::default();

            if let Some(overlap_f) = expand_function_block(
                &mut f,
                fblk,
                &mut self.context.cbtable,
                &function_addrs,
                &self.state.block_assoc,
                &self.context.icfg,
            ) {
                tracing::debug!(
                    "merging function at {addr} with overlapping function {}",
                    self.context.ftable[overlap_f].address()
                );
                self.context.ftable.merge_with(
                    overlap_f,
                    f,
                    FunctionBuilder {
                        blocks: &mut self.context.cbtable,
                        icfg: &self.context.icfg,
                        function_addrs: &function_addrs,
                    },
                );
            } else {
                self.context.ftable.insert_with(addr, |_addr, id| {
                    f.update_id(id);
                    f.update_entry(fblk);
                    f.for_blocks_mut(&mut self.context.cbtable, |_, cb| {
                        cb.update_function(id);
                    });

                    arch.compute_function_properties(
                        &mut f,
                        self.context.lifter,
                        &self.state.ctx,
                        &self.context.icfg,
                    );

                    entry.properties().apply(&mut f);
                    f
                });
            }

            if let Some(func) = self.context.ftable.get_point_mut(addr) {
                unlink_forward_unreachable_blocks(
                    func,
                    &mut self.context.cbtable,
                    &self.context.icfg,
                );
            }
        }

        let mut orphan_blocks = Vec::new();

        self.context.cbtable.for_each(|addr, blk| {
            if blk.function() == FunctionId::default() {
                orphan_blocks.push((*addr, blk.node()));
            }
        });

        for (addr, nx) in orphan_blocks {
            self.context.cbtable.remove_point(addr);
            self.context.icfg.remove_node(nx);
        }

        *self.state.itable = self.context.itable.into();
    }
}

impl<'a, T> GuidedICFGBuilder<'a, T> {
    pub fn state(&self) -> &T {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut T {
        &mut self.state
    }
}
