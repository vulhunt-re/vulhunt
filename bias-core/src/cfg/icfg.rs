use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Write;
use std::mem;
use std::ops::{Deref, DerefMut};

use ahash::{AHashMap, AHashSet};
use fixedbitset::FixedBitSet;
use fugue::fspec::FunctionSpecs;
use fugue::ir::disassembly::{ContextDatabase, IRBuilderArena, ParserContext};
use fugue::ir::error::Error as IRError;
use fugue::ir::Address;
use iset::IntervalSet;
use itertools::Itertools;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::EdgeRef;
pub use petgraph::Direction;
use roaring::treemap::RoaringTreemap as SetU64;

use super::block::BlockInfo;
use super::context::{ICFGExtendedContext, ICFGProjectContext};
use super::flow::FlowKind;
use super::insn::{InsnInfo, InsnInfoId, InsnInfoTable, InsnTable};
use super::specs::FunctionSpecManager;
use super::tables::TableRecovery;
use crate::arch::ebpf::ARCH_EBPF;
use crate::arch::{AddressRangeSet, Arch, ExpansionResult};
use crate::cfg::block::BlockInfoTable;
use crate::cio::TypeDB;
use crate::data::{DataTypeDB, PointerProvenance};
use crate::eval::{EvalError, IREvalConfig, IREvaluator};
use crate::inject::InjectionManager;
use crate::ir::stmt::StmtCache;
use crate::ir::InsnTarget;
use crate::kb::block::{CodeBlock, CodeBlockId, CodeBlockTable};
use crate::kb::function::{
    Function, FunctionEntryStrategy, FunctionId, FunctionInfo, FunctionTable,
};
use crate::kb::function_summary::FunctionSummaryTable;
use crate::kb::id::{Identifiable, MKey};
use crate::kb::table::MPointTable;
use crate::kb::xref::XRef;
use crate::lifter::Lifter;
use crate::loader::LoadedBinary;
use crate::project::analysis::AnalysisManager;
use crate::project::ProjectContext;
use crate::region::{Memory, Region};
use crate::symbols::SymbolTable;
use crate::Project;

pub type ICFGRepr = StableDiGraph<CodeBlockId, FlowKind>;

#[derive(Default, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct ICFG(ICFGRepr);

impl Deref for ICFG {
    type Target = StableDiGraph<CodeBlockId, FlowKind>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ICFG {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ICFG {
    pub fn degree(&self, blk: NodeIndex, direction: Direction) -> usize {
        self.edges_directed(blk, direction).count()
    }

    pub fn non_strict_chain<'a, C, P>(
        &self,
        blk: CodeBlockId,
        count: usize,
        context: C,
    ) -> Vec<(Address, Address)>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        let context = context.into();

        if let Some(bounds) = self.non_strict_bounds(blk, context) {
            let mut chain = vec![bounds];
            let mut count = count;

            let mut incoming = bounds.0;

            while count > 0 {
                let blk = if let Some(blk) = context.cbtable.get_point(&incoming) {
                    blk
                } else {
                    break;
                };

                let mut in_blks = self
                    .edges_directed(blk.node(), Direction::Incoming)
                    .filter(|e| !e.weight().is_call());

                let next_in = if let Some(next_in) = in_blks.next().map(|e| self[e.source()]) {
                    next_in
                } else {
                    break;
                };

                if in_blks.next().is_some() {
                    break;
                }

                if let Some(nbounds) = self.non_strict_bounds(next_in, context) {
                    incoming = nbounds.0;
                    chain.push(nbounds);
                } else {
                    break;
                }

                count -= 1;
            }

            chain.reverse();
            chain
        } else {
            Vec::with_capacity(0)
        }
    }

    pub fn non_strict_blocks<'a, C, P>(
        &self,
        blk: CodeBlockId,
        context: C,
    ) -> Vec<(Address, Address)>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        let context = context.into();

        let block = match context.cbtable.get(blk) {
            None => return Default::default(),
            Some(block) => block,
        };

        let start = block.address();

        let mut last_id = block.node();

        // call and fall: if get next if outgoing from current is only call and fall
        let call_and_fall = |blk: NodeIndex| -> Option<NodeIndex> {
            let mut next = None;
            for out in self.edges_directed(blk, Direction::Outgoing) {
                if out.weight().is_call() {
                    continue;
                } else if out.weight().is_fall() {
                    next = Some(out.target());
                } else {
                    return None;
                }
            }
            next
        };

        let semantic_fall = |blk: NodeIndex| -> Option<NodeIndex> {
            let mut next = None;
            let mut fall = None;

            // check outgoing edges all go to the same destination
            for out in self.edges_directed(blk, Direction::Outgoing) {
                if out.weight().is_branch() {
                    if let Some(ref node) = next {
                        if out.target() != *node {
                            return None;
                        }
                    } else {
                        next = Some(out.target());
                    }
                } else if out.weight().is_fall() {
                    fall = Some(out.target());
                } else {
                    return None;
                }
            }

            if next != fall {
                None
            } else if let Some(next) = next {
                // check all incoming edges into fall destination are from
                // the same source node (i.e., this node).
                let all_in_same = self
                    .edges_directed(next, Direction::Incoming)
                    .map(|e| e.source())
                    .all_equal();
                if all_in_same {
                    fall
                } else {
                    None
                }
            } else {
                None
            }
        };

        // non-strict: if outgoing is only call and/or fall, and next only has fall
        // incoming OR if semantic fall, then join
        let non_strict = |id: NodeIndex| -> Option<NodeIndex> {
            call_and_fall(id)
                .and_then(|nid| {
                    if self.degree(nid, Direction::Incoming) == 1 {
                        Some(nid)
                    } else {
                        None
                    }
                })
                .or_else(|| semantic_fall(id))
        };

        let mut bounds = vec![(start, block.last_address())];

        while let Some(nx) = non_strict(last_id) {
            last_id = nx;

            let nblock = &context.cbtable[self.0[last_id]];

            bounds.push((nblock.address(), nblock.last_address()));
        }

        bounds
    }

    pub fn non_strict_bounds<'a, C, P>(
        &self,
        blk: CodeBlockId,
        context: C,
    ) -> Option<(Address, Address)>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        let context = context.into();

        let block = context.cbtable.get(blk)?;
        let start = block.address();

        let mut last_id = block.node();

        // call and fall: if get next if outgoing from current is only call and fall
        let call_and_fall = |blk: NodeIndex| -> Option<NodeIndex> {
            let mut next = None;
            for out in self.edges_directed(blk, Direction::Outgoing) {
                if out.weight().is_call() {
                    continue;
                } else if out.weight().is_fall() {
                    next = Some(out.target());
                } else {
                    return None;
                }
            }
            next
        };

        let semantic_fall = |blk: NodeIndex| -> Option<NodeIndex> {
            let mut next = None;
            let mut fall = None;

            // check outgoing edges all go to the same destination
            for out in self.edges_directed(blk, Direction::Outgoing) {
                if out.weight().is_branch() {
                    if let Some(ref node) = next {
                        if out.target() != *node {
                            return None;
                        }
                    } else {
                        next = Some(out.target());
                    }
                } else if out.weight().is_fall() {
                    fall = Some(out.target());
                } else {
                    return None;
                }
            }

            if next != fall {
                None
            } else if let Some(next) = next {
                // check all incoming edges into fall destination are from
                // the same source node (i.e., this node).
                let all_in_same = self
                    .edges_directed(next, Direction::Incoming)
                    .map(|e| e.source())
                    .all_equal();
                if all_in_same {
                    fall
                } else {
                    None
                }
            } else {
                None
            }
        };

        // non-strict: if outgoing is only call and/or fall, and next only has fall
        // incoming OR if semantic fall, then join
        let non_strict = |id: NodeIndex| -> Option<NodeIndex> {
            call_and_fall(id)
                .and_then(|nid| {
                    if self.degree(nid, Direction::Incoming) == 1 {
                        Some(nid)
                    } else {
                        None
                    }
                })
                .or_else(|| semantic_fall(id))
        };

        while let Some(nx) = non_strict(last_id) {
            last_id = nx;
        }

        let end = if last_id != block.node() {
            let nblock = &context.cbtable[self.0[last_id]];
            nblock.last_address()
        } else {
            block.last_address()
        };

        Some((start, end))
    }

    pub fn for_each_called_by<'a, F, C, P>(&self, fcn: FunctionId, context: C, mut f: F)
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
        F: FnMut(&'a Function, ProjectContext<'a, P>),
    {
        let context = context.into();
        let mut seen = FixedBitSet::with_capacity(context.ftable.len());

        let fcn = &context.ftable[fcn];
        let mut work = vec![fcn];

        while let Some(fcn) = work.pop() {
            for blk in fcn.blocks().keys() {
                let blk = &context.cbtable[*blk];

                for succ in self
                    .edges_directed(blk.node(), Direction::Outgoing)
                    .filter(|e| e.weight().is_call())
                {
                    // NOTE: if the function has multiple entries, then we only
                    // consider the "main" entrypoint via this logic.
                    let nfblk = &context.cbtable[context.icfg[succ.target()]];
                    if let Some(nf) = context.ftable.get_point(nfblk.address()) {
                        if seen.contains(nf.id().index()) {
                            continue;
                        }

                        f(nf, context);

                        seen.insert(nf.id().index());
                        work.push(nf);
                    }
                }
            }
        }
    }
}

pub struct ICFGBuilder<'a, 'b> {
    context: ICFGBuilderContext<'a>,
    config: &'b Configuration<'b>,
    blocks: AHashMap<Address, (NodeIndex, CodeBlockId)>,
    functions: AHashMap<Address, FunctionInfo>, // possible function starts
    invalids: AHashSet<Address>,
    specifications: FunctionSpecManager<'b>,
    semantic_nops: BTreeMap<Address, InsnInfoId>, // ordered by address
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallKind {
    Inside,
    Outside,
}

pub(super) fn expand_function<'a, A, T>(
    arch: &T,
    func: &mut Function,
    lifter: &Lifter,
    address: A,
    blocks: &BlockInfoTable<'_>,
    icfg: &mut ICFG,
    functions: &AHashMap<Address, FunctionInfo>,
) -> ExpansionResult
where
    A: Borrow<Address>,
    T: Arch,
{
    let address = address.borrow();
    if let Some(id) = blocks.id(address) {
        arch.expand_function_block(func, lifter, id, blocks, icfg, functions)
    } else {
        ExpansionResult::Error
    }
}

fn unlink_forward_unreachable_blocks(
    func: &mut Function,
    blocks: &BlockInfoTable<'_>,
    icfg: &mut ICFG,
) {
    let mut seen = BTreeSet::new();
    let mut worklist = VecDeque::new();

    worklist.push_back(func.entry());

    // collect forward reachable blocks
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

    // unlink unreachable blocks
    let faddr = func.address();
    for (blk, _) in func.blocks_mut().extract_if(|id, _| !seen.contains(id)) {
        let block = &blocks[blk];
        tracing::debug!("unlinking unreachable block {} from {faddr}", block.start());
        block.unmark_in_function();
    }
}

fn rollback_function(start: Address, ftable: &mut FunctionTable, blocks: &BlockInfoTable<'_>) {
    let Some(func) = ftable.remove_point(start) else {
        return;
    };

    for blk in func.blocks().keys().copied() {
        let block = &blocks[blk];
        block.unmark_in_function();
    }
}

#[derive(Clone)]
pub struct Configuration<'a> {
    pub use_loader_hints: bool,
    pub use_function_start_patterns: bool,
    pub use_function_specifications: Cow<'a, [FunctionSpecs]>,
    pub platform: Option<&'a str>,
    pub resolve_indirects: bool,
    pub resolve_switch_tables_greedily: bool,
    pub compute_statistics: Option<&'a str>,
    pub compute_block_statistics: bool,
    pub scan_from_known_entry: bool,
    pub scan_indirect_xrefs_for_code: bool,
    pub scan_call_target_segments: bool,
    pub mark_xrefs_as_taken: bool,
    pub mark_xrefs_table_limit: usize,
    pub propagate_invalidity: bool,
    pub avoid_invalid_or_nonsense_ranges: bool,
    pub ir_allocator_reset_period: usize,
}

impl<'a> AsRef<Configuration<'a>> for Configuration<'a> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a> Default for Configuration<'a> {
    fn default() -> Self {
        Self {
            use_loader_hints: true,
            use_function_start_patterns: true,
            use_function_specifications: Default::default(),
            platform: None,
            resolve_indirects: true,
            resolve_switch_tables_greedily: true,
            compute_statistics: None,
            compute_block_statistics: false,
            scan_call_target_segments: false,
            scan_from_known_entry: false,
            scan_indirect_xrefs_for_code: true,
            mark_xrefs_as_taken: true,
            mark_xrefs_table_limit: 512,
            propagate_invalidity: true,
            avoid_invalid_or_nonsense_ranges: true,
            ir_allocator_reset_period: 100_000,
        }
    }
}

pub(super) struct FunctionBuilder<'a, 'b> {
    pub blocks: &'a MPointTable<Address, BlockInfo<'b>>,
    pub icfg: &'a ICFG,
}

impl<'a, 'b> FunctionEntryStrategy for FunctionBuilder<'a, 'b> {
    type T = (bool, bool, Address);

    fn priority(&mut self, block: CodeBlockId, f: FunctionId) -> Self::T {
        let block = &self.blocks[block];
        block.mark_in_function(f);
        (
            !block.is_called(),
            self.icfg
                .edges_directed(block.node(), Direction::Incoming)
                .next()
                .is_some(),
            block.start(),
        )
    }

    fn entry(&mut self, _block: CodeBlockId, _f: FunctionId, priority: Self::T) -> Address {
        priority.2
    }
}

pub struct ICFGBuilderContext<'a> {
    pub lifter: &'a Lifter,
    pub icfg: &'a mut ICFG,
    pub datadb: &'a mut DataTypeDB,
    pub itable: InsnInfoTable,
    pub cbtable: &'a mut CodeBlockTable,
    pub ftable: &'a mut FunctionTable,
    pub fstable: &'a mut FunctionSummaryTable,
    pub symtab: &'a mut SymbolTable,
    pub memory: &'a Memory,
    pub typedb: &'a TypeDB,
    pub analyses: &'a AnalysisManager,
    pub injections: &'a InjectionManager,
}

impl<'a> ICFGBuilderContext<'a> {
    pub fn evaluator(&self, config: IREvalConfig) -> Result<IREvaluator, EvalError> {
        IREvaluator::new_with(self.tables(), config)
    }

    pub fn tables(&self) -> ProjectContext<'_, InsnInfoTable> {
        ProjectContext {
            lifter: self.lifter,
            icfg: &*self.icfg,
            datadb: &*self.datadb,
            itable: &self.itable,
            cbtable: &*self.cbtable,
            ftable: &*self.ftable,
            fstable: &*self.fstable,
            symtab: &*self.symtab,
            memory: &*self.memory,
            typedb: &*self.typedb,
            analyses: &*self.analyses,
            injections: &*self.injections,
        }
    }
}

impl<'a, 'b> ICFGBuilder<'a, 'b> {
    pub fn build<T>(project: &'a mut Project, binary: &'a T)
    where
        T: LoadedBinary + ?Sized,
    {
        Self::build_with(project, binary, &Default::default())
    }

    pub fn build_with<T>(project: &'a mut Project, binary: &'a T, config: &Configuration<'b>)
    where
        T: LoadedBinary + ?Sized,
    {
        let segments = project
            .memory
            .regions()
            .values(..)
            .filter(|r| {
                if project.lifter.arch().id() == ARCH_EBPF {
                    r.is_code()
                } else {
                    let contains_entry = binary
                        .entry_point()
                        .as_ref()
                        .map(|entry| r.bounds().contains(entry))
                        .unwrap_or_default();

                    let name = r.name().to_ascii_lowercase();

                    let known_section = name.contains("text")
                        || name.contains("code")
                        || name.contains("efi")
                        || name.contains("plt")
                        || name.contains("init")
                        || name.contains("extern");
                    let unknown_section = r.is_code() && name == "unnamed";

                    contains_entry || known_section || unknown_section
                }
            })
            .collect::<VecDeque<_>>();

        let itable = mem::take(&mut project.itable).into();

        let mut ctx = project.lifter().context();
        let mut builder = ICFGBuilder {
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
            specifications: FunctionSpecManager::new(&config, &project.lifter),
            config: &config,
            blocks: Default::default(),
            functions: Default::default(),
            invalids: Default::default(),
            semantic_nops: Default::default(),
        };

        builder.explore(binary, &mut ctx, segments);

        let itable = builder.context.itable.into();

        project.itable = itable;

        let specifications = builder.specifications;

        project
            .load_symbols(&specifications)
            .expect("always succeeds");
    }

    #[inline(always)]
    fn update<'az>(
        irb: &'az IRBuilderArena,
        ctx: &mut ContextDatabase,
        pctx: &mut ParserContext<'a, 'az>,
        cache: &mut StmtCache,
        cfg: &mut Self,
        wl: &mut VecDeque<Address>,
        xrefs: &mut Vec<XRef>,
        xref_properties: &mut BTreeMap<Address, PointerProvenance>,
        address: &Address,
        current_region: &Region,
        view: &[u8],
        avoids: &AddressRangeSet,
    ) -> Result<(FallKind, Address, usize), IRError> {
        let res = {
            || -> Result<(FallKind, Address, usize, InsnInfo), IRError> {
                let ilink =
                    InsnInfo::new(cfg.context.lifter, irb, ctx, pctx, cache, *address, view)?;

                // add unvisited destinations
                ilink.with_target_addresses(|addr, is_call| {
                    if cfg.context.memory.contains(&addr) {
                        if is_call {
                            cfg.functions.insert(addr, FunctionInfo::default());
                        }
                        if addr != *address && !avoids.contains_avoid(addr) {
                            cfg.blocks.insert(addr, Default::default());

                            if !cfg.invalids.contains(&addr)
                                && cfg.context.itable.insn(&addr).is_none()
                            {
                                wl.push_back(addr);
                            }
                        }
                    }
                });

                let nfall = ilink.next_address();

                if !ilink.is_nop() && cfg.semantic_nops.contains_key(address) {
                    tracing::trace!(
                        "marking {} (is nop: {}) for:\n{}",
                        address,
                        ilink.is_nop(),
                        ilink.insn()
                    );
                    ilink.mark_maybe_taken();
                    if !avoids.contains_avoid(*address) {
                        cfg.blocks.insert(*address, Default::default());
                    }
                }

                if ilink.has_fall() {
                    if ilink.is_flow() && !avoids.contains_avoid(nfall) {
                        cfg.blocks.insert(nfall, Default::default());
                    }

                    Ok((FallKind::Inside, nfall, ilink.len(), ilink))
                } else {
                    Ok((FallKind::Outside, nfall, ilink.len(), ilink))
                }
            }()
        };

        match res {
            Ok((k, a, n, insn)) => {
                let is_nop = insn.is_nop();

                if cfg.config.mark_xrefs_as_taken {
                    insn.insn().xrefs_into(cfg.context.memory, xrefs);
                    for xref in xrefs.drain(..) {
                        let target = xref.target();
                        if xref.kind().is_load()
                        /* && !cfg.blocks.contains_key(&target) */
                        {
                            if !avoids.contains(target)
                                && !cfg.invalids.contains(&target)
                                && cfg.context.itable.insn(&target).is_none()
                            {
                                tracing::trace!("marking {target} as unexplored via {address}");
                                wl.push_back(target);
                            }

                            if cfg.config.scan_indirect_xrefs_for_code {
                                // try to process derived references if xref is to a table
                                if let Some(r) = cfg.context.memory.find_region(&xref.target()) {
                                    let mut position = xref.target();
                                    let shift = cfg.context.lifter.global_space().address_size();
                                    let bits = shift as u32 * 8;

                                    while let Ok(p) = r.read_pointer(position, bits) {
                                        if current_region.bounds().contains(&p) {
                                            xref_properties
                                                .entry(p)
                                                .or_insert(PointerProvenance::FROM_DATA);

                                            if !avoids.contains(p)
                                                && !cfg.invalids.contains(&p)
                                                && cfg.context.itable.insn(&p).is_none()
                                            {
                                                tracing::trace!("marking {p} as unexplored via {address}/{target} (indirectly)");
                                                wl.push_back(p);
                                            }
                                        } else {
                                            break;
                                        }

                                        position = position + shift;
                                    }
                                }
                            }
                        }
                    }
                }

                let id = cfg.context.itable.insert(insn);
                if is_nop {
                    // fall from nop
                    tracing::trace!("marking semantic nop: {}", *address);
                    cfg.semantic_nops.insert(a, id);
                }

                Ok((k, a, n))
            }
            Err(e) => {
                cfg.invalids.insert(*address);
                Err(e)
            }
        }
    }

    fn explore<T>(&mut self, binary: &T, ctx: &mut ContextDatabase, segments: VecDeque<&Region>)
    where
        T: LoadedBinary + ?Sized,
    {
        let mut wl = VecDeque::new();
        let mut irb = self.context.lifter.irb(4096);
        let mut bounds = IntervalSet::new();
        let mut pending = IntervalSet::new();
        let mut cache = StmtCache::default();
        let mut segments = segments;
        let mut xrefs = Vec::new();
        let mut xref_properties = BTreeMap::new();
        let mut func_starts_by_pattern = BTreeSet::new();
        let mut failures = SetU64::new();

        for segment in segments.iter() {
            tracing::trace!(
                "marking segment {}-{} as unexplored",
                segment.bounds().start,
                segment.bounds().end
            );
            pending.insert(segment.bounds());
        }

        while let Some(segment) = segments.pop_front() {
            tracing::trace!(
                "exploring segment {}-{}",
                segment.bounds().start,
                segment.bounds().end
            );

            bounds.insert(segment.bounds());

            let start = if self.config.scan_from_known_entry {
                binary
                    .entry_point()
                    .and_then(|ep| {
                        if segment.interval().contains(&ep) {
                            Some(ep)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(*segment.address())
            } else {
                *segment.address()
            };

            wl.push_back(start);

            if let Some(entry) = binary.entry_point() {
                // mark real EP as taken
                wl.push_back(entry);
            }

            let avoids = if self.config.avoid_invalid_or_nonsense_ranges {
                self.context
                    .lifter
                    .arch()
                    .invalid_or_nonsense_ranges(start, segment.bytes())
            } else {
                Default::default()
            };

            if self.config.use_function_start_patterns {
                self.context.lifter.arch().for_each_function_by_pattern(
                    &self.context.lifter,
                    ctx,
                    &segment,
                    &mut |addr| {
                        wl.push_back(addr);
                        func_starts_by_pattern.insert(addr);
                    },
                );
            }

            if self.config.use_loader_hints {
                binary.for_each_function(|fcn| {
                    if segment.contains(fcn.entry) {
                        wl.push_back(fcn.entry);
                        fcn.context
                            .apply(self.context.lifter.address_value(fcn.entry), ctx);
                    }
                });
            }

            'sweep: while !wl.is_empty() {
                let last_ir_allocator_reset = self.context.itable.len();
                irb.reset();

                let mut pctx =
                    ParserContext::empty(&irb, self.context.lifter.translator().manager());

                // 1. linear sweep the region looking for all blocks based on jump/calls
                while let Some(nstart) = wl.pop_front() {
                    if self.context.itable.insn(nstart).is_some() {
                        self.blocks.insert(nstart, Default::default());
                        continue;
                    }

                    if failures.contains(nstart.offset()) {
                        continue;
                    }

                    let view = match segment.view_bytes_from(nstart) {
                        Ok(view) => view,
                        Err(_) => {
                            continue; // skip failures
                        }
                    };

                    let mut offset = 0;
                    let mut address = nstart;
                    //let mut last_padding = false;

                    // 1.1. sweep until we encounter an instruction that does not fall
                    while offset < view.len() {
                        let res = Self::update(
                            &irb,
                            ctx,
                            &mut pctx,
                            &mut cache,
                            self,
                            &mut wl,
                            &mut xrefs,
                            &mut xref_properties,
                            &address,
                            segment,
                            &view[offset..],
                            &avoids,
                        );

                        match res {
                            Ok((kind, nfall, noffset)) => {
                                address = nfall;
                                offset += noffset;

                                if kind == FallKind::Outside {
                                    //address = nfall;
                                    offset += noffset;

                                    //last_padding = false;
                                    break;
                                }

                                // TODO: rewrite this bit
                                // if last padding then maybe taken
                                // last_padding = self.semantic_nops.contains_key(&address);

                                //address = nfall;
                                //offset += noffset;
                            }
                            Err(_) => {
                                failures.insert(address.offset());
                                // try next address as new block
                                // TODO: maybe this should be alignment based?
                                //
                                // E.g., 2 + for Thumb, 4 for ARM, etc.
                                //
                                address = address + 1u64;
                                break;
                            }
                        }

                        if self.context.itable.insn(address).is_some() {
                            break;
                        }
                    }

                    if offset != 0 {
                        // made some progress
                        self.blocks.insert(nstart, Default::default());
                    }

                    if let (true, next) = avoids.next_after_avoid(address) {
                        if let Some(next) = next {
                            tracing::trace!(
                                "marking {} as next block after avoid as unexplored",
                                next
                            );
                            wl.push_back(next);
                        }
                    } else {
                        tracing::trace!("marking {} as unexplored", address);
                        wl.push_back(address);
                    }

                    if (self.context.itable.len() - last_ir_allocator_reset)
                        >= self.config.ir_allocator_reset_period
                    {
                        continue 'sweep;
                    }
                }
            }

            // processed the segment; update the regions if guided by call targets
            if self.config.scan_call_target_segments {
                for addr in self.functions.keys() {
                    let start = *addr;
                    let end = start + 1usize;

                    if start < end && pending.has_overlap(start..end) {
                        continue;
                    }

                    let Some(region) = self.context.memory.find_region(addr) else {
                        continue;
                    };

                    if region.is_code() {
                        pending.insert(region.bounds());
                        segments.push_back(region);
                    }
                }
            }
        }

        // clean-up
        drop(irb);
        drop(cache);
        drop(failures);

        if self.config.mark_xrefs_as_taken {
            let data = DataTypeDB::new(self.context.lifter);

            let shift = self.context.lifter.global_space().address_size();
            let bits = shift as u32 * 8;

            let mut processed = BTreeSet::new();
            let mut xrefs = Vec::new();

            // 2.1. mark possible starts via data-xrefs
            for iinfo in self.context.itable.iter() {
                iinfo.insn().xrefs_into(self.context.memory, &mut xrefs);
                for xref in xrefs
                    .drain(..)
                    .filter(|xref| xref.kind().is_load() && processed.insert(xref.target()))
                {
                    if xref.kind().is_load() {
                        if let Some(tinfo) = self.context.itable.insn(xref.target()) {
                            tracing::trace!(
                                "marking {} as maybe taken (via {})",
                                tinfo.address(),
                                xref.source()
                            );

                            let r = self.context.memory.find_region(&xref.target()).unwrap();
                            if let Ok(p) = r.read_pointer(xref.target(), bits) {
                                if let Some(rp) = self.context.memory.find_region(p) {
                                    let dt = data.identify_data_via(self.context.memory, rp, p);
                                    let prov = PointerProvenance::from(dt);

                                    *xref_properties.entry(xref.target()).or_insert(prov) |= prov;
                                }
                            }

                            tinfo.mark_maybe_taken();
                            self.blocks.insert(tinfo.address(), Default::default());
                        }

                        // try to process derived references if xref is to a table
                        if let Some(r) = self.context.memory.find_region(&xref.target()) {
                            let mut position = xref.target();
                            let mut counter = 0usize;

                            while let Ok(p) = r.read_pointer(position, bits) {
                                if counter >= self.config.mark_xrefs_table_limit {
                                    break;
                                }

                                if let Some(tinfo) = self.context.itable.insn(p) {
                                    let dt =
                                        data.identify_data_via(self.context.memory, r, position);
                                    if let Some(d) = dt.as_ref() {
                                        tracing::trace!("potential indirect code pointer via {} at {position} (data: {d})", tinfo.address());
                                    }

                                    let prov = PointerProvenance::from(dt);
                                    *xref_properties.entry(tinfo.address()).or_insert(prov) |= prov;

                                    tracing::trace!(
                                        "marking {} as maybe taken (indirect code pointer)",
                                        tinfo.address(),
                                    );

                                    tinfo.mark_maybe_taken();
                                    self.blocks.insert(tinfo.address(), Default::default());
                                } else if !self.context.memory.contains(&p) {
                                    tracing::trace!(
                                        "stopped marking indirect code pointers via {} at {p}",
                                        iinfo.address()
                                    );
                                    break;
                                }

                                counter += 1;
                                position = position + shift;
                            }
                        }
                    }
                }
            }
        }

        let mut hints = AHashSet::new();

        if let Some(entry) = binary.entry_point() {
            if let Some(tinfo) = self.context.itable.insn(entry) {
                tinfo.mark_call_target();
                tinfo.mark_loader_hint();
                self.blocks.entry(tinfo.address()).or_default();
                hints.insert(tinfo.address());
            }
        }

        if self.config.use_loader_hints {
            binary.for_each_function(|fcn| {
                if let Some(tinfo) = self.context.itable.insn(fcn.entry) {
                    tinfo.mark_call_target();
                    tinfo.mark_loader_hint();

                    let curr_addr = tinfo.address();
                    self.blocks.entry(curr_addr).or_default();
                    hints.insert(curr_addr);

                    self.functions
                        .entry(curr_addr)
                        .or_default()
                        .extend(fcn.properties);
                }
            });
        }

        // 3. mark explicit branch+call destinations
        for start in self.blocks.keys() {
            if let Some(link) = self.context.itable.insn_mut(start) {
                link.mark_branch_target();
                if self.functions.contains_key(start) {
                    link.mark_call_target();
                }
            }
        }

        // 4. create linked block mapping
        let mut blocks = MPointTable::<Address, BlockInfo<'_>>::default();

        // 4.1. build initial CFG with block IDs
        blocks.reserve(self.blocks.len());

        for (addr, (nx, bid)) in self.blocks.iter_mut() {
            blocks.insert_with(*addr, |_addr, id| {
                *bid = id;
                *nx = self.context.icfg.add_node(id);

                tracing::debug!("adding block: {addr} -> {nx:?}");

                let mut block = BlockInfo::default();

                block.update_id(id);
                block.update_node(*nx);

                block
            });
        }

        // 5 build block and detect if invalid
        let mut indirect_blocks = Vec::new();
        blocks.for_each_mut(|addr, blk| {
            blk.update_with(*addr, &self.context.itable, &self.blocks, self.context.icfg);

            // 5.1 mark indirects
            if self.config.resolve_indirects && blk.has_unresolved_targets() {
                indirect_blocks.push(blk.id());
            }
        });

        // 7.0 switch table and indirects resolution
        if !indirect_blocks.is_empty() {
            //indirect_blocks.sort_by_key(|&(k, _)| k);
            let icfg_context = ICFGProjectContext {
                lifter: &self.context.lifter,
                icfg: &mut self.context.icfg,
                datadb: &self.context.datadb,
                itable: &self.context.itable,
                cbtable: &self.context.cbtable,
                ftable: &self.context.ftable,
                fstable: &self.context.fstable,
                symtab: &self.context.symtab,
                memory: &self.context.memory,
                typedb: &self.context.typedb,
                analyses: &self.context.analyses,
                injections: &self.context.injections,
            };

            TableRecovery::new(&self.config).find_edges_simplified(
                icfg_context,
                &mut self.functions,
                &mut blocks,
                &mut self.blocks,
                &mut indirect_blocks,
            );
        }

        if self.config.use_loader_hints {
            binary.for_each_function(|fcn| {
                // if the block here is marked as invalid, we will never add it
                // we therefore remove the invalidity on such blocks.
                if let Some(blk) = blocks.get_point_mut(fcn.entry) {
                    if blk.has_insns() && blk.is_invalid() {
                        blk.clear_invalid();
                    }
                }
            });
        }

        // 7.1 cfg-altering function marking
        // find and mark functions that have a significant impact on control flow
        // and function recovery (e.g., special externals/PLT/non-returning functions)
        let mut non_returning_functions = BTreeSet::new();
        let mut tail_functions = BTreeSet::new();
        {
            let mut icfg_context = ICFGExtendedContext {
                lifter: &self.context.lifter,
                icfg: &mut self.context.icfg,
                datadb: &self.context.datadb,
                itable: &self.context.itable,
                cbtable: &self.context.cbtable,
                ftable: &self.context.ftable,
                fstable: &self.context.fstable,
                symtab: &self.context.symtab,
                memory: &self.context.memory,
                typedb: &self.context.typedb,
                analyses: &self.context.analyses,
                injections: &self.context.injections,
                specifications: &self.specifications,
                block_table: &mut blocks,
                block_map: &mut self.blocks,
                non_returning_functions: &mut non_returning_functions,
                tail_functions: &mut tail_functions,
            };

            binary.for_each_critical_function(&mut icfg_context, |func_addr| {
                tracing::trace!("adding critical function {func_addr}");
                self.functions.entry(func_addr).or_default();
                hints.insert(func_addr);
            });
        }

        // 8. detect "bad blocks" (those that fall into invalid
        // blocks/regions marked as data)
        if self.config.propagate_invalidity {
            // from current blocks, find all overlapping ranges
            let ranges = blocks
                .values()
                .filter_map(|blk| {
                    if blk.has_insns() {
                        Some(blk.start()..blk.end())
                    } else {
                        None
                    }
                })
                .collect::<IntervalSet<Address>>();

            let mut marked_invalid = true;
            while marked_invalid {
                marked_invalid = false;
                tracing::trace!("performing invalid block detection pass");
                blocks.values().for_each(|blk| {
                    if blk.is_invalid() {
                        tracing::trace!("removing invalid {:?}", blk.node());
                        self.context.icfg.remove_node(blk.node());
                        return
                    }

                    // looks like a table of pointers
                    if blk.insns().all(|insn| xref_properties.contains_key(&insn.address())) {
                        let no_edges = self.context.icfg.edges_directed(blk.node(), Direction::Incoming).next().is_none();

                        if no_edges && !hints.contains(&blk.start()) {
                            let addr = blk.start();
                            tracing::debug!("marking invalid (assumed jump table): {}", addr);
                            blk.mark_invalid();

                            let mut invalid_wl = vec![blk];
                            while let Some(bb) = invalid_wl.pop() {
                                for e in self.context.icfg.edges_directed(bb.node(), Direction::Outgoing) {
                                    let mut target_in = self.context.icfg.edges_directed(e.target(), Direction::Incoming);

                                    let first = target_in.next();
                                    let second = target_in.next();

                                    if target_in.count() > 0 {
                                        continue
                                    }

                                    let can_drop = second.is_none() || matches!(first, Some(t) if t.source() == e.target()) || matches!(second, Some(t) if t.source() == e.target());

                                    if can_drop {
                                        // only reachable by invalid
                                        let sbb = &blocks[self.context.icfg[e.target()]];
                                        if !sbb.is_invalid() && !sbb.first_insn().is_maybe_taken() && !hints.contains(&sbb.start()) {
                                            tracing::debug!("only reachable by invalid {}", sbb.start());
                                            invalid_wl.push(sbb);
                                        }
                                    }
                                }
                                bb.mark_invalid();
                                self.context.icfg.remove_node(bb.node());
                            }

                            self.context.icfg.remove_node(blk.node());
                            self.invalids.insert(addr);
                            marked_invalid = true;
                            return
                        }
                    }

                    // looks like data
                    if matches!(xref_properties.get(&blk.start()), Some(prop) if prop.contains(PointerProvenance::FROM_DATA)) {
                        let no_edges = self.context.icfg.edges_directed(blk.node(), Direction::Incoming).next().is_none();
                        let overlaps = ranges.overlap(blk.start()).count() > 1;

                        if no_edges && overlaps && !hints.contains(&blk.start()) {
                            let addr = blk.start();
                            tracing::debug!("marking invalid (probably data): {}", addr);
                            blk.mark_invalid();

                            let mut invalid_wl = vec![blk];
                            while let Some(bb) = invalid_wl.pop() {
                                for e in self.context.icfg.edges_directed(bb.node(), Direction::Outgoing) {
                                    let mut target_in = self.context.icfg.edges_directed(e.target(), Direction::Incoming);

                                    let first = target_in.next();
                                    let second = target_in.next();

                                    if target_in.count() > 0 {
                                        continue
                                    }

                                    let can_drop = second.is_none() || matches!(first, Some(t) if t.source() == e.target()) || matches!(second, Some(t) if t.source() == e.target());

                                    if can_drop {
                                        // only reachable by invalid
                                        let sbb = &blocks[self.context.icfg[e.target()]];
                                        if !sbb.is_invalid() && !sbb.first_insn().is_maybe_taken() && !hints.contains(&sbb.start()) {
                                            tracing::debug!("only reachable by invalid {}", sbb.start());
                                            invalid_wl.push(sbb);
                                        }
                                    }
                                }
                                bb.mark_invalid();
                                self.context.icfg.remove_node(bb.node());
                            }

                            self.context.icfg.remove_node(blk.node());
                            self.invalids.insert(addr);
                            marked_invalid = true;
                            return
                        }
                    }

                    if !blk.is_trap() && blk.is_padding() && !blk.is_loader_hint() {
                        let no_edges = self.context.icfg.edges_directed(blk.node(), Direction::Incoming).next().is_none();

                        // no true links into this block => real padding
                        if no_edges && !hints.contains(&blk.start()) {
                            let addr = blk.start();
                            tracing::debug!("marking invalid (no real incoming edges): {}", addr);

                            blk.mark_invalid();

                            let mut invalid_wl = vec![blk];
                            while let Some(bb) = invalid_wl.pop() {
                                for e in self.context.icfg.edges_directed(bb.node(), Direction::Outgoing) {
                                    if self.context.icfg.edges_directed(e.target(), Direction::Incoming).count() == 1 {
                                        // only reachable by invalid
                                        let sbb = &blocks[self.context.icfg[e.target()]];
                                        if !sbb.is_invalid() && !sbb.first_insn().is_maybe_taken() && !hints.contains(&sbb.start()) {
                                            tracing::debug!("only reachable by invalid {}", sbb.start());
                                            invalid_wl.push(sbb);
                                        }
                                    }
                                }
                                bb.mark_invalid();
                                self.context.icfg.remove_node(bb.node());
                            }

                            self.invalids.insert(addr);
                            marked_invalid = true;
                            return
                        }
                    }

                    if !blk.is_terminal() && matches!(blocks.get_point(blk.last_insn().next_address()), Some(nblk) if nblk.is_invalid()) && !hints.contains(&blk.start()) {
                        let addr = blk.start();

                        // if the call looks like nonsense, we might have disassembled data => discard
                        let call_is_invalid = if blk.last_insn().is_call() {
                            let mut is_call_tgt_invalid = true;
                            for (_, target) in blk.last_insn().targets().iter() {
                                if let InsnTarget::InterSub(bt) = target {
                                    if let Some(loc) = bt.location_value() {
                                        is_call_tgt_invalid = !self.context.itable.contains(loc.address());
                                    }
                                    break;

                                }
                            }
                            is_call_tgt_invalid
                        } else {
                            false
                        };

                        if !blk.last_insn().is_call() || call_is_invalid {
                            tracing::debug!("marking invalid (falls to invalid): {}", addr);
                            blk.mark_invalid();

                            let mut invalid_wl = vec![blk];
                            while let Some(bb) = invalid_wl.pop() {
                                for e in self.context.icfg.edges_directed(bb.node(), Direction::Outgoing) {
                                    if self.context.icfg.edges_directed(e.target(), Direction::Incoming).count() == 1 {
                                        // only reachable by invalid
                                        let sbb = &blocks[self.context.icfg[e.target()]];
                                        if !sbb.is_invalid() && !sbb.first_insn().is_maybe_taken() && !hints.contains(&sbb.start()) {
                                            tracing::debug!("only reachable by invalid {}", sbb.start());
                                            invalid_wl.push(sbb);
                                        }
                                    }
                                }
                                bb.mark_invalid();
                                self.context.icfg.remove_node(bb.node());
                            }

                            self.context.icfg.remove_node(blk.node());
                            self.invalids.insert(addr);
                            marked_invalid = true;
                            return
                        }
                    }

                    if ranges.overlap(blk.start()).count() > 1 {
                        let no_edges = self.context.icfg.edges_directed(blk.node(), Direction::Incoming).next().is_none();

                        if no_edges && !hints.contains(&blk.start()) {
                            let addr = blk.start();
                            tracing::debug!("marking invalid: {}", addr);

                            blk.mark_invalid();

                            let mut invalid_wl = vec![blk];
                            while let Some(bb) = invalid_wl.pop() {
                                for e in self.context.icfg.edges_directed(bb.node(), Direction::Outgoing) {
                                    if self.context.icfg.edges_directed(e.target(), Direction::Incoming).count() == 1 {
                                        // only reachable by invalid
                                        let sbb = &blocks[self.context.icfg[e.target()]];
                                        if !sbb.is_invalid() && !sbb.first_insn().is_maybe_taken() && !hints.contains(&sbb.start()) {
                                            tracing::debug!("only reachable by invalid {}", sbb.start());
                                            invalid_wl.push(sbb);
                                        }
                                    }
                                }
                                bb.mark_invalid();
                                self.context.icfg.remove_node(bb.node());
                            }

                            self.invalids.insert(addr);
                            marked_invalid = true;
                            return
                        }
                    }
                })
            }
        }

        // 9. final padding classification (i.e., unreachable blocks of just semantic NOP)
        //
        // NOTE: We can mark some functions as potentially non-returning in this step.
        //
        let mut override_flows_for = Vec::new();
        let mut fall_edges = Vec::new();

        blocks.values().for_each(|blk| {
            if !blk.is_trap() && blk.is_padding() {
                let mut non_returning_fall = false;
                let mut edge_count = 0;

                for e in self
                    .context
                    .icfg
                    .edges_directed(blk.node(), Direction::Incoming)
                {
                    edge_count += 1;
                    // mark source call as possibly non-returning
                    if e.weight().is_fall() {
                        for se in self
                            .context
                            .icfg
                            .edges_directed(e.source(), Direction::Outgoing)
                        {
                            if se.weight().is_call()
                                || se.weight().is_indirect()
                                || se.weight().is_return()
                            {
                                override_flows_for.push((se.source(), se.target()));
                                non_returning_fall = true;
                            }
                        }
                    }
                }

                for (src_node, tgt_node) in &override_flows_for {
                    self.context
                        .icfg
                        .update_edge(*src_node, *tgt_node, FlowKind::TailCallBranch);
                    for edge in self
                        .context
                        .icfg
                        .edges_directed(*src_node, Direction::Outgoing)
                    {
                        if edge.weight().is_fall() {
                            fall_edges.push(edge.id());
                            break;
                        }
                    }
                }
                override_flows_for.clear();

                // remove fall edge for caller block
                for fe in &fall_edges {
                    self.context.icfg.remove_edge(*fe);
                }
                fall_edges.clear();

                tracing::debug!(
                    "analysing padding block at {} (incoming: {})",
                    blk.start(),
                    edge_count
                );

                // no true links into this block => real padding
                if !(non_returning_fall || edge_count == 0) {
                    blk.clear_padding();
                }
            }
        });

        // 10. find function starts
        // 10.1. all obvious functions (xrefs from calls and symbol addresses)
        for (start, props) in self
            .functions
            .iter()
            .sorted_by_key(|(start, _)| *start)
            .rev()
        {
            tracing::debug!("expanding from: {}", start);
            let Some(fblk) = blocks.get_point(*start) else {
                tracing::debug!("block has not been recognised; not expanding");
                continue;
            };

            if hints.contains(&start) {
                // do not invalidate the "padding" block if it is contained in hints;
                // for example, on AArch64 with PAC enabled, blocks that start with
                // PACIASP instructions can be mistakenly marked as padding
                fblk.clear_padding();
            }

            if fblk.is_in_function() {
                if hints.contains(&start) {
                    let fid = fblk.function().unwrap();
                    let func = self.context.ftable.get(fid).unwrap();
                    tracing::debug!(
                        "{} is a function symbol but already in function {}",
                        fblk.start(),
                        func.address()
                    );
                }
                tracing::debug!("block already inside function; not expanding");
            } else if fblk.is_padding() || fblk.is_invalid() || !fblk.has_insns() {
                tracing::debug!("block at {start} is padding or invalid; not expanding");
            } else {
                let mut discard = false;
                self.context.ftable.insert_with(*start, |addr, id| {
                    let mut f = Function::new(id, *addr, fblk.id(), None, Default::default());

                    let lifter = self.context.lifter;
                    let arch = lifter.arch();

                    arch.compute_function_properties(&mut f, lifter, &ctx, &*self.context.icfg);

                    if expand_function(
                        arch,
                        &mut f,
                        lifter,
                        addr,
                        &blocks,
                        &mut self.context.icfg,
                        &self.functions,
                    )
                    .is_err()
                    {
                        discard = true;
                        tracing::debug!("error while expanding function at {}", addr);
                    }

                    props.apply(&mut f);

                    // unlink unreachable blocks
                    unlink_forward_unreachable_blocks(&mut f, &blocks, &mut self.context.icfg);

                    f
                });

                if discard {
                    // rollback the addition and block associations
                    rollback_function(*start, &mut self.context.ftable, &blocks);
                }
            }
        }

        // 10.2. if we have a backend aiding function recognition, then
        // use it to add functions we missed
        //
        // NOTE: this treats our external loader as a source of absolute
        // truth, which might not be what we want?
        //
        // check references to possible function starts found via pattern matching
        // this has a lower prio than xrefs and symbol hints to reduce false positives
        //
        if self.config.use_function_start_patterns && !func_starts_by_pattern.is_empty() {
            for start in func_starts_by_pattern.iter().sorted().rev() {
                let start_addr = *start;

                let Some(fblk) = blocks.get_point(start) else {
                    tracing::debug!(
                        "possible function start block has not been recognised: {}",
                        start
                    );
                    continue;
                };

                if !fblk.is_in_function() && !fblk.is_invalid() && fblk.has_insns() {
                    tracing::debug!(
                        "possible function start block at {} has data reference or comes from a strong pattern; marking as function",
                        start
                    );

                    let mut discard = false;
                    self.context.ftable.insert_with(start_addr, |addr, id| {
                        let mut f = Function::new(id, *addr, fblk.id(), None, Default::default());

                        let lifter = self.context.lifter;
                        let arch = lifter.arch();

                        arch.compute_function_properties(&mut f, lifter, &ctx, &*self.context.icfg);

                        if expand_function(
                            self.context.lifter.arch(),
                            &mut f,
                            self.context.lifter,
                            addr,
                            &blocks,
                            &mut self.context.icfg,
                            &self.functions
                        ).is_err() {
                            discard = true;
                            tracing::debug!("error while expanding function based on pattern match at {}; skipping", addr);
                        }

                        if let Some(props) = self.functions.get(&start_addr) {
                            props.apply(&mut f);
                        }

                        unlink_forward_unreachable_blocks(&mut f, &blocks, &mut self.context.icfg);

                        f
                    });

                    if discard {
                        // rollback the addition and block associations
                        rollback_function(start_addr, &mut self.context.ftable, &blocks);
                    } else {
                        self.functions.entry(start_addr).or_default();
                    }
                } else {
                    hints.insert(start_addr);
                }
            }
        }

        for blk in blocks
            .values()
            .filter(|blk| !blk.is_invalid() && !blk.is_padding() && !blk.is_in_function())
            .sorted_by_key(|blk| blk.start())
            .rev()
        {
            if blk.is_in_function() {
                tracing::debug!("skipping {}", blk.start());
                continue;
            }

            let has_unresolved = blk.has_unresolved_targets();
            let is_terminal = blk.is_terminal();
            let last_is_call = blk.last_insn().is_call();
            let last_is_return = blk.last_insn().is_return();

            tracing::trace!(
                "candidate block {} has unresolved or terminal: {}",
                blk.start(),
                has_unresolved || is_terminal
            );

            let try_it = if hints.contains(&blk.start()) {
                tracing::trace!("candidate block (loader hint): {}", blk.start());
                true
            } else if last_is_call && !has_unresolved {
                tracing::trace!("candidate block (resolved call): {}", blk.start());
                true
            } else if last_is_return {
                tracing::trace!("candidate block (return/stub?): {}", blk.start());
                true
            } else if (has_unresolved || is_terminal)
                && self.functions.contains_key(&blk.last_insn().next_address())
            {
                tracing::trace!("candidate block (indirect/next is func): {}", blk.start());
                true
            } else if (has_unresolved || is_terminal)
                && blocks
                    .get_point(blk.last_insn().next_address())
                    .map(|nblk| {
                        if !nblk.is_invalid() {
                            nblk.is_padding()
                                && self.functions.contains_key(&nblk.last_insn().next_address()) || {
                                    // on region boundary
                                    let curr = nblk.last_insn().address();
                                    let last = nblk.last_insn().next_address();
                                    bounds.overlap(curr).next() != bounds.overlap(last).next()
                                }
                        } else {
                            false
                        }
                    })
                    .unwrap_or_default()
            {
                tracing::trace!(
                    "candidate block (indirect/next is func via padding): {}",
                    blk.start()
                );
                true
            } else if (has_unresolved || is_terminal)
                && blocks
                    .get_point(blk.last_insn().next_address())
                    .map(|nblk| {
                        if !nblk.is_invalid() {
                            nblk.is_padding()
                                && matches!(blocks.get_point(nblk.last_insn().next_address()), Some(nnblk) if nnblk.is_in_function())
                        } else {
                            false
                        }
                    })
                    .unwrap_or_default()
            {
                tracing::trace!(
                    "candidate block (indirect/next is in func via padding): {}",
                    blk.start()
                );
                true
            //} else if blk.first_insn().is_maybe_taken() {
            //    tracing::trace!("candidate block (by indirect code reference): {}", blk.start());
            //    true
            } else {
                false
            };

            if try_it {
                let mut f = Function::default();
                match self.context.lifter.arch().expand_function_block(
                    &mut f,
                    self.context.lifter,
                    blk.id(),
                    &blocks,
                    &mut self.context.icfg,
                    &self.functions,
                ) {
                    ExpansionResult::Success => {
                        // TODO: order first by if no incoming edges, then by address
                        if let Some(((_, fentry), fbid)) = f
                            .blocks()
                            .keys()
                            .map(|id| {
                                let blk = blocks.get(*id).unwrap();
                                let k = (
                                    self.context
                                        .icfg
                                        .edges_directed(blk.node(), Direction::Incoming)
                                        .next()
                                        .is_some(),
                                    blk.start(),
                                );
                                (k, *id)
                            })
                            .sorted_by_key(|&(k, _)| k)
                            .next()
                        {
                            tracing::trace!("adding: {}", fentry);

                            let lifter = self.context.lifter;
                            let arch = lifter.arch();

                            arch.compute_function_properties(
                                &mut f,
                                lifter,
                                &ctx,
                                &*self.context.icfg,
                            );

                            let props = self.functions.entry(fentry).or_default();
                            props.apply(&mut f);

                            self.context.ftable.insert_with(fentry, |_addr, id| {
                                f.update_id(id);
                                f.update_entry(fbid);

                                tracing::info!("start function marking for {:?}", id);

                                // update block IDs
                                for bid in f.blocks().keys() {
                                    let blk = &blocks[*bid];
                                    blk.mark_in_function(id);

                                    tracing::info!(
                                        "marking in function {} / {:?}",
                                        blk.start(),
                                        blk.node()
                                    );
                                }

                                // prune unreachable blocks
                                unlink_forward_unreachable_blocks(
                                    &mut f,
                                    &blocks,
                                    &mut self.context.icfg,
                                );

                                f
                            });
                        }
                    }
                    ExpansionResult::OverlapsWithFunction(overlap_f) => {
                        let lifter = self.context.lifter;
                        let arch = lifter.arch();

                        arch.compute_function_properties(&mut f, lifter, &ctx, &*self.context.icfg);

                        tracing::trace!("{} overlaps function!", blk.start());
                        if let Some((old_address, new_address)) = self.context.ftable.merge_with(
                            overlap_f,
                            f,
                            FunctionBuilder {
                                blocks: &blocks,
                                icfg: &*self.context.icfg,
                            },
                        ) {
                            self.functions.remove(&old_address);

                            let props = self.functions.entry(new_address).or_default();
                            let f = self.context.ftable.get_point_mut(new_address).unwrap();

                            props.apply(f);

                            unlink_forward_unreachable_blocks(f, &blocks, &mut self.context.icfg);
                        }
                    }
                    ExpansionResult::Error => (),
                }
            }
        }

        // Pass 2: jumps to functions that are not called
        for blk in blocks
            .values()
            .filter(|blk| !blk.is_invalid() && !blk.is_padding() && !blk.is_in_function())
            .sorted_by_key(|blk| blk.start())
            .rev()
        {
            if blk.is_in_function() {
                tracing::debug!("skipping {}", blk.start());
                continue;
            }

            tracing::debug!("analysing block {} (pass 2)", blk.start());

            let has_unresolved = blk.has_unresolved_targets();

            if has_unresolved {
                tracing::debug!("block {} has unresolved (pass 2)", blk.start());
            }

            let unresolved = has_unresolved
                && {
                    let last_next = blk.last_insn().next_address();
                    if self.functions.contains_key(&last_next) {
                        true
                    } else if let Some(nblk) = blocks.get_point(last_next) {
                        let has_insns = nblk.has_insns();
                        let is_invalid = nblk.is_invalid();
                        let is_padding = nblk.is_padding();

                        if has_insns {
                            (is_invalid || is_padding)
                                && matches!(blocks.get_point(nblk.last_insn().next_address()), Some(nnblk) if nnblk.is_in_function())
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

            if unresolved
                || self
                    .context
                    .icfg
                    .edges_directed(blk.node(), Direction::Outgoing)
                    .any(|e| {
                        let kind = e.weight();
                        (kind.is_branch() || kind.is_call())
                            && blocks[self.context.icfg[e.target()]].is_in_function()
                    })
            {
                tracing::trace!("processing {}", blk.start());

                let mut f = Function::default();
                match self.context.lifter.arch().expand_function_block(
                    &mut f,
                    self.context.lifter,
                    blk.id(),
                    &blocks,
                    &mut self.context.icfg,
                    &self.functions,
                ) {
                    ExpansionResult::Success => {
                        // TODO: order first by if no incoming edges, then by address
                        if let Some(((_, fentry), fbid)) = f
                            .blocks()
                            .keys()
                            .map(|id| {
                                let blk = blocks.get(*id).unwrap();
                                let k = (
                                    self.context
                                        .icfg
                                        .edges_directed(blk.node(), Direction::Incoming)
                                        .next()
                                        .is_some(),
                                    blk.start(),
                                );
                                (k, *id)
                            })
                            .sorted_by_key(|&(k, _)| k)
                            .next()
                        {
                            tracing::trace!("adding: {}", fentry);

                            let lifter = self.context.lifter;
                            let arch = lifter.arch();

                            arch.compute_function_properties(
                                &mut f,
                                lifter,
                                &ctx,
                                &*self.context.icfg,
                            );

                            let props = self.functions.entry(fentry).or_default();
                            props.apply(&mut f);

                            self.context.ftable.insert_with(fentry, |_addr, id| {
                                f.update_id(id);
                                f.update_entry(fbid);
                                // update block IDs
                                for bid in f.blocks().keys() {
                                    let blk = &blocks[*bid];
                                    blk.mark_in_function(id);
                                }

                                unlink_forward_unreachable_blocks(
                                    &mut f,
                                    &blocks,
                                    &mut self.context.icfg,
                                );

                                f
                            });
                        }
                    }
                    ExpansionResult::OverlapsWithFunction(overlap_f) => {
                        let lifter = self.context.lifter;
                        let arch = lifter.arch();

                        arch.compute_function_properties(&mut f, lifter, &ctx, &*self.context.icfg);

                        if let Some((old_address, new_address)) = self.context.ftable.merge_with(
                            overlap_f,
                            f,
                            FunctionBuilder {
                                blocks: &blocks,
                                icfg: &*self.context.icfg,
                            },
                        ) {
                            self.functions.remove(&old_address);

                            let props = self.functions.entry(new_address).or_default();
                            let f = self.context.ftable.get_point_mut(new_address).unwrap();

                            props.apply(f);

                            unlink_forward_unreachable_blocks(f, &blocks, &mut self.context.icfg);
                        }
                    }
                    ExpansionResult::Error => (),
                }
            }
        }

        for fid in non_returning_functions
            .iter()
            .filter_map(|addr| blocks.get_point(addr).and_then(|block| block.function()))
        {
            self.context.ftable[fid].mark_non_returning();
        }

        for fid in tail_functions
            .iter()
            .filter_map(|addr| blocks.get_point(addr).and_then(|block| block.function()))
        {
            self.context.ftable[fid].mark_tail();
        }

        // store blocks in table
        *self.context.cbtable = blocks.filter_map(|bid, blk| {
            if let Some(fid) = blk.function() {
                Some(CodeBlock::new(bid, fid, blk.node(), blk.insns()))
            } else {
                tracing::trace!("removing {:?}", blk.node());
                // ensure not in ICFG: this happens if we do not include the block
                // as part of the second pass, but it could be valid
                self.context.icfg.remove_node(blk.node());
                None
            }
        });

        if let Some(stats_path) = self.config.compute_statistics {
            let mut stats = File::create(stats_path).expect("open statistics path for writing");
            let mut my_fns = self.functions.keys().collect::<Vec<_>>();
            my_fns.sort();
            for my_fn in my_fns {
                writeln!(stats, "{}", my_fn).expect("write statistics");
            }

            if self.config.compute_block_statistics {
                for b in self.context.cbtable.values().sorted_by_key(|b| b.address()) {
                    writeln!(
                        stats,
                        "{}-{} ({})",
                        b.address(),
                        b.last_address(),
                        self.context.ftable[b.function()].address()
                    )
                    .expect("write statistics");
                }
            }
        }
    }
}
