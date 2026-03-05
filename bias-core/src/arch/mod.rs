use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;
use std::ops::{Range, RangeInclusive};

use arrayvec::ArrayVec;
use bitflags::bitflags;
use dyn_clone::DynClone;
use fugue::fspec::pattern::PatternSetMatchIter;
pub use fugue::ir::disassembly::context::ContextBitRange;
use fugue::ir::disassembly::ContextDatabase;
use fugue::ir::{Address, AddressValue, Translator};
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::EdgeReference;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use range_set_blaze::RangeSetBlaze;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::Deserialize;
use smallvec::SmallVec;

use self::aarch64::{AARCH64, ARCH_AARCH64};
use self::arm::{ARCH_ARM, ARM};
use self::ebpf::{ARCH_EBPF, EBPF};
use self::x86::{ARCH_X86, ARCH_X86_64, X86};
use self::xtensa::{ARCH_XTENSA, XTENSA};
use crate::cfg::block::BlockInfoTable;
use crate::cfg::function::FunctionStarts;
use crate::cfg::{FlowKind, ICFG};
use crate::ir::{Expr, Term, Var};
use crate::kb::block::CodeBlockId;
use crate::kb::function::{Function, FunctionId};
use crate::kb::id::Identifiable;
use crate::kb::{uuid, Uuid};
use crate::lifter::Lifter;
use crate::region::Region;

pub mod aarch64;
pub mod arm;
pub mod ebpf;
pub mod x86;
pub mod xtensa;

mod address_set;
pub use address_set::AddressSet;

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FlagKind: u8 {
        const Z = 0b0000_0001;
        const C = 0b0000_0010;
        const N = 0b0000_0100;
        const V = 0b0000_1000;
        const P = 0b0001_0000;
        const A = 0b0010_0000;
    }
}

#[derive(Debug)]
pub enum ExpansionResult {
    Success,
    OverlapsWithFunction(FunctionId),
    Error,
}

impl ExpansionResult {
    pub fn is_err(&self) -> bool {
        matches!(self, ExpansionResult::Error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Flag {
    var: Var,
    kind: FlagKind,
}

impl Borrow<Var> for Flag {
    fn borrow(&self) -> &Var {
        &self.var
    }
}

impl PartialEq<&'_ Var> for Flag {
    fn eq(&self, other: &&'_ Var) -> bool {
        self.var == **other
    }
}

impl PartialEq<Var> for Flag {
    fn eq(&self, other: &Var) -> bool {
        self.var == *other
    }
}

impl Flag {
    pub const fn new(var: Var) -> Self {
        Self::new_with(var, FlagKind::empty())
    }

    pub const fn new_with(var: Var, kind: FlagKind) -> Self {
        Self { var, kind }
    }

    pub const fn z(var: Var) -> Self {
        Self::new_with(var, FlagKind::Z)
    }

    pub const fn c(var: Var) -> Self {
        Self::new_with(var, FlagKind::C)
    }

    pub const fn n(var: Var) -> Self {
        Self::new_with(var, FlagKind::N)
    }

    pub const fn v(var: Var) -> Self {
        Self::new_with(var, FlagKind::V)
    }

    pub const fn p(var: Var) -> Self {
        Self::new_with(var, FlagKind::P)
    }

    pub const fn a(var: Var) -> Self {
        Self::new_with(var, FlagKind::A)
    }

    pub fn kind(&self) -> FlagKind {
        self.kind
    }

    pub fn variable(&self) -> Var {
        self.var
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct AddressRangeSet {
    #[serde(
        deserialize_with = "range_set_blaze_deserialiser",
        serialize_with = "range_set_blaze_serialiser"
    )]
    ranges: RangeSetBlaze<u64>,
    definite_avoids: Vec<RangeInclusive<u64>>,
    maximum_offset: u64,
}

fn range_set_blaze_deserialiser<'de, D>(deserialiser: D) -> Result<RangeSetBlaze<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Ranges;

    impl<'de> Visitor<'de> for Ranges {
        type Value = RangeSetBlaze<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("sequence of ranges")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut ranges = RangeSetBlaze::<u64>::new();

            while let Some((start, end)) = seq.next_element::<(u64, u64)>()? {
                ranges.ranges_insert(start..=end);
            }

            Ok(ranges)
        }
    }

    deserialiser.deserialize_any(Ranges)
}

fn range_set_blaze_serialiser<S>(
    range: &RangeSetBlaze<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut seq = serializer.serialize_seq(None)?;
    for r in range.ranges() {
        seq.serialize_element(&(r.start(), r.end()))?;
    }

    seq.end()
}

impl AddressRangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(start: impl Into<Address>, size: usize) -> Self {
        let start = start.into().offset();
        Self {
            maximum_offset: start + size as u64,
            ..Default::default()
        }
    }

    pub fn compute_avoids(&mut self, minimum_size: usize) {
        self.definite_avoids.clear();
        for range in self.ranges.ranges() {
            if (range.end() - range.start()) >= minimum_size as u64 {
                self.definite_avoids.push(range);
            }
        }
        self.definite_avoids.sort_by_key(|range| *range.start());
    }

    pub fn insert(&mut self, addr: impl Into<Address>) {
        self.ranges.insert(addr.into().offset());
    }

    pub fn insert_range(&mut self, range: impl Into<Range<Address>>) {
        let range = range.into();
        if range.start > range.end {
            return;
        }

        self.ranges
            .ranges_insert(range.start.offset()..=range.end.offset() - 1);
    }

    pub fn insert_with_length(&mut self, addr: impl Into<Address>, len: usize) {
        if len == 0 {
            return;
        }

        let offset = addr.into().offset();

        self.ranges.ranges_insert(offset..=offset + len as u64 - 1);
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        self.ranges.contains(addr.into().offset())
    }

    pub fn contains_avoid(&self, addr: impl Into<Address>) -> bool {
        let addr = addr.into().offset();
        self.definite_avoids
            .binary_search_by(|range| {
                if addr < *range.start() {
                    Ordering::Greater
                } else if addr > *range.end() {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn next_after_avoid(&self, addr: impl Into<Address>) -> (bool, Option<Address>) {
        let addr = addr.into().offset();
        let Ok(pos) = self.definite_avoids.binary_search_by(|range| {
            if addr < *range.start() {
                Ordering::Greater
            } else if addr > *range.end() {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        }) else {
            return (false, None);
        };

        let Some(next) = self.definite_avoids[pos].end().checked_add(1) else {
            return (true, None);
        };

        if next < self.maximum_offset {
            (true, Some(next.into()))
        } else {
            (true, None)
        }
    }

    pub fn is_start(&self, addr: impl Into<Address>) -> bool {
        let addr = addr.into();
        self.contains(addr) && (addr.offset() == 0 || !self.contains(addr - 1usize))
    }

    pub fn ranges<'a>(&'a self) -> impl ExactSizeIterator<Item = Range<Address>> + 'a {
        self.ranges
            .ranges()
            .map(|range| Address::from(*range.start())..Address::from(*range.end() + 1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextUpdate {
    bits: ContextBitRange,
    value: u32,
}

impl ContextUpdate {
    pub fn new(bits: ContextBitRange, value: u32) -> Self {
        Self { bits, value }
    }

    pub fn bits(&self) -> &ContextBitRange {
        &self.bits
    }

    pub fn value(&self) -> u32 {
        self.value
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextUpdates(ArrayVec<ContextUpdate, 2>);

impl From<ContextUpdate> for ContextUpdates {
    fn from(value: ContextUpdate) -> Self {
        Self(ArrayVec::from_iter([value]))
    }
}

impl ContextUpdates {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn single(bits: ContextBitRange, value: u32) -> Self {
        ContextUpdate::new(bits, value).into()
    }

    #[inline]
    pub fn push(&mut self, value: ContextUpdate) {
        self.0.push(value);
    }

    #[inline]
    pub fn apply(&self, address: AddressValue, context: &mut ContextDatabase) {
        for ContextUpdate { bits, value } in self.0.iter() {
            tracing::trace!("setting context bits {bits:?} to {value} at {address}");
            context.set_variable_by_bits(bits, address, *value);
        }
    }

    #[inline]
    pub fn apply_range(
        &self,
        from: AddressValue,
        to: Option<AddressValue>,
        context: &mut ContextDatabase,
    ) {
        for ContextUpdate { bits, value } in self.0.iter() {
            tracing::trace!("setting context bits {bits:?} to {value} from {from} to {to:?}");
            context.set_variable_region_by_bits(bits, from, to, *value);
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionThunkTemplate {
    bytes: SmallVec<[u8; 16]>,
    context: ContextUpdates,
}

impl<T> From<T> for FunctionThunkTemplate
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl FunctionThunkTemplate {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self::new_with(bytes, ContextUpdates::default())
    }

    pub fn new_with(bytes: impl AsRef<[u8]>, context: ContextUpdates) -> Self {
        Self {
            bytes: SmallVec::from_slice(bytes.as_ref()),
            context,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn context(&self) -> &ContextUpdates {
        &self.context
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

pub trait Arch: Send + Sync {
    fn id(&self) -> Uuid;

    #[allow(unused)]
    fn flags(&self, translator: &Translator) -> Vec<Flag> {
        Vec::with_capacity(0)
    }

    #[allow(unused)]
    fn frame_pointer(&self, translator: &Translator) -> Option<Var> {
        None
    }

    #[allow(unused)]
    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        Vec::with_capacity(0)
    }

    #[allow(unused)]
    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_skip_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_trap_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_halt_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_service_call(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_mapping_symbol(&self, symbol: &str) -> bool {
        false
    }

    #[allow(unused)]
    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        AddressRangeSet::default()
    }

    #[allow(unused)]
    fn is_tail_call(
        &self,
        edge: EdgeReference<'_, FlowKind>,
        icfg: &ICFG,
        blocks: &BlockInfoTable<'_>,
        functions: &FunctionStarts,
    ) -> Option<(NodeIndex, NodeIndex)> {
        let tgt_bid = icfg[edge.target()];
        let src_bid = icfg[edge.source()];

        // check if we jump to the start of another function
        matches!(
            blocks.get(tgt_bid),
            Some(tgt_block) if functions.contains_key(&tgt_block.first_insn().address())
        )
        .then(|| (edge.source(), edge.target()))
    }

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate;

    fn expand_function_block(
        &self,
        func: &mut Function,
        _lifter: &Lifter,
        id: CodeBlockId,
        blocks: &BlockInfoTable<'_>,
        icfg: &mut ICFG,
        function_starts: &FunctionStarts,
    ) -> ExpansionResult {
        let mut worklist = VecDeque::new();
        let mut overlaps = None;

        worklist.push_back(id);

        while let Some(id) = worklist.pop_front() {
            if func.blocks().contains_key(&id) {
                continue;
            }

            let block = &blocks[id];
            if block.is_invalid() {
                continue;
            }

            // NOTE:
            // We should we handle the case where we have
            // two functions that overlap are of different
            // instruction sets. E.g.,:
            //
            // ARM -> Thumb or Thumb -> ARM?
            //

            if let Some(id) = block.function() {
                tracing::debug!(
                    "already inside function: {} (seen: {:?}, found {})",
                    block.start(),
                    overlaps,
                    id
                );
                overlaps = overlaps.or(Some(id));
                continue;
            }

            func.blocks_mut().insert(id, block.start());
            block.mark_in_function(func.id());

            let mut tailcall_pending_changes = Vec::new();
            if !block.is_called() {
                'outer: for pred in icfg.edges_directed(block.node(), Direction::Incoming) {
                    if pred.weight().is_call() || pred.weight().is_return() {
                        continue;
                    }

                    // allow only unconditional branches
                    // otherwise false positives are possible:
                    //
                    // jnz     Perl_my_exit_cold ; -> abort()
                    // test    al, 4
                    // jnz     short loc_42F48
                    if matches!(pred.weight(), FlowKind::Branch) {
                        if let Some(nodes) = self.is_tail_call(pred, icfg, blocks, function_starts)
                        {
                            tailcall_pending_changes.push(nodes);
                            continue;
                        }
                    }

                    let nblock = icfg[pred.source()];
                    let nblk = &blocks[nblock];

                    if nblk.is_padding() {
                        if icfg
                            .edges_directed(nblk.node(), Direction::Incoming)
                            .count()
                            == 0
                        {
                            tracing::trace!("skipping padding block at {}", nblk.start());
                            continue;
                        }

                        for pred in icfg.edges_directed(nblk.node(), Direction::Incoming) {
                            let pblock = icfg[pred.source()];
                            let pblk = &blocks[pblock];
                            if matches!(pblk.function(), Some(pfid) if pfid != func.id()) {
                                tracing::trace!(
                                    "skipping padding between functions at {}",
                                    nblk.start()
                                );
                                continue 'outer;
                            }
                        }
                    }

                    if !nblk.is_invalid()
                        && !function_starts.contains_key(&nblk.first_insn().address())
                    {
                        tracing::debug!(
                            "adding incoming (expand): {} -> {} ({:?})",
                            nblk.start(),
                            block.start(),
                            pred
                        );

                        if overlaps.is_none() {
                            worklist.push_back(nblock);
                        }
                    }
                }
            }

            for succ in icfg.edges_directed(block.node(), Direction::Outgoing) {
                if succ.weight().is_call() || succ.weight().is_return() {
                    continue;
                }

                if matches!(succ.weight(), FlowKind::Branch) {
                    if let Some(nodes) = self.is_tail_call(succ, icfg, blocks, function_starts) {
                        tailcall_pending_changes.push(nodes);
                        continue;
                    }
                }

                let nblock = icfg[succ.target()];
                let nblk = &blocks[nblock];

                if !nblk.is_invalid() && !function_starts.contains_key(&nblk.first_insn().address())
                {
                    tracing::debug!(
                        "adding outgoing (expand): {} -> {} ({:?})",
                        block.start(),
                        nblk.start(),
                        succ
                    );

                    if overlaps.is_none() {
                        worklist.push_back(nblock);
                    }
                }
            }

            // override flows for detected tailcalls
            for (src, tgt) in tailcall_pending_changes {
                icfg.update_edge(src, tgt, FlowKind::TailCallBranch);

                let tgt_block = &blocks[icfg[tgt]];
                tgt_block.first_insn().mark_call_target();

                let src_block = &blocks[icfg[src]];
                src_block.last_insn().mark_call();
            }
        }

        match overlaps {
            None => ExpansionResult::Success,
            Some(id) => ExpansionResult::OverlapsWithFunction(id),
        }
    }

    #[allow(unused)]
    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &ContextDatabase,
        icfg: &ICFG,
    ) {
    }

    fn compute_function_start_context(&self, address: Address) -> (Address, ContextUpdates) {
        (address, ContextUpdates::default())
    }

    #[allow(unused)]
    /// Realigns address (floored). Returns `None` if address is already aligned.
    fn compute_aligned_address(
        &self,
        address: Address,
        lifter: &Lifter,
        ctx: &ContextDatabase,
    ) -> Option<(Address, usize)> {
        let alignment = lifter.translator().alignment();
        let mask = alignment as u64 - 1;
        let naddress = Address::from(address.offset() & !mask);

        (address != naddress).then_some((naddress, alignment))
    }

    #[allow(unused)]
    fn function_start_patterns<'a>(
        &self,
        lifter: &Lifter,
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>> {
        None
    }

    #[allow(unused)]
    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        ctx: &mut ContextDatabase,
        segment: &Region,
        f: F,
    ) where
        F: FnMut(Address),
    {
    }
}

pub trait ErasedArch: DynClone + Send + Sync {
    fn id(&self) -> Uuid;

    fn flags(&self, translator: &Translator) -> Vec<Flag>;

    fn frame_pointer(&self, translator: &Translator) -> Option<Var>;

    fn gprs(&self, translator: &Translator) -> Vec<Var>;

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool;

    fn is_skip_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool;

    fn is_trap_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool;

    fn is_halt_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool;

    fn is_service_call(&self, name: &'static str, args: &[Term<Expr>]) -> bool;

    fn is_mapping_symbol(&self, symbol: &str) -> bool;

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet;

    fn is_tail_call(
        &self,
        edge: EdgeReference<'_, FlowKind>,
        icfg: &ICFG,
        blocks: &BlockInfoTable,
        functions: &FunctionStarts,
    ) -> Option<(NodeIndex, NodeIndex)>;

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate;

    fn expand_function_block(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        id: CodeBlockId,
        blocks: &BlockInfoTable,
        icfg: &mut ICFG,
        function_starts: &FunctionStarts,
    ) -> ExpansionResult;

    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &ContextDatabase,
        icfg: &ICFG,
    );

    fn compute_function_start_context(&self, address: Address) -> (Address, ContextUpdates);

    fn compute_aligned_address(
        &self,
        address: Address,
        lifter: &Lifter,
        ctx: &ContextDatabase,
    ) -> Option<(Address, usize)>;

    fn function_start_patterns<'a>(
        &self,
        lifter: &Lifter,
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>>;

    fn for_each_function_by_pattern(
        &self,
        lifter: &Lifter,
        ctx: &mut ContextDatabase,
        segment: &Region,
        f: &mut dyn FnMut(Address),
    );
}
dyn_clone::clone_trait_object!(ErasedArch);

impl<T> Arch for Box<T>
where
    T: Arch + ?Sized,
{
    fn id(&self) -> Uuid {
        <T as Arch>::id(&**self)
    }

    fn flags(&self, translator: &Translator) -> Vec<Flag> {
        <T as Arch>::flags(&self, translator)
    }

    fn frame_pointer(&self, translator: &Translator) -> Option<Var> {
        <T as Arch>::frame_pointer(&self, translator)
    }

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        <T as Arch>::gprs(&self, translator)
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        <T as Arch>::is_nonsense_pattern(&self, bytes)
    }

    fn is_skip_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_skip_intrinsic(&self, name, args)
    }

    fn is_trap_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_trap_intrinsic(&self, name, args)
    }

    fn is_halt_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_halt_intrinsic(&self, name, args)
    }

    fn is_service_call(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_service_call(&self, name, args)
    }

    fn is_mapping_symbol(&self, symbol: &str) -> bool {
        <T as Arch>::is_mapping_symbol(&self, symbol)
    }

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        <T as Arch>::invalid_or_nonsense_ranges(&self, start, bytes)
    }

    fn is_tail_call(
        &self,
        edge: EdgeReference<'_, FlowKind>,
        icfg: &ICFG,
        blocks: &BlockInfoTable,
        functions: &FunctionStarts,
    ) -> Option<(NodeIndex, NodeIndex)> {
        <T as Arch>::is_tail_call(&self, edge, icfg, blocks, functions)
    }

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate {
        <T as Arch>::external_thunk_template(&self, translator)
    }

    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &ContextDatabase,
        icfg: &ICFG,
    ) {
        <T as Arch>::compute_function_properties(&self, func, lifter, ctxt, icfg)
    }

    fn compute_function_start_context(&self, address: Address) -> (Address, ContextUpdates) {
        <T as Arch>::compute_function_start_context(&self, address)
    }

    fn compute_aligned_address(
        &self,
        address: Address,
        lifter: &Lifter,
        ctx: &ContextDatabase,
    ) -> Option<(Address, usize)> {
        <T as Arch>::compute_aligned_address(&self, address, lifter, ctx)
    }

    fn expand_function_block(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        id: CodeBlockId,
        blocks: &BlockInfoTable,
        icfg: &mut ICFG,
        function_starts: &FunctionStarts,
    ) -> ExpansionResult {
        <T as Arch>::expand_function_block(&self, func, lifter, id, blocks, icfg, function_starts)
    }

    fn function_start_patterns<'a>(
        &self,
        lifter: &Lifter,
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>> {
        <T as Arch>::function_start_patterns(&self, lifter, bytes)
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        ctx: &mut ContextDatabase,
        segment: &Region,
        mut f: F,
    ) where
        F: FnMut(Address),
    {
        <T as Arch>::for_each_function_by_pattern(&self, lifter, ctx, segment, &mut f);
    }
}

impl Arch for dyn ErasedArch {
    fn id(&self) -> Uuid {
        Self::id(&*self)
    }

    fn flags(&self, translator: &Translator) -> Vec<Flag> {
        Self::flags(&*self, translator)
    }

    fn frame_pointer(&self, translator: &Translator) -> Option<Var> {
        Self::frame_pointer(&*self, translator)
    }

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        Self::gprs(&*self, translator)
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        Self::is_nonsense_pattern(&*self, bytes)
    }

    fn is_skip_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        Self::is_skip_intrinsic(&*self, name, args)
    }

    fn is_trap_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        Self::is_trap_intrinsic(&*self, name, args)
    }

    fn is_halt_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        Self::is_halt_intrinsic(&*self, name, args)
    }

    fn is_service_call(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        Self::is_service_call(&*self, name, args)
    }

    fn is_mapping_symbol(&self, symbol: &str) -> bool {
        Self::is_mapping_symbol(&*self, symbol)
    }

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        Self::invalid_or_nonsense_ranges(&*self, start, bytes)
    }

    fn is_tail_call(
        &self,
        edge: EdgeReference<'_, FlowKind>,
        icfg: &ICFG,
        blocks: &BlockInfoTable,
        functions: &FunctionStarts,
    ) -> Option<(NodeIndex, NodeIndex)> {
        Self::is_tail_call(&*self, edge, icfg, blocks, functions)
    }

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate {
        Self::external_thunk_template(&*self, translator)
    }

    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &ContextDatabase,
        icfg: &ICFG,
    ) {
        Self::compute_function_properties(&*self, func, lifter, ctxt, icfg);
    }

    fn compute_function_start_context(&self, address: Address) -> (Address, ContextUpdates) {
        Self::compute_function_start_context(&*self, address)
    }

    fn compute_aligned_address(
        &self,
        address: Address,
        lifter: &Lifter,
        ctx: &ContextDatabase,
    ) -> Option<(Address, usize)> {
        Self::compute_aligned_address(&*self, address, lifter, ctx)
    }

    fn expand_function_block(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        id: CodeBlockId,
        blocks: &BlockInfoTable,
        icfg: &mut ICFG,
        function_starts: &FunctionStarts,
    ) -> ExpansionResult {
        Self::expand_function_block(&*self, func, lifter, id, blocks, icfg, function_starts)
    }

    fn function_start_patterns<'a>(
        &self,
        lifter: &Lifter,
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>> {
        Self::function_start_patterns(&*self, lifter, bytes)
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        ctx: &mut ContextDatabase,
        segment: &Region,
        mut f: F,
    ) where
        F: FnMut(Address),
    {
        Self::for_each_function_by_pattern(&*self, lifter, ctx, segment, &mut f);
    }
}

impl<T> ErasedArch for T
where
    T: Arch + Clone,
{
    fn id(&self) -> Uuid {
        <T as Arch>::id(&self)
    }

    fn flags(&self, translator: &Translator) -> Vec<Flag> {
        <T as Arch>::flags(&self, translator)
    }

    fn frame_pointer(&self, translator: &Translator) -> Option<Var> {
        <T as Arch>::frame_pointer(&self, translator)
    }

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        <T as Arch>::gprs(&self, translator)
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        <T as Arch>::is_nonsense_pattern(&self, bytes)
    }

    fn is_skip_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_skip_intrinsic(&self, name, args)
    }

    fn is_trap_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_trap_intrinsic(&self, name, args)
    }

    fn is_halt_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_halt_intrinsic(&self, name, args)
    }

    fn is_service_call(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        <T as Arch>::is_service_call(&self, name, args)
    }

    fn is_mapping_symbol(&self, symbol: &str) -> bool {
        <T as Arch>::is_mapping_symbol(&self, symbol)
    }

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        <T as Arch>::invalid_or_nonsense_ranges(&self, start, bytes)
    }

    fn is_tail_call(
        &self,
        edge: EdgeReference<'_, FlowKind>,
        icfg: &ICFG,
        blocks: &BlockInfoTable,
        functions: &FunctionStarts,
    ) -> Option<(NodeIndex, NodeIndex)> {
        <T as Arch>::is_tail_call(&self, edge, icfg, blocks, functions)
    }

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate {
        <T as Arch>::external_thunk_template(&self, translator)
    }

    fn expand_function_block(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        id: CodeBlockId,
        blocks: &BlockInfoTable,
        icfg: &mut ICFG,
        function_starts: &FunctionStarts,
    ) -> ExpansionResult {
        <T as Arch>::expand_function_block(&self, func, lifter, id, blocks, icfg, function_starts)
    }

    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &ContextDatabase,
        icfg: &ICFG,
    ) {
        <T as Arch>::compute_function_properties(&self, func, lifter, ctxt, icfg)
    }

    fn compute_function_start_context(&self, address: Address) -> (Address, ContextUpdates) {
        <T as Arch>::compute_function_start_context(&self, address)
    }

    fn compute_aligned_address(
        &self,
        address: Address,
        lifter: &Lifter,
        ctx: &ContextDatabase,
    ) -> Option<(Address, usize)> {
        <T as Arch>::compute_aligned_address(&self, address, lifter, ctx)
    }

    fn function_start_patterns<'a>(
        &self,
        lifter: &Lifter,
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>> {
        <T as Arch>::function_start_patterns(&self, lifter, bytes)
    }

    fn for_each_function_by_pattern(
        &self,
        lifter: &Lifter,
        ctx: &mut ContextDatabase,
        segment: &Region,
        f: &mut dyn FnMut(Address),
    ) {
        <T as Arch>::for_each_function_by_pattern(&self, lifter, ctx, segment, f);
    }
}

#[derive(Copy, Clone, Default)]
pub struct DefaultArch;

pub const ARCH_DEFAULT: Uuid = uuid("32978AAD-6AB6-4981-A22D-EC4BE12E9C90");

impl Arch for DefaultArch {
    fn id(&self) -> Uuid {
        ARCH_DEFAULT
    }

    fn external_thunk_template(&self, _translator: &Translator) -> FunctionThunkTemplate {
        FunctionThunkTemplate::new([0x00])
    }
}

impl DefaultArch {
    pub fn new() -> Box<dyn ErasedArch> {
        Box::new(DefaultArch)
    }
}

impl serde::Serialize for Box<dyn ErasedArch> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        <Self as Arch>::id(&self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Box<dyn ErasedArch> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Uuid::deserialize(deserializer)? {
            ARCH_AARCH64 => AARCH64::new(),
            ARCH_ARM => ARM::new(),
            ARCH_EBPF => EBPF::new(),
            ARCH_X86 => X86::new(false),
            ARCH_X86_64 => X86::new(true),
            ARCH_XTENSA => XTENSA::new(),
            _ => DefaultArch::new(),
        })
    }
}
