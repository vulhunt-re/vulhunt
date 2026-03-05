use std::borrow::Borrow;
use std::cell::Cell;
use std::ops::{Index, IndexMut};

use fugue::ir::disassembly::{ContextDatabase, IRBuilderArena, ParserContext};
use fugue::ir::error::Error as IRError;
use fugue::ir::Address;
use smallvec::SmallVec;

use super::flow::FlowInfo;
use crate::define_mtable_key;
use crate::ir::stmt::{Stmt, StmtCache};
use crate::ir::{Insn, InsnTarget, Term};
use crate::kb::id::Identifiable;
use crate::kb::table::UPointTable;
use crate::lifter::Lifter;

define_mtable_key!(InsnInfoId, "CB541A76-A292-4D17-B290-919E41FB5E59");

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InsnInfo {
    id: InsnInfoId,
    insn: Term<Insn>,
    properties: Cell<FlowInfo>,
    targets: SmallVec<[(usize, InsnTarget); 2]>,
}

impl Identifiable for InsnInfo {
    type Key = InsnInfoId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

impl InsnInfo {
    pub(super) fn new<'a, 'az, A>(
        lifter: &'a Lifter,
        irb: &'az IRBuilderArena,
        ctx: &mut ContextDatabase,
        pctx: &mut ParserContext<'a, 'az>,
        cache: &mut StmtCache,
        address: A,
        bytes: &[u8],
    ) -> Result<Self, IRError>
    where
        A: Into<Address>,
    {
        Self::new_with(
            lifter,
            irb,
            ctx,
            pctx,
            cache,
            Default::default(),
            address,
            bytes,
        )
    }

    pub(super) fn new_with<'a, 'az, A>(
        lifter: &'a Lifter,
        irb: &'az IRBuilderArena,
        ctx: &mut ContextDatabase,
        pctx: &mut ParserContext<'a, 'az>,
        cache: &mut StmtCache,
        id: InsnInfoId,
        address: A,
        bytes: &[u8],
    ) -> Result<Self, IRError>
    where
        A: Into<Address>,
    {
        let address = address.into();

        tracing::trace!("disassembling at {}", address);

        let insn = Insn::lift_with(lifter, irb, ctx, pctx, cache, address, bytes)?;

        let properties = Cell::new(FlowInfo::empty());
        let targets = insn.branch_targets();

        let length = insn.length();

        let mut info = Self {
            id,
            insn,
            properties,
            targets,
        };

        info.update_properties(lifter, &bytes[..length]);
        Ok(info)
    }

    pub fn address(&self) -> Address {
        self.insn().address()
    }

    pub fn fall_address(&self) -> Option<Address> {
        if self.has_fall() {
            Some(self.next_address())
        } else {
            None
        }
    }

    pub fn has_fall(&self) -> bool {
        self.properties.get().contains(FlowInfo::FALL)
    }

    pub fn in_table(&self) -> bool {
        self.properties.get().contains(FlowInfo::IN_TABLE)
    }

    pub fn insn(&self) -> &Term<Insn> {
        &self.insn
    }

    pub fn insn_mut(&mut self) -> &mut Term<Insn> {
        &mut self.insn
    }

    pub fn is_branch(&self) -> bool {
        self.properties.get().contains(FlowInfo::BRANCH)
    }

    pub fn is_branch_dest(&self) -> bool {
        self.properties.get().contains(FlowInfo::BRANCH_DEST)
    }

    pub fn is_call(&self) -> bool {
        self.properties.get().contains(FlowInfo::CALL)
    }

    pub fn is_call_dest(&self) -> bool {
        self.properties.get().contains(FlowInfo::CALL_DEST)
    }

    pub fn is_dest(&self) -> bool {
        self.properties.get().intersects(FlowInfo::DEST)
    }

    pub fn is_flow(&self) -> bool {
        self.properties.get().intersects(FlowInfo::FLOW)
    }

    pub fn is_maybe_taken(&self) -> bool {
        self.properties.get().contains(FlowInfo::MAYBE_TAKEN)
    }

    pub fn is_nop(&self) -> bool {
        self.properties.get().contains(FlowInfo::NOP)
    }

    pub fn is_nonsense(&self) -> bool {
        self.properties.get().contains(FlowInfo::NONSENSE)
    }

    pub fn is_return(&self) -> bool {
        self.properties.get().contains(FlowInfo::RETURN)
    }

    pub fn is_taken(&self) -> bool {
        self.properties.get().intersects(FlowInfo::TAKEN)
    }

    pub fn is_trap(&self) -> bool {
        self.properties.get().contains(FlowInfo::TRAP)
    }

    pub fn is_loader_hint(&self) -> bool {
        self.properties.get().contains(FlowInfo::HINT)
    }

    pub fn is_halt(&self) -> bool {
        self.properties.get().contains(FlowInfo::HALT)
    }

    pub fn flow_info(&self) -> FlowInfo {
        self.properties.get()
    }

    pub fn len(&self) -> usize {
        self.insn().length()
    }

    pub fn mark_branch(&self) {
        self.properties
            .set(self.properties.get() | FlowInfo::BRANCH);
    }

    pub fn mark_branch_target(&self) {
        self.properties
            .set(self.properties.get() | FlowInfo::BRANCH_DEST);
    }

    pub fn mark_call(&self) {
        self.properties.set(self.properties.get() | FlowInfo::CALL);
    }

    pub fn mark_call_target(&self) {
        self.properties
            .set(self.properties.get() | FlowInfo::CALL_DEST);
    }

    pub fn mark_in_table(&self) {
        self.properties
            .set(self.properties.get() | FlowInfo::IN_TABLE);
    }

    pub fn mark_maybe_taken(&self) {
        self.properties
            .set(self.properties.get() | FlowInfo::MAYBE_TAKEN);
    }

    pub fn mark_loader_hint(&self) {
        self.properties.set(self.properties.get() | FlowInfo::HINT);
    }

    pub fn next_address(&self) -> Address {
        self.address() + self.len()
    }

    pub fn targets(&self) -> &[(usize, InsnTarget)] {
        &self.targets
    }

    pub fn target_matches<F>(&self, f: F) -> bool
    where
        F: Fn(&InsnTarget) -> bool,
    {
        self.targets.iter().any(|(_, tgt)| f(tgt))
    }

    #[inline(always)]
    fn update_properties(&mut self, lifter: &Lifter, pattern: &[u8]) {
        let mut prop = self.properties.get() & !FlowInfo::FLOW;
        for (_, target) in self.targets.iter() {
            match target {
                InsnTarget::IntraBlk(_, true) => prop |= FlowInfo::FALL,
                InsnTarget::IntraBlk(_, false)
                | InsnTarget::InterBlk(_)
                | InsnTarget::Unresolved => prop |= FlowInfo::BRANCH,
                InsnTarget::InterSub(_) => prop |= FlowInfo::CALL,
                InsnTarget::InterRet(_, _) => prop |= FlowInfo::RETURN,
                _ => (),
            }
        }

        let arch = lifter.arch();
        let ops = self.insn.operations();

        if ops.is_empty() || self.insn.is_semantic_nop(arch) {
            tracing::trace!("semantic no-op at {} ({})", self.address(), self.insn());
            prop |= FlowInfo::NOP | FlowInfo::FALL;
        } else if ops.first().map(|stmt| stmt.is_trap(arch)).unwrap_or(false) {
            tracing::trace!("trap at {} ({})", self.address(), self.insn());
            prop |= FlowInfo::TRAP;
        } else if lifter.arch().is_nonsense_pattern(pattern) {
            tracing::trace!("nonsense pattern at {} ({})", self.address(), self.insn());
            prop |= FlowInfo::NONSENSE;
        } else if self.insn.is_service_call(arch) {
            prop |= FlowInfo::CALL;
        }

        if self.insn.is_halt(arch) {
            prop |= FlowInfo::HALT;
        }

        self.properties.set(prop);
    }

    pub fn target_addresses_with<'a>(&'a self) -> impl Iterator<Item = (&'a Term<Stmt>, Address)> {
        self.targets.iter().filter_map(|(i, target)| match target {
            InsnTarget::IntraBlk(loc, false) if loc.position() == 0 => {
                Some((&self.insn.operations[*i], loc.address()))
            }
            InsnTarget::InterSub(bt) | InsnTarget::InterBlk(bt) | InsnTarget::InterRet(bt, _) => {
                let Some(loc) = bt.location_value() else {
                    return None;
                };
                if loc.position() == 0 {
                    Some((&self.insn.operations[*i], loc.address()))
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    pub fn target_addresses<'a>(&'a self) -> impl Iterator<Item = Address> + 'a {
        self.targets.iter().filter_map(|(_, target)| match target {
            InsnTarget::IntraBlk(loc, false) if loc.position() == 0 => Some(loc.address()),
            InsnTarget::InterSub(bt) | InsnTarget::InterBlk(bt) | InsnTarget::InterRet(bt, _) => {
                let Some(loc) = bt.location_value() else {
                    return None;
                };
                if loc.position() == 0 {
                    Some(loc.address())
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    pub fn with_target_addresses<F>(&self, mut f: F)
    where
        F: FnMut(Address, bool),
    {
        for (_, target) in self.targets().iter() {
            match target {
                InsnTarget::IntraBlk(_, true) => (),
                InsnTarget::IntraBlk(loc, false) => f(loc.address(), false),
                InsnTarget::InterSub(bt) => {
                    if let Some(loc) = bt.location_value() {
                        f(loc.address(), true)
                    }
                }
                InsnTarget::InterBlk(bt) | InsnTarget::InterRet(bt, _) => {
                    if let Some(loc) = bt.location_value() {
                        f(loc.address(), false)
                    }
                }
                _ => (),
            }
        }
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct InsnInfoTable(UPointTable<Address, InsnInfo>);

impl InsnInfoTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, mut insn: InsnInfo) -> InsnInfoId {
        self.0.insert(insn.address(), |id| {
            *insn.id_mut() = id;
            insn
        })
    }

    pub fn contains<A>(&self, address: A) -> bool
    where
        A: Borrow<Address>,
    {
        self.0.contains_point(address.borrow())
    }

    pub fn insn<A>(&self, address: A) -> Option<&InsnInfo>
    where
        A: Borrow<Address>,
    {
        self.0.get_point(address.borrow())
    }

    pub fn insn_mut<A>(&mut self, address: A) -> Option<&mut InsnInfo>
    where
        A: Borrow<Address>,
    {
        self.0.get_point_mut(address.borrow())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &InsnInfo> {
        self.0.values()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut InsnInfo> {
        self.0.values_mut()
    }

    // Compute the block on-demand based on the current state of the
    // instruction link arena.
    pub fn block<'a, A>(&'a self, address: A) -> InsnInfoIter<'a>
    where
        A: Borrow<Address>,
    {
        InsnInfoIter(self.insn(address), self)
    }
}

impl Index<InsnInfoId> for InsnInfoTable {
    type Output = InsnInfo;

    fn index(&self, id: InsnInfoId) -> &Self::Output {
        self.0.get(id).unwrap()
    }
}

impl IndexMut<InsnInfoId> for InsnInfoTable {
    fn index_mut(&mut self, id: InsnInfoId) -> &mut Self::Output {
        self.0.get_mut(id).unwrap()
    }
}

impl Index<Address> for InsnInfoTable {
    type Output = InsnInfo;

    fn index(&self, address: Address) -> &Self::Output {
        self.0.get_point(address).unwrap()
    }
}

impl IndexMut<Address> for InsnInfoTable {
    fn index_mut(&mut self, address: Address) -> &mut Self::Output {
        self.0.get_point_mut(address).unwrap()
    }
}

pub struct InsnInfoIter<'a>(Option<&'a InsnInfo>, &'a InsnInfoTable);

impl<'a> Iterator for InsnInfoIter<'a> {
    type Item = &'a InsnInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(curr) = self.0.take() {
            if !curr.has_fall() || curr.is_flow() {
                return Some(curr);
            }

            if let Some(next) = curr
                .fall_address()
                .and_then(|addr| self.1 .0.get_point(addr))
            {
                if !next.is_dest() {
                    self.0 = Some(next);
                }
            }

            Some(curr)
        } else {
            None
        }
    }
}

pub trait InsnTable {
    fn get_at<A>(&self, address: A) -> Option<&Term<Insn>>
    where
        A: Into<Address>;
    fn get_at_mut<A>(&mut self, address: A) -> Option<&mut Term<Insn>>
    where
        A: Into<Address>;

    fn get(&self, id: InsnInfoId) -> Option<&Term<Insn>>;
    fn get_mut(&mut self, id: InsnInfoId) -> Option<&mut Term<Insn>>;

    fn contains<A>(&self, address: A) -> bool
    where
        A: Into<Address>;

    fn len(&self) -> usize;
}

impl InsnTable for InsnInfoTable {
    #[inline(always)]
    fn get_at<A>(&self, address: A) -> Option<&Term<Insn>>
    where
        A: Into<Address>,
    {
        self.insn(address.into()).map(|info| info.insn())
    }

    #[inline(always)]
    fn get_at_mut<A>(&mut self, address: A) -> Option<&mut Term<Insn>>
    where
        A: Into<Address>,
    {
        self.insn_mut(address.into()).map(|info| info.insn_mut())
    }

    #[inline(always)]
    fn get(&self, id: InsnInfoId) -> Option<&Term<Insn>> {
        self.0.get(id).map(|info| info.insn())
    }

    #[inline(always)]
    fn get_mut(&mut self, id: InsnInfoId) -> Option<&mut Term<Insn>> {
        self.0.get_mut(id).map(|info| info.insn_mut())
    }

    #[inline(always)]
    fn contains<A>(&self, address: A) -> bool
    where
        A: Into<Address>,
    {
        self.0.contains_point(address.into())
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InsnTerm {
    pub(crate) id: InsnInfoId,
    pub(crate) insn: Term<Insn>,
    pub(crate) properties: FlowInfo,
    pub(crate) targets: SmallVec<[(usize, InsnTarget); 2]>,
}

impl From<InsnInfo> for InsnTerm {
    fn from(t: InsnInfo) -> Self {
        Self {
            id: t.id,
            insn: t.insn,
            properties: t.properties.into_inner(),
            targets: t.targets,
        }
    }
}

impl From<InsnInfoTable> for InsnTermTable {
    fn from(t: InsnInfoTable) -> Self {
        t.0.map_in_place(InsnTerm::from)
    }
}

impl From<InsnTerm> for InsnInfo {
    fn from(t: InsnTerm) -> Self {
        Self {
            id: t.id,
            insn: t.insn,
            properties: Cell::new(t.properties),
            targets: t.targets,
        }
    }
}

impl From<InsnTermTable> for InsnInfoTable {
    fn from(t: InsnTermTable) -> Self {
        Self(t.map_in_place(InsnInfo::from))
    }
}

impl Identifiable for InsnTerm {
    type Key = InsnInfoId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

impl InsnTerm {
    pub fn insn(&self) -> &Term<Insn> {
        &self.insn
    }

    pub fn insn_mut(&mut self) -> &mut Term<Insn> {
        &mut self.insn
    }

    pub fn address(&self) -> Address {
        self.insn().address()
    }

    pub fn fall_address(&self) -> Option<Address> {
        if self.has_fall() {
            Some(self.next_address())
        } else {
            None
        }
    }

    pub fn has_fall(&self) -> bool {
        self.properties.contains(FlowInfo::FALL)
    }

    pub fn in_table(&self) -> bool {
        self.properties.contains(FlowInfo::IN_TABLE)
    }

    pub fn is_branch(&self) -> bool {
        self.properties.contains(FlowInfo::BRANCH)
    }

    pub fn is_branch_dest(&self) -> bool {
        self.properties.contains(FlowInfo::BRANCH_DEST)
    }

    pub fn is_call(&self) -> bool {
        self.properties.contains(FlowInfo::CALL)
    }

    pub fn is_call_dest(&self) -> bool {
        self.properties.contains(FlowInfo::CALL_DEST)
    }

    pub fn is_dest(&self) -> bool {
        self.properties.intersects(FlowInfo::DEST)
    }

    pub fn is_flow(&self) -> bool {
        self.properties.intersects(FlowInfo::FLOW)
    }

    pub fn is_maybe_taken(&self) -> bool {
        self.properties.contains(FlowInfo::MAYBE_TAKEN)
    }

    pub fn is_nop(&self) -> bool {
        self.properties.contains(FlowInfo::NOP)
    }

    pub fn is_nonsense(&self) -> bool {
        self.properties.contains(FlowInfo::NONSENSE)
    }

    pub fn is_return(&self) -> bool {
        self.properties.contains(FlowInfo::RETURN)
    }

    pub fn is_taken(&self) -> bool {
        self.properties.intersects(FlowInfo::TAKEN)
    }

    pub fn is_trap(&self) -> bool {
        self.properties.contains(FlowInfo::TRAP)
    }

    pub fn is_halt(&self) -> bool {
        self.properties.contains(FlowInfo::HALT)
    }

    pub fn flow_info(&self) -> FlowInfo {
        self.properties
    }

    pub fn len(&self) -> usize {
        self.insn().length()
    }

    pub fn next_address(&self) -> Address {
        self.address() + self.len()
    }

    pub fn targets(&self) -> &[(usize, InsnTarget)] {
        &self.targets
    }

    pub fn target_matches<F>(&self, f: F) -> bool
    where
        F: Fn(&InsnTarget) -> bool,
    {
        self.targets.iter().any(|(_, tgt)| f(tgt))
    }
}

pub type InsnTermTable = UPointTable<Address, InsnTerm>;

impl InsnTable for InsnTermTable {
    #[inline(always)]
    fn get_at<A>(&self, address: A) -> Option<&Term<Insn>>
    where
        A: Into<Address>,
    {
        self.get_point(address.into()).map(|info| &info.insn)
    }

    #[inline(always)]
    fn get_at_mut<A>(&mut self, address: A) -> Option<&mut Term<Insn>>
    where
        A: Into<Address>,
    {
        self.get_point_mut(address.into())
            .map(|info| &mut info.insn)
    }

    #[inline(always)]
    fn get(&self, id: InsnInfoId) -> Option<&Term<Insn>> {
        self.get(id).map(|info| &info.insn)
    }

    #[inline(always)]
    fn get_mut(&mut self, id: InsnInfoId) -> Option<&mut Term<Insn>> {
        self.get_mut(id).map(|info| &mut info.insn)
    }

    #[inline(always)]
    fn contains<A>(&self, address: A) -> bool
    where
        A: Into<Address>,
    {
        self.contains_point(address.into())
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.len()
    }
}
