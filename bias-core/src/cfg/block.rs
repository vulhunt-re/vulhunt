use std::borrow::Borrow;
use std::cell::Cell;

use ahash::AHashMap;
use fugue::ir::Address;
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

use super::flow::FlowInfo;
use super::icfg::ICFG;
use super::insn::{InsnInfo, InsnInfoTable};
use crate::cfg::flow::FlowKind;
use crate::kb::block::CodeBlockId;
use crate::kb::function::FunctionId;
use crate::kb::id::Identifiable;
use crate::kb::table::MPointTable;

#[derive(Default)]
pub struct BlockInfo<'a> {
    id: CodeBlockId,
    node: NodeIndex,
    props: Cell<FlowInfo>,
    function: Cell<Option<FunctionId>>,
    insns: SmallVec<[&'a InsnInfo; 1]>,
}

impl<'a> Identifiable for BlockInfo<'a> {
    type Key = CodeBlockId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

impl<'a> BlockInfo<'a> {
    pub fn update_with<A>(
        &mut self,
        address: A,
        table: &'a InsnInfoTable,
        blocks: &AHashMap<Address, (NodeIndex, CodeBlockId)>,
        icfg: &mut ICFG,
    ) where
        A: Borrow<Address>,
    {
        let address = address.borrow();
        let insns = table.block(address);

        self.insns.clear();
        self.insns.extend(insns.into_iter());

        if self.insns.is_empty() {
            self.mark_invalid();
            return;
        }

        self.props.set(FlowInfo::empty());

        // mark as INVALID if block falls through into an invalid instruction (and is not a call)
        let last = self.last_insn();
        if !last.is_call() && matches!(last.fall_address(), Some(fall) if !table.contains(fall)) {
            self.mark_invalid();
        }

        if self.first_insn().is_trap() {
            self.mark_trap();
        }

        if self.first_insn().is_loader_hint() {
            self.mark_loader_hint();
        }

        // mark as NOP padding block if all instructions are NOP
        if self
            .insns
            .iter()
            .all(|insn| insn.is_nop() || insn.is_trap())
        {
            tracing::debug!("padding block: {address}");
            self.mark_padding();
        }

        if self.insns.iter().all(|insn| insn.is_nonsense()) {
            tracing::debug!("nonsense padding block: {address}");
            self.mark_padding();
        }

        // link blocks by resolved edges
        if self.is_viable() {
            let last = self.last_insn();
            let sx = self.node;

            let has_fall = if let Some(fall) = last.fall_address() {
                if let Some((dx, _)) = blocks.get(&fall) {
                    tracing::debug!("linking: {} - {} (fall)", self.start(), fall);
                    icfg.add_edge(sx, *dx, FlowKind::Fall);
                }
                true
            } else {
                false
            };

            last.with_target_addresses(|succ, is_call| {
                if let Some((dx, _)) = blocks.get(&succ) {
                    tracing::debug!("linking: {} - {} (branch)", self.start(), succ);
                    icfg.add_edge(
                        sx,
                        *dx,
                        if is_call {
                            FlowKind::Call
                        } else if has_fall {
                            FlowKind::CBranch
                        } else {
                            FlowKind::Branch
                        },
                    );
                }
            });
        }
    }

    pub fn start(&self) -> Address {
        self.first_insn().address()
    }

    pub fn end(&self) -> Address {
        let last = self.last_insn();
        last.address() + last.len()
    }

    pub fn node(&self) -> NodeIndex {
        self.node
    }

    pub fn update_node(&mut self, node: NodeIndex) {
        self.node = node;
    }

    pub fn first_insn(&self) -> &InsnInfo {
        &**self.insns.first().unwrap()
    }

    pub fn last_insn(&self) -> &InsnInfo {
        &**self.insns.last().unwrap()
    }

    pub fn insns<'b>(&'b self) -> impl Iterator<Item = &'b InsnInfo> {
        self.insns.iter().map(|insn| *insn)
    }

    pub fn num_insns(&self) -> usize {
        self.insns.len()
    }

    pub fn get_insn(&self, index: usize) -> Option<&InsnInfo> {
        self.insns.get(index).map(|&insn| insn)
    }

    pub fn is_called(&self) -> bool {
        self.first_insn().is_call_dest()
    }

    pub fn is_terminal(&self) -> bool {
        !self.last_insn().has_fall() || self.last_insn().is_halt() //.insn().is_halt()
    }

    pub fn is_invalid(&self) -> bool {
        self.props.get().contains(FlowInfo::INVALID)
    }

    pub fn mark_invalid(&self) {
        self.props.set(self.props.get() | FlowInfo::INVALID);
    }

    pub fn clear_invalid(&self) {
        self.props.set(self.props.get() & !FlowInfo::INVALID);
    }

    pub fn is_padding(&self) -> bool {
        self.props.get().contains(FlowInfo::NOP)
    }

    pub fn mark_padding(&self) {
        self.props.set(self.props.get() | FlowInfo::NOP);
    }

    pub fn clear_padding(&self) {
        self.props.set(self.props.get() & !FlowInfo::NOP);
    }

    pub fn is_loader_hint(&self) -> bool {
        self.props.get().contains(FlowInfo::HINT)
    }

    pub fn mark_loader_hint(&self) {
        self.props.set(self.props.get() | FlowInfo::HINT);
    }

    pub fn is_trap(&self) -> bool {
        self.props.get().contains(FlowInfo::TRAP)
    }

    pub fn mark_trap(&self) {
        self.props.set(self.props.get() | FlowInfo::TRAP);
    }

    pub fn is_viable(&self) -> bool {
        !self.props.get().intersects(FlowInfo::UNVIABLE)
    }

    pub fn is_in_function(&self) -> bool {
        self.props.get().contains(FlowInfo::IN_FUNCTION)
    }

    pub fn has_insns(&self) -> bool {
        !self.insns.is_empty()
    }

    pub fn mark_in_function(&self, id: FunctionId) {
        self.props.set(self.props.get() | FlowInfo::IN_FUNCTION);
        self.function.set(Some(id));
    }

    pub fn unmark_in_function(&self) {
        self.props.set(self.props.get() & !FlowInfo::IN_FUNCTION);
        self.function.set(None);
    }

    pub fn function(&self) -> Option<FunctionId> {
        self.function.get()
    }

    pub fn has_unresolved_targets(&self) -> bool {
        self.insns().any(|insn| {
            insn.targets()
                .iter()
                .any(|(_, tgt)| tgt.indirect_or_unresolved())
        })
    }
}

pub type BlockInfoTable<'a> = MPointTable<Address, BlockInfo<'a>>;
