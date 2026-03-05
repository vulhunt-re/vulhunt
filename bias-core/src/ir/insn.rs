use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::iter::{once, repeat};
use std::mem::take;
use std::ops::{Index, Range};

use ahash::{AHashMap, AHashSet};
use fugue::bv::BitVec;
use fugue::ir::address::Address;
use fugue::ir::disassembly::{ContextDatabase, IRBuilderArena, ParserContext};
use fugue::ir::error::Error;
use fugue::ir::il::traits::*;
use fugue::ir::space::AddressSpaceId;
use itertools::{Itertools, Position};
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use shared_arena::Arena;
use smallvec::{smallvec, SmallVec};
use ustr::Ustr;

use super::stmt::StmtCache;
use super::var::LocalVars;
use super::{TermMut, VarsMutVisitor, VarsVisitor, VisitMut, VisitVars, VisitVarsMut};
use crate::arch::Arch;
use crate::cfg::FlowKind;
use crate::ir::expr::ValHint;
use crate::ir::term::Term;
use crate::ir::{
    BranchTarget, Expr, Location, SimpleVar, Stmt, Var, VarsSubst, VarsSubstVisitor, Visit,
};
use crate::kb::xref::XRef;
use crate::lifter::Lifter;
use crate::region::Memory;

thread_local! { static INSN: Arena<Insn> = Default::default(); }

pub(crate) fn collect_garbage() {
    INSN.with(|v| v.shrink_to_fit());
}

pub fn stats() -> (usize, usize) {
    INSN.with(|v| v.stats())
}

impl From<Insn> for Term<Insn> {
    fn from(s: Insn) -> Self {
        INSN.with(|a| Term::new(a, s))
    }
}

crate::impl_term_mut!(INSN for Insn);

impl TermMut<Insn> for Term<Insn> {
    fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<Insn>),
    {
        INSN.with(|a| self.update_with(a, |_, v| f(v)))
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct Insn {
    pub address: Address,
    pub operations: SmallVec<[Term<Stmt>; 6]>,
    pub delay_slots: u8,
    pub length: u8,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct InsnText {
    pub address: Address,
    pub mnemonic: Ustr,
    pub operands: String,
    pub operand_data: SmallVec<[InsnOperand; 2]>,
    pub tokens: Vec<InsnToken>,
    pub delay_slots: u8,
    pub length: u8,
}

impl InsnText {
    #[inline]
    pub fn address(&self) -> Address {
        self.address
    }

    #[inline]
    pub fn next_address(&self) -> Address {
        self.address + self.length as usize
    }

    #[inline]
    pub fn mnemonic(&self) -> Ustr {
        self.mnemonic
    }

    #[inline]
    pub fn operand_str(&self) -> &str {
        &self.operands
    }

    #[inline]
    pub fn operands(&self) -> &[InsnOperand] {
        &self.operand_data
    }

    #[inline]
    pub fn operands_mut(&mut self) -> &mut SmallVec<[InsnOperand; 2]> {
        &mut self.operand_data
    }

    #[inline]
    pub fn tokens(&self) -> &[InsnToken] {
        &self.tokens
    }

    #[inline]
    pub fn tokens_mut(&mut self) -> &mut Vec<InsnToken> {
        &mut self.tokens
    }

    #[inline]
    pub fn delay_slots(&self) -> usize {
        self.delay_slots as _
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.length as _
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InsnChunk<'a, T: Copy = ()> {
    pub location: Location,
    pub origin: T,
    pub operations: &'a [Term<Stmt>],
}

impl<'a> InsnChunk<'a> {
    pub fn new(location: impl Into<Location>, operations: &'a [Term<Stmt>]) -> InsnChunk<'a> {
        InsnChunk::new_with(location, (), operations)
    }
}

impl<'a, T: Copy> InsnChunk<'a, T> {
    pub fn new_with(
        location: impl Into<Location>,
        origin: T,
        operations: &'a [Term<Stmt>],
    ) -> Self {
        Self {
            location: location.into(),
            origin,
            operations,
        }
    }

    pub fn operations(&self) -> &[Term<Stmt>] {
        self.operations
    }

    pub fn first(&self) -> Option<&Term<Stmt>> {
        self.operations().first()
    }

    pub fn last(&self) -> Option<&Term<Stmt>> {
        self.operations().last()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Term<Stmt>> {
        self.operations().iter()
    }

    pub fn should_fall(&self) -> bool {
        self.operations
            .last()
            .map(|op| op.has_fall())
            .unwrap_or(true) // empty == nop
    }

    pub fn is_branch(&self) -> bool {
        self.flow_is(|op| op.is_branch())
    }

    pub fn is_call(&self) -> bool {
        self.flow_is(|op| op.is_call())
    }

    pub fn is_return(&self) -> bool {
        self.flow_is(|op| op.is_return())
    }

    pub fn flow_is(&self, f: impl FnOnce(&Term<Stmt>) -> bool) -> bool {
        self.flow_operation().map(f).unwrap_or(false)
    }

    pub fn flow_operation(&self) -> Option<&Term<Stmt>> {
        self.operations.last()
    }
}

impl<'a> From<&'a Insn> for InsnChunk<'a> {
    fn from(insn: &'a Insn) -> Self {
        Self::new(insn.address(), insn.operations())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct InsnChunks<'a, T = ()>(Vec<InsnChunk<'a, T>>)
where
    T: Copy;

impl<'a, T: Copy> InsnChunks<'a, T> {
    #[inline]
    pub fn new() -> Self {
        Self(Default::default())
    }

    #[inline]
    pub fn push(&mut self, chunk: impl Into<InsnChunk<'a, T>>) {
        self.0.push(chunk.into())
    }

    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &InsnChunk<'a, T>> {
        self.0.iter()
    }

    #[inline]
    pub fn first(&self) -> Option<&InsnChunk<'a, T>> {
        self.0.first()
    }

    #[inline]
    pub fn last(&self) -> Option<&InsnChunk<'a, T>> {
        self.0.last()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn should_fall(&self) -> bool {
        self.0
            .last()
            .map(|chunk| chunk.should_fall())
            .unwrap_or(true)
    }

    #[inline]
    pub fn is_call(&self) -> bool {
        self.last().map(|chunk| chunk.is_call()).unwrap_or(false)
    }

    #[inline]
    pub fn is_branch(&self) -> bool {
        self.last().map(|chunk| chunk.is_branch()).unwrap_or(false)
    }

    #[inline]
    pub fn is_return(&self) -> bool {
        self.last().map(|chunk| chunk.is_return()).unwrap_or(false)
    }
}

impl<'a, T: Copy> From<InsnChunks<'a, T>> for Vec<InsnChunk<'a, T>> {
    fn from(value: InsnChunks<'a, T>) -> Self {
        value.0
    }
}

impl<'a, T: Copy> Index<usize> for InsnChunks<'a, T> {
    type Output = InsnChunk<'a, T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<'a, T: Copy> From<InsnChunk<'a, T>> for InsnChunks<'a, T> {
    fn from(chunk: InsnChunk<'a, T>) -> Self {
        Self(vec![chunk])
    }
}

pub struct InsnChunksFormatter<'c, 'i, 't, T: Copy> {
    chunks: &'c InsnChunks<'i, T>,
    fmt: Cow<'t, TranslatorFormatter<'t>>,
}

impl<'c, 'i, 't, T: Copy> fmt::Display for InsnChunksFormatter<'c, 'i, 't, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        for op in self
            .chunks
            .0
            .iter()
            .map(|chunk| {
                chunk
                    .operations
                    .iter()
                    .enumerate()
                    .zip(repeat(chunk.location))
                    .map(|((i, o), l)| (l + i, o))
            })
            .flatten()
            .with_position()
        {
            match op {
                (Position::First | Position::Middle, (l, op)) => {
                    writeln!(f, "{l} {}", op.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
                (Position::Only | Position::Last, (l, op)) => {
                    write!(f, "{l} {}", op.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
            }
        }

        Ok(())
    }
}

impl<'c, 'i, 't, T: Copy + 'i> TranslatorDisplay<'c, 't> for InsnChunks<'i, T>
where
    'i: 'c,
{
    type Target = InsnChunksFormatter<'c, 'i, 't, T>;

    fn display_full(&'c self, fmt: Cow<'t, TranslatorFormatter<'t>>) -> Self::Target {
        InsnChunksFormatter { chunks: self, fmt }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct InsnChunkBuilder {
    branches: Vec<(usize, Option<(usize, FlowKind)>)>,
    targets: Vec<usize>,
    nodes: Vec<(usize, usize, NodeIndex)>,
}

impl InsnChunkBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.branches.clear();
        self.targets.clear();
        self.nodes.clear();
    }
}

pub type IntraInsnCFG<'a, T = ()> = StableDiGraph<InsnChunks<'a, T>, FlowKind>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", content = "operand")]
pub enum InsnOperand {
    #[serde(rename = "address")]
    Address(Address, Option<Range<u32>>),
    #[serde(rename = "group")]
    Group(Vec<InsnOperand>),
    #[serde(rename = "register")]
    Register(Ustr, Option<Range<u32>>),
    #[serde(rename = "value")]
    Value(i64, Option<Range<u32>>),
}

impl PartialOrd for InsnOperand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        fn aux<T: Ord>(
            t1: &T,
            t2: &T,
            r1: &Option<Range<u32>>,
            r2: &Option<Range<u32>>,
        ) -> Ordering {
            let c = t1.cmp(t2);
            if c.is_eq() {
                match (r1, r2) {
                    (None, None) => Ordering::Equal,
                    (None, Some(_)) => Ordering::Less,
                    (Some(_), None) => Ordering::Greater,
                    (Some(r1), Some(r2)) => {
                        let rc = r1.start.cmp(&r2.start);
                        if rc.is_eq() {
                            r1.end.cmp(&r2.end)
                        } else {
                            rc
                        }
                    }
                }
            } else {
                c
            }
        }

        match (self, other) {
            (Self::Address(a1, v1), Self::Address(a2, v2)) => Some(aux(a1, a2, v1, v2)),
            (Self::Address(_, _), _) => Some(Ordering::Less),

            (Self::Group(_), Self::Address(_, _)) => Some(Ordering::Greater),
            (Self::Group(g1), Self::Group(g2)) => g1.partial_cmp(g2),
            (Self::Group(_), _) => Some(Ordering::Less),

            (Self::Register(_, _), Self::Address(_, _) | Self::Group(_)) => Some(Ordering::Greater),
            (Self::Register(r1, v1), Self::Register(r2, v2)) => Some(aux(r1, r2, v1, v2)),
            (Self::Register(_, _), _) => Some(Ordering::Less),

            (Self::Value(_, _), Self::Address(_, _) | Self::Group(_) | Self::Register(_, _)) => {
                Some(Ordering::Greater)
            }
            (Self::Value(vv1, v1), Self::Value(vv2, v2)) => Some(aux(vv1, vv2, v1, v2)),
        }
    }
}

impl Ord for InsnOperand {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl InsnOperand {
    #[inline(always)]
    fn visit_aux<F>(&self, f: &mut F)
    where
        F: FnMut(&InsnOperand),
    {
        if let Self::Group(opnds) = self {
            for opnd in opnds {
                opnd.visit_aux(f);
            }
        } else {
            f(self)
        }
    }

    pub fn visit<F>(&self, mut f: F)
    where
        F: FnMut(&InsnOperand),
    {
        self.visit_aux(&mut f)
    }

    pub fn children(&self) -> &[InsnOperand] {
        if let Self::Group(opnds) = self {
            opnds.as_ref()
        } else {
            &[]
        }
    }

    pub fn register(&self) -> Option<Ustr> {
        if let Self::Register(s, _) = self {
            Some(*s)
        } else {
            None
        }
    }

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(a, _) => Some(*a),
            Self::Value(v, _) => Some(Address::from(*v as u64)),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<i64> {
        match self {
            Self::Address(a, _) => Some(u64::from(a) as i64),
            Self::Value(v, _) => Some(*v),
            _ => None,
        }
    }

    pub fn is_address(&self, memory: &Memory) -> bool {
        match self {
            Self::Address(_, _) => true,
            Self::Value(v, _) => memory.contains(Address::from(*v as u64)),
            _ => false,
        }
    }

    pub fn is_value(&self, memory: &Memory) -> bool {
        match self {
            Self::Value(v, _) => !memory.contains(Address::from(*v as u64)),
            _ => false,
        }
    }

    pub fn is_register(&self) -> bool {
        matches!(self, Self::Register(_, _))
    }

    pub fn is_group(&self) -> bool {
        matches!(self, Self::Group(_))
    }

    pub fn bits(&self) -> Option<&Range<u32>> {
        match self {
            Self::Address(_, r) | Self::Register(_, r) | Self::Value(_, r) => r.as_ref(),
            _ => None,
        }
    }
}

impl From<fugue::ir::il::instruction::Operand<'_, '_>> for InsnOperand {
    fn from(op: fugue::ir::il::instruction::Operand) -> Self {
        use fugue::ir::il::instruction::Operand;
        match op {
            Operand::Address(v, r) => Self::Address(v, r),
            Operand::Group(vs) => Self::Group(vs.into_iter().map(Self::from).collect()),
            Operand::Register(v, r) => Self::Register(Ustr::from(v.trim()), r),
            Operand::Value(v, r) => Self::Value(v, r),
        }
    }
}

impl InsnOperand {
    fn from_operands(ops: fugue::ir::il::instruction::Operands) -> SmallVec<[Self; 2]> {
        ops.into_iter().map(Self::from).collect()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[serde(tag = "type", content = "operand")]
pub enum InsnToken {
    #[serde(rename = "address")]
    Address(Address),
    #[serde(rename = "register")]
    Register(Ustr),
    #[serde(rename = "symbol")]
    Symbol(Ustr),
    #[serde(rename = "value")]
    Value(i64),
}

impl InsnToken {
    fn from_tokens(tokens: fugue::ir::disassembly::symbol::Tokens) -> Vec<Self> {
        use fugue::ir::disassembly::symbol::Token;

        let mut output = Vec::with_capacity(tokens.len());

        for token in tokens.into_iter() {
            match token {
                Token::Address(v) => output.push(Self::Address(v)),
                Token::Register(v) => output.push(Self::Register(Ustr::from(v.trim()))),
                Token::Symbol(v) => {
                    output.extend(v.split_whitespace().map(Ustr::from).map(Self::Symbol));
                }
                Token::Value(v) => output.push(Self::Value(v)),
            }
        }

        output
    }
}

impl Insn {
    pub fn from_parts(
        address: impl Into<Address>,
        stmts: impl Into<SmallVec<[Term<Stmt>; 6]>>,
    ) -> Self {
        Self {
            address: address.into(),
            operations: stmts.into(),
            delay_slots: 0,
            length: 0,
        }
    }

    pub fn disassemble<'a, 'az, A>(
        lifter: &'a Lifter,
        irb: &'az IRBuilderArena,
        ctx: &mut ContextDatabase,
        pctx: &mut ParserContext<'a, 'az>,
        addr: A,
        bytes: &[u8],
    ) -> Result<InsnText, Error>
    where
        A: Into<Address>,
    {
        let t = lifter.translator();

        let address = addr.into();
        let address_val = t.address(address.into());

        let (mnemonic, operand_str, operand_data, tokens, delay_slots, length) = t
            .disassemble_aux(
                ctx,
                pctx,
                irb,
                address_val,
                bytes,
                |fmt, delay_slots, length| -> Result<_, fugue::ir::error::Error> {
                    let mnemonic = Ustr::from(fmt.mnemonic_str(irb).as_str());
                    let operand_str = fmt.operands_str(irb).as_str().to_owned();
                    let operand_data = InsnOperand::from_operands(fmt.operand_data(irb));

                    let (mut tokens, body_tokens) = fmt.tokens(irb);
                    tokens.append(body_tokens);

                    Ok((
                        mnemonic,
                        operand_str,
                        operand_data,
                        InsnToken::from_tokens(tokens),
                        delay_slots,
                        length,
                    ))
                },
            )?;

        if length as usize > bytes.len() {
            return Err(Error::Disassembly(
                fugue::ir::disassembly::Error::InstructionResolution,
            ));
        }

        Ok(InsnText {
            address,
            mnemonic,
            operands: operand_str,
            operand_data,
            tokens,
            delay_slots: delay_slots as u8,
            length: length as u8,
        })
    }

    pub fn lift<'a, 'az, A>(
        lifter: &'a Lifter,
        irb: &'az IRBuilderArena,
        ctx: &mut ContextDatabase,
        pctx: &mut ParserContext<'a, 'az>,
        addr: A,
        bytes: &[u8],
    ) -> Result<Term<Self>, Error>
    where
        A: Into<Address>,
    {
        let t = lifter.translator();
        let ffs = lifter.float_kinds();

        let address = addr.into();
        let address_val = t.address(address.into());

        let mut base = irb.builder(t);

        let raw = t.lift_pcode_raw_with(ctx, pctx, irb, &mut base, address_val, bytes)?;

        let manager = t.manager();
        let user_ops = t.user_ops();

        if raw.length as usize > bytes.len() {
            return Err(Error::Disassembly(
                fugue::ir::disassembly::Error::InstructionResolution,
            ));
        }

        let operations = if raw.operations.is_empty() {
            smallvec![Stmt::skip()]
        } else {
            raw.operations
                .into_iter()
                .enumerate()
                .map(|(i, op)| {
                    Stmt::from_parts(
                        manager,
                        ffs,
                        user_ops,
                        &address_val,
                        i,
                        op.opcode,
                        op.inputs,
                        op.output,
                    )
                })
                .collect()
        };

        Ok(Insn {
            operations,
            address,
            delay_slots: raw.delay_slots,
            length: raw.length,
        }
        .into())
    }

    pub fn lift_with<'a, 'az, A>(
        lifter: &'a Lifter,
        irb: &'az IRBuilderArena,
        ctx: &mut ContextDatabase,
        pctx: &mut ParserContext<'a, 'az>,
        cache: &mut StmtCache,
        addr: A,
        bytes: &[u8],
    ) -> Result<Term<Self>, Error>
    where
        A: Into<Address>,
    {
        let t = lifter.translator();
        let ffs = lifter.float_kinds();

        let address = addr.into();
        if let Some((_realigned, alignment)) =
            lifter.arch().compute_aligned_address(address, lifter, ctx)
        {
            return Err(Error::Disassembly(
                fugue::ir::disassembly::Error::IncorrectAlignment {
                    address: address.offset(),
                    alignment,
                },
            ));
        }
        let address_val = t.address(address.into());

        let mut base = irb.builder(t);

        let raw = t.lift_pcode_raw_with(ctx, pctx, irb, &mut base, address_val, bytes)?;

        let manager = t.manager();
        let user_ops = t.user_ops();

        if raw.length as usize > bytes.len() {
            return Err(Error::Disassembly(
                fugue::ir::disassembly::Error::InstructionResolution,
            ));
        }

        let operations = if raw.operations.is_empty() {
            smallvec![Stmt::skip()]
        } else {
            raw.operations
                .into_iter()
                .enumerate()
                .map(|(i, op)| {
                    Stmt::from_parts_with(
                        manager,
                        ffs,
                        user_ops,
                        &address_val,
                        i,
                        op.opcode,
                        op.inputs,
                        op.output,
                        cache,
                    )
                })
                .collect()
        };

        Ok(Insn {
            address,
            operations,
            delay_slots: raw.delay_slots,
            length: raw.length,
        }
        .into())
    }

    pub fn nop<A>(address: A, length: usize) -> Term<Self>
    where
        A: Into<Address>,
    {
        Self {
            address: address.into(),
            operations: smallvec![Stmt::skip()],
            delay_slots: 0,
            length: length as u8,
        }
        .into()
    }

    #[inline]
    pub fn address(&self) -> Address {
        self.address
    }

    #[inline]
    pub fn next_address(&self) -> Address {
        self.address + self.length as usize
    }

    #[inline]
    pub fn operations(&self) -> &[Term<Stmt>] {
        self.operations.as_ref()
    }

    #[inline]
    pub fn operations_mut(&mut self) -> &mut SmallVec<[Term<Stmt>; 6]> {
        &mut self.operations
    }

    #[inline]
    pub fn first_operation(&self) -> Option<&Term<Stmt>> {
        self.operations.as_ref().first()
    }

    #[inline]
    pub fn last_operation(&self) -> Option<&Term<Stmt>> {
        self.operations.as_ref().last()
    }

    #[inline]
    pub fn delay_slots(&self) -> usize {
        self.delay_slots as usize
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.length as usize
    }

    #[inline]
    pub fn has_flow(&self) -> bool {
        for stmt in self.operations().iter() {
            if matches!(
                &**stmt,
                Stmt::Branch(_) | Stmt::CBranch(_, _) | Stmt::Call(_, _) | Stmt::Return(_)
            ) {
                return true;
            }
        }
        false
    }

    #[inline]
    pub fn has_local_flow(&self) -> bool {
        let non_terminal_branch = |i| i + 1 != self.operations().len();

        for (i, stmt) in self.operations().iter().enumerate() {
            match &**stmt {
                Stmt::Branch(t) | Stmt::CBranch(_, t) => {
                    if matches!(t.location_value(), Some(v) if v.address() == self.address())
                        || non_terminal_branch(i)
                    {
                        return true;
                    }
                }
                Stmt::Call(_, _) | Stmt::Return(_) if non_terminal_branch(i) => {
                    return true;
                }
                _ => (),
            }
        }
        false
    }

    #[inline]
    pub fn has_loop(&self) -> bool {
        for (i, stmt) in self.operations().iter().enumerate() {
            match &**stmt {
                Stmt::Branch(t) | Stmt::CBranch(_, t) => {
                    if matches!(&**t, BranchTarget::Location(loc) if loc.address() == self.address() && loc.position() <= i)
                    {
                        return true;
                    }
                }
                _ => (),
            }
        }
        false
    }

    #[inline]
    fn local_branches_and_targets_into(&self, builder: &mut InsnChunkBuilder) {
        builder.targets.push(0); // first operation is always a target; local start

        for (i, stmt) in self.operations().iter().enumerate() {
            match &**stmt {
                Stmt::Branch(t) | Stmt::CBranch(_, t) => {
                    let flow = if matches!(&**stmt, Stmt::Branch(_)) {
                        FlowKind::Branch
                    } else {
                        FlowKind::CBranch
                    };

                    if let BranchTarget::Location(loc) = &**t {
                        if loc.address() == self.address()
                            && loc.position() < self.operations().len()
                        {
                            // local target
                            builder.targets.push(loc.position());
                            builder.branches.push((i, Some((loc.position(), flow))));
                            if loc.position() > 0 {
                                if self.operations()[loc.position() - 1].has_fall() {
                                    builder.branches.push((
                                        loc.position() - 1,
                                        Some((loc.position(), FlowKind::Fall)),
                                    ));
                                }
                            }
                        } else {
                            builder.branches.push((i, None));
                        }
                    } else {
                        builder.branches.push((i, None));
                    }

                    if flow.is_conditional() && i + 1 < self.operations().len() {
                        // fall through for cbranch
                        builder.targets.push(i + 1);
                        builder.branches.push((i, Some((i + 1, FlowKind::Fall))));
                    }
                }
                Stmt::Call(_, _) | Stmt::Return(_) => {
                    builder.branches.push((i, None));
                    if i + 1 < self.operations().len() {
                        // fall through
                        builder.targets.push(i + 1);
                        builder.branches.push((i, Some((i + 1, FlowKind::Fall))));
                    }
                }
                _ => (),
            }
        }

        builder.branches.sort_unstable();
        builder.branches.dedup();

        builder.targets.sort_unstable();
        builder.targets.dedup();
    }

    #[inline]
    pub fn local_branches_and_targets(
        &self,
    ) -> (Vec<(usize, Option<(usize, FlowKind)>)>, Vec<usize>) {
        let mut builder = InsnChunkBuilder::new();
        self.local_branches_and_targets_into(&mut builder);

        (builder.branches, builder.targets)
    }

    pub fn local_blocks(&self) -> Vec<(usize, usize)> {
        let (branches, mut targets) = self.local_branches_and_targets();
        let last = self.operations.len();

        targets.extend(branches.into_iter().map(|(b, _)| b + 1).chain(once(last)));
        targets.sort_unstable();
        targets.dedup();

        targets.into_iter().tuple_windows().collect()
    }

    pub fn local_cfg(&self) -> (NodeIndex, IntraInsnCFG<'_>) {
        let (branches, mut targets) = self.local_branches_and_targets();
        let last = self.operations.len();

        targets.extend(branches.iter().map(|(b, _)| b + 1).chain(once(last)));
        targets.sort_unstable();
        targets.dedup();

        let mut cfg = IntraInsnCFG::new();
        let mut nodes = SmallVec::<[(usize, usize, NodeIndex); 3]>::default();

        for (start, end) in targets.into_iter().tuple_windows() {
            let node = InsnChunk::new(
                Location::new(self.address, start),
                &self.operations[start..end],
            );
            nodes.push((start, end - 1, cfg.add_node(node.into())));
        }

        let mut bpos = 0;
        for (_, ei, nx) in nodes.iter() {
            if bpos > branches.len() {
                break;
            }

            while bpos < branches.len() && branches[bpos].0 == *ei {
                if let Some((idx, kind)) = branches[bpos].1 {
                    let idx = nodes.binary_search_by_key(&idx, |(si, _, _)| *si).unwrap();
                    let ndx = nodes[idx].2;
                    cfg.add_edge(*nx, ndx, kind);
                }
                bpos += 1;
            }
        }

        (nodes[0].2, cfg)
    }

    #[inline]
    pub fn splice_local_cfg<'a, T: Copy>(
        &'a self,
        builder: &mut InsnChunkBuilder,
        origin: T,
        cfg: &mut IntraInsnCFG<'a, T>,
    ) -> (NodeIndex, SmallVec<[(usize, NodeIndex); 2]>) {
        builder.clear();
        self.local_branches_and_targets_into(builder);

        let last = self.operations.len();

        builder.targets.extend(
            builder
                .branches
                .iter()
                .map(|(b, _)| b + 1)
                .chain(once(last)),
        );
        builder.targets.sort_unstable();
        builder.targets.dedup();

        for (&start, &end) in builder.targets.iter().tuple_windows() {
            let node = InsnChunk::new_with(
                Location::new(self.address, start),
                origin,
                &self.operations[start..end],
            );
            builder
                .nodes
                .push((start, end - 1, cfg.add_node(node.into())));
        }

        let mut bpos = 0;
        let mut exits = SmallVec::new();

        for &(_, ei, nx) in builder.nodes.iter() {
            if bpos > builder.branches.len() {
                break;
            }

            while bpos < builder.branches.len() && builder.branches[bpos].0 == ei {
                if let Some((idx, kind)) = builder.branches[bpos].1 {
                    let idx = builder
                        .nodes
                        .binary_search_by_key(&idx, |(si, _, _)| *si)
                        .unwrap();
                    let ndx = builder.nodes[idx].2;
                    cfg.add_edge(nx, ndx, kind);
                } else {
                    // non-local branch
                    exits.push((ei, nx));
                }
                bpos += 1;
            }
        }

        let last_node = builder.nodes.last().unwrap();
        if matches!(cfg[last_node.2].0.last().and_then(|n| n.operations.last()), Some(last) if last.has_fall())
        {
            exits.push((last_node.1, last_node.2));
        }

        // FIXME:
        // non-local targets should produce 1 >= exits; last chunk is not
        // necessarily the exit.
        (builder.nodes[0].2, exits)
    }

    pub fn compact_temporaries(&mut self, lifter: &Lifter) {
        // essentially fold forward removing assignments to temporary variables
        let locals = LocalVars::insn(lifter, self);

        struct SubstTemp<'a> {
            locals: LocalVars<'a>,
            bindings: AHashMap<SimpleVar, Term<Expr>>,
        }

        impl<'a> VarsSubst for SubstTemp<'a> {
            fn subst_def(&mut self, var: Var, stmt: &mut Term<Stmt>) {
                if !var.is_temporary() {
                    return;
                }

                let svar = SimpleVar::from(var);
                let pvar = self.locals.enclosing(var);
                let mut expr = stmt.rhs().unwrap().to_owned();

                if svar != pvar {
                    Expr::resize_with(&mut expr, &svar, &pvar);
                }

                self.bindings.insert(pvar, expr);

                *stmt = Stmt::skip();
            }

            fn subst_use(&mut self, var: Var, expr: &mut Term<Expr>) {
                if !var.is_temporary() {
                    return;
                }

                let svar = self.locals.enclosing(var);
                let pvar = SimpleVar::from(var);

                if let Some(nexpr) = self.bindings.get(&svar) {
                    let mut nexpr = nexpr.to_owned();
                    if svar != pvar {
                        Expr::resize_with(&mut nexpr, &svar, &pvar);
                    }
                    *expr = nexpr;
                }
            }
        }

        let mut subst = SubstTemp {
            locals,
            bindings: Default::default(),
        };

        let mut visitor = VarsSubstVisitor::new(&mut subst);

        self.visit_mut(&mut visitor);

        self.compact_redundant();
    }

    pub fn compact_redundant(&mut self) {
        self.compact_redundant_with(&Location::new(
            self.address.clone() + self.length as usize,
            0,
        ))
    }

    // TODO: remove assignments to unique space variables
    pub fn compact_redundant_with(&mut self, fall: &Location) {
        let mut posn: SmallVec<[usize; 6]> = smallvec![0; self.operations.len()];

        // build a mapping from Location -> next non-nop Location
        let mut next = 0;
        for (i, op) in self.operations.iter().enumerate() {
            posn[i] = next;
            if !op.is_skip() {
                next += 1;
            }
        }

        // next is now the length of non-nops; hence if we have any posn[i] >= next, then we
        // rewrite to fall
        self.operations = take(&mut self.operations)
            .into_iter()
            .filter_map(|op| match *op {
                Stmt::Skip => None,
                Stmt::Branch(ref br) => Some(Stmt::branch(Self::adjust_local_branch(
                    br,
                    &self.address,
                    &posn,
                    next,
                    &fall,
                ))),
                Stmt::CBranch(ref c, ref br) => Some(Stmt::branch_conditional(
                    c.clone(),
                    Self::adjust_local_branch(br, &self.address, &posn, next, &fall),
                )),
                _ => Some(op),
            })
            .collect();
    }

    fn adjust_local_branch(
        branch: &BranchTarget,
        curr: &Address,
        posn: &[usize],
        thresh: usize,
        fall: &Location,
    ) -> Term<BranchTarget> {
        if let Some(loc) = branch.location_value() {
            if loc.address() == *curr {
                if let Some(nloc) = posn.get(loc.position()).map(|npos| {
                    if *npos >= thresh {
                        fall.clone()
                    } else {
                        Location::new(curr.clone(), *npos)
                    }
                }) {
                    return BranchTarget::location(nloc).into();
                }
            }
        }
        branch.clone().into()
    }

    pub fn branch_targets(&self) -> SmallVec<[(usize, InsnTarget); 2]> {
        let mut targets = SmallVec::<[_; 2]>::new();
        self.branch_targets_into(&mut targets);
        targets
    }

    pub fn branch_targets_visit_into(&self, targets: &mut SmallVec<[(usize, InsnTarget); 2]>) {
        let address = self.address();
        let naddress = self.address() + self.length();
        let op_count = self.operations().len();

        struct VisitBranches<'a> {
            address: Address,
            naddress: Address,
            curr_pos: usize,
            op_count: usize,
            tgts: &'a mut SmallVec<[(usize, InsnTarget); 2]>,
        }

        impl<'a> VisitBranches<'a> {
            fn push(&mut self, target: InsnTarget) {
                self.tgts.push((self.curr_pos, target))
            }

            fn is_local(&self, location: &Location) -> bool {
                location.address() == self.address
            }

            fn is_fall(&self, location: &Location) -> bool {
                location.address() == self.naddress
            }

            fn branch(&mut self, target: &Term<BranchTarget>) {
                match &**target {
                    BranchTarget::External(exp, _) | BranchTarget::Computed(exp) => {
                        if let Some(off) = (**exp).value().and_then(|v| v.to_u64()) {
                            self.push(if off == self.address.offset() {
                                InsnTarget::IntraIns(Location::new(self.address, 0), false)
                            } else if off == self.naddress.offset() {
                                InsnTarget::IntraBlk(Location::new(self.naddress, 0), false)
                            } else {
                                InsnTarget::InterBlk(target.clone())
                            });
                        } else {
                            self.push(InsnTarget::Unresolved);
                        }
                    }
                    BranchTarget::Location(loc) => self.push(if self.is_local(loc) {
                        InsnTarget::IntraIns(*loc, false)
                    } else if self.is_fall(loc) {
                        InsnTarget::IntraBlk(*loc, false)
                    } else {
                        InsnTarget::InterBlk(target.clone())
                    }),
                }
            }

            fn call(&mut self, target: &Term<BranchTarget>) {
                self.push(InsnTarget::InterSub(target.clone()));
            }

            fn return_(&mut self, target: &Term<BranchTarget>) {
                self.push(InsnTarget::InterRet(
                    target.clone(),
                    self.curr_pos + 1 == self.op_count,
                ));
            }

            fn intrinsic(&mut self) {
                self.push(InsnTarget::Intrinsic);
            }

            fn fall(&mut self) {
                self.push(if self.curr_pos + 1 >= self.op_count {
                    InsnTarget::IntraBlk(Location::new(self.naddress, self.curr_pos), true)
                } else {
                    InsnTarget::IntraIns(
                        Location::new(self.address, self.curr_pos - self.op_count),
                        true,
                    )
                });
            }
        }

        impl<'a, 'ir> Visit<'ir> for VisitBranches<'a> {
            fn visit_stmt_branch(&mut self, target: &'ir Term<BranchTarget>) {
                self.branch(target);
            }

            fn visit_stmt_cbranch(
                &mut self,
                _condition: &'ir Term<Expr>,
                target: &'ir Term<BranchTarget>,
            ) {
                self.branch(target);
                self.fall();
            }

            fn visit_stmt_call(
                &mut self,
                target: &'ir Term<BranchTarget>,
                _args: &'ir [Term<Expr>],
            ) {
                self.call(target);
                self.fall();
            }

            fn visit_stmt_intrinsic(&mut self, _name: &'static str, _args: &'ir [Term<Expr>]) {
                self.intrinsic();
                self.fall();
            }

            fn visit_stmt_return(&mut self, target: &'ir Term<BranchTarget>) {
                self.return_(target);
            }

            fn visit_stmt(&mut self, stmt: &'ir Term<Stmt>) {
                match **stmt {
                    Stmt::Branch(ref target) => self.visit_stmt_branch(target),
                    Stmt::CBranch(ref condition, ref target) => {
                        self.visit_stmt_cbranch(condition, target)
                    }
                    Stmt::Call(ref target, ref args) => self.visit_stmt_call(target, args),
                    Stmt::Return(ref target) => self.visit_stmt_return(target),
                    Stmt::Intrinsic(ref name, ref args) => {
                        self.visit_stmt_intrinsic(name.as_str(), args)
                    }
                    _ => {
                        if self.curr_pos + 1 == self.op_count {
                            self.fall();
                        }
                    }
                }
            }
        }

        let mut visitor = VisitBranches {
            address,
            naddress,
            op_count,
            curr_pos: 0,
            tgts: targets,
        };

        for (i, stmt) in self.operations().iter().enumerate() {
            visitor.curr_pos = i;
            visitor.visit_stmt(stmt);
        }
    }

    // Find and classify all possible branch targets from a given instruction
    //
    // NOTE: this method's correctness relies on the assumption that Insn's
    // operations are freshly emitted by the lifter (i.e., we assume that
    // there are no expression-based calls or branches).
    //
    // TODO(slt): reimplement using visitor.
    //
    pub fn branch_targets_into(&self, targets: &mut SmallVec<[(usize, InsnTarget); 2]>) {
        let address = self.address();
        let naddress = self.address() + self.length();
        let op_count = self.operations().len();

        let is_local = |loc: &Location| -> bool { loc.address() == address };
        let is_fall = |loc: &Location| -> bool { loc.address() == naddress };

        let nlocation = |i: usize| -> Location {
            if i >= op_count {
                Location::new(naddress.clone(), i - op_count)
            } else {
                Location::new(address.clone(), i)
            }
        };

        let nbranch = |i: usize,
                       tgt: &Term<BranchTarget>,
                       targets: &mut SmallVec<[(usize, InsnTarget); 2]>| {
            match &**tgt {
                BranchTarget::External(exp, _) | BranchTarget::Computed(exp) => {
                    if let Expr::Val(ref bv, _) = &**exp {
                        if let Some(off) = bv.to_u64() {
                            if off == address.offset() {
                                targets.push((
                                    i,
                                    InsnTarget::IntraIns(Location::new(address.clone(), 0), false),
                                ));
                            } else if off == naddress.offset() {
                                targets.push((
                                    i,
                                    InsnTarget::IntraBlk(Location::new(naddress.clone(), 0), false),
                                ));
                            } else {
                                targets.push((i, InsnTarget::InterBlk(tgt.clone())));
                            }
                        } else {
                            targets.push((i, InsnTarget::Unresolved));
                        }
                    } else {
                        targets.push((i, InsnTarget::Unresolved));
                    }
                }
                BranchTarget::Location(loc) => {
                    if is_local(loc) {
                        targets.push((i, InsnTarget::IntraIns(loc.clone(), false)));
                    } else if is_fall(loc) {
                        targets.push((i, InsnTarget::IntraBlk(loc.clone(), false)));
                    } else {
                        targets.push((i, InsnTarget::InterBlk(tgt.clone())));
                    }
                }
            }
        };

        let nfall = |i: usize, fall: Location, targets: &mut SmallVec<[(usize, InsnTarget); 2]>| {
            targets.push((
                i,
                if is_local(&fall) {
                    InsnTarget::IntraIns(fall, true)
                } else {
                    InsnTarget::IntraBlk(fall, true)
                },
            ));
        };

        for (i, stmt) in self.operations().iter().enumerate() {
            let next = nlocation(i + 1);
            match &**stmt {
                Stmt::Branch(tgt) => {
                    nbranch(i, tgt, targets);
                }
                Stmt::CBranch(_, tgt) => {
                    nbranch(i, tgt, targets);
                    nfall(i, next, targets);
                }
                Stmt::Call(tgt, _) => {
                    targets.push((i, InsnTarget::InterSub(tgt.clone())));
                    nfall(i, next, targets);
                }
                Stmt::Return(tgt) => {
                    targets.push((i, InsnTarget::InterRet(tgt.clone(), i + 1 == op_count)));
                }
                Stmt::Intrinsic(_, _) => {
                    targets.push((i, InsnTarget::Intrinsic));
                    nfall(i, next, targets);
                }
                _ => {
                    if i + 1 == op_count {
                        nfall(i, next, targets);
                    }
                }
            }
        }
    }

    pub fn visit_xrefs<V>(&self, memory: &Memory, visitor: &mut V)
    where
        V: VisitXRefs,
    {
        struct VisitLoadStore<'a, V>
        where
            V: VisitXRefs,
        {
            locn: Location,
            refs: &'a mut V,
            memory: &'a Memory,
            hints: &'a mut AHashSet<Var>,
        }

        impl<'a, 'ir, V> Visit<'ir> for VisitLoadStore<'a, V>
        where
            V: VisitXRefs,
        {
            fn visit_expr_val(&mut self, val: &'ir BitVec, hint: ValHint) {
                if let Some(addr) = val.to_u64() {
                    let addr = Address::from(addr);
                    if self
                        .memory
                        .find_region(&addr)
                        .map(|rgn| !rgn.is_code())
                        .unwrap_or_default()
                    {
                        self.refs.visit_xref(XRef::load(self.locn, addr));
                    } else if hint.contains(ValHint::ADDRESS) {
                        self.refs.visit_xref(XRef::load(self.locn, addr));
                    }
                }
            }

            fn visit_hint_pointer(&mut self, var: &'ir Var) {
                tracing::trace!("pointer hint for {var} via {}", self.locn);
                self.hints.insert(*var);
            }

            fn visit_expr_var(&mut self, var: &'ir Var) {
                if let Some(addr) = var.address() {
                    if self.memory.find_region(&addr).is_some() {
                        self.refs.visit_xref(XRef::load(self.locn, addr));
                    }
                }
            }

            fn visit_stmt_assign(&mut self, var: &'ir Var, expr: &'ir Term<Expr>) {
                self.visit_expr(expr);

                if let Some(addr) = var.address() {
                    if self.memory.find_region(&addr).is_some() {
                        self.refs.visit_xref(XRef::store(self.locn, addr));
                    }
                }

                if self.hints.remove(var) {
                    tracing::trace!("applying pointer hint for {var} with {expr}");
                    if let Some(addr) = expr.address_value() {
                        if self.memory.find_region(&addr).is_some() {
                            self.refs.visit_xref(XRef::load(self.locn, addr));
                        }
                    }
                }
            }

            fn visit_expr_load(
                &mut self,
                source: &'ir Term<Expr>,
                _bits: u32,
                _space: AddressSpaceId,
            ) {
                if let Some(val) = (**source).value().and_then(|val| val.to_u64()) {
                    let addr = Address::from(val);
                    if self.memory.find_region(&addr).is_some() {
                        self.refs.visit_xref(XRef::load(self.locn, addr));
                    }
                }
            }

            fn visit_stmt_store(
                &mut self,
                target: &'ir Term<Expr>,
                source: &'ir Term<Expr>,
                _bits: u32,
                _space: AddressSpaceId,
            ) {
                self.visit_expr(source);
                if let Some(val) = (**target).value().and_then(|val| val.to_u64()) {
                    let addr = Address::from(val);
                    if self.memory.find_region(&addr).is_some() {
                        self.refs.visit_xref(XRef::store(self.locn, addr));
                    }
                }
            }
        }

        let addr = self.address();
        let mut hints = Default::default();
        for (i, op) in self.operations().iter().enumerate() {
            let locn = Location::new(addr, i);
            let mut visit = VisitLoadStore {
                locn,
                refs: visitor,
                memory,
                hints: &mut hints,
            };
            visit.visit_stmt(op);
        }
    }

    pub fn xrefs_into(&self, memory: &Memory, refs: &mut Vec<XRef>) {
        struct Visit<'a> {
            refs: &'a mut Vec<XRef>,
        }

        impl<'a> VisitXRefs for Visit<'a> {
            fn visit_xref(&mut self, xref: XRef) {
                self.refs.push(xref);
            }
        }

        self.visit_xrefs(memory, &mut Visit { refs })
    }

    pub fn xrefs(&self, memory: &Memory) -> Vec<XRef> {
        let mut refs = Vec::with_capacity(0);
        self.xrefs_into(memory, &mut refs);
        refs
    }

    pub fn is_halt(&self, arch: &impl Arch) -> bool {
        self.operations()
            .first()
            .map(|op| op.is_halt(arch))
            .unwrap_or_default()
    }

    pub fn is_service_call(&self, arch: &impl Arch) -> bool {
        self.operations().iter().any(|op| op.is_service_call(arch))
    }

    pub fn is_semantic_nop(&self, arch: &impl Arch) -> bool {
        // NO stores
        // NO branches
        // NO intrinsic
        // NO defs except to unique

        struct Visitor<'a, T>
        where
            T: Arch,
        {
            arch: &'a T,
            is_nop: bool,
        }

        impl<'a, 'ir, T> Visit<'ir> for Visitor<'a, T>
        where
            T: Arch,
        {
            fn visit_stmt_assign(&mut self, var: &'ir Var, expr: &'ir Term<Expr>) {
                self.visit_expr(expr);
                if !var.is_temporary() {
                    self.is_nop = false;
                }
            }

            fn visit_stmt_store(
                &mut self,
                _target: &'ir Term<Expr>,
                _source: &'ir Term<Expr>,
                _bits: u32,
                _space: AddressSpaceId,
            ) {
                self.is_nop = false;
            }

            fn visit_branch_target(&mut self, _target: &'ir Term<BranchTarget>) {
                self.is_nop = false;
            }

            fn visit_intrinsic(&mut self, name: &'static str, args: &'ir [Term<Expr>], _bits: u32) {
                self.is_nop = self.arch.is_skip_intrinsic(name, args);
            }
        }

        let mut visitor = Visitor { is_nop: true, arch };
        for op in self.operations().iter() {
            if !op.is_semantic_skip() {
                visitor.visit_stmt(op);
            }
        }

        visitor.is_nop
    }

    #[inline]
    pub fn constants_into<'ir>(&'ir self, into: &mut AHashSet<&'ir BitVec>) {
        for op in self.operations() {
            op.constants_into(into)
        }
    }

    pub fn constants<'ir>(&'ir self) -> AHashSet<&'ir BitVec> {
        let mut consts = AHashSet::new();
        self.constants_into(&mut consts);
        consts
    }

    pub fn visit<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        for (i, op) in self.operations().iter().enumerate() {
            visitor.visit_location(Location::new(self.address, i));
            visitor.visit_stmt(op);
        }
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        for (i, op) in self.operations.iter_mut().enumerate() {
            visitor.visit_location(Location::new(self.address, i));
            visitor.visit_stmt_mut(op);
        }
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        let mut visit = VarsVisitor::new(visitor);
        for op in self.operations() {
            visit.visit_stmt(op);
        }
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        let mut visit = VarsMutVisitor::new(visitor);
        for op in self.operations_mut() {
            visit.visit_stmt_mut(op);
        }
    }
}

pub trait VisitXRefs {
    fn visit_xref(&mut self, xref: XRef);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum InsnTarget {
    IntraIns(Location, bool),
    IntraBlk(Location, bool),
    InterBlk(Term<BranchTarget>),
    InterSub(Term<BranchTarget>),
    InterRet(Term<BranchTarget>, bool),
    Intrinsic,
    Unresolved,
}

impl InsnTarget {
    // Local block targets and calls; .1 is true if call
    pub fn target_location(&self) -> (Option<Location>, bool) {
        match self {
            Self::InterSub(loc) => {
                if let BranchTarget::Location(loc) = &**loc {
                    (Some(loc.clone()), true)
                } else {
                    (None, true)
                }
            }
            Self::InterRet(loc, _) | Self::InterBlk(loc) => {
                if let BranchTarget::Location(loc) = &**loc {
                    (Some(loc.clone()), false)
                } else {
                    Default::default()
                }
            }
            Self::IntraBlk(loc, false) => (Some(loc.clone()), false),
            _ => Default::default(),
        }
    }

    // Just local block targets
    pub fn target_block_location(&self) -> Option<Location> {
        match self {
            Self::InterBlk(loc) => {
                if let BranchTarget::Location(loc) = &**loc {
                    Some(loc.clone())
                } else {
                    None
                }
            }
            Self::IntraBlk(loc, false) => Some(loc.clone()),
            _ => None,
        }
    }

    // Just local block targets
    pub fn local_target(&self) -> Option<Location> {
        match self {
            Self::InterBlk(loc) => {
                if let Some(loc) = loc.location_value() {
                    Some(loc.clone())
                } else {
                    None
                }
            }
            Self::IntraBlk(loc, _) => Some(loc.clone()),
            _ => None,
        }
    }

    pub fn is_branch_to(&self, target: Address) -> bool {
        self.is_branch_to_with(target, true)
    }

    pub fn is_branch_to_with(&self, target: Address, fall_is_branch: bool) -> bool {
        match self {
            Self::InterBlk(loc) => {
                if let Some(loc) = loc.location_value() {
                    loc.address() == target
                } else {
                    false
                }
            }
            Self::IntraBlk(loc, is_fall) => (!is_fall || fall_is_branch) && loc.address() == target,
            _ => false,
        }
    }

    pub fn is_fall_to(&self, target: Address) -> bool {
        match self {
            Self::IntraIns(loc, true) | Self::IntraBlk(loc, true) => {
                loc.address() == target && loc.position() == 0
            }
            _ => false,
        }
    }

    pub fn indirect_or_unresolved_branch(&self) -> bool {
        match self {
            Self::InterBlk(loc) => loc.location_value().is_none(),
            Self::Unresolved => true,
            _ => false,
        }
    }

    pub fn indirect_or_unresolved(&self) -> bool {
        match self {
            Self::InterSub(loc) | Self::InterBlk(loc) => loc.location_value().is_none(),
            Self::Unresolved => true,
            _ => false,
        }
    }

    pub fn is_call_to(&self, target: Address) -> bool {
        matches!(self, Self::InterSub(loc) if matches!(loc.location_value(), Some(loc) if loc.address() == target))
    }

    // IDA-style basic blocks
    pub fn ends_block(&self) -> bool {
        match self {
            Self::Unresolved | Self::InterBlk(_) | Self::InterRet(_, true) => true,
            _ => false,
        }
    }

    // Strict basic blocks: any branching operation ends the block
    pub fn ends_block_strict(&self) -> bool {
        match self {
            Self::Unresolved
            | Self::Intrinsic
            | Self::InterSub(_)
            | Self::InterBlk(_)
            | Self::InterRet(_, _) => true,
            _ => false,
        }
    }
}

impl fmt::Display for InsnTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved => write!(f, "unresolved flow"),
            Self::IntraIns(loc, _) => write!(f, "intra-instruction flow to {}", loc),
            Self::IntraBlk(loc, _) => write!(f, "intra-block flow to {}", loc),
            Self::InterBlk(tgt) => write!(f, "inter-block flow to {}", tgt),
            Self::InterSub(tgt) => write!(f, "inter-sub-routine flow to {}", tgt),
            Self::InterRet(tgt, _last) => write!(f, "inter-sub-routine flow to {} via return", tgt),
            Self::Intrinsic => write!(f, "intrinsic flow"),
        }
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let len = self.operations.len();
        if len > 0 {
            for (i, op) in self.operations.iter().enumerate() {
                write!(
                    f,
                    "{}.{:02}: {}{}",
                    self.address,
                    i,
                    op,
                    if i == len - 1 { "" } else { "\n" }
                )?;
            }
            Ok(())
        } else {
            write!(f, "{}.00: skip", self.address)
        }
    }
}

pub struct InsnFormatter<'insn, 'trans> {
    insn: &'insn Insn,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'insn, 'trans> fmt::Display for InsnFormatter<'insn, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let len = self.insn.operations.len();
        if len > 0 {
            for (i, op) in self.insn.operations.iter().enumerate() {
                write!(
                    f,
                    "{}.{:02}: {}{}",
                    self.insn.address,
                    i,
                    op.display_full(Cow::Borrowed(&*self.fmt)),
                    if i == len - 1 { "" } else { "\n" }
                )?;
            }
            Ok(())
        } else {
            write!(f, "{}.00: skip", self.insn.address)
        }
    }
}

impl<'insn, 'trans> TranslatorDisplay<'insn, 'trans> for Insn {
    type Target = InsnFormatter<'insn, 'trans>;

    fn display_full(&'insn self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        InsnFormatter { insn: self, fmt }
    }
}

#[cfg(test)]
mod test {
    use std::env;

    use fugue::bytes::Endian;
    use fugue::ir::space::{AddressSpace, Space, SpaceKind};
    use smallvec::smallvec;

    use super::*;
    use crate::ir::{Expr, Stmt, Var};
    use crate::lifter::LifterBuilder;

    #[test]
    fn ser_de() -> Result<(), Box<dyn std::error::Error>> {
        let rspace = AddressSpace::Space(Space::new(SpaceKind::Register, "REG", 8, 1, 0, None, 0));

        let address = Address::from(0x1000u32);

        let r1 = Var::new(&rspace, 0, 32, 0);
        let r2 = Var::new(&rspace, 4, 32, 0);
        let r3 = Var::new(&rspace, 8, 32, 0);

        let ops: SmallVec<[Term<Stmt>; 6]> = smallvec![
            Stmt::assign(r1, Expr::int_add(Expr::var(r1), Expr::var(r2))),
            Stmt::skip(),
            Stmt::assign(r2, Expr::int_mul(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::assign(r2, Expr::int_mul(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::branch(Location::new(address, 1)),
            Stmt::assign(r3, Expr::int_mul(Expr::var(r2), Expr::var(r1))),
            Stmt::branch(Location::new(address, 4)),
            Stmt::assign(r1, Expr::int_add(Expr::var(r2), Expr::var(r3))),
            Stmt::branch(Location::new(address, 4)),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::branch(Location::new(address, 2)),
        ];

        let insn = Insn {
            address,
            operations: ops,
            length: 1,
            delay_slots: 0,
        };

        let ser = bincode::serialize(&insn)?;
        let de = bincode::deserialize(&ser)?;

        assert_eq!(insn, de);

        Ok(())
    }

    #[test]
    fn local_blocks() -> Result<(), Box<dyn std::error::Error>> {
        let rspace = AddressSpace::Space(Space::new(SpaceKind::Register, "REG", 8, 1, 0, None, 0));
        let tspace = AddressSpace::Unique(Space::new(SpaceKind::Internal, "TMP", 8, 1, 0, None, 0));

        let data = env::var("BIAS_DATA")?;

        let lb = LifterBuilder::new(data)?;
        let lifter = lb.build_with("x86", Endian::Little, 64, "default", "efi")?;

        let address = Address::from(0x1000u32);

        let r1 = Var::new(&rspace, 0, 32, 0);
        let r2 = Var::new(&rspace, 4, 32, 0);
        let r3 = Var::new(&rspace, 8, 32, 0);

        let t1 = Var::new(&tspace, 0, 32, 0);
        let t2 = Var::new(&tspace, 4, 32, 0);
        let t3 = Var::new(&tspace, 8, 8, 0);

        let ops: SmallVec<[Term<Stmt>; 6]> = smallvec![
            Stmt::assign(t1, Expr::int_add(Expr::var(r1), Expr::var(r2))),
            Stmt::skip(),
            Stmt::assign(t2, Expr::int_mul(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::assign(r2, Expr::int_mul(Expr::var(t2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::assign(t3, Expr::int_le(Expr::var(r2), Expr::val(0x10u32))),
            Stmt::branch_conditional(Expr::var(t3), Location::from(address + 1u32)),
            Stmt::assign(r3, Expr::int_mul(Expr::var(r2), Expr::var(t1))),
            Stmt::assign(r1, Expr::int_add(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::branch(Location::new(address, 2)),
        ];

        let mut insn = Insn {
            address,
            operations: ops,
            length: 1,
            delay_slots: 0,
        };

        assert!(insn.has_loop());
        assert_eq!(insn.local_blocks(), vec![(0, 2), (2, 9), (9, 15),]);

        insn.compact_temporaries(&lifter);

        assert!(insn.has_loop());

        Ok(())
    }

    #[test]
    fn local_cfg() -> Result<(), Box<dyn std::error::Error>> {
        let rspace = AddressSpace::Space(Space::new(SpaceKind::Register, "REG", 8, 1, 0, None, 0));
        let tspace = AddressSpace::Unique(Space::new(SpaceKind::Internal, "TMP", 8, 1, 0, None, 0));

        let address = Address::from(0x1000u32);

        let r1 = Var::new(&rspace, 0, 32, 0);
        let r2 = Var::new(&rspace, 4, 32, 0);
        let r3 = Var::new(&rspace, 8, 32, 0);

        let t1 = Var::new(&tspace, 0, 32, 0);
        let t2 = Var::new(&tspace, 4, 32, 0);
        let t3 = Var::new(&tspace, 8, 8, 0);

        let ops: SmallVec<[Term<Stmt>; 6]> = smallvec![
            Stmt::assign(t1, Expr::int_add(Expr::var(r1), Expr::var(r2))),
            Stmt::skip(),
            Stmt::assign(t2, Expr::int_mul(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::assign(r2, Expr::int_mul(Expr::var(t2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::assign(t3, Expr::int_le(Expr::var(r2), Expr::val(0x10u32))),
            Stmt::branch_conditional(Expr::var(t3), Location::from(address + 1u32)),
            Stmt::assign(r3, Expr::int_mul(Expr::var(r2), Expr::var(t1))),
            Stmt::assign(r1, Expr::int_add(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::branch(Location::new(address, 2)),
        ];

        let insn = Insn {
            address,
            operations: ops,
            length: 1,
            delay_slots: 0,
        };

        assert!(insn.has_loop());
        assert_eq!(insn.local_blocks(), vec![(0, 2), (2, 9), (9, 15),]);

        assert!(insn.has_loop());

        let (_root, cfg) = insn.local_cfg();

        assert_eq!(cfg.node_count(), 3);
        assert_eq!(cfg.edge_count(), 3);

        Ok(())
    }

    #[test]
    fn compact_insn() -> Result<(), Box<dyn std::error::Error>> {
        let rspace = AddressSpace::Space(Space::new(SpaceKind::Register, "REG", 8, 1, 0, None, 0));
        let tspace = AddressSpace::Unique(Space::new(SpaceKind::Internal, "TMP", 8, 1, 0, None, 0));

        let data = env::var("BIAS_DATA")?;

        let lb = LifterBuilder::new(data)?;
        let lifter = lb.build_with("x86", Endian::Little, 64, "default", "efi")?;

        let address = Address::from(0x1000u32);

        let r1 = Var::new(&rspace, 0, 32, 0);
        let r2 = Var::new(&rspace, 4, 32, 0);
        let r3 = Var::new(&rspace, 8, 32, 0);

        let t1 = Var::new(&tspace, 0, 32, 0);
        let t2 = Var::new(&tspace, 4, 32, 0);

        let ops: SmallVec<[Term<Stmt>; 6]> = smallvec![
            Stmt::assign(t1, Expr::int_add(Expr::var(r1), Expr::var(r2))),
            Stmt::skip(),
            Stmt::assign(t2, Expr::int_mul(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::assign(r2, Expr::int_mul(Expr::var(t2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::assign(r3, Expr::int_mul(Expr::var(r2), Expr::var(t1))),
            Stmt::assign(r1, Expr::int_add(Expr::var(r2), Expr::var(r3))),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::skip(),
            Stmt::branch(Location::new(address, 2)),
        ];

        let nops: SmallVec<[Term<Stmt>; 6]> = smallvec![
            Stmt::assign(
                r2,
                Expr::int_mul(Expr::int_mul(Expr::var(r2), Expr::var(r3)), Expr::var(r3))
            ),
            Stmt::assign(
                r3,
                Expr::int_mul(Expr::var(r2), Expr::int_add(Expr::var(r1), Expr::var(r2)))
            ),
            Stmt::assign(r1, Expr::int_add(Expr::var(r2), Expr::var(r3))),
            Stmt::branch(Location::new(address, 0)),
        ];

        let mut insn = Insn {
            address,
            operations: ops,
            length: 1,
            delay_slots: 0,
        };

        insn.compact_temporaries(&lifter);

        let ninsn = Insn {
            address,
            operations: nops,
            length: 1,
            delay_slots: 0,
        };

        assert_eq!(insn, ninsn);

        Ok(())
    }
}
