use std::borrow::Cow;
use std::fmt;

use ahash::AHashSet;
use fugue::ir::il::traits::{TranslatorDisplay, TranslatorFormatter};
use fugue::ir::Address;
use itertools::{Itertools, Position};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

use crate::cfg::insn::InsnInfo;
use crate::ir::insn::{InsnChunk, InsnChunks};
use crate::ir::{
    BitVec, Insn, InsnTarget, Location, PhiVarsMut, SimpleVar, Stmt, Term, Var, VarsMutVisitor,
    VarsVisitor, Visit, VisitMut, VisitOpVarsMut, VisitVars, VisitVarsMut,
};
use crate::kb::function::FunctionId;
use crate::kb::id::Identifiable;
use crate::kb::phi::Phi;
use crate::kb::table::MPointTable;
use crate::{define_mtable_key, Project};

define_mtable_key!(CodeBlockId, "1C49FE9B-4A2E-4505-B420-02E6BDCD4E4C");

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CodeBlock {
    pub(crate) id: CodeBlockId,
    pub(crate) fid: FunctionId,

    pub(crate) node: NodeIndex,
    pub(crate) phis: Vec<Phi>,
    pub(crate) insns: SmallVec<[Term<Insn>; 1]>,

    pub(crate) size: usize,
}

impl CodeBlock {
    pub fn new<'a, I>(id: CodeBlockId, fid: FunctionId, node: NodeIndex, insns: I) -> Self
    where
        I: Iterator<Item = &'a InsnInfo>,
    {
        let mut size = 0;
        Self {
            id,
            fid,
            node,
            phis: Default::default(),
            insns: insns
                .map(|insn| {
                    size += insn.len();
                    insn.insn().clone()
                })
                .collect(),
            size,
        }
    }

    #[inline]
    pub fn function(&self) -> FunctionId {
        self.fid
    }

    #[inline]
    pub fn update_function(&mut self, nfid: FunctionId) {
        self.fid = nfid;
    }

    #[inline]
    pub fn address(&self) -> Address {
        self.insns.first().unwrap().address()
    }

    #[inline]
    pub fn last_address(&self) -> Address {
        self.insns.last().unwrap().address()
    }

    #[inline]
    pub fn next_address(&self) -> Address {
        let last = self.insns.last().unwrap();
        last.address() + last.length()
    }

    #[inline]
    pub fn node(&self) -> NodeIndex {
        self.node
    }

    #[inline]
    pub fn update_node(&mut self, node: NodeIndex) {
        self.node = node;
    }

    #[inline]
    pub fn first_insn(&self) -> &Insn {
        self.insns.first().unwrap()
    }

    #[inline]
    pub fn last_insn(&self) -> &Insn {
        self.insns.last().unwrap()
    }

    #[inline]
    pub fn last_operation(&self) -> &Term<Stmt> {
        self.last_insn().last_operation().unwrap()
    }

    pub fn branch_targets(&self) -> SmallVec<[(usize, InsnTarget); 2]> {
        self.last_insn().branch_targets()
    }

    pub fn branch_targets_into(&self, targets: &mut SmallVec<[(usize, InsnTarget); 2]>) {
        self.last_insn().branch_targets_into(targets)
    }

    #[inline]
    pub fn insns(&self) -> &[Term<Insn>] {
        &self.insns
    }

    #[inline]
    pub fn insns_mut(&mut self) -> &mut SmallVec<[Term<Insn>; 1]> {
        &mut self.insns
    }

    #[inline]
    pub fn phis(&self) -> &[Phi] {
        &self.phis
    }

    #[inline]
    pub fn phis_mut(&mut self) -> &mut Vec<Phi> {
        &mut self.phis
    }

    #[inline]
    pub fn has_insn<F>(&self, f: F) -> bool
    where
        F: Fn(&Term<Insn>) -> bool,
    {
        self.insns.iter().any(f)
    }

    #[inline]
    pub fn has_stmt<F>(&self, f: F) -> bool
    where
        F: Fn(&Term<Stmt>) -> bool,
    {
        let f = &f;
        self.has_insn(|insn| insn.operations.iter().any(f))
    }

    #[inline]
    pub fn is_call(&self) -> bool {
        self.last_operation().is_call()
    }

    #[inline]
    pub fn is_cond(&self) -> bool {
        self.last_operation().is_cond()
    }

    #[inline]
    pub fn is_jump(&self) -> bool {
        self.last_operation().is_jump()
    }

    #[inline]
    pub fn is_indirect_jump(&self) -> bool {
        self.last_operation().is_indirect_jump()
    }

    #[inline]
    pub fn is_return(&self) -> bool {
        self.last_operation().is_return()
    }

    #[inline]
    pub fn flows_inter(&self) -> bool {
        let last = self.last_operation();
        last.is_call() || last.is_return()
    }

    #[inline]
    pub fn flows_intra(&self) -> bool {
        !self.flows_inter()
    }

    #[inline]
    pub fn constants_into<'ir>(&'ir self, into: &mut AHashSet<&'ir BitVec>) {
        for op in self.insns() {
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
        for phi in self.phis() {
            phi.visit(visitor);
        }

        for op in self.insns() {
            op.visit(visitor);
        }
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        for phi in self.phis_mut() {
            phi.visit_mut(visitor);
        }

        for op in self.insns_mut() {
            op.visit_mut(visitor);
        }
    }

    pub fn visit_insn_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        for op in self.insns() {
            op.visit_vars(visitor);
        }
    }

    pub fn visit_insn_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for op in self.insns_mut() {
            op.visit_vars_mut(visitor);
        }
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        for phi in self.phis() {
            phi.visit_vars(visitor);
        }

        for op in self.insns() {
            op.visit_vars(visitor);
        }
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for phi in self.phis_mut() {
            phi.visit_vars_mut(visitor);
        }

        for op in self.insns_mut() {
            op.visit_vars_mut(visitor);
        }
    }

    pub fn visit_vars_with<'ir, V>(&'ir self, visitor: &mut V, only_free_uses: bool)
    where
        V: VisitVars<'ir>,
    {
        if only_free_uses {
            self.visit_vars(&mut VisitFreeUses {
                defs: Default::default(),
                visitor,
            })
        } else {
            self.visit_vars(visitor)
        }
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> CodeBlockFormatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }

    pub fn len(&self) -> usize {
        self.size
    }
}

impl Identifiable for CodeBlock {
    type Key = CodeBlockId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

pub type CodeBlockTable = MPointTable<Address, CodeBlock>;

struct VisitFreeUses<'a, 'ir, V>
where
    V: VisitVars<'ir>,
{
    defs: AHashSet<&'ir Var>,
    visitor: &'a mut V,
}

impl<'a, 'ir, V> VisitVars<'ir> for VisitFreeUses<'a, 'ir, V>
where
    V: VisitVars<'ir>,
{
    fn visit_def(&mut self, var: &'ir Var) {
        self.defs.insert(var);
        self.visitor.visit_def(var);
    }

    fn visit_use(&mut self, var: &'ir Var) {
        if !self.defs.contains(var) {
            self.visitor.visit_use(var);
        }
    }
}

pub struct CodeBlockFormatter<'cb, 'trans> {
    blk: &'cb CodeBlock,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'cb, 'trans> fmt::Display for CodeBlockFormatter<'cb, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let addr = self.blk.address();
        for phi in self.blk.phis() {
            writeln!(
                f,
                "{}    {}",
                addr,
                phi.display_full(Cow::Borrowed(&*self.fmt))
            )?;
        }

        for insn in self.blk.insns().iter().with_position() {
            match insn {
                (Position::First | Position::Middle, insn) => {
                    writeln!(f, "{}", insn.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
                (Position::Only | Position::Last, insn) => {
                    write!(f, "{}", insn.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
            }
        }

        Ok(())
    }
}

impl<'cb, 'trans> TranslatorDisplay<'cb, 'trans> for CodeBlock {
    type Target = CodeBlockFormatter<'cb, 'trans>;

    fn display_full(&'cb self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        CodeBlockFormatter { blk: self, fmt }
    }
}

impl VisitOpVarsMut for CodeBlock {
    fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for insn in self.insns_mut() {
            insn.visit_vars_mut(visitor);
        }
    }

    fn visit_phi_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for phi in self.phis_mut() {
            phi.visit_vars_mut(visitor)
        }
    }
}

impl PhiVarsMut for CodeBlock {
    fn push_phi(&mut self, phi: Phi) {
        self.phis.push(phi)
    }

    fn clear_phis(&mut self) {
        self.phis.clear();
    }

    fn get_phi(&self, var: impl Into<SimpleVar>) -> Option<&Phi> {
        let var = var.into();
        self.phis
            .iter()
            .find(|phi| var == SimpleVar::from(phi.target()))
    }

    fn get_phi_mut(&mut self, var: impl Into<SimpleVar>) -> Option<&mut Phi> {
        let var = var.into();
        self.phis
            .iter_mut()
            .find(|phi| var == SimpleVar::from(phi.target()))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChunkedCodeBlock {
    origin: CodeBlockId,
    phis: Vec<Phi>,
    node: NodeIndex,
    call_target: Option<FunctionId>,
    chunks: Vec<CodeBlockInsnChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CodeBlockInsnChunk {
    location: Location,
    operations: Vec<Term<Stmt>>,
}

impl From<InsnChunk<'_, CodeBlockId>> for CodeBlockInsnChunk {
    fn from(value: InsnChunk<'_, CodeBlockId>) -> Self {
        Self {
            location: value.location,
            operations: value.operations.to_vec(),
        }
    }
}

impl CodeBlockInsnChunk {
    pub fn location(&self) -> Location {
        self.location
    }

    pub fn last_location(&self) -> Location {
        self.location + (self.operations.len() - 1)
    }

    pub fn operations(&self) -> &[Term<Stmt>] {
        &self.operations
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

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut Term<Stmt>> {
        self.operations.iter_mut()
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

    pub fn visit<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        for (i, op) in self.iter().enumerate() {
            visitor.visit_location(self.location + i);
            visitor.visit_stmt(op);
        }
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        let loc = self.location;
        for (i, op) in self.iter_mut().enumerate() {
            visitor.visit_location(loc + i);
            visitor.visit_stmt_mut(op);
        }
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        let mut visit = VarsVisitor::new(visitor);
        for (i, op) in self.iter().enumerate() {
            visit.visit_location(self.location + i);
            visit.visit_stmt(op);
        }
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        let mut visit = VarsMutVisitor::new(visitor);
        let loc = self.location;

        for (i, op) in self.iter_mut().enumerate() {
            visit.visit_location(loc + i);
            visit.visit_stmt_mut(op);
        }
    }

    pub fn visit_vars_with<'ir, V>(&'ir self, visitor: &mut V, only_free_uses: bool)
    where
        V: VisitVars<'ir>,
    {
        if only_free_uses {
            self.visit_vars(&mut VisitFreeUses {
                defs: Default::default(),
                visitor,
            })
        } else {
            self.visit_vars(visitor)
        }
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> CodeBlockInsnChunkFormatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }
}

pub struct CodeBlockInsnChunkFormatter<'cb, 'trans> {
    chunk: &'cb CodeBlockInsnChunk,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'cb, 'trans> fmt::Display for CodeBlockInsnChunkFormatter<'cb, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        for (i, op) in self.chunk.iter().with_position().enumerate() {
            let loc = self.chunk.location + i;
            match op {
                (Position::First | Position::Middle, op) => {
                    writeln!(f, "{loc} {}", op.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
                (Position::Only | Position::Last, op) => {
                    write!(f, "{loc} {}", op.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
            }
        }

        Ok(())
    }
}

impl<'cb, 'trans> TranslatorDisplay<'cb, 'trans> for CodeBlockInsnChunk {
    type Target = CodeBlockInsnChunkFormatter<'cb, 'trans>;

    fn display_full(&'cb self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        CodeBlockInsnChunkFormatter { chunk: self, fmt }
    }
}

impl From<InsnChunks<'_, CodeBlockId>> for ChunkedCodeBlock {
    fn from(value: InsnChunks<'_, CodeBlockId>) -> Self {
        assert!(!value.is_empty());
        let chunks = Vec::from(value);
        Self {
            origin: chunks[0].origin,
            phis: Vec::new(),
            node: NodeIndex::default(),
            call_target: None,
            chunks: chunks.into_iter().map(CodeBlockInsnChunk::from).collect(),
        }
    }
}

impl ChunkedCodeBlock {
    #[inline]
    pub fn origin(&self) -> CodeBlockId {
        self.origin
    }

    #[inline]
    pub fn node(&self) -> NodeIndex {
        self.node
    }

    #[inline]
    pub fn update_node(&mut self, node: NodeIndex) {
        self.node = node;
    }

    #[inline]
    pub fn update_call_target(&mut self, target: FunctionId) {
        self.call_target = Some(target);
    }

    #[inline]
    pub fn location(&self) -> Location {
        self.first_chunk().location()
    }

    #[inline]
    pub fn last_location(&self) -> Location {
        self.last_chunk().last_location()
    }

    #[inline]
    pub fn find_chunk(&self, loc: impl Into<Location>) -> Option<&CodeBlockInsnChunk> {
        self.find_chunk_with(loc, |_| true)
    }

    #[inline]
    pub fn find_chunk_with(
        &self,
        loc: impl Into<Location>,
        f: impl Fn(&CodeBlockInsnChunk) -> bool,
    ) -> Option<&CodeBlockInsnChunk> {
        let loc = loc.into();

        if self.location() > loc || loc > self.last_location() {
            return None;
        }

        let chunk = self
            .chunks
            .iter()
            .find(|chunk| chunk.location() >= loc && loc <= chunk.last_location())?;

        if f(chunk) {
            Some(chunk)
        } else {
            None
        }
    }

    #[inline]
    pub fn first_chunk(&self) -> &CodeBlockInsnChunk {
        self.chunks.first().expect("at least one chunk")
    }

    #[inline]
    pub fn last_chunk(&self) -> &CodeBlockInsnChunk {
        self.chunks.last().expect("at least one chunk")
    }

    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CodeBlockInsnChunk> {
        self.chunks.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut CodeBlockInsnChunk> {
        self.chunks.iter_mut()
    }

    #[inline]
    pub fn first(&self) -> Option<&CodeBlockInsnChunk> {
        self.chunks.first()
    }

    #[inline]
    pub fn last(&self) -> Option<&CodeBlockInsnChunk> {
        self.chunks.last()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    #[inline]
    pub fn call_target(&self) -> Option<FunctionId> {
        self.call_target
    }

    #[inline]
    pub fn should_fall(&self) -> bool {
        self.chunks
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

    #[inline]
    pub fn phis(&self) -> &[Phi] {
        &self.phis
    }

    #[inline]
    pub fn phis_mut(&mut self) -> &mut Vec<Phi> {
        &mut self.phis
    }

    pub fn visit<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        let loc = self.location();
        for phi in self.phis() {
            phi.visit_at(loc, visitor);
        }

        for op in self.iter() {
            op.visit(visitor);
        }
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        let loc = self.location();
        for phi in self.phis_mut() {
            visitor.visit_location(loc);
            phi.visit_mut(visitor);
        }

        for op in self.iter_mut() {
            op.visit_mut(visitor);
        }
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        let loc = self.location();
        for phi in self.phis() {
            phi.visit_vars_at(loc, visitor);
        }

        for op in self.iter() {
            op.visit_vars(visitor);
        }
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for phi in self.phis_mut() {
            phi.visit_vars_mut(visitor);
        }

        for op in self.iter_mut() {
            op.visit_vars_mut(visitor);
        }
    }

    pub fn visit_vars_with<'ir, V>(&'ir self, visitor: &mut V, only_free_uses: bool)
    where
        V: VisitVars<'ir>,
    {
        if only_free_uses {
            self.visit_vars(&mut VisitFreeUses {
                defs: Default::default(),
                visitor,
            })
        } else {
            self.visit_vars(visitor)
        }
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> ChunkedCodeBlockFormatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }
}

pub struct ChunkedCodeBlockFormatter<'cb, 'trans> {
    blk: &'cb ChunkedCodeBlock,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'cb, 'trans> fmt::Display for ChunkedCodeBlockFormatter<'cb, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let loc = self.blk.location();
        for phi in self.blk.phis() {
            writeln!(f, "{} {}", loc, phi.display_full(Cow::Borrowed(&*self.fmt)))?;
        }

        for chunk in self.blk.iter().with_position() {
            match chunk {
                (Position::First | Position::Middle, chunk) => {
                    writeln!(f, "{}", chunk.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
                (Position::Only | Position::Last, chunk) => {
                    write!(f, "{}", chunk.display_full(Cow::Borrowed(&*self.fmt)))?;
                }
            }
        }

        Ok(())
    }
}

impl<'cb, 'trans> TranslatorDisplay<'cb, 'trans> for ChunkedCodeBlock {
    type Target = ChunkedCodeBlockFormatter<'cb, 'trans>;

    fn display_full(&'cb self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        ChunkedCodeBlockFormatter { blk: self, fmt }
    }
}

impl VisitOpVarsMut for ChunkedCodeBlock {
    fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for chunk in self.iter_mut() {
            chunk.visit_vars_mut(visitor);
        }
    }

    fn visit_phi_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for phi in self.phis_mut() {
            phi.visit_vars_mut(visitor)
        }
    }
}

impl PhiVarsMut for ChunkedCodeBlock {
    fn push_phi(&mut self, phi: Phi) {
        self.phis.push(phi)
    }

    fn clear_phis(&mut self) {
        self.phis.clear();
    }

    fn get_phi(&self, var: impl Into<SimpleVar>) -> Option<&Phi> {
        let var = var.into();
        self.phis
            .iter()
            .find(|phi| var == SimpleVar::from(phi.target()))
    }

    fn get_phi_mut(&mut self, var: impl Into<SimpleVar>) -> Option<&mut Phi> {
        let var = var.into();
        self.phis
            .iter_mut()
            .find(|phi| var == SimpleVar::from(phi.target()))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct EmptyCodeBlock {
    node: NodeIndex,
    phis: Vec<Phi>,
}

impl EmptyCodeBlock {
    pub fn new() -> Self {
        Self::new_with(NodeIndex::default())
    }

    pub fn new_with(node: NodeIndex) -> Self {
        Self {
            node,
            phis: Default::default(),
        }
    }

    #[inline]
    pub fn node(&self) -> NodeIndex {
        self.node
    }

    #[inline]
    pub fn update_node(&mut self, node: NodeIndex) {
        self.node = node;
    }

    #[inline]
    pub fn phis(&self) -> &[Phi] {
        &self.phis
    }

    #[inline]
    pub fn phis_mut(&mut self) -> &mut Vec<Phi> {
        &mut self.phis
    }

    pub fn visit<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        for phi in self.phis() {
            phi.visit(visitor);
        }
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        for phi in self.phis_mut() {
            phi.visit_mut(visitor);
        }
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        for phi in self.phis() {
            phi.visit_vars(visitor);
        }
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for phi in self.phis_mut() {
            phi.visit_vars_mut(visitor);
        }
    }

    pub fn visit_vars_with<'ir, V>(&'ir self, visitor: &mut V, only_free_uses: bool)
    where
        V: VisitVars<'ir>,
    {
        if only_free_uses {
            self.visit_vars(&mut VisitFreeUses {
                defs: Default::default(),
                visitor,
            })
        } else {
            self.visit_vars(visitor)
        }
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> EmptyCodeBlockFormatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }
}

pub struct EmptyCodeBlockFormatter<'cb, 'trans> {
    blk: &'cb EmptyCodeBlock,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'cb, 'trans> fmt::Display for EmptyCodeBlockFormatter<'cb, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let Some((last, rest)) = self.blk.phis().split_last() else {
            return Ok(());
        };

        for phi in rest {
            phi.display_full(Cow::Borrowed(&*self.fmt)).fmt(f)?;
            writeln!(f)?;
        }
        last.display_full(Cow::Borrowed(&*self.fmt)).fmt(f)?;

        Ok(())
    }
}

impl<'cb, 'trans> TranslatorDisplay<'cb, 'trans> for EmptyCodeBlock {
    type Target = EmptyCodeBlockFormatter<'cb, 'trans>;

    fn display_full(&'cb self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        EmptyCodeBlockFormatter { blk: self, fmt }
    }
}

impl VisitOpVarsMut for EmptyCodeBlock {
    fn visit_vars_mut<V>(&mut self, _visitor: &mut V)
    where
        V: VisitVarsMut,
    {
    }

    fn visit_phi_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        for phi in self.phis_mut() {
            phi.visit_vars_mut(visitor)
        }
    }
}

impl PhiVarsMut for EmptyCodeBlock {
    fn push_phi(&mut self, phi: Phi) {
        self.phis.push(phi)
    }

    fn clear_phis(&mut self) {
        self.phis.clear();
    }

    fn get_phi(&self, var: impl Into<SimpleVar>) -> Option<&Phi> {
        let var = var.into();
        self.phis
            .iter()
            .find(|phi| var == SimpleVar::from(phi.target()))
    }

    fn get_phi_mut(&mut self, var: impl Into<SimpleVar>) -> Option<&mut Phi> {
        let var = var.into();
        self.phis
            .iter_mut()
            .find(|phi| var == SimpleVar::from(phi.target()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EmptyOrChunkedCodeBlock {
    Empty(EmptyCodeBlock),
    Chunked(ChunkedCodeBlock),
}

impl From<EmptyCodeBlock> for EmptyOrChunkedCodeBlock {
    fn from(value: EmptyCodeBlock) -> Self {
        EmptyOrChunkedCodeBlock::Empty(value)
    }
}

impl From<ChunkedCodeBlock> for EmptyOrChunkedCodeBlock {
    fn from(value: ChunkedCodeBlock) -> Self {
        EmptyOrChunkedCodeBlock::Chunked(value)
    }
}

impl EmptyOrChunkedCodeBlock {
    pub fn new_empty() -> Self {
        EmptyOrChunkedCodeBlock::Empty(EmptyCodeBlock::new())
    }

    pub fn new_chunked(chunks: impl Into<ChunkedCodeBlock>) -> Self {
        EmptyOrChunkedCodeBlock::Chunked(chunks.into())
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, EmptyOrChunkedCodeBlock::Empty(_))
    }

    pub fn is_chunked(&self) -> bool {
        matches!(self, EmptyOrChunkedCodeBlock::Chunked(_))
    }

    pub fn as_chunked(&self) -> Option<&ChunkedCodeBlock> {
        if let EmptyOrChunkedCodeBlock::Chunked(chunked) = self {
            Some(chunked)
        } else {
            None
        }
    }

    pub fn as_empty(&self) -> Option<&EmptyCodeBlock> {
        if let EmptyOrChunkedCodeBlock::Empty(empty) = self {
            Some(empty)
        } else {
            None
        }
    }

    pub fn node(&self) -> NodeIndex {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.node(),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.node(),
        }
    }

    pub fn update_node(&mut self, node: NodeIndex) {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.update_node(node),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.update_node(node),
        }
    }

    pub fn update_call_target(&mut self, target: FunctionId) {
        match self {
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.update_call_target(target),
            EmptyOrChunkedCodeBlock::Empty(_) => (), // no call target in empty blocks
        }
    }

    pub fn call_target(&self) -> Option<FunctionId> {
        match self {
            EmptyOrChunkedCodeBlock::Empty(_) => None,
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.call_target(),
        }
    }

    pub fn location(&self) -> Option<Location> {
        match self {
            EmptyOrChunkedCodeBlock::Empty(_) => None,
            EmptyOrChunkedCodeBlock::Chunked(chunked) => Some(chunked.location()),
        }
    }

    pub fn last_location(&self) -> Option<Location> {
        match self {
            EmptyOrChunkedCodeBlock::Empty(_) => None,
            EmptyOrChunkedCodeBlock::Chunked(chunked) => Some(chunked.last_location()),
        }
    }

    pub fn phis(&self) -> &[Phi] {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.phis(),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.phis(),
        }
    }

    pub fn phis_mut(&mut self) -> &mut Vec<Phi> {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.phis_mut(),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.phis_mut(),
        }
    }

    pub fn visit<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: Visit<'ir>,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit(visitor),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.visit(visitor),
        }
    }

    pub fn visit_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitMut,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit_mut(visitor),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.visit_mut(visitor),
        }
    }

    pub fn visit_vars<'ir, V>(&'ir self, visitor: &mut V)
    where
        V: VisitVars<'ir>,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit_vars(visitor),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.visit_vars(visitor),
        }
    }

    pub fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit_vars_mut(visitor),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.visit_vars_mut(visitor),
        }
    }

    pub fn visit_vars_with<'ir, V>(&'ir self, visitor: &mut V, only_free_uses: bool)
    where
        V: VisitVars<'ir>,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit_vars_with(visitor, only_free_uses),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => {
                chunked.visit_vars_with(visitor, only_free_uses)
            }
        }
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> EmptyOrChunkedCodeBlockFomatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }
}

pub struct EmptyOrChunkedCodeBlockFomatter<'cb, 'trans> {
    blk: &'cb EmptyOrChunkedCodeBlock,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'cb, 'trans> fmt::Display for EmptyOrChunkedCodeBlockFomatter<'cb, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match &self.blk {
            EmptyOrChunkedCodeBlock::Empty(empty) => {
                empty.display_full(Cow::Borrowed(&*self.fmt)).fmt(f)
            }
            EmptyOrChunkedCodeBlock::Chunked(chunked) => {
                chunked.display_full(Cow::Borrowed(&*self.fmt)).fmt(f)
            }
        }
    }
}

impl<'cb, 'trans> TranslatorDisplay<'cb, 'trans> for EmptyOrChunkedCodeBlock {
    type Target = EmptyOrChunkedCodeBlockFomatter<'cb, 'trans>;

    fn display_full(&'cb self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        EmptyOrChunkedCodeBlockFomatter { blk: self, fmt }
    }
}

impl VisitOpVarsMut for EmptyOrChunkedCodeBlock {
    fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit_vars_mut(visitor),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.visit_vars_mut(visitor),
        }
    }

    fn visit_phi_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.visit_phi_vars_mut(visitor),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.visit_phi_vars_mut(visitor),
        }
    }
}

impl PhiVarsMut for EmptyOrChunkedCodeBlock {
    fn push_phi(&mut self, phi: Phi) {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.push_phi(phi),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.push_phi(phi),
        }
    }

    fn clear_phis(&mut self) {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.clear_phis(),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.clear_phis(),
        }
    }

    fn get_phi(&self, var: impl Into<SimpleVar>) -> Option<&Phi> {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.get_phi(var),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.get_phi(var),
        }
    }

    fn get_phi_mut(&mut self, var: impl Into<SimpleVar>) -> Option<&mut Phi> {
        match self {
            EmptyOrChunkedCodeBlock::Empty(empty) => empty.get_phi_mut(var),
            EmptyOrChunkedCodeBlock::Chunked(chunked) => chunked.get_phi_mut(var),
        }
    }
}
