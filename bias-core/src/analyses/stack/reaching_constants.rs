use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};

use itertools::Itertools;
use petgraph::visit::{EdgeRef, IntoEdgesDirected, VisitMap, Visitable};
use petgraph::EdgeDirection;

use crate::analyses::stack::aliases::{
    FunctionStackAccesses, FunctionStackRefs, StackAccessVisitor, StackAccesses,
};
use crate::analyses::stack::StackVarDef;
use crate::ir::{BinOp, UnOp};
use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
pub enum ConstValue {
    Top,
    Val(BitVec),
    Bot,
}

impl Default for ConstValue {
    fn default() -> Self {
        Self::Bot
    }
}

impl Display for ConstValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bot => write!(f, "?"),
            Self::Val(v) => {
                if v.msb() {
                    write!(f, "-{:x}", -v.clone().signed())
                } else {
                    write!(f, "{:x}", v)
                }
            }
        }
    }
}

impl ToAddress for ConstValue {
    fn to_address(&self) -> Option<Address> {
        match self {
            Self::Val(bv) => bv.to_address(),
            _ => None,
        }
    }
}

impl ConstValue {
    pub fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    pub fn is_bot(&self) -> bool {
        matches!(self, Self::Bot)
    }

    pub fn is_unk(&self) -> bool {
        matches!(self, Self::Top | Self::Bot)
    }

    pub fn val(value: impl Into<BitVec>) -> Self {
        Self::Val(value.into())
    }

    pub fn as_val(&self) -> Option<&BitVec> {
        if let Self::Val(bv) = self {
            Some(bv)
        } else {
            None
        }
    }

    pub fn join(&mut self, other: Self) {
        match (&self, other) {
            (Self::Top, _) | (_, Self::Top) => {
                *self = Self::Top;
            }
            (Self::Bot, v) => {
                *self = v;
            }
            (_, Self::Bot) => {}
            (Self::Val(v1), Self::Val(v2)) => {
                if *v1 != v2 {
                    *self = Self::Top;
                }
            }
        }
    }

    #[inline(always)]
    fn lift1_val(self, f: impl Fn(BitVec) -> BitVec) -> Self {
        if let Self::Val(v) = self {
            Self::Val(f(v))
        } else if self.is_bot() {
            Self::Bot
        } else {
            Self::Top
        }
    }

    #[inline(always)]
    fn try_lift2_bv(
        mut lexpr: BitVec,
        mut rexpr: BitVec,
        f: impl Fn(BitVec, BitVec) -> Option<BitVec>,
    ) -> Option<BitVec> {
        let lbits = lexpr.bits();
        let rbits = rexpr.bits();

        if lbits != rbits {
            if lbits > rbits {
                rexpr.cast_assign(lbits)
            } else {
                lexpr.cast_assign(rbits)
            }
        }

        f(lexpr, rexpr)
    }

    #[inline(always)]
    fn try_lift2_val(self, rexpr: Self, f: impl Fn(BitVec, BitVec) -> Option<BitVec>) -> Self {
        match (self, rexpr) {
            (Self::Val(l), Self::Val(r)) => {
                if let Some(bv) = Self::try_lift2_bv(l, r, f) {
                    Self::Val(bv)
                } else {
                    Self::Bot
                }
            }
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
        }
    }

    #[inline(always)]
    fn lift2_bv(
        mut lexpr: BitVec,
        mut rexpr: BitVec,
        f: impl Fn(BitVec, BitVec) -> BitVec,
    ) -> BitVec {
        let lbits = lexpr.bits();
        let rbits = rexpr.bits();

        if lbits != rbits {
            if lbits > rbits {
                rexpr.cast_assign(lbits)
            } else {
                lexpr.cast_assign(rbits)
            }
        }

        f(lexpr, rexpr)
    }

    #[inline]
    fn lift2_val(self, rexpr: Self, f: impl Fn(BitVec, BitVec) -> BitVec) -> Self {
        match (self, rexpr) {
            (Self::Val(l), Self::Val(r)) => Self::Val(Self::lift2_bv(l, r, f)),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
        }
    }
}

pub struct ReachingStackConstsVisitor<'a> {
    rsmapping: AHashMap<StackVarDef, ConstValue>,
    tmapping: AHashMap<Var, ConstValue>,
    location: Location,
    functions: &'a FunctionTable,
    injections: &'a InjectionManager,
    registers: &'a VarView,
    clobbers: AHashSet<Var>,
    // stack_vars: &'a StackView,
    stack_accesses: &'a StackAccesses,
    stack_pointer: Var,
    extra_pop: BitVec,
}

impl<'a> ReachingStackConstsVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        functions: &'a FunctionTable,
        injections: &'a InjectionManager,
        // stack_vars: &'a StackView,
        stack_accesses: &'a StackAccesses,
    ) -> Self {
        Self::new_with(
            lifter,
            functions,
            injections,
            AHashMap::default(),
            /* stack_vars, */ stack_accesses,
        )
    }

    pub fn new_with(
        lifter: &'a Lifter,
        functions: &'a FunctionTable,
        injections: &'a InjectionManager,
        rsmapping: AHashMap<StackVarDef, ConstValue>,
        // stack_vars: &'a StackView,
        stack_accesses: &'a StackAccesses,
    ) -> Self {
        let prototype = lifter.default_prototype();
        let registers = &lifter.register_map();
        let clobbers = prototype
            .killed_registers()
            .into_iter()
            .chain(prototype.output_registers().into_iter())
            .map(|var| registers.parent(&var).unwrap_or(var))
            .collect();
        let stack_pointer = lifter.stack_pointer();

        Self {
            rsmapping,
            tmapping: AHashMap::default(),
            location: Location::default(),
            registers,
            functions,
            injections,
            clobbers,
            // stack_vars,
            stack_accesses,
            stack_pointer,
            extra_pop: BitVec::from_u64(
                lifter.default_prototype().extra_pop(),
                stack_pointer.nbits() as _,
            ),
        }
    }

    pub fn constant_values(&self) -> impl Iterator<Item = (&StackVarDef, &BitVec)> {
        self.rsmapping
            .iter()
            .filter_map(|(var, val)| val.as_val().map(|val| (var, val)))
    }

    #[inline]
    fn eval_expr(&mut self, expr: &Term<Expr>) -> ConstValue {
        match &**expr {
            Expr::Var(rvar) => {
                let rvar = self.registers.parent(rvar).unwrap_or(*rvar);
                if rvar.is_register() {
                    self.rsmapping
                        .get(&StackVarDef::Var(rvar))
                        .cloned()
                        .unwrap_or_default()
                } else if rvar.is_temporary() {
                    self.tmapping.get(&rvar).cloned().unwrap_or_default()
                } else {
                    ConstValue::Top
                }
            }
            Expr::Val(rval, _) => ConstValue::val(rval.to_owned()),
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(expr);
                match op {
                    UnOp::NEG => ConstValue::lift1_val(val, BitVec::neg),
                    UnOp::NOT => ConstValue::lift1_val(val, BitVec::not),
                    _ => {
                        if val.is_bot() {
                            ConstValue::Bot
                        } else {
                            ConstValue::Top
                        }
                    }
                }
            }
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);
                match op {
                    BinOp::ADD => ConstValue::lift2_val(lval, rval, BitVec::add),
                    BinOp::SUB => ConstValue::lift2_val(lval, rval, BitVec::sub),
                    BinOp::MUL => ConstValue::lift2_val(lval, rval, BitVec::mul),
                    BinOp::DIV => ConstValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::div(l, r))
                        }
                    }),
                    BinOp::REM => ConstValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::rem(l, r))
                        }
                    }),
                    BinOp::SDIV => ConstValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_div_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::SREM => ConstValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_rem_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::AND => ConstValue::lift2_val(lval, rval, BitVec::bitand),
                    BinOp::OR => ConstValue::lift2_val(lval, rval, BitVec::bitor),
                    BinOp::XOR => ConstValue::lift2_val(lval, rval, BitVec::bitxor),
                    BinOp::SHL => ConstValue::lift2_val(lval, rval, BitVec::shl),
                    BinOp::SHR => ConstValue::lift2_val(lval, rval, BitVec::shr),
                    BinOp::SAR => ConstValue::lift2_val(lval, rval, |mut l, r| {
                        l.signed_shr_assign(&r);
                        l
                    }),
                }
            }
            Expr::Load(expr, sz, _) => {
                let aval = self.eval_expr(expr);

                if let Some(loads) = self.stack_accesses.loads_at(&self.location) {
                    for load in loads {
                        if let Some(val) = self.rsmapping.get(&StackVarDef::Stack(*load)) {
                            return val.clone().lift1_val(|val| val.unsigned_cast(*sz as _));
                        }
                    }
                    return ConstValue::Bot; // we expect the value to change
                }

                if aval.is_bot() {
                    ConstValue::Bot
                } else {
                    ConstValue::Top
                }
            }
            _ => ConstValue::Top,
        }
    }

    #[inline]
    fn eval_stmt(&mut self, stmt: &Term<Stmt>) {
        match &**stmt {
            Stmt::Assign(var, expr) => {
                if var.is_address() {
                    self.eval_expr(expr);
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);
                let val = self.eval_expr(expr);

                if lvar.is_register() {
                    self.rsmapping.insert(lvar.into(), val);
                } else {
                    self.tmapping.insert(lvar, val);
                }
            }
            Stmt::Store(_, src, sz, _) => {
                let val = self.eval_expr(src);
                if let Some(stores) = self.stack_accesses.stores_at(&self.location) {
                    for store in stores {
                        self.rsmapping.insert(
                            StackVarDef::Stack(*store),
                            val.clone().lift1_val(|val| val.unsigned_cast(*sz as _)),
                        );
                    }
                }
            }
            Stmt::Call(br, _) => {
                let target = self.eval_branch(br);

                // NOTE: we may have a fixup override
                if let Some(f) = target
                    .to_address()
                    .and_then(|addr| self.functions.get_point(addr))
                    .and_then(|f| {
                        self.injections
                            .get_function_stub(f.id())
                            .and_then(InjectionStub::fixup)
                    })
                {
                    for op in f.operations() {
                        self.eval_stmt(op);
                    }
                    return;
                }

                self.rsmapping.iter_mut().for_each(|(var, val)| {
                    if let StackVarDef::Var(var) = var {
                        if self.clobbers.contains(var) {
                            *val = ConstValue::Bot;
                        }
                    }
                });

                match self.rsmapping.entry(self.stack_pointer.into()) {
                    Entry::Vacant(e) => {
                        e.insert(ConstValue::Bot);
                    }
                    Entry::Occupied(mut e) => {
                        let val = std::mem::take(e.get_mut());
                        e.insert(ConstValue::lift2_val(
                            val,
                            ConstValue::val(self.extra_pop.clone()),
                            BitVec::add,
                        ));
                    }
                }
            }
            _ => (),
        }
    }

    #[inline]
    fn eval_branch(&mut self, target: &Term<BranchTarget>) -> ConstValue {
        match &**target {
            BranchTarget::Location(loc) => ConstValue::val(BitVec::from_u64(
                loc.address().offset(),
                self.stack_pointer.nbits() as _,
            )),
            BranchTarget::Computed(loc) => self.eval_expr(loc),
            BranchTarget::External(_, _) => ConstValue::Top,
        }
    }

    #[inline]
    pub fn eval_insn(&mut self, insn: &Term<Insn>) {
        self.tmapping.clear();
        for (i, stmt) in insn.operations().iter().enumerate() {
            self.location = Location::new(insn.address(), i);
            self.eval_stmt(stmt);
        }
    }

    #[inline]
    pub fn eval_block(&mut self, block: &CodeBlock) {
        for insn in block.insns() {
            self.eval_insn(insn);
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockReachingStackConsts {
    incoming: AHashMap<StackVarDef, ConstValue>,
    outgoing: AHashMap<StackVarDef, ConstValue>,
}

impl BlockReachingStackConsts {
    #[inline]
    pub fn incoming(&self) -> &AHashMap<StackVarDef, ConstValue> {
        &self.incoming
    }

    #[inline]
    pub fn incoming_values(&self) -> impl Iterator<Item = (&StackVarDef, &BitVec)> {
        self.incoming.iter().filter_map(|(var, val)| {
            if let Some(val) = val.as_val() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn outgoing(&self) -> &AHashMap<StackVarDef, ConstValue> {
        &self.outgoing
    }

    #[inline]
    pub fn outgoing_values(&self) -> impl Iterator<Item = (&StackVarDef, &BitVec)> {
        self.outgoing.iter().filter_map(|(var, val)| {
            if let Some(val) = val.as_val() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn incoming_stack(&self, project: &Project) -> Vec<(i64, Vec<u8>)> {
        Self::stack(&self.incoming, project)
    }

    #[inline]
    pub fn outgoing_stack(&self, project: &Project) -> Vec<(i64, Vec<u8>)> {
        Self::stack(&self.outgoing, project)
    }

    #[inline]
    fn stack(values: &AHashMap<StackVarDef, ConstValue>, project: &Project) -> Vec<(i64, Vec<u8>)> {
        let stack_values = values
            .iter()
            .filter_map(|(var, val)| {
                let offset = var.stack_delta()?;
                let value = val.as_val()?;
                Some((offset, value))
            })
            .sorted_by_key(|(k, _)| *k);

        let mut regions = Vec::<(i64, Vec<u8>)>::new();

        for (off, val) in stack_values {
            if let Some((last_off, last_buf)) = regions.last_mut() {
                let last_len = last_buf.len();
                if *last_off + last_len as i64 == off {
                    last_buf.extend(std::iter::repeat(0u8).take(val.bits() / 8));
                    if project.lifter().endian().is_big() {
                        val.to_be_bytes(&mut last_buf[last_len..]);
                    } else {
                        val.to_le_bytes(&mut last_buf[last_len..]);
                    }

                    continue;
                }
            }

            let mut buf = vec![0u8; val.bits() / 8];
            if project.lifter().endian().is_big() {
                val.to_be_bytes(&mut buf);
            } else {
                val.to_le_bytes(&mut buf);
            }
            regions.push((off, buf));
        }

        regions
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionReachingStackConsts {
    blocks: AHashMap<CodeBlockId, BlockReachingStackConsts>,
}

impl FunctionReachingStackConsts {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockReachingStackConsts> {
        &self.blocks
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReachingStackConsts {
    mapping: AHashMap<FunctionId, FunctionReachingStackConsts>,
}

impl ReachingStackConsts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, FunctionReachingStackConsts> {
        &self.mapping
    }

    #[inline]
    pub fn analyse_function(
        project: &Project,
        f: &Function,
        accesses: &FunctionStackRefs,
    ) -> FunctionReachingStackConsts {
        Self::analyse_function_with(project, f, accesses, None)
    }

    #[inline]
    pub fn analyse_function_with<'a>(
        project: &'a Project,
        f: &'a Function,
        accesses: &'a FunctionStackRefs,
        block_accesses: impl Into<Option<&'a FunctionStackAccesses>>,
    ) -> FunctionReachingStackConsts {
        let mut gkmap = AHashMap::new();

        let lifter = project.lifter();
        let functions = project.functions();
        let injections = project.injections();

        let mut blk_accesses = AHashMap::with_capacity(0);

        let block_accesses = match block_accesses.into() {
            Some(accesses) => {
                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingStackConsts::default());
                }
                accesses.blocks()
            }
            None => {
                let mut access_visitor = StackAccessVisitor::new(lifter, functions, injections);

                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingStackConsts::default());
                    blk_accesses.insert(
                        id,
                        access_visitor.analyse_block(&accesses.blocks()[&id], blk),
                    );
                }

                &blk_accesses
            }
        };

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());
        let mut edge_visitor = cfg.visit_map();

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut nincoming = AHashMap::<StackVarDef, ConstValue>::new();

            edge_visitor.clear();

            for pred in cfg
                .edges_directed(blk.node(), EdgeDirection::Incoming)
                .filter_map(|e| {
                    if edge_visitor.visit(e.source()) {
                        gkmap.get(&project.icfg()[e.source()])
                    } else {
                        None
                    }
                })
            {
                for (k, v) in pred.outgoing.iter() {
                    match nincoming.entry(*k) {
                        Entry::Occupied(mut e) => {
                            e.get_mut().join(v.to_owned());
                        }
                        Entry::Vacant(e) => {
                            e.insert(v.to_owned());
                        }
                    }
                }
            }

            let accesses = &block_accesses[&blk.id()];

            let mut builder = ReachingStackConstsVisitor::new_with(
                lifter,
                functions,
                injections,
                nincoming.clone(),
                accesses,
            );

            builder.eval_block(blk);

            let noutgoing = builder.rsmapping;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing != current.outgoing;

            current.incoming = nincoming;
            current.outgoing = noutgoing;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionReachingStackConsts { blocks: gkmap }
    }
}
