use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};

use fugue::ir::convention::PrototypeOperand;
use petgraph::visit::{EdgeRef, IntoEdgesDirected, VisitMap, Visitable};
use petgraph::EdgeDirection;

use crate::analyses::stack::StackAccess;
use crate::ir::{BinOp, BranchTarget, UnOp};
use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
pub enum StackRefValue {
    Top,
    Val(BitVec),
    Var(BitVec),
    Bot,
}

impl Default for StackRefValue {
    fn default() -> Self {
        Self::Bot
    }
}

impl Display for StackRefValue {
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
            Self::Var(v) => {
                if v.msb() {
                    write!(f, "sp-{:x}", -v.clone().signed())
                } else {
                    write!(f, "sp+{:x}", v)
                }
            }
        }
    }
}

impl ToAddress for StackRefValue {
    fn to_address(&self) -> Option<Address> {
        match self {
            Self::Val(bv) => bv.to_address(),
            _ => None,
        }
    }
}

impl StackRefValue {
    pub fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    pub fn is_bot(&self) -> bool {
        matches!(self, Self::Bot)
    }

    pub fn is_unk(&self) -> bool {
        matches!(self, Self::Top | Self::Bot)
    }

    pub fn is_ref(&self) -> bool {
        matches!(self, Self::Var(_))
    }

    pub fn is_val(&self) -> bool {
        matches!(self, Self::Val(_))
    }

    pub fn stack_var(lifter: &Lifter) -> Self {
        Self::Var(BitVec::zero(lifter.address_bits() as _))
    }

    pub fn val(value: impl Into<BitVec>) -> Self {
        Self::Val(value.into())
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
            (Self::Var(v1), Self::Var(v2)) => {
                if *v1 != v2 {
                    *self = Self::Top;
                }
            }
            _ => {
                *self = Self::Top;
            }
        }
    }

    #[inline(always)]
    fn lift1_val(expr: Self, f: impl Fn(BitVec) -> BitVec) -> Self {
        if let Self::Val(v) = expr {
            Self::Val(f(v))
        } else if expr.is_bot() {
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

    #[inline]
    fn try_lift2_val(
        lexpr: Self,
        rexpr: Self,
        f: impl Fn(BitVec, BitVec) -> Option<BitVec>,
    ) -> Self {
        match (lexpr, rexpr) {
            (Self::Val(l), Self::Val(r)) => {
                if let Some(bv) = Self::try_lift2_bv(l, r, f) {
                    Self::Val(bv)
                } else {
                    Self::Top
                }
            }
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
            (mut l, r) => {
                l.join(r);
                l
            }
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
    fn lift2_val(lexpr: Self, rexpr: Self, f: impl Fn(BitVec, BitVec) -> BitVec) -> Self {
        match (lexpr, rexpr) {
            (Self::Val(l), Self::Val(r)) => Self::Val(Self::lift2_bv(l, r, f)),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
            (mut l, r) => {
                l.join(r);
                l
            }
        }
    }

    #[inline]
    fn lift2_any(lexpr: Self, rexpr: Self, f: impl Fn(BitVec, BitVec) -> BitVec) -> Self {
        match (lexpr, rexpr) {
            (Self::Val(l), Self::Val(r)) => Self::Val(Self::lift2_bv(l, r, f)),
            (Self::Var(l), Self::Val(r)) => Self::Var(Self::lift2_bv(l, r, f)),
            (Self::Val(l), Self::Var(r)) => Self::Var(Self::lift2_bv(l, r, f)),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
            (mut l, r) => {
                l.join(r);
                l
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StackAccesses {
    stack_loads: AHashMap<Location, AHashSet<StackAccess>>,
    stack_stores: AHashMap<Location, AHashSet<StackAccess>>,
    stack_call_state: AHashMap<Location, AHashMap<Var, i64>>,
    stack_call_fixups: AHashMap<Location, FunctionId>,
}

impl StackAccesses {
    #[inline]
    pub fn loads(&self) -> &AHashMap<Location, AHashSet<StackAccess>> {
        &self.stack_loads
    }

    #[inline]
    pub fn loads_at(&self, location: &Location) -> Option<&AHashSet<StackAccess>> {
        self.stack_loads.get(location)
    }

    #[inline]
    pub fn stores(&self) -> &AHashMap<Location, AHashSet<StackAccess>> {
        &self.stack_stores
    }

    #[inline]
    pub fn stores_at(&self, location: &Location) -> Option<&AHashSet<StackAccess>> {
        self.stack_stores.get(location)
    }

    #[inline]
    pub fn call_states(&self) -> &AHashMap<Location, AHashMap<Var, i64>> {
        &self.stack_call_state
    }

    #[inline]
    pub fn call_state_at(&self, location: &Location) -> Option<&AHashMap<Var, i64>> {
        self.stack_call_state.get(location)
    }

    pub fn call_fixup_at(&self, location: &Location) -> Option<FunctionId> {
        self.stack_call_fixups.get(location).copied()
    }

    #[inline]
    pub fn resolve_at(
        &self,
        operand: &PrototypeOperand,
        lifter: &Lifter,
        location: &Location,
    ) -> Option<i64> {
        let call_state = self.call_state_at(location)?;

        match operand {
            PrototypeOperand::Register { varnode, .. } => {
                let var = Var::new0(
                    lifter.register_space(),
                    varnode.offset(),
                    varnode.size() as u32 * 8,
                );

                let avar = lifter.register_map().parent(&var).unwrap_or(var);

                call_state.get(&avar).copied()
            }
            PrototypeOperand::StackRelative(offset) => {
                let stack_pointer = *call_state.get(&lifter.stack_pointer())?;
                Some(stack_pointer + *offset as i64)
            }
            _ => None,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.stack_loads.is_empty() && self.stack_stores.is_empty()
    }
}

#[derive(Clone)]
pub struct StackAccessVisitor<'a> {
    rmapping: AHashMap<Var, StackRefValue>,
    tmapping: AHashMap<Var, StackRefValue>,
    stack_loads: AHashMap<Location, AHashSet<StackAccess>>,
    stack_stores: AHashMap<Location, AHashSet<StackAccess>>,
    stack_call_state: AHashMap<Location, AHashMap<Var, i64>>,
    stack_call_fixups: AHashMap<Location, FunctionId>,
    location: Location,
    functions: &'a FunctionTable,
    injections: &'a InjectionManager,
    registers: &'a VarView,
    stack_pointer: Var,
    extra_pop: BitVec,
}

impl<'a> StackAccessVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        functions: &'a FunctionTable,
        injections: &'a InjectionManager,
    ) -> Self {
        let stack_pointer = lifter.stack_pointer();
        Self {
            rmapping: AHashMap::new(),
            tmapping: AHashMap::new(),
            stack_loads: AHashMap::new(),
            stack_stores: AHashMap::new(),
            stack_call_state: AHashMap::new(),
            stack_call_fixups: AHashMap::new(),
            location: Location::default(),
            functions,
            injections,
            registers: &*lifter.register_map(),
            stack_pointer,
            extra_pop: BitVec::from_u64(
                lifter.default_prototype().extra_pop(),
                stack_pointer.nbits() as _,
            ),
        }
    }

    pub fn analyse_block(&mut self, refs: &BlockStackRefs, blk: &'a CodeBlock) -> StackAccesses {
        self.rmapping.clear();
        self.rmapping
            .extend(refs.incoming().iter().map(|(v, r)| (*v, r.clone())));

        for insn in blk.insns() {
            self.eval_insn(insn);
        }

        StackAccesses {
            stack_loads: std::mem::take(&mut self.stack_loads),
            stack_stores: std::mem::take(&mut self.stack_stores),
            stack_call_state: std::mem::take(&mut self.stack_call_state),
            stack_call_fixups: std::mem::take(&mut self.stack_call_fixups),
        }
    }

    #[inline]
    fn eval_expr(&mut self, expr: &Term<Expr>) -> StackRefValue {
        match &**expr {
            Expr::Var(rvar) => {
                let rvar = self.registers.parent(rvar).unwrap_or(*rvar);
                if rvar.is_register() {
                    self.rmapping
                        .get(&rvar)
                        .cloned()
                        .unwrap_or(StackRefValue::Bot)
                } else if rvar.is_temporary() {
                    self.tmapping
                        .get(&rvar)
                        .cloned()
                        .unwrap_or(StackRefValue::Bot)
                } else {
                    StackRefValue::Top
                }
            }
            Expr::Val(rval, _) => StackRefValue::val(rval.to_owned()),
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(expr);
                match op {
                    UnOp::NEG => StackRefValue::lift1_val(val, BitVec::neg),
                    UnOp::NOT => StackRefValue::lift1_val(val, BitVec::not),
                    _ => {
                        if val.is_bot() {
                            StackRefValue::Bot
                        } else {
                            StackRefValue::Top
                        }
                    }
                }
            }
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);
                match op {
                    BinOp::ADD => StackRefValue::lift2_any(lval, rval, BitVec::add),
                    BinOp::SUB => StackRefValue::lift2_any(lval, rval, BitVec::sub),
                    BinOp::MUL => StackRefValue::lift2_val(lval, rval, BitVec::mul),
                    BinOp::DIV => StackRefValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::div(l, r))
                        }
                    }),
                    BinOp::REM => StackRefValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::rem(l, r))
                        }
                    }),
                    BinOp::SDIV => StackRefValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_div_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::SREM => StackRefValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_rem_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::AND => StackRefValue::lift2_val(lval, rval, BitVec::bitand),
                    BinOp::OR => StackRefValue::lift2_val(lval, rval, BitVec::bitor),
                    BinOp::XOR => StackRefValue::lift2_val(lval, rval, BitVec::bitxor),
                    BinOp::SHL => StackRefValue::lift2_val(lval, rval, BitVec::shl),
                    BinOp::SHR => StackRefValue::lift2_val(lval, rval, BitVec::shr),
                    BinOp::SAR => StackRefValue::lift2_val(lval, rval, |mut l, r| {
                        l.signed_shr_assign(&r);
                        l
                    }),
                }
            }
            Expr::Load(expr, sz, _) => match self.eval_expr(expr) {
                StackRefValue::Var(off) => {
                    if let Some(offset) = off.to_i64() {
                        self.stack_loads
                            .entry(self.location)
                            .or_default()
                            .insert(StackAccess {
                                offset,
                                size: *sz as usize / 8,
                            });
                    }
                    StackRefValue::Top
                }
                _ => StackRefValue::Top,
            },
            // NOTE:
            // even though the operations below are unhandled,
            // we visit them to collect loads.
            Expr::Concat(lexpr, rexpr) | Expr::BinRel(_, lexpr, rexpr) => {
                self.eval_expr(lexpr);
                self.eval_expr(rexpr);
                StackRefValue::Top
            }
            Expr::Extract(expr, _, _)
            | Expr::ExtractHigh(expr, _)
            | Expr::ExtractLow(expr, _)
            | Expr::UnRel(_, expr)
            | Expr::Cast(expr, _) => {
                self.eval_expr(expr);
                StackRefValue::Top
            }
            Expr::IfElse(cexpr, texpr, fexpr) => {
                self.eval_expr(cexpr);
                let mut l = self.eval_expr(texpr);
                let r = self.eval_expr(fexpr);
                if !l.is_unk() && !r.is_unk() {
                    l.join(r);
                    l
                } else {
                    StackRefValue::Top
                }
            }
            Expr::Intrinsic(_, args, _) => {
                for arg in args {
                    self.eval_expr(arg);
                }
                StackRefValue::Top
            }
            _ => StackRefValue::Top,
        }
    }

    #[inline]
    fn eval_branch(&mut self, target: &Term<BranchTarget>) -> StackRefValue {
        match &**target {
            BranchTarget::Location(loc) => StackRefValue::val(BitVec::from_u64(
                loc.address().offset(),
                self.stack_pointer.nbits() as _,
            )),
            BranchTarget::Computed(loc) => self.eval_expr(loc),
            BranchTarget::External(_, _) => StackRefValue::Top,
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
                    self.rmapping.insert(lvar, val);
                } else {
                    self.tmapping.insert(lvar, val);
                }
            }
            Stmt::Store(dst, src, sz, _) => {
                self.eval_expr(src);
                if let StackRefValue::Var(off) = self.eval_expr(dst) {
                    if let Some(offset) = off.to_i64() {
                        self.stack_stores
                            .entry(self.location)
                            .or_default()
                            .insert(StackAccess {
                                offset,
                                size: *sz as usize / 8,
                            });
                    }
                }
            }
            Stmt::CBranch(cond, bt) => {
                self.eval_expr(cond);
                self.eval_branch(bt);
            }
            Stmt::Branch(bt) | Stmt::Return(bt) => {
                self.eval_branch(bt);
            }
            Stmt::Call(bt, args) => {
                for arg in args {
                    self.eval_expr(arg);
                }

                let target = self.eval_branch(bt);

                // save incoming state to call
                let call_state = self
                    .rmapping
                    .iter()
                    .filter_map(|(var, sref)| {
                        if let StackRefValue::Var(ref bv) = sref {
                            bv.to_i64().map(|offset| (*var, offset))
                        } else {
                            None
                        }
                    })
                    .collect();

                self.stack_call_state.insert(self.location, call_state);

                // NOTE: we still save the call-state, but we allow fixups to
                // determine the side-effects of the call (since this will generally
                // also include a fixup for the SP.
                if let Some((fid, f)) = target
                    .to_address()
                    .and_then(|addr| self.functions.get_point(addr))
                    .and_then(|f| {
                        let fid = f.id();
                        let fixup = self
                            .injections
                            .get_function_stub(fid)
                            .and_then(InjectionStub::fixup)?;
                        Some((fid, fixup))
                    })
                {
                    for op in f.operations() {
                        self.eval_stmt(op);
                    }

                    self.stack_call_fixups.insert(self.location, fid);
                    return;
                }

                match self.rmapping.entry(self.stack_pointer) {
                    Entry::Vacant(e) => {
                        e.insert(StackRefValue::Bot);
                    }
                    Entry::Occupied(mut e) => {
                        let val = std::mem::take(e.get_mut());
                        e.insert(StackRefValue::lift2_any(
                            val,
                            StackRefValue::val(self.extra_pop.clone()),
                            BitVec::add,
                        ));
                    }
                }
            }
            Stmt::Intrinsic(_, args) => {
                for arg in args {
                    self.eval_expr(arg);
                }
            }
            _ => (),
        }
    }

    #[inline]
    fn eval_insn(&mut self, insn: &Term<Insn>) {
        self.tmapping.clear();
        for (i, stmt) in insn.operations().iter().enumerate() {
            self.location = Location::new(insn.address(), i);
            self.eval_stmt(stmt);
        }
    }
}

#[derive(Clone)]
pub struct StackRefVisitor<'a> {
    rmapping: AHashMap<Var, StackRefValue>,
    tmapping: AHashMap<Var, StackRefValue>,
    functions: &'a FunctionTable,
    injections: &'a InjectionManager,
    registers: &'a VarView,
    stack_pointer: Var,
    extra_pop: BitVec,
}

#[inline]
fn incoming_map(
    lifter: &Lifter,
    injections: &InjectionManager,
    f: &Function,
    entry: bool,
) -> AHashMap<Var, StackRefValue> {
    let mut rmapping = AHashMap::new();
    if entry {
        let stack_pointer = lifter.stack_pointer();
        let stack_default = StackRefValue::stack_var(lifter);

        rmapping.insert(stack_pointer, stack_default);

        for (reg, val) in injections
            .global_values()
            .chain(injections.function_values(f.id()))
            .filter_map(|(opnd, val)| opnd.register().map(|r| (r, val)))
        {
            let avar = lifter.register_map().parent(&reg).unwrap_or(reg);
            let value = (reg != avar)
                .then(|| {
                    let mut val = val.unsigned_cast(avar.nbits() as _);
                    let voff = (reg.offset() - avar.offset()) as u32 * 8;
                    if voff != 0 {
                        val <<= voff;
                    }
                    val
                })
                .unwrap_or_else(|| val.to_owned());

            rmapping.insert(avar, StackRefValue::val(value));
        }
    }
    rmapping
}

impl<'a> StackRefVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        functions: &'a FunctionTable,
        injections: &'a InjectionManager,
        rmapping: AHashMap<Var, StackRefValue>,
    ) -> Self {
        let stack_pointer = lifter.stack_pointer();
        Self {
            functions,
            injections,
            registers: &*lifter.register_map(),

            rmapping,
            tmapping: AHashMap::new(),
            stack_pointer,
            extra_pop: BitVec::from_u64(
                lifter.default_prototype().extra_pop(),
                stack_pointer.nbits() as _,
            ),
        }
    }

    #[inline]
    fn eval_expr(&mut self, expr: &Term<Expr>) -> StackRefValue {
        match &**expr {
            Expr::Var(rvar) => {
                let rvar = self.registers.parent(rvar).unwrap_or(*rvar);
                if rvar.is_register() {
                    self.rmapping
                        .get(&rvar)
                        .cloned()
                        .unwrap_or(StackRefValue::Bot)
                } else if rvar.is_temporary() {
                    self.tmapping
                        .get(&rvar)
                        .cloned()
                        .unwrap_or(StackRefValue::Bot)
                } else {
                    StackRefValue::Top
                }
            }
            Expr::Val(rval, _) => StackRefValue::val(rval.to_owned()),
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(expr);
                match op {
                    UnOp::NEG => StackRefValue::lift1_val(val, BitVec::neg),
                    UnOp::NOT => StackRefValue::lift1_val(val, BitVec::not),
                    _ => {
                        if val.is_bot() {
                            StackRefValue::Bot
                        } else {
                            StackRefValue::Top
                        }
                    }
                }
            }
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);
                match op {
                    BinOp::ADD => StackRefValue::lift2_any(lval, rval, BitVec::add),
                    BinOp::SUB => StackRefValue::lift2_any(lval, rval, BitVec::sub),
                    BinOp::MUL => StackRefValue::lift2_val(lval, rval, BitVec::mul),
                    BinOp::DIV => StackRefValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::div(l, r))
                        }
                    }),
                    BinOp::REM => StackRefValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::rem(l, r))
                        }
                    }),
                    BinOp::SDIV => StackRefValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_div_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::SREM => StackRefValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_rem_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::AND => StackRefValue::lift2_val(lval, rval, BitVec::bitand),
                    BinOp::OR => StackRefValue::lift2_val(lval, rval, BitVec::bitor),
                    BinOp::XOR => StackRefValue::lift2_val(lval, rval, BitVec::bitxor),
                    BinOp::SHL => StackRefValue::lift2_val(lval, rval, BitVec::shl),
                    BinOp::SHR => StackRefValue::lift2_val(lval, rval, BitVec::shr),
                    BinOp::SAR => StackRefValue::lift2_val(lval, rval, |mut l, r| {
                        l.signed_shr_assign(&r);
                        l
                    }),
                }
            }
            Expr::Concat(_lexpr, _rexpr) | Expr::BinRel(_, _lexpr, _rexpr) => StackRefValue::Top,
            Expr::Extract(_expr, _, _)
            | Expr::ExtractHigh(_expr, _)
            | Expr::ExtractLow(_expr, _)
            | Expr::UnRel(_, _expr)
            | Expr::Cast(_expr, _) => StackRefValue::Top,
            Expr::IfElse(_cexpr, texpr, fexpr) => {
                let mut l = self.eval_expr(texpr);
                let r = self.eval_expr(fexpr);
                if !l.is_unk() && !r.is_unk() {
                    l.join(r);
                    l
                } else {
                    StackRefValue::Top
                }
            }
            Expr::Intrinsic(_, args, _) => {
                for arg in args {
                    self.eval_expr(arg);
                }
                StackRefValue::Top
            }
            _ => StackRefValue::Top,
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
                    self.rmapping.insert(lvar, val);
                } else {
                    self.tmapping.insert(lvar, val);
                }
            }
            Stmt::Call(br, _) => {
                let target = self.eval_branch(br);

                // NOTE: we may have an override
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

                match self.rmapping.entry(self.stack_pointer) {
                    Entry::Vacant(e) => {
                        e.insert(StackRefValue::Bot);
                    }
                    Entry::Occupied(mut e) => {
                        let val = std::mem::take(e.get_mut());
                        e.insert(StackRefValue::lift2_any(
                            val,
                            StackRefValue::val(self.extra_pop.clone()),
                            BitVec::add,
                        ));
                    }
                }
            }
            _ => (),
        }
    }

    fn eval_branch(&mut self, target: &Term<BranchTarget>) -> StackRefValue {
        match &**target {
            BranchTarget::Location(loc) => StackRefValue::val(BitVec::from_u64(
                loc.address().offset(),
                self.stack_pointer.nbits() as _,
            )),
            BranchTarget::Computed(loc) => self.eval_expr(loc),
            BranchTarget::External(_, _) => StackRefValue::Top,
        }
    }

    #[inline]
    pub fn eval_insn(&mut self, insn: &Term<Insn>) {
        self.tmapping.clear();
        for stmt in insn.operations() {
            self.eval_stmt(stmt);
        }
    }

    #[inline]
    pub fn alias(&self, var: &Var) -> StackRefValue {
        if var.is_register() {
            let avar = self.registers.parent(var).unwrap_or(*var);
            self.rmapping
                .get(&avar)
                .cloned()
                .unwrap_or(StackRefValue::Bot)
        } else {
            StackRefValue::Bot
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockStackRefs {
    incoming: AHashMap<Var, StackRefValue>,
    outgoing: AHashMap<Var, StackRefValue>,
}

impl BlockStackRefs {
    pub fn incoming(&self) -> &AHashMap<Var, StackRefValue> {
        &self.incoming
    }

    pub fn incoming_values(&self) -> impl Iterator<Item = (&Var, &StackRefValue)> {
        self.incoming.iter().filter_map(|(var, val)| {
            if !val.is_unk() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn outgoing(&self) -> &AHashMap<Var, StackRefValue> {
        &self.outgoing
    }

    pub fn outgoing_values(&self) -> impl Iterator<Item = (&Var, &StackRefValue)> {
        self.outgoing.iter().filter_map(|(var, val)| {
            if !val.is_unk() {
                Some((var, val))
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionStackRefs {
    blocks: AHashMap<CodeBlockId, BlockStackRefs>,
}

impl FunctionStackRefs {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockStackRefs> {
        &self.blocks
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionStackAccesses {
    blocks: AHashMap<CodeBlockId, StackAccesses>,
}

impl FunctionStackAccesses {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, StackAccesses> {
        &self.blocks
    }
}

#[derive(Clone, Debug, Default)]
pub struct StackRefs {
    mapping: AHashMap<FunctionId, FunctionStackRefs>,
}

impl StackRefs {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, FunctionStackRefs> {
        &self.mapping
    }

    #[inline]
    pub fn analyse_function_full(
        project: &Project,
        f: &Function,
    ) -> (FunctionStackRefs, FunctionStackAccesses) {
        let accesses = Self::analyse_function(project, f);

        let mut access_visitor =
            StackAccessVisitor::new(project.lifter(), project.functions(), project.injections());
        let mut block_accesses = FunctionStackAccesses::default();

        for blk in f.blocks_with(project.code_blocks()) {
            let id = blk.id();
            block_accesses.blocks.insert(
                id,
                access_visitor.analyse_block(&accesses.blocks()[&id], blk),
            );
        }

        (accesses, block_accesses)
    }

    #[inline]
    pub fn analyse_function(project: &Project, f: &Function) -> FunctionStackRefs {
        let mut gkmap = AHashMap::new();

        let lifter = project.lifter();
        let functions = project.functions();
        let injections = project.injections();

        let entry = f.entry();

        for blk in f.blocks_with(project.code_blocks()) {
            let init = BlockStackRefs {
                incoming: incoming_map(lifter, injections, f, blk.id() == entry),
                outgoing: Default::default(),
            };
            gkmap.insert(blk.id(), init);
        }

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());
        let mut edge_visitor = cfg.visit_map();

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut nincoming = incoming_map(lifter, injections, f, blk.id() == entry);

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

            let mut builder =
                StackRefVisitor::new(lifter, functions, injections, nincoming.clone());

            for insn in blk.insns() {
                builder.eval_insn(insn);
            }

            let noutgoing = builder.rmapping;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing != current.outgoing;

            current.incoming = nincoming;
            current.outgoing = noutgoing;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionStackRefs { blocks: gkmap }
    }
}
