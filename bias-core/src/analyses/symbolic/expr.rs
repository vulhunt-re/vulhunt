use std::collections::btree_map::Entry as BEntry;
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};

use petgraph::visit::{EdgeRef, IntoEdgesDirected, VisitMap, Visitable};
use petgraph::EdgeDirection;
use smallvec::{smallvec, SmallVec};

use crate::ir::{BinOp, BranchTarget, UnOp};
use crate::prelude::*;

pub trait AliasVisitor<'a> {
    #[allow(unused)]
    fn visit_aliases_pre(
        &mut self,
        insn: &Term<Insn>,
        position: usize,
        stmt: &Term<Stmt>,
        state: &AliasVisitorContext<'a>,
    ) {
    }

    #[allow(unused)]
    fn visit_aliases_post(
        &mut self,
        insn: &Term<Insn>,
        position: usize,
        stmt: &Term<Stmt>,
        state: &AliasVisitorContext<'a>,
    ) {
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub enum AliasValue {
    Top,
    V(BitVec),
    S(BitVec),
    G(Box<Self>, BitVec),
    R(Var, BitVec),
    Bot,
}

impl Default for AliasValue {
    fn default() -> Self {
        Self::Bot
    }
}

impl Display for AliasValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bot => write!(f, "?"),
            Self::V(v) => {
                if v.msb() {
                    write!(f, "-{:x}", -v.clone().signed())
                } else {
                    write!(f, "{:x}", v)
                }
            }
            Self::S(v) => {
                if v.msb() {
                    write!(f, "sp-{:x}", -v.clone().signed())
                } else {
                    write!(f, "sp+{:x}", v)
                }
            }
            Self::R(r, v) => {
                if v.is_zero() {
                    write!(f, "{r}")
                } else if v.msb() {
                    write!(f, "{r}-{:x}", -v.clone().signed())
                } else {
                    write!(f, "{r}+{:x}", v)
                }
            }
            Self::G(p, v) => {
                if p.is_ref() {
                    write!(f, "*({p})")?
                } else {
                    write!(f, "*{p}")?
                };
                if v.msb() {
                    write!(f, "-{:x}", -v.clone().signed())
                } else {
                    write!(f, "+{:x}", v)
                }
            }
        }
    }
}

impl AliasValue {
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
        matches!(self, Self::S(_) | Self::G(_, _))
    }

    pub fn is_val(&self) -> bool {
        matches!(self, Self::V(_))
    }

    pub fn is_reg(&self) -> bool {
        matches!(self, Self::R(_, _))
    }

    pub fn is_true(&self) -> Option<bool> {
        self.value().map(|bv| !bv.is_zero())
    }

    pub fn is_false(&self) -> Option<bool> {
        self.value().map(|bv| bv.is_zero())
    }

    pub fn stack_var(lifter: &Lifter) -> Self {
        Self::S(BitVec::zero(lifter.address_bits() as _))
    }

    pub fn val(value: impl Into<BitVec>) -> Self {
        Self::V(value.into())
    }

    pub fn reg(var: impl Into<Var>) -> Self {
        let var = var.into();
        Self::R(var, BitVec::zero(var.nbits() as _))
    }

    pub fn stack_delta(&self) -> Option<i64> {
        match self {
            Self::S(off) => off.signed_cast(64).to_i64(),
            _ => None,
        }
    }

    pub fn offset(&self) -> Option<usize> {
        match self {
            Self::S(off) | Self::G(_, off) | Self::R(_, off) => off.to_usize(),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<&BitVec> {
        if let Self::V(ref v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::G(v, off) if off.is_zero() => {
                if let Self::V(bv) = &**v {
                    bv.to_address()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn ptr0(gptr: impl Into<BitVec>, off: impl Into<BitVec>) -> Self {
        Self::ptr(Self::val(gptr), off)
    }

    pub fn ptr(gptr: impl Into<Self>, off: impl Into<BitVec>) -> Self {
        Self::G(Box::new(gptr.into()), off.into())
    }

    pub fn global_base_ptr(&self) -> Option<Address> {
        if let Self::G(base, _) = self {
            base.global_base_ptr_aux()
        } else {
            None
        }
    }

    #[inline]
    fn global_base_ptr_aux(&self) -> Option<Address> {
        match self {
            Self::V(bv) => bv.to_address(),
            Self::G(base, _) => base.global_base_ptr_aux(),
            _ => None,
        }
    }

    #[inline]
    pub fn decompose_global_access(&self) -> Option<(Address, SmallVec<[i64; 2]>)> {
        if let Self::G(base, offset) = self {
            let mut offsets = smallvec![offset.to_i64()?];
            base.decompose_global_access_aux(&mut offsets)
                .map(|address| {
                    offsets.reverse();
                    (address, offsets)
                })
        } else {
            None
        }
    }

    fn decompose_global_access_aux(&self, offsets: &mut SmallVec<[i64; 2]>) -> Option<Address> {
        match self {
            Self::V(bv) => bv.to_address(),
            Self::G(base, offset) => {
                offsets.push(offset.to_i64()?);
                base.decompose_global_access_aux(offsets)
            }
            _ => None,
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
            (Self::V(v1), Self::V(v2)) => {
                if *v1 != v2 {
                    *self = Self::Top;
                }
            }
            (Self::S(v1), Self::S(v2)) => {
                if *v1 != v2 {
                    *self = Self::Top;
                }
            }
            (Self::R(r1, v1), Self::R(r2, v2)) => {
                if *r1 != r2 || *v1 != v2 {
                    *self = Self::Top;
                }
            }
            (Self::G(p1, v1), Self::G(p2, v2)) => {
                if *p1 != p2 || *v1 != v2 {
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
        if let Self::V(v) = expr {
            Self::V(f(v))
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
            (Self::V(l), Self::V(r)) => {
                if let Some(bv) = Self::try_lift2_bv(l, r, f) {
                    Self::V(bv)
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
            (Self::V(l), Self::V(r)) => Self::V(Self::lift2_bv(l, r, f)),
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
            (Self::V(l), Self::V(r)) => Self::V(Self::lift2_bv(l, r, f)),
            (Self::S(l), Self::V(r)) => Self::S(Self::lift2_bv(l, r, f)),
            (Self::V(l), Self::S(r)) => Self::S(Self::lift2_bv(l, r, f)),
            (Self::R(rr, l), Self::V(r)) => Self::R(rr, Self::lift2_bv(l, r, f)),
            (Self::V(l), Self::R(rr, r)) => Self::R(rr, Self::lift2_bv(l, r, f)),
            (Self::G(p, l), Self::V(r)) => Self::G(p, Self::lift2_bv(l, r, f)),
            (Self::V(l), Self::G(p, r)) => Self::G(p, Self::lift2_bv(l, r, f)),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
            (mut l, r) => {
                l.join(r);
                l
            }
        }
    }

    #[inline]
    pub fn extract(self, offset: usize, bytes: usize) -> Self {
        match self {
            Self::V(ref v) => {
                let vbytes = v.bits() / 8;
                let nbytes = offset + bytes;

                if nbytes > vbytes {
                    return Self::Top;
                }

                if offset > 0 {
                    Self::V((v >> (offset as u32 * 8)).unsigned_cast(bytes * 8))
                } else {
                    Self::V(v.unsigned_cast(bytes * 8))
                }
            }
            Self::S(bv) => {
                let bits = bv.bits();
                Self::S(bv + BitVec::from_usize(offset, bits))
            }
            Self::R(rr, bv) => {
                let bits = bv.bits();
                Self::R(rr, bv + BitVec::from_usize(offset, bits))
            }
            Self::G(_, _) if offset == 0 => self,
            Self::Bot => Self::Bot,
            _ => Self::Top,
        }
    }

    #[inline]
    pub fn blit_into(self, offset: usize, bytes: usize, val: &mut Option<Self>) {
        match self {
            Self::V(mut v) => match val {
                None => {
                    v.unsigned_cast_assign(bytes * 8);
                    if offset > 0 {
                        v <<= offset as u32 * 8;
                    }
                    *val = Some(Self::V(v));
                }
                Some(Self::V(old)) => {
                    let nbits = bytes * 8;

                    if old.bits() == v.bits() && offset == 0 {
                        v.unsigned_cast_assign(nbits);
                        *old = v;
                    } else {
                        let mask0 = !(BitVec::max_value_with(nbits, false) << v.nbits())
                            << (offset as u32 * 8);
                        v.unsigned_cast_assign(nbits);
                        v &= &mask0;

                        let mask1 = !mask0;
                        old.unsigned_cast_assign(nbits);

                        *old &= mask1;
                        *old |= v;
                    }
                }
                Some(ref mut old) => {
                    if offset == 0 && v.nbits() as usize / 8 == bytes {
                        *old = Self::V(v);
                    } else if offset == 0 {
                        // partial update
                        *old = Self::V(v);
                    } else {
                        *old = Self::Top;
                    }
                }
            },
            _ if offset == 0 => {
                *val = if self.is_unk() {
                    Some(Self::Top)
                } else {
                    Some(self)
                };
            }
            _ => *val = Some(Self::Top),
        }
    }
}

#[derive(Clone)]
pub struct AliasVisitorContext<'a> {
    rmapping: AHashMap<Var, AliasValue>,
    smapping: BTreeMap<i64, AliasValue>,
    gmapping: BTreeMap<Address, AliasValue>,
    tmapping: AHashMap<Var, AliasValue>,
    call_target: Option<AliasValue>,
    memory: &'a Memory,
    registers: &'a VarView,
    stack_pointer: Var,
    extra_pop: BitVec,
}

#[inline]
fn incoming_map(lifter: &Lifter, entry: bool) -> AHashMap<Var, AliasValue> {
    let mut rmapping = AHashMap::new();
    if entry {
        let stack_pointer = lifter.stack_pointer();
        let stack_default = AliasValue::stack_var(lifter);

        rmapping.insert(stack_pointer, stack_default);
    }
    rmapping
}

impl<'a> AliasVisitorContext<'a> {
    pub fn new(
        lifter: &'a Lifter,
        memory: &'a Memory,
        rmapping: AHashMap<Var, AliasValue>,
        smapping: BTreeMap<i64, AliasValue>,
        gmapping: BTreeMap<Address, AliasValue>,
    ) -> Self {
        let stack_pointer = lifter.stack_pointer();
        Self {
            registers: &*lifter.register_map(),
            memory,

            rmapping,
            smapping,
            gmapping,
            tmapping: AHashMap::new(),

            call_target: None,

            stack_pointer,
            extra_pop: BitVec::from_u64(
                lifter.default_prototype().extra_pop(),
                stack_pointer.nbits() as _,
            ),
        }
    }

    pub fn empty(lifter: &'a Lifter, memory: &'a Memory) -> Self {
        Self::new(
            lifter,
            memory,
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }

    #[inline]
    fn eval_expr(&mut self, expr: &Term<Expr>) -> AliasValue {
        match &**expr {
            Expr::Var(var) => {
                let rvar = self.registers.parent(var).unwrap_or(*var);

                let val = if rvar.is_register() {
                    let val = self
                        .rmapping
                        .get(&rvar)
                        .cloned()
                        .unwrap_or(AliasValue::reg(rvar));
                    if val.is_ref() && rvar == *var {
                        val
                    } else {
                        let shift = (var.offset() - rvar.offset()) as usize;
                        let bytes = var.nbits() as usize / 8;
                        val.extract(shift, bytes)
                    }
                } else if rvar.is_temporary() {
                    let val = self.tmapping.get(&rvar).cloned().unwrap_or(AliasValue::Bot);
                    if val.is_ref() && rvar == *var {
                        val
                    } else {
                        let shift = (var.offset() - rvar.offset()) as usize;
                        let bytes = var.nbits() as usize / 8;
                        val.extract(shift, bytes)
                    }
                } else {
                    rvar.address()
                        .map(|addr| {
                            AliasValue::ptr0(
                                BitVec::from_u64(addr.offset(), self.stack_pointer.nbits() as _),
                                BitVec::zero(self.stack_pointer.nbits() as _),
                            )
                        })
                        .unwrap_or(AliasValue::Top)
                };

                val
            }
            Expr::Val(rval, _) => AliasValue::val(rval.to_owned()),
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(expr);
                match op {
                    UnOp::NEG => AliasValue::lift1_val(val, BitVec::neg),
                    UnOp::NOT => {
                        if expr.is_bool() {
                            AliasValue::lift1_val(val, |v| !v & BitVec::one(8))
                        } else {
                            AliasValue::lift1_val(val, BitVec::not)
                        }
                    }
                    _ => {
                        if val.is_bot() {
                            AliasValue::Bot
                        } else {
                            AliasValue::Top
                        }
                    }
                }
            }
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);
                match op {
                    BinOp::ADD => AliasValue::lift2_any(lval, rval, BitVec::add),
                    BinOp::SUB => AliasValue::lift2_any(lval, rval, BitVec::sub),
                    BinOp::MUL => AliasValue::lift2_val(lval, rval, BitVec::mul),
                    BinOp::DIV => AliasValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::div(l, r))
                        }
                    }),
                    BinOp::REM => AliasValue::try_lift2_val(lval, rval, |l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            Some(BitVec::rem(l, r))
                        }
                    }),
                    BinOp::SDIV => AliasValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_div_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::SREM => AliasValue::try_lift2_val(lval, rval, |mut l, r| {
                        if r.is_zero() {
                            None
                        } else {
                            l.signed_rem_assign(&r);
                            Some(l)
                        }
                    }),
                    BinOp::AND => AliasValue::lift2_val(lval, rval, BitVec::bitand),
                    BinOp::OR => AliasValue::lift2_val(lval, rval, BitVec::bitor),
                    BinOp::XOR => AliasValue::lift2_val(lval, rval, BitVec::bitxor),
                    BinOp::SHL => AliasValue::lift2_val(lval, rval, BitVec::shl),
                    BinOp::SHR => AliasValue::lift2_val(lval, rval, BitVec::shr),
                    BinOp::SAR => AliasValue::lift2_val(lval, rval, |mut l, r| {
                        l.signed_shr_assign(&r);
                        l
                    }),
                }
            }
            Expr::Load(pval, _, _) => {
                let pval = self.eval_expr(pval);
                if pval.is_top() {
                    AliasValue::Top
                } else if pval.is_bot() {
                    AliasValue::Bot
                } else if let Some(sv) = pval
                    .stack_delta()
                    .and_then(|delta| self.smapping.get(&delta))
                    .cloned()
                {
                    sv
                } else {
                    AliasValue::ptr(pval, BitVec::zero(self.stack_pointer.nbits() as _))
                }
            }
            Expr::Concat(lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);

                AliasValue::lift2_val(lval, rval, |mut l, mut r| {
                    let lbits = l.nbits();
                    let rbits = r.nbits();

                    let obits = lbits + rbits;

                    l.unsigned_cast_assign(obits as _);
                    r.unsigned_cast_assign(obits as _);

                    l <<= rbits as u32;

                    l |= r;
                    l
                })
            }
            Expr::BinRel(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);

                match op {
                    BinRel::EQ => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l == r { 1u8 } else { 0u8 })
                    }),
                    BinRel::NEQ => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l != r { 1u8 } else { 0u8 })
                    }),
                    BinRel::LT => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l < r { 1u8 } else { 0u8 })
                    }),
                    BinRel::LE => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l <= r { 1u8 } else { 0u8 })
                    }),
                    BinRel::SLT => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l.signed_cmp(&r).is_lt() { 1u8 } else { 0u8 })
                    }),
                    BinRel::SLE => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l.signed_cmp(&r).is_le() { 1u8 } else { 0u8 })
                    }),
                    BinRel::CARRY => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l.carry(&r) { 1u8 } else { 0u8 })
                    }),
                    BinRel::SCARRY => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l.signed_carry(&r) { 1u8 } else { 0u8 })
                    }),
                    BinRel::SBORROW => AliasValue::lift2_val(lval, rval, |l, r| {
                        BitVec::from(if l.signed_borrow(&r) { 1u8 } else { 0u8 })
                    }),
                }
            }
            Expr::Extract(expr, loff, moff) => {
                let val = self.eval_expr(expr);
                let bits = moff - loff;

                AliasValue::lift1_val(val, |mut v| {
                    if *loff > 0 {
                        v >>= *loff;
                    }
                    v.unsigned_cast_assign(bits as _);
                    v
                })
            }
            Expr::ExtractHigh(expr, bits) => {
                let val = self.eval_expr(expr);

                AliasValue::lift1_val(val, |mut v| {
                    let vbits = v.nbits();
                    if *bits < vbits {
                        let diff = vbits - *bits;
                        v >>= diff;
                    }
                    v.unsigned_cast_assign(*bits as _);
                    v
                })
            }
            Expr::ExtractLow(expr, bits) => {
                let val = self.eval_expr(expr);

                AliasValue::lift1_val(val, |mut v| {
                    v.unsigned_cast_assign(*bits as _);
                    v
                })
            }
            Expr::Cast(expr, t) => {
                let v = self.eval_expr(expr);
                let t_bits = t.nbits() as usize;

                if t.is_bool() {
                    AliasValue::lift1_val(v, |v| BitVec::from(if v.is_zero() { 0u8 } else { 1u8 }))
                } else if t.is_unsigned() {
                    AliasValue::lift1_val(v, |mut v| {
                        v.unsigned_cast_assign(t_bits);
                        v
                    })
                } else if t.is_signed() {
                    AliasValue::lift1_val(v, |mut v| {
                        v.signed_cast_assign(t_bits);
                        v
                    })
                } else {
                    AliasValue::Top
                }
            }
            Expr::IfElse(_cexpr, texpr, fexpr) => {
                let mut l = self.eval_expr(texpr);
                let r = self.eval_expr(fexpr);
                if !l.is_unk() && !r.is_unk() {
                    l.join(r);
                    l
                } else {
                    AliasValue::Top
                }
            }
            Expr::Intrinsic(_, args, _) => {
                for arg in args {
                    self.eval_expr(arg);
                }
                AliasValue::Top
            }
            _ => AliasValue::Top,
        }
    }

    fn eval_branch(&mut self, target: &Term<BranchTarget>) -> AliasValue {
        match &**target {
            BranchTarget::Location(loc) => AliasValue::val(BitVec::from_u64(
                loc.address().offset(),
                self.stack_pointer.nbits() as _,
            )),
            BranchTarget::Computed(loc) => self.eval_expr(loc),
            BranchTarget::External(_, _) => AliasValue::Top,
        }
    }

    #[inline]
    fn eval_stmt(&mut self, stmt: &Term<Stmt>) {
        match &**stmt {
            Stmt::Assign(var, expr) => {
                if let Some(address) = var.address() {
                    let val = self.eval_expr(expr);
                    let sz = var.nbits();

                    match self.gmapping.entry(address) {
                        BEntry::Vacant(e) => {
                            let mut oval = None;
                            val.blit_into(0, sz as usize / 8, &mut oval);
                            e.insert(oval.unwrap());
                        }
                        BEntry::Occupied(mut e) => {
                            let mut oval = Some(std::mem::take(e.get_mut()));
                            val.blit_into(0, sz as usize / 8, &mut oval);
                            e.insert(oval.unwrap());
                        }
                    }
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);
                let val = self.eval_expr(expr);

                if lvar.is_register() {
                    match self.rmapping.entry(lvar) {
                        Entry::Vacant(e) => {
                            let mut oval = None;
                            val.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            e.insert(oval.unwrap());
                        }
                        Entry::Occupied(mut e) => {
                            let mut oval = Some(std::mem::take(e.get_mut()));
                            val.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            e.insert(oval.unwrap());
                        }
                    }
                } else {
                    match self.tmapping.entry(lvar) {
                        Entry::Vacant(e) => {
                            let mut oval = None;
                            val.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            e.insert(oval.unwrap());
                        }
                        Entry::Occupied(mut e) => {
                            let mut oval = Some(std::mem::take(e.get_mut()));
                            val.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            e.insert(oval.unwrap());
                        }
                    }
                }
            }
            Stmt::Call(p, _) => {
                // TODO: add clobbers
                let target = self.eval_branch(p);

                self.call_target = Some(target);

                match self.rmapping.entry(self.stack_pointer) {
                    Entry::Vacant(e) => {
                        e.insert(AliasValue::Bot);
                    }
                    Entry::Occupied(mut e) => {
                        let val = std::mem::take(e.get_mut());
                        e.insert(AliasValue::lift2_any(
                            val,
                            AliasValue::val(self.extra_pop.clone()),
                            BitVec::add,
                        ));
                    }
                }
            }
            Stmt::Branch(p) if p.is_computed() => {
                let v = self.eval_branch(p);
                self.call_target = Some(v);
            }
            Stmt::Store(d, s, sz, _spc) => {
                let d = self.eval_expr(d);
                let s = self.eval_expr(s);

                if let Some(off) = d.stack_delta() {
                    match self.smapping.entry(off) {
                        BEntry::Vacant(e) => {
                            let mut oval = None;

                            s.blit_into(0, *sz as usize / 8, &mut oval);
                            e.insert(oval.unwrap());
                        }
                        BEntry::Occupied(mut e) => {
                            let mut oval = Some(std::mem::take(e.get_mut()));

                            s.blit_into(0, *sz as usize / 8, &mut oval);
                            e.insert(oval.unwrap());
                        }
                    }
                } else if let Some(address) = d.value().to_address() {
                    if !self.memory.contains(address) {
                        return;
                    }

                    match self.gmapping.entry(address) {
                        BEntry::Vacant(e) => {
                            let mut oval = None;

                            s.blit_into(0, *sz as usize / 8, &mut oval);
                            e.insert(oval.unwrap());
                        }
                        BEntry::Occupied(mut e) => {
                            let mut oval = Some(std::mem::take(e.get_mut()));

                            s.blit_into(0, *sz as usize / 8, &mut oval);
                            e.insert(oval.unwrap());
                        }
                    }
                }
            }
            _ => (),
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
    pub fn visit_insn<V>(&mut self, insn: &Term<Insn>, visitor: &mut V)
    where
        V: AliasVisitor<'a>,
    {
        self.tmapping.clear();
        for (i, stmt) in insn.operations().iter().enumerate() {
            visitor.visit_aliases_pre(insn, i, stmt, self);
            self.eval_stmt(stmt);
            visitor.visit_aliases_post(insn, i, stmt, self);
        }
    }

    #[inline]
    pub fn visit_block<V>(&mut self, block: &CodeBlock, visitor: &mut V)
    where
        V: AliasVisitor<'a>,
    {
        for insn in block.insns() {
            self.visit_insn(insn, visitor)
        }
    }

    #[inline]
    pub fn get_var_alias(&self, var: &Var) -> Option<&AliasValue> {
        if var.is_register() {
            let avar = self.registers.parent(var).unwrap_or(*var);
            self.rmapping.get(&avar)
        } else if var.is_temporary() {
            self.tmapping.get(var)
        } else if let Some(addr) = var.address() {
            self.gmapping.get(&addr)
        } else {
            None
        }
    }

    #[inline]
    pub fn get_stack_alias(&self, offset: i64) -> Option<&AliasValue> {
        self.smapping.get(&offset)
    }

    #[inline]
    pub fn get_global_alias(&self, global: Address) -> Option<&AliasValue> {
        self.gmapping.get(&global)
    }

    #[inline]
    pub fn alias(&self, var: &Var) -> AliasValue {
        if var.is_register() {
            let avar = self.registers.parent(var).unwrap_or(*var);
            self.rmapping.get(&avar).cloned().unwrap_or(AliasValue::Bot)
        } else {
            AliasValue::Bot
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockAliases {
    incoming: AHashMap<Var, AliasValue>,
    incoming_stack: BTreeMap<i64, AliasValue>,
    incoming_globals: BTreeMap<Address, AliasValue>,
    outgoing: AHashMap<Var, AliasValue>,
    outgoing_stack: BTreeMap<i64, AliasValue>,
    outgoing_globals: BTreeMap<Address, AliasValue>,
    call_target: Option<AliasValue>,
}

impl BlockAliases {
    pub fn visitor_context<'a>(&self, project: &'a Project) -> AliasVisitorContext<'a> {
        AliasVisitorContext::new(
            project.lifter(),
            project.memory(),
            self.incoming.to_owned(),
            self.incoming_stack.to_owned(),
            self.incoming_globals.to_owned(),
        )
    }

    pub fn reinitialise_context<'a>(&self, context: &mut AliasVisitorContext<'a>) {
        context.gmapping.clear();
        context.rmapping.clear();
        context.smapping.clear();

        context.gmapping.extend(
            self.incoming_globals
                .iter()
                .map(|(k, v)| (*k, v.to_owned())),
        );
        context
            .rmapping
            .extend(self.incoming.iter().map(|(k, v)| (*k, v.to_owned())));
        context
            .smapping
            .extend(self.incoming_stack.iter().map(|(k, v)| (*k, v.to_owned())));
    }

    pub fn incoming(&self) -> &AHashMap<Var, AliasValue> {
        &self.incoming
    }

    pub fn incoming_globals(&self) -> &BTreeMap<Address, AliasValue> {
        &self.incoming_globals
    }

    pub fn incoming_stack(&self) -> &BTreeMap<i64, AliasValue> {
        &self.incoming_stack
    }

    pub fn incoming_values(&self) -> impl Iterator<Item = (&Var, &AliasValue)> {
        self.incoming.iter().filter_map(|(var, val)| {
            if !val.is_unk() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn incoming_global_values(&self) -> impl Iterator<Item = (Address, &AliasValue)> {
        self.incoming_globals.iter().filter_map(
            |(&off, v)| {
                if !v.is_unk() {
                    Some((off, v))
                } else {
                    None
                }
            },
        )
    }

    pub fn incoming_stack_values(&self) -> impl Iterator<Item = (i64, &AliasValue)> {
        self.incoming_stack.iter().filter_map(
            |(&off, v)| {
                if !v.is_unk() {
                    Some((off, v))
                } else {
                    None
                }
            },
        )
    }

    pub fn outgoing(&self) -> &AHashMap<Var, AliasValue> {
        &self.outgoing
    }

    pub fn outgoing_globals(&self) -> &BTreeMap<Address, AliasValue> {
        &self.outgoing_globals
    }

    pub fn outgoing_stack(&self) -> &BTreeMap<i64, AliasValue> {
        &self.outgoing_stack
    }

    pub fn outgoing_values(&self) -> impl Iterator<Item = (&Var, &AliasValue)> {
        self.outgoing
            .iter()
            .filter_map(|(var, v)| if !v.is_unk() { Some((var, v)) } else { None })
    }

    pub fn outgoing_global_values(&self) -> impl Iterator<Item = (Address, &AliasValue)> {
        self.outgoing_globals.iter().filter_map(
            |(&off, v)| {
                if !v.is_unk() {
                    Some((off, v))
                } else {
                    None
                }
            },
        )
    }

    pub fn outgoing_stack_values(&self) -> impl Iterator<Item = (i64, &AliasValue)> {
        self.outgoing_stack.iter().filter_map(
            |(&off, v)| {
                if !v.is_unk() {
                    Some((off, v))
                } else {
                    None
                }
            },
        )
    }

    pub fn call_target(&self) -> Option<&AliasValue> {
        self.call_target.as_ref()
    }

    fn widen_value(vd: &mut AliasValue, vs: &AliasValue) -> bool {
        let mut did_widen = false;

        match (&*vd, vs) {
            (AliasValue::V(v1), AliasValue::V(v2)) => {
                if v1 != v2 {
                    *vd = AliasValue::V(v2.to_owned());
                    did_widen = true;
                }
            }
            _ => {
                if vd != vs {
                    *vd = AliasValue::Top;
                    did_widen = true;
                }
            }
        }

        did_widen
    }

    pub fn widen_globals(
        v1: &mut BTreeMap<Address, AliasValue>,
        v2: &BTreeMap<Address, AliasValue>,
    ) -> bool {
        let mut did_widen = false;

        for (k, other) in v2.iter() {
            if let Some(v) = v1.get_mut(&k) {
                did_widen |= Self::widen_value(v, other);
            } else {
                v1.insert(*k, AliasValue::Top);
                did_widen = true;
            }
        }

        did_widen
    }

    pub fn widen_registers(
        v1: &mut AHashMap<Var, AliasValue>,
        v2: &AHashMap<Var, AliasValue>,
    ) -> bool {
        let mut did_widen = false;

        for (k, other) in v2.iter() {
            if let Some(v) = v1.get_mut(&k) {
                did_widen |= Self::widen_value(v, other);
            } else {
                v1.insert(*k, AliasValue::Top);
                did_widen = true;
            }
        }

        did_widen
    }

    pub fn widen_stack(v1: &mut BTreeMap<i64, AliasValue>, v2: &BTreeMap<i64, AliasValue>) -> bool {
        let mut did_widen = false;

        for (k, other) in v2.iter() {
            if let Some(v) = v1.get_mut(&k) {
                did_widen |= Self::widen_value(v, other);
            } else {
                v1.insert(*k, AliasValue::Top);
                did_widen = true;
            }
        }

        did_widen
    }
}

#[derive(Clone, Debug, Default)]
pub struct FunctionAliases {
    blocks: AHashMap<CodeBlockId, BlockAliases>,
}

impl FunctionAliases {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockAliases> {
        &self.blocks
    }

    #[inline]
    pub fn visit<'a, V>(&self, project: &'a Project, visitor: &mut V)
    where
        V: AliasVisitor<'a>,
    {
        let mut ctx = AliasVisitorContext::empty(project.lifter(), project.memory());
        self.visit_with(project, &mut ctx, visitor)
    }

    #[inline]
    pub fn visit_with<'a, V>(
        &self,
        project: &'a Project,
        ctx: &mut AliasVisitorContext<'a>,
        visitor: &mut V,
    ) where
        V: AliasVisitor<'a>,
    {
        for (&bid, aliases) in self.blocks.iter() {
            let block = &project.code_blocks()[bid];
            aliases.reinitialise_context(ctx);
            ctx.visit_block(block, visitor)
        }
    }

    #[inline]
    pub fn visit_block<'a, V>(&self, project: &'a Project, block: CodeBlockId, visitor: &mut V)
    where
        V: AliasVisitor<'a>,
    {
        let mut ctx = AliasVisitorContext::empty(project.lifter(), project.memory());
        self.visit_block_with(project, &mut ctx, block, visitor)
    }

    #[inline]
    pub fn visit_block_with<'a, V>(
        &self,
        project: &'a Project,
        ctx: &mut AliasVisitorContext<'a>,
        block: CodeBlockId,
        visitor: &mut V,
    ) where
        V: AliasVisitor<'a>,
    {
        let Some(aliases) = self.blocks.get(&block) else {
            return;
        };

        let block = &project.code_blocks()[block];
        aliases.reinitialise_context(ctx);
        ctx.visit_block(block, visitor)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Aliases {
    mapping: AHashMap<FunctionId, FunctionAliases>,
}

impl Aliases {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, FunctionAliases> {
        &self.mapping
    }

    pub fn analyse_project(project: &Project) -> Self {
        Self {
            mapping: project
                .functions()
                .values()
                .map(|f| (f.id(), Self::analyse_function(project, f)))
                .collect(),
        }
    }

    pub fn analyse_function(project: &Project, f: &Function) -> FunctionAliases {
        let mut gkmap = AHashMap::new();

        let lifter = project.lifter();
        let memory = project.memory();
        let entry = f.entry();

        for blk in f.blocks_with(project.code_blocks()) {
            let init = BlockAliases {
                incoming: incoming_map(lifter, blk.id() == entry),
                incoming_stack: Default::default(),
                incoming_globals: Default::default(),
                outgoing: Default::default(),
                outgoing_stack: Default::default(),
                outgoing_globals: Default::default(),
                call_target: Default::default(),
            };
            gkmap.insert(blk.id(), init);
        }

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());
        let mut edge_visitor = cfg.visit_map();

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut nincoming = incoming_map(lifter, blk.id() == entry);
            let mut nincoming_stack = BTreeMap::<i64, AliasValue>::default();
            let mut nincoming_globals = BTreeMap::<Address, AliasValue>::default();

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

                for (k, v) in pred.outgoing_stack.iter() {
                    match nincoming_stack.entry(*k) {
                        BEntry::Occupied(mut e) => {
                            e.get_mut().join(v.to_owned());
                        }
                        BEntry::Vacant(e) => {
                            e.insert(v.to_owned());
                        }
                    }
                }

                for (k, v) in pred.outgoing_globals.iter() {
                    match nincoming_globals.entry(*k) {
                        BEntry::Occupied(mut e) => {
                            e.get_mut().join(v.to_owned());
                        }
                        BEntry::Vacant(e) => {
                            e.insert(v.to_owned());
                        }
                    }
                }
            }

            let mut builder = AliasVisitorContext::new(
                lifter,
                memory,
                nincoming.clone(),
                nincoming_stack.clone(),
                nincoming_globals.clone(),
            );

            for insn in blk.insns() {
                builder.eval_insn(insn);
            }

            let mut noutgoing = builder.rmapping;
            let mut noutgoing_stack = builder.smapping;
            let mut noutgoing_globals = builder.gmapping;

            let call_target = builder.call_target;
            let current = gkmap.get_mut(&blk.id()).unwrap();

            let mut did_change = call_target != current.call_target;

            if noutgoing != current.outgoing {
                did_change |= if BlockAliases::widen_registers(&mut noutgoing, &current.outgoing) {
                    noutgoing != current.outgoing
                } else {
                    true
                };
            }

            if noutgoing_stack != current.outgoing_stack {
                did_change |=
                    if BlockAliases::widen_stack(&mut noutgoing_stack, &current.outgoing_stack) {
                        noutgoing_stack != current.outgoing_stack
                    } else {
                        true
                    };
            }

            if noutgoing_globals != current.outgoing_globals {
                did_change |= if BlockAliases::widen_globals(
                    &mut noutgoing_globals,
                    &current.outgoing_globals,
                ) {
                    noutgoing_globals != current.outgoing_globals
                } else {
                    true
                };
            }

            current.incoming = nincoming;
            current.incoming_stack = nincoming_stack;
            current.incoming_globals = nincoming_globals;

            current.outgoing = noutgoing;
            current.outgoing_stack = noutgoing_stack;
            current.outgoing_globals = noutgoing_globals;

            current.call_target = call_target;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionAliases { blocks: gkmap }
    }
}
