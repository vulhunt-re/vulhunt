use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};

use petgraph::visit::{EdgeRef, IntoEdgesDirected};
use petgraph::EdgeDirection;
use smallvec::{smallvec, SmallVec};

use crate::ir::{BinOp, BranchTarget, UnOp};
use crate::prelude::*;

pub mod expr;
pub mod typed;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub enum AliasValue {
    Top,
    V(BitVec),
    S(BitVec),
    G(Box<Self>, BitVec),
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

impl ToAddress for AliasValue {
    fn to_address(&self) -> Option<Address> {
        match self {
            Self::V(val) => val.to_address(),
            _ => None,
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

    pub fn stack_var(lifter: &Lifter) -> Self {
        Self::S(BitVec::zero(lifter.address_bits() as _))
    }

    pub fn val(value: impl Into<BitVec>) -> Self {
        Self::V(value.into())
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
            Self::S(_) if offset == 0 => self,
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
                    *old = Self::Top;
                }
            },
            _ if offset == 0 => {
                *val = Some(self);
            }
            _ => *val = Some(Self::Top),
        }
    }
}

#[derive(Clone)]
pub struct AliasVisitor<'a> {
    rmapping: AHashMap<Var, AliasValue>,
    tmapping: AHashMap<Var, AliasValue>,
    call_target: Option<AliasValue>,
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
) -> AHashMap<Var, AliasValue> {
    let mut rmapping = AHashMap::new();
    if entry {
        let stack_pointer = lifter.stack_pointer();
        let stack_default = AliasValue::stack_var(lifter);

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

            rmapping.insert(avar, AliasValue::val(value));
        }
    }
    rmapping
}

impl<'a> AliasVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        functions: &'a FunctionTable,
        injections: &'a InjectionManager,
        rmapping: AHashMap<Var, AliasValue>,
    ) -> Self {
        let stack_pointer = lifter.stack_pointer();
        Self {
            functions,
            injections,
            registers: &*lifter.register_map(),

            rmapping,
            tmapping: AHashMap::new(),
            call_target: None,
            stack_pointer,
            extra_pop: BitVec::from_u64(
                lifter.default_prototype().extra_pop(),
                stack_pointer.nbits() as _,
            ),
        }
    }

    #[inline]
    fn eval_expr(&mut self, expr: &Term<Expr>) -> AliasValue {
        match &**expr {
            Expr::Var(var) => {
                let rvar = self.registers.parent(var).unwrap_or(*var);

                let val = if rvar.is_register() {
                    let val = self.rmapping.get(&rvar).cloned().unwrap_or(AliasValue::Bot);
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
                    UnOp::NOT => AliasValue::lift1_val(val, BitVec::not),
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
                } else {
                    AliasValue::ptr(pval, BitVec::zero(self.stack_pointer.nbits() as _))
                }
            }
            Expr::Concat(_lexpr, _rexpr) | Expr::BinRel(_, _lexpr, _rexpr) => AliasValue::Top,
            Expr::Extract(_expr, _, _)
            | Expr::ExtractHigh(_expr, _)
            | Expr::ExtractLow(_expr, _)
            | Expr::UnRel(_, _expr)
            | Expr::Cast(_expr, _) => AliasValue::Top,
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
                if var.is_address() {
                    self.eval_expr(expr);
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);
                let val = self.eval_expr(expr);

                /*
                let val = if var.offset() != lvar.offset() {
                    AliasValue::Top
                } else {
                    self.eval_expr(expr)
                };
                */

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

                    self.call_target = Some(target);

                    return;
                }

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
    outgoing: AHashMap<Var, AliasValue>,
    call_target: Option<AliasValue>,
}

impl BlockAliases {
    pub fn incoming(&self) -> &AHashMap<Var, AliasValue> {
        &self.incoming
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

    pub fn outgoing(&self) -> &AHashMap<Var, AliasValue> {
        &self.outgoing
    }

    pub fn outgoing_values(&self) -> impl Iterator<Item = (&Var, &AliasValue)> {
        self.outgoing.iter().filter_map(|(var, val)| {
            if !val.is_unk() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn call_target(&self) -> Option<&AliasValue> {
        self.call_target.as_ref()
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
        let functions = project.functions();
        let injections = project.injections();
        let entry = f.entry();

        for blk in f.blocks_with(project.code_blocks()) {
            let init = BlockAliases {
                incoming: incoming_map(lifter, injections, f, blk.id() == entry),
                outgoing: Default::default(),
                call_target: Default::default(),
            };
            gkmap.insert(blk.id(), init);
        }

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut nincoming = incoming_map(lifter, injections, f, blk.id() == entry);
            for pred in cfg
                .edges_directed(blk.node(), EdgeDirection::Incoming)
                .filter_map(|e| gkmap.get(&project.icfg()[e.source()]))
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

            let mut builder = AliasVisitor::new(lifter, functions, injections, nincoming.clone());

            for insn in blk.insns() {
                builder.eval_insn(insn);
            }

            let noutgoing = builder.rmapping;
            let call_target = builder.call_target;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing != current.outgoing || call_target != current.call_target;

            current.incoming = nincoming;
            current.outgoing = noutgoing;
            current.call_target = call_target;

            if did_change {
                worklist.push_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionAliases { blocks: gkmap }
    }
}
