use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::fmt;

use ahash::AHashMap as Map;
use fugue::bv::BitVec;
use fugue::bytes::Order;
use fugue::ir::disassembly::{IRBuilderArena, VarnodeData};
use fugue::ir::float_format::FloatFormat;
use fugue::ir::il::pcode::Operand;
use fugue::ir::space_manager::{FromSpace, SpaceManager};
use fugue::ir::{Address, AddressSpace, AddressSpaceId};
use itertools::Itertools;
use smallvec::SmallVec;
use ustr::Ustr;

use super::SimpleVar;
use crate::ir::term::arena::Arena;
use crate::ir::term::{Term, TermMut};
use crate::ir::traits::*;
use crate::ir::{FloatKind, Type, TypeKind, Var};

pub mod rewriter;
pub mod simplify;

thread_local! {
    static EXPR: std::cell::RefCell<Arena<Expr>> = Default::default();
}

pub fn collect_garbage() {
    EXPR.with_borrow_mut(|v| {
        *v = Default::default();
    });
}

pub fn stats() -> (usize, usize) {
    EXPR.with_borrow(|v| v.stats())
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum UnOp {
    NOT,
    NEG,

    ABS,
    SQRT,
    CEILING,
    FLOOR,
    ROUND,

    POPCOUNT(u32),
}

impl UnOp {
    pub fn apply<E>(&self, e: E) -> Term<Expr>
    where
        E: Into<Term<Expr>>,
    {
        let e = e.into();

        match self {
            Self::NOT => {
                if e.is_bool() {
                    Expr::bool_not(e)
                } else {
                    Expr::int_not(e)
                }
            }
            Self::NEG => {
                if let Some(fmt) = e.float_kind() {
                    Expr::float_neg_with(e, fmt)
                } else {
                    Expr::int_neg(e)
                }
            }
            _ => Expr::unary_op(*self, e),
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum UnRel {
    NAN,
}

impl UnRel {
    pub fn apply<E>(&self, e: E) -> Term<Expr>
    where
        E: Into<Term<Expr>>,
    {
        Expr::unary_rel(*self, e.into())
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum BinOp {
    AND,
    OR,
    XOR,
    ADD,
    SUB,
    DIV,
    SDIV,
    MUL,
    REM,
    SREM,
    SHL,
    SAR,
    SHR,
}

impl BinOp {
    pub fn is_associative(&self) -> bool {
        matches!(
            self,
            Self::AND | Self::OR | Self::XOR | Self::ADD | Self::MUL
        )
    }

    pub fn is_commutative(&self) -> bool {
        matches!(
            self,
            Self::AND | Self::OR | Self::XOR | Self::ADD | Self::MUL
        )
    }

    pub fn apply<E1, E2>(&self, l: E1, r: E2) -> Term<Expr>
    where
        E1: Into<Term<Expr>>,
        E2: Into<Term<Expr>>,
    {
        let l = l.into();
        let r = r.into();

        match self {
            Self::AND => {
                if l.is_bool() || r.is_bool() {
                    Expr::bool_and(l, r)
                } else {
                    Expr::int_and(l, r)
                }
            }
            Self::OR => {
                if l.is_bool() || r.is_bool() {
                    Expr::bool_or(l, r)
                } else {
                    Expr::int_or(l, r)
                }
            }
            Self::XOR => {
                if l.is_bool() || r.is_bool() {
                    Expr::bool_xor(l, r)
                } else {
                    Expr::int_xor(l, r)
                }
            }
            Self::ADD => {
                if let Some(fmt) = l.float_kind() {
                    Expr::float_add_with(l, r, fmt)
                } else {
                    Expr::int_add(l, r)
                }
            }
            Self::DIV => {
                if let Some(fmt) = l.float_kind() {
                    Expr::float_div_with(l, r, fmt)
                } else {
                    Expr::int_div(l, r)
                }
            }
            Self::SDIV => Expr::int_sdiv(l, r),
            Self::MUL => {
                if let Some(fmt) = l.float_kind() {
                    Expr::float_mul_with(l, r, fmt)
                } else {
                    Expr::int_mul(l, r)
                }
            }
            Self::REM => {
                if l.is_signed() {
                    Expr::int_srem(l, r)
                } else {
                    Expr::int_rem(l, r)
                }
            }
            Self::SREM => Expr::int_srem(l, r),
            Self::SUB => {
                if let Some(fmt) = l.float_kind() {
                    Expr::float_sub_with(l, r, fmt)
                } else {
                    Expr::int_sub(l, r)
                }
            }
            Self::SHL => Expr::int_shl(l, r),
            Self::SAR => Expr::int_sar(l, r),
            Self::SHR => Expr::int_shr(l, r),
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum BinRel {
    EQ,
    NEQ,
    LT,
    LE,
    SLT,
    SLE,

    SBORROW,
    CARRY,
    SCARRY,
}

impl BinRel {
    pub fn is_commutative(&self) -> bool {
        matches!(self, Self::EQ | Self::NEQ)
    }

    pub fn apply<E1, E2>(&self, l: E1, r: E2) -> Term<Expr>
    where
        E1: Into<Term<Expr>>,
        E2: Into<Term<Expr>>,
    {
        let l = l.into();
        let r = r.into();

        match self {
            Self::EQ => {
                if l.is_bool() || r.is_bool() {
                    Expr::bool_eq(l, r)
                } else if let Some(fmt) = l.float_kind() {
                    Expr::float_eq_with(l, r, fmt)
                } else {
                    Expr::int_eq(l, r)
                }
            }
            Self::NEQ => {
                if l.is_bool() || r.is_bool() {
                    Expr::bool_neq(l, r)
                } else if let Some(fmt) = l.float_kind() {
                    Expr::float_neq_with(l, r, fmt)
                } else {
                    Expr::int_neq(l, r)
                }
            }
            Self::LT => {
                if let Some(fmt) = l.float_kind() {
                    Expr::float_lt_with(l, r, fmt)
                } else {
                    Expr::int_lt(l, r)
                }
            }
            Self::LE => {
                if let Some(fmt) = l.float_kind() {
                    Expr::float_le_with(l, r, fmt)
                } else {
                    Expr::int_le(l, r)
                }
            }
            Self::SLT => Expr::int_slt(l, r),
            Self::SLE => Expr::int_sle(l, r),
            Self::CARRY => Expr::int_carry(l, r),
            Self::SCARRY => Expr::int_scarry(l, r),
            Self::SBORROW => Expr::int_sborrow(l, r),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize)]
    pub struct ValHint: u8 {
        const CONSTANT = 0b0000_0001;
        const ADDRESS = 0b0000_0010;
    }
}

// Total ordering over Expr terms gives: Val(.) < Var(.) < ...
#[derive(Debug, Clone, Hash, Eq, Ord, serde::Deserialize, serde::Serialize, educe::Educe)]
#[educe(PartialEq(bound()), PartialOrd(bound()))]
pub enum Expr {
    Val(
        #[educe(PartialEq(method(bv_partial_eq)))]
        #[educe(PartialOrd(method(bv_partial_cmp)))]
        BitVec,
        ValHint,
    ), // BitVec -> T

    Var(Var), // String * usize -> T

    Load(Term<Expr>, u32, AddressSpaceId), // SPACE[T]:SIZE -> T
    Cast(Term<Expr>, Term<Type>),          // T -> Type::T

    UnRel(UnRel, Term<Expr>), // T -> bool
    UnOp(UnOp, Term<Expr>),   // T -> T

    BinRel(BinRel, Term<Expr>, Term<Expr>), // T * T -> bool
    BinOp(BinOp, Term<Expr>, Term<Expr>),   // T * T -> T

    IfElse(Term<Expr>, Term<Expr>, Term<Expr>), // if T then T else T

    Extract(Term<Expr>, u32, u32), // T T[LSB..MSB) -> T
    ExtractHigh(Term<Expr>, u32),
    ExtractLow(Term<Expr>, u32),

    Choice(
        Term<Expr>,
        Vec<(BitVec, Term<Expr>)>,
        Option<Term<Expr>>,
        u32,
    ),

    Concat(Term<Expr>, Term<Expr>), // T * T -> T

    // Call(Term<BranchTarget>, SmallVec<[Term<Expr>; 4]>, u32),
    Intrinsic(Ustr, SmallVec<[Term<Expr>; 2]>, u32),
}

#[inline(always)]
fn bv_partial_eq(lhs: &BitVec, rhs: &BitVec) -> bool {
    lhs.bits() == rhs.bits() && lhs == rhs
}

#[inline(always)]
fn bv_partial_cmp(lhs: &BitVec, rhs: &BitVec) -> Option<Ordering> {
    let ord = lhs.bits().partial_cmp(&rhs.bits())?;
    if ord.is_eq() {
        lhs.partial_cmp(rhs)
    } else {
        Some(ord)
    }
}

impl From<Expr> for Term<Expr> {
    fn from(e: Expr) -> Self {
        EXPR.with_borrow(|a| Term::new(a, e))
    }
}

impl AsMut<Expr> for Term<Expr> {
    fn as_mut(&mut self) -> &mut Expr {
        EXPR.with_borrow(|arena| crate::ir::term::arena::ArenaArc::make_mut(arena, &mut self.val))
    }
}

impl ::std::borrow::BorrowMut<Expr> for Term<Expr> {
    fn borrow_mut(&mut self) -> &mut Expr {
        EXPR.with_borrow(|arena| crate::ir::term::arena::ArenaArc::make_mut(arena, &mut self.val))
    }
}

impl ::std::ops::DerefMut for Term<Expr> {
    fn deref_mut(&mut self) -> &mut Expr {
        EXPR.with_borrow(|arena| crate::ir::term::arena::ArenaArc::make_mut(arena, &mut self.val))
    }
}

impl TermMut<Expr> for Term<Expr> {
    fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<Expr>),
    {
        EXPR.with_borrow(|a| self.update_with(a, |_, v| f(v)))
    }
}

impl Expr {
    pub fn fmt_l1(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Val(v, _) => write!(f, "{}", v),
            Expr::Var(v) => write!(f, "{}", v),

            Expr::Load(expr, bits, space) => {
                write!(f, "space[{}][{}]:{}", space.index(), expr, bits)
            }

            Expr::Intrinsic(name, args, _) => {
                write!(f, "{}(", name)?;
                if !args.is_empty() {
                    write!(f, "{}", args[0])?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg)?;
                    }
                }
                write!(f, ")")
            }

            Expr::ExtractHigh(expr, bits) => {
                write!(f, "extract-high({}, bits={})", expr, bits)
            }
            Expr::ExtractLow(expr, bits) => write!(f, "extract-low({}, bits={})", expr, bits),

            Expr::Cast(expr, t) => {
                expr.fmt_l1(f)?;
                write!(f, " as {}", t)
            }

            Expr::Choice(expr, _, default, bits) => {
                if let Some(default) = default {
                    write!(
                        f,
                        "choice(on={}, options=[...], default={}, bits={})",
                        expr, default, bits
                    )
                } else {
                    write!(f, "choice(on={}, options=[...], bits={})", expr, bits)
                }
            }

            Expr::Extract(expr, lsb, msb) => {
                write!(f, "extract({}, from={}, to={})", expr, lsb, msb)
            }

            Expr::UnOp(UnOp::ABS, expr) => write!(f, "abs({})", expr),
            Expr::UnOp(UnOp::SQRT, expr) => {
                write!(f, "sqrt({})", expr)
            }
            Expr::UnOp(UnOp::ROUND, expr) => {
                write!(f, "round({})", expr)
            }
            Expr::UnOp(UnOp::CEILING, expr) => {
                write!(f, "ceiling({})", expr)
            }
            Expr::UnOp(UnOp::FLOOR, expr) => {
                write!(f, "floor({})", expr)
            }
            Expr::UnOp(UnOp::POPCOUNT(bits), expr) => {
                write!(f, "popcount({}, bits={})", expr, bits)
            }

            Expr::UnRel(UnRel::NAN, expr) => {
                write!(f, "is-nan({})", expr)
            }

            Expr::BinRel(BinRel::CARRY, e1, e2) => write!(f, "carry({}, {})", e1, e2),
            Expr::BinRel(BinRel::SCARRY, e1, e2) => write!(f, "scarry({}, {})", e1, e2),
            Expr::BinRel(BinRel::SBORROW, e1, e2) => write!(f, "sborrow({}, {})", e1, e2),

            expr => write!(f, "({})", expr),
        }
    }

    pub fn fmt_l2(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::UnOp(UnOp::NEG, expr) => {
                write!(f, "-")?;
                expr.fmt_l1(f)
            }
            Expr::UnOp(UnOp::NOT, expr) => {
                write!(f, "!")?;
                expr.fmt_l1(f)
            }
            expr => expr.fmt_l1(f),
        }
    }

    pub fn fmt_l3(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::BinOp(BinOp::MUL, e1, e2) => {
                e1.fmt_l3(f)?;
                write!(f, " * ")?;
                e2.fmt_l2(f)
            }
            Expr::BinOp(BinOp::DIV, e1, e2) => {
                e1.fmt_l3(f)?;
                write!(f, " / ")?;
                e2.fmt_l2(f)
            }
            Expr::BinOp(BinOp::SDIV, e1, e2) => {
                e1.fmt_l3(f)?;
                write!(f, " s/ ")?;
                e2.fmt_l2(f)
            }
            Expr::BinOp(BinOp::REM, e1, e2) => {
                e1.fmt_l3(f)?;
                write!(f, " % ")?;
                e2.fmt_l2(f)
            }
            Expr::BinOp(BinOp::SREM, e1, e2) => {
                e1.fmt_l3(f)?;
                write!(f, " s% ")?;
                e2.fmt_l2(f)
            }
            expr => expr.fmt_l2(f),
        }
    }

    pub fn fmt_l4(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::BinOp(BinOp::ADD, e1, e2) => {
                e1.fmt_l4(f)?;
                write!(f, " + ")?;
                e2.fmt_l3(f)
            }
            Expr::BinOp(BinOp::SUB, e1, e2) => {
                e1.fmt_l4(f)?;
                write!(f, " - ")?;
                e2.fmt_l3(f)
            }
            expr => expr.fmt_l3(f),
        }
    }

    pub fn fmt_l5(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::BinOp(BinOp::SHL, e1, e2) => {
                e1.fmt_l5(f)?;
                write!(f, " << ")?;
                e2.fmt_l4(f)
            }
            Expr::BinOp(BinOp::SHR, e1, e2) => {
                e1.fmt_l5(f)?;
                write!(f, " >> ")?;
                e2.fmt_l4(f)
            }
            Expr::BinOp(BinOp::SAR, e1, e2) => {
                e1.fmt_l5(f)?;
                write!(f, " s>> ")?;
                e2.fmt_l4(f)
            }
            expr => expr.fmt_l4(f),
        }
    }

    pub fn fmt_l6(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::BinRel(BinRel::LT, e1, e2) => {
                e1.fmt_l6(f)?;
                write!(f, " < ")?;
                e2.fmt_l5(f)
            }
            Expr::BinRel(BinRel::LE, e1, e2) => {
                e1.fmt_l6(f)?;
                write!(f, " <= ")?;
                e2.fmt_l5(f)
            }
            Expr::BinRel(BinRel::SLT, e1, e2) => {
                e1.fmt_l6(f)?;
                write!(f, " s< ")?;
                e2.fmt_l5(f)
            }
            Expr::BinRel(BinRel::SLE, e1, e2) => {
                e1.fmt_l6(f)?;
                write!(f, " s<= ")?;
                e2.fmt_l5(f)
            }
            expr => expr.fmt_l5(f),
        }
    }

    pub fn fmt_l7(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::BinRel(BinRel::EQ, e1, e2) => {
                e1.fmt_l7(f)?;
                write!(f, " == ")?;
                e2.fmt_l6(f)
            }
            Expr::BinRel(BinRel::NEQ, e1, e2) => {
                e1.fmt_l7(f)?;
                write!(f, " != ")?;
                e2.fmt_l6(f)
            }
            expr => expr.fmt_l6(f),
        }
    }

    pub fn fmt_l8(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Expr::BinOp(BinOp::AND, e1, e2) = self {
            e1.fmt_l8(f)?;
            write!(f, " & ")?;
            e2.fmt_l7(f)
        } else {
            self.fmt_l7(f)
        }
    }

    pub fn fmt_l9(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Expr::BinOp(BinOp::XOR, e1, e2) = self {
            e1.fmt_l9(f)?;
            write!(f, " ^ ")?;
            e2.fmt_l8(f)
        } else {
            self.fmt_l8(f)
        }
    }

    pub fn fmt_l10(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Expr::BinOp(BinOp::OR, e1, e2) = self {
            e1.fmt_l10(f)?;
            write!(f, " | ")?;
            e2.fmt_l9(f)
        } else {
            self.fmt_l9(f)
        }
    }

    pub fn fmt_l11(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Expr::Concat(e1, e2) = self {
            e1.fmt_l11(f)?;
            write!(f, " ++ ")?;
            e2.fmt_l10(f)
        } else {
            self.fmt_l10(f)
        }
    }

    pub fn fmt_l12(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Expr::IfElse(c, et, ef) = self {
            write!(f, "if ")?;
            c.fmt_l12(f)?;
            write!(f, " then ")?;
            et.fmt_l12(f)?;
            write!(f, " else ")?;
            ef.fmt_l12(f)
        } else {
            self.fmt_l11(f)
        }
    }
}

impl<'v, 't> Expr {
    fn fmt_l1_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::Val(v, _) => write!(f, "{}", v.display_full(Cow::Borrowed(&*d.fmt)),),
            Expr::Var(v) => write!(f, "{}", v.display_full(Cow::Borrowed(&*d.fmt))),

            Expr::Intrinsic(name, args, _) => {
                write!(f, "{}{}{}(", d.fmt.keyword_start, name, d.fmt.keyword_end)?;
                if !args.is_empty() {
                    write!(f, "{}", args[0].display_full(Cow::Borrowed(&*d.fmt)))?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg.display_full(Cow::Borrowed(&*d.fmt)))?;
                    }
                }
                write!(f, ")")
            }

            Expr::ExtractHigh(expr, bits) => write!(
                f,
                "{}extract-high{}({}, {}bits{}={}{}{})",
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                expr.display_full(Cow::Borrowed(&*d.fmt)),
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                d.fmt.value_start,
                bits,
                d.fmt.value_end,
            ),
            Expr::ExtractLow(expr, bits) => write!(
                f,
                "{}extract-low{}({}, {}bits{}={}{}{})",
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                expr.display_full(Cow::Borrowed(&*d.fmt)),
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                d.fmt.value_start,
                bits,
                d.fmt.value_end,
            ),

            Expr::Choice(expr, _, default, bits) => {
                if let Some(default) = default {
                    write!(f, "{}choice{}({}on{}={}{}{}, {}options{}=[...], {}default{}={}{}{}, {}bits{}={}{}{})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    d.fmt.value_start,
                    expr,
                    d.fmt.value_end,
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    d.fmt.value_start,
                    default,
                    d.fmt.value_end,
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    d.fmt.value_start,
                    bits,
                    d.fmt.value_end,
                )
                } else {
                    write!(
                        f,
                        "{}choice{}({}on{}={}{}{}, {}options{}=[...], {}bits{}={}{}{})",
                        d.fmt.keyword_start,
                        d.fmt.keyword_end,
                        d.fmt.keyword_start,
                        d.fmt.keyword_end,
                        d.fmt.value_start,
                        expr,
                        d.fmt.value_end,
                        d.fmt.keyword_start,
                        d.fmt.keyword_end,
                        d.fmt.keyword_start,
                        d.fmt.keyword_end,
                        d.fmt.value_start,
                        bits,
                        d.fmt.value_end,
                    )
                }
            }
            Expr::Load(expr, bits, space) => {
                if let Some(trans) = d.fmt.translator {
                    let space = unsafe { trans.manager().unchecked_space_by_id(*space) };
                    write!(
                        f,
                        "{}{}{}[{}]:{}{}{}",
                        d.fmt.variable_start,
                        space.name(),
                        d.fmt.variable_end,
                        expr.display_full(Cow::Borrowed(&*d.fmt)),
                        d.fmt.value_start,
                        bits,
                        d.fmt.value_end,
                    )
                } else {
                    write!(
                        f,
                        "{}space{}[{}{}{}][{}]:{}{}{}",
                        d.fmt.variable_start,
                        d.fmt.variable_end,
                        d.fmt.value_start,
                        space.index(),
                        d.fmt.value_end,
                        expr.display_full(Cow::Borrowed(&*d.fmt)),
                        d.fmt.value_start,
                        bits,
                        d.fmt.value_end,
                    )
                }
            }
            Expr::Cast(expr, t) => {
                expr.fmt_l1_with(f, d)?;
                write!(
                    f,
                    " {}as{} {}{}{}",
                    d.fmt.keyword_start, d.fmt.keyword_end, d.fmt.type_start, t, d.fmt.type_end
                )
            }

            Expr::Extract(expr, lsb, msb) => write!(
                f,
                "{}extract{}({}, {}from{}={}{}{}, {}to{}={}{}{})",
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                expr.display_full(Cow::Borrowed(&*d.fmt)),
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                d.fmt.value_start,
                lsb,
                d.fmt.value_end,
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                d.fmt.value_start,
                msb,
                d.fmt.value_end,
            ),

            Expr::UnOp(UnOp::ABS, expr) => {
                write!(
                    f,
                    "{}abs{}({})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt))
                )
            }
            Expr::UnOp(UnOp::SQRT, expr) => {
                write!(
                    f,
                    "{}sqrt{}({})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt))
                )
            }
            Expr::UnOp(UnOp::ROUND, expr) => {
                write!(
                    f,
                    "{}round{}({})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt))
                )
            }
            Expr::UnOp(UnOp::CEILING, expr) => {
                write!(
                    f,
                    "{}ceiling{}({})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt))
                )
            }
            Expr::UnOp(UnOp::FLOOR, expr) => {
                write!(
                    f,
                    "{}floor{}({})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt))
                )
            }
            Expr::UnOp(UnOp::POPCOUNT(bits), expr) => {
                write!(
                    f,
                    "{}popcount{}({}, {}bits{}={}{}{})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt)),
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    d.fmt.value_start,
                    bits,
                    d.fmt.value_end,
                )
            }

            Expr::UnRel(UnRel::NAN, expr) => {
                write!(
                    f,
                    "{}is-nan{}({})",
                    d.fmt.keyword_start,
                    d.fmt.keyword_end,
                    expr.display_full(Cow::Borrowed(&*d.fmt))
                )
            }

            Expr::BinRel(BinRel::CARRY, e1, e2) => write!(
                f,
                "{}carry{}({}, {})",
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                e1.display_full(Cow::Borrowed(&*d.fmt)),
                e2.display_full(Cow::Borrowed(&*d.fmt))
            ),
            Expr::BinRel(BinRel::SCARRY, e1, e2) => write!(
                f,
                "{}scarry{}({}, {})",
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                e1.display_full(Cow::Borrowed(&*d.fmt)),
                e2.display_full(Cow::Borrowed(&*d.fmt))
            ),
            Expr::BinRel(BinRel::SBORROW, e1, e2) => write!(
                f,
                "{}sborrow{}({}, {})",
                d.fmt.keyword_start,
                d.fmt.keyword_end,
                e1.display_full(Cow::Borrowed(&*d.fmt)),
                e2.display_full(Cow::Borrowed(&*d.fmt))
            ),

            expr => write!(f, "({})", expr.display_full(Cow::Borrowed(&*d.fmt))),
        }
    }

    fn fmt_l2_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::UnOp(UnOp::NEG, expr) => {
                write!(f, "{}-{}", d.fmt.keyword_start, d.fmt.keyword_end)?;
                expr.fmt_l1_with(f, d)
            }
            Expr::UnOp(UnOp::NOT, expr) => {
                write!(f, "{}!{}", d.fmt.keyword_start, d.fmt.keyword_end)?;
                expr.fmt_l1_with(f, d)
            }
            expr => expr.fmt_l1_with(f, d),
        }
    }

    fn fmt_l3_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::BinOp(BinOp::MUL, e1, e2) => {
                e1.fmt_l3_with(f, d)?;
                write!(f, " {}*{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l2_with(f, d)
            }
            Expr::BinOp(BinOp::DIV, e1, e2) => {
                e1.fmt_l3_with(f, d)?;
                write!(f, " {}/{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l2_with(f, d)
            }
            Expr::BinOp(BinOp::SDIV, e1, e2) => {
                e1.fmt_l3_with(f, d)?;
                write!(f, " {}s/{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l2_with(f, d)
            }
            Expr::BinOp(BinOp::REM, e1, e2) => {
                e1.fmt_l3_with(f, d)?;
                write!(f, " {}%{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l2_with(f, d)
            }
            Expr::BinOp(BinOp::SREM, e1, e2) => {
                e1.fmt_l3_with(f, d)?;
                write!(f, " {}s%{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l2_with(f, d)
            }
            expr => expr.fmt_l2_with(f, d),
        }
    }

    fn fmt_l4_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::BinOp(BinOp::ADD, e1, e2) => {
                e1.fmt_l4_with(f, d)?;
                write!(f, " {}+{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l3_with(f, d)
            }
            Expr::BinOp(BinOp::SUB, e1, e2) => {
                e1.fmt_l4_with(f, d)?;
                write!(f, " {}-{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l3_with(f, d)
            }
            expr => expr.fmt_l3_with(f, d),
        }
    }

    fn fmt_l5_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::BinOp(BinOp::SHL, e1, e2) => {
                e1.fmt_l5_with(f, d)?;
                write!(f, " {}<<{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l4_with(f, d)
            }
            Expr::BinOp(BinOp::SHR, e1, e2) => {
                e1.fmt_l5_with(f, d)?;
                write!(f, " {}>>{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l4_with(f, d)
            }
            Expr::BinOp(BinOp::SAR, e1, e2) => {
                e1.fmt_l5_with(f, d)?;
                write!(f, " {}s>>{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l4_with(f, d)
            }
            expr => expr.fmt_l4_with(f, d),
        }
    }

    fn fmt_l6_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::BinRel(BinRel::LT, e1, e2) => {
                e1.fmt_l6_with(f, d)?;
                write!(f, " {}<{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l5_with(f, d)
            }
            Expr::BinRel(BinRel::LE, e1, e2) => {
                e1.fmt_l6_with(f, d)?;
                write!(f, " {}<={} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l5_with(f, d)
            }
            Expr::BinRel(BinRel::SLT, e1, e2) => {
                e1.fmt_l6_with(f, d)?;
                write!(f, " {}s<{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l5_with(f, d)
            }
            Expr::BinRel(BinRel::SLE, e1, e2) => {
                e1.fmt_l6_with(f, d)?;
                write!(f, " {}s<={} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l5_with(f, d)
            }
            expr => expr.fmt_l5_with(f, d),
        }
    }

    fn fmt_l7_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        match self {
            Expr::BinRel(BinRel::EQ, e1, e2) => {
                e1.fmt_l7_with(f, d)?;
                write!(f, " {}=={} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l6_with(f, d)
            }
            Expr::BinRel(BinRel::NEQ, e1, e2) => {
                e1.fmt_l7_with(f, d)?;
                write!(f, " {}!={} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
                e2.fmt_l6_with(f, d)
            }
            expr => expr.fmt_l6_with(f, d),
        }
    }

    fn fmt_l8_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        if let Expr::BinOp(BinOp::AND, e1, e2) = self {
            e1.fmt_l8_with(f, d)?;
            write!(f, " {}&{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            e2.fmt_l7_with(f, d)
        } else {
            self.fmt_l7_with(f, d)
        }
    }

    fn fmt_l9_with(&'v self, f: &mut fmt::Formatter<'_>, d: &ExprFormatter<'v, 't>) -> fmt::Result {
        if let Expr::BinOp(BinOp::XOR, e1, e2) = self {
            e1.fmt_l9_with(f, d)?;
            write!(f, " {}^{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            e2.fmt_l8_with(f, d)
        } else {
            self.fmt_l8_with(f, d)
        }
    }

    fn fmt_l10_with(
        &'v self,
        f: &mut fmt::Formatter<'_>,
        d: &ExprFormatter<'v, 't>,
    ) -> fmt::Result {
        if let Expr::BinOp(BinOp::OR, e1, e2) = self {
            e1.fmt_l10_with(f, d)?;
            write!(f, " {}|{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            e2.fmt_l9_with(f, d)
        } else {
            self.fmt_l9_with(f, d)
        }
    }

    fn fmt_l11_with(
        &'v self,
        f: &mut fmt::Formatter<'_>,
        d: &ExprFormatter<'v, 't>,
    ) -> fmt::Result {
        if let Expr::Concat(e1, e2) = self {
            e1.fmt_l11_with(f, d)?;
            write!(f, " {}++{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            e2.fmt_l10_with(f, d)
        } else {
            self.fmt_l10_with(f, d)
        }
    }

    fn fmt_l12_with(
        &'v self,
        f: &mut fmt::Formatter<'_>,
        d: &ExprFormatter<'v, 't>,
    ) -> fmt::Result {
        if let Expr::IfElse(c, et, ef) = self {
            write!(f, "{}if{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            c.fmt_l12_with(f, d)?;
            write!(f, " {}then{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            et.fmt_l12_with(f, d)?;
            write!(f, " {}else{} ", d.fmt.keyword_start, d.fmt.keyword_end)?;
            ef.fmt_l12_with(f, d)
        } else {
            self.fmt_l11_with(f, d)
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_l12(f)
    }
}

pub struct ExprFormatter<'expr, 'trans> {
    expr: &'expr Expr,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'expr, 'trans> fmt::Display for ExprFormatter<'expr, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expr.fmt_l12_with(f, self)
    }
}

impl<'expr, 'trans> TranslatorDisplay<'expr, 'trans> for Expr {
    type Target = ExprFormatter<'expr, 'trans>;

    fn display_full(
        &'expr self,
        fmt: Cow<'trans, TranslatorFormatter<'trans>>,
    ) -> ExprFormatter<'expr, 'trans> {
        ExprFormatter { expr: self, fmt }
    }
}

impl From<BitVec> for Expr {
    fn from(val: BitVec) -> Self {
        Self::Val(val, ValHint::CONSTANT)
    }
}

impl From<Var> for Expr {
    fn from(var: Var) -> Self {
        Self::Var(var)
    }
}

impl<'z> FromSpace<'z, VarnodeData> for Expr {
    fn from_space_with(t: VarnodeData, _arena: &'_ IRBuilderArena, manager: &SpaceManager) -> Self {
        Expr::from_space(t, manager)
    }

    fn from_space(vnd: VarnodeData, manager: &SpaceManager) -> Expr {
        let space = unsafe { manager.unchecked_space_by_id(vnd.space()) };
        if space.is_constant() {
            Expr::from(BitVec::from_u64(vnd.offset(), vnd.size() * 8))
        } else {
            Expr::from(Var::from(vnd))
            /*
            if space.is_unique() || space.is_register() {
                Expr::from(Var::from(vnd))
            } else {
                // address-like: the vnd size is what it points to
                let asz = space.address_size() * 8;
                let val = BitVec::from_u64(vnd.offset(), asz);
                let src = if space.word_size() > 1 {
                    let s = Expr::from(val);
                    let bits = s.nbits();

                    let w = Expr::from(BitVec::from_usize(space.word_size(), bits as usize));

                    Expr::int_mul(s, w)
                } else {
                    Expr::from(val).into()
                };

                // TODO: we should preserve this information!!!
                //Expr::Cast(Box::new(src), Type::Pointer(Box::new(Type::Void), asz))

                Expr::Load(
                    src,
                    asz as u32,
                    vnd.space(),
                )
            }
            */
        }
    }
}

impl BitSize for Expr {
    fn nbits(&self) -> u32 {
        match self {
            Self::UnRel(_, _) | Self::BinRel(_, _, _) => 8,
            Self::UnOp(UnOp::POPCOUNT(bits), _) => *bits,
            Self::UnOp(_, e) | Self::BinOp(_, e, _) => e.nbits(),
            Self::Cast(_, cast) => cast.nbits(),
            Self::Extract(_, lsb, msb) => *msb - *lsb,
            Self::ExtractHigh(_, bits) | Self::ExtractLow(_, bits) => *bits,
            Self::Concat(l, r) => l.nbits() + r.nbits(),
            Self::IfElse(_, e, _) => e.nbits(),
            Self::Choice(_, _, _, bits) => *bits,
            Self::Intrinsic(_, _, bits) => *bits,
            Self::Load(_, bits, _) => *bits,
            Self::Val(bv, _) => bv.nbits() as u32,
            Self::Var(var) => var.nbits(),
        }
    }
}

impl Expr {
    pub fn is_cast_kind<F>(&self, f: F) -> bool
    where
        F: Fn(&Type) -> bool,
    {
        matches!(self, Self::Cast(_, cst) if f(cst))
    }

    pub fn is_bool(&self) -> bool {
        match self {
            Expr::BinRel(_, _, _) | Expr::UnRel(_, _) => true,
            Expr::BinOp(_, e, _) | Expr::UnOp(_, e) | Expr::IfElse(_, e, _) => e.is_bool(),
            Expr::Cast(_, t) => t.is_bool(),
            _ => false,
        }
    }

    fn is_cast_kind_aux_op<F>(&self, f: F) -> bool
    where
        F: Fn(&Type) -> bool,
    {
        match self {
            Expr::BinOp(_, e, _) | Expr::UnOp(_, e) | Expr::IfElse(_, e, _) => {
                e.is_cast_kind_aux_op(f)
            }
            Expr::Cast(_, t) => f(t),
            _ => false,
        }
    }

    fn float_kind(&self) -> Option<FloatKind> {
        match self {
            Expr::BinOp(_, e, _) | Expr::UnOp(_, e) | Expr::IfElse(_, e, _) => e.float_kind(),
            Expr::Cast(_, t) => {
                if let TypeKind::Float(fmt) = t.kind() {
                    Some(fmt.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn is_signed(&self) -> bool {
        self.is_cast_kind_aux_op(Type::is_signed)
            || matches!(self, Expr::Val(bv, _) if bv.is_signed())
    }

    pub fn is_signed_bits(&self, bits: u32) -> bool {
        self.is_cast_kind_aux_op(|s| s.is_signed_with(bits))
            || matches!(self, Expr::Val(bv, _) if bv.is_signed() && bv.nbits() == bits)
    }

    pub fn is_float(&self) -> bool {
        self.is_cast_kind_aux_op(Type::is_float)
    }

    pub fn is_float_kind<F>(&self, format: F) -> bool
    where
        F: Borrow<FloatFormat>,
    {
        self.is_cast_kind_aux_op(|f| f.is_float_kind(format.borrow()))
    }

    pub fn is_unsigned(&self) -> bool {
        match self {
            Expr::BinRel(_, _, _) | Expr::UnRel(_, _) => true,
            Expr::Cast(_, t) => matches!(t.kind(), TypeKind::Unsigned(_) | TypeKind::Pointer(_, _)),
            Expr::UnOp(UnOp::POPCOUNT(_), _) => true,
            Expr::UnOp(_, e) | Expr::BinOp(_, e, _) | Expr::IfElse(_, e, _) => e.is_unsigned(),
            Expr::Val(bv, _) => !bv.is_signed(),
            _ => true,
        }
    }

    pub fn is_unsigned_bits(&self, bits: u32) -> bool {
        match self {
            Expr::BinRel(_, _, _) | Expr::UnRel(_, _) => bits == 8,
            Expr::Cast(_, t) => {
                matches!(t.kind(), TypeKind::Unsigned(n) | TypeKind::Pointer(_, n) if *n == bits)
            }
            Expr::UnOp(UnOp::POPCOUNT(nbits), _) => *nbits == bits,
            Expr::UnOp(_, e) | Expr::BinOp(_, e, _) | Expr::IfElse(_, e, _) => {
                e.is_unsigned() && e.nbits() == bits
            }
            Expr::Val(bv, _) => !bv.is_signed() && bv.nbits() == bits,
            e => e.nbits() == bits,
        }
    }

    pub fn variable(&self) -> Option<&Var> {
        if let Self::Var(ref v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn address_value(&self) -> Option<Address> {
        match self {
            Self::Val(ref v, _) => v.to_u64().map(Address::from),
            Self::Var(vnd) => vnd.address(),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<&BitVec> {
        if let Self::Val(ref v, _) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn cast_bool<E>(expr: E) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();

        if let Self::Val(bv, _) = &*expr {
            Self::val(if bv.is_zero() {
                BitVec::zero(8)
            } else {
                BitVec::one(8)
            })
        } else if expr.is_bool() {
            expr
        } else {
            Self::Cast(expr.into(), Type::bool()).into()
        }
    }

    pub fn cast_signed<E>(expr: E, bits: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        if let Self::Val(bv, _) = &*expr {
            Self::val(bv.signed_cast(bits as usize))
        } else if expr.is_signed_bits(bits) {
            expr
        } else {
            Self::Cast(expr.into(), Type::signed(bits)).into()
        }
    }

    pub fn cast_unsigned<E>(expr: E, bits: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let mut expr = expr.into();
        if let Self::Val(bv, _) = &mut *expr {
            *bv = bv.unsigned_cast(bits as usize);
            expr
        } else if expr.is_unsigned_bits(bits) {
            expr
        } else {
            Self::Cast(expr.into(), Type::unsigned(bits)).into()
        }
    }

    pub fn cast_float<E, K>(expr: E, format: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = format.into();
        if expr.is_float_kind(&*kind) {
            expr
        } else {
            Self::Cast(expr.into(), Type::float(kind)).into()
        }
    }

    pub fn cast<E>(expr: E, bits: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        Self::Cast(expr.into(), Type::unsigned(bits)).into()
    }

    pub fn extract_high<E>(expr: E, bits: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        if let Self::Val(e, _) = &*expr {
            Self::val(if bits >= e.nbits() {
                e.unsigned_cast(bits as usize)
            } else {
                (&*e >> (e.nbits() as u32 - bits as u32))
                    .unsigned()
                    .cast(bits as usize)
            })
        } else if expr.is_unsigned_bits(bits) {
            expr
        } else {
            Self::ExtractHigh(expr.into(), bits).into()
        }
    }

    pub fn extract_low<E>(expr: E, bits: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        if let Self::Val(e, _) = &*expr {
            Self::val(e.unsigned_cast(bits as usize))
        } else if expr.is_unsigned_bits(bits) {
            expr
        } else {
            Self::ExtractLow(expr.into(), bits).into()
        }
    }

    pub fn choice_with<S, E, I, D>(selector: S, choices: I, default: D) -> Term<Self>
    where
        S: Into<Term<Self>>,
        I: ExactSizeIterator<Item = E>,
        E: Into<(BitVec, Term<Self>)>,
        D: Into<Option<Term<Self>>>,
    {
        assert_ne!(choices.len(), 0);

        let mut bits = 0;

        let selector = selector.into();
        let selector_bits = selector.nbits();

        let mut choices = choices
            .into_iter()
            .map(|choice| {
                let (mut guard, expr) = choice.into();
                if guard.nbits() != selector_bits {
                    guard.cast_assign(selector_bits as usize);
                }

                bits = bits.max(expr.nbits());

                (guard, expr)
            })
            .sorted_by(|(lk, _), (rk, _)| lk.cmp(rk))
            .dedup_by(|(lk, _), (rk, _)| lk == rk)
            .collect::<Vec<(_, _)>>();

        let default = if let Some(default) = default.into() {
            let default_bits = default.nbits();
            Some(if default_bits < bits {
                Expr::cast(default, bits)
            } else {
                bits = default_bits;
                default
            })
        } else {
            None
        };

        for (_, expr) in choices.iter_mut() {
            if expr.nbits() != bits {
                *expr = Expr::cast(expr.clone(), bits);
            }
        }

        Self::Choice(selector, choices, default, bits).into()
    }

    pub fn choice<S, E, I>(selector: S, choices: I) -> Term<Self>
    where
        S: Into<Term<Self>>,
        I: ExactSizeIterator<Item = E>,
        E: Into<(BitVec, Term<Self>)>,
    {
        Self::choice_with(selector, choices, None)
    }

    pub fn concat<E1, E2>(lhs: E1, rhs: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (&*lhs, &*rhs) {
            (Self::Val(h, _), Self::Val(l, _)) => Self::val({
                let bits = (h.nbits() + l.nbits()) as usize;
                (h.unsigned_cast(bits) << l.nbits()) | l.unsigned_cast(bits)
            }),
            _ => Self::Concat(lhs, rhs).into(),
        }
    }

    pub fn concat_with<O, E1, E2>(lhs: E1, rhs: E2) -> Term<Self>
    where
        O: Order,
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (&*lhs, &*rhs) {
            (Self::Val(h, _), Self::Val(l, _)) => Self::val({
                let bits = (h.nbits() + l.nbits()) as usize;
                (h.unsigned_cast(bits) << l.nbits()) | l.unsigned_cast(bits)
            }),
            (Self::Extract(t1, l1, h1), Self::Extract(t2, l2, h2))
                if O::ENDIAN.is_big() && t1 == t2 && h1 == l2 =>
            {
                Self::extract(t1.clone(), *l1, *h2)
            }
            (Self::Extract(t1, l1, h1), Self::Extract(t2, l2, h2))
                if O::ENDIAN.is_little() && t1 == t2 && l1 == h2 =>
            {
                Self::extract(t1.clone(), *l2, *h1)
            }
            _ => Self::Concat(lhs, rhs).into(),
        }
    }

    pub(crate) fn unary_op<E>(op: UnOp, expr: E) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        Self::UnOp(op, expr.into()).into()
    }

    pub fn unary_op_with<E, F>(op: UnOp, expr: E, eval: F) -> Term<Self>
    where
        E: Into<Term<Self>>,
        F: Fn(&Term<Self>) -> Option<Term<Self>>,
    {
        let expr = expr.into();

        eval(&expr).unwrap_or_else(|| Self::unary_op(op, expr))
    }

    pub(crate) fn unary_rel<E>(rel: UnRel, expr: E) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        Self::cast_bool(Self::UnRel(rel, expr.into()))
    }

    pub(crate) fn binary_op<E1, E2>(op: BinOp, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::BinOp(op, expr1.into(), expr2.into()).into()
    }

    pub fn binary_op_promote_as<E1, E2, F, G>(
        op: BinOp,
        expr1: E1,
        expr2: E2,
        cast: F,
        eval: G,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(Term<Self>, u32) -> Term<Self>,
        G: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        let e1 = expr1.into();
        let e2 = expr2.into();

        let bits = e1.nbits().max(e2.nbits());

        let v1 = cast(e1, bits);
        let v2 = cast(e2, bits);

        eval(&v1, &v2).unwrap_or_else(|| Self::binary_op(op, v1, v2))
    }

    pub fn binary_op_promote<E1, E2>(op: BinOp, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_as(
            op,
            expr1,
            expr2,
            |e, sz| Self::cast_unsigned(e, sz),
            |_, _| None,
        )
    }

    pub fn binary_op_promote_with<E1, E2, F>(op: BinOp, expr1: E1, expr2: E2, eval: F) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        Self::binary_op_promote_as(op, expr1, expr2, |e, sz| Self::cast_unsigned(e, sz), eval)
    }

    pub fn binary_op_promote_bool<E1, E2>(op: BinOp, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_as(op, expr1, expr2, |e, _sz| Self::cast_bool(e), |_, _| None)
    }

    pub fn binary_op_promote_bool_with<E1, E2, F>(
        op: BinOp,
        expr1: E1,
        expr2: E2,
        eval: F,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        Self::binary_op_promote_as(op, expr1, expr2, |e, _sz| Self::cast_bool(e), eval)
    }

    pub fn binary_op_promote_signed_with<E1, E2, F>(
        op: BinOp,
        expr1: E1,
        expr2: E2,
        eval: F,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        Self::binary_op_promote_as(op, expr1, expr2, |e, sz| Self::cast_signed(e, sz), eval)
    }

    pub(crate) fn binary_op_promote_signed<E1, E2>(op: BinOp, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_as(
            op,
            expr1,
            expr2,
            |e, sz| Self::cast_signed(e, sz),
            |_, _| None,
        )
    }

    pub(crate) fn binary_op_promote_float<E1, E2>(
        op: BinOp,
        expr1: E1,
        expr2: E2,
        formats: &Map<u32, FloatKind>,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_as(
            op,
            expr1,
            expr2,
            |e, sz| Self::cast_float(Self::cast_signed(e, sz), formats[&sz].clone()),
            |_, _| None,
        )
    }

    pub(crate) fn binary_op_promote_float_with<E1, E2>(
        op: BinOp,
        expr1: E1,
        expr2: E2,
        format: FloatKind,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_as(
            op,
            expr1,
            expr2,
            |e, _sz| Self::cast_float(Self::cast_signed(e, format.nbits()), format.clone()),
            |_, _| None,
        )
    }

    pub(crate) fn binary_rel<E1, E2>(rel: BinRel, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::cast_bool(Self::BinRel(rel, expr1.into(), expr2.into()))
    }

    pub(crate) fn binary_rel_promote_as<E1, E2, F, G>(
        op: BinRel,
        expr1: E1,
        expr2: E2,
        cast: F,
        eval: G,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(Term<Self>, u32) -> Term<Self>,
        G: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        let e1 = expr1.into();
        let e2 = expr2.into();

        let bits = e1.nbits().max(e2.nbits());

        let v1 = cast(e1, bits);
        let v2 = cast(e2, bits);

        eval(&v1, &v2).unwrap_or_else(|| Self::binary_rel(op, v1, v2))
    }

    pub fn binary_rel_promote<E1, E2>(op: BinRel, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_as(
            op,
            expr1,
            expr2,
            |e, sz| Self::cast_unsigned(e, sz),
            |_, _| None,
        )
    }

    pub fn binary_rel_promote_with<E1, E2, F>(
        op: BinRel,
        expr1: E1,
        expr2: E2,
        eval: F,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        Self::binary_rel_promote_as(op, expr1, expr2, |e, sz| Self::cast_unsigned(e, sz), eval)
    }

    pub fn binary_rel_promote_float_with<E1, E2>(
        op: BinRel,
        expr1: E1,
        expr2: E2,
        format: FloatKind,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_as(
            op,
            expr1,
            expr2,
            |e, _sz| Self::cast_float(Self::cast_signed(e, format.nbits()), format.clone()),
            |_, _| None,
        )
    }

    pub(crate) fn binary_rel_promote_float<E1, E2>(
        op: BinRel,
        expr1: E1,
        expr2: E2,
        formats: &Map<u32, FloatKind>,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_as(
            op,
            expr1,
            expr2,
            |e, sz| Self::cast_float(Self::cast_signed(e, sz), formats[&sz].clone()),
            |_, _| None,
        )
    }

    pub fn binary_rel_promote_signed_with<E1, E2, F>(
        op: BinRel,
        expr1: E1,
        expr2: E2,
        eval: F,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        Self::binary_rel_promote_as(op, expr1, expr2, |e, sz| Self::cast_signed(e, sz), eval)
    }

    pub fn binary_rel_promote_signed<E1, E2>(op: BinRel, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_as(
            op,
            expr1,
            expr2,
            |e, sz| Self::cast_signed(e, sz),
            |_, _| None,
        )
    }

    pub fn binary_rel_promote_bool<E1, E2>(op: BinRel, expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_as(op, expr1, expr2, |e, _sz| Self::cast_bool(e), |_, _| None)
    }

    pub fn binary_rel_promote_bool_with<E1, E2, F>(
        op: BinRel,
        expr1: E1,
        expr2: E2,
        eval: F,
    ) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
        F: Fn(&Term<Self>, &Term<Self>) -> Option<Term<Self>>,
    {
        Self::binary_rel_promote_as(op, expr1, expr2, |e, _sz| Self::cast_bool(e), eval)
    }

    pub fn load<E>(expr: E, size: u32, space: &AddressSpace) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        Self::Load(
            Self::cast_unsigned(expr, space.address_size() as u32 * 8),
            size,
            space.id(),
        )
        .into()
    }

    /*
    pub fn call<T>(target: T, bits: u32) -> Term<Self>
    where
        T: Into<Term<BranchTarget>>,
    {
        Self::Call(target.into(), Default::default(), bits).into()
    }

    pub fn call_with<T, I, E>(target: T, arguments: I, bits: u32) -> Term<Self>
    where
        T: Into<Term<BranchTarget>>,
        I: ExactSizeIterator<Item = E>,
        E: Into<Term<Self>>,
    {
        let mut args = SmallVec::with_capacity(arguments.len());
        for arg in arguments {
            args.push(arg.into());
        }

        Self::Call(target.into(), args, bits).into()
    }
    */

    pub fn intrinsic<N, I, E>(name: N, arguments: I, bits: u32) -> Term<Self>
    where
        N: Into<Ustr>,
        I: ExactSizeIterator<Item = E>,
        E: Into<Term<Self>>,
    {
        let mut args = SmallVec::with_capacity(arguments.len());
        for arg in arguments {
            args.push(arg.into());
        }

        Self::Intrinsic(name.into(), args, bits).into()
    }

    pub fn extract<E>(expr: E, loff: u32, moff: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        if let Self::Val(e, _) = &*expr {
            Self::val(if loff > 0 {
                (e >> loff as u32).unsigned_cast((moff - loff) as usize)
            } else {
                e.unsigned_cast((moff - loff) as usize)
            })
        } else if loff == 0 && moff == expr.nbits() {
            expr
        } else {
            Self::Extract(expr, loff, moff).into()
        }
    }

    pub fn ite<C, E1, E2>(cond: C, texpr: E1, fexpr: E2) -> Term<Self>
    where
        C: Into<Term<Self>>,
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        let cond = Self::cast_bool(cond);
        let e1 = texpr.into();
        let e2 = fexpr.into();

        assert_eq!(e1.nbits(), e2.nbits());

        if let Self::Val(v, _) = &*cond {
            if v.is_zero() {
                e2
            } else {
                e1
            }
        } else if e1 == e2 {
            e1
        } else {
            Self::IfElse(cond, e1, e2).into()
        }
    }

    pub fn bool_not<E>(expr: E) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();

        Self::unary_op_with(UnOp::NOT, Self::cast_bool(expr), |v| match &**v {
            Expr::Val(v, _) => Some(Expr::val(!v)),
            Expr::UnOp(UnOp::NOT, expr) => Some(expr.clone()),
            Expr::BinRel(BinRel::EQ, lexpr, rexpr) => {
                Some(Expr::BinRel(BinRel::NEQ, lexpr.clone(), rexpr.clone()).into())
            }
            Expr::BinRel(BinRel::NEQ, lexpr, rexpr) => {
                Some(Expr::BinRel(BinRel::EQ, lexpr.clone(), rexpr.clone()).into())
            }
            Expr::BinRel(BinRel::LT, lexpr, rexpr) => {
                Some(Expr::BinRel(BinRel::LE, rexpr.clone(), lexpr.clone()).into())
            }
            Expr::BinRel(BinRel::LE, lexpr, rexpr) => {
                Some(Expr::BinRel(BinRel::LT, rexpr.clone(), lexpr.clone()).into())
            }
            Expr::BinRel(BinRel::SLT, lexpr, rexpr) => {
                Some(Expr::BinRel(BinRel::SLE, rexpr.clone(), lexpr.clone()).into())
            }
            Expr::BinRel(BinRel::SLE, lexpr, rexpr) => {
                Some(Expr::BinRel(BinRel::SLT, rexpr.clone(), lexpr.clone()).into())
            }
            _ => None,
        })
    }

    pub fn bool_eq<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_bool_with(BinRel::EQ, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv == rv) as u8)),
            _ if l == r => Some(Expr::val(1u8)),
            _ => None,
        })
    }

    pub fn bool_neq<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_bool_with(BinRel::NEQ, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv == rv) as u8)),
            _ if l == r => Some(Expr::val(0u8)),
            _ => None,
        })
    }

    pub fn bool_and<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_bool_with(BinOp::AND, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv & rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(l.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(r.clone()),
            _ if l == r => Some(l.clone()),
            _ => None,
        })
    }

    pub fn bool_or<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_bool_with(BinOp::OR, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv | rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(r.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ if l == r => Some(l.clone()),
            _ => None,
        })
    }

    pub fn bool_xor<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_bool_with(BinOp::XOR, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv ^ rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(r.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ if l == r => Some(Expr::val(BitVec::zero(l.nbits() as usize))),
            _ => None,
        })
    }

    pub fn float_nan<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();

        let format = formats[&bits].clone();

        Self::unary_rel(
            UnRel::NAN,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_neg<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();
        let format = formats[&bits].clone();

        Self::unary_op(
            UnOp::NEG,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_neg_with<E, K>(expr: E, kind: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = kind.into();

        Self::unary_op(
            UnOp::NEG,
            if expr.is_float_kind(&*kind) {
                expr
            } else {
                Expr::cast_float(Expr::cast_signed(expr, kind.nbits()), kind)
            },
        )
    }

    pub fn float_abs<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();
        let format = formats[&bits].clone();

        Self::unary_op(
            UnOp::ABS,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_abs_with<E, K>(expr: E, format: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = format.into();
        Self::unary_op(
            UnOp::ABS,
            if expr.is_float_kind(&*kind) {
                expr
            } else {
                Expr::cast_float(Expr::cast_signed(expr, kind.nbits()), kind)
            },
        )
    }

    pub fn float_sqrt<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();
        let format = formats[&bits].clone();

        Self::unary_op(
            UnOp::SQRT,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_sqrt_with<E, K>(expr: E, format: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = format.into();
        Self::unary_op(
            UnOp::SQRT,
            if expr.is_float_kind(&*kind) {
                expr
            } else {
                Expr::cast_float(Expr::cast_signed(expr, kind.nbits()), kind)
            },
        )
    }

    pub fn float_ceiling<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();
        let format = formats[&bits].clone();

        Self::unary_op(
            UnOp::CEILING,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_ceiling_with<E, K>(expr: E, format: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = format.into();
        Self::unary_op(
            UnOp::CEILING,
            if expr.is_float_kind(&*kind) {
                expr
            } else {
                Expr::cast_float(Expr::cast_signed(expr, kind.nbits()), kind)
            },
        )
    }

    pub fn float_round<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();
        let format = formats[&bits].clone();

        Self::unary_op(
            UnOp::ROUND,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_round_with<E, K>(expr: E, format: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = format.into();
        Self::unary_op(
            UnOp::ROUND,
            if expr.is_float_kind(&*kind) {
                expr
            } else {
                Expr::cast_float(Expr::cast_signed(expr, kind.nbits()), kind)
            },
        )
    }

    pub fn float_floor<E>(expr: E, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let bits = expr.nbits();
        let format = formats[&bits].clone();

        Self::unary_op(
            UnOp::FLOOR,
            Expr::cast_float(Expr::cast_signed(expr, bits), format),
        )
    }

    pub fn float_floor_with<E, K>(expr: E, format: K) -> Term<Self>
    where
        E: Into<Term<Self>>,
        K: Into<FloatKind>,
    {
        let expr = expr.into();
        let kind = format.into();
        Self::unary_op(
            UnOp::FLOOR,
            if expr.is_float_kind(&*kind) {
                expr
            } else {
                Expr::cast_float(Expr::cast_signed(expr, kind.nbits()), kind)
            },
        )
    }

    pub fn float_eq_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float_with(BinRel::EQ, expr1, expr2, format)
    }

    pub fn float_neq_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float_with(BinRel::NEQ, expr1, expr2, format)
    }

    pub fn float_lt_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float_with(BinRel::LT, expr1, expr2, format)
    }

    pub fn float_le_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float_with(BinRel::LE, expr1, expr2, format)
    }

    pub fn float_eq<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float(BinRel::EQ, expr1, expr2, formats)
    }

    pub fn float_neq<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float(BinRel::NEQ, expr1, expr2, formats)
    }

    pub fn float_lt<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float(BinRel::LT, expr1, expr2, formats)
    }

    pub fn float_le<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_float(BinRel::LE, expr1, expr2, formats)
    }

    pub fn float_add<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float(BinOp::ADD, expr1, expr2, formats)
    }

    pub fn float_sub<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float(BinOp::SUB, expr1, expr2, formats)
    }

    pub fn float_div<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float(BinOp::DIV, expr1, expr2, formats)
    }

    pub fn float_mul<E1, E2>(expr1: E1, expr2: E2, formats: &Map<u32, FloatKind>) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float(BinOp::MUL, expr1, expr2, formats)
    }

    pub fn float_add_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float_with(BinOp::ADD, expr1, expr2, format)
    }

    pub fn float_sub_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float_with(BinOp::SUB, expr1, expr2, format)
    }

    pub fn float_div_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float_with(BinOp::DIV, expr1, expr2, format)
    }

    pub fn float_mul_with<E1, E2>(expr1: E1, expr2: E2, format: FloatKind) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_float_with(BinOp::MUL, expr1, expr2, format)
    }

    pub fn count_ones<E>(expr: E, bits: u32) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        Self::unary_op(UnOp::POPCOUNT(bits), expr.into())
    }

    pub fn int_neg<E>(expr: E) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let size = expr.nbits();

        Self::unary_op_with(UnOp::NEG, Self::cast_unsigned(expr, size), |v| match &**v {
            Expr::Val(v, _) => Some(Expr::val(-v)),
            _ => None,
        })
    }

    pub fn int_not<E>(expr: E) -> Term<Self>
    where
        E: Into<Term<Self>>,
    {
        let expr = expr.into();
        let size = expr.nbits();

        Self::unary_op_with(UnOp::NOT, Self::cast_unsigned(expr, size), |v| match &**v {
            Expr::Val(v, _) => Some(Expr::val(!v)),
            _ => None,
        })
    }

    pub fn int_eq<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::EQ, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv == rv) as u8)),
            (Expr::BinOp(BinOp::SUB, v, cst), z)
                if cst.is_val() && z.is_val_with(|v| v.is_zero()) =>
            {
                Some(Expr::int_eq(v.clone(), cst.clone()))
            }
            _ if l == r => Some(Expr::val(1u8)),
            _ => None,
        })
    }

    pub fn int_neq<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::NEQ, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv == rv) as u8)),
            _ if l == r => Some(Expr::val(0u8)),
            _ => None,
        })
    }

    pub fn int_lt<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::LT, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv < rv) as u8)),
            _ if l == r => Some(Expr::val(0u8)),
            _ => None,
        })
    }

    pub fn int_le<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::LE, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv <= rv) as u8)),
            _ if l == r => Some(Expr::val(1u8)),
            _ => None,
        })
    }

    pub fn int_slt<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::SLT, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv < rv) as u8)),
            (Expr::BinOp(BinOp::SUB, v, cst), z)
                if cst.is_val() && z.is_val_with(|v| v.is_zero()) =>
            {
                Some(Expr::int_slt(v.clone(), cst.clone()))
            }
            _ if l == r => Some(Expr::val(0u8)),
            _ => None,
        })
    }

    pub fn int_sle<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::SLE, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val((lv <= rv) as u8)),
            _ if l == r => Some(Expr::val(1u8)),
            _ => None,
        })
    }

    pub fn int_carry<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::CARRY, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv.carry(rv) as u8)),
            _ => None,
        })
    }

    pub fn int_scarry<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::SCARRY, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv.signed_carry(rv) as u8)),
            _ => None,
        })
    }

    pub fn int_sborrow<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_rel_promote_with(BinRel::SBORROW, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv.signed_borrow(rv) as u8)),
            _ => None,
        })
    }

    pub fn int_add<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::ADD, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv + rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(r.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_sub<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::SUB, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv - rv)),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_mul<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::MUL, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv * rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(l.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(r.clone()),
            (Expr::Val(v, _), _) if v.is_one() => Some(r.clone()),
            (_, Expr::Val(v, _)) if v.is_one() => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_div<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::DIV, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => {
                if rv.is_zero() {
                    None
                } else {
                    Some(Expr::val(lv / rv))
                }
            }
            _ => None,
        })
    }

    pub fn int_sdiv<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_signed(BinOp::SDIV, expr1, expr2)
    }

    pub fn int_rem<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::REM, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => {
                if rv.is_zero() {
                    None
                } else {
                    Some(Expr::val(lv % rv))
                }
            }
            _ => None,
        })
    }

    pub fn int_srem<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_signed(BinOp::SREM, expr1, expr2)
    }

    pub fn int_shl<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::SHL, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv << rv)),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_shr<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::SHR, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv >> rv)),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_sar<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_signed(BinOp::SAR, expr1, expr2)
    }

    pub fn int_and<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::AND, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv & rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(l.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(r.clone()),
            _ if l == r => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_or<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::OR, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv | rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(r.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ if l == r => Some(l.clone()),
            _ => None,
        })
    }

    pub fn int_xor<E1, E2>(expr1: E1, expr2: E2) -> Term<Self>
    where
        E1: Into<Term<Self>>,
        E2: Into<Term<Self>>,
    {
        Self::binary_op_promote_with(BinOp::XOR, expr1, expr2, |l, r| match (&**l, &**r) {
            (Expr::Val(lv, _), Expr::Val(rv, _)) => Some(Expr::val(lv ^ rv)),
            (Expr::Val(v, _), _) if v.is_zero() => Some(r.clone()),
            (_, Expr::Val(v, _)) if v.is_zero() => Some(l.clone()),
            _ if l == r => Some(Expr::val(BitVec::zero(l.nbits() as usize))),
            _ => None,
        })
    }

    pub fn val<V>(v: V) -> Term<Self>
    where
        V: Into<BitVec>,
    {
        Self::Val(v.into(), ValHint::CONSTANT).into()
    }

    pub fn addr<V>(v: V) -> Term<Self>
    where
        V: Into<Address>,
    {
        Self::Val(u64::from(v.into()).into(), ValHint::ADDRESS).into()
    }

    pub fn var<V>(v: V) -> Term<Self>
    where
        V: Into<Var>,
    {
        Self::Var(v.into()).into()
    }
}

impl<'z> FromSpace<'z, Operand> for Expr {
    fn from_space_with(
        operand: Operand,
        _arena: &'z IRBuilderArena,
        manager: &SpaceManager,
    ) -> Self {
        Expr::from_space(operand, manager)
    }

    fn from_space(operand: Operand, manager: &SpaceManager) -> Self {
        if let Operand::Constant { value, size, .. } = operand {
            Expr::Val(BitVec::from_u64(value, size * 8), ValHint::CONSTANT)
        } else {
            Var::from_space(operand, manager).into()
        }
    }
}

impl Expr {
    pub fn is_val(&self) -> bool {
        matches!(self, Expr::Val(_, _))
    }

    pub fn is_val_with<F>(&self, f: F) -> bool
    where
        F: FnOnce(&BitVec) -> bool,
    {
        match self {
            Expr::Val(v, _) => f(v),
            _ => false,
        }
    }

    pub fn is_bv<V: Into<BitVec>>(&self, val: V) -> bool {
        self.is_val_with(|v| *v == val.into())
    }

    pub fn is_var(&self) -> bool {
        matches!(self, Expr::Var(_))
    }

    pub fn is_var_with<F>(&self, f: F) -> bool
    where
        F: FnOnce(&Var) -> bool,
    {
        matches!(self, Expr::Var(v) if f(v))
    }

    pub fn is_binop(&self, op: BinOp) -> bool {
        matches!(self, Expr::BinOp(op1, _, _) if op == *op1)
    }

    pub fn is_binrel(&self, op: BinRel) -> bool {
        matches!(self, Expr::BinRel(op1, _, _) if op == *op1)
    }

    pub fn is_binop_with<F>(&self, op: BinOp, f: F) -> bool
    where
        F: FnOnce(&Expr, &Expr) -> bool,
    {
        matches!(self, Expr::BinOp(op1, l, r) if op == *op1 && f(&*l, &*r))
    }

    pub fn is_binop_llr_with<F>(&self, op: BinOp, f: F) -> bool
    where
        F: FnOnce(&Expr, &Expr, &Expr) -> bool,
    {
        matches!(self, Expr::BinOp(op1, l, r) if op == *op1 &&
                 matches!(&**l, Expr::BinOp(op2, ll, lr) if op == *op2 && f(ll, lr, r)))
    }

    pub fn is_binop_lrr_with<F>(&self, op: BinOp, f: F) -> bool
    where
        F: FnOnce(&Expr, &Expr, &Expr) -> bool,
    {
        matches!(self, Expr::BinOp(op1, l, r) if op == *op1 &&
                 matches!(&**r, Expr::BinOp(op2, rl, rr) if op == *op2 && f(l, rl, rr)))
    }

    #[inline]
    pub fn unop_with<'a, T: 'a, F>(&'a self, op: UnOp, f: F) -> Option<T>
    where
        F: FnOnce(&'a Term<Expr>) -> Option<T>,
    {
        if let Expr::UnOp(opd, e) = self {
            if *opd == op {
                f(e)
            } else {
                None
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn binop_with<'a, T: 'a, F>(&'a self, op: BinOp, f: F) -> Option<T>
    where
        F: FnOnce(&'a Term<Expr>, &'a Term<Expr>) -> Option<T>,
    {
        if let Expr::BinOp(opd, l, r) = self {
            if *opd == op {
                f(l, r)
            } else {
                None
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn binrel_with<'a, T: 'a, F>(&'a self, op: BinRel, f: F) -> Option<T>
    where
        F: FnOnce(&'a Term<Expr>, &'a Term<Expr>) -> Option<T>,
    {
        if let Expr::BinRel(opd, l, r) = self {
            if *opd == op {
                f(l, r)
            } else {
                None
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn constant(&self) -> Option<&BitVec> {
        if let Self::Val(bv, ValHint::CONSTANT) = self {
            Some(bv)
        } else {
            None
        }
    }

    #[inline]
    pub fn address(&self) -> Option<Address> {
        if let Self::Val(bv, ValHint::ADDRESS) = self {
            Some(bv.to_u64().unwrap().into())
        } else {
            None
        }
    }

    #[inline]
    pub fn load_source(&self) -> Option<(&Term<Expr>, u32)> {
        if let Self::Load(expr, bits, _) = self {
            Some((expr, *bits))
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn match_lr<'a, T: 'a, U: 'a, F, G>(
        l: &'a Term<Expr>,
        r: &'a Term<Expr>,
        f: F,
        g: G,
    ) -> Option<(T, U)>
    where
        F: Fn(&'a Term<Expr>) -> Option<T>,
        G: Fn(&'a Term<Expr>) -> Option<U>,
    {
        f(l).and_then(|t| g(r).map(|u| (t, u)))
            .or_else(|| g(l).and_then(|u| f(r).map(|t| (t, u))))
    }

    #[inline]
    pub fn cond_via_and(&self) -> Option<(&Var, &BitVec)> {
        self.binop_with(BinOp::AND, |l, r| Some((l, r)))
            .and_then(|(l, r)| Self::match_lr(l, r, |e| e.variable(), |e| e.constant()))
    }

    #[inline]
    pub fn cond_via_sub(&self) -> Option<(&Var, &BitVec)> {
        self.binop_with(BinOp::SUB, |l, r| Some((l, r)))
            .and_then(|(l, r)| Self::match_lr(l, r, |e| e.variable(), |e| e.constant()))
    }

    #[inline]
    pub fn zflag(&self) -> Option<(&Term<Expr>, &Term<Expr>)> {
        self.binrel_with(BinRel::EQ, |l, r| Some((l, r)))
    }

    // if A == B; if A is a var and B is a val
    #[inline]
    pub fn zflag_vc(&self) -> Option<(&Var, &BitVec)> {
        self.zflag()
            .and_then(|(l, r)| Self::match_lr(l, r, |e| e.variable(), |e| e.constant()))
    }

    #[inline]
    pub fn cflag(&self) -> Option<(&Term<Expr>, &Term<Expr>)> {
        self.binrel_with(BinRel::LT, |l, r| Some((l, r)))
    }

    // if A < B; if A is a var and B is a val
    #[inline]
    pub fn cflag_vc(&self) -> Option<(&Var, &BitVec)> {
        self.cflag()
            .and_then(|(l, r)| l.variable().zip(r.constant()))
    }

    #[inline]
    pub fn nflag(&self) -> Option<(&Term<Expr>, &Term<Expr>)> {
        self.binrel_with(BinRel::SLT, |l, r| Some((l, r)))
    }

    // if A <s B; if A is a var and B is a val
    #[inline]
    pub fn nflag_vc(&self) -> Option<(&Var, &BitVec)> {
        self.nflag()
            .and_then(|(l, r)| l.variable().zip(r.constant()))
    }

    #[inline]
    pub fn vflag(&self) -> Option<(&Term<Expr>, &Term<Expr>)> {
        self.binrel_with(BinRel::SBORROW, |l, r| Some((l, r)))
    }

    // if sborrow(A, B); if A is a var and B is a val
    #[inline]
    pub fn vflag_vc(&self) -> Option<(&Var, &BitVec)> {
        self.vflag()
            .and_then(|(l, r)| l.variable().zip(r.constant()))
    }

    #[inline]
    pub fn cond_eq(&self) -> Option<(&Var, &BitVec)> {
        self.zflag_vc()
    }

    #[inline]
    pub fn cond_neq(&self) -> Option<(&Var, &BitVec)> {
        self.unop_with(UnOp::NOT, |e| e.cond_eq()).or_else(|| {
            self.binrel_with(BinRel::NEQ, |l, r| {
                Self::match_lr(l, r, |e| e.variable(), |e| e.constant())
            })
        })
    }

    #[inline]
    pub fn cond_slt(&self) -> Option<(&Var, &BitVec)> {
        self.binrel_with(BinRel::NEQ, |l, r| {
            Self::match_lr(l, r, |e| e.nflag_vc(), |e| e.vflag_vc()).and_then(|(lf, rf)| {
                if lf == rf {
                    Some(lf)
                } else {
                    None
                }
            })
        })
    }

    #[inline]
    pub fn cond_sle(&self) -> Option<(&Var, &BitVec)> {
        self.binrel_with(BinRel::SLE, |l, r| Some((l, r)))
            .and_then(|(l, r)| Self::match_lr(l, r, |e| e.variable(), |e| e.constant()))
            .or_else(|| {
                self.binop_with(BinOp::OR, |l, r| {
                    Self::match_lr(l, r, |e| e.cond_eq(), |e| e.cond_slt()).and_then(|(lf, rf)| {
                        if lf == rf {
                            Some(lf)
                        } else {
                            None
                        }
                    })
                })
            })
    }

    #[inline]
    pub fn cond_sge(&self) -> Option<(&Var, &BitVec)> {
        self.binrel_with(BinRel::EQ, |l, r| {
            Self::match_lr(l, r, |e| e.nflag_vc(), |e| e.vflag_vc()).and_then(|(lf, rf)| {
                if lf == rf {
                    Some(lf)
                } else {
                    None
                }
            })
        })
    }

    #[inline]
    pub fn cond_sgt(&self) -> Option<(&Var, &BitVec)> {
        self.binop_with(BinOp::AND, |l, r| {
            Self::match_lr(l, r, |e| e.cond_neq(), |e| e.cond_sge()).and_then(|(lf, rf)| {
                if lf == rf {
                    Some(lf)
                } else {
                    None
                }
            })
        })
    }

    #[inline]
    pub fn cond_lt(&self) -> Option<(&Var, &BitVec)> {
        self.cflag_vc()
    }

    #[inline]
    pub fn cond_le(&self) -> Option<(&Var, &BitVec)> {
        self.binrel_with(BinRel::LE, |l, r| Some((l, r)))
            .and_then(|(l, r)| Self::match_lr(l, r, |e| e.variable(), |e| e.constant()))
            .or_else(|| {
                self.binop_with(BinOp::OR, |l, r| {
                    Self::match_lr(l, r, |e| e.cond_lt(), |e| e.cond_eq()).and_then(|(lf, rf)| {
                        if lf == rf {
                            Some(lf)
                        } else {
                            None
                        }
                    })
                })
            })
    }

    #[inline]
    pub fn cond_gt(&self) -> Option<(&Var, &BitVec)> {
        self.unop_with(UnOp::NOT, |e| e.cond_le())
    }

    #[inline]
    pub fn cond_ge(&self) -> Option<(&Var, &BitVec)> {
        self.unop_with(UnOp::NOT, |e| e.cond_lt())
    }

    fn comm3_reduce<'a>(
        op: BinOp,
        a: &'a Term<Expr>,
        b: &'a Term<Expr>,
        c: &'a Term<Expr>,
    ) -> (bool, Term<Expr>) {
        let mut t = [a, b, c];

        let sorted = **a >= **b && **b >= **c;

        if **t[0] < **t[1] {
            t.swap(0, 1);
        }
        if **t[1] < **t[2] {
            t.swap(1, 2);
        }
        if **t[0] < **t[1] {
            t.swap(0, 1);
        }

        let v = if t[1].is_val() && t[2].is_val() {
            op.apply(t[0].clone(), op.apply(t[1].clone(), t[2].clone()))
        } else {
            op.apply(op.apply(t[0].clone(), t[1].clone()), t[2].clone())
        };

        (sorted, v)
    }

    pub fn group_left(&self) -> Term<Self> {
        match self {
            Self::BinOp(op1, l, r) => match &**r {
                Self::BinOp(op2, rl, rr) if *op1 == *op2 => if op1.is_commutative() {
                    Self::comm3_reduce(*op1, l, rl, rr).1
                } else {
                    op1.apply(op1.apply(l.clone(), rl.clone()), rr.clone())
                }
                .canonical(),
                _ if op1.is_commutative() => match &**l {
                    Self::BinOp(op2, ll, rl) if *op1 == *op2 => {
                        tracing::trace!("other reduce!");
                        let (sorted, t) = Self::comm3_reduce(*op1, ll, rl, r);
                        if !sorted {
                            t.canonical()
                        } else {
                            self.clone().into()
                        }
                    }
                    _ => self.clone().into(),
                },
                _ => self.clone().into(),
            },
            _ => self.clone().into(),
        }
    }

    // NOTES: rewrites expressions such that:
    // - a op b becomes b op a if a < b and op is comm.
    // - a op (b op c) becomes (a op b) op c if op is assoc.
    // ...
    //
    // The goal of canonicalisation is to produce expressions that are in the form
    // X + a, where a is some constant and X is some expression. Since we have a total
    // order over expressions, we can enforce the form Var + Val.
    pub fn canonical(&self) -> Term<Self> {
        match self {
            Self::Cast(e, c) => {
                let ex = e.canonical();
                c.apply(ex)
            }
            Self::UnOp(op, e) => {
                let ex = e.canonical();
                op.apply(ex)
            }
            Self::UnRel(op, e) => {
                let ex = e.canonical();
                op.apply(ex)
            }
            Self::BinOp(op, l, r) => {
                let lx = l.canonical();
                let rx = r.canonical();

                let nx = if op.is_commutative() {
                    let (nlx, nrx) = if *lx < *rx { (rx, lx) } else { (lx, rx) };
                    op.apply(nlx, nrx)
                } else {
                    op.apply(lx, rx)
                };

                if op.is_associative() {
                    nx.group_left()
                } else {
                    nx.into()
                }
            }
            Self::BinRel(op, l, r) => {
                let lx = l.canonical();
                let rx = r.canonical();

                if op.is_commutative() {
                    let (nlx, nrx) = if *lx < *rx { (rx, lx) } else { (lx, rx) };
                    op.apply(nlx, nrx)
                } else {
                    op.apply(lx, rx)
                }
            }
            Self::Concat(l, r) => {
                let lx = l.canonical();
                let rx = r.canonical();
                Self::concat(lx, rx)
            }
            Self::Extract(e, loff, moff) => {
                let ex = e.canonical();
                Self::extract(ex, *loff, *moff)
            }
            Self::ExtractLow(e, bits) => {
                let ex = e.canonical();
                Self::extract_low(ex, *bits)
            }
            Self::ExtractHigh(e, bits) => {
                let ex = e.canonical();
                Self::extract_high(ex, *bits)
            }
            Self::Load(e, sz, spc) => {
                let ex = e.canonical();
                Self::Load(ex, *sz, *spc).into()
            }
            Self::IfElse(b, t, f) => {
                let bx = b.canonical();
                let tx = t.canonical();
                let fx = f.canonical();
                Self::ite(bx, tx, fx)
            }
            /*
            Self::Call(bt, args, sz) => {
                // TODO: canonical_with for bt?
                let btx = bt.canonical();
                let argsx = args.iter().map(|arg| arg.canonical()).collect();
                Self::Call(btx, argsx, *sz).into()
            }
            */
            Self::Intrinsic(nm, args, sz) => {
                let argsx = args.iter().map(|arg| arg.canonical()).collect();
                Self::Intrinsic(nm.clone(), argsx, *sz).into()
            }
            t => t.clone().into(), // Val | Var
        }
    }

    /// Assumes that svar.nbits() != pvar.nbits()
    /// Assumes that either svar completely contains pvar or pvar completely contains svar
    pub fn resize_with(expr: &mut Term<Expr>, svar: &SimpleVar, pvar: &SimpleVar) {
        match svar.nbits().cmp(&pvar.nbits()) {
            Ordering::Greater => {
                let nexpr = expr.clone();
                *expr = if svar.offset() == pvar.offset() {
                    // truncate
                    // e.g svar: RAX, pvar: AL
                    Expr::extract_low(nexpr, pvar.nbits())
                } else {
                    // e.g. svar: RAX, pvar: AH
                    let loff = (pvar.offset() - svar.offset()) as u32 * 8;
                    let moff = loff + pvar.nbits();
                    Expr::extract(nexpr, loff, moff)
                }
            }
            Ordering::Less => {
                let nexpr = expr.clone();
                *expr = if svar.offset() == pvar.offset() {
                    // e.g. svar: AL, pvar: RAX
                    let hbits = Expr::extract_high(Expr::var(**pvar), pvar.nbits() - svar.nbits());
                    Expr::concat(hbits, nexpr)
                } else {
                    if svar.offset() + (svar.nbits() as u64 / 8) == (pvar.nbits() as u64 / 8) {
                        // e.g. svar: AH, pvar: AX
                        let lbits =
                            Expr::extract_low(Expr::var(**pvar), pvar.nbits() - svar.nbits());
                        Expr::concat(nexpr, lbits)
                    } else {
                        // e.g. svar: AH, pvar: RAX
                        let shift = (svar.offset() - pvar.offset()) as u32 * 8;

                        let lbits = Expr::extract_low(Expr::var(**pvar), shift);
                        let nhbits = pvar.nbits() - svar.nbits() - shift;

                        if nhbits == 0 {
                            Expr::concat(nexpr, lbits)
                        } else {
                            let hbits = Expr::extract_high(Expr::var(**pvar), nhbits);
                            Expr::concat(hbits, Expr::concat(nexpr, lbits))
                        }
                    }
                }
            }
            Ordering::Equal => (),
        }
    }

    pub fn height(&self) -> usize {
        match self {
            Self::UnRel(_, e) => 1 + e.height(),
            Self::BinRel(_, l, r) => 1 + l.height().max(r.height()),
            Self::UnOp(_, e) => 1 + e.height(),
            Self::BinOp(_, l, r) => 1 + l.height().max(r.height()),
            Self::Cast(e, _) => 1 + e.height(),
            Self::Extract(e, _, _) => 1 + e.height(),
            Self::ExtractHigh(e, _) | Self::ExtractLow(e, _) => 1 + e.height(),
            Self::Concat(l, r) => 1 + l.height().max(r.height()),
            Self::IfElse(c, t, f) => 1 + c.height().max(t.height()).max(f.height()),
            Self::Choice(e, es, d, _) => {
                1 + e
                    .height()
                    .max(es.iter().map(|(_, e)| e.height()).max().unwrap_or(0))
                    .max(d.as_ref().map(|d| d.height()).unwrap_or(0))
            }
            Self::Intrinsic(_, es, _) => 1 + es.iter().map(|e| e.height()).max().unwrap_or(0),
            Self::Load(e, _, _) => 1 + e.height(),
            Self::Val(_, _) => 1,
            Self::Var(_) => 1,
        }
    }

    pub fn size(&self) -> usize {
        let mut q = vec![self];
        let mut n = 0;
        while let Some(e) = q.pop() {
            n += 1;
            match e {
                Self::UnRel(_, e) => q.push(e),
                Self::BinRel(_, l, r) => {
                    q.push(l);
                    q.push(r)
                }
                Self::UnOp(_, e) => q.push(e),
                Self::BinOp(_, l, r) => {
                    q.push(l);
                    q.push(r)
                }
                Self::Cast(e, _) => q.push(e),
                Self::Extract(e, _, _) => q.push(e),
                Self::ExtractHigh(e, _) | Self::ExtractLow(e, _) => q.push(e),
                Self::Concat(l, r) => {
                    q.push(l);
                    q.push(r)
                }
                Self::IfElse(c, t, f) => {
                    q.push(c);
                    q.push(t);
                    q.push(f)
                }
                Self::Choice(e, es, d, _) => {
                    q.push(e);
                    q.extend(es.iter().map(|(_, e)| &**e));
                    if let Some(ref d) = d {
                        q.push(d)
                    }
                }
                Self::Intrinsic(_, es, _) => q.extend(es.iter().map(|e| &**e)),
                Self::Load(e, _, _) => q.push(e),
                _ => (),
            }
        }
        n
    }
}

#[cfg(test)]
mod test {
    use fugue::bytes::{BE, LE};
    use fugue::ir::AddressSpace;

    use super::*;

    #[test]
    fn test_canon() {
        let spc = AddressSpace::unique("uniq", 0, None);

        let x = Expr::int_add(
            Expr::int_add(
                Expr::val(10u64),
                Expr::int_mul(
                    Expr::int_add(Expr::val(99u32), Expr::val(1u32)),
                    Expr::var(Var::new(&spc, 0, 32, 0)),
                ),
            ),
            Expr::int_add(
                Expr::concat(
                    Expr::int_mul(Expr::var(Var::new(&spc, 4, 32, 0)), Expr::val(0u32)),
                    Expr::val(44u32),
                ),
                Expr::cast_unsigned(Expr::val(32u32), 64),
            ),
        )
        .canonical();

        let y = Expr::int_add(
            Expr::val(10u32),
            Expr::int_add(
                Expr::val(99u32),
                Expr::int_add(Expr::val(44u32), Expr::val(32u32)),
            ),
        )
        .canonical();

        assert_eq!(
            x,
            Expr::int_add(
                Expr::cast_unsigned(
                    Expr::int_mul(Expr::var(Var::new(&spc, 0, 32, 0)), Expr::val(100u32)),
                    64
                ),
                Expr::val(86u64),
            ),
        );
        assert_eq!(y, Expr::val(185u32),);

        let t = Expr::int_add(Expr::val(10), Expr::var(Var::new0(&spc, 0, 32)));
        let z = Expr::concat_with::<BE, _, _>(
            Expr::extract(t.clone(), 0, 16),
            Expr::concat_with::<BE, _, _>(
                Expr::extract(t.clone(), 16, 24),
                Expr::extract(t.clone(), 24, 32),
            ),
        );

        assert_eq!(t.canonical(), z.canonical());

        let z = Expr::concat_with::<LE, _, _>(
            Expr::extract(t.clone(), 24, 32),
            Expr::concat_with::<LE, _, _>(
                Expr::extract(t.clone(), 16, 24),
                Expr::extract(t.clone(), 0, 16),
            ),
        );

        assert_eq!(t.canonical(), z.canonical());
    }
}
