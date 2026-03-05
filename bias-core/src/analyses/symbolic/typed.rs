use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::btree_map::Entry as BEntry;
use std::collections::hash_map::Entry as HEntry;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::mem;
use std::ops::{Add, BitAnd, BitOr, BitXor, Deref, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};

use itertools::Itertools;
use petgraph::visit::{EdgeRef, IntoEdgesDirected, VisitMap, Visitable};
use petgraph::EdgeDirection;
use smallvec::{smallvec, SmallVec};

use crate::analyses::paths::path::{CodePath, CodePathBlockRef};
use crate::ir::types::FunctionArg;
use crate::ir::{BinOp, BranchTarget, UnOp};
use crate::prelude::*;

pub const ALIAS_CONTEXT_LIMIT: usize = 3;
pub const ALIAS_FUNCTION_CONTEXT_LIMIT: usize = 300;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum Clobber {
    None,
    Direct,
    Pointee,
}

impl Clobber {
    #[inline]
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    #[inline]
    pub fn is_pointee(&self) -> bool {
        matches!(self, Self::Pointee)
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct NamedValue {
    name: Ustr,
    source: Location,
}

impl Display for NamedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.name, self.source)
    }
}

impl NamedValue {
    pub fn new(name: impl Into<Ustr>, source: impl Into<Location>) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
        }
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn source(&self) -> Location {
        self.source
    }
}

pub trait AliasVisitor<'a, 'b, T>
where
    T: ContextualTypeResolver<'a>,
{
    fn visit_aliases_pre(
        &mut self,
        insn: &Term<Insn>,
        position: usize,
        stmt: &Term<Stmt>,
        state: &TypedAliasVisitor<'a, 'b, T>,
    );

    fn visit_aliases_post(
        &mut self,
        insn: &Term<Insn>,
        position: usize,
        stmt: &Term<Stmt>,
        state: &TypedAliasVisitor<'a, 'b, T>,
    );
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum AliasValue {
    Top,
    V(BitVec),
    N(NamedValue),
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
                //if v.msb() {
                //    write!(f, "-{:x}", -v.clone().signed())
                //} else {
                write!(f, "{:x}", v)
                //}
            }
            Self::N(n) => n.fmt(f),
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
            Self::V(v) => v.to_address(),
            Self::G(v, off) if off.is_zero() => v.to_address(),
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

    pub fn is_ptr(&self) -> bool {
        matches!(self, Self::G(_, _))
    }

    pub fn is_sym(&self) -> bool {
        matches!(self, Self::N(_))
    }

    pub fn is_sym_ptr(&self) -> bool {
        let mut ptr = self;
        loop {
            let Self::G(base, _) = ptr else {
                return false;
            };

            if base.is_sym() {
                return true;
            }

            ptr = base;
        }
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

    pub fn sym(named: impl Into<NamedValue>) -> Self {
        Self::N(named.into())
    }

    pub fn val(value: impl Into<BitVec>) -> Self {
        Self::V(value.into())
    }

    pub fn symbol(&self) -> Option<&NamedValue> {
        if let Self::N(ref named) = self {
            Some(named)
        } else {
            None
        }
    }

    pub fn value(&self) -> Option<&BitVec> {
        if let Self::V(ref v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn stack_delta(&self) -> Option<i64> {
        match self {
            Self::S(off) => off.signed_cast(64).to_i64(),
            _ => None,
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
                let v1_bits = v1.nbits();
                let v2_bits = v2.nbits();

                if v1_bits < v2_bits {
                    if v2.unsigned_cast(v1_bits as _) == *v1 {
                        return;
                    }
                    *self = Self::Top;
                } else if v1_bits > v2_bits {
                    if v1.unsigned_cast(v2_bits as _) == v2 {
                        *self = Self::V(v2);
                        return;
                    }
                    *self = Self::Top;
                } else if *v1 != v2 {
                    *self = Self::Top;
                }
            }
            (Self::N(n1), Self::N(n2)) => {
                if *n1 != n2 {
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
            Self::S(bv) => {
                let bits = bv.bits();
                Self::S(bv + BitVec::from_usize(offset, bits))
            }
            Self::G(_, _) if offset == 0 => self,
            Self::N(_) if offset == 0 => self,
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
            _ if offset == 0 => *val = Some(self),
            _ => *val = Some(Self::Top),
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum AliasType {
    Top,
    T(Term<Type>),
    Bot,
}

impl Default for AliasType {
    fn default() -> Self {
        Self::Bot
    }
}

impl Display for AliasType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bot => write!(f, "?"),
            Self::T(t) => write!(f, "{t}"),
        }
    }
}

impl AliasType {
    pub fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    pub fn is_bot(&self) -> bool {
        matches!(self, Self::Bot)
    }

    pub fn is_unk(&self) -> bool {
        matches!(self, Self::Top | Self::Bot)
    }

    pub fn type_value(&self) -> Option<&Term<Type>> {
        if let Self::T(t) = self {
            Some(t)
        } else {
            None
        }
    }

    pub fn typed(t: impl Into<Term<Type>>) -> Self {
        Self::T(t.into())
    }

    pub fn void_ptr(bits: u32) -> Self {
        Self::typed(Type::pointer(Type::void(), bits))
    }

    pub fn unsigned(bits: u32) -> Self {
        Self::typed(Type::unsigned(bits))
    }

    pub fn bool() -> Self {
        Self::typed(Type::bool())
    }

    pub fn from_val(val: &BitVec) -> Self {
        Self::typed(if val.is_signed() {
            Type::signed(val.nbits())
        } else {
            Type::unsigned(val.nbits())
        })
    }

    pub fn into_bits(self) -> Self {
        Self::lift1(self, |t| {
            if t.is_signed() {
                Type::signed(t.nbits())
            } else {
                Type::unsigned(t.nbits())
            }
        })
    }

    pub fn into_bits2(self, other: Self) -> Self {
        Self::lift2(self, other, |t1, t2| {
            if t1.is_signed() && t2.is_signed() {
                Type::signed(t1.nbits())
            } else {
                Type::unsigned(t2.nbits())
            }
        })
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
            (Self::T(v1), Self::T(v2)) => {
                if *v1 != v2 {
                    if v1.nbits() == v2.nbits() {
                        *self = Self::typed(Type::unsigned(v1.nbits()));
                    } else {
                        *self = Self::Top;
                    }
                }
            }
        }
    }

    #[inline(always)]
    fn lift1(t: Self, f: impl Fn(Term<Type>) -> Term<Type>) -> Self {
        if let Self::T(v) = t {
            Self::T(f(v))
        } else if t.is_bot() {
            Self::Bot
        } else {
            Self::Top
        }
    }

    #[inline(always)]
    fn lift2_t(
        mut t1: Term<Type>,
        mut t2: Term<Type>,
        f: impl Fn(Term<Type>, Term<Type>) -> Term<Type>,
    ) -> Term<Type> {
        let lbits = t1.nbits();
        let rbits = t2.nbits();

        if lbits != rbits {
            if lbits > rbits {
                t2 = Type::unsigned(lbits)
            } else {
                t1 = Type::unsigned(rbits)
            }
        }

        f(t1, t2)
    }

    #[inline]
    fn lift2(t1: Self, t2: Self, f: impl Fn(Term<Type>, Term<Type>) -> Term<Type>) -> Self {
        match (t1, t2) {
            (Self::T(l), Self::T(r)) => Self::T(Self::lift2_t(l, r, f)),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bot, _) | (_, Self::Bot) => Self::Bot,
        }
    }

    #[inline]
    pub fn extract(self, offset: usize, bytes: usize) -> Self {
        match self {
            Self::T(ref t) => {
                let vbytes = t.nbytes();
                let nbytes = offset + bytes;

                if nbytes > vbytes {
                    return Self::Top;
                }

                if offset == 0 && bytes == vbytes {
                    self
                } else {
                    Self::T(Type::unsigned(bytes as u32 * 8))
                }
            }
            Self::Bot => Self::Bot,
            _ => Self::Top,
        }
    }

    #[inline]
    pub fn blit_into(self, offset: usize, bytes: usize, val: &mut Option<Self>) {
        match self {
            Self::T(t) => match val {
                None => {
                    if offset == 0 && t.nbytes() == bytes {
                        *val = Some(Self::typed(t));
                    } else {
                        *val = Some(Self::T(Type::unsigned(bytes as u32 * 8)));
                    }
                }
                Some(Self::T(old)) => {
                    if offset == 0 && t.nbytes() == bytes {
                        *old = t;
                    } else {
                        *old = Type::unsigned(bytes as u32 * 8);
                    }
                }
                Some(ref mut old) => {
                    if offset == 0 && t.nbytes() == bytes {
                        *old = Self::T(t);
                    } else {
                        // *old = Self::T(Type::unsigned(bytes as u32 * 8));
                        *old = Self::Top;
                    }
                }
            },
            _ if offset == 0 => {
                *val = Some(self);
            }
            _ => *val = Some(Self::Top),
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum OriginVar {
    G(Address),
    S(i64),
    R(u64, u32),
    N(NamedValue),
}

impl From<Address> for OriginVar {
    fn from(value: Address) -> Self {
        Self::G(value)
    }
}

impl From<i64> for OriginVar {
    fn from(value: i64) -> Self {
        Self::S(value)
    }
}

impl From<&'_ Var> for OriginVar {
    fn from(value: &Var) -> Self {
        Self::R(value.offset(), value.nbits())
    }
}

impl From<&'_ NamedValue> for OriginVar {
    fn from(value: &NamedValue) -> Self {
        Self::N(value.clone())
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AliasOrigin {
    location: Location,
    varid: Option<OriginVar>,
    index: i64,
}

impl AliasOrigin {
    pub fn new(location: impl Into<Location>) -> Self {
        Self::new_with(location, 0)
    }

    pub fn new_with(location: impl Into<Location>, index: i64) -> Self {
        Self {
            location: location.into(),
            varid: None,
            index,
        }
    }

    pub fn new_for(location: impl Into<Location>, var: impl Into<OriginVar>, index: i64) -> Self {
        Self {
            location: location.into(),
            varid: Some(var.into()),
            index,
        }
    }

    pub fn new_before(location: impl Into<Location>, index: usize) -> Self {
        Self {
            location: location.into(),
            varid: None,
            index: -(index as i64) - 1,
        }
    }

    pub fn new_before_for(
        location: impl Into<Location>,
        var: impl Into<OriginVar>,
        index: usize,
    ) -> Self {
        Self {
            location: location.into(),
            varid: Some(var.into()),
            index: -(index as i64) - 1,
        }
    }

    pub fn with_var(&self, var: impl Into<OriginVar>) -> Self {
        Self {
            varid: Some(var.into()),
            ..self.clone()
        }
    }

    pub fn with_index(&self, index: i64) -> Self {
        Self {
            index,
            ..self.clone()
        }
    }

    pub fn location(&self) -> Location {
        self.location
    }

    pub fn index(&self) -> i64 {
        self.index
    }

    pub fn join(&mut self, other: Self, at: impl Into<Location>) {
        if *self != other {
            *self = Self::new(at)
        }
    }

    pub fn join_phi(&mut self, other: Self, at: impl Into<Location>, var: impl Into<OriginVar>) {
        if *self != other {
            *self = Self::new_for(at, var, -1)
        }
    }
}

impl Display for AliasOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}<{}>", self.location, self.index)
    }
}

impl From<Location> for AliasOrigin {
    fn from(value: Location) -> Self {
        Self::new(value)
    }
}

impl From<Address> for AliasOrigin {
    fn from(value: Address) -> Self {
        Self::from(Location::from(value))
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct TypedAliasValue {
    pub v: AliasValue,
    pub t: AliasType,
    pub o: AliasOrigin,
}

trait TypedAliasResolve<'a, T: ContextualTypeResolver<'a>> {
    fn resolve_named(self, ctx: &TypedAliasVisitor<'a, '_, T>) -> Self;
}

impl<'a, T> TypedAliasResolve<'a, T> for TypedAliasValue
where
    T: ContextualTypeResolver<'a>,
{
    fn resolve_named(self, ctx: &TypedAliasVisitor<'a, '_, T>) -> Self {
        ctx.resolve_named(self)
    }
}

impl TypedAliasValue {
    pub fn new(
        v: impl Into<AliasValue>,
        t: impl Into<AliasType>,
        o: impl Into<AliasOrigin>,
    ) -> Self {
        Self {
            v: v.into(),
            t: t.into(),
            o: o.into(),
        }
    }

    pub fn sym(named: impl Into<NamedValue>, origin: impl Into<AliasOrigin>) -> Self {
        Self::new(AliasValue::sym(named), AliasType::Bot, origin)
    }

    pub fn val(v: impl Into<BitVec>, origin: impl Into<AliasOrigin>) -> Self {
        Self::new(AliasValue::val(v), AliasType::Bot, origin)
    }

    pub fn typed_bot(t: impl Into<Term<Type>>, origin: impl Into<AliasOrigin>) -> Self {
        Self::new(AliasValue::Bot, AliasType::typed(t), origin)
    }

    pub fn typed_top(t: impl Into<Term<Type>>, origin: impl Into<AliasOrigin>) -> Self {
        Self::new(AliasValue::Top, AliasType::typed(t), origin)
    }

    pub fn top(origin: impl Into<AliasOrigin>) -> Self {
        Self::new(AliasValue::Top, AliasType::Top, origin)
    }

    pub fn bot(origin: impl Into<AliasOrigin>) -> Self {
        Self::new(AliasValue::Bot, AliasType::Bot, origin)
    }
}

#[derive(Clone)]
pub struct AliasTypingContext<'a> {
    pub registers: AHashMap<Var, TypedAliasValue>,
    pub stack_variables: BTreeMap<i64, TypedAliasValue>,
    pub global_variables: BTreeMap<Address, TypedAliasValue>,
    pub symbol_variables: AHashMap<NamedValue, TypedAliasValue>,
    pub pre_call_state: Option<CallSiteContext>,
    pub functions: &'a FunctionTable,
    pub function_summaries: &'a FunctionSummaryTable,
    pub function_killed: Cow<'a, [Operand]>,
    pub injections: &'a InjectionManager,
    pub lifter: &'a Lifter,
    pub memory: &'a Memory,
    pub typedb: &'a TypeDB,
    pub stack_pointer: Var,
    pub location: Location,
}

impl<'a> AliasTypingContext<'a> {
    pub fn new(project: &'a Project) -> Self {
        Self::new_with(project, project.type_db())
    }

    pub fn new_with(project: &'a Project, typedb: &'a TypeDB) -> Self {
        let functions = project.functions();
        let function_summaries = project.function_summaries();
        let injections = project.injections();
        let lifter = project.lifter();
        let memory = project.memory();
        let stack_pointer = lifter.stack_pointer();

        Self {
            registers: Default::default(),
            stack_variables: Default::default(),
            global_variables: Default::default(),
            symbol_variables: Default::default(),
            pre_call_state: Default::default(),
            functions,
            function_summaries,
            function_killed: Default::default(),
            injections,
            lifter,
            memory,
            typedb,
            stack_pointer,
            location: Location::default(),
        }
    }

    pub fn address_bits(&self) -> u32 {
        self.lifter.address_bits()
    }

    pub fn address_bytes(&self) -> usize {
        self.lifter.address_bytes()
    }

    pub fn sync_pre_call_state(&mut self) {
        self.pre_call_state = Some(CallSiteContext {
            rmapping: self.registers.clone(),
            smapping: self.stack_variables.clone(),
            nmapping: self.symbol_variables.clone(),
            gmapping: self.global_variables.clone(),
        });
    }

    pub fn clear_pre_call_state(&mut self) {
        self.pre_call_state = None;
    }

    pub fn pre_call_state(&self) -> Option<&CallSiteContext> {
        self.pre_call_state.as_ref()
    }

    pub fn pre_call_state_mut(&mut self) -> Option<&mut CallSiteContext> {
        self.pre_call_state.as_mut()
    }

    pub fn set_default_killed(&mut self, addr: impl Into<Address>) {
        let Some(fid) = self.functions.get_point(&addr.into()).map(Function::id) else {
            return;
        };

        let Some(summary) = self.function_summaries.get_for_function(fid) else {
            return;
        };

        self.function_killed = Cow::Borrowed(summary.definitely_killed());
    }

    pub fn clear_killed(&mut self) {
        self.function_killed = Cow::Borrowed(Default::default());
    }

    pub fn compute_incoming_map_with<T>(
        &mut self,
        function: &'a Function,
        entry: bool,
        resolver: &T,
    ) where
        T: ContextualTypeResolver<'a>,
    {
        if entry {
            self.location = Location::from(function.address());

            self.apply_injections(function);

            resolver.resolve_entry_type(self, function)
        } else {
            self.registers.clear();
            self.stack_variables.clear();
            self.global_variables.clear();
            self.symbol_variables.clear();
        }
    }

    fn apply_injections(&mut self, function: &Function) {
        for (opnd, val) in self
            .injections
            .global_values()
            .chain(self.injections.function_values(function.id()))
        {
            match opnd {
                InjectionOperand::Global(addr) => {
                    let value = TypedAliasValue::val(
                        val.to_owned(),
                        AliasOrigin::new_before(self.location, 0),
                    );
                    self.global_variables.insert(*addr, value);
                }
                InjectionOperand::Register(var) => {
                    let pvar = self.lifter.register_map().parent(var).unwrap_or(*var);
                    let pval = (pvar != *var)
                        .then(|| {
                            let mut val = val.unsigned_cast(pvar.nbits() as _);
                            let voff = (var.offset() - pvar.offset()) as u32 * 8;
                            if voff != 0 {
                                val <<= voff;
                            }
                            val
                        })
                        .unwrap_or_else(|| val.to_owned());
                    let value =
                        TypedAliasValue::val(pval, AliasOrigin::new_before(self.location, 0));
                    self.registers.insert(pvar, value);
                }
            }
        }
    }

    pub fn constants(&self) -> Vec<(i64, Vec<u8>)> {
        let mut regions = Vec::<(i64, Vec<u8>)>::new();

        for (off, val) in self.stack_variables.iter().filter_map(|(off, vt)| {
            if let Some(val) = vt.v.value() {
                Some((off, val))
            } else {
                None
            }
        }) {
            if let Some((last_off, last_buf)) = regions.last_mut() {
                let last_len = last_buf.len();
                if *last_off + last_len as i64 == *off {
                    last_buf.extend(std::iter::repeat(0u8).take(val.bits() / 8));
                    if self.lifter.endian().is_big() {
                        val.to_be_bytes(&mut last_buf[last_len..]);
                    } else {
                        val.to_le_bytes(&mut last_buf[last_len..]);
                    }

                    continue;
                }
            }

            let mut buf = vec![0u8; val.bits() / 8];
            if self.lifter.endian().is_big() {
                val.to_be_bytes(&mut buf);
            } else {
                val.to_le_bytes(&mut buf);
            }
            regions.push((*off, buf));
        }

        regions
    }

    pub fn clobber_aliases(&mut self, r: AliasValue, t: AliasType) {
        if let Some(delta) = r.stack_delta() {
            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.stack_variables.get_mut(&delta) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        vt.v = AliasValue::Top;
                        vt.t = AliasType::typed(pointee.clone());
                        vt.o = AliasOrigin::new(self.location);
                    }
                } else {
                    self.stack_variables.insert(
                        delta,
                        TypedAliasValue::typed_top(pointee.clone(), self.location),
                    );
                }
            }
        } else if let Some(address) = r.value().to_address() {
            if !self.memory.contains(address) {
                return;
            }

            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.global_variables.get_mut(&address) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        vt.v = AliasValue::Top;
                        vt.t = AliasType::typed(pointee.clone());
                        vt.o = AliasOrigin::new(self.location);
                    }
                } else {
                    self.global_variables.insert(
                        address,
                        TypedAliasValue::typed_top(pointee.clone(), self.location),
                    );
                }
            }
        }
    }

    pub fn update_aliases_by_origin(
        &mut self,
        v: AliasValue,
        t: AliasType,
        o: AliasOrigin,
        clobber: bool,
    ) {
        for vt in self.registers.values_mut().filter(|vt| vt.o == o) {
            vt.v = v.clone();
            vt.t = t.clone();
        }

        for vt in self.stack_variables.values_mut().filter(|vt| vt.o == o) {
            vt.v = v.clone();
            vt.t = t.clone();
        }

        for vt in self.global_variables.values_mut().filter(|vt| vt.o == o) {
            vt.v = v.clone();
            vt.t = t.clone();
        }

        for vt in self.symbol_variables.values_mut().filter(|vt| vt.o == o) {
            vt.v = v.clone();
            vt.t = t.clone();
        }

        if let Some(delta) = v.stack_delta() {
            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.stack_variables.get_mut(&delta) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        if clobber {
                            vt.v = AliasValue::Top;
                        }
                        vt.t = AliasType::typed(pointee.clone());
                    }
                } else {
                    self.stack_variables.insert(
                        delta,
                        TypedAliasValue::typed_top(pointee.clone(), self.location),
                    );
                }
            }
        } else if let Some(address) = v.value().to_address() {
            if !self.memory.contains(address) {
                return;
            }

            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.global_variables.get_mut(&address) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        if clobber {
                            vt.v = AliasValue::Top;
                        }
                        vt.t = AliasType::typed(pointee.clone());
                    }
                } else {
                    self.global_variables.insert(
                        address,
                        TypedAliasValue::typed_top(pointee.clone(), self.location),
                    );
                }
            }
        }
    }

    pub fn update_aliases(&mut self, r: AliasValue, t: AliasType, clobber: bool) {
        for vt in self.registers.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        for vt in self.stack_variables.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        for vt in self.global_variables.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        for vt in self.symbol_variables.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        if let Some(delta) = r.stack_delta() {
            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.stack_variables.get_mut(&delta) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        if clobber {
                            vt.v = AliasValue::Top;
                        }
                        vt.t = AliasType::typed(pointee.clone());
                    }
                } else {
                    self.stack_variables.insert(
                        delta,
                        TypedAliasValue::typed_top(pointee.clone(), self.location),
                    );
                }
            }
        } else if let Some(address) = r.value().to_address() {
            if !self.memory.contains(address) {
                return;
            }

            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.global_variables.get_mut(&address) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        if clobber {
                            vt.v = AliasValue::Top;
                        }
                        vt.t = AliasType::typed(pointee.clone());
                    }
                } else {
                    self.global_variables.insert(
                        address,
                        TypedAliasValue::typed_top(pointee.clone(), self.location),
                    );
                }
            }
        }
    }

    #[inline]
    pub fn update_output(&mut self, index: usize, v: TypedAliasValue) -> bool {
        match self.lifter.default_prototype().output_operand(index) {
            Some(Operand::Register(r)) => {
                self.registers.insert(r, v);
                true
            }
            Some(Operand::Stack(d, _)) => {
                let Some(shift) = self
                    .registers
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())
                else {
                    return false;
                };
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.lifter.default_prototype().extra_pop() as i64);

                self.stack_variables.insert(delta, v);
                true
            }
            _ => false,
        }
    }

    #[inline]
    pub fn update_input(&mut self, index: usize, v: TypedAliasValue) -> bool {
        match self.lifter.default_prototype().input_operand(index) {
            Some(Operand::Register(r)) => {
                self.registers.insert(r, v);
                true
            }
            Some(Operand::Stack(d, _)) => {
                let Some(shift) = self
                    .registers
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())
                else {
                    return false;
                };
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.lifter.default_prototype().extra_pop() as i64);

                self.stack_variables.insert(delta, v);
                true
            }
            _ => false,
        }
    }

    pub fn input_origin(&self, index: usize) -> Option<AliasOrigin> {
        match self.lifter.default_prototype().input_operand(index)? {
            Operand::Register(r) => Some(AliasOrigin::new_before_for(self.location, &r, index + 1)),
            Operand::Stack(d, _) => {
                let shift = self
                    .registers
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.lifter.default_prototype().extra_pop() as i64);
                Some(AliasOrigin::new_before_for(self.location, delta, index + 1))
            }
            _ => None,
        }
    }

    pub fn output_origin(&self, index: usize) -> Option<AliasOrigin> {
        if index != 0 {
            return None;
        }

        match self.lifter.default_prototype().output_operand(index)? {
            Operand::Register(r) => Some(AliasOrigin::new_before_for(self.location, &r, index)),
            Operand::Stack(d, _) => {
                let shift = self
                    .registers
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.lifter.default_prototype().extra_pop() as i64);
                Some(AliasOrigin::new_before_for(self.location, delta, index))
            }
            _ => None,
        }
    }

    #[inline]
    pub fn input_operand(&self, index: usize) -> Option<&TypedAliasValue> {
        match self.lifter.default_prototype().input_operand(index)? {
            Operand::Register(r) => self.registers.get(&r),
            Operand::Stack(d, _) => {
                let shift = self
                    .registers
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.lifter.default_prototype().extra_pop() as i64);

                self.stack_variables.get(&delta)
            }
            _ => None,
        }
    }

    #[inline]
    pub fn input_operand_value(&self, index: usize) -> Option<&AliasValue> {
        self.input_operand(index).map(|vt| &vt.v)
    }

    #[inline]
    pub fn input_operand_type(&self, index: usize) -> Option<&AliasType> {
        self.input_operand(index).map(|vt| &vt.t)
    }

    #[inline]
    pub fn output_operand(&self, index: usize) -> Option<&TypedAliasValue> {
        match self.lifter.default_prototype().output_operand(index)? {
            Operand::Register(r) => self.registers.get(&r),
            Operand::Stack(d, _) => {
                let shift = self
                    .registers
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.lifter.default_prototype().extra_pop() as i64);

                self.stack_variables.get(&delta)
            }
            _ => None,
        }
    }

    #[inline]
    pub fn output_operand_value(&self, index: usize) -> Option<&AliasValue> {
        self.output_operand(index).map(|vt| &vt.v)
    }

    #[inline]
    pub fn output_operand_type(&self, index: usize) -> Option<&AliasType> {
        self.output_operand(index).map(|vt| &vt.t)
    }

    pub fn update_named(
        &mut self,
        named: impl Into<NamedValue>,
        value: impl Into<TypedAliasValue>,
    ) {
        self.symbol_variables.insert(named.into(), value.into());
    }

    pub fn update_named_with_input(&mut self, named: impl Into<NamedValue>, index: usize) -> bool {
        let Some(value) = self.input_operand(index).cloned() else {
            return false;
        };
        self.update_named(named, value);
        true
    }

    pub fn update_named_with_output(&mut self, named: impl Into<NamedValue>, index: usize) -> bool {
        let Some(value) = self.output_operand(index).cloned() else {
            return false;
        };
        self.update_named(named, value);
        true
    }

    pub fn with_bytes<U, F>(&self, from: &AliasValue, mut f: F) -> Option<U>
    where
        F: FnMut(&[u8]) -> U,
    {
        match from {
            AliasValue::V(bv) => {
                if let Some(addr) = bv.to_address() {
                    let bytes = self.memory.view_bytes_from(addr).ok()?;
                    Some(f(bytes))
                } else {
                    None
                }
            }
            AliasValue::S(d) => {
                if let Some(d) = d.signed_cast(64).to_i64() {
                    let constants = self.constants();
                    let i = constants
                        .binary_search_by(|(s, b)| {
                            if d < *s {
                                Ordering::Less
                            } else if ((d - s) as usize) < b.len() {
                                Ordering::Equal
                            } else {
                                Ordering::Greater
                            }
                        })
                        .ok()?;

                    let (start, bytes) = &constants[i];
                    let offset = (d - start) as usize;

                    Some(f(&bytes[offset..]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CallSiteContext {
    rmapping: AHashMap<Var, TypedAliasValue>,
    smapping: BTreeMap<i64, TypedAliasValue>,
    nmapping: AHashMap<NamedValue, TypedAliasValue>,
    gmapping: BTreeMap<Address, TypedAliasValue>,
}

impl CallSiteContext {
    pub fn registers(&self) -> &AHashMap<Var, TypedAliasValue> {
        &self.rmapping
    }

    pub fn globals(&self) -> &BTreeMap<Address, TypedAliasValue> {
        &self.gmapping
    }

    pub fn stack_variables(&self) -> &BTreeMap<i64, TypedAliasValue> {
        &self.smapping
    }

    pub fn symbols(&self) -> &AHashMap<NamedValue, TypedAliasValue> {
        &self.nmapping
    }

    pub fn register_values(&self) -> impl Iterator<Item = (&Var, &AliasValue, &AliasType)> {
        self.rmapping.iter().filter_map(
            |(var, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((var, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn global_values(&self) -> impl Iterator<Item = (Address, &AliasValue, &AliasType)> {
        self.gmapping.iter().filter_map(
            |(&off, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((off, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn stack_values(&self) -> impl Iterator<Item = (i64, &AliasValue, &AliasType)> {
        self.smapping.iter().filter_map(
            |(&off, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((off, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn symbol_values(&self) -> impl Iterator<Item = (&NamedValue, &AliasValue, &AliasType)> {
        self.nmapping.iter().filter_map(
            |(sym, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((sym, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn display_with<'a>(&'a self, project: &'a Project) -> CallSiteContextDisplay<'a> {
        CallSiteContextDisplay {
            aliases: self,
            project,
        }
    }
}

pub type CallSiteContexts = Vec<TypedBlockAliases>;
pub type CallSiteContextsRef<'a> = &'a CallSiteContexts;
pub type IncomingContexts = AHashMap<Address, Vec<TypedBlockAliases>>;
pub type IncomingContextsRef<'a> = &'a IncomingContexts;

pub const DEFAULT_TYPE_RESOLVER: DefaultTypeResolver = ();
pub type DefaultTypeResolver = ();

pub trait IntraContextualTypeResolver {
    type Resolver<'a>: ContextualTypeResolver<'a>;

    fn resolve_with<'a>(project: &'a Project) -> Self::Resolver<'a> {
        let mut context = AnalysisContext::default();
        Self::resolve_with_context(project, &mut context)
    }

    fn resolve_with_context<'a, 'c: 'a>(
        project: &'a Project,
        context: &mut AnalysisContext<'c>,
    ) -> Self::Resolver<'a>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedType {
    Clobber(Term<Type>),
    Preserve(Term<Type>),
}

impl Deref for ResolvedType {
    type Target = Term<Type>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Clobber(t) | Self::Preserve(t) => t,
        }
    }
}

impl From<Term<Type>> for ResolvedType {
    fn from(t: Term<Type>) -> Self {
        Self::Clobber(t)
    }
}

impl ResolvedType {
    pub fn clobber(t: impl Into<Term<Type>>) -> Self {
        Self::Clobber(t.into())
    }

    pub fn preserve(t: impl Into<Term<Type>>) -> Self {
        Self::Preserve(t.into())
    }

    pub fn update(&mut self, t: impl Into<Term<Type>>) -> Term<Type> {
        match self {
            Self::Clobber(ref mut ot) | Self::Preserve(ref mut ot) => {
                std::mem::replace(ot, t.into())
            }
        }
    }

    pub fn into_clobber(self) -> Self {
        match self {
            Self::Preserve(t) => Self::Clobber(t),
            _ => self,
        }
    }

    pub fn into_preserve(self) -> Self {
        match self {
            Self::Clobber(t) => Self::Preserve(t),
            _ => self,
        }
    }

    pub fn clobber_kind(&self) -> Clobber {
        match self {
            Self::Clobber(_) => Clobber::Direct,
            Self::Preserve(_) => Clobber::None,
        }
    }
}

pub trait InterContextualTypeResolver {
    type Resolver<'a>: ContextualTypeResolver<'a>;

    fn resolve_with<'a>(
        project: &'a Project,
        contexts: CallSiteContextsRef<'a>,
        rcontexts: IncomingContextsRef<'a>,
    ) -> Self::Resolver<'a> {
        let mut context = AnalysisContext::default();
        Self::resolve_with_context(project, contexts, rcontexts, &mut context)
    }

    fn resolve_with_context<'a, 'c: 'a>(
        project: &'a Project,
        contexts: CallSiteContextsRef<'a>,
        rcontexts: IncomingContextsRef<'a>,
        context: &mut AnalysisContext<'c>,
    ) -> Self::Resolver<'a>;
}

pub trait ContextualTypeResolver<'a> {
    fn resolve_type_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        target: Option<Address>,
        t: &Term<Type>,
    ) -> Option<ResolvedType>;

    fn resolve_intrinsic_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        name: Ustr,
        arguments: Vec<TypedAliasValue>,
        bits: Option<u32>,
    ) -> Option<TypedAliasValue>;

    fn resolve_entry_type(&self, context: &mut AliasTypingContext<'a>, function: &'a Function);

    fn types(&self) -> Option<&'a TypeDB> {
        None
    }
}

impl IntraContextualTypeResolver for DefaultTypeResolver {
    type Resolver<'a> = DefaultTypeResolver;

    fn resolve_with_context<'a, 'c: 'a>(
        _project: &'a Project,
        _context: &mut AnalysisContext<'c>,
    ) -> Self::Resolver<'a> {
        ()
    }
}

impl InterContextualTypeResolver for DefaultTypeResolver {
    type Resolver<'a> = DefaultTypeResolver;

    fn resolve_with_context<'a, 'c: 'a>(
        _project: &'a Project,
        _contexts: CallSiteContextsRef<'a>,
        _rcontexts: IncomingContextsRef<'a>,
        _context: &mut AnalysisContext<'c>,
    ) -> Self::Resolver<'a> {
        ()
    }
}

impl<'a> ContextualTypeResolver<'a> for DefaultTypeResolver {
    fn resolve_type_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        _target: Option<Address>,
        t: &Term<Type>,
    ) -> Option<ResolvedType> {
        Some(ResolvedType::clobber(
            t.resolve(context.typedb).pointee()?.resolve(context.typedb),
        ))
    }

    fn resolve_intrinsic_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        _name: Ustr,
        _arguments: Vec<TypedAliasValue>,
        bits: Option<u32>,
    ) -> Option<TypedAliasValue> {
        if bits.is_some() {
            Some(TypedAliasValue::top(context.location))
        } else {
            None
        }
    }

    fn resolve_entry_type(&self, context: &mut AliasTypingContext<'a>, function: &'a Function) {
        // NOTE: we generate locations as:
        // - SP is output indexed at -1
        // - Each incoming argument is at -(arg + 1) - 1 (first argument at -2)

        let loc = Location::from(function.address());
        let stack_pointer = context.lifter.stack_pointer();
        let stack_default = TypedAliasValue::new(
            AliasValue::stack_var(context.lifter),
            AliasType::void_ptr(context.address_bits()),
            AliasOrigin::new_before_for(loc, &stack_pointer, 0),
        );

        context.registers.insert(stack_pointer, stack_default);

        // apply function type
        if let Some(args) = context
            .typedb
            .get_code_type_at(function.address())
            .as_ref()
            .and_then(|ft| ft.function_args())
        {
            let proto = context.lifter.default_prototype();

            for (i, t) in args.iter().enumerate() {
                match proto.input_operand(i) {
                    Some(Operand::Register(reg)) => {
                        context.registers.insert(
                            reg,
                            TypedAliasValue::typed_top(
                                t.type_().to_owned(),
                                AliasOrigin::new_before_for(loc, &reg, i + 1),
                            ),
                        );
                    }
                    Some(Operand::Stack(delta, _)) => {
                        context.stack_variables.insert(
                            delta,
                            TypedAliasValue::typed_top(
                                t.type_().to_owned(),
                                AliasOrigin::new_before_for(loc, delta, i + 1),
                            ),
                        );
                    }
                    _ => (),
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct TypedAliasVisitor<'a, 'b, T>
where
    T: ContextualTypeResolver<'a>,
{
    rmapping: AHashMap<Var, TypedAliasValue>,
    smapping: BTreeMap<i64, TypedAliasValue>,
    nmapping: AHashMap<NamedValue, TypedAliasValue>,
    gmapping: BTreeMap<Address, TypedAliasValue>,
    tmapping: AHashMap<Var, TypedAliasValue>,
    pre_call_state: Option<CallSiteContext>,
    call_target: Option<TypedAliasValue>,
    condition: Option<TypedAliasValue>,
    functions: &'a FunctionTable,
    function_summaries: &'a FunctionSummaryTable,
    injections: &'a InjectionManager,
    lifter: &'a Lifter,
    registers: &'a VarView,
    memory: &'a Memory,
    typedb: &'a TypeDB,
    type_resolver: &'b T,
    stack_pointer: Var,
    extra_pop: BitVec,
}

impl<'a, 'b> TypedAliasVisitor<'a, 'b, DefaultTypeResolver> {
    pub fn new(
        functions: &'a FunctionTable,
        function_summaries: &'a FunctionSummaryTable,
        injections: &'a InjectionManager,
        lifter: &'a Lifter,
        typedb: &'a TypeDB,
        memory: &'a Memory,
        rmapping: AHashMap<Var, TypedAliasValue>,
        smapping: BTreeMap<i64, TypedAliasValue>,
        nmapping: AHashMap<NamedValue, TypedAliasValue>,
        gmapping: BTreeMap<Address, TypedAliasValue>,
    ) -> Self {
        TypedAliasVisitor::new_with(
            functions,
            function_summaries,
            injections,
            lifter,
            typedb,
            memory,
            rmapping,
            smapping,
            nmapping,
            gmapping,
            &DEFAULT_TYPE_RESOLVER,
        )
    }
}

pub trait TypedAliasVisitable {
    fn visit_aliases_with<'a, 'b, T, V>(
        &self,
        driver: &mut TypedAliasVisitor<'a, 'b, T>,
        visitor: &mut V,
    ) where
        T: ContextualTypeResolver<'a>,
        V: AliasVisitor<'a, 'b, T>;
}

impl TypedAliasVisitable for Term<Insn> {
    fn visit_aliases_with<'a, 'b, T, V>(
        &self,
        driver: &mut TypedAliasVisitor<'a, 'b, T>,
        visitor: &mut V,
    ) where
        T: ContextualTypeResolver<'a>,
        V: AliasVisitor<'a, 'b, T>,
    {
        driver.visit_insn(self, visitor)
    }
}

impl TypedAliasVisitable for CodeBlock {
    fn visit_aliases_with<'a, 'b, T, V>(
        &self,
        driver: &mut TypedAliasVisitor<'a, 'b, T>,
        visitor: &mut V,
    ) where
        T: ContextualTypeResolver<'a>,
        V: AliasVisitor<'a, 'b, T>,
    {
        driver.visit_block(self, visitor)
    }
}

impl<'a, 'b, T> TypedAliasVisitor<'a, 'b, T>
where
    T: ContextualTypeResolver<'a>,
{
    pub fn new_with(
        functions: &'a FunctionTable,
        function_summaries: &'a FunctionSummaryTable,
        injections: &'a InjectionManager,
        lifter: &'a Lifter,
        typedb: &'a TypeDB,
        memory: &'a Memory,
        rmapping: AHashMap<Var, TypedAliasValue>,
        smapping: BTreeMap<i64, TypedAliasValue>,
        nmapping: AHashMap<NamedValue, TypedAliasValue>,
        gmapping: BTreeMap<Address, TypedAliasValue>,
        type_resolver: &'b T,
    ) -> Self {
        let stack_pointer = lifter.stack_pointer();
        Self {
            registers: &*lifter.register_map(),

            rmapping,
            smapping,
            gmapping,
            nmapping,
            tmapping: AHashMap::new(),
            pre_call_state: None,
            call_target: None,
            condition: None,

            functions,
            function_summaries,
            injections,
            lifter,
            typedb,
            memory,

            type_resolver,
            stack_pointer,
            extra_pop: BitVec::from_u64(
                lifter.default_prototype().extra_pop(),
                stack_pointer.nbits() as _,
            ),
        }
    }

    pub fn with_typing_context<U, F>(&mut self, location: Location, f: F) -> U
    where
        F: FnOnce(&mut AliasTypingContext<'a>, &T) -> U,
    {
        let mut context = AliasTypingContext {
            registers: std::mem::take(&mut self.rmapping),
            stack_variables: std::mem::take(&mut self.smapping),
            global_variables: std::mem::take(&mut self.gmapping),
            symbol_variables: std::mem::take(&mut self.nmapping),
            pre_call_state: std::mem::take(&mut self.pre_call_state),
            functions: self.functions,
            function_summaries: self.function_summaries,
            injections: self.injections,
            function_killed: Default::default(),
            lifter: self.lifter,
            memory: self.memory,
            typedb: self.typedb,
            stack_pointer: self.stack_pointer,
            location,
        };

        let r = f(&mut context, self.type_resolver);

        self.rmapping = context.registers;
        self.smapping = context.stack_variables;
        self.gmapping = context.global_variables;
        self.pre_call_state = context.pre_call_state;

        r
    }

    fn update_alias_types(&mut self, r: AliasValue, t: AliasType, o: impl Into<AliasOrigin>) {
        for vt in self.rmapping.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        for vt in self.smapping.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        for vt in self.gmapping.values_mut().filter(|vt| vt.v == r) {
            vt.t = t.clone();
        }

        let o = o.into();

        if let Some(delta) = r.stack_delta() {
            // TODO: A more complete implementation...
            //
            // In this case, we want the type to be a deref of whatever t is.
            //
            // However, what if the value stored is of a different size, say:
            //
            // *(sp-8) == 0x61626364 (uint32)
            //
            // The type of sp-8 will be ptr<uint32>, but if sp-8 is used as a
            // string (i.e., ptr<char>), we can't apply the type char to *(sp-8),
            // without splitting the value stored at sp-8 across (sp-8)+0,
            // (sp-8)+1, and so on...
            //
            // For the stack, if might make more sense to store everything as
            // byte values, thereby allowing this kind of splitting naturally.
            //
            // For example, on a constant store to the stack, we'd split the
            // value into bytes, and on a load of a constant from the stack,
            // we'd read out a BitVec.
            //

            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.smapping.get_mut(&delta) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        vt.t = AliasType::typed(pointee.clone());
                    }
                } else {
                    self.smapping
                        .insert(delta, TypedAliasValue::typed_top(pointee.clone(), o));
                }
            }
        } else if let Some(address) = r.value().to_address() {
            if !self.memory.contains(address) {
                return;
            }

            // TODO: actually check if this is an address
            if let Some(pointee) = t.type_value().and_then(|t| t.pointee()) {
                if let Some(vt) = self.gmapping.get_mut(&address) {
                    if matches!(vt.t.type_value(), Some(tt) if tt.nbits() == pointee.nbits())
                        || vt.t.is_unk()
                    {
                        vt.t = AliasType::typed(pointee.clone());
                    }
                } else {
                    self.gmapping
                        .insert(address, TypedAliasValue::typed_top(pointee.clone(), o));
                }
            }
        }
    }

    fn apply_operand_type(
        &mut self,
        operand: &PrototypeOperand,
        t: Term<Type>,
        clobber: Clobber,
        origin: impl Into<AliasOrigin>,
    ) {
        let origin = origin.into();
        match operand {
            PrototypeOperand::Register { varnode, .. } => {
                let var = Var::new0(
                    self.lifter.register_space(),
                    varnode.offset(),
                    varnode.size() as u32 * 8,
                );

                let pvar = self.registers.parent(&var).unwrap_or(var);
                let t = AliasType::typed(t);

                match self.rmapping.entry(pvar) {
                    HEntry::Vacant(entry) => {
                        let val = AliasValue::Bot;
                        let mut typ = None;
                        t.blit_into(
                            (var.offset() - pvar.offset()) as usize,
                            pvar.nbits() as usize / 8,
                            &mut typ,
                        );
                        entry.insert(TypedAliasValue::new(
                            val,
                            typ.unwrap(),
                            origin.with_var(&pvar),
                        ));
                    }
                    HEntry::Occupied(mut entry) => {
                        let vt = std::mem::take(entry.get_mut());
                        let mut typ = Some(vt.t);
                        t.blit_into(
                            (var.offset() - pvar.offset()) as usize,
                            pvar.nbits() as usize / 8,
                            &mut typ,
                        );

                        let typ = typ.unwrap();

                        if vt.v.is_ref() || vt.v.is_val() {
                            entry.insert(TypedAliasValue::new(
                                vt.v.clone(),
                                typ.clone(),
                                vt.o.clone(),
                            ));
                            self.update_alias_types(vt.v, typ, vt.o);
                        } else {
                            entry.insert(TypedAliasValue::new(vt.v, typ, vt.o));
                        }
                    }
                }

                if clobber.is_direct() {
                    let vt = self.rmapping.get_mut(&pvar).unwrap();
                    vt.v = AliasValue::Bot;
                    vt.o = origin.with_var(&pvar);
                } else if clobber.is_pointee() {
                    let vt = self.rmapping.get(&pvar).cloned().unwrap();
                    self.with_typing_context(origin.location(), |ctx, _| {
                        ctx.clobber_aliases(vt.v, vt.t)
                    });
                    /*
                    } else {
                        let vt = self.rmapping.get_mut(&pvar).unwrap();
                        vt.o = Some(loc);
                    */
                }
            }
            PrototypeOperand::StackRelative(offset) => {
                if let Some(stack_base) = self
                    .rmapping
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.value())
                {
                    let mut shifted = BitVec::from_u64(*offset, self.stack_pointer.nbits() as _);
                    shifted += stack_base;

                    if let Some(shift) = shifted.signed_cast(64).to_i64() {
                        let sz = t.nbytes();
                        let t = AliasType::typed(t);

                        match self.smapping.entry(shift) {
                            BEntry::Vacant(entry) => {
                                let val = AliasValue::Bot;
                                let mut typ = None;
                                t.blit_into(0, sz, &mut typ);
                                entry.insert(TypedAliasValue::new(
                                    val,
                                    typ.unwrap(),
                                    origin.with_var(shift),
                                ));
                            }
                            BEntry::Occupied(mut entry) => {
                                let vt = std::mem::take(entry.get_mut());
                                let mut typ = Some(vt.t);
                                t.blit_into(0, sz, &mut typ);

                                let typ = typ.unwrap();

                                if vt.v.is_ref() || vt.v.is_val() {
                                    entry.insert(TypedAliasValue::new(
                                        vt.v.clone(),
                                        typ.clone(),
                                        vt.o.clone(),
                                    ));
                                    self.update_alias_types(vt.v, typ, vt.o);
                                } else {
                                    entry.insert(TypedAliasValue::new(vt.v, typ, vt.o));
                                }
                            }
                        }

                        if clobber.is_direct() {
                            let vt = self.smapping.get_mut(&shift).unwrap();
                            vt.v = AliasValue::Bot;
                            vt.o = origin.with_var(shift);
                        } else if clobber.is_pointee() {
                            let vt = self.smapping.get(&shift).cloned().unwrap();
                            self.with_typing_context(origin.location(), |ctx, _| {
                                ctx.clobber_aliases(vt.v, vt.t)
                            });
                            /*
                            } else {
                                let vt = self.smapping.get_mut(&shift).unwrap();
                                vt.o = Some(loc);
                            */
                        }
                    }
                }
            }
            _ => (),
            /*
            PrototypeOperand::RegisterJoin {
                first_varnode,
                second_varnode,
                ..
            } => {
                // high
                let first = self.read_var(&Var::new(
                    self.registers().address_space_ref(),
                    first_varnode.offset(),
                    first_varnode.size() as u32 * 8,
                    0,
                ))?;
                // low
                let second = self.read_var(&Var::new(
                    self.registers().address_space_ref(),
                    second_varnode.offset(),
                    second_varnode.size() as u32 * 8,
                    0,
                ))?;

                let bits = first.bits() + second.bits();
                Ok(first.unsigned_cast(bits) << second.nbits() | second.unsigned_cast(bits))
            }
            */
        }
    }

    #[inline]
    fn resolve_named(&self, vt: TypedAliasValue) -> TypedAliasValue {
        let AliasValue::N(ref named) = vt.v else {
            return vt;
        };
        let Some(nvt) = self.nmapping.get(named).cloned() else {
            return vt;
        };
        nvt
    }

    #[inline]
    fn eval_expr(&mut self, loc: &Location, expr: &Term<Expr>) -> TypedAliasValue {
        match &**expr {
            Expr::Var(var) => {
                let rvar = self.registers.parent(var).unwrap_or(*var);

                if rvar.is_register() {
                    let vt =
                        self.rmapping
                            .get(&rvar)
                            .cloned()
                            .unwrap_or(TypedAliasValue::typed_bot(
                                Type::unsigned(rvar.nbits()),
                                *loc,
                            ));
                    if vt.v.is_ref() && rvar == *var {
                        vt
                    } else {
                        let shift = (var.offset() - rvar.offset()) as usize;
                        let bytes = var.nbits() as usize / 8;
                        TypedAliasValue::new(
                            vt.v.extract(shift, bytes),
                            vt.t.extract(shift, bytes),
                            vt.o,
                        )
                    }
                } else if rvar.is_temporary() {
                    let vt =
                        self.tmapping
                            .get(&rvar)
                            .cloned()
                            .unwrap_or(TypedAliasValue::typed_bot(
                                Type::unsigned(rvar.nbits()),
                                *loc,
                            ));
                    if vt.v.is_ref() && rvar == *var {
                        vt
                    } else {
                        let shift = (var.offset() - rvar.offset()) as usize;
                        let bytes = var.nbits() as usize / 8;
                        TypedAliasValue::new(
                            vt.v.extract(shift, bytes),
                            vt.t.extract(shift, bytes),
                            vt.o,
                        )
                    }
                } else if let Some(vt) = rvar
                    .address()
                    .and_then(|addr| self.gmapping.get(&addr).cloned())
                {
                    let bytes = rvar.nbits() as usize / 8;
                    TypedAliasValue::new(vt.v.extract(0, bytes), vt.t.extract(0, bytes), vt.o)
                } else {
                    let val = rvar
                        .address()
                        .map(|addr| {
                            AliasValue::ptr0(
                                BitVec::from_u64(addr.offset(), self.stack_pointer.nbits() as _),
                                BitVec::zero(self.stack_pointer.nbits() as _),
                            )
                        })
                        .unwrap_or(AliasValue::Top);

                    let bits = rvar.nbits();
                    let t = if let Some(vt) = rvar
                        .address()
                        .and_then(|addr| self.typedb.get_data_type_at(addr))
                    {
                        if vt.nbits() != bits {
                            AliasType::unsigned(bits)
                        } else {
                            AliasType::typed(vt)
                        }
                    } else {
                        AliasType::unsigned(bits)
                    };

                    TypedAliasValue::new(val, t, *loc)
                }
            }
            Expr::Val(rval, _) => TypedAliasValue::new(
                AliasValue::val(rval.to_owned()),
                AliasType::from_val(rval),
                *loc,
            ),
            Expr::UnOp(op, expr) => {
                let vt = self.eval_expr(loc, expr).resolve_named(self);
                let nval = match op {
                    UnOp::NEG => AliasValue::lift1_val(vt.v, BitVec::neg),
                    UnOp::NOT => {
                        if expr.is_bool() {
                            AliasValue::lift1_val(vt.v, |v| !v & BitVec::one(8))
                        } else {
                            AliasValue::lift1_val(vt.v, BitVec::not)
                        }
                    }
                    _ => {
                        if vt.v.is_bot() {
                            AliasValue::Bot
                        } else {
                            AliasValue::Top
                        }
                    }
                };
                TypedAliasValue::new(nval, vt.t.into_bits(), *loc)
            }
            Expr::BinOp(op, lexpr, rexpr) => {
                let TypedAliasValue { v: lval, t: t1, .. } =
                    self.eval_expr(loc, lexpr).resolve_named(self);
                let TypedAliasValue { v: rval, t: t2, .. } =
                    self.eval_expr(loc, rexpr).resolve_named(self);
                match op {
                    BinOp::ADD => {
                        let t = if let Some(off) =
                            rval.value().and_then(|bv| bv.signed_cast(64).to_i64())
                        {
                            AliasType::lift1(t1, |t| {
                                let t = t.resolve(self.typedb);
                                if off < 0 {
                                    t.apply_shift(off)
                                        .unwrap_or_else(|| Type::unsigned(t.nbits()))
                                } else {
                                    let off = off as usize;
                                    if let Some(p) = t.pointee() {
                                        p.resolve(self.typedb)
                                            .type_at_offset(off)
                                            .map(|t| Type::pointer(t, self.stack_pointer.nbits()))
                                            .unwrap_or_else(|| Type::unsigned(t.nbits()))
                                    } else {
                                        t.type_at_offset(off)
                                            .unwrap_or_else(|| Type::unsigned(t.nbits()))
                                    }
                                }
                            })
                        } else {
                            AliasType::into_bits2(t1, t2)
                        };

                        let val = AliasValue::lift2_any(lval, rval, BitVec::add);
                        TypedAliasValue::new(val, t, *loc)
                    }
                    BinOp::SUB => TypedAliasValue::new(
                        AliasValue::lift2_any(lval, rval, BitVec::sub),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::MUL => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, BitVec::mul),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::DIV => TypedAliasValue::new(
                        AliasValue::try_lift2_val(lval, rval, |l, r| {
                            if r.is_zero() {
                                None
                            } else {
                                Some(BitVec::div(l, r))
                            }
                        }),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::REM => TypedAliasValue::new(
                        AliasValue::try_lift2_val(lval, rval, |l, r| {
                            if r.is_zero() {
                                None
                            } else {
                                Some(BitVec::rem(l, r))
                            }
                        }),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::SDIV => TypedAliasValue::new(
                        AliasValue::try_lift2_val(lval, rval, |mut l, r| {
                            if r.is_zero() {
                                None
                            } else {
                                l.signed_div_assign(&r);
                                Some(l)
                            }
                        }),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::SREM => TypedAliasValue::new(
                        AliasValue::try_lift2_val(lval, rval, |mut l, r| {
                            if r.is_zero() {
                                None
                            } else {
                                l.signed_rem_assign(&r);
                                Some(l)
                            }
                        }),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::AND => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, BitVec::bitand),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::OR => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, BitVec::bitor),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::XOR => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, BitVec::bitxor),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::SHL => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, BitVec::shl),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::SHR => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, BitVec::shr),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                    BinOp::SAR => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |mut l, r| {
                            l.signed_shr_assign(&r);
                            l
                        }),
                        AliasType::into_bits2(t1, t2),
                        *loc,
                    ),
                }
            }
            Expr::Load(pval, bits, _) => {
                let TypedAliasValue { v: pval, t, .. } =
                    self.eval_expr(loc, pval).resolve_named(self);

                let t = if let Some(vt) = pval.value().to_address().and_then(|addr| {
                    self.gmapping
                        .get(&addr)
                        .and_then(|t| t.t.type_value())
                        .cloned()
                        .or_else(|| self.typedb.get_data_type_at(addr))
                }) {
                    if vt.nbits() != *bits {
                        AliasType::unsigned(*bits)
                    } else {
                        AliasType::typed(vt)
                    }
                } else {
                    AliasType::lift1(t, |t| {
                        if let Some(p) = t.resolve(self.typedb).pointee() {
                            // Load from struct at offset 0 resolves to the first field...
                            let pr = p.resolve(self.typedb);
                            if pr.is_struct() {
                                if let Some(f0) = pr.type_at_offset(0) {
                                    if f0.nbits() == *bits {
                                        return f0;
                                    }
                                }
                            }
                            if p.nbits() != *bits {
                                Type::unsigned(*bits)
                            } else {
                                p.to_owned()
                            }
                        } else {
                            Type::unsigned(*bits)
                        }
                    })
                };

                let val = if pval.is_top() {
                    AliasValue::Top
                } else if pval.is_bot() {
                    AliasValue::Bot
                } else if let Some(TypedAliasValue { v: sv, mut t, o }) = pval
                    .stack_delta()
                    .and_then(|delta| self.smapping.get(&delta).cloned())
                    .map(|value| self.resolve_named(value))
                {
                    if let Some(AliasType::T(st)) = sv
                        .stack_delta()
                        .and_then(|delta| self.smapping.get(&delta))
                        .map(|vt| self.resolve_named(vt.clone()).t)
                    {
                        t = AliasType::typed(Type::pointer(st, self.stack_pointer.nbits() as _));
                    }
                    let bytes = *bits as usize / 8;

                    return TypedAliasValue::new(sv.extract(0, bytes), t.extract(0, bytes), o);
                } else {
                    AliasValue::ptr(pval, BitVec::zero(self.stack_pointer.nbits() as _))
                };

                TypedAliasValue::new(val, t, *loc)
            }
            Expr::Concat(lexpr, rexpr) => {
                let TypedAliasValue { v: lval, .. } =
                    self.eval_expr(loc, lexpr).resolve_named(self);
                let TypedAliasValue { v: rval, .. } =
                    self.eval_expr(loc, rexpr).resolve_named(self);

                TypedAliasValue::new(
                    AliasValue::lift2_val(lval, rval, |mut l, mut r| {
                        let lbits = l.nbits();
                        let rbits = r.nbits();

                        let obits = lbits + rbits;

                        l.unsigned_cast_assign(obits as _);
                        r.unsigned_cast_assign(obits as _);

                        l <<= rbits as u32;

                        l |= r;
                        l
                    }),
                    AliasType::unsigned(lexpr.nbits() + rexpr.nbits()),
                    *loc,
                )
            }
            Expr::BinRel(op, lexpr, rexpr) => {
                let TypedAliasValue { v: lval, .. } =
                    self.eval_expr(loc, lexpr).resolve_named(self);
                let TypedAliasValue { v: rval, .. } =
                    self.eval_expr(loc, rexpr).resolve_named(self);
                match op {
                    BinRel::EQ => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l == r { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::NEQ => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l != r { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::LT => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l < r { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::LE => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l <= r { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::SLT => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l.signed_cmp(&r).is_lt() { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::SLE => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l.signed_cmp(&r).is_le() { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::CARRY => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l.carry(&r) { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::SCARRY => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l.signed_carry(&r) { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                    BinRel::SBORROW => TypedAliasValue::new(
                        AliasValue::lift2_val(lval, rval, |l, r| {
                            BitVec::from(if l.signed_borrow(&r) { 1u8 } else { 0u8 })
                        }),
                        AliasType::bool(),
                        *loc,
                    ),
                }
            }
            Expr::UnRel(_, _expr) => TypedAliasValue::typed_top(Type::bool(), *loc),
            Expr::Cast(expr, t) => {
                let v = self.eval_expr(loc, expr).resolve_named(self);
                let t_bits = t.nbits() as usize;

                let v_cast = if t.is_bool() {
                    AliasValue::lift1_val(v.v, |v| {
                        BitVec::from(if v.is_zero() { 0u8 } else { 1u8 })
                    })
                } else if v.v.is_sym()
                    && matches!(v.t.type_value(), Some(tn) if tn.nbits() as usize <= t_bits)
                {
                    v.v
                } else if t.is_unsigned() {
                    if v.v.is_ref() {
                        if let Some(stack_offset) = v.v.stack_delta() {
                            if let Some(stack_alias) = self.get_stack_alias(stack_offset) {
                                let vt = TypedAliasValue {
                                    v: AliasValue::lift1_val(stack_alias.v.to_owned(), |mut v| {
                                        v.unsigned_cast_assign(t_bits);
                                        v
                                    }),
                                    t: AliasType::unsigned(t_bits as u32),
                                    o: stack_alias.o.to_owned(),
                                };

                                self.smapping.insert(stack_offset, vt);
                            }
                        }

                        v.v
                    } else {
                        AliasValue::lift1_val(v.v, |mut v| {
                            v.unsigned_cast_assign(t_bits);
                            v
                        })
                    }
                } else if t.is_signed() {
                    AliasValue::lift1_val(v.v, |mut v| {
                        v.signed_cast_assign(t_bits);
                        v
                    })
                } else {
                    AliasValue::Top
                };

                TypedAliasValue::new(v_cast, AliasType::T(t.to_owned()), v.o)
            }
            Expr::Extract(expr, loff, moff) => {
                let TypedAliasValue { v: val, o, .. } =
                    self.eval_expr(loc, expr).resolve_named(self);
                let bits = moff - loff;

                TypedAliasValue::new(
                    AliasValue::lift1_val(val, |mut v| {
                        if *loff > 0 {
                            v >>= *loff;
                        }
                        v.unsigned_cast_assign(bits as _);
                        v
                    }),
                    AliasType::unsigned(bits),
                    o,
                )
            }
            Expr::ExtractHigh(expr, bits) => {
                let TypedAliasValue { v: val, o, .. } =
                    self.eval_expr(loc, expr).resolve_named(self);

                TypedAliasValue::new(
                    AliasValue::lift1_val(val, |mut v| {
                        let vbits = v.nbits();
                        if *bits < vbits {
                            let diff = vbits - *bits;
                            v >>= diff;
                        }
                        v.unsigned_cast_assign(*bits as _);
                        v
                    }),
                    AliasType::unsigned(*bits),
                    o,
                )
            }
            Expr::ExtractLow(expr, bits) => {
                let TypedAliasValue { v: val, o, .. } =
                    self.eval_expr(loc, expr).resolve_named(self);

                TypedAliasValue::new(
                    AliasValue::lift1_val(val, |mut v| {
                        v.unsigned_cast_assign(*bits as _);
                        v
                    }),
                    AliasType::unsigned(*bits),
                    o,
                )
            }
            Expr::IfElse(_cexpr, texpr, fexpr) => {
                let TypedAliasValue {
                    v: mut l,
                    t: t1,
                    o: mut o1,
                } = self.eval_expr(loc, texpr).resolve_named(self);
                let TypedAliasValue { v: r, t: t2, o: o2 } =
                    self.eval_expr(loc, fexpr).resolve_named(self);
                let v = if !l.is_unk() && !r.is_unk() {
                    l.join(r);
                    l
                } else {
                    AliasValue::Top
                };

                o1.join(o2, *loc);

                TypedAliasValue::new(v, AliasType::into_bits2(t1, t2), o1)
            }
            Expr::Intrinsic(name, args, sz) => {
                let vts = args.iter().map(|arg| self.eval_expr(loc, arg)).collect();
                let vt = self.with_typing_context(*loc, move |ctx, resolver| {
                    resolver
                        .resolve_intrinsic_with(ctx, *name, vts, Some(*sz))
                        .unwrap_or(TypedAliasValue::top(*loc))
                });

                if let Some((rt, args)) = vt.t.type_value().and_then(|ft| {
                    ft.function_return()
                        .and_then(|rt| ft.function_args().map(|args| (rt, args)))
                }) {
                    let resolver = self.lifter.default_prototype();

                    for (i, arg) in args.iter().enumerate() {
                        if let Some(input) = resolver.input(i) {
                            self.apply_operand_type(
                                input,
                                arg.type_().clone(),
                                if arg.is_output() {
                                    Clobber::Pointee
                                } else {
                                    Clobber::None
                                },
                                *loc,
                            );
                        }
                    }

                    if !rt.is_void() {
                        TypedAliasValue::new(vt.v, AliasType::typed(rt.to_owned()), *loc)
                    } else {
                        TypedAliasValue::top(*loc)
                    }
                } else {
                    vt
                }
            }
            _ => TypedAliasValue::top(*loc),
        }
    }

    fn eval_branch(&mut self, at: &Location, target: &Term<BranchTarget>) -> TypedAliasValue {
        match &**target {
            BranchTarget::Location(loc) => {
                let val = AliasValue::val(BitVec::from_u64(
                    loc.address().offset(),
                    self.stack_pointer.nbits() as _,
                ));

                let typ =
                    AliasType::typed(self.typedb.get_data_type_at(loc.address()).unwrap_or_else(
                        || {
                            Type::pointer(
                                Type::function(Type::void(), std::iter::empty::<FunctionArg>()),
                                self.stack_pointer.nbits(),
                            )
                        },
                    ));

                TypedAliasValue::new(val, typ, *at)
            }
            BranchTarget::Computed(loc) => self.eval_expr(at, loc),
            BranchTarget::External(_, _) => TypedAliasValue::top(*at),
        }
    }

    #[inline]
    fn eval_stmt(&mut self, loc: &Location, stmt: &Term<Stmt>) {
        match &**stmt {
            Stmt::Assign(var, expr) => {
                if let Some(address) = var.address() {
                    let vt = self.eval_expr(loc, expr);
                    let sz = var.nbits();
                    match self.gmapping.entry(address) {
                        BEntry::Vacant(e) => {
                            let mut oval = None;
                            let mut toval = None;

                            vt.v.blit_into(0, sz as usize / 8, &mut oval);
                            vt.t.blit_into(0, sz as usize / 8, &mut toval);

                            e.insert(TypedAliasValue {
                                v: oval.unwrap(),
                                t: toval.unwrap(),
                                o: vt.o,
                            });
                        }
                        BEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: oval, t: toval, ..
                            } = std::mem::take(e.get_mut());
                            let mut oval = Some(oval);
                            let mut toval = Some(toval);

                            vt.v.blit_into(0, sz as usize / 8, &mut oval);

                            if !vt.t.is_unk() {
                                vt.t.blit_into(0, sz as usize / 8, &mut toval);
                            }

                            e.insert(TypedAliasValue {
                                v: oval.unwrap(),
                                t: toval.unwrap(),
                                o: vt.o,
                            });
                        }
                    }
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);
                let vt = self.eval_expr(loc, expr);

                /*
                if t.is_unk() {
                    if let Some(AliasType::T(st)) = val.stack_delta().and_then(|delta| self.smapping.get(&delta)).map(|(_, t)| t.clone()) {
                        t = AliasType::typed(Type::pointer(st, self.stack_pointer.nbits() as _));
                    }
                }
                */

                /*
                let val = if var.offset() != lvar.offset() {
                    AliasValue::Top
                } else {
                    self.eval_expr(loc, expr)
                };
                */

                if lvar.is_register() {
                    match self.rmapping.entry(lvar) {
                        HEntry::Vacant(e) => {
                            let mut oval = None;
                            let mut toval = None;
                            vt.v.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            vt.t.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut toval,
                            );
                            e.insert(TypedAliasValue::new(oval.unwrap(), toval.unwrap(), vt.o));
                        }
                        HEntry::Occupied(mut e) => {
                            let ovt = std::mem::take(e.get_mut());
                            let mut oval = Some(ovt.v);
                            let mut toval = Some(ovt.t);

                            vt.v.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            vt.t.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut toval,
                            );

                            e.insert(TypedAliasValue::new(oval.unwrap(), toval.unwrap(), vt.o));
                        }
                    }
                } else {
                    match self.tmapping.entry(lvar) {
                        HEntry::Vacant(e) => {
                            let mut oval = None;
                            let mut toval = None;
                            vt.v.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            vt.t.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut toval,
                            );
                            e.insert(TypedAliasValue::new(oval.unwrap(), toval.unwrap(), vt.o));
                        }
                        HEntry::Occupied(mut e) => {
                            let ovt = std::mem::take(e.get_mut());
                            let mut oval = Some(ovt.v);
                            let mut toval = Some(ovt.t);

                            vt.v.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut oval,
                            );
                            vt.t.blit_into(
                                (var.offset() - lvar.offset()) as usize,
                                lvar.nbits() as usize / 8,
                                &mut toval,
                            );

                            e.insert(TypedAliasValue::new(oval.unwrap(), toval.unwrap(), vt.o));
                        }
                    }
                }
            }
            Stmt::Call(p, _) => {
                let mut vt = self.eval_branch(loc, p);

                // NOTE: we may have an override
                if let Some(f) =
                    vt.v.to_address()
                        .and_then(|addr| self.functions.get_point(addr))
                        .and_then(|f| {
                            self.injections
                                .get_function_stub(f.id())
                                .and_then(InjectionStub::fixup)
                        })
                {
                    tracing::trace!("call fixup @ {loc}: {}", f.name());

                    for op in f.operations() {
                        self.eval_stmt(loc, op);
                    }

                    self.call_target = Some(vt);

                    return;
                }

                // Fix-up the stack-pointer
                match self.rmapping.entry(self.stack_pointer) {
                    HEntry::Vacant(e) => {
                        e.insert(TypedAliasValue::new(
                            AliasValue::Bot,
                            AliasType::void_ptr(self.stack_pointer.nbits()),
                            AliasOrigin::new_before_for(*loc, &self.stack_pointer, 0),
                        ));
                    }
                    HEntry::Occupied(mut e) => {
                        let vt = std::mem::take(e.get_mut());
                        e.insert(TypedAliasValue::new(
                            AliasValue::lift2_any(
                                vt.v,
                                AliasValue::val(self.extra_pop.clone()),
                                BitVec::add,
                            ),
                            vt.t,
                            AliasOrigin::new_before_for(*loc, &self.stack_pointer, 0),
                        ));
                    }
                }

                // Apply argument types and clobbers
                //
                // - For a direct call, we should apply types based on the type database
                // - For an indirect call, we fallback to use our resolver

                let ft = self
                    .resolve_named(vt.clone())
                    .v
                    .value()
                    .to_address()
                    .and_then(|addr| self.typedb.get_code_type_at(addr));

                if let Some(ft) = ft.as_ref().cloned() {
                    vt.t = AliasType::T(Type::pointer(ft, self.lifter.address_bits()));
                }

                // NOTE: at this point it seems like we can't avoid obtaining a type,
                // so it's a bit unclear if we just get void (*)(), whether applying
                // clobbers to the return type is fine, given we don't know whether
                // the type came from the resolver itself or from our default
                // implementation, so we delegate clobber application to the underlying
                // resolver. During type resolution, the resolver can clear and/or update
                // the clobber set applied.
                //

                let (ft, killed) = match vt.t.type_value() {
                    None => {
                        let t = Type::pointer(
                            Type::function(Type::void(), std::iter::empty::<FunctionArg>()),
                            self.lifter.address_bits(),
                        );

                        self.with_typing_context(*loc, |ctx, r| {
                            let addr = vt.v.value().to_address();

                            if let Some(addr) = addr {
                                ctx.set_default_killed(addr);
                            }

                            let ft = r.resolve_type_with(ctx, addr, &t);
                            let killed = mem::take(&mut ctx.function_killed);

                            (ft, killed)
                        })
                    }
                    Some(t) => self.with_typing_context(*loc, |ctx, r| {
                        let addr = vt.v.value().to_address();

                        if let Some(addr) = addr {
                            ctx.set_default_killed(addr);
                        }

                        let ft = r.resolve_type_with(ctx, addr, t);
                        let killed = mem::take(&mut ctx.function_killed);

                        (ft, killed)
                    }),
                };

                // NOTE: for now, we just deal with register kills (as they are the most
                // problematic)

                for kill in killed.iter().filter_map(Operand::as_register) {
                    if kill == self.stack_pointer {
                        // SP will be killed during the return and we will
                        // always report it in this case, but we do know it
                        // will be preserved on the return (since we handle
                        // it).
                        continue;
                    }

                    match self.rmapping.entry(kill) {
                        HEntry::Vacant(e) => {
                            e.insert(TypedAliasValue::new(
                                AliasValue::Top,
                                AliasType::unsigned(kill.nbits()),
                                AliasOrigin::new_with(*loc, 0),
                            ));
                        }
                        HEntry::Occupied(mut e) => {
                            let vt = e.get_mut();
                            vt.v = AliasValue::Top;
                            vt.o = AliasOrigin::new_with(*loc, 0);
                        }
                    }
                }

                if let Some((rv, rt, args)) = ft.as_ref().and_then(|ft| {
                    ft.function_return()
                        .and_then(|rt| ft.function_args().map(|args| (ft.clobber_kind(), rt, args)))
                }) {
                    let resolver = self.lifter.default_prototype();

                    for (i, arg) in args.iter().enumerate() {
                        if let Some(input) = resolver.input(i) {
                            // TODO: clobber value (if needed)
                            self.apply_operand_type(
                                input,
                                arg.type_().clone(),
                                if arg.is_output() {
                                    Clobber::Pointee
                                } else {
                                    Clobber::None
                                },
                                AliasOrigin::new_with(*loc, i as i64 + 1),
                            );
                        }
                    }

                    if !rt.is_void() {
                        if let Some(output) = resolver.output(0) {
                            self.apply_operand_type(
                                output,
                                rt.clone(),
                                rv,
                                AliasOrigin::new_with(*loc, 0),
                            );
                        }
                    }
                }

                // TODO: ensure a call target cannot be a shifted pointer; just map to bot
                self.call_target = Some(vt);
            }
            Stmt::Branch(p) if p.is_computed() => {
                let vt = self.eval_branch(loc, p);

                let (ft, killed) = match vt.t.type_value() {
                    None => {
                        let t = Type::pointer(
                            Type::function(Type::void(), std::iter::empty::<FunctionArg>()),
                            self.lifter.address_bits(),
                        );

                        self.with_typing_context(*loc, |ctx, r| {
                            let addr = vt.v.value().to_address();

                            if let Some(addr) = addr {
                                ctx.set_default_killed(addr);
                            }

                            let ft = r.resolve_type_with(ctx, addr, &t);
                            let killed = mem::take(&mut ctx.function_killed);

                            (ft, killed)
                        })
                    }
                    Some(t) => self.with_typing_context(*loc, |ctx, r| {
                        let addr = vt.v.value().to_address();

                        if let Some(addr) = addr {
                            ctx.set_default_killed(addr);
                        }

                        let ft = r.resolve_type_with(ctx, addr, t);
                        let killed = mem::take(&mut ctx.function_killed);

                        (ft, killed)
                    }),
                };

                for kill in killed.iter().filter_map(Operand::as_register) {
                    match self.rmapping.entry(kill) {
                        HEntry::Vacant(e) => {
                            e.insert(TypedAliasValue::new(
                                AliasValue::Top,
                                AliasType::unsigned(kill.nbits()),
                                AliasOrigin::new_with(*loc, 0),
                            ));
                        }
                        HEntry::Occupied(mut e) => {
                            let vt = e.get_mut();
                            vt.v = AliasValue::Top;
                            vt.o = AliasOrigin::new_with(*loc, 0);
                        }
                    }
                }

                if let Some((rt, args)) = ft.as_ref().and_then(|ft| {
                    ft.function_return()
                        .and_then(|rt| ft.function_args().map(|args| (rt, args)))
                }) {
                    let resolver = self.lifter.default_prototype();

                    for (i, arg) in args.iter().enumerate() {
                        if let Some(input) = resolver.input(i) {
                            self.apply_operand_type(
                                input,
                                arg.type_().clone(),
                                if arg.is_output() {
                                    Clobber::Pointee
                                } else {
                                    Clobber::None
                                },
                                AliasOrigin::new_with(*loc, i as i64 + 1),
                            );
                        }
                    }

                    if !rt.is_void() {
                        if let Some(output) = resolver.output(0) {
                            self.apply_operand_type(
                                output,
                                rt.clone(),
                                Clobber::Direct,
                                AliasOrigin::new_with(*loc, 0),
                            );
                        }
                    }
                }

                // TODO: ensure a call target cannot be a shifted pointer; just map to bot
                self.call_target = Some(vt);
            }
            Stmt::CBranch(cond, _) => {
                self.condition = Some(self.eval_expr(loc, cond));
            }
            Stmt::Store(d, s, sz, _spc) => {
                let TypedAliasValue { v: d, .. } = self.eval_expr(loc, d).resolve_named(self);
                let TypedAliasValue { v: s, mut t, o } = self.eval_expr(loc, s).resolve_named(self);

                if let Some(AliasType::T(st)) = s
                    .stack_delta()
                    .and_then(|delta| self.smapping.get(&delta))
                    .map(|TypedAliasValue { t, .. }| t.clone())
                {
                    t = AliasType::typed(Type::pointer(st, self.stack_pointer.nbits() as _));
                }

                if let Some(off) = d.stack_delta() {
                    if let Some(fs) = t
                        .type_value()
                        .map(|t| t.resolve(self.typedb))
                        .as_ref()
                        .and_then(|t| t.struct_fields())
                    {
                        for f in fs {
                            let ft = f.type_();
                            let bytes = ft.nbytes();

                            let s = s.to_owned().extract(f.offset(), bytes);
                            let t = AliasType::typed(ft.to_owned());

                            match self.smapping.entry(off + f.offset() as i64) {
                                BEntry::Vacant(e) => {
                                    let mut oval = None;
                                    let mut toval = None;

                                    s.blit_into(0, bytes, &mut oval);
                                    t.blit_into(0, bytes, &mut toval);

                                    e.insert(TypedAliasValue {
                                        v: oval.unwrap(),
                                        t: toval.unwrap(),
                                        o: o.clone(),
                                    });
                                }
                                BEntry::Occupied(mut e) => {
                                    let TypedAliasValue {
                                        v: oval, t: toval, ..
                                    } = std::mem::take(e.get_mut());
                                    let mut oval = Some(oval);
                                    let mut toval = Some(toval);

                                    s.blit_into(0, bytes, &mut oval);
                                    t.blit_into(0, bytes, &mut toval);

                                    e.insert(TypedAliasValue {
                                        v: oval.unwrap(),
                                        t: toval.unwrap(),
                                        o: o.clone(),
                                    });
                                }
                            }
                        }
                    } else {
                        match self.smapping.entry(off) {
                            BEntry::Vacant(e) => {
                                let mut oval = None;
                                let mut toval = None;

                                s.blit_into(0, *sz as usize / 8, &mut oval);
                                t.blit_into(0, *sz as usize / 8, &mut toval);

                                e.insert(TypedAliasValue {
                                    v: oval.unwrap(),
                                    t: toval.unwrap(),
                                    o,
                                });
                            }
                            BEntry::Occupied(mut e) => {
                                let TypedAliasValue {
                                    v: oval, t: toval, ..
                                } = std::mem::take(e.get_mut());
                                let mut oval = Some(oval);
                                let mut toval = Some(toval);

                                s.blit_into(0, *sz as usize / 8, &mut oval);
                                t.blit_into(0, *sz as usize / 8, &mut toval);

                                e.insert(TypedAliasValue {
                                    v: oval.unwrap(),
                                    t: toval.unwrap(),
                                    o,
                                });
                            }
                        }
                    }
                } else if let Some(address) = d.value().to_address() {
                    if !self.memory.contains(address) {
                        return;
                    }

                    if let Some(fs) = t
                        .type_value()
                        .map(|t| t.resolve(self.typedb))
                        .as_ref()
                        .and_then(|t| t.struct_fields())
                    {
                        for f in fs {
                            let ft = f.type_();
                            let bytes = ft.nbytes();

                            let s = s.to_owned().extract(f.offset(), bytes);
                            let t = AliasType::typed(ft.to_owned());

                            match self.gmapping.entry(address + f.offset()) {
                                BEntry::Vacant(e) => {
                                    let mut oval = None;
                                    let mut toval = None;

                                    s.blit_into(0, bytes, &mut oval);
                                    t.blit_into(0, bytes, &mut toval);

                                    e.insert(TypedAliasValue {
                                        v: oval.unwrap(),
                                        t: toval.unwrap(),
                                        o: o.clone(),
                                    });
                                }
                                BEntry::Occupied(mut e) => {
                                    let TypedAliasValue {
                                        v: oval, t: toval, ..
                                    } = std::mem::take(e.get_mut());
                                    let mut oval = Some(oval);
                                    let mut toval = Some(toval);

                                    s.blit_into(0, bytes, &mut oval);
                                    t.blit_into(0, bytes, &mut toval);

                                    e.insert(TypedAliasValue {
                                        v: oval.unwrap(),
                                        t: toval.unwrap(),
                                        o: o.clone(),
                                    });
                                }
                            }
                        }
                    } else {
                        match self.gmapping.entry(address) {
                            BEntry::Vacant(e) => {
                                let mut oval = None;
                                let mut toval = None;

                                s.blit_into(0, *sz as usize / 8, &mut oval);
                                t.blit_into(0, *sz as usize / 8, &mut toval);

                                e.insert(TypedAliasValue {
                                    v: oval.unwrap(),
                                    t: toval.unwrap(),
                                    o,
                                });
                            }
                            BEntry::Occupied(mut e) => {
                                let TypedAliasValue {
                                    v: oval, t: toval, ..
                                } = std::mem::take(e.get_mut());
                                let mut oval = Some(oval);
                                let mut toval = Some(toval);

                                s.blit_into(0, *sz as usize / 8, &mut oval);
                                t.blit_into(0, *sz as usize / 8, &mut toval);

                                e.insert(TypedAliasValue {
                                    v: oval.unwrap(),
                                    t: toval.unwrap(),
                                    o,
                                });
                            }
                        }
                    }
                }
            }
            Stmt::Intrinsic(name, args) => {
                let vts = args.iter().map(|arg| self.eval_expr(loc, arg)).collect();
                let vt = self.with_typing_context(*loc, move |ctx, resolver| {
                    resolver
                        .resolve_intrinsic_with(ctx, *name, vts, None)
                        .unwrap_or_else(|| TypedAliasValue::top(*loc))
                });

                if let Some(args) = vt.t.type_value().and_then(|ft| ft.function_args()) {
                    let resolver = self.lifter.default_prototype();
                    for (i, arg) in args.iter().enumerate() {
                        if let Some(input) = resolver.input(i) {
                            self.apply_operand_type(
                                input,
                                arg.type_().clone(),
                                if arg.is_output() {
                                    Clobber::Pointee
                                } else {
                                    Clobber::None
                                },
                                *loc,
                            );
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
        for (i, stmt) in insn.operations().iter().enumerate() {
            self.eval_stmt(&Location::new(insn.address(), i), stmt);
        }
    }

    #[inline]
    pub fn visit_insn<V>(&mut self, insn: &Term<Insn>, visitor: &mut V)
    where
        V: AliasVisitor<'a, 'b, T>,
    {
        self.tmapping.clear();
        for (i, stmt) in insn.operations().iter().enumerate() {
            visitor.visit_aliases_pre(insn, i, stmt, self);
            self.eval_stmt(&Location::new(insn.address(), i), stmt);
            visitor.visit_aliases_post(insn, i, stmt, self);
        }
    }

    #[inline]
    pub fn visit_block<V>(&mut self, block: &CodeBlock, visitor: &mut V)
    where
        V: AliasVisitor<'a, 'b, T>,
    {
        for insn in block.insns() {
            self.visit_insn(insn, visitor)
        }
    }

    #[inline]
    pub fn get_var_alias(&self, var: &Var) -> Option<&TypedAliasValue> {
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
    pub fn get_stack_alias(&self, offset: i64) -> Option<&TypedAliasValue> {
        self.smapping.get(&offset)
    }

    #[inline]
    pub fn get_global_alias(&self, global: Address) -> Option<&TypedAliasValue> {
        self.gmapping.get(&global)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TypedBlockAliases {
    incoming: AHashMap<Var, TypedAliasValue>,
    incoming_stack: BTreeMap<i64, TypedAliasValue>,
    incoming_symbol: AHashMap<NamedValue, TypedAliasValue>,
    incoming_global: BTreeMap<Address, TypedAliasValue>,
    outgoing: AHashMap<Var, TypedAliasValue>,
    outgoing_stack: BTreeMap<i64, TypedAliasValue>,
    outgoing_symbol: AHashMap<NamedValue, TypedAliasValue>,
    outgoing_global: BTreeMap<Address, TypedAliasValue>,
    call_target: Option<TypedAliasValue>,
    pre_call_state: Option<CallSiteContext>,
    condition: Option<TypedAliasValue>,
    limit: usize,
}

impl TypedBlockAliases {
    pub fn visitor<'a, 'b, T>(
        &self,
        project: &'a Project,
        resolver: &'b T,
    ) -> TypedAliasVisitor<'a, 'b, T>
    where
        T: ContextualTypeResolver<'a>,
    {
        TypedAliasVisitor::new_with(
            project.functions(),
            project.function_summaries(),
            project.injections(),
            project.lifter(),
            project.type_db(),
            project.memory(),
            self.incoming.to_owned(),
            self.incoming_stack.to_owned(),
            self.incoming_symbol.to_owned(),
            self.incoming_global.to_owned(),
            resolver,
        )
    }

    pub fn incoming(&self) -> &AHashMap<Var, TypedAliasValue> {
        &self.incoming
    }

    pub fn incoming_globals(&self) -> &BTreeMap<Address, TypedAliasValue> {
        &self.incoming_global
    }

    pub fn incoming_stack(&self) -> &BTreeMap<i64, TypedAliasValue> {
        &self.incoming_stack
    }

    pub fn incoming_symbols(&self) -> &AHashMap<NamedValue, TypedAliasValue> {
        &self.incoming_symbol
    }

    pub fn incoming_values(&self) -> impl Iterator<Item = (&Var, &AliasValue, &AliasType)> {
        self.incoming.iter().filter_map(
            |(var, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((var, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn incoming_global_values(
        &self,
    ) -> impl Iterator<Item = (Address, &AliasValue, &AliasType)> {
        self.incoming_global.iter().filter_map(
            |(&off, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((off, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn incoming_stack_values(&self) -> impl Iterator<Item = (i64, &AliasValue, &AliasType)> {
        self.incoming_stack.iter().filter_map(
            |(&off, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((off, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn incoming_symbol_values(
        &self,
    ) -> impl Iterator<Item = (&NamedValue, &AliasValue, &AliasType)> {
        self.incoming_symbol.iter().filter_map(
            |(sym, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((sym, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn outgoing(&self) -> &AHashMap<Var, TypedAliasValue> {
        &self.outgoing
    }

    pub fn outgoing_globals(&self) -> &BTreeMap<Address, TypedAliasValue> {
        &self.outgoing_global
    }

    pub fn outgoing_stack(&self) -> &BTreeMap<i64, TypedAliasValue> {
        &self.outgoing_stack
    }

    pub fn outgoing_symbols(&self) -> &AHashMap<NamedValue, TypedAliasValue> {
        &self.outgoing_symbol
    }

    pub fn outgoing_values(&self) -> impl Iterator<Item = (&Var, &AliasValue, &AliasType)> {
        self.outgoing.iter().filter_map(
            |(var, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((var, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn outgoing_global_values(
        &self,
    ) -> impl Iterator<Item = (Address, &AliasValue, &AliasType)> {
        self.outgoing_global.iter().filter_map(
            |(&off, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((off, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn outgoing_stack_values(&self) -> impl Iterator<Item = (i64, &AliasValue, &AliasType)> {
        self.outgoing_stack.iter().filter_map(
            |(&off, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((off, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn outgoing_symbol_values(
        &self,
    ) -> impl Iterator<Item = (&NamedValue, &AliasValue, &AliasType)> {
        self.outgoing_symbol.iter().filter_map(
            |(sym, TypedAliasValue { v, t, .. })| {
                if !v.is_unk() {
                    Some((sym, v, t))
                } else {
                    None
                }
            },
        )
    }

    pub fn pre_call_state(&self) -> Option<&CallSiteContext> {
        self.pre_call_state.as_ref()
    }

    pub fn call_target(&self) -> Option<&TypedAliasValue> {
        self.call_target.as_ref()
    }

    pub fn condition(&self) -> Option<&TypedAliasValue> {
        self.condition.as_ref()
    }

    pub fn display_with<'a>(&'a self, project: &'a Project) -> TypedBlockAliasesDisplay<'a> {
        TypedBlockAliasesDisplay {
            aliases: self,
            project,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct TypedFunctionAliases {
    blocks: AHashMap<CodeBlockId, TypedBlockAliases>,
}

pub struct TypedFunctionAliasesDisplay<'a> {
    aliases: &'a TypedFunctionAliases,
    project: &'a Project,
}

pub struct TypedBlockAliasesDisplay<'a> {
    aliases: &'a TypedBlockAliases,
    project: &'a Project,
}

pub struct CallSiteContextDisplay<'a> {
    aliases: &'a CallSiteContext,
    project: &'a Project,
}

impl<'a> Display for CallSiteContextDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("call-site registers/variables\n")?;

        for (var, vt) in self.aliases.registers() {
            let v = &vt.v;
            let t = &vt.t;
            let name = var.display_with(Some(self.project.lifter().translator()));
            writeln!(f, "{name} = {v} ({t})")?;
        }

        f.write_str("\ncall-site stack\n")?;

        for (spd, vt) in self.aliases.stack_variables() {
            let v = &vt.v;
            let t = &vt.t;
            writeln!(f, "sp+{spd} = {v} ({t})")?;
        }

        Ok(())
    }
}

impl<'a> Display for TypedBlockAliasesDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("incoming registers/variables\n")?;

        for (var, vt) in self.aliases.incoming() {
            let v = &vt.v;
            let t = &vt.t;
            let name = var.display_with(Some(self.project.lifter().translator()));
            writeln!(f, "{name} = {v} ({t})")?;
        }

        f.write_str("\noutgoing registers/variables\n")?;

        for (var, vt) in self.aliases.outgoing() {
            let v = &vt.v;
            let t = &vt.t;
            let name = var.display_with(Some(self.project.lifter().translator()));
            writeln!(f, "{name} = {v} ({t})")?;
        }

        f.write_str("\nincoming stack\n")?;

        for (spd, vt) in self.aliases.incoming_stack() {
            let v = &vt.v;
            let t = &vt.t;
            writeln!(f, "sp+{spd} = {v} ({t})")?;
        }

        f.write_str("\noutgoing stack\n")?;

        for (spd, vt) in self.aliases.outgoing_stack() {
            let v = &vt.v;
            let t = &vt.t;
            writeln!(f, "sp+{spd} = {v} ({t})")?;
        }

        if let Some(aliases) = self.aliases.pre_call_state() {
            aliases.display_with(self.project).fmt(f)?;
        }

        if let Some(vt) = self.aliases.call_target() {
            let v = &vt.v;
            let t = &vt.t;

            write!(f, "\ncall target: {v} ({t})")?;
        }

        if let Some(vt) = self.aliases.condition() {
            let v = &vt.v;
            let t = &vt.t;

            write!(f, "\ncondition: {v} ({t})")?;
        }

        Ok(())
    }
}

impl<'a> Display for TypedFunctionAliasesDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blocks = self.project.code_blocks();
        let sorted = self
            .aliases
            .blocks
            .iter()
            .sorted_by_key(|(&b, _)| blocks[b].address());

        for (&bid, aliases) in sorted {
            let blk = &blocks[bid];
            let addr = blk.address();
            f.write_fmt(format_args!(
                "--- block @ {addr} ---\n{}\n\n{}\n---\n",
                blk.display(self.project),
                TypedBlockAliasesDisplay {
                    aliases,
                    project: self.project,
                }
            ))?;
        }

        Ok(())
    }
}

impl TypedFunctionAliases {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, TypedBlockAliases> {
        &self.blocks
    }

    #[inline]
    pub fn into_blocks(self) -> AHashMap<CodeBlockId, TypedBlockAliases> {
        self.blocks
    }

    #[inline]
    pub fn visit<'a, 'b, T, V>(&self, project: &'a Project, resolver: &'b T, visitor: &mut V)
    where
        T: ContextualTypeResolver<'a>,
        V: AliasVisitor<'a, 'b, T>,
    {
        for (&bid, aliases) in self.blocks.iter() {
            let block = &project.code_blocks()[bid];
            let mut visit = aliases.visitor(project, resolver);
            visit.visit_block(block, visitor)
        }
    }

    #[inline]
    pub fn visit_block<'a, 'b, T, V>(
        &self,
        project: &'a Project,
        resolver: &'b T,
        block: CodeBlockId,
        visitor: &mut V,
    ) where
        T: ContextualTypeResolver<'a>,
        V: AliasVisitor<'a, 'b, T>,
    {
        let Some(aliases) = self.blocks.get(&block) else {
            return;
        };

        let block = &project.code_blocks()[block];
        let mut visit = aliases.visitor(project, resolver);
        visit.visit_block(block, visitor)
    }

    pub fn display_with<'a>(&'a self, project: &'a Project) -> TypedFunctionAliasesDisplay<'a> {
        TypedFunctionAliasesDisplay {
            aliases: self,
            project,
        }
    }
}

impl<'a> IntoIterator for &'a TypedFunctionAliases {
    type IntoIter = std::collections::hash_map::Iter<'a, CodeBlockId, TypedBlockAliases>;
    type Item = (&'a CodeBlockId, &'a TypedBlockAliases);

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter()
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct TypedAliases {
    mapping: AHashMap<FunctionId, TypedFunctionAliases>,
}

impl<'a> IntoIterator for &'a TypedAliases {
    type IntoIter = std::collections::hash_map::Iter<'a, FunctionId, TypedFunctionAliases>;
    type Item = (&'a FunctionId, &'a TypedFunctionAliases);

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.mapping.iter()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TypedCodePathAliases {
    mapping: Vec<TypedBlockAliases>,
}

impl TypedCodePathAliases {
    pub fn get(&self, block: &CodePathBlockRef) -> Option<&TypedBlockAliases> {
        self.mapping.get(block.index())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &TypedBlockAliases> {
        self.mapping.iter()
    }

    pub fn iter_with<'a>(
        &'a self,
        path: &'a CodePath,
    ) -> impl Iterator<Item = (CodePathBlockRef, &'a TypedBlockAliases)> + 'a {
        path.iter().zip(self.iter())
    }
}

impl TypedAliases {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn update_indirects(&self, project: &mut Project) {
        let cbtable = &project.cbtable;
        let ftable = &mut project.ftable;
        let icfg = &mut project.icfg;

        for (&bid, ct) in self
            .mapping
            .values()
            .map(|f| {
                f.into_iter().filter_map(|(k, v)| {
                    v.call_target()
                        .and_then(|vt| vt.v.value().to_address().map(|a| (k, a)))
                })
            })
            .flatten()
        {
            let sblk = &cbtable[bid];
            if !sblk.is_call() {
                continue;
            }

            if !ftable.contains_point(ct) {
                continue;
            }

            let Some(tblk) = cbtable.get_point(ct) else {
                continue;
            };

            let snode = sblk.node();
            let tnode = tblk.node();

            icfg.add_edge(snode, tnode, FlowKind::ICall);
        }
    }

    pub fn update_callgraph(&self, project: &Project, callgraph: &mut CallGraph) {
        let cbtable = &project.cbtable;
        let ftable = &project.ftable;

        for (&bid, ct) in self
            .mapping
            .values()
            .map(|f| {
                f.into_iter().filter_map(|(k, v)| {
                    v.call_target().and_then(|vt| {
                        if vt.v.is_unk() {
                            vt.t.type_value().and_then(|t| t.name().map(|n| (k, n)))
                        } else {
                            None
                        }
                    })
                })
            })
            .flatten()
        {
            let sfcn = &ftable[cbtable[bid].function()];
            callgraph.add_external_call(sfcn, ct);
        }
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, TypedFunctionAliases> {
        &self.mapping
    }

    pub fn analyse_function<'a, R>(project: &'a Project, f: &'a Function) -> TypedFunctionAliases
    where
        R: IntraContextualTypeResolver,
    {
        let resolver = R::resolve_with(project);
        Self::analyse_function_with(project, f, &resolver)
    }

    pub fn analyse_function_with_context<'a, 'c, R>(
        project: &'a Project,
        f: &'a Function,
        context: &mut AnalysisContext<'c>,
    ) -> TypedFunctionAliases
    where
        R: IntraContextualTypeResolver,
    {
        let resolver = R::resolve_with_context(project, context);
        Self::analyse_function_with(project, f, &resolver)
    }

    pub fn analyse_function_with<'a, 'b, R>(
        project: &'a Project,
        f: &'a Function,
        resolver: &'b R,
    ) -> TypedFunctionAliases
    where
        R: ContextualTypeResolver<'a>,
    {
        let mut gkmap = AHashMap::new();

        let functions = project.functions();
        let function_summaries = project.function_summaries();
        let injections = project.injections();
        let lifter = project.lifter();
        let typedb = resolver.types().unwrap_or(project.type_db());
        let memory = project.memory();
        let entry = f.entry();

        for blk in f.blocks_with(project.code_blocks()) {
            let mut context = AliasTypingContext::new(project);
            context.compute_incoming_map_with(f, blk.id() == entry, resolver);

            let init = TypedBlockAliases {
                incoming: context.registers,
                incoming_stack: context.stack_variables,
                incoming_symbol: context.symbol_variables,
                incoming_global: context.global_variables,
                outgoing: Default::default(),
                outgoing_stack: Default::default(),
                outgoing_symbol: Default::default(),
                outgoing_global: Default::default(),
                call_target: Default::default(),
                pre_call_state: Default::default(),
                condition: Default::default(),
                limit: 0,
            };

            gkmap.insert(blk.id(), init);
        }

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());
        let mut edge_visitor = cfg.visit_map();

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut context = AliasTypingContext::new_with(project, typedb);
            context.compute_incoming_map_with(f, blk.id() == entry, resolver);

            let mut nincoming = context.registers;
            let mut nincoming_stack = context.stack_variables;
            let mut nincoming_symbol = context.symbol_variables;
            let mut nincoming_global = context.global_variables;

            // NOTE: the origin for joined values here is problematic; what we are essentially
            // simulating is a phi variable assignment for each variable, and the ideal situation
            // would be that each such assignment happens at a separate location. However, we do
            // not have any phi variables, nor do we know which variables are seen at this point.
            //

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
                for (k, TypedAliasValue { v, t, o }) in pred.outgoing.iter() {
                    match nincoming.entry(*k) {
                        HEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), blk.address(), k);
                        }
                        HEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }

                for (k, TypedAliasValue { v, t, o }) in pred.outgoing_stack.iter() {
                    match nincoming_stack.entry(*k) {
                        BEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), blk.address(), *k);
                        }
                        BEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }

                for (k, TypedAliasValue { v, t, o }) in pred.outgoing_symbol.iter() {
                    match nincoming_symbol.entry(*k) {
                        HEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), blk.address(), k);
                        }
                        HEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }

                for (k, TypedAliasValue { v, t, o }) in pred.outgoing_global.iter() {
                    match nincoming_global.entry(*k) {
                        BEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), blk.address(), *k);
                        }
                        BEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }
            }

            let mut builder = TypedAliasVisitor::new_with(
                functions,
                function_summaries,
                injections,
                lifter,
                typedb,
                memory,
                nincoming.clone(),
                nincoming_stack.clone(),
                nincoming_symbol.clone(),
                nincoming_global.clone(),
                resolver,
            );

            for insn in blk.insns() {
                builder.eval_insn(insn);
            }

            let noutgoing = builder.rmapping;
            let noutgoing_stack = builder.smapping;
            let noutgoing_symbol = builder.nmapping;
            let noutgoing_global = builder.gmapping;
            let call_target = builder.call_target;
            let pre_call_state = builder.pre_call_state;
            let condition = builder.condition;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing != current.outgoing
                || noutgoing_stack != current.outgoing_stack
                || noutgoing_symbol != current.outgoing_symbol
                || noutgoing_global != current.outgoing_global
                || call_target != current.call_target
                || condition != current.condition;

            current.incoming = nincoming;
            current.incoming_stack = nincoming_stack;
            current.incoming_symbol = nincoming_symbol;
            current.incoming_global = nincoming_global;
            current.outgoing = noutgoing;
            current.outgoing_stack = noutgoing_stack;
            current.outgoing_symbol = noutgoing_symbol;
            current.outgoing_global = noutgoing_global;
            current.call_target = call_target;
            current.pre_call_state = pre_call_state;
            current.condition = condition;
            current.limit += 1;

            if did_change && current.limit < ALIAS_FUNCTION_CONTEXT_LIMIT {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        TypedFunctionAliases { blocks: gkmap }
    }

    pub fn analyse_project<R>(project: &Project) -> Self
    where
        R: InterContextualTypeResolver,
    {
        Self::from_slice::<R>(project, &CallGraph::new_with(&project))
    }

    pub fn analyse_project_with_context<'c, R>(
        project: &Project,
        context: &mut AnalysisContext<'c>,
    ) -> Self
    where
        R: InterContextualTypeResolver,
    {
        Self::from_slice_with_context::<R>(project, &CallGraph::new_with(project), context)
    }

    pub fn from_slice<R>(project: &Project, cg: &CallGraph) -> Self
    where
        R: InterContextualTypeResolver,
    {
        Self::from_slice_with::<R>(project, cg)
    }

    pub fn from_slice_with<R>(project: &Project, cg: &CallGraph) -> Self
    where
        R: InterContextualTypeResolver,
    {
        let mut context = AnalysisContext::default();
        Self::from_slice_with_context::<R>(project, cg, &mut context)
    }

    pub fn from_slice_with_context<'c, R>(
        project: &Project,
        cg: &CallGraph,
        context: &mut AnalysisContext<'c>,
    ) -> Self
    where
        R: InterContextualTypeResolver,
    {
        let mut func_info = IncomingContexts::new();
        let mut call_info = IncomingContexts::new();
        let mut call_site_info = AHashMap::<Address, AliasType>::new();

        let mut changed = true;
        let mut limit = 0;
        let mut slf = Self::default();

        while changed && limit < ALIAS_CONTEXT_LIMIT {
            changed = false;
            let mut visit = cg.post_ordered(&project);

            while let Some(f) = visit.next_filter_map(&**cg, |_, fx| {
                cg[fx].function(|id| &project.functions()[id])
            }) {
                let fid = f.id();
                let faddr = f.address();

                let aliases = if let Some(contexts) = call_info.get(&f.address()) {
                    let resolver = R::resolve_with_context(&project, contexts, &func_info, context);
                    TypedAliases::analyse_function_with(&project, f, &resolver)
                } else {
                    let t = Vec::with_capacity(0);
                    let resolver = R::resolve_with_context(&project, &t, &func_info, context);
                    TypedAliases::analyse_function_with(&project, f, &resolver)
                };

                func_info.entry(faddr).or_default().clear();

                for (block, refs) in aliases.blocks() {
                    let block = &project.code_blocks()[*block];

                    if let Some(addr) = refs.call_target().and_then(|vt| vt.v.value().to_address())
                    {
                        call_info.entry(addr).or_default().push(refs.to_owned());
                    }

                    if let Some(vt) = refs.call_target() {
                        let t = &vt.t;

                        match call_site_info.entry(block.address()) {
                            HEntry::Vacant(tt) => {
                                tt.insert(t.to_owned());
                                changed = true;
                            }
                            HEntry::Occupied(mut tt) => {
                                let old = tt.get_mut();
                                let ntype = t.to_owned().max(old.to_owned());
                                if *old != ntype {
                                    *old = ntype;
                                    changed = true;
                                }
                            }
                        }
                    }

                    if block.is_return() {
                        func_info.entry(faddr).or_default().push(refs.to_owned());
                    }
                }

                slf.mapping.insert(fid, aliases);
            }
            limit += 1;
        }

        slf
    }

    #[inline]
    pub fn analyse_slice<R>(&mut self, project: &mut Project, cg: &CallGraph, update_globals: bool)
    where
        R: InterContextualTypeResolver,
    {
        self.analyse_slice_with::<R>(project, cg, update_globals)
    }

    #[inline]
    pub fn analyse_slice_with<R>(
        &mut self,
        project: &mut Project,
        cg: &CallGraph,
        update_globals: bool,
    ) where
        R: InterContextualTypeResolver,
    {
        let mut context = AnalysisContext::default();
        self.analyse_slice_with_context::<R>(project, cg, update_globals, &mut context)
    }

    #[inline]
    pub fn analyse_slice_with_context<'c, R>(
        &mut self,
        project: &mut Project,
        cg: &CallGraph,
        update_globals: bool,
        context: &mut AnalysisContext<'c>,
    ) where
        R: InterContextualTypeResolver,
    {
        let mut func_info = IncomingContexts::new();
        let mut call_info = IncomingContexts::new();
        let mut call_site_info = AHashMap::<Address, AliasType>::new();

        let mut changed = true;
        let mut limit = 0;

        while changed && limit < ALIAS_CONTEXT_LIMIT {
            changed = false;
            let mut visit = cg.post_ordered(&project);

            while let Some(f) = visit.next_filter_map(&**cg, |_, fx| {
                cg[fx].function(|id| &project.functions()[id])
            }) {
                let fid = f.id();
                let faddr = f.address();

                let aliases = if let Some(contexts) = call_info.get(&f.address()) {
                    let resolver = R::resolve_with_context(&project, contexts, &func_info, context);
                    TypedAliases::analyse_function_with(&project, f, &resolver)
                } else {
                    let t = &Vec::with_capacity(0);
                    let resolver = R::resolve_with_context(&project, &t, &func_info, context);
                    TypedAliases::analyse_function_with(&project, f, &resolver)
                };

                func_info.entry(faddr).or_default().clear();

                for (block, refs) in aliases.blocks() {
                    let block = &project.code_blocks()[*block];

                    if let Some(addr) = refs.call_target().and_then(|vt| vt.v.value().to_address())
                    {
                        call_info.entry(addr).or_default().push(refs.to_owned());
                    }

                    if let Some(vt) = refs.call_target() {
                        let t = &vt.t;

                        match call_site_info.entry(block.address()) {
                            HEntry::Vacant(tt) => {
                                tt.insert(t.to_owned());
                                changed = true;
                            }
                            HEntry::Occupied(mut tt) => {
                                let old = tt.get_mut();
                                let ntype = t.to_owned().max(old.to_owned());
                                if *old != ntype {
                                    *old = ntype;
                                    changed = true;
                                }
                            }
                        }

                        // did the call site information change?
                        if self
                            .mapping
                            .get(&fid)
                            .and_then(|m| m.blocks().get(&block.id()))
                            .map(|old| old != refs)
                            .unwrap_or(true)
                        {
                            changed = true;
                        }
                    }

                    if block.is_return() {
                        func_info.entry(faddr).or_default().push(refs.to_owned());
                    }

                    if update_globals {
                        for (addr, vt) in refs.outgoing_globals() {
                            if let Some(tt) = vt.t.type_value() {
                                let tt = if let Some(ot) = project.type_db().get_data_type_at(*addr)
                                {
                                    if ot == *tt {
                                        continue;
                                    }

                                    tt.to_owned().max(ot)
                                } else {
                                    tt.to_owned()
                                };

                                project.type_db_mut().set_data_type_at(*addr, tt);
                            }
                        }
                    }
                }

                self.mapping.insert(fid, aliases);
            }
            limit += 1;
        }
    }

    #[inline]
    pub fn analyse_path<R>(project: &Project, path: &CodePath) -> TypedCodePathAliases
    where
        R: InterContextualTypeResolver,
    {
        let mut context = AnalysisContext::default();
        Self::analyse_path_with_context::<R>(project, path, &mut context)
    }

    #[inline]
    pub fn analyse_path_with_context<'a, 'c, R>(
        project: &'a Project,
        path: &CodePath,
        context: &mut AnalysisContext<'c>,
    ) -> TypedCodePathAliases
    where
        R: InterContextualTypeResolver,
    {
        let mut mapping = Vec::<TypedBlockAliases>::new();

        let lifter = project.lifter();
        let memory = project.memory();

        let blocks = project.code_blocks();
        let functions = project.functions();
        let function_summaries = project.function_summaries();
        let injections = project.injections();

        let contexts = Default::default();
        let rcontexts = Default::default();
        let resolver = R::resolve_with_context(&project, &contexts, &rcontexts, context);

        let typedb = resolver.types().unwrap_or(project.type_db());

        let mut last_function = None;

        for blk in path.iter() {
            let block = &blocks[*blk];

            let curr_function = block.function();
            let prev_function = last_function.replace(curr_function);

            let is_entry = !matches!(prev_function, Some(fid) if fid == curr_function);

            let mut context = AliasTypingContext::new(project);
            context.compute_incoming_map_with(&functions[curr_function], is_entry, &resolver);

            let mut current = TypedBlockAliases {
                incoming: context.registers,
                incoming_stack: context.stack_variables,
                incoming_symbol: context.symbol_variables,
                incoming_global: context.global_variables,
                outgoing: Default::default(),
                outgoing_stack: Default::default(),
                outgoing_symbol: Default::default(),
                outgoing_global: Default::default(),
                pre_call_state: Default::default(),
                call_target: Default::default(),
                condition: Default::default(),
                limit: 0,
            };

            if let Some(pred) = path.pred(blk).and_then(|pred| mapping.get(pred.index())) {
                for (k, TypedAliasValue { v, t, o }) in pred.outgoing.iter() {
                    match current.incoming.entry(*k) {
                        HEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), block.address(), k);
                        }
                        HEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }

                for (k, TypedAliasValue { v, t, o }) in pred.outgoing_stack.iter() {
                    match current.incoming_stack.entry(*k) {
                        BEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), block.address(), *k);
                        }
                        BEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }

                for (k, TypedAliasValue { v, t, o }) in pred.outgoing_symbol.iter() {
                    match current.incoming_symbol.entry(*k) {
                        HEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), block.address(), k);
                        }
                        HEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }

                for (k, TypedAliasValue { v, t, o }) in pred.outgoing_global.iter() {
                    match current.incoming_global.entry(*k) {
                        BEntry::Occupied(mut e) => {
                            let TypedAliasValue {
                                v: v0,
                                t: t0,
                                o: o0,
                            } = e.get_mut();
                            v0.join(v.to_owned());
                            t0.join(t.to_owned());
                            o0.join_phi(o.to_owned(), block.address(), *k);
                        }
                        BEntry::Vacant(e) => {
                            e.insert(TypedAliasValue {
                                v: v.to_owned(),
                                t: t.to_owned(),
                                o: o.to_owned(),
                            });
                        }
                    }
                }
            }

            let mut builder = TypedAliasVisitor::new_with(
                functions,
                function_summaries,
                injections,
                lifter,
                typedb,
                memory,
                current.incoming.clone(),
                current.incoming_stack.clone(),
                current.incoming_symbol.clone(),
                current.incoming_global.clone(),
                &resolver,
            );

            for insn in block.insns() {
                builder.eval_insn(insn);
            }

            current.outgoing = builder.rmapping;
            current.outgoing_stack = builder.smapping;
            current.outgoing_symbol = builder.nmapping;
            current.outgoing_global = builder.gmapping;
            current.call_target = builder.call_target;
            current.condition = builder.condition;

            mapping.push(current);
        }

        TypedCodePathAliases { mapping }
    }
}

pub struct ITypeResolver<'a, R>
where
    R: IntraContextualTypeResolver,
{
    resolver: R::Resolver<'a>,
    contexts: CallSiteContextsRef<'a>,
    rcontexts: IncomingContextsRef<'a>,
}

impl<'a, R> ITypeResolver<'a, R>
where
    R: IntraContextualTypeResolver,
{
    pub fn adjust_stack_delta(
        &self,
        context: &AliasTypingContext<'a>,
        v: &AliasValue,
        offset: i64,
    ) -> AliasValue {
        if let AliasValue::S(ref delta) = v {
            let mut delta = delta.to_owned();

            let xpop = BitVec::from_i64(
                context.lifter.default_prototype().extra_pop() as i64,
                delta.bits(),
            );
            let nspd = BitVec::from_i64(offset, delta.bits());

            delta -= nspd;
            delta -= xpop;

            AliasValue::S(delta)
        } else {
            v.to_owned()
        }
    }
}

impl<R> InterContextualTypeResolver for ITypeResolver<'_, R>
where
    R: IntraContextualTypeResolver,
{
    type Resolver<'a> = ITypeResolver<'a, R>;

    fn resolve_with_context<'a, 'c: 'a>(
        project: &'a Project,
        contexts: CallSiteContextsRef<'a>,
        rcontexts: IncomingContextsRef<'a>,
        context: &mut AnalysisContext<'c>,
    ) -> ITypeResolver<'a, R> {
        ITypeResolver {
            resolver: R::resolve_with_context(project, context),
            contexts,
            rcontexts,
        }
    }
}

impl<'a, R> ContextualTypeResolver<'a> for ITypeResolver<'a, R>
where
    R: IntraContextualTypeResolver,
{
    fn resolve_type_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        target: Option<Address>,
        t: &Term<Type>,
    ) -> Option<ResolvedType> {
        // This resolves external call type arguments;
        let mut t = self.resolver.resolve_type_with(context, target, t);
        if t.is_some() {
            return t;
        }

        if let Some(contexts) = target.and_then(|addr| self.rcontexts.get(&addr)) {
            // we can override the return, if it exists...
            let Operand::Register(retn) = context
                .lifter
                .default_prototype()
                .output_operand(0)
                .unwrap()
            else {
                return t;
            };

            let mut rett = None::<&AliasType>;
            for rcontext in contexts.iter() {
                if let Some(vt) = rcontext.outgoing().get(&retn) {
                    if let Some(vtt) = rett {
                        if *vtt != vt.t {
                            rett = None;
                            break;
                        }
                    } else {
                        rett = Some(&vt.t);
                    }
                } else {
                    rett = None;
                    break;
                }
            }

            if let Some(tt) = rett.take().and_then(|t| t.type_value()) {
                t = Some(ResolvedType::clobber(Type::function(
                    tt.to_owned(),
                    std::iter::empty::<FunctionArg>(),
                )));
            }
        }

        t
    }

    fn resolve_intrinsic_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        name: Ustr,
        arguments: Vec<TypedAliasValue>,
        bits: Option<u32>,
    ) -> Option<TypedAliasValue> {
        self.resolver
            .resolve_intrinsic_with(context, name, arguments, bits)
    }

    fn resolve_entry_type(&self, context: &mut AliasTypingContext<'a>, function: &'a Function) {
        self.resolver.resolve_entry_type(context, function);

        for ctx in self.contexts.iter() {
            if let Some(spd_shift) = ctx
                .outgoing()
                .get(&context.stack_pointer)
                .and_then(|sp| sp.v.stack_delta())
            {
                for (r, vt) in ctx.outgoing() {
                    if *r == context.stack_pointer {
                        continue; // do not override the stack pointer!!
                    }

                    let v = self.adjust_stack_delta(context, &vt.v, spd_shift);
                    let vt = TypedAliasValue::new(v, vt.t.to_owned(), vt.o.clone());

                    match context.registers.entry(*r) {
                        HEntry::Vacant(kv) => {
                            kv.insert(vt);
                        }
                        HEntry::Occupied(mut kv) => {
                            let ovt = kv.get_mut();
                            ovt.v.join(vt.v);
                            ovt.t = ovt.t.to_owned().max(vt.t);
                        }
                    }
                }
                let xpop = context.lifter.default_prototype().extra_pop() as i64;

                for (spd, vt) in ctx.outgoing_stack() {
                    let nspd = spd.wrapping_sub(spd_shift).wrapping_sub(xpop);

                    if nspd < 0 {
                        continue;
                    }

                    let v = self.adjust_stack_delta(context, &vt.v, spd_shift);
                    let vt = TypedAliasValue::new(v, vt.t.to_owned(), vt.o.clone());

                    match context.stack_variables.entry(nspd) {
                        BEntry::Vacant(kv) => {
                            kv.insert(vt);
                        }
                        BEntry::Occupied(mut kv) => {
                            let ovt = kv.get_mut();
                            ovt.v.join(vt.v);
                            ovt.t = ovt.t.to_owned().max(vt.t);
                        }
                    }
                }
            }
        }
    }
}
