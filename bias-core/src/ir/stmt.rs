use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::fmt;

use ahash::AHashMap as Map;
use fugue::bv::BitVec;
use fugue::ir::address::AddressValue;
use fugue::ir::disassembly::lift::UserOpStr;
use fugue::ir::disassembly::{ArenaVec, Opcode, VarnodeData};
use fugue::ir::space::{AddressSpace, AddressSpaceId};
use fugue::ir::space_manager::{FromSpace, IntoSpace, SpaceManager};
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use ustr::Ustr;

use crate::arch::Arch;
use crate::ir::term::arena::Arena;
use crate::ir::term::{Term, TermMut};
use crate::ir::traits::*;
use crate::ir::{BranchTarget, Expr, FloatKind, Location, ValHint, Var};
use crate::kb::AHashSet;

thread_local! {
    static STMT: Arena<Stmt> = Default::default();
}

pub(crate) fn collect_garbage() {
    STMT.with(|v| v.shrink_to_fit());
}

pub fn stats() -> (usize, usize) {
    STMT.with(|v| v.stats())
}

pub static POINTER_HINT: Lazy<Ustr> = Lazy::new(|| Ustr::from("pointer"));

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum Stmt {
    Assign(Var, Term<Expr>),

    Store(Term<Expr>, Term<Expr>, u32, AddressSpaceId), // SPACE[T]:SIZE <- T

    Branch(Term<BranchTarget>),
    CBranch(Term<Expr>, Term<BranchTarget>),

    Call(Term<BranchTarget>, SmallVec<[Term<Expr>; 2]>),
    Return(Term<BranchTarget>),

    Skip, // NO-OP

    Intrinsic(Ustr, SmallVec<[Term<Expr>; 2]>), // no output intrinsic

    PointerHint(Var),
}

impl From<Stmt> for Term<Stmt> {
    fn from(s: Stmt) -> Self {
        STMT.with(|a| Term::new(a, s))
    }
}

crate::impl_term_mut!(STMT for Stmt);

impl TermMut<Stmt> for Term<Stmt> {
    fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<Stmt>),
    {
        STMT.with(|a| self.update_with(a, |_, v| f(v)))
    }
}

impl fmt::Display for Stmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign(dest, src) => write!(f, "{} ← {}", dest, src),
            Self::Store(dest, src, size, spc) => {
                write!(f, "space[{}][{}]:{} ← {}", spc.index(), dest, size, src)
            }
            Self::Branch(target) => write!(f, "goto {}", target),
            Self::CBranch(cond, target) => write!(f, "goto {} if {}", target, cond),
            Self::Call(target, args) => {
                if !args.is_empty() {
                    write!(f, "call {}(", target)?;
                    write!(f, "{}", args[0])?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg)?;
                    }
                    write!(f, ")")
                } else {
                    write!(f, "call {}", target)
                }
            }
            Self::Return(target) => write!(f, "return {}", target),
            Self::Skip => write!(f, "skip"),
            Self::Intrinsic(name, args) => {
                write!(f, "{}(", name)?;
                if !args.is_empty() {
                    write!(f, "{}", args[0])?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg)?;
                    }
                }
                write!(f, ")")
            }
            Self::PointerHint(var) => write!(f, "hint:pointer({})", var),
        }
    }
}

impl<'stmt, 'trans> fmt::Display for StmtFormatter<'stmt, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.stmt {
            Stmt::Assign(dest, src) => write!(
                f,
                "{} {}←{} {}",
                dest.display_full(Cow::Borrowed(&*self.fmt)),
                self.fmt.keyword_start,
                self.fmt.keyword_end,
                src.display_full(Cow::Borrowed(&*self.fmt))
            ),
            Stmt::Store(dest, src, size, spc) => {
                if let Some(trans) = self.fmt.translator {
                    let space = unsafe { trans.manager().unchecked_space_by_id(*spc) };
                    write!(
                        f,
                        "{}{}{}[{}]:{}{}{} {}←{} {}",
                        self.fmt.variable_start,
                        space.name(),
                        self.fmt.variable_end,
                        dest.display_full(Cow::Borrowed(&*self.fmt)),
                        self.fmt.value_start,
                        size,
                        self.fmt.value_end,
                        self.fmt.keyword_start,
                        self.fmt.keyword_end,
                        src.display_full(Cow::Borrowed(&*self.fmt))
                    )
                } else {
                    write!(
                        f,
                        "{}space{}[{}{}{}][{}]:{}{}{} {}←{} {}",
                        self.fmt.variable_start,
                        self.fmt.variable_end,
                        self.fmt.value_start,
                        spc.index(),
                        self.fmt.value_end,
                        dest.display_full(Cow::Borrowed(&*self.fmt)),
                        self.fmt.value_start,
                        size,
                        self.fmt.value_end,
                        self.fmt.keyword_start,
                        self.fmt.keyword_end,
                        src.display_full(Cow::Borrowed(&*self.fmt))
                    )
                }
            }
            Stmt::Branch(target) => {
                write!(
                    f,
                    "{}goto{} {}",
                    self.fmt.keyword_start,
                    self.fmt.keyword_end,
                    target.display_full(Cow::Borrowed(&*self.fmt)),
                )
            }
            Stmt::CBranch(cond, target) => write!(
                f,
                "{}goto{} {} {}if{} {}",
                self.fmt.keyword_start,
                self.fmt.keyword_end,
                target.display_full(Cow::Borrowed(&*self.fmt)),
                self.fmt.keyword_start,
                self.fmt.keyword_end,
                cond.display_full(Cow::Borrowed(&*self.fmt))
            ),
            Stmt::Call(target, args) => {
                if !args.is_empty() {
                    write!(
                        f,
                        "{}call{} {}(",
                        self.fmt.keyword_start,
                        self.fmt.keyword_end,
                        target.display_full(Cow::Borrowed(&*self.fmt))
                    )?;
                    write!(f, "{}", args[0].display_full(Cow::Borrowed(&*self.fmt)))?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg.display_full(Cow::Borrowed(&*self.fmt)))?;
                    }
                    write!(f, ")")
                } else {
                    write!(
                        f,
                        "{}call{} {}",
                        self.fmt.keyword_start,
                        self.fmt.keyword_end,
                        target.display_full(Cow::Borrowed(&*self.fmt))
                    )
                }
            }
            Stmt::Return(target) => {
                write!(
                    f,
                    "{}return{} {}",
                    self.fmt.keyword_start,
                    self.fmt.keyword_end,
                    target.display_full(Cow::Borrowed(&*self.fmt))
                )
            }
            Stmt::Skip => write!(f, "{}skip{}", self.fmt.keyword_start, self.fmt.keyword_end),
            Stmt::Intrinsic(name, args) => {
                write!(f, "{}(", name)?;
                if !args.is_empty() {
                    write!(f, "{}", args[0].display_full(Cow::Borrowed(&*self.fmt)))?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg.display_full(Cow::Borrowed(&*self.fmt)))?;
                    }
                }
                write!(f, ")")
            }
            Stmt::PointerHint(var) => write!(
                f,
                "hint:pointer({})",
                var.display_full(Cow::Borrowed(&*self.fmt))
            ),
        }
    }
}

pub struct StmtFormatter<'stmt, 'trans> {
    stmt: &'stmt Stmt,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'stmt, 'trans> TranslatorDisplay<'stmt, 'trans> for Stmt {
    type Target = StmtFormatter<'stmt, 'trans>;

    fn display_full(
        &'stmt self,
        fmt: Cow<'trans, TranslatorFormatter<'trans>>,
    ) -> StmtFormatter<'stmt, 'trans> {
        StmtFormatter { stmt: self, fmt }
    }
}

pub type StmtCache = Map<Term<Stmt>, ()>;

impl Stmt {
    pub fn from_parts_with<'a>(
        manager: &SpaceManager,
        float_formats: &Map<u32, FloatKind>,
        user_ops: &[UserOpStr],
        address: &AddressValue,
        position: usize,
        opcode: Opcode,
        inputs: ArenaVec<'a, VarnodeData>,
        output: Option<VarnodeData>,
        cached: &mut Map<Term<Self>, ()>,
    ) -> Term<Self> {
        let stmt = Self::from_parts(
            manager,
            float_formats,
            user_ops,
            address,
            position,
            opcode,
            inputs,
            output,
        );

        match cached.entry(stmt) {
            Entry::Vacant(v) => {
                let k = v.key().to_owned();
                v.insert(());
                k
            }
            Entry::Occupied(v) => v.key().to_owned(),
        }
    }

    #[inline]
    pub fn from_parts<'a>(
        manager: &SpaceManager,
        float_formats: &Map<u32, FloatKind>,
        user_ops: &[UserOpStr],
        address: &AddressValue,
        position: usize,
        opcode: Opcode,
        inputs: ArenaVec<'a, VarnodeData>,
        output: Option<VarnodeData>,
    ) -> Term<Self> {
        let mut inputs = inputs.into_iter();
        let spaces = manager.spaces();
        match opcode {
            Opcode::Copy => Self::assign(
                output.unwrap(),
                Expr::from_space(inputs.next().unwrap(), manager),
            ),
            Opcode::Load => {
                let space = &spaces[inputs.next().unwrap().offset() as usize];
                let destination = output.unwrap();
                let source: Expr = inputs.next().unwrap().into_space(manager);
                let s: Term<Expr> = source.into();
                let size = destination.size() * 8;

                let src = if space.word_size() > 1 {
                    let bits = s.nbits();

                    let w = Expr::from(BitVec::from_usize(space.word_size(), bits as usize));

                    Expr::int_mul(s, w)
                } else {
                    s
                };

                Self::assign(destination, Expr::load(src, size as u32, space))
            }
            Opcode::Store => {
                let space = &spaces[inputs.next().unwrap().offset() as usize];
                let destination: Expr = inputs.next().unwrap().into_space(manager);
                let d: Term<Expr> = destination.into();
                let source = inputs.next().unwrap();
                let size = source.size() as u32 * 8;

                let dest = if space.word_size() > 1 {
                    let bits = d.nbits();

                    let w = Expr::from(BitVec::from_usize(space.word_size(), bits as usize));

                    Expr::int_mul(d, w)
                } else {
                    d
                };

                Self::store(dest, Expr::from_space(source, manager), size, space)
            }
            Opcode::Branch => {
                let target = Location::absolute_from(address, inputs.next().unwrap(), position);
                Self::branch(target)
            }
            Opcode::CBranch => {
                let target = Location::absolute_from(address, inputs.next().unwrap(), position);
                let condition = Expr::from_space(inputs.next().unwrap(), manager);

                Self::branch_conditional(condition, target)
            }
            Opcode::IBranch => {
                let target = Expr::from_space(inputs.next().unwrap(), manager);
                let space = unsafe { manager.unchecked_space_by_id(address.space()) };

                Self::branch_indirect(target, space)
            }
            Opcode::Call => {
                let target = Location::absolute_from(address, inputs.next().unwrap(), position);
                Self::call(target)
            }
            Opcode::ICall => {
                let target = Expr::from_space(inputs.next().unwrap(), manager);

                Self::call_indirect(target)
            }
            Opcode::CallOther => {
                let name = Ustr::from(&user_ops[inputs.next().unwrap().offset() as usize]);
                if let Some(output) = output {
                    let output = Var::from(output);
                    let bits = output.nbits();
                    Self::assign(
                        output,
                        Expr::intrinsic(
                            &*name,
                            inputs.into_iter().map(|v| Expr::from_space(v, manager)),
                            bits,
                        ),
                    )
                } else {
                    if name == *POINTER_HINT {
                        Self::PointerHint(Var::from(inputs.next().unwrap())).into()
                    } else {
                        Self::intrinsic(
                            &*name,
                            inputs.into_iter().map(|v| Expr::from_space(v, manager)),
                        )
                    }
                }
            }
            Opcode::Return => {
                let target = Expr::from_space(inputs.next().unwrap(), manager);
                let space = unsafe { manager.unchecked_space_by_id(address.space()) };

                Self::return_(target, space)
            }
            Opcode::Subpiece => {
                let source = Expr::from_space(inputs.next().unwrap(), manager);
                let src_size = source.nbits();

                let output = output.unwrap();
                let out_size = output.size() as u32 * 8;

                let loff = inputs.next().unwrap().offset() as u32 * 8;
                let trun_size = src_size.checked_sub(loff).unwrap_or(0);

                let trun = if out_size > trun_size {
                    // extract high + expand
                    let source_htrun = Expr::extract_high(source, trun_size);
                    Expr::cast_unsigned(source_htrun, out_size)
                } else {
                    // extract
                    let hoff = loff + out_size;
                    Expr::extract(source, loff, hoff)
                };

                Self::assign(output, trun)
            }
            Opcode::PopCount => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = Var::from(output.unwrap());

                let size = output.nbits();
                let popcount = Expr::count_ones(input, size);

                Self::assign(output, popcount)
            }
            Opcode::BoolNot => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::bool_not(input))
            }
            Opcode::BoolAnd => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::bool_and(input1, input2))
            }
            Opcode::BoolOr => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::bool_or(input1, input2))
            }
            Opcode::BoolXor => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::bool_xor(input1, input2))
            }
            Opcode::IntNeg => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_neg(input))
            }
            Opcode::IntNot => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_not(input))
            }
            Opcode::IntSExt => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();
                let size = output.size() as u32 * 8;

                Self::assign(output, Expr::cast_signed(input, size))
            }
            Opcode::IntZExt => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();
                let size = output.size() as u32 * 8;

                Self::assign(output, Expr::cast_unsigned(input, size))
            }
            Opcode::IntEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_eq(input1, input2))
            }
            Opcode::IntNotEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_neq(input1, input2))
            }
            Opcode::IntLess => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_lt(input1, input2))
            }
            Opcode::IntLessEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_le(input1, input2))
            }
            Opcode::IntSLess => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_slt(input1, input2))
            }
            Opcode::IntSLessEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_sle(input1, input2))
            }
            Opcode::IntCarry => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_carry(input1, input2))
            }
            Opcode::IntSCarry => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_scarry(input1, input2))
            }
            Opcode::IntSBorrow => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_sborrow(input1, input2))
            }
            Opcode::IntAdd => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_add(input1, input2))
            }
            Opcode::IntSub => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_sub(input1, input2))
            }
            Opcode::IntDiv => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_div(input1, input2))
            }
            Opcode::IntSDiv => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_sdiv(input1, input2))
            }
            Opcode::IntMul => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_mul(input1, input2))
            }
            Opcode::IntRem => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_rem(input1, input2))
            }
            Opcode::IntSRem => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_srem(input1, input2))
            }
            Opcode::IntLShift => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_shl(input1, input2))
            }
            Opcode::IntRShift => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_shr(input1, input2))
            }
            Opcode::IntSRShift => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_sar(input1, input2))
            }
            Opcode::IntAnd => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_and(input1, input2))
            }
            Opcode::IntOr => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_or(input1, input2))
            }
            Opcode::IntXor => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::int_xor(input1, input2))
            }
            Opcode::FloatIsNaN => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_nan(input, float_formats))
            }
            Opcode::FloatAbs => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_abs(input, float_formats))
            }
            Opcode::FloatNeg => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_neg(input, float_formats))
            }
            Opcode::FloatSqrt => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_sqrt(input, float_formats))
            }
            Opcode::FloatFloor => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_floor(input, float_formats))
            }
            Opcode::FloatCeiling => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_ceiling(input, float_formats))
            }
            Opcode::FloatRound => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_round(input, float_formats))
            }
            Opcode::FloatEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_eq(input1, input2, float_formats))
            }
            Opcode::FloatNotEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_neq(input1, input2, float_formats))
            }
            Opcode::FloatLess => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_lt(input1, input2, float_formats))
            }
            Opcode::FloatLessEq => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_le(input1, input2, float_formats))
            }
            Opcode::FloatAdd => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_add(input1, input2, float_formats))
            }
            Opcode::FloatSub => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_sub(input1, input2, float_formats))
            }
            Opcode::FloatDiv => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_div(input1, input2, float_formats))
            }
            Opcode::FloatMul => {
                let input1 = Expr::from_space(inputs.next().unwrap(), manager);
                let input2 = Expr::from_space(inputs.next().unwrap(), manager);
                let output = output.unwrap();

                Self::assign(output, Expr::float_mul(input1, input2, float_formats))
            }
            Opcode::FloatOfFloat => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let input_size = input.nbits();

                let output = Var::from(output.unwrap());
                let output_size = output.nbits();

                let input_format = float_formats[&input_size].clone();
                let output_format = float_formats[&output_size].clone();

                Self::assign(
                    output,
                    Expr::cast_float(Expr::cast_float(input, input_format), output_format),
                )
            }
            Opcode::FloatOfInt => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let input_size = input.nbits();

                let output = Var::from(output.unwrap());
                let output_size = output.nbits();

                let format = float_formats[&output_size].clone();
                Self::assign(
                    output,
                    Expr::cast_float(Expr::cast_signed(input, input_size), format),
                )
            }
            Opcode::FloatTruncate => {
                let input = Expr::from_space(inputs.next().unwrap(), manager);
                let input_size = input.nbits();

                let output = Var::from(output.unwrap());
                let output_size = output.nbits();

                let format = float_formats[&input_size].clone();
                Self::assign(
                    output,
                    Expr::cast_signed(Expr::cast_float(input, format), output_size),
                )
            }
            Opcode::Label => Self::skip(),
            Opcode::Build
            | Opcode::CrossBuild
            | Opcode::CPoolRef
            | Opcode::Piece
            | Opcode::Extract
            | Opcode::DelaySlot
            | Opcode::New
            | Opcode::Insert
            | Opcode::Cast
            | Opcode::SegmentOp => {
                panic!("unimplemented due to spec.")
            }
        }
    }
}

impl Stmt {
    pub fn assign<D, S>(destination: D, source: S) -> Term<Self>
    where
        D: Into<Var>,
        S: Into<Term<Expr>>,
    {
        let dest = destination.into();
        let bits = dest.nbits();
        Self::Assign(dest, Expr::cast_unsigned(source, bits)).into()
    }

    pub fn store<D, S>(destination: D, source: S, size: u32, space: &AddressSpace) -> Term<Self>
    where
        D: Into<Term<Expr>>,
        S: Into<Term<Expr>>,
    {
        Self::Store(
            Expr::cast_unsigned(destination.into(), space.address_size() as u32 * 8),
            source.into(),
            size,
            space.id(),
        )
        .into()
    }

    pub fn branch<T>(target: T) -> Term<Self>
    where
        T: Into<Term<BranchTarget>>,
    {
        Self::Branch(target.into()).into()
    }

    pub fn branch_conditional<C, T>(condition: C, target: T) -> Term<Self>
    where
        C: Into<Term<Expr>>,
        T: Into<Term<BranchTarget>>,
    {
        Self::CBranch(Expr::cast_bool(condition), target.into()).into()
    }

    pub fn branch_indirect<T>(target: T, _space: &AddressSpace) -> Term<Self>
    where
        T: Into<Term<Expr>>,
    {
        // let vptr = Type::pointer(Type::void(), space.address_size() as u32 * 8);

        // Self::Branch(BranchTarget::computed(Expr::Cast(target.into(), vptr))).into()

        Self::Branch(BranchTarget::computed(target.into())).into()
        /*
        Self::Branch(BranchTarget::computed(Expr::load(
            target,
            space.address_size() * 8,
            space,
        )))
        */
    }

    pub fn call<T>(target: T) -> Term<Self>
    where
        T: Into<Term<BranchTarget>>,
    {
        Self::Call(target.into(), Default::default()).into()
    }

    pub fn call_indirect<T>(target: T) -> Term<Self>
    where
        T: Into<Term<Expr>>,
    {
        Self::Call(BranchTarget::computed(target.into()), Default::default()).into()
    }

    pub fn call_with<T, I, E>(target: T, arguments: I) -> Term<Self>
    where
        T: Into<Term<BranchTarget>>,
        I: ExactSizeIterator<Item = E>,
        E: Into<Term<Expr>>,
    {
        let mut args = SmallVec::with_capacity(arguments.len());
        for arg in arguments.map(|e| e.into()) {
            args.push(arg);
        }

        Self::Call(target.into(), args).into()
    }

    pub fn call_indirect_with<T, I, E>(target: T, arguments: I) -> Term<Self>
    where
        T: Into<Term<Expr>>,
        I: ExactSizeIterator<Item = E>,
        E: Into<Term<Expr>>,
    {
        let mut args = SmallVec::with_capacity(arguments.len());
        for arg in arguments.map(|e| e.into()) {
            args.push(arg);
        }

        Self::Call(BranchTarget::computed(target.into()), args).into()
    }

    pub fn return_<T>(target: T, _space: &AddressSpace) -> Term<Self>
    where
        T: Into<Term<Expr>>,
    {
        // let vptr = Type::pointer(Type::void(), space.address_size() as u32 * 8);

        // Self::Return(BranchTarget::computed(Expr::Cast(target.into(), vptr))).into()
        Self::Return(BranchTarget::computed(target.into())).into()
        /*
            target,
            space.address_size() * 8,
            space,
        )))
        */
    }

    pub fn skip() -> Term<Self> {
        Self::Skip.into()
    }

    pub fn intrinsic<N, I, E>(name: N, arguments: I) -> Term<Self>
    where
        N: Into<Ustr>,
        I: ExactSizeIterator<Item = E>,
        E: Into<Term<Expr>>,
    {
        let mut args = SmallVec::with_capacity(arguments.len());
        for arg in arguments.map(|e| e.into()) {
            args.push(arg);
        }

        Self::Intrinsic(name.into(), args).into()
    }

    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            Stmt::Branch(_)
                | Stmt::CBranch(_, _)
                | Stmt::Call(_, _)
                | Stmt::Intrinsic(_, _)
                | Stmt::Return(_)
        )
    }

    pub fn is_jump(&self) -> bool {
        matches!(self, Stmt::Branch(_) | Stmt::CBranch(_, _))
    }

    pub fn is_indirect_jump(&self) -> bool {
        matches!(self, Stmt::Branch(bt) | Stmt::CBranch(_, bt) if !bt.is_fixed() && bt.is_computed_with(|ex| !ex.is_val()))
    }

    pub fn is_cond(&self) -> bool {
        matches!(self, Stmt::CBranch(_, _))
    }

    pub fn is_call(&self) -> bool {
        matches!(self, Stmt::Call(_, _))
    }

    pub fn is_indirect_call(&self) -> bool {
        matches!(self, Stmt::Call(bt, _) if !bt.is_fixed() && bt.is_computed_with(|ex| !ex.is_val()))
    }

    pub fn indirect_call_target(&self) -> Option<&Term<Expr>> {
        match self {
            Stmt::Call(bt, _) => match &**bt {
                BranchTarget::Computed(expr) => Some(expr),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn is_intrinsic(&self) -> bool {
        matches!(self, Stmt::Intrinsic(_, _))
    }

    pub fn has_fall(&self) -> bool {
        !matches!(self, Stmt::Branch(_) | Stmt::Return(_))
    }

    pub fn is_return(&self) -> bool {
        matches!(self, Stmt::Return(_))
    }

    pub fn is_skip(&self) -> bool {
        matches!(self, Stmt::Skip)
    }

    pub fn is_halt(&self, arch: &impl Arch) -> bool {
        matches!(self, Stmt::Intrinsic(s, a) if arch.is_halt_intrinsic(s.as_str(), a))
    }

    pub fn is_service_call(&self, arch: &impl Arch) -> bool {
        match self {
            Stmt::Intrinsic(s, a) => arch.is_service_call(s.as_str(), a),
            Stmt::Assign(_, e) => {
                matches!(&**e, Expr::Intrinsic(s, a, _) if arch.is_service_call(s.as_str(), a))
            }
            _ => false,
        }
    }

    pub fn is_semantic_skip(&self) -> bool {
        // Case 1: is a skip
        self.is_skip() ||
        // Case 2: is assignment to self
        matches!(self, Stmt::Assign(d, e) if e.is_var_with(|s| d == s))
    }

    pub fn has_load(&self) -> bool {
        struct Visitor {
            has_load: bool,
        }

        impl<'ir> Visit<'ir> for Visitor {
            fn visit_expr_load(
                &mut self,
                _source: &'ir Term<Expr>,
                _bits: u32,
                _space: AddressSpaceId,
            ) {
                self.has_load = true;
            }
        }

        let mut visit = Visitor { has_load: false };
        visit.visit_stmt_ref(self);
        visit.has_load
    }

    pub fn is_trap(&self, arch: &impl Arch) -> bool {
        struct Visitor<'a, T>
        where
            T: Arch,
        {
            arch: &'a T,
            is_trap: bool,
        }

        impl<'a, 'ir, T> Visit<'ir> for Visitor<'a, T>
        where
            T: Arch,
        {
            fn visit_intrinsic(&mut self, name: &'static str, args: &'ir [Term<Expr>], _bits: u32) {
                self.is_trap = self.arch.is_trap_intrinsic(name, args);
            }
        }

        let mut visit = Visitor {
            arch,
            is_trap: false,
        };
        visit.visit_stmt_ref(self);
        visit.is_trap
    }

    pub fn rhs(&self) -> Option<&Term<Expr>> {
        match self {
            Stmt::Assign(_, rhs) | Stmt::Store(_, rhs, _, _) => Some(rhs),
            _ => None,
        }
    }

    #[inline]
    pub fn constants_into<'ir>(&'ir self, into: &mut AHashSet<&'ir BitVec>) {
        struct Visitor<'a, 'ir> {
            consts: &'a mut AHashSet<&'ir BitVec>,
        }

        impl<'a, 'ir> Visit<'ir> for Visitor<'a, 'ir> {
            fn visit_expr_val(&mut self, val: &'ir BitVec, _hint: ValHint) {
                self.consts.insert(val);
            }
        }

        let mut visit = Visitor { consts: into };
        visit.visit_stmt_ref(self);
    }

    pub fn constants<'ir>(&'ir self) -> AHashSet<&'ir BitVec> {
        let mut consts = AHashSet::new();
        self.constants_into(&mut consts);
        consts
    }
}
