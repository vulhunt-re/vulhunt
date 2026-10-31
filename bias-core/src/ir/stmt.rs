use std::borrow::Cow;
use std::fmt;

use ahash::AHashMap as Map;
use fugue::bv::BitVec;
use fugue::lifter::runtime::language::Language;
use fugue::lifter::runtime::pcode::{Op, PCodeOp, Varnode};
use fugue::sleigh::language::spaces::AddressSpaceId;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use ustr::Ustr;

use crate::arch::Arch;
use crate::ir::term::arena::Arena;
use crate::ir::term::{Term, TermMut};
use crate::ir::traits::*;
use crate::ir::{Address, BranchTarget, Expr, FloatKind, Location, ValHint, Var};
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
                if let Some(space_name) = self
                    .fmt
                    .language
                    .and_then(|language| language.space_name(spc.index() as u8))
                {
                    write!(
                        f,
                        "{}{}{}[{}]:{}{}{} {}←{} {}",
                        self.fmt.variable_start,
                        space_name,
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
    fmt: Cow<'trans, LanguageFormatter<'trans>>,
}

impl<'stmt, 'trans> LanguageDisplay<'stmt, 'trans> for Stmt {
    type Target = StmtFormatter<'stmt, 'trans>;

    fn display_full(
        &'stmt self,
        fmt: Cow<'trans, LanguageFormatter<'trans>>,
    ) -> StmtFormatter<'stmt, 'trans> {
        StmtFormatter { stmt: self, fmt }
    }
}

pub type StmtCache = Map<Term<Stmt>, ()>;

impl Stmt {
    pub fn from_pcode<'a>(
        language: &'static Language,
        float_formats: &'a Map<u32, FloatKind>,
        address: Address,
        operations: &'a [PCodeOp],
    ) -> impl Iterator<Item = Term<Self>> + 'a {
        operations
            .iter()
            .enumerate()
            .filter(|(_, operation)| !operation.is_arg())
            .map(move |(index, _)| {
                Self::from_pcode_op(language, float_formats, address, operations, index)
            })
    }

    fn from_pcode_op(
        language: &'static Language,
        float_formats: &Map<u32, FloatKind>,
        address: Address,
        operations: &[PCodeOp],
        index: usize,
    ) -> Term<Self> {
        let operation = &operations[index];
        let inputs = operation.inputs();

        let input = |n: usize| Expr::from_varnode(language, &inputs[n]);
        let output = || {
            Var::from_varnode(
                language,
                operation.output().expect("p-code operation has an output"),
            )
        };

        match operation.op() {
            Op::Copy => Self::assign(output(), input(0)),
            Op::Load(space) => {
                let output = output();
                let source = Term::from(input(0));
                let word_size = language
                    .space_word_size(space)
                    .expect("load space is defined by the language");

                let source = if word_size > 1 {
                    let bits = source.nbits();
                    let w = Expr::from(BitVec::from_usize(word_size, bits));
                    Expr::int_mul(source, w)
                } else {
                    source
                };

                let size = output.nbits();
                Self::assign(
                    output,
                    Expr::load(
                        source,
                        size,
                        language.space_id(space),
                        space_address_bits(language, space),
                    ),
                )
            }
            Op::Store(space) => {
                let destination = Term::from(input(0));
                let size = inputs[1].size() as u32 * 8;
                let word_size = language
                    .space_word_size(space)
                    .expect("store space is defined by the language");

                let destination = if word_size > 1 {
                    let bits = destination.nbits();
                    let w = Expr::from(BitVec::from_usize(word_size, bits));
                    Expr::int_mul(destination, w)
                } else {
                    destination
                };

                Self::store(
                    destination,
                    input(1),
                    size,
                    language.space_id(space),
                    space_address_bits(language, space),
                )
            }
            Op::Branch => Self::branch(branch_location(
                language, address, operations, index, &inputs[0],
            )),
            Op::CBranch => Self::branch_conditional(
                input(1),
                branch_location(language, address, operations, index, &inputs[0]),
            ),
            Op::IBranch => Self::branch_indirect(input(0)),
            Op::Call => Self::call(branch_location(
                language, address, operations, index, &inputs[0],
            )),
            Op::ICall => Self::call_indirect(input(0)),
            Op::UserOp(id, _) => {
                let name = language
                    .user_op_by_id(id)
                    .expect("user-op is defined by the language");
                let spilled = &operations[index + 1..index + 1 + operation.spill()];
                let arguments = inputs
                    .iter()
                    .chain(spilled.iter().flat_map(PCodeOp::inputs))
                    .map(|varnode| Expr::from_varnode(language, varnode))
                    .collect::<SmallVec<[Expr; 4]>>();

                if operation.output().is_some() {
                    let output = output();
                    let bits = output.nbits();
                    Self::assign(output, Expr::intrinsic(name, arguments.into_iter(), bits))
                } else if name == POINTER_HINT.as_str() {
                    Self::PointerHint(Var::from_varnode(language, &inputs[0])).into()
                } else {
                    Self::intrinsic(name, arguments.into_iter())
                }
            }
            Op::Return => Self::return_(input(0)),
            Op::Subpiece => {
                let source = input(0);
                let src_size = source.nbits();

                let output = output();
                let out_size = output.nbits();

                let loff = inputs[1].offset() as u32 * 8;
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
            Op::CountOnes => {
                let output = output();
                let size = output.nbits();
                Self::assign(output, Expr::count_ones(input(0), size))
            }
            Op::CountLeadingZeros => {
                let input = Term::from(input(0));
                let bits = input.nbits();

                let mut smeared = input;
                let mut shift = 1;
                while shift < bits {
                    let amount = Expr::from(BitVec::from_u32(shift, bits));
                    smeared = Expr::int_or(smeared.clone(), Expr::int_shr(smeared, amount));
                    shift <<= 1;
                }

                let output = output();
                let size = output.nbits();
                Self::assign(output, Expr::count_ones(Expr::int_not(smeared), size))
            }
            Op::BoolNot => Self::assign(output(), Expr::bool_not(input(0))),
            Op::BoolAnd => Self::assign(output(), Expr::bool_and(input(0), input(1))),
            Op::BoolOr => Self::assign(output(), Expr::bool_or(input(0), input(1))),
            Op::BoolXor => Self::assign(output(), Expr::bool_xor(input(0), input(1))),
            Op::IntNeg => Self::assign(output(), Expr::int_neg(input(0))),
            Op::IntNot => Self::assign(output(), Expr::int_not(input(0))),
            Op::SignExt => {
                let output = output();
                let size = output.nbits();
                Self::assign(output, Expr::cast_signed(input(0), size))
            }
            Op::ZeroExt => {
                let output = output();
                let size = output.nbits();
                Self::assign(output, Expr::cast_unsigned(input(0), size))
            }
            Op::IntEq => Self::assign(output(), Expr::int_eq(input(0), input(1))),
            Op::IntNotEq => Self::assign(output(), Expr::int_neq(input(0), input(1))),
            Op::IntLess => Self::assign(output(), Expr::int_lt(input(0), input(1))),
            Op::IntLessEq => Self::assign(output(), Expr::int_le(input(0), input(1))),
            Op::IntSignedLess => Self::assign(output(), Expr::int_slt(input(0), input(1))),
            Op::IntSignedLessEq => Self::assign(output(), Expr::int_sle(input(0), input(1))),
            Op::IntCarry => Self::assign(output(), Expr::int_carry(input(0), input(1))),
            Op::IntSignedCarry => Self::assign(output(), Expr::int_scarry(input(0), input(1))),
            Op::IntSignedBorrow => Self::assign(output(), Expr::int_sborrow(input(0), input(1))),
            Op::IntAdd => Self::assign(output(), Expr::int_add(input(0), input(1))),
            Op::IntSub => Self::assign(output(), Expr::int_sub(input(0), input(1))),
            Op::IntDiv => Self::assign(output(), Expr::int_div(input(0), input(1))),
            Op::IntSignedDiv => Self::assign(output(), Expr::int_sdiv(input(0), input(1))),
            Op::IntMul => Self::assign(output(), Expr::int_mul(input(0), input(1))),
            Op::IntRem => Self::assign(output(), Expr::int_rem(input(0), input(1))),
            Op::IntSignedRem => Self::assign(output(), Expr::int_srem(input(0), input(1))),
            Op::IntLeftShift => Self::assign(output(), Expr::int_shl(input(0), input(1))),
            Op::IntRightShift => Self::assign(output(), Expr::int_shr(input(0), input(1))),
            Op::IntSignedRightShift => Self::assign(output(), Expr::int_sar(input(0), input(1))),
            Op::IntAnd => Self::assign(output(), Expr::int_and(input(0), input(1))),
            Op::IntOr => Self::assign(output(), Expr::int_or(input(0), input(1))),
            Op::IntXor => Self::assign(output(), Expr::int_xor(input(0), input(1))),
            Op::FloatIsNaN => Self::assign(output(), Expr::float_nan(input(0), float_formats)),
            Op::FloatAbs => Self::assign(output(), Expr::float_abs(input(0), float_formats)),
            Op::FloatNeg => Self::assign(output(), Expr::float_neg(input(0), float_formats)),
            Op::FloatSqrt => Self::assign(output(), Expr::float_sqrt(input(0), float_formats)),
            Op::FloatFloor => Self::assign(output(), Expr::float_floor(input(0), float_formats)),
            Op::FloatCeiling => {
                Self::assign(output(), Expr::float_ceiling(input(0), float_formats))
            }
            Op::FloatRound => Self::assign(output(), Expr::float_round(input(0), float_formats)),
            Op::FloatEq => {
                Self::assign(output(), Expr::float_eq(input(0), input(1), float_formats))
            }
            Op::FloatNotEq => {
                Self::assign(output(), Expr::float_neq(input(0), input(1), float_formats))
            }
            Op::FloatLess => {
                Self::assign(output(), Expr::float_lt(input(0), input(1), float_formats))
            }
            Op::FloatLessEq => {
                Self::assign(output(), Expr::float_le(input(0), input(1), float_formats))
            }
            Op::FloatAdd => {
                Self::assign(output(), Expr::float_add(input(0), input(1), float_formats))
            }
            Op::FloatSub => {
                Self::assign(output(), Expr::float_sub(input(0), input(1), float_formats))
            }
            Op::FloatDiv => {
                Self::assign(output(), Expr::float_div(input(0), input(1), float_formats))
            }
            Op::FloatMul => {
                Self::assign(output(), Expr::float_mul(input(0), input(1), float_formats))
            }
            Op::FloatToFloat => {
                let input = input(0);
                let input_size = input.nbits();

                let output = output();
                let output_size = output.nbits();

                let input_format = float_formats[&input_size].clone();
                let output_format = float_formats[&output_size].clone();

                Self::assign(
                    output,
                    Expr::cast_float(Expr::cast_float(input, input_format), output_format),
                )
            }
            Op::IntToFloat => {
                let input = input(0);
                let input_size = input.nbits();

                let output = output();
                let output_size = output.nbits();

                let format = float_formats[&output_size].clone();
                Self::assign(
                    output,
                    Expr::cast_float(Expr::cast_signed(input, input_size), format),
                )
            }
            Op::FloatToInt => {
                let input = input(0);
                let input_size = input.nbits();

                let output = output();
                let output_size = output.nbits();

                let format = float_formats[&input_size].clone();
                Self::assign(
                    output,
                    Expr::cast_signed(Expr::cast_float(input, format), output_size),
                )
            }
            Op::Arg => unreachable!("spilled user-op arguments are lowered with their user-op"),
        }
    }
}

fn branch_location(
    language: &Language,
    address: Address,
    operations: &[PCodeOp],
    index: usize,
    target: &Varnode,
) -> Location {
    if !language.in_constant_space(target) {
        return Location::new(target.offset(), 0);
    }

    let shift = u64::BITS.saturating_sub(target.size() as u32 * 8);
    let offset = ((target.offset() << shift) as i64) >> shift;

    let position = index
        .checked_add_signed(offset as isize)
        .and_then(|target| {
            let spilled = operations
                .get(..target)?
                .iter()
                .filter(|operation| operation.is_arg());
            Some(target - spilled.count())
        })
        .expect("relative branch target within instruction");

    Location::new(address, position)
}

fn space_address_bits(language: &Language, space: u8) -> u32 {
    let highest = language
        .space_upper_bound(space)
        .expect("space is defined by the language");
    let word_size = language
        .space_word_size(space)
        .expect("space is defined by the language") as u64;
    (u64::BITS - (highest / word_size).leading_zeros()).div_ceil(8) * 8
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

    pub fn store<D, S>(
        destination: D,
        source: S,
        size: u32,
        space: AddressSpaceId,
        address_bits: u32,
    ) -> Term<Self>
    where
        D: Into<Term<Expr>>,
        S: Into<Term<Expr>>,
    {
        Self::Store(
            Expr::cast_unsigned(destination.into(), address_bits),
            source.into(),
            size,
            space,
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

    pub fn branch_indirect<T>(target: T) -> Term<Self>
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

    pub fn return_<T>(target: T) -> Term<Self>
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
