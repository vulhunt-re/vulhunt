use std::{fmt::Display, ops::Deref};

use crate::prelude::*;
use hashcons_arena::HRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BitVecRef<'a>(HRef<'a, BitVec>);

impl AsRef<BitVec> for BitVecRef<'_> {
    fn as_ref(&self) -> &BitVec {
        self.0.as_ref()
    }
}

impl Deref for BitVecRef<'_> {
    type Target = BitVec;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<'a> From<HRef<'a, BitVec>> for BitVecRef<'a> {
    fn from(href: HRef<'a, BitVec>) -> Self {
        Self(href)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SSExprRef<'a>(HRef<'a, SSExpr<'a>>);

impl<'a> AsRef<SSExpr<'a>> for SSExprRef<'a> {
    fn as_ref(&self) -> &SSExpr<'a> {
        self.0.as_ref()
    }
}

impl<'a> Deref for SSExprRef<'a> {
    type Target = SSExpr<'a>;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<'a> From<HRef<'a, SSExpr<'a>>> for SSExprRef<'a> {
    fn from(href: HRef<'a, SSExpr<'a>>) -> Self {
        Self(href)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cast {
    Bool,
    Signed(u32),
    Unsigned(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SSExpr<'a> {
    Val(BitVecRef<'a>),
    Var(Var),

    Cast(SSExprRef<'a>, Cast),

    UnOp(UnOp, SSExprRef<'a>),
    UnRel(UnRel, SSExprRef<'a>),

    BinOp(BinOp, [SSExprRef<'a>; 2]),
    BinRel(BinRel, [SSExprRef<'a>; 2]),

    Extract(SSExprRef<'a>, u32, u32),
    Concat([SSExprRef<'a>; 2]),

    Load(SSExprRef<'a>, u32),
    Store(SSExprRef<'a>, u32),
}

pub struct SSExprDisplay<'a> {
    expr: &'a SSExprRef<'a>,
    project: &'a Project,
}

impl<'a> SSExprRef<'a> {
    pub fn display(&'a self, project: &'a Project) -> SSExprDisplay<'a> {
        SSExprDisplay::new(self, project)
    }
}

impl<'a> SSExprDisplay<'a> {
    pub fn new(expr: &'a SSExprRef<'a>, project: &'a Project) -> Self {
        Self { expr, project }
    }

    fn fmt_sse_l0(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::Val(bv) => bv.fmt(f),
            SSExpr::Var(var) => var.display(self.project).fmt(f),
            SSExpr::Cast(e, c) => {
                Self::new(e, self.project).fmt_sse_l1(f)?;
                match c {
                    Cast::Bool => f.write_str(" as bool"),
                    Cast::Signed(bits) => write!(f, " as int{bits}"),
                    Cast::Unsigned(bits) => write!(f, " as uint{bits}"),
                }
            }
            SSExpr::Store(e, _bits) => write!(f, "store({})", e.display(self.project)),
            SSExpr::Load(e, _bits) => write!(f, "load({})", e.display(self.project)),
            SSExpr::Extract(e, loff, hoff) => {
                write!(f, "extract({}, {loff}, {hoff})", e.display(self.project))
            }
            SSExpr::Concat([e1, e2]) => write!(
                f,
                "concat({}, {})",
                e1.display(self.project),
                e2.display(self.project)
            ),
            SSExpr::UnOp(UnOp::ABS, e) => write!(f, "abs({})", e.display(self.project)),
            SSExpr::UnOp(UnOp::SQRT, e) => write!(f, "sqrt({})", e.display(self.project)),
            SSExpr::UnOp(UnOp::ROUND, e) => write!(f, "round({})", e.display(self.project)),
            SSExpr::UnOp(UnOp::CEILING, e) => write!(f, "ceiling({})", e.display(self.project)),
            SSExpr::UnOp(UnOp::FLOOR, e) => write!(f, "floor({})", e.display(self.project)),
            SSExpr::UnOp(UnOp::POPCOUNT(_bits), e) => {
                write!(f, "popcount({})", e.display(self.project))
            }
            SSExpr::UnRel(UnRel::NAN, e) => write!(f, "is-nan({})", e.display(self.project)),
            SSExpr::BinRel(BinRel::CARRY, [e1, e2]) => write!(
                f,
                "carry({}, {})",
                e1.display(self.project),
                e2.display(self.project)
            ),
            SSExpr::BinRel(BinRel::SCARRY, [e1, e2]) => write!(
                f,
                "scarry({}, {})",
                e1.display(self.project),
                e2.display(self.project)
            ),
            SSExpr::BinRel(BinRel::SBORROW, [e1, e2]) => write!(
                f,
                "sborrow({}, {})",
                e1.display(self.project),
                e2.display(self.project)
            ),
            _ => write!(f, "({})", self),
        }
    }

    fn fmt_sse_l1(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::UnOp(UnOp::NEG, e) => {
                f.write_str("-")?;
                Self::new(e, self.project).fmt_sse_l0(f)
            }
            SSExpr::UnOp(UnOp::NOT, e) => {
                f.write_str("!")?;
                Self::new(e, self.project).fmt_sse_l0(f)
            }
            _ => self.fmt_sse_l0(f),
        }
    }

    fn fmt_sse_l2(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinOp(BinOp::MUL, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l2(f)?;
                f.write_str(" * ")?;
                Self::new(e2, self.project).fmt_sse_l1(f)
            }
            SSExpr::BinOp(BinOp::DIV, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l2(f)?;
                f.write_str(" / ")?;
                Self::new(e2, self.project).fmt_sse_l1(f)
            }
            SSExpr::BinOp(BinOp::SDIV, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l2(f)?;
                f.write_str(" s/ ")?;
                Self::new(e2, self.project).fmt_sse_l1(f)
            }
            SSExpr::BinOp(BinOp::REM, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l2(f)?;
                f.write_str(" % ")?;
                Self::new(e2, self.project).fmt_sse_l1(f)
            }
            SSExpr::BinOp(BinOp::SREM, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l2(f)?;
                f.write_str(" s% ")?;
                Self::new(e2, self.project).fmt_sse_l1(f)
            }
            _ => self.fmt_sse_l1(f),
        }
    }

    fn fmt_sse_l3(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinOp(BinOp::ADD, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l3(f)?;
                f.write_str(" + ")?;
                Self::new(e2, self.project).fmt_sse_l2(f)
            }
            SSExpr::BinOp(BinOp::SUB, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l3(f)?;
                f.write_str(" - ")?;
                Self::new(e2, self.project).fmt_sse_l2(f)
            }
            _ => self.fmt_sse_l2(f),
        }
    }

    fn fmt_sse_l4(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinOp(BinOp::SHL, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l4(f)?;
                f.write_str(" << ")?;
                Self::new(e2, self.project).fmt_sse_l3(f)
            }
            SSExpr::BinOp(BinOp::SHR, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l4(f)?;
                f.write_str(" >> ")?;
                Self::new(e2, self.project).fmt_sse_l3(f)
            }
            SSExpr::BinOp(BinOp::SAR, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l4(f)?;
                f.write_str(" s>> ")?;
                Self::new(e2, self.project).fmt_sse_l3(f)
            }
            _ => self.fmt_sse_l3(f),
        }
    }

    fn fmt_sse_l5(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinRel(BinRel::LT, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l5(f)?;
                f.write_str(" < ")?;
                Self::new(e2, self.project).fmt_sse_l4(f)
            }
            SSExpr::BinRel(BinRel::LE, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l5(f)?;
                f.write_str(" <= ")?;
                Self::new(e2, self.project).fmt_sse_l4(f)
            }
            SSExpr::BinRel(BinRel::SLT, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l5(f)?;
                f.write_str(" s< ")?;
                Self::new(e2, self.project).fmt_sse_l4(f)
            }
            SSExpr::BinRel(BinRel::SLE, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l5(f)?;
                f.write_str(" s<= ")?;
                Self::new(e2, self.project).fmt_sse_l4(f)
            }
            _ => self.fmt_sse_l4(f),
        }
    }

    fn fmt_sse_l6(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinRel(BinRel::EQ, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l6(f)?;
                f.write_str(" = ")?;
                Self::new(e2, self.project).fmt_sse_l5(f)
            }
            SSExpr::BinRel(BinRel::NEQ, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l6(f)?;
                f.write_str(" != ")?;
                Self::new(e2, self.project).fmt_sse_l5(f)
            }
            _ => self.fmt_sse_l5(f),
        }
    }

    fn fmt_sse_l7(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinOp(BinOp::AND, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l7(f)?;
                f.write_str(" & ")?;
                Self::new(e2, self.project).fmt_sse_l6(f)
            }
            _ => self.fmt_sse_l6(f),
        }
    }

    fn fmt_sse_l8(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinOp(BinOp::XOR, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l8(f)?;
                f.write_str(" ^ ")?;
                Self::new(e2, self.project).fmt_sse_l7(f)
            }
            _ => self.fmt_sse_l7(f),
        }
    }

    fn fmt_sse_l9(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &**self.expr {
            SSExpr::BinOp(BinOp::OR, [e1, e2]) => {
                Self::new(e1, self.project).fmt_sse_l9(f)?;
                f.write_str(" | ")?;
                Self::new(e2, self.project).fmt_sse_l8(f)
            }
            _ => self.fmt_sse_l8(f),
        }
    }
}

impl Display for SSExprDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_sse_l9(f)
    }
}
