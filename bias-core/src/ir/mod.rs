pub use crate::fugue::bv::BitVec;
pub use crate::fugue::bytes::Order;
pub use crate::fugue::ir::Address;

pub mod branch;
pub use branch::{BranchTarget, BranchTargetFormatter};

pub mod expr;
pub use expr::{BinOp, BinRel, Expr, ExprFormatter, UnOp, UnRel, ValHint};

pub mod insn;
pub use insn::{Insn, InsnFormatter, InsnTarget};

pub mod location;
pub use location::Location;

pub mod stmt;
pub use stmt::{Stmt, StmtFormatter};

pub mod traits;
pub use traits::*;

pub mod term;
pub use term::{Term, TermMut};

pub mod types;
pub use types::{
    EnumVariant, FloatKind, FunctionArg, FunctionArgProps, StructField, Type, TypeKind,
    UnionVariant,
};

pub mod var;
pub use var::{SimpleVar, Var, VarFormatter, VarView};

pub fn collect_garbage() {
    insn::collect_garbage();
    stmt::collect_garbage();
    branch::collect_garbage();
    types::collect_garbage();
    expr::collect_garbage();
}
