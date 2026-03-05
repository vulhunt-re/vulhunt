use std::ops::{Deref, DerefMut};

use fugue::bv::BitVec;
use fugue::ir::AddressSpaceId;
use smallvec::SmallVec;

use crate::ir::expr::ValHint;
use crate::ir::term::Term;
use crate::ir::{BinOp, BinRel, BranchTarget, Expr, Location, Stmt, Type, UnOp, UnRel, Var};
use crate::kb::function_summary::FunctionSummaryId;

#[allow(unused_variables)]
pub trait VisitMut {
    fn visit_var_mut(&mut self, expr: &mut Var) {}

    fn visit_branch_target_computed_mut(&mut self, target: &mut Term<Expr>) {
        self.visit_expr_mut(target)
    }

    fn visit_branch_target_location_mut(&mut self, target: &mut Location) {}

    fn visit_branch_target_external_mut(
        &mut self,
        target: &mut Term<Expr>,
        id: &mut FunctionSummaryId,
    ) {
        self.visit_expr_mut(target)
    }

    fn visit_branch_target_mut(&mut self, target: &mut Term<BranchTarget>) {
        match target.to_mut() {
            BranchTarget::External(ref mut target, ref mut id) => {
                self.visit_branch_target_external_mut(target, id)
            }
            BranchTarget::Computed(ref mut target) => self.visit_branch_target_computed_mut(target),
            BranchTarget::Location(ref mut location) => {
                self.visit_branch_target_location_mut(location)
            }
        }
    }

    fn visit_call_mut(
        &mut self,
        target: &mut Term<BranchTarget>,
        args: &mut [Term<Expr>],
        bits: u32,
    ) {
        for arg in args {
            self.visit_expr_mut(arg);
        }
        self.visit_branch_target_mut(target);
    }

    fn visit_intrinsic_mut(&mut self, name: &'static str, args: &mut [Term<Expr>], bits: u32) {
        for arg in args {
            self.visit_expr_mut(arg);
        }
    }

    fn visit_expr_var_mut(&mut self, var: &mut Var) {
        self.visit_var_mut(var)
    }

    fn visit_expr_val_mut(&mut self, val: &mut BitVec, hint: &mut ValHint) {}

    fn visit_expr_load_mut(&mut self, source: &mut Term<Expr>, bits: u32, space: AddressSpaceId) {
        self.visit_expr_mut(source);
    }

    fn visit_expr_cast_mut(&mut self, expr: &mut Term<Expr>, type_: &mut Term<Type>) {
        self.visit_expr_mut(expr);
    }

    fn visit_expr_binop_mut(&mut self, op: BinOp, lexpr: &mut Term<Expr>, rexpr: &mut Term<Expr>) {
        self.visit_expr_mut(lexpr);
        self.visit_expr_mut(rexpr);
    }

    fn visit_expr_binrel_mut(
        &mut self,
        rel: BinRel,
        lexpr: &mut Term<Expr>,
        rexpr: &mut Term<Expr>,
    ) {
        self.visit_expr_mut(lexpr);
        self.visit_expr_mut(rexpr);
    }

    fn visit_expr_unop_mut(&mut self, op: UnOp, expr: &mut Term<Expr>) {
        self.visit_expr_mut(expr);
    }

    fn visit_expr_unrel_mut(&mut self, rel: UnRel, expr: &mut Term<Expr>) {
        self.visit_expr_mut(expr);
    }

    fn visit_expr_ite_mut(
        &mut self,
        condition: &mut Term<Expr>,
        texpr: &mut Term<Expr>,
        fexpr: &mut Term<Expr>,
    ) {
        self.visit_expr_mut(condition);
        self.visit_expr_mut(texpr);
        self.visit_expr_mut(fexpr);
    }

    fn visit_expr_extract_mut(&mut self, expr: &mut Term<Expr>, lsb: u32, msb: u32) {
        self.visit_expr_mut(expr);
    }

    fn visit_expr_extract_high_mut(&mut self, expr: &mut Term<Expr>, bits: u32) {
        self.visit_expr_mut(expr);
    }

    fn visit_expr_extract_low_mut(&mut self, expr: &mut Term<Expr>, bits: u32) {
        self.visit_expr_mut(expr);
    }

    fn visit_expr_concat_mut(&mut self, lexpr: &mut Term<Expr>, rexpr: &mut Term<Expr>) {
        self.visit_expr_mut(lexpr);
        self.visit_expr_mut(rexpr);
    }

    fn visit_expr_choice_mut(
        &mut self,
        selector: &mut Term<Expr>,
        choices: &mut Vec<(BitVec, Term<Expr>)>,
        default: &mut Option<Term<Expr>>,
        bits: u32,
    ) {
        self.visit_expr_mut(selector);
        for (_, choice) in choices.iter_mut() {
            self.visit_expr_mut(choice);
        }
        if let Some(ref mut default) = default {
            self.visit_expr_mut(default)
        }
    }

    /*
    fn visit_expr_call_mut(
        &mut self,
        target: &mut Term<BranchTarget>,
        args: &mut [Term<Expr>],
        bits: u32,
    ) {
        self.visit_call_mut(target, args, bits)
    }
    */

    fn visit_expr_intrinsic_mut(&mut self, name: &'static str, args: &mut [Term<Expr>], bits: u32) {
        self.visit_intrinsic_mut(name, args, bits)
    }

    fn visit_expr_mut(&mut self, expr: &mut Term<Expr>) {
        match expr.to_mut() {
            Expr::Val(ref mut val, ref mut hint) => self.visit_expr_val_mut(val, hint),
            Expr::Var(ref mut var) => self.visit_expr_var_mut(var),
            Expr::Load(ref mut source, bits, space) => {
                self.visit_expr_load_mut(source, *bits, *space)
            }
            Expr::Cast(ref mut expr, ref mut type_) => self.visit_expr_cast_mut(expr, type_),
            Expr::BinOp(op, ref mut lexpr, ref mut rexpr) => {
                self.visit_expr_binop_mut(*op, lexpr, rexpr)
            }
            Expr::BinRel(rel, ref mut lexpr, ref mut rexpr) => {
                self.visit_expr_binrel_mut(*rel, lexpr, rexpr)
            }
            Expr::UnOp(op, ref mut expr) => self.visit_expr_unop_mut(*op, expr),
            Expr::UnRel(rel, ref mut expr) => self.visit_expr_unrel_mut(*rel, expr),
            Expr::IfElse(ref mut condition, ref mut texpr, ref mut fexpr) => {
                self.visit_expr_ite_mut(condition, texpr, fexpr)
            }
            Expr::Choice(ref mut sel, ref mut choices, ref mut default, bits) => {
                self.visit_expr_choice_mut(sel, choices, default, *bits)
            }
            Expr::Extract(ref mut expr, lsb, msb) => self.visit_expr_extract_mut(expr, *lsb, *msb),
            Expr::ExtractHigh(ref mut expr, bits) => self.visit_expr_extract_high_mut(expr, *bits),
            Expr::ExtractLow(ref mut expr, bits) => self.visit_expr_extract_low_mut(expr, *bits),
            Expr::Concat(ref mut lexpr, ref mut rexpr) => self.visit_expr_concat_mut(lexpr, rexpr),
            // Expr::Call(ref mut target, ref mut args, bits) => self.visit_expr_call_mut(target, args, bits),
            Expr::Intrinsic(ref mut name, ref mut args, bits) => {
                self.visit_expr_intrinsic_mut(name.as_str(), args, *bits)
            }
        }
    }

    fn visit_stmt_assign_mut(&mut self, var: &mut Var, expr: &mut Term<Expr>) {
        self.visit_expr_mut(expr);
        self.visit_var_mut(var);
    }

    fn visit_stmt_load_mut(
        &mut self,
        target: &mut Var,
        source: &mut Term<Expr>,
        bits: u32,
        space: AddressSpaceId,
    ) {
        self.visit_expr_load_mut(source, bits, space);
        self.visit_var_mut(target);
    }

    fn visit_stmt_store_mut(
        &mut self,
        target: &mut Term<Expr>,
        source: &mut Term<Expr>,
        bits: u32,
        space: AddressSpaceId,
    ) {
        self.visit_expr_mut(target);
        self.visit_expr_mut(source);
    }

    fn visit_stmt_branch_mut(&mut self, target: &mut Term<BranchTarget>) {
        self.visit_branch_target_mut(target);
    }

    fn visit_stmt_cbranch_mut(
        &mut self,
        condition: &mut Term<Expr>,
        target: &mut Term<BranchTarget>,
    ) {
        self.visit_expr_mut(condition);
        self.visit_branch_target_mut(target);
    }

    fn visit_stmt_call_mut(&mut self, target: &mut Term<BranchTarget>, args: &mut [Term<Expr>]) {
        self.visit_call_mut(target, args, 0)
    }

    fn visit_stmt_return_mut(&mut self, target: &mut Term<BranchTarget>) {
        self.visit_branch_target_mut(target);
    }

    fn visit_stmt_intrinsic_mut(&mut self, name: &'static str, args: &mut [Term<Expr>]) {
        self.visit_intrinsic_mut(name, args, 0)
    }

    fn visit_hint_pointer_mut(&mut self, expr: &mut Var) {
        self.visit_expr_var_mut(expr)
    }

    fn visit_stmt_mut(&mut self, stmt: &mut Term<Stmt>) {
        match stmt.to_mut() {
            Stmt::Assign(ref mut var, ref mut expr) => self.visit_stmt_assign_mut(var, expr),
            Stmt::Store(ref mut target, ref mut source, bits, space) => {
                self.visit_stmt_store_mut(target, source, *bits, *space)
            }
            Stmt::Branch(ref mut target) => self.visit_stmt_branch_mut(target),
            Stmt::CBranch(ref mut condition, ref mut target) => {
                self.visit_stmt_cbranch_mut(condition, target)
            }
            Stmt::Call(ref mut target, ref mut args) => self.visit_stmt_call_mut(target, args),
            Stmt::Return(ref mut target) => self.visit_stmt_return_mut(target),
            Stmt::Intrinsic(ref mut name, ref mut args) => {
                self.visit_stmt_intrinsic_mut(name.as_str(), args)
            }
            Stmt::PointerHint(ref mut var) => self.visit_hint_pointer_mut(var),
            Stmt::Skip => (),
        }
    }

    fn visit_phi_mut(&mut self, target: &mut Var, sources: &mut SmallVec<[Var; 2]>) {
        for source in sources {
            self.visit_expr_var_mut(source);
        }
        self.visit_var_mut(target);
    }

    fn visit_location(&mut self, target: Location) {}
}

pub trait VisitVarsMut {
    fn visit_def_mut(&mut self, var: &mut Var);
    fn visit_use_mut(&mut self, var: &mut Var);
}

pub struct VarsMutVisitor<'a, T>
where
    T: VisitVarsMut,
{
    visit: &'a mut T,
}

impl<'a, T> Deref for VarsMutVisitor<'a, T>
where
    T: VisitVarsMut,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.visit
    }
}

impl<'a, T> DerefMut for VarsMutVisitor<'a, T>
where
    T: VisitVarsMut,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.visit
    }
}

impl<'a, T> VarsMutVisitor<'a, T>
where
    T: VisitVarsMut,
{
    pub fn new(visit: &'a mut T) -> Self {
        Self { visit }
    }
}

impl<'a, T> VisitMut for VarsMutVisitor<'a, T>
where
    T: VisitVarsMut,
{
    fn visit_phi_mut(&mut self, target: &mut Var, sources: &mut SmallVec<[Var; 2]>) {
        for source in sources {
            self.visit.visit_use_mut(source);
        }
        self.visit.visit_def_mut(target);
    }

    fn visit_stmt_assign_mut(&mut self, var: &mut Var, expr: &mut Term<Expr>) {
        self.visit_expr_mut(expr);
        self.visit.visit_def_mut(var);
    }

    fn visit_stmt_load_mut(
        &mut self,
        target: &mut Var,
        source: &mut Term<Expr>,
        bits: u32,
        space: AddressSpaceId,
    ) {
        self.visit_expr_load_mut(source, bits, space);
        self.visit.visit_def_mut(target);
    }

    fn visit_expr_var_mut(&mut self, var: &mut Var) {
        self.visit.visit_use_mut(var);
    }
}

pub trait VarsSubst {
    fn subst_def(&mut self, var: Var, stmt: &mut Term<Stmt>);
    fn subst_use(&mut self, var: Var, expr: &mut Term<Expr>);

    #[allow(unused)]
    fn subst_phi_def(&mut self, var: &mut Var) {}
    #[allow(unused)]
    fn subst_phi_use(&mut self, var: &mut Var) {}
}

pub struct VarsSubstVisitor<'a, T>
where
    T: VarsSubst,
{
    visit: &'a mut T,
}

impl<'a, T> Deref for VarsSubstVisitor<'a, T>
where
    T: VarsSubst,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.visit
    }
}

impl<'a, T> DerefMut for VarsSubstVisitor<'a, T>
where
    T: VarsSubst,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.visit
    }
}

impl<'a, T> VarsSubstVisitor<'a, T>
where
    T: VarsSubst,
{
    pub fn new(visit: &'a mut T) -> Self {
        Self { visit }
    }
}

impl<'a, T> VisitMut for VarsSubstVisitor<'a, T>
where
    T: VarsSubst,
{
    fn visit_stmt_mut(&mut self, stmt: &mut Term<Stmt>) {
        match stmt.to_mut() {
            Stmt::Assign(var, ref mut expr) => {
                self.visit_expr_mut(expr);
                self.subst_def(*var, stmt);
            }
            Stmt::Store(ref mut target, ref mut source, bits, space) => {
                self.visit_stmt_store_mut(target, source, *bits, *space)
            }
            Stmt::Branch(ref mut target) => self.visit_stmt_branch_mut(target),
            Stmt::CBranch(ref mut condition, ref mut target) => {
                self.visit_stmt_cbranch_mut(condition, target)
            }
            Stmt::Call(ref mut target, ref mut args) => self.visit_stmt_call_mut(target, args),
            Stmt::Return(ref mut target) => self.visit_stmt_return_mut(target),
            Stmt::Intrinsic(ref mut name, ref mut args) => {
                self.visit_stmt_intrinsic_mut(name.as_str(), args)
            }
            Stmt::PointerHint(ref mut var) => self.visit_hint_pointer_mut(var),
            Stmt::Skip => (),
        }
    }

    fn visit_expr_mut(&mut self, expr: &mut Term<Expr>) {
        match expr.to_mut() {
            Expr::Val(ref mut val, ref mut hint) => self.visit_expr_val_mut(val, hint),
            Expr::Var(var) => self.subst_use(*var, expr),
            Expr::Cast(ref mut expr, ref mut type_) => self.visit_expr_cast_mut(expr, type_),
            Expr::Load(ref mut source, bits, space) => {
                self.visit_expr_load_mut(source, *bits, *space)
            }
            Expr::BinOp(op, ref mut lexpr, ref mut rexpr) => {
                self.visit_expr_binop_mut(*op, lexpr, rexpr)
            }
            Expr::BinRel(rel, ref mut lexpr, ref mut rexpr) => {
                self.visit_expr_binrel_mut(*rel, lexpr, rexpr)
            }
            Expr::UnOp(op, ref mut expr) => self.visit_expr_unop_mut(*op, expr),
            Expr::UnRel(rel, ref mut expr) => self.visit_expr_unrel_mut(*rel, expr),
            Expr::IfElse(ref mut condition, ref mut texpr, ref mut fexpr) => {
                self.visit_expr_ite_mut(condition, texpr, fexpr)
            }
            Expr::Choice(ref mut sel, ref mut choices, ref mut default, bits) => {
                self.visit_expr_choice_mut(sel, choices, default, *bits)
            }
            Expr::Extract(ref mut expr, lsb, msb) => self.visit_expr_extract_mut(expr, *lsb, *msb),
            Expr::ExtractHigh(ref mut expr, bits) => self.visit_expr_extract_high_mut(expr, *bits),
            Expr::ExtractLow(ref mut expr, bits) => self.visit_expr_extract_low_mut(expr, *bits),
            Expr::Concat(ref mut lexpr, ref mut rexpr) => self.visit_expr_concat_mut(lexpr, rexpr),
            Expr::Intrinsic(ref mut name, ref mut args, bits) => {
                self.visit_expr_intrinsic_mut(name.as_str(), args, *bits)
            }
        }
    }

    fn visit_phi_mut(&mut self, target: &mut Var, sources: &mut SmallVec<[Var; 2]>) {
        for source in sources {
            self.visit.subst_phi_use(source);
        }
        self.visit.subst_phi_def(target);
    }
}

pub trait VisitOpVarsMut {
    fn visit_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut;

    #[allow(unused)]
    fn visit_phi_vars_mut<V>(&mut self, visitor: &mut V)
    where
        V: VisitVarsMut,
    {
    }
}
