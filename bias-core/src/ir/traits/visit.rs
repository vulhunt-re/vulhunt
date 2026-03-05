use std::ops::{Deref, DerefMut};

use fugue::bv::BitVec;
use fugue::ir::AddressSpaceId;

use crate::ir::expr::ValHint;
use crate::ir::term::Term;
use crate::ir::{BinOp, BinRel, BranchTarget, Expr, Location, Stmt, Type, UnOp, UnRel, Var};
use crate::kb::function_summary::FunctionSummaryId;

#[allow(unused_variables)]
pub trait Visit<'ir> {
    fn visit_var(&mut self, expr: &'ir Var) {}

    fn visit_branch_target_computed(&mut self, target: &'ir Term<Expr>) {
        self.visit_expr(target)
    }

    fn visit_branch_target_location(&mut self, target: &'ir Location) {}

    fn visit_branch_target_external(
        &mut self,
        target: &'ir Term<Expr>,
        id: &'ir FunctionSummaryId,
    ) {
        self.visit_expr(target)
    }

    fn visit_branch_target(&mut self, target: &'ir Term<BranchTarget>) {
        match **target {
            BranchTarget::External(ref target, ref id) => {
                self.visit_branch_target_external(target, id)
            }
            BranchTarget::Computed(ref target) => self.visit_branch_target_computed(target),
            BranchTarget::Location(ref location) => self.visit_branch_target_location(location),
        }
    }

    fn visit_call(&mut self, target: &'ir Term<BranchTarget>, args: &'ir [Term<Expr>], bits: u32) {
        for arg in args {
            self.visit_expr(arg);
        }
        self.visit_branch_target(target);
    }

    fn visit_intrinsic(&mut self, name: &'static str, args: &'ir [Term<Expr>], bits: u32) {
        for arg in args {
            self.visit_expr(arg);
        }
    }

    fn visit_expr_var(&mut self, var: &'ir Var) {
        self.visit_var(var)
    }

    fn visit_expr_val(&mut self, val: &'ir BitVec, hint: ValHint) {}

    fn visit_expr_load(&mut self, source: &'ir Term<Expr>, bits: u32, space: AddressSpaceId) {
        self.visit_expr(source);
    }

    fn visit_expr_cast(&mut self, expr: &'ir Term<Expr>, type_: &'ir Term<Type>) {
        self.visit_expr(expr);
    }

    fn visit_expr_binop(&mut self, op: BinOp, lexpr: &'ir Term<Expr>, rexpr: &'ir Term<Expr>) {
        self.visit_expr(lexpr);
        self.visit_expr(rexpr);
    }

    fn visit_expr_binrel(&mut self, rel: BinRel, lexpr: &'ir Term<Expr>, rexpr: &'ir Term<Expr>) {
        self.visit_expr(lexpr);
        self.visit_expr(rexpr);
    }

    fn visit_expr_unop(&mut self, op: UnOp, expr: &'ir Term<Expr>) {
        self.visit_expr(expr);
    }

    fn visit_expr_unrel(&mut self, rel: UnRel, expr: &'ir Term<Expr>) {
        self.visit_expr(expr);
    }

    fn visit_expr_ite(
        &mut self,
        condition: &'ir Term<Expr>,
        texpr: &'ir Term<Expr>,
        fexpr: &'ir Term<Expr>,
    ) {
        self.visit_expr(condition);
        self.visit_expr(texpr);
        self.visit_expr(fexpr);
    }

    fn visit_expr_extract(&mut self, expr: &'ir Term<Expr>, lsb: u32, msb: u32) {
        self.visit_expr(expr);
    }

    fn visit_expr_extract_high(&mut self, expr: &'ir Term<Expr>, bits: u32) {
        self.visit_expr(expr);
    }

    fn visit_expr_extract_low(&mut self, expr: &'ir Term<Expr>, bits: u32) {
        self.visit_expr(expr);
    }

    fn visit_expr_concat(&mut self, lexpr: &'ir Term<Expr>, rexpr: &'ir Term<Expr>) {
        self.visit_expr(lexpr);
        self.visit_expr(rexpr);
    }

    fn visit_expr_choice(
        &mut self,
        selector: &'ir Term<Expr>,
        choices: &'ir Vec<(BitVec, Term<Expr>)>,
        default: &'ir Option<Term<Expr>>,
        bits: u32,
    ) {
        self.visit_expr(selector);
        for (_, choice) in choices.iter() {
            self.visit_expr(choice);
        }
        if let Some(ref default) = default {
            self.visit_expr(default)
        }
    }

    /*
    fn visit_expr_call(
        &mut self,
        target: &'ir Term<BranchTarget>,
        args: &'ir [Term<Expr>],
        bits: u32,
    ) {
        self.visit_call(target, args, bits)
    }
    */

    fn visit_expr_intrinsic(&mut self, name: &'static str, args: &'ir [Term<Expr>], bits: u32) {
        self.visit_intrinsic(name, args, bits)
    }

    fn visit_expr(&mut self, expr: &'ir Term<Expr>) {
        match **expr {
            Expr::Val(ref val, hint) => self.visit_expr_val(val, hint),
            Expr::Var(ref var) => self.visit_expr_var(var),
            Expr::Load(ref source, bits, space) => self.visit_expr_load(source, bits, space),
            Expr::Cast(ref expr, ref type_) => self.visit_expr_cast(expr, type_),
            Expr::BinOp(op, ref lexpr, ref rexpr) => self.visit_expr_binop(op, lexpr, rexpr),
            Expr::BinRel(rel, ref lexpr, ref rexpr) => self.visit_expr_binrel(rel, lexpr, rexpr),
            Expr::UnOp(op, ref expr) => self.visit_expr_unop(op, expr),
            Expr::UnRel(rel, ref expr) => self.visit_expr_unrel(rel, expr),
            Expr::IfElse(ref condition, ref texpr, ref fexpr) => {
                self.visit_expr_ite(condition, texpr, fexpr)
            }
            Expr::Choice(ref sel, ref choices, ref default, bits) => {
                self.visit_expr_choice(sel, choices, default, bits)
            }
            Expr::Extract(ref expr, lsb, msb) => self.visit_expr_extract(expr, lsb, msb),
            Expr::ExtractHigh(ref expr, bits) => self.visit_expr_extract_high(expr, bits),
            Expr::ExtractLow(ref expr, bits) => self.visit_expr_extract_low(expr, bits),
            Expr::Concat(ref lexpr, ref rexpr) => self.visit_expr_concat(lexpr, rexpr),
            // Expr::Call(ref target, ref args, bits) => self.visit_expr_call(target, args, bits),
            Expr::Intrinsic(ref name, ref args, bits) => {
                self.visit_expr_intrinsic(name.as_str(), args, bits)
            }
        }
    }

    fn visit_stmt_assign(&mut self, var: &'ir Var, expr: &'ir Term<Expr>) {
        self.visit_expr(expr);
        self.visit_var(var);
    }

    fn visit_stmt_store(
        &mut self,
        target: &'ir Term<Expr>,
        source: &'ir Term<Expr>,
        bits: u32,
        space: AddressSpaceId,
    ) {
        self.visit_expr(source);
        self.visit_expr(target);
    }

    fn visit_stmt_branch(&mut self, target: &'ir Term<BranchTarget>) {
        self.visit_branch_target(target);
    }

    fn visit_stmt_cbranch(&mut self, condition: &'ir Term<Expr>, target: &'ir Term<BranchTarget>) {
        self.visit_expr(condition);
        self.visit_branch_target(target);
    }

    fn visit_stmt_call(&mut self, target: &'ir Term<BranchTarget>, args: &'ir [Term<Expr>]) {
        self.visit_call(target, args, 0)
    }

    fn visit_stmt_return(&mut self, target: &'ir Term<BranchTarget>) {
        self.visit_branch_target(target);
    }

    fn visit_stmt_intrinsic(&mut self, name: &'static str, args: &'ir [Term<Expr>]) {
        self.visit_intrinsic(name, args, 0)
    }

    fn visit_hint_pointer(&mut self, expr: &'ir Var) {
        self.visit_expr_var(expr)
    }

    fn visit_stmt(&mut self, stmt: &'ir Term<Stmt>) {
        self.visit_stmt_ref(stmt)
    }

    fn visit_stmt_ref(&mut self, stmt: &'ir Stmt) {
        match *stmt {
            Stmt::Assign(ref var, ref expr) => self.visit_stmt_assign(var, expr),
            Stmt::Store(ref target, ref source, bits, space) => {
                self.visit_stmt_store(target, source, bits, space)
            }
            Stmt::Branch(ref target) => self.visit_stmt_branch(target),
            Stmt::CBranch(ref condition, ref target) => self.visit_stmt_cbranch(condition, target),
            Stmt::Call(ref target, ref args) => self.visit_stmt_call(target, args),
            Stmt::Return(ref target) => self.visit_stmt_return(target),
            Stmt::Intrinsic(ref name, ref args) => self.visit_stmt_intrinsic(name.as_str(), args),
            Stmt::PointerHint(ref var) => self.visit_hint_pointer(var),
            Stmt::Skip => (),
        }
    }

    fn visit_phi(&mut self, target: &'ir Var, sources: &'ir [Var]) {
        for source in sources {
            self.visit_expr_var(source);
        }
        self.visit_var(target);
    }

    fn visit_location(&mut self, target: Location) {}
}

pub trait VisitVars<'ir> {
    #[allow(unused)]
    fn visit_def(&mut self, var: &'ir Var) {}
    #[allow(unused)]
    fn visit_def_at(&mut self, loc: Location, var: &'ir Var) {
        self.visit_def(var);
    }

    #[allow(unused)]
    fn visit_use(&mut self, var: &'ir Var) {}
    #[allow(unused)]
    fn visit_use_at(&mut self, loc: Location, var: &'ir Var) {
        self.visit_use(var);
    }
}

pub struct VarsVisitor<'a, T> {
    location: Option<Location>,
    visit: &'a mut T,
}

impl<'a, T> Deref for VarsVisitor<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.visit
    }
}

impl<'a, T> DerefMut for VarsVisitor<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.visit
    }
}

impl<'a, T> VarsVisitor<'a, T> {
    pub fn new_from<L>(location: L, visit: &'a mut T) -> Self
    where
        L: Into<Option<Location>>,
    {
        Self {
            location: location.into(),
            visit,
        }
    }

    pub fn new(visit: &'a mut T) -> Self {
        Self::new_from(None, visit)
    }
}

impl<'a, 'ir, T> Visit<'ir> for VarsVisitor<'a, T>
where
    T: VisitVars<'ir>,
{
    fn visit_location(&mut self, target: Location) {
        self.location = Some(target);
    }

    fn visit_phi(&mut self, target: &'ir Var, sources: &'ir [Var]) {
        if let Some(location) = self.location {
            for source in sources {
                self.visit.visit_use_at(location, source);
            }
            self.visit.visit_def_at(location, target);
        } else {
            for source in sources {
                self.visit.visit_use(source);
            }
            self.visit.visit_def(target);
        }
    }

    fn visit_stmt_assign(&mut self, var: &'ir Var, expr: &'ir Term<Expr>) {
        self.visit_expr(expr);
        if let Some(location) = self.location {
            self.visit.visit_def_at(location, var);
        } else {
            self.visit.visit_def(var);
        }
    }

    fn visit_expr_var(&mut self, var: &'ir Var) {
        if let Some(location) = self.location {
            self.visit.visit_use_at(location, var);
        } else {
            self.visit.visit_use(var);
        }
    }
}
