use smallvec::SmallVec;

use crate::ir::traits::*;
use crate::ir::var::VarViews;
use crate::ir::{Address, Expr, Insn, SimpleVar, Stmt, Term, Var};
use crate::kb::block::CodeBlock;
use crate::kb::function::Function;
use crate::Project;

struct AllVariables<'a, 'b> {
    views: &'a mut VarViews<'b>,
}

impl<'a, 'b, 'ir> VisitVars<'ir> for AllVariables<'a, 'b> {
    fn visit_def(&mut self, var: &'ir Var) {
        self.views.insert(SimpleVar(*var));
    }

    fn visit_use(&mut self, var: &'ir Var) {
        self.views.insert(SimpleVar(*var));
    }
}

pub struct VariableAliasNormaliserVisitor<'v> {
    classes: VarViews<'v>,
}

impl<'v> VariableAliasNormaliserVisitor<'v> {
    #[allow(dead_code)]
    pub fn transform_insns<'a, I: 'a, F>(insns: I, mut f: F)
    where
        I: Iterator<Item = &'a Term<Insn>>,
        F: FnMut(Address, &[Term<Stmt>]),
    {
        let mut ops = SmallVec::<[Term<Stmt>; 6]>::default();
        let mut slf = Self {
            classes: Default::default(),
        };

        for insn in insns {
            insn.visit_vars(&mut AllVariables {
                views: &mut slf.classes,
            });

            ops.clone_from(&insn.operations);

            for op in ops.iter_mut() {
                slf.visit_stmt_mut(op)
            }

            f(insn.address(), &ops)
        }
    }

    pub fn transform_each<F>(function: &Function, project: &Project, mut f: F)
    where
        F: FnMut(CodeBlock),
    {
        let mut views = VarViews::default();
        for blk in function.blocks_with(project.code_blocks()) {
            // this visit excludes existing phis
            blk.visit_insn_vars(&mut AllVariables { views: &mut views });
        }
        let mut slf = Self { classes: views };

        for mut blk in function.blocks_with(project.code_blocks()).cloned() {
            blk.phis_mut().clear();
            for insn in blk.insns_mut() {
                for op in insn.operations_mut() {
                    slf.visit_stmt_mut(op);
                }
            }
            f(blk)
        }
    }
}

impl<'v> VisitMut for VariableAliasNormaliserVisitor<'v> {
    fn visit_expr_mut(&mut self, expr: &mut Term<Expr>) {
        match expr.to_mut() {
            Expr::UnRel(op, ref mut expr) => self.visit_expr_unrel_mut(*op, expr),
            Expr::UnOp(op, ref mut expr) => self.visit_expr_unop_mut(*op, expr),
            Expr::Load(ref mut expr, bits, spc) => self.visit_expr_load_mut(expr, *bits, *spc),
            Expr::BinRel(op, ref mut lexpr, ref mut rexpr) => {
                self.visit_expr_binrel_mut(*op, lexpr, rexpr)
            }
            Expr::BinOp(op, ref mut lexpr, ref mut rexpr) => {
                self.visit_expr_binop_mut(*op, lexpr, rexpr)
            }
            Expr::Cast(ref mut expr, ref mut cast) => self.visit_expr_cast_mut(expr, cast),
            Expr::ExtractLow(ref mut expr, bits) => self.visit_expr_extract_low_mut(expr, *bits),
            Expr::ExtractHigh(ref mut expr, bits) => self.visit_expr_extract_high_mut(expr, *bits),
            Expr::Extract(ref mut expr, lsb, msb) => self.visit_expr_extract_mut(expr, *lsb, *msb),
            Expr::Concat(ref mut lexpr, ref mut rexpr) => self.visit_expr_concat_mut(lexpr, rexpr),
            Expr::IfElse(ref mut cond, ref mut texpr, ref mut fexpr) => {
                self.visit_expr_ite_mut(cond, texpr, fexpr)
            }
            Expr::Intrinsic(name, ref mut args, bits) => {
                self.visit_expr_intrinsic_mut(name.as_str(), args, *bits)
            }
            Expr::Var(var) => {
                let svar = SimpleVar(*var);
                let pvar = self.classes.enclosing(svar);

                let rvar = *pvar;
                let mut exprv = Expr::var(rvar);

                Expr::resize_with(&mut exprv, &pvar, &svar);

                *expr = exprv;
            }
            _ => (),
        }
    }

    fn visit_stmt_assign_mut(&mut self, var: &mut Var, expr: &mut Term<Expr>) {
        self.visit_expr_mut(expr);

        let svar = SimpleVar(*var);
        let pvar = self.classes.enclosing(svar);
        let rvar = Var::new(pvar.space(), pvar.offset(), pvar.nbits(), var.generation());

        Expr::resize_with(expr, &svar, &pvar);

        *var = rvar;
    }
}
