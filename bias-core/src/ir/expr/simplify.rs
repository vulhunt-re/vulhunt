use std::iter::once;

use crate::ir::expr::BinOp;
use crate::ir::{Expr, Term};

pub trait ExprRewrite {
    fn apply_rewrite<'a>(&mut self, expr: &'a Term<Expr>) -> Option<Term<Expr>>;
}

pub struct ExprRewriter {
    rules: Vec<Box<dyn ExprRewrite>>,
    complexity_bound: usize,
}

impl Default for ExprRewriter {
    fn default() -> Self {
        Self {
            rules: vec![Box::new(ExprAssocCommReduce::default())],
            complexity_bound: 10,
        }
    }
}

impl ExprRewriter {
    pub fn new() -> Self {
        Self {
            rules: Vec::with_capacity(0),
            ..Default::default()
        }
    }

    pub fn new_with(complexity_bound: usize) -> Self {
        Self {
            rules: Vec::with_capacity(0),
            complexity_bound,
        }
    }

    pub fn push<R>(&mut self, rule: R)
    where
        R: ExprRewrite + 'static,
    {
        self.rules.push(Box::new(rule))
    }

    pub fn apply(&mut self, expr: &Term<Expr>) -> Term<Expr> {
        let mut changed = true;
        let mut curr = expr.clone();

        if self.complexity_bound > 0 && expr.size() > self.complexity_bound {
            return expr.clone();
        }

        while changed {
            changed = false;

            // visit child expressions
            if let Some(ncurr) = self.apply_visit(&curr) {
                curr = ncurr;
                changed = true;
            }

            // visit this expression
            for rule in self.rules.iter_mut() {
                if let Some(ncurr) = rule.apply_rewrite(&curr) {
                    if curr != ncurr {
                        curr = ncurr;
                        changed = true;
                    }
                }
            }
        }

        curr
    }

    fn apply_then(&mut self, expr: &Term<Expr>) -> Option<Term<Expr>> {
        let nexpr = self.apply(expr);
        if *expr != nexpr {
            Some(nexpr)
        } else {
            None
        }
    }

    fn apply_visit(&mut self, expr: &Term<Expr>) -> Option<Term<Expr>> {
        match &**expr {
            Expr::Cast(e, c) => {
                if let Some(e) = self.apply_then(e) {
                    Some(c.apply(e))
                } else {
                    None
                }
            }
            Expr::UnOp(op, e) => {
                if let Some(e) = self.apply_then(e) {
                    Some(op.apply(e))
                } else {
                    None
                }
            }
            Expr::UnRel(op, e) => {
                if let Some(e) = self.apply_then(e) {
                    Some(op.apply(e))
                } else {
                    None
                }
            }
            Expr::BinOp(op, l, r) => match (self.apply_then(l), self.apply_then(r)) {
                (None, None) => None,
                (Some(nl), None) => Some(op.apply(nl, r.clone())),
                (None, Some(nr)) => Some(op.apply(l.clone(), nr)),
                (Some(nl), Some(nr)) => Some(op.apply(nl, nr)),
            },
            Expr::BinRel(op, l, r) => match (self.apply_then(l), self.apply_then(r)) {
                (None, None) => None,
                (Some(nl), None) => Some(op.apply(nl, r.clone())),
                (None, Some(nr)) => Some(op.apply(l.clone(), nr)),
                (Some(nl), Some(nr)) => Some(op.apply(nl, nr)),
            },
            Expr::Concat(l, r) => match (self.apply_then(l), self.apply_then(r)) {
                (None, None) => None,
                (Some(nl), None) => Some(Expr::concat(nl, r.clone())),
                (None, Some(nr)) => Some(Expr::concat(l.clone(), nr)),
                (Some(nl), Some(nr)) => Some(Expr::concat(nl, nr)),
            },
            Expr::Extract(e, loff, moff) => {
                if let Some(e) = self.apply_then(e) {
                    Some(Expr::extract(e, *loff, *moff))
                } else {
                    None
                }
            }
            Expr::ExtractLow(e, bits) => {
                if let Some(e) = self.apply_then(e) {
                    Some(Expr::extract_low(e, *bits))
                } else {
                    None
                }
            }
            Expr::ExtractHigh(e, bits) => {
                if let Some(e) = self.apply_then(e) {
                    Some(Expr::extract_high(e, *bits))
                } else {
                    None
                }
            }
            Expr::IfElse(b, t, f) => {
                let nb = self.apply_then(b);
                let nt = self.apply_then(t);
                let nf = self.apply_then(f);

                if nb.is_some() || nt.is_some() || nf.is_some() {
                    let nb = nb.unwrap_or_else(|| b.clone());
                    let nt = nt.unwrap_or_else(|| t.clone());
                    let nf = nf.unwrap_or_else(|| f.clone());

                    Some(Expr::ite(nb, nt, nf))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn flatten_binop<'a>(expr: &'a Term<Expr>, into: &mut Vec<Term<Expr>>) -> Option<BinOp> {
        if let Expr::BinOp(op, l, r) = &**expr {
            if op.is_associative() {
                Self::flatten_binop_with(l, *op, into);
                Self::flatten_binop_with(r, *op, into);
                return Some(*op);
            }
        }
        None
    }

    fn flatten_binop_with<'a>(expr: &'a Term<Expr>, op: BinOp, into: &mut Vec<Term<Expr>>) {
        if let Expr::BinOp(op1, l, r) = &**expr {
            if *op1 == op {
                Self::flatten_binop_with(l, op, into);
                Self::flatten_binop_with(r, op, into);
                return;
            }
        }
        into.push(expr.clone());
    }
}

#[derive(Default)]
pub struct ExprAssocCommReduce {
    cache: Vec<Term<Expr>>,
}

impl ExprRewrite for ExprAssocCommReduce {
    fn apply_rewrite<'a>(&mut self, expr: &'a Term<Expr>) -> Option<Term<Expr>> {
        self.cache.clear();
        if let Some(op) = ExprRewriter::flatten_binop(expr, &mut self.cache) {
            if op.is_commutative() {
                self.cache.sort_unstable();

                let val_split = self.cache.iter().position(|t| !t.is_val());

                if matches!(val_split, Some(split) if split > 1) {
                    // multiple values
                    let val_split = val_split.unwrap();
                    let mut it = self.cache.drain(..);

                    let val = (&mut it).take(val_split).reduce(|l, r| op.apply(l, r))?;

                    it.rev()
                        .chain(once(val).into_iter())
                        .reduce(|l, r| op.apply(l, r))
                } else {
                    self.cache.drain(..).rev().reduce(|l, r| op.apply(l, r))
                }
            } else {
                self.cache.drain(..).reduce(|l, r| op.apply(l, r))
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use fugue::bytes::{BE, LE};
    use fugue::ir::AddressSpace;

    use super::*;
    use crate::ir::{Expr, Var};

    #[test]
    fn test_simplify() {
        let mut simplifier = ExprRewriter::default();
        let spc = AddressSpace::unique("uniq", 0, None);

        let x = simplifier.apply(&Expr::int_add(
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
        ));

        let y = simplifier.apply(&Expr::int_add(
            Expr::val(10u32),
            Expr::int_add(
                Expr::val(99u32),
                Expr::int_add(Expr::val(44u32), Expr::val(32u32)),
            ),
        ));

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

        assert_eq!(simplifier.apply(&t), simplifier.apply(&z));

        let z = Expr::concat_with::<LE, _, _>(
            Expr::extract(t.clone(), 24, 32),
            Expr::concat_with::<LE, _, _>(
                Expr::extract(t.clone(), 16, 24),
                Expr::extract(t.clone(), 0, 16),
            ),
        );

        assert_eq!(simplifier.apply(&t), simplifier.apply(&z));

        let var0 = Var::new0(&spc, 0, 32);

        let v1 = Expr::int_add(
            Expr::int_add(Expr::val(0x20u32), Expr::var(var0)),
            Expr::int_add(Expr::val(0x10u32), Expr::var(var0)),
        );

        let v2 = Expr::int_add(
            Expr::int_add(Expr::var(var0), Expr::var(var0)),
            Expr::val(0x30u32),
        );

        assert_eq!(simplifier.apply(&v1), simplifier.apply(&v2));
    }
}
