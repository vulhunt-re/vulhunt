use std::cmp::Ordering;
use std::str::FromStr;

use egg::{
    Analysis, CostFunction, EGraph, ENodeOrVar, Extractor, Id, Language, LanguageChildren, Pattern,
    PatternAst, RecExpr, Rewrite, Runner, Var as PatternVar,
};

use crate::fugue::ir::AddressSpaceId;
use crate::ir::{BinOp, BinRel, BitSize, BitVec, Expr, Term, Type, UnOp, UnRel, ValHint, Var};
use crate::kb::{Lazy, Ustr};

pub static DEFAULT_RULES: Lazy<Vec<Rewrite<ExprT, ConstFolding>>> = Lazy::new(|| {
    let mut rules = Vec::new();

    // Commutative
    fn comm(name: &'static str, f: impl Fn(Id, Id) -> ExprT) -> Rewrite<ExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
        let _e = searcher.add(ENodeOrVar::ENode(f(v1, v2)));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
        let _e = applier.add(ENodeOrVar::ENode(f(v2, v1)));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    }

    let binop_comm = |name: &'static str, op: BinOp| comm(name, |l, r| ExprT::BinOp(op, [l, r]));
    let binrel_comm = |name: &'static str, op: BinRel| comm(name, |l, r| ExprT::BinRel(op, [l, r]));

    rules.push(binop_comm("binop-add-comm", BinOp::ADD));
    rules.push(binop_comm("binop-mul-comm", BinOp::MUL));
    rules.push(binop_comm("binop-and-comm", BinOp::AND));
    rules.push(binop_comm("binop-or-comm", BinOp::OR));
    rules.push(binop_comm("binop-xor-comm", BinOp::XOR));

    rules.push(binrel_comm("binrel-carry-comm", BinRel::CARRY));
    rules.push(binrel_comm("binrel-scarry-comm", BinRel::SCARRY));
    rules.push(binrel_comm("binrel-eq-comm", BinRel::EQ));
    rules.push(binrel_comm("binrel-neq-comm", BinRel::NEQ));

    // Associative
    fn assoc(name: &'static str, f: impl Fn(Id, Id) -> ExprT) -> Rewrite<ExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
        let v3 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v3").unwrap()));
        let e1 = searcher.add(ENodeOrVar::ENode(f(v2, v3)));
        let _e = searcher.add(ENodeOrVar::ENode(f(v1, e1)));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
        let v3 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v3").unwrap()));
        let e1 = applier.add(ENodeOrVar::ENode(f(v1, v2)));
        let _e = applier.add(ENodeOrVar::ENode(f(e1, v3)));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    }

    let binop_assoc = |name: &'static str, op: BinOp| assoc(name, |l, r| ExprT::BinOp(op, [l, r]));

    rules.push(binop_assoc("binop-add-assoc", BinOp::ADD));
    rules.push(binop_assoc("binop-mul-assoc", BinOp::MUL));
    rules.push(binop_assoc("binop-and-assoc", BinOp::AND));
    rules.push(binop_assoc("binop-or-assoc", BinOp::OR));
    rules.push(binop_assoc("binop-xor-assoc", BinOp::XOR));

    rules.push(assoc("concat-assoc", |l, r| ExprT::Concat([l, r])));

    // Distributive
    let binop_distr =
        |name: &'static str, op1: BinOp, op2: BinOp, right: bool| -> Rewrite<ExprT, ConstFolding> {
            let mut searcher = PatternAst::default();
            let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
            let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
            let v3 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v3").unwrap()));
            let e1 = searcher.add(ENodeOrVar::ENode(ExprT::BinOp(op2, [v2, v3])));
            let _e = searcher.add(ENodeOrVar::ENode(ExprT::BinOp(op1, [v1, e1])));

            let mut applier = PatternAst::default();
            let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
            let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
            let v3 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v3").unwrap()));
            let e1 = applier.add(ENodeOrVar::ENode(ExprT::BinOp(op1, [v1, v2])));
            let e2 = applier.add(ENodeOrVar::ENode(ExprT::BinOp(op1, [v1, v3])));
            let _e = applier.add(ENodeOrVar::ENode(ExprT::BinOp(op2, [e1, e2])));

            let searcher = Pattern::new(searcher);
            let applier = Pattern::new(applier);

            if !right {
                Rewrite::new(name, searcher, applier).unwrap()
            } else {
                Rewrite::new(name, applier, searcher).unwrap()
            }
        };

    rules.push(binop_distr(
        "binop-mul-add-distr-left",
        BinOp::MUL,
        BinOp::ADD,
        false,
    ));
    rules.push(binop_distr(
        "binop-mul-add-distr-right",
        BinOp::MUL,
        BinOp::ADD,
        true,
    ));

    rules.push(binop_distr(
        "binop-mul-sub-distr-left",
        BinOp::MUL,
        BinOp::SUB,
        false,
    ));
    rules.push(binop_distr(
        "binop-mul-sub-distr-right",
        BinOp::MUL,
        BinOp::SUB,
        true,
    ));

    rules.push(binop_distr(
        "binop-and-or-distr-left",
        BinOp::AND,
        BinOp::OR,
        false,
    ));
    rules.push(binop_distr(
        "binop-and-or-distr-right",
        BinOp::AND,
        BinOp::OR,
        true,
    ));

    rules.push(binop_distr(
        "binop-and-xor-distr-left",
        BinOp::AND,
        BinOp::XOR,
        false,
    ));
    rules.push(binop_distr(
        "binop-and-xor-distr-right",
        BinOp::AND,
        BinOp::XOR,
        true,
    ));

    rules.push(binop_distr(
        "binop-or-and-distr-left",
        BinOp::OR,
        BinOp::AND,
        false,
    ));
    rules.push(binop_distr(
        "binop-or-and-distr-right",
        BinOp::OR,
        BinOp::AND,
        true,
    ));

    // Absorb
    let binop_absorb =
        |name: &'static str, op1: BinOp, op2: BinOp| -> Rewrite<ExprT, ConstFolding> {
            let mut searcher = PatternAst::default();
            let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
            let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
            let e1 = searcher.add(ENodeOrVar::ENode(ExprT::BinOp(op2, [v1, v2])));
            let _e = searcher.add(ENodeOrVar::ENode(ExprT::BinOp(op1, [v1, e1])));

            let mut applier = PatternAst::default();
            let _v = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));

            let searcher = Pattern::new(searcher);
            let applier = Pattern::new(applier);

            Rewrite::new(name, searcher, applier).unwrap()
        };

    rules.push(binop_absorb("binop-and-or-absorb", BinOp::AND, BinOp::OR));
    rules.push(binop_absorb("binop-or-and-absorb", BinOp::OR, BinOp::AND));

    let binrel_fusion = |name: &'static str,
                         op1: BinRel,
                         op2: BinRel,
                         op3: BinOp,
                         op4: BinRel|
     -> Rewrite<ExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
        let e1 = searcher.add(ENodeOrVar::ENode(ExprT::BinRel(op1, [v1, v2])));
        let e2 = searcher.add(ENodeOrVar::ENode(ExprT::BinRel(op2, [v1, v2])));
        let _e = searcher.add(ENodeOrVar::ENode(ExprT::BinOp(op3, [e1, e2])));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v1").unwrap()));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_str("?v2").unwrap()));
        let _e = applier.add(ENodeOrVar::ENode(ExprT::BinRel(op4, [v1, v2])));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    };

    rules.push(binrel_fusion(
        "binrel-lt-eq-fusion",
        BinRel::LT,
        BinRel::EQ,
        BinOp::OR,
        BinRel::LE,
    ));
    rules.push(binrel_fusion(
        "binrel-slt-eq-fusion",
        BinRel::SLT,
        BinRel::EQ,
        BinOp::OR,
        BinRel::SLE,
    ));

    rules
});

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExprT {
    Val(BitVec, ValHint),
    Var(Var),

    Load(Id, u32, AddressSpaceId),
    Cast(Id, Term<Type>),

    UnOp(UnOp, Id),
    UnRel(UnRel, Id),

    BinOp(BinOp, [Id; 2]),
    BinRel(BinRel, [Id; 2]),

    IfElse([Id; 3]),
    Extract(Id, u32, u32),
    Concat([Id; 2]),

    Intrinsic(Ustr, Vec<Id>, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExprDiscriminant {
    Val,
    Var,
    Load,
    Cast,
    UnOp,
    UnRel,
    BinOp,
    BinRel,
    IfElse,
    Extract,
    Concat,
    Intrinsic,
}

impl Language for ExprT {
    type Discriminant = ExprDiscriminant;

    #[inline]
    fn discriminant(&self) -> Self::Discriminant {
        match self {
            Self::Val(_, _) => ExprDiscriminant::Val,
            Self::Var(_) => ExprDiscriminant::Var,

            Self::Load(_, _, _) => ExprDiscriminant::Load,
            Self::Cast(_, _) => ExprDiscriminant::Cast,

            Self::UnOp(_, _) => ExprDiscriminant::UnOp,
            Self::UnRel(_, _) => ExprDiscriminant::UnRel,

            Self::BinOp(_, _) => ExprDiscriminant::BinOp,
            Self::BinRel(_, _) => ExprDiscriminant::BinRel,

            Self::IfElse(_) => ExprDiscriminant::IfElse,
            Self::Extract(_, _, _) => ExprDiscriminant::Extract,
            Self::Concat(_) => ExprDiscriminant::Concat,

            Self::Intrinsic(_, _, _) => ExprDiscriminant::Intrinsic,
        }
    }

    #[inline]
    fn children(&self) -> &[Id] {
        match self {
            Self::Val(_, _) | Self::Var(_) => &[],
            Self::Load(v, _, _) | Self::Cast(v, _) | Self::UnOp(_, v) | Self::UnRel(_, v) => {
                v.as_slice()
            }
            Self::BinOp(_, vs) | Self::BinRel(_, vs) => vs.as_slice(),
            Self::IfElse(vs) => vs.as_slice(),
            Self::Extract(v, _, _) => v.as_slice(),
            Self::Concat(vs) => vs.as_slice(),
            Self::Intrinsic(_, vs, _) => vs.as_slice(),
        }
    }

    #[inline]
    fn children_mut(&mut self) -> &mut [Id] {
        match self {
            Self::Val(_, _) | Self::Var(_) => &mut [],
            Self::Load(v, _, _) | Self::Cast(v, _) | Self::UnOp(_, v) | Self::UnRel(_, v) => {
                v.as_mut_slice()
            }
            Self::BinOp(_, vs) | Self::BinRel(_, vs) => vs.as_mut_slice(),
            Self::IfElse(vs) => vs.as_mut_slice(),
            Self::Extract(v, _, _) => v.as_mut_slice(),
            Self::Concat(vs) => vs.as_mut_slice(),
            Self::Intrinsic(_, vs, _) => vs.as_mut_slice(),
        }
    }

    #[inline]
    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Val(v1, _), Self::Val(v2, _)) => v1.nbits() == v2.nbits(),
            (Self::Var(v1), Self::Var(v2)) => v1.nbits() == v2.nbits(),
            (Self::Load(_, s1, v1), Self::Load(_, s2, v2)) => s1 == s2 && v1 == v2,
            (Self::Cast(_, t1), Self::Cast(_, t2)) => t1 == t2,
            (Self::UnOp(op1, _), Self::UnOp(op2, _)) => op1 == op2,
            (Self::UnRel(op1, _), Self::UnRel(op2, _)) => op1 == op2,
            (Self::BinOp(op1, _), Self::BinOp(op2, _)) => op1 == op2,
            (Self::BinRel(op1, _), Self::BinRel(op2, _)) => op1 == op2,
            (Self::IfElse(_), Self::IfElse(_)) => true,
            (Self::Extract(_, l1, h1), Self::Extract(_, l2, h2)) => l1 == l2 && h1 == h2,
            (Self::Concat(_), Self::Concat(_)) => true,
            (Self::Intrinsic(n1, vs1, sz1), Self::Intrinsic(n2, vs2, sz2)) => {
                n1 == n2 && vs1.len() == vs2.len() && sz1 == sz2
            }
            _ => false,
        }
    }
}

fn is_commutative_binop(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::ADD | BinOp::MUL | BinOp::AND | BinOp::OR | BinOp::XOR
    )
}

fn is_commutative_binrel(op: BinRel) -> bool {
    matches!(
        op,
        BinRel::CARRY | BinRel::SCARRY | BinRel::EQ | BinRel::NEQ
    )
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct CanonicalCost {
    size: usize,
    penalty: usize,
    is_var: bool,
}

impl Ord for CanonicalCost {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.size, self.penalty).cmp(&(other.size, other.penalty))
    }
}

impl PartialOrd for CanonicalCost {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct CanonicalCostFn;

impl CostFunction<ExprT> for CanonicalCostFn {
    type Cost = CanonicalCost;

    fn cost<C>(&mut self, enode: &ExprT, mut costs: C) -> Self::Cost
    where
        C: FnMut(Id) -> Self::Cost,
    {
        match enode {
            ExprT::Var(_) => CanonicalCost {
                size: 1,
                penalty: 0,
                is_var: true,
            },

            ExprT::BinOp(op, [left, right]) => {
                let left_cost = costs(*left);
                let right_cost = costs(*right);

                let is_canonical = left_cost.is_var && !right_cost.is_var;
                let penalty_incr = if is_commutative_binop(*op) && !is_canonical {
                    1
                } else {
                    0
                };

                CanonicalCost {
                    size: 1 + left_cost.size + right_cost.size,
                    penalty: left_cost.penalty + right_cost.penalty + penalty_incr,
                    is_var: false,
                }
            }

            ExprT::BinRel(op, [left, right]) => {
                let left_cost = costs(*left);
                let right_cost = costs(*right);

                let is_canonical = left_cost.is_var && !right_cost.is_var;
                let penalty_incr = if is_commutative_binrel(*op) && !is_canonical {
                    1
                } else {
                    0
                };

                CanonicalCost {
                    size: 1 + left_cost.size + right_cost.size,
                    penalty: left_cost.penalty + right_cost.penalty + penalty_incr,
                    is_var: false,
                }
            }

            _ => {
                let (child_size, child_penalty) = enode
                    .children()
                    .iter()
                    .map(|id| {
                        let c = costs(*id);
                        (c.size, c.penalty)
                    })
                    .fold((0, 0), |(s, p), (cs, cp)| (s + cs, p + cp));

                CanonicalCost {
                    size: 1 + child_size,
                    penalty: child_penalty,
                    is_var: false,
                }
            }
        }
    }
}

impl From<ExprT> for RecExpr<ExprT> {
    fn from(e: ExprT) -> Self {
        RecExpr::from(vec![e])
    }
}

#[derive(Default)]
pub struct ExprRewriter {
    worklist: Vec<TExpr>,
    ids: Vec<Id>,
}

enum TExpr {
    T(Term<Expr>),
    ILoad(u32, AddressSpaceId),
    ICast(Term<Type>),
    IUnOp(UnOp),
    IUnRel(UnRel),
    IBinOp(BinOp),
    IBinRel(BinRel),
    IIfElse,
    IExtract(u32, u32),
    IConcat,
    IIntrinsic(Ustr, u32, u32),
}

impl ExprRewriter {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    fn pop_id(&mut self) -> Id {
        self.ids.pop().unwrap()
    }

    #[inline]
    pub fn simplify_expr(
        &mut self,
        expr: &Term<Expr>,
        rules: &[Rewrite<ExprT, ConstFolding>],
    ) -> Term<Expr> {
        let runner = Runner::<ExprT, ConstFolding>::new(ConstFolding::default())
            .with_expr(&self.convert_expr(expr))
            .run(rules);
        let root = runner.roots[0];
        let extractor = Extractor::new(&runner.egraph, CanonicalCostFn);
        let (_, best) = extractor.find_best(root);
        self.convert_recexpr(&best)
    }

    #[inline]
    pub fn simplify_expr_with(
        &mut self,
        expr: &Term<Expr>,
        rules: &[Rewrite<ExprT, ConstFolding>],
        costf: impl CostFunction<ExprT>,
    ) -> Term<Expr> {
        let runner = Runner::<ExprT, ConstFolding>::new(ConstFolding::default())
            .with_expr(&self.convert_expr(expr))
            .run(rules);
        let root = runner.roots[0];
        let extractor = Extractor::new(&runner.egraph, costf);
        let (_, best) = extractor.find_best(root);

        self.convert_recexpr(&best)
    }

    #[inline]
    pub fn convert_expr(&mut self, expr: &Term<Expr>) -> RecExpr<ExprT> {
        let mut rec = RecExpr::default();

        self.ids.clear();
        self.worklist.clear();
        self.worklist.push(TExpr::T(expr.to_owned()));

        while let Some(e) = self.worklist.pop() {
            use TExpr::*;
            match e {
                T(t) => match &*t {
                    Expr::Val(bv, h) => self.ids.push(rec.add(ExprT::Val(bv.clone(), *h))),
                    Expr::Var(v) => self.ids.push(rec.add(ExprT::Var(*v))),
                    Expr::Load(e, sz, sp) => {
                        self.worklist.push(TExpr::ILoad(*sz, *sp));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::Cast(e, t) => {
                        self.worklist.push(TExpr::ICast(t.clone()));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::UnOp(op, e) => {
                        self.worklist.push(TExpr::IUnOp(*op));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::UnRel(op, e) => {
                        self.worklist.push(TExpr::IUnRel(*op));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::BinOp(op, e1, e2) => {
                        self.worklist.push(TExpr::IBinOp(*op));
                        self.worklist.push(TExpr::T(e2.clone()));
                        self.worklist.push(TExpr::T(e1.clone()));
                    }
                    Expr::BinRel(op, e1, e2) => {
                        self.worklist.push(TExpr::IBinRel(*op));
                        self.worklist.push(TExpr::T(e2.clone()));
                        self.worklist.push(TExpr::T(e1.clone()));
                    }
                    Expr::IfElse(e1, e2, e3) => {
                        self.worklist.push(TExpr::IIfElse);
                        self.worklist.push(TExpr::T(e3.clone()));
                        self.worklist.push(TExpr::T(e2.clone()));
                        self.worklist.push(TExpr::T(e1.clone()));
                    }
                    Expr::Extract(e, l, h) => {
                        self.worklist.push(TExpr::IExtract(*l, *h));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::ExtractLow(e, h) => {
                        self.worklist.push(TExpr::IExtract(0, *h));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::ExtractHigh(e, l) => {
                        self.worklist.push(TExpr::IExtract(*l, e.nbits()));
                        self.worklist.push(TExpr::T(e.clone()));
                    }
                    Expr::Concat(e1, e2) => {
                        self.worklist.push(TExpr::IConcat);
                        self.worklist.push(TExpr::T(e2.clone()));
                        self.worklist.push(TExpr::T(e1.clone()));
                    }
                    Expr::Intrinsic(s, es, sz) => {
                        self.worklist
                            .push(TExpr::IIntrinsic(*s, es.len() as _, *sz));
                        for e in es.iter().rev() {
                            self.worklist.push(TExpr::T(e.clone()));
                        }
                    }
                    _ => unimplemented!(), // ignore choice
                },
                ILoad(sz, sp) => {
                    let id = rec.add(ExprT::Load(self.pop_id(), sz, sp));
                    self.ids.push(id)
                }
                ICast(t) => {
                    let id = rec.add(ExprT::Cast(self.pop_id(), t));
                    self.ids.push(id)
                }
                IUnOp(op) => {
                    let id = rec.add(ExprT::UnOp(op, self.pop_id()));
                    self.ids.push(id);
                }
                IUnRel(op) => {
                    let id = rec.add(ExprT::UnRel(op, self.pop_id()));
                    self.ids.push(id);
                }
                IBinOp(op) => {
                    let rid = self.pop_id();
                    let lid = self.pop_id();
                    self.ids.push(rec.add(ExprT::BinOp(op, [lid, rid])));
                }
                IBinRel(op) => {
                    let rid = self.pop_id();
                    let lid = self.pop_id();
                    self.ids.push(rec.add(ExprT::BinRel(op, [lid, rid])));
                }
                IIfElse => {
                    let fid = self.pop_id();
                    let tid = self.pop_id();
                    let cid = self.pop_id();
                    self.ids.push(rec.add(ExprT::IfElse([cid, tid, fid])));
                }
                IExtract(l, h) => {
                    let id = rec.add(ExprT::Extract(self.pop_id(), l, h));
                    self.ids.push(id);
                }
                IConcat => {
                    let rid = self.pop_id();
                    let lid = self.pop_id();
                    self.ids.push(rec.add(ExprT::Concat([lid, rid])));
                }
                IIntrinsic(s, n, sz) => {
                    let ids = self.ids.split_off(self.ids.len() - n as usize);
                    self.ids.push(rec.add(ExprT::Intrinsic(s, ids, sz)));
                }
            }
        }

        rec.into()
    }

    #[inline]
    pub fn convert_recexpr(&self, expr: &RecExpr<ExprT>) -> Term<Expr> {
        pub fn convert_recexpr_aux(expr: &RecExpr<ExprT>, id: Id) -> Term<Expr> {
            use ExprT::*;
            match &expr[id] {
                Val(bv, h) => Expr::Val(bv.clone(), *h),
                Var(v) => Expr::Var(*v),
                Load(id, sz, sp) => Expr::Load(convert_recexpr_aux(expr, *id), *sz, *sp),
                Cast(id, t) => Expr::Cast(convert_recexpr_aux(expr, *id), t.clone()),
                UnOp(op, id) => Expr::UnOp(*op, convert_recexpr_aux(expr, *id)),
                UnRel(op, id) => Expr::UnRel(*op, convert_recexpr_aux(expr, *id)),
                BinOp(op, [id1, id2]) => Expr::BinOp(
                    *op,
                    convert_recexpr_aux(expr, *id1),
                    convert_recexpr_aux(expr, *id2),
                ),
                BinRel(op, [id1, id2]) => Expr::BinRel(
                    *op,
                    convert_recexpr_aux(expr, *id1),
                    convert_recexpr_aux(expr, *id2),
                ),
                IfElse([id1, id2, id3]) => Expr::IfElse(
                    convert_recexpr_aux(expr, *id1),
                    convert_recexpr_aux(expr, *id2),
                    convert_recexpr_aux(expr, *id3),
                ),
                Extract(id, l, h) => Expr::Extract(convert_recexpr_aux(expr, *id), *l, *h),
                Concat([id1, id2]) => Expr::Concat(
                    convert_recexpr_aux(expr, *id1),
                    convert_recexpr_aux(expr, *id2),
                ),
                Intrinsic(s, ids, sz) => Expr::Intrinsic(
                    *s,
                    ids.iter()
                        .map(|id| convert_recexpr_aux(expr, *id))
                        .collect(),
                    *sz,
                ),
            }
            .into()
        }
        convert_recexpr_aux(expr, Id::from(expr.len() - 1))
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ConstFolding;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConstOrMeta {
    S(u32, bool),
    C(BitVec, bool),
}

impl From<BitVec> for ConstOrMeta {
    fn from(bv: BitVec) -> Self {
        Self::C(bv, false)
    }
}

impl From<&'_ BitVec> for ConstOrMeta {
    fn from(bv: &'_ BitVec) -> Self {
        Self::C(bv.to_owned(), false)
    }
}

impl From<&'_ Var> for ConstOrMeta {
    fn from(v: &'_ Var) -> Self {
        Self::S(v.nbits(), false)
    }
}

impl From<&'_ Term<Type>> for ConstOrMeta {
    fn from(t: &'_ Term<Type>) -> Self {
        Self::S(t.nbits(), t.is_bool())
    }
}

impl BitSize for ConstOrMeta {
    #[inline(always)]
    fn nbits(&self) -> u32 {
        match self {
            Self::C(bv, _) => bv.nbits(),
            Self::S(sz, _) => *sz,
        }
    }
}

impl ConstOrMeta {
    #[inline(always)]
    pub fn value(&self) -> Option<&BitVec> {
        if let ConstOrMeta::C(ref bv, _) = self {
            Some(bv)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn is_bool(&self) -> bool {
        match self {
            Self::C(_, b) | Self::S(_, b) => *b,
        }
    }

    fn bits<V: BitSize>(v: &V) -> Self {
        Self::S(v.nbits(), false)
    }

    #[inline(always)]
    fn into_bool(self) -> Self {
        match self {
            Self::C(bv, _) => Self::C(bv, true),
            Self::S(sz, _) => Self::S(sz, true),
        }
    }

    #[inline(always)]
    fn lift1(&self, f: impl Fn(&BitVec, bool) -> Self) -> Self {
        match self {
            Self::C(bv, t) => f(bv, *t),
            Self::S(sz, t) => Self::S(*sz, *t),
        }
    }

    #[inline(always)]
    fn lift1_full(&self, f: impl Fn(&BitVec, bool) -> Self, g: impl Fn(u32, bool) -> Self) -> Self {
        match self {
            Self::C(bv, t) => f(bv, *t),
            Self::S(sz, t) => g(*sz, *t),
        }
    }

    #[inline(always)]
    fn lift2(&self, other: &Self, f: impl Fn(&BitVec, &BitVec, bool) -> Self) -> Self {
        match (self, other) {
            (Self::C(bv1, t1), Self::C(bv2, t2)) => f(bv1, bv2, *t1 || *t2),
            (Self::S(sz, t), _) | (_, Self::S(sz, t)) => Self::S(*sz, *t),
        }
    }

    #[inline(always)]
    fn lift2_full(
        &self,
        other: &Self,
        f: impl Fn(&BitVec, &BitVec, bool) -> Self,
        g: impl Fn(u32, u32, bool) -> Self,
    ) -> Self {
        match (self, other) {
            (Self::C(bv1, t1), Self::C(bv2, t2)) => f(bv1, bv2, *t1 || *t2),
            (Self::S(sz, t), v) => g(*sz, v.nbits(), *t || v.is_bool()),
            (v, Self::S(sz, t)) => g(v.nbits(), *sz, *t || v.is_bool()),
        }
    }
}

impl Analysis<ExprT> for ConstFolding {
    type Data = ConstOrMeta;

    fn merge(&mut self, to: &mut Self::Data, from: Self::Data) -> egg::DidMerge {
        egg::merge_max(to, from)
    }

    fn make(egraph: &mut EGraph<ExprT, Self>, enode: &ExprT, _id: Id) -> Self::Data {
        use std::ops::{Neg, Not};

        let x = |i: &Id| &egraph[*i].data;

        match enode {
            ExprT::Val(v, _) => v.into(),
            ExprT::Var(v) => v.into(),
            ExprT::Cast(v, t) => {
                x(v).lift1_full(
                    |v, _is_bool| {
                        if t.is_bool() {
                            return ConstOrMeta::from(
                                if (v.unsigned_cast(8).to_u8().unwrap() & 1) == 0 {
                                    BitVec::zero(8)
                                } else {
                                    BitVec::one(8)
                                },
                            )
                            .into_bool();
                        }

                        if t.is_float() {
                            return t.into();
                        }

                        let tbits = t.nbits();
                        let tsign = t.is_signed();

                        if tsign {
                            // signed cast
                            v.signed_cast(tbits as usize).into()
                        } else {
                            // unsigned cast
                            v.unsigned_cast(tbits as usize).into()
                        }
                    },
                    |_, _| ConstOrMeta::S(t.nbits(), t.is_bool()),
                )
            }
            ExprT::Load(_, sz, _) => ConstOrMeta::S(*sz, false),
            ExprT::UnOp(op, e) => x(e).lift1(|e, is_bool| match op {
                UnOp::NOT => {
                    if is_bool {
                        ConstOrMeta::C(e.not() & BitVec::one(e.nbits() as usize), true)
                    } else {
                        e.not().into()
                    }
                }
                UnOp::NEG => e.neg().into(),
                UnOp::POPCOUNT(bits) => BitVec::from_u32(e.count_ones(), *bits as _).into(),
                _ => ConstOrMeta::bits(e),
            }),
            ExprT::UnRel(_, _) => ConstOrMeta::S(8, true),
            ExprT::BinOp(op, [e1, e2]) => x(e1).lift2(x(e2), |e1, e2, _is_bool| match op {
                BinOp::AND => (e1 & e2).into(),
                BinOp::OR => (e1 | e2).into(),
                BinOp::XOR => (e1 ^ e2).into(),
                BinOp::ADD => (e1 + e2).into(),
                BinOp::SUB => (e1 - e2).into(),
                BinOp::MUL => (e1 * e2).into(),
                BinOp::SHL => (e1 << e2).into(),
                BinOp::SHR => (e1 >> e2).into(),
                BinOp::SAR => e1.signed_shr(e2).into(),
                BinOp::DIV => {
                    if e2.is_zero() {
                        ConstOrMeta::bits(e1)
                    } else {
                        (e1 / e2).into()
                    }
                }
                BinOp::SDIV => {
                    if e2.is_zero() {
                        ConstOrMeta::bits(e1)
                    } else {
                        e1.signed_div(e2).into()
                    }
                }
                BinOp::REM => {
                    if e2.is_zero() {
                        ConstOrMeta::bits(e1)
                    } else {
                        (e1 % e2).into()
                    }
                }
                BinOp::SREM => {
                    if e2.is_zero() {
                        ConstOrMeta::bits(e1)
                    } else {
                        e1.signed_rem(e2).into()
                    }
                }
            }),
            ExprT::BinRel(op, [e1, e2]) => {
                let as_bool = |v: bool| -> ConstOrMeta {
                    ConstOrMeta::C(if v { BitVec::one(8) } else { BitVec::zero(8) }, true)
                };

                x(e1).lift2_full(
                    x(e2),
                    |e1, e2, _is_bool| {
                        as_bool(match op {
                            BinRel::EQ => e1 == e2,
                            BinRel::NEQ => e1 != e2,
                            BinRel::LT => e1 < e2,
                            BinRel::LE => e1 <= e2,
                            BinRel::SLT => e1.signed_cmp(e2).is_lt(),
                            BinRel::SLE => e1.signed_cmp(e2).is_le(),
                            BinRel::SBORROW => e1.signed_borrow(&e2),
                            BinRel::CARRY => e1.carry(&e2),
                            BinRel::SCARRY => e1.signed_carry(&e2),
                        })
                    },
                    |_, _, _| ConstOrMeta::S(8, true),
                )
            }
            ExprT::IfElse([c1, e1, e2]) => x(c1).lift1(|c1, _is_bool| {
                if c1.is_zero() {
                    x(e1).clone()
                } else {
                    x(e2).clone()
                }
            }),
            ExprT::Concat([e1, e2]) => x(e1).lift2_full(
                x(e2),
                |e1, e2, _is_bool| {
                    let tbits = e1.nbits() + e2.nbits();
                    let sbits = e2.nbits();

                    let e1x = e1.unsigned_cast(tbits as usize) << sbits;
                    let e2x = e2.unsigned_cast(tbits as usize);

                    (e1x | e2x).into()
                },
                |sz1, sz2, _is_bool| ConstOrMeta::S(sz1 + sz2, false),
            ),
            ExprT::Extract(e, l, h) => x(e).lift1_full(
                |e, _is_bool| {
                    if (h - l) == e.nbits() {
                        e.clone().into()
                    } else {
                        if *l > 0 {
                            (e >> *l).unsigned().cast((h - l) as usize)
                        } else {
                            e.unsigned_cast((h - l) as usize)
                        }
                        .into()
                    }
                },
                |sz, _| ConstOrMeta::S((h - l).min(sz), false),
            ),
            ExprT::Intrinsic(_, _, sz) => ConstOrMeta::S(*sz, false),
        }
    }

    fn modify(egraph: &mut EGraph<ExprT, Self>, id: Id) {
        if let ConstOrMeta::C(bv, _) = &egraph[id].data {
            let added = egraph.add(ExprT::Val(bv.clone(), ValHint::CONSTANT));
            egraph.union(id, added);
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use egg::{Applier, AstSize, ENodeOrVar, Pattern, PatternAst, Var as PVar};

    use super::*;
    use crate::prelude::{AddressSpace, Var, BE};

    #[test]
    fn test_default_rules() {
        let mut r = ExprRewriter::new();
        let spc = AddressSpace::unique("uniq", 0, None);

        let var0 = Var::new0(&spc, 0, 32);

        let v1 = Expr::int_add(
            Expr::int_add(Expr::var(var0), Expr::val(0x20u32)),
            Expr::int_add(Expr::var(var0), Expr::val(0x10u32)),
        );

        let v2 = Expr::int_add(
            Expr::int_add(Expr::var(var0), Expr::var(var0)),
            Expr::val(0x30u32),
        );

        assert_eq!(
            r.simplify_expr(&v1, &*DEFAULT_RULES),
            r.simplify_expr(&v2, &*DEFAULT_RULES)
        );

        let t = Expr::concat(Expr::val(10), Expr::var(Var::new0(&spc, 0, 32)));
        let z = Expr::concat_with::<BE, _, _>(
            Expr::extract(t.clone(), 0, 16),
            Expr::concat_with::<BE, _, _>(
                Expr::extract(t.clone(), 16, 24),
                Expr::extract(t.clone(), 24, 64),
            ),
        );

        assert_eq!(
            r.simplify_expr(&t, &*DEFAULT_RULES),
            r.simplify_expr(&z, &*DEFAULT_RULES)
        );

        let c1 = Expr::bool_or(
            Expr::int_lt(Expr::var(Var::new0(&spc, 0, 32)), Expr::val(10u32)),
            Expr::int_eq(Expr::var(Var::new0(&spc, 0, 32)), Expr::val(10u32)),
        );
        let c2 = Expr::int_le(Expr::var(Var::new0(&spc, 0, 32)), Expr::val(10u32));

        assert_eq!(
            r.simplify_expr(&c1, &*DEFAULT_RULES),
            r.simplify_expr(&c2, &*DEFAULT_RULES)
        );
    }

    #[test]
    fn test_simplify() {
        let mut r = ExprRewriter::new();
        let spc = AddressSpace::unique("uniq", 0, None);

        let expr1 = Expr::int_add(
            Expr::var(Var::new0(&spc, 4, 32)),
            Expr::int_add(
                Expr::int_mul(Expr::var(Var::new0(&spc, 4, 32)), Expr::val(1u32)),
                Expr::var(Var::new0(&spc, 4, 32)),
            ),
        );

        let mut pat1 = PatternAst::<ExprT>::default();
        let pa = pat1.add(ENodeOrVar::Var(PVar::from_str("?a").unwrap()));
        let _pp = pat1.add(ENodeOrVar::ENode(ExprT::BinOp(BinOp::ADD, [pa, pa])));

        struct Add2Mul {
            var: PVar,
        }

        impl Applier<ExprT, ConstFolding> for Add2Mul {
            fn apply_one(
                &self,
                egraph: &mut EGraph<ExprT, ConstFolding>,
                eclass: Id,
                subst: &egg::Subst,
                _searcher_ast: Option<&PatternAst<ExprT>>,
                _rule_name: egg::Symbol,
            ) -> Vec<Id> {
                let a = subst[self.var];
                let sz = egraph[a].data.nbits() as usize;

                let two = egraph.add(ExprT::Val(BitVec::from_u32(2, sz), ValHint::CONSTANT));
                let addtwo = egraph.add(ExprT::BinOp(BinOp::MUL, [two, a]));

                if egraph.union(eclass, addtwo) {
                    vec![addtwo]
                } else {
                    vec![]
                }
            }
        }

        let searcher1 = Pattern::new(pat1);
        let applier1 = Add2Mul {
            var: PVar::from_str("?a").unwrap(),
        };

        let rw1 = Rewrite::new("add2mul", searcher1, applier1).unwrap();

        let mut pat1 = PatternAst::<ExprT>::default();

        let pa = pat1.add(ENodeOrVar::Var(PVar::from_str("?a").unwrap()));
        let pb = pat1.add(ENodeOrVar::Var(PVar::from_str("?b").unwrap()));

        let p1 = pat1.add(ENodeOrVar::ENode(ExprT::BinOp(BinOp::MUL, [pa, pb])));
        let _p2 = pat1.add(ENodeOrVar::ENode(ExprT::BinOp(BinOp::ADD, [pb, p1])));

        struct Add3Mul {
            pa: PVar,
            pb: PVar,
        }

        impl Applier<ExprT, ConstFolding> for Add3Mul {
            fn apply_one(
                &self,
                egraph: &mut EGraph<ExprT, ConstFolding>,
                eclass: Id,
                subst: &egg::Subst,
                _searcher_ast: Option<&PatternAst<ExprT>>,
                _rule_name: egg::Symbol,
            ) -> Vec<Id> {
                let a = subst[self.pa];
                let b = subst[self.pb];
                let sz = egraph[a].data.nbits() as usize;

                let one = egraph.add(ExprT::Val(BitVec::from_u32(1, sz), ValHint::CONSTANT));
                let pa1 = egraph.add(ExprT::BinOp(BinOp::ADD, [a, one]));
                let pa2 = egraph.add(ExprT::BinOp(BinOp::MUL, [pa1, b]));

                if egraph.union(eclass, pa2) {
                    vec![pa2]
                } else {
                    vec![]
                }
            }
        }

        let searcher2 = Pattern::new(pat1);
        let applier2 = Add3Mul {
            pa: PVar::from_str("?a").unwrap(),
            pb: PVar::from_str("?b").unwrap(),
        };

        let rw2 = Rewrite::new("add3mul", searcher2, applier2).unwrap();

        let expr2 = r.simplify_expr_with(&expr1, &[rw1, rw2], AstSize);

        assert_ne!(expr1, expr2);
        assert_eq!(
            expr2,
            Expr::int_mul(Expr::val(3u32), Expr::var(Var::new0(&spc, 4, 32)))
        );
    }

    #[test]
    fn test_id() {
        let mut r = ExprRewriter::new();

        let expr1 = Expr::int_add(
            Expr::val(10u32),
            Expr::int_mul(Expr::val(20u32), Expr::val(1u32)),
        );
        let expr2 = r.convert_expr(&expr1);
        let expr3 = r.convert_recexpr(&expr2);

        assert_eq!(expr1, expr3);

        let expr4 = Expr::ite(Expr::val(1u8), Expr::val(20u32), Expr::val(30u32));
        let expr5 = r.convert_expr(&expr4);
        let expr6 = r.convert_recexpr(&expr5);

        assert_eq!(expr4, expr6);

        let expr7 = Expr::ite(
            Expr::val(1u8),
            Expr::int_mul(
                Expr::int_add(Expr::val(20u32), Expr::val(40u32)),
                Expr::val(30u32),
            ),
            Expr::val(50u32),
        );
        let expr8 = r.convert_expr(&expr7);
        let expr9 = r.convert_recexpr(&expr8);

        assert_eq!(expr7, expr9);

        let expr10 = Expr::intrinsic(
            "test",
            vec![
                Expr::val(1u8),
                Expr::int_mul(
                    Expr::int_add(Expr::val(20u32), Expr::val(40u32)),
                    Expr::val(30u32),
                ),
                Expr::val(50u32),
            ]
            .into_iter(),
            32,
        );
        let expr11 = r.convert_expr(&expr10);
        let expr12 = r.convert_recexpr(&expr11);

        assert_eq!(expr10, expr12);
    }
}
