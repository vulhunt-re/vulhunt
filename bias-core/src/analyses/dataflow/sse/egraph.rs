use std::slice;

use crate::kb::Lazy;
use crate::prelude::*;

use egg::{
    AstDepth, ConditionalApplier, EGraph, ENodeOrVar, Extractor, Id, Language, Pattern, PatternAst,
    RecExpr, Rewrite, Runner, Subst, Var as PatternVar,
};

use super::arena::SSExprArena;
use super::expr::{Cast, SSExpr, SSExprRef};

pub static DEFAULT_RULES: Lazy<Vec<Rewrite<SSExprT, ConstFolding>>> = Lazy::new(|| {
    let mut rules = Vec::new();

    // Commutative
    /*
    fn comm(name: &'static str, f: impl Fn(Id, Id) -> SSExprT) -> Rewrite<SSExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let _e = searcher.add(ENodeOrVar::ENode(f(v1, v2)));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let _e = applier.add(ENodeOrVar::ENode(f(v2, v1)));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    }

    let binop_comm = |name: &'static str, op: BinOp| comm(name, |l, r| SSExprT::BinOp(op, [l, r]));
    let binrel_comm =
        |name: &'static str, op: BinRel| comm(name, |l, r| SSExprT::BinRel(op, [l, r]));

    rules.push(binop_comm("binop-add-comm", BinOp::ADD));
    rules.push(binop_comm("binop-mul-comm", BinOp::MUL));
    rules.push(binop_comm("binop-and-comm", BinOp::AND));
    rules.push(binop_comm("binop-or-comm", BinOp::OR));
    rules.push(binop_comm("binop-xor-comm", BinOp::XOR));

    rules.push(binrel_comm("binrel-carry-comm", BinRel::CARRY));
    rules.push(binrel_comm("binrel-scarry-comm", BinRel::SCARRY));
    rules.push(binrel_comm("binrel-eq-comm", BinRel::EQ));
    rules.push(binrel_comm("binrel-neq-comm", BinRel::NEQ));
    */

    // Normalisation of subtraction of BitVecs
    let sub_is_add = |name: &'static str| -> Rewrite<SSExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let _e = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(BinOp::SUB, [v1, v2])));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let e0 = applier.add(ENodeOrVar::ENode(SSExprT::UnOp(UnOp::NEG, v2)));
        let _e = applier.add(ENodeOrVar::ENode(SSExprT::BinOp(BinOp::ADD, [v1, e0])));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    };

    rules.push(sub_is_add("binop-sub-is-add"));

    // Associative
    fn assoc_lr(
        name: &'static str,
        f: impl Fn(Id, Id) -> SSExprT,
    ) -> Rewrite<SSExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let v3 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(3u32)));
        let e1 = searcher.add(ENodeOrVar::ENode(f(v2, v3)));
        let _e = searcher.add(ENodeOrVar::ENode(f(v1, e1)));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let v3 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(3u32)));
        let e1 = applier.add(ENodeOrVar::ENode(f(v1, v2)));
        let _e = applier.add(ENodeOrVar::ENode(f(e1, v3)));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    }

    let binop_assoc_lr =
        |name: &'static str, op: BinOp| assoc_lr(name, |l, r| SSExprT::BinOp(op, [l, r]));

    rules.push(binop_assoc_lr("binop-add-assoc-lr", BinOp::ADD));
    rules.push(binop_assoc_lr("binop-mul-assoc-lr", BinOp::MUL));
    rules.push(binop_assoc_lr("binop-and-assoc-lr", BinOp::AND));
    rules.push(binop_assoc_lr("binop-or-assoc-lr", BinOp::OR));
    rules.push(binop_assoc_lr("binop-xor-assoc-lr", BinOp::XOR));

    rules.push(assoc_lr("concat-assoc-lr", |l, r| SSExprT::Concat([l, r])));

    fn assoc_rl(
        name: &'static str,
        f: impl Fn(Id, Id) -> SSExprT,
    ) -> Rewrite<SSExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let v3 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(3u32)));
        let e1 = searcher.add(ENodeOrVar::ENode(f(v1, v2)));
        let _e = searcher.add(ENodeOrVar::ENode(f(e1, v3)));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let v3 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(3u32)));
        let e1 = applier.add(ENodeOrVar::ENode(f(v2, v3)));
        let _e = applier.add(ENodeOrVar::ENode(f(v1, e1)));

        let searcher = Pattern::new(searcher);
        let applier = Pattern::new(applier);

        Rewrite::new(name, searcher, applier).unwrap()
    }

    let binop_assoc_rl =
        |name: &'static str, op: BinOp| assoc_rl(name, |l, r| SSExprT::BinOp(op, [l, r]));

    rules.push(binop_assoc_rl("binop-add-assoc-rl", BinOp::ADD));
    rules.push(binop_assoc_rl("binop-mul-assoc-rl", BinOp::MUL));
    rules.push(binop_assoc_rl("binop-and-assoc-rl", BinOp::AND));
    rules.push(binop_assoc_rl("binop-or-assoc-rl", BinOp::OR));
    rules.push(binop_assoc_rl("binop-xor-assoc-rl", BinOp::XOR));

    rules.push(assoc_rl("concat-assoc-rl", |l, r| SSExprT::Concat([l, r])));

    // Distributive
    let binop_distr = |name: &'static str,
                       op1: BinOp,
                       op2: BinOp,
                       right: bool|
     -> Rewrite<SSExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let v3 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(3u32)));
        let e1 = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(op2, [v2, v3])));
        let _e = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(op1, [v1, e1])));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let v3 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(3u32)));
        let e1 = applier.add(ENodeOrVar::ENode(SSExprT::BinOp(op1, [v1, v2])));
        let e2 = applier.add(ENodeOrVar::ENode(SSExprT::BinOp(op1, [v1, v3])));
        let _e = applier.add(ENodeOrVar::ENode(SSExprT::BinOp(op2, [e1, e2])));

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
        |name: &'static str, op1: BinOp, op2: BinOp| -> Rewrite<SSExprT, ConstFolding> {
            let mut searcher = PatternAst::default();
            let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
            let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
            let e1 = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(op2, [v1, v2])));
            let _e = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(op1, [v1, e1])));

            let mut applier = PatternAst::default();
            let _v = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));

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
     -> Rewrite<SSExprT, ConstFolding> {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let e1 = searcher.add(ENodeOrVar::ENode(SSExprT::BinRel(op1, [v1, v2])));
        let e2 = searcher.add(ENodeOrVar::ENode(SSExprT::BinRel(op2, [v1, v2])));
        let _e = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(op3, [e1, e2])));

        let mut applier = PatternAst::default();
        let v1 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = applier.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let _e = applier.add(ENodeOrVar::ENode(SSExprT::BinRel(op4, [v1, v2])));

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

    {
        let mut searcher = PatternAst::default();
        let v1 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));
        let v2 = searcher.add(ENodeOrVar::Var(PatternVar::from_u32(2u32)));
        let _e = searcher.add(ENodeOrVar::ENode(SSExprT::BinOp(BinOp::ADD, [v1, v2])));
        let searcher = Pattern::new(searcher);

        let mut applier = PatternAst::default();
        let _ = applier.add(ENodeOrVar::Var(PatternVar::from_u32(1u32)));

        let applier = ConditionalApplier {
            condition: |egraph: &mut EGraph<SSExprT, ConstFolding>, _id, subst: &Subst| {
                if let Some(v) = egraph[subst[PatternVar::from_u32(2u32)]].data.as_ref() {
                    v.is_zero()
                } else {
                    false
                }
            },
            applier: Pattern::new(applier),
        };

        rules.push(Rewrite::new("binop-add-zero", searcher, applier).unwrap());
    }

    rules
});

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SSExprT {
    Val(BitVec),
    Var(Var),

    Cast(Id, Cast),

    UnOp(UnOp, Id),
    UnRel(UnRel, Id),

    BinOp(BinOp, [Id; 2]),
    BinRel(BinRel, [Id; 2]),

    Extract(Id, u32, u32),
    Concat([Id; 2]),

    Load(Id, u32),
    Store(Id, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SSExprKind {
    Val,
    Var,
    Cast(Cast),
    UnOp(UnOp),
    UnRel(UnRel),
    BinOp(BinOp),
    BinRel(BinRel),
    Extract,
    Concat,
    Load,
    Store,
}

impl Language for SSExprT {
    type Discriminant = SSExprKind;

    fn discriminant(&self) -> Self::Discriminant {
        match self {
            Self::Val(_) => SSExprKind::Val,
            Self::Var(_) => SSExprKind::Var,
            Self::Cast(_, cast) => SSExprKind::Cast(*cast),
            Self::UnOp(op, _) => SSExprKind::UnOp(*op),
            Self::UnRel(op, _) => SSExprKind::UnRel(*op),
            Self::BinOp(op, _) => SSExprKind::BinOp(*op),
            Self::BinRel(op, _) => SSExprKind::BinRel(*op),
            Self::Extract(_, _, _) => SSExprKind::Extract,
            Self::Concat(_) => SSExprKind::Concat,
            Self::Load(_, _) => SSExprKind::Load,
            Self::Store(_, _) => SSExprKind::Store,
        }
    }

    fn children(&self) -> &[Id] {
        match self {
            Self::Val(_) | Self::Var(_) => &[],
            Self::Cast(id, _)
            | Self::UnOp(_, id)
            | Self::UnRel(_, id)
            | Self::Extract(id, _, _)
            | Self::Load(id, _)
            | Self::Store(id, _) => slice::from_ref(id),
            Self::BinOp(_, ids) | Self::BinRel(_, ids) | Self::Concat(ids) => ids,
        }
    }

    fn children_mut(&mut self) -> &mut [Id] {
        match self {
            Self::Val(_) | Self::Var(_) => &mut [],
            Self::Cast(id, _)
            | Self::UnOp(_, id)
            | Self::UnRel(_, id)
            | Self::Extract(id, _, _)
            | Self::Load(id, _)
            | Self::Store(id, _) => slice::from_mut(id),
            Self::BinOp(_, ids) | Self::BinRel(_, ids) | Self::Concat(ids) => ids,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Val(v1), Self::Val(v2)) => v1.nbits() == v2.nbits(),
            (Self::Var(v1), Self::Var(v2)) => v1.nbits() == v2.nbits(),
            (Self::Cast(_, c1), Self::Cast(_, c2)) => c1 == c2,
            (Self::UnOp(op1, _), Self::UnOp(op2, _)) => op1 == op2,
            (Self::UnRel(op1, _), Self::UnRel(op2, _)) => op1 == op2,
            (Self::BinOp(op1, _), Self::BinOp(op2, _)) => op1 == op2,
            (Self::BinRel(op1, _), Self::BinRel(op2, _)) => op1 == op2,
            (Self::Extract(_, l1, h1), Self::Extract(_, l2, h2)) => l1 == l2 && h1 == h2,
            (Self::Concat(_), Self::Concat(_)) => true,
            (Self::Load(_, s1), Self::Load(_, s2)) => s1 == s2,
            (Self::Store(_, s1), Self::Store(_, s2)) => s1 == s2,
            _ => false,
        }
    }
}

#[derive(Default)]
pub struct ConstFolding;

impl egg::Analysis<SSExprT> for ConstFolding {
    type Data = Option<BitVec>;

    fn merge(&mut self, a: &mut Self::Data, b: Self::Data) -> egg::DidMerge {
        egg::merge_max(a, b)
    }

    fn make(egraph: &mut EGraph<SSExprT, Self>, enode: &SSExprT, _id: Id) -> Self::Data {
        match enode {
            SSExprT::Val(v) => Some(v.clone()),
            SSExprT::UnOp(op, id) => {
                let v = egraph[*id].data.as_ref()?;
                match *op {
                    UnOp::NEG => Some(-v),
                    _ => None,
                }
            }
            SSExprT::BinOp(op, [e1, e2]) => match *op {
                BinOp::ADD => {
                    let v1 = egraph[*e1].data.as_ref()?;
                    let v2 = egraph[*e2].data.as_ref()?;

                    if v1.nbits() != v2.nbits() {
                        return None;
                    }

                    Some(v1 + v2)
                }
                BinOp::SUB => {
                    let v1 = egraph[*e1].data.as_ref()?;
                    let v2 = egraph[*e2].data.as_ref()?;

                    if v1.nbits() != v2.nbits() {
                        return None;
                    }

                    Some(v1 - v2)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn modify(egraph: &mut EGraph<SSExprT, Self>, id: Id) {
        if let Some(ref bv) = egraph[id].data {
            let added = egraph.add(SSExprT::Val(bv.clone()));
            egraph.union(id, added);
        }
    }
}

impl SSExprT {
    pub fn from_expr(e: &mut EGraph<Self, ConstFolding>, expr: &SSExprRef) -> Self {
        match &**expr {
            SSExpr::Val(v) => Self::Val((**v).clone()),
            SSExpr::Var(v) => Self::Var(*v),
            SSExpr::Cast(expr, cast) => {
                let ee = SSExprT::from_expr(e, expr);
                let id = e.add(ee);
                Self::Cast(id, *cast)
            }
            SSExpr::UnOp(op, expr) => {
                let ee = SSExprT::from_expr(e, expr);
                let id = e.add(ee);
                Self::UnOp(*op, id)
            }
            SSExpr::BinOp(op, [expr1, expr2]) => {
                let ee1 = SSExprT::from_expr(e, expr1);
                let id1 = e.add(ee1);
                let ee2 = SSExprT::from_expr(e, expr2);
                let id2 = e.add(ee2);
                Self::BinOp(*op, [id1, id2])
            }
            SSExpr::UnRel(op, expr) => {
                let ee = SSExprT::from_expr(e, expr);
                let id = e.add(ee);
                Self::UnRel(*op, id)
            }
            SSExpr::BinRel(op, [expr1, expr2]) => {
                let ee1 = SSExprT::from_expr(e, expr1);
                let id1 = e.add(ee1);
                let ee2 = SSExprT::from_expr(e, expr2);
                let id2 = e.add(ee2);
                Self::BinRel(*op, [id1, id2])
            }
            SSExpr::Extract(expr, l, h) => {
                let ee = SSExprT::from_expr(e, expr);
                let id = e.add(ee);
                Self::Extract(id, *l, *h)
            }
            SSExpr::Concat([expr1, expr2]) => {
                let ee1 = SSExprT::from_expr(e, expr1);
                let id1 = e.add(ee1);
                let ee2 = SSExprT::from_expr(e, expr2);
                let id2 = e.add(ee2);
                Self::Concat([id1, id2])
            }
            SSExpr::Load(expr, s) => {
                let ee = SSExprT::from_expr(e, expr);
                let id = e.add(ee);
                Self::Load(id, *s)
            }
            SSExpr::Store(expr, s) => {
                let ee = SSExprT::from_expr(e, expr);
                let id = e.add(ee);
                Self::Store(id, *s)
            }
        }
    }

    pub fn into_expr<'sse>(arena: &'sse SSExprArena, rexpr: &RecExpr<Self>) -> SSExprRef<'sse> {
        pub fn convert_recexpr_aux<'sse>(
            arena: &'sse SSExprArena,
            expr: &RecExpr<SSExprT>,
            id: Id,
        ) -> SSExprRef<'sse> {
            match &expr[id] {
                SSExprT::Val(v) => arena.val(v.clone()),
                SSExprT::Var(v) => arena.var(*v),
                SSExprT::Cast(id, cast) => {
                    let expr = convert_recexpr_aux(arena, expr, *id);
                    arena.cast(expr, *cast)
                }
                SSExprT::UnOp(op, id) => {
                    let expr = convert_recexpr_aux(arena, expr, *id);
                    arena.unop(*op, expr)
                }
                SSExprT::BinOp(op, [id1, id2]) => {
                    let expr1 = convert_recexpr_aux(arena, expr, *id1);
                    let expr2 = convert_recexpr_aux(arena, expr, *id2);
                    arena.binop(*op, expr1, expr2)
                }
                SSExprT::UnRel(op, id) => {
                    let expr = convert_recexpr_aux(arena, expr, *id);
                    arena.unrel(*op, expr)
                }
                SSExprT::BinRel(op, [id1, id2]) => {
                    let expr1 = convert_recexpr_aux(arena, expr, *id1);
                    let expr2 = convert_recexpr_aux(arena, expr, *id2);
                    arena.binrel(*op, expr1, expr2)
                }
                SSExprT::Extract(id, l, h) => {
                    let expr = convert_recexpr_aux(arena, expr, *id);
                    arena.extract(expr, *l, *h)
                }
                SSExprT::Concat([id1, id2]) => {
                    let expr1 = convert_recexpr_aux(arena, expr, *id1);
                    let expr2 = convert_recexpr_aux(arena, expr, *id2);
                    arena.concat(expr1, expr2)
                }
                SSExprT::Load(id, s) => {
                    let expr = convert_recexpr_aux(arena, expr, *id);
                    arena.load(expr, *s)
                }
                SSExprT::Store(id, s) => {
                    let expr = convert_recexpr_aux(arena, expr, *id);
                    arena.store(expr, *s)
                }
            }
        }
        convert_recexpr_aux(arena, rexpr, rexpr.root())
    }

    #[cfg(test)]
    pub fn simplify<'sse>(arena: &'sse SSExprArena, expr: &SSExprRef<'sse>) -> SSExprRef<'sse> {
        let mut egraph = EGraph::<SSExprT, ConstFolding>::default();

        let expr = SSExprT::from_expr(&mut egraph, expr);
        let root = egraph.add(expr);

        egraph.rebuild();

        let runner = Runner::default().with_egraph(egraph).run(&*DEFAULT_RULES);

        let extractor = Extractor::new(&runner.egraph, AstDepth);
        let (_, best) = extractor.find_best(root);

        Self::into_expr(arena, &best)
    }

    pub fn simplify_with_limiting<'sse>(
        arena: &'sse SSExprArena,
        expr: &SSExprRef<'sse>,
        limit: impl Into<Option<usize>>,
    ) -> Option<SSExprRef<'sse>> {
        let limit = limit.into();
        let mut egraph = EGraph::<SSExprT, ConstFolding>::default();

        let expr = SSExprT::from_expr(&mut egraph, expr);
        let root = egraph.add(expr);

        egraph.rebuild();

        let runner = Runner::default().with_egraph(egraph).run(&*DEFAULT_RULES);

        let extractor = Extractor::new(&runner.egraph, AstDepth);
        let (_, best) = extractor.find_best(root);

        if limit.is_some_and(|l| best.len() > l) {
            tracing::trace!(
                "simplified expression exceeds complexity limit: {} > {}",
                best.len(),
                limit.unwrap(),
            );
            return None;
        }

        Some(Self::into_expr(arena, &best))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_simplify() {
        let _ = tracing_subscriber::fmt::try_init();

        let arena = SSExprArena::new();
        let space = AddressSpace::unique("unique", 0, None);

        let expr = arena.binop(
            BinOp::ADD,
            arena.val(BitVec::from_u32(1, 8)),
            arena.val(BitVec::from_u32(2, 8)),
        );

        let simplified = SSExprT::simplify(&arena, &expr);
        assert_eq!(simplified, arena.val(BitVec::from_u32(3, 8)));

        let expr = arena.load(
            arena.binop(
                BinOp::ADD,
                arena.binop(
                    BinOp::ADD,
                    arena.var(Var::new0(&space, 0x10, 8)),
                    arena.val(BitVec::from_u32(2, 8)),
                ),
                arena.val(BitVec::from_u32(3, 8)),
            ),
            0,
        );

        let simplified = SSExprT::simplify(&arena, &expr);
        assert_eq!(
            simplified,
            arena.load(
                arena.binop(
                    BinOp::ADD,
                    arena.var(Var::new0(&space, 0x10, 8)),
                    arena.val(BitVec::from_u32(5, 8))
                ),
                0
            )
        );
    }
}
