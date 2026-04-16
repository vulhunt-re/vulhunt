use std::mem;

use crate::prelude::*;

use hashbrown::HashSet;
use hashcons_arena::{BoxedHashConsArena, HRef, HashConsArena};
use fxhash::FxBuildHasher;

use super::egraph::SSExprT;
use super::expr::{Cast, SSExpr, SSExprRef};

pub type VarSet = HashSet<Var, FxBuildHasher>;
pub type SSExprSet<'a> = HashSet<SSExprRef<'a>, FxBuildHasher>;
pub type SSExprVec<'a> = Vec<SSExprRef<'a>>;

pub struct SSExprArena {
    sses: HashConsArena<SSExpr<'static>>,
    bitvecs: BoxedHashConsArena<BitVec>,
}

impl SSExprArena {
    pub fn new() -> Self {
        Self {
            sses: HashConsArena::new(),
            bitvecs: BoxedHashConsArena::new(),
        }
    }

    fn intern<'sse>(&'sse self, expr: SSExpr<'sse>) -> SSExprRef<'sse> {
        unsafe {
            // NOTE: we need to transmute here to convert the lifetime of the
            // expression from 'sse to 'static. This is safe because we are sure
            // the expression is valid for the lifetime of the arena and we will
            // return a reference to the interned expression which is guaranteed
            // to be valid for the lifetime of the arena.
            let interned = self.sses.intern(mem::transmute(expr));
            // SAFETY: `intern` returns a reference to the interned expression
            // which is guaranteed to be valid for the lifetime of the arena.
            mem::transmute(interned)
        }
    }

    fn intern_bv<'sse>(&'sse self, val: BitVec) -> HRef<'sse, BitVec> {
        self.bitvecs.intern(val)
    }

    pub fn val<'sse>(&'sse self, val: impl Into<BitVec>) -> SSExprRef<'sse> {
        let bv = self.intern_bv(val.into());
        self.intern(SSExpr::Val(bv.into()))
    }

    pub fn var<'sse>(&'sse self, var: impl Into<Var>) -> SSExprRef<'sse> {
        self.intern(SSExpr::Var(var.into()))
    }

    pub fn cast<'sse>(&'sse self, e: impl Into<SSExprRef<'sse>>, c: Cast) -> SSExprRef<'sse> {
        self.intern(SSExpr::Cast(e.into(), c))
    }

    pub fn unop<'sse>(&'sse self, op: UnOp, e: impl Into<SSExprRef<'sse>>) -> SSExprRef<'sse> {
        self.intern(SSExpr::UnOp(op, e.into()))
    }

    pub fn unrel<'sse>(&'sse self, op: UnRel, e: impl Into<SSExprRef<'sse>>) -> SSExprRef<'sse> {
        self.intern(SSExpr::UnRel(op, e.into()))
    }

    pub fn binop<'sse>(
        &'sse self,
        op: BinOp,
        e1: impl Into<SSExprRef<'sse>>,
        e2: impl Into<SSExprRef<'sse>>,
    ) -> SSExprRef<'sse> {
        self.intern(SSExpr::BinOp(op, [e1.into(), e2.into()]))
    }

    pub fn binrel<'sse>(
        &'sse self,
        op: BinRel,
        e1: impl Into<SSExprRef<'sse>>,
        e2: impl Into<SSExprRef<'sse>>,
    ) -> SSExprRef<'sse> {
        self.intern(SSExpr::BinRel(op, [e1.into(), e2.into()]))
    }

    pub fn extract<'sse>(
        &'sse self,
        e: impl Into<SSExprRef<'sse>>,
        loff: u32,
        hoff: u32,
    ) -> SSExprRef<'sse> {
        self.intern(SSExpr::Extract(e.into(), loff, hoff))
    }

    pub fn concat<'sse>(
        &'sse self,
        e1: impl Into<SSExprRef<'sse>>,
        e2: impl Into<SSExprRef<'sse>>,
    ) -> SSExprRef<'sse> {
        self.intern(SSExpr::Concat([e1.into(), e2.into()]))
    }

    pub fn load<'sse>(&'sse self, e: impl Into<SSExprRef<'sse>>, sz: u32) -> SSExprRef<'sse> {
        self.intern(SSExpr::Load(e.into(), sz))
    }

    pub fn store<'sse>(&'sse self, e: impl Into<SSExprRef<'sse>>, sz: u32) -> SSExprRef<'sse> {
        self.intern(SSExpr::Store(e.into(), sz))
    }

    pub fn from_expr<'sse>(&'sse self, expr: &Term<Expr>) -> Option<SSExprRef<'sse>> {
        match expr.value() {
            Expr::Val(bv, _) => Some(self.val(bv.clone())),
            Expr::Var(var) => Some(self.var(*var)),
            _ => None,
        }
    }

    pub fn matcher<'sse>(&'sse self) -> SSEMatcher<'sse> {
        SSEMatcher::new()
    }

    pub fn replacer<'sse>(&'sse self) -> SSEReplacer<'sse> {
        SSEReplacer::new(self)
    }

    pub fn replacer_with_limit<'sse>(
        &'sse self,
        limit: impl Into<Option<usize>>,
    ) -> SSEReplacer<'sse> {
        SSEReplacer::new_with(self, limit)
    }
}

pub struct SSESimplifier<'sse> {
    sses: &'sse SSExprArena,
    limit: Option<usize>,
}

impl<'sse> SSESimplifier<'sse> {
    pub fn new(sses: &'sse SSExprArena) -> Self {
        Self::new_with(sses, None)
    }

    pub fn new_with(sses: &'sse SSExprArena, limit: impl Into<Option<usize>>) -> Self {
        Self {
            sses,
            limit: limit.into(),
        }
    }

    pub fn simplify(&self, e: SSExprRef<'sse>) -> Option<SSExprRef<'sse>> {
        SSExprT::simplify_with_limiting(self.sses, &e, self.limit)
    }
}

pub struct SSEMatcher<'a> {
    wl: SSExprVec<'a>,
    vars: VarSet,
}

impl<'a> SSEMatcher<'a> {
    pub fn new() -> Self {
        Self {
            wl: SSExprVec::new(),
            vars: VarSet::default(),
        }
    }

    pub fn matches(&mut self, e: SSExprRef<'a>, mut f: impl FnMut(SSExprRef<'a>) -> bool) -> bool {
        self.wl.clear();
        self.wl.push(e);

        while let Some(e) = self.wl.pop() {
            if f(e) {
                return true;
            }

            match &*e {
                SSExpr::Cast(e, _)
                | SSExpr::UnOp(_, e)
                | SSExpr::UnRel(_, e)
                | SSExpr::Load(e, _)
                | SSExpr::Store(e, _)
                | SSExpr::Extract(e, _, _) => self.wl.push(*e),
                SSExpr::BinOp(_, [e1, e2])
                | SSExpr::BinRel(_, [e1, e2])
                | SSExpr::Concat([e1, e2]) => {
                    self.wl.push(*e1);
                    self.wl.push(*e2);
                }
                _ => (),
            }
        }

        false
    }

    pub fn contains(&mut self, s: SSExprRef<'a>, t: SSExprRef<'a>) -> bool {
        self.matches(s, |x| x == t)
    }

    pub fn contains_unique_variables(&mut self, e: SSExprRef<'a>) -> bool {
        self.matches(
            e,
            |e| matches!(e.as_ref(), SSExpr::Var(v) if v.is_temporary()),
        )
    }

    pub fn all_variables_match(
        &mut self,
        e: SSExprRef<'a>,
        mut f: impl FnMut(&Var) -> bool,
    ) -> bool {
        self.wl.clear();
        self.wl.push(e);

        while let Some(e) = self.wl.pop() {
            match &*e {
                SSExpr::Var(v) => {
                    if !f(v) {
                        return false;
                    }
                }
                SSExpr::Cast(e, _)
                | SSExpr::UnOp(_, e)
                | SSExpr::UnRel(_, e)
                | SSExpr::Load(e, _)
                | SSExpr::Store(e, _)
                | SSExpr::Extract(e, _, _) => self.wl.push(*e),
                SSExpr::BinOp(_, [e1, e2])
                | SSExpr::BinRel(_, [e1, e2])
                | SSExpr::Concat([e1, e2]) => {
                    self.wl.push(*e1);
                    self.wl.push(*e2);
                }
                _ => (),
            }
        }

        true
    }

    pub fn any_variables_match(
        &mut self,
        e: SSExprRef<'a>,
        mut f: impl FnMut(&Var) -> bool,
    ) -> bool {
        self.wl.clear();
        self.wl.push(e);

        while let Some(e) = self.wl.pop() {
            match &*e {
                SSExpr::Var(v) => {
                    if f(v) {
                        return true;
                    }
                }
                SSExpr::Cast(e, _)
                | SSExpr::UnOp(_, e)
                | SSExpr::UnRel(_, e)
                | SSExpr::Load(e, _)
                | SSExpr::Store(e, _)
                | SSExpr::Extract(e, _, _) => self.wl.push(*e),
                SSExpr::BinOp(_, [e1, e2])
                | SSExpr::BinRel(_, [e1, e2])
                | SSExpr::Concat([e1, e2]) => {
                    self.wl.push(*e1);
                    self.wl.push(*e2);
                }
                _ => (),
            }
        }

        false
    }

    pub fn variables(&mut self, e: SSExprRef<'a>) -> &VarSet {
        self.vars.clear();
        self.wl.clear();
        self.wl.push(e);

        while let Some(e) = self.wl.pop() {
            match &*e {
                SSExpr::Var(v) => {
                    self.vars.insert(*v);
                }
                SSExpr::Cast(e, _)
                | SSExpr::UnOp(_, e)
                | SSExpr::UnRel(_, e)
                | SSExpr::Load(e, _)
                | SSExpr::Store(e, _)
                | SSExpr::Extract(e, _, _) => self.wl.push(*e),
                SSExpr::BinOp(_, [e1, e2])
                | SSExpr::BinRel(_, [e1, e2])
                | SSExpr::Concat([e1, e2]) => {
                    self.wl.push(*e1);
                    self.wl.push(*e2);
                }
                _ => (),
            }
        }

        &self.vars
    }
}

pub struct SSEReplacer<'sse> {
    sses: &'sse SSExprArena,
    stack: SSExprVec<'sse>,
    flattened: SSExprVec<'sse>,
    replaced: SSExprSet<'sse>,
    simplifier: SSESimplifier<'sse>,
}

impl<'sse> SSEReplacer<'sse> {
    pub fn new(sses: &'sse SSExprArena) -> Self {
        Self::new_with(sses, None)
    }

    pub fn new_with(sses: &'sse SSExprArena, limit: impl Into<Option<usize>>) -> Self {
        Self {
            sses,
            stack: SSExprVec::new(),
            flattened: SSExprVec::new(),
            replaced: SSExprSet::default(),
            simplifier: SSESimplifier::new_with(sses, limit),
        }
    }

    fn stack_pop(&mut self) -> SSExprRef<'sse> {
        self.stack.pop().expect("stack is not empty")
    }

    pub fn replace_map(
        &mut self,
        target: SSExprRef<'sse>,
        mut f: impl FnMut(&'sse SSExprArena, SSExprRef<'sse>) -> Option<SSExprRef<'sse>>,
    ) -> Option<SSExprRef<'sse>> {
        use SSExpr as E;

        // scratch state is reused across calls; clear it up front so a previous
        // replacement cannot corrupt the next traversal/rebuild
        self.stack.clear();
        self.flattened.clear();
        self.replaced.clear();

        self.stack.push(target);

        while let Some(current) = self.stack.pop() {
            // if this node should be replaced, add replacement and continue
            if let Some(with) = f(self.sses, current) {
                if with != current {
                    self.flattened.push(with);
                    self.replaced.insert(with);
                    continue;
                }
            }

            // add current node to flattened representation
            self.flattened.push(current);

            // add children to stack in reverse order so they're processed in correct order
            match &*current {
                E::Cast(e, _)
                | E::UnOp(_, e)
                | E::UnRel(_, e)
                | E::Extract(e, _, _)
                | E::Load(e, _)
                | E::Store(e, _) => {
                    self.stack.push(*e);
                }
                E::BinOp(_, [e1, e2]) | E::BinRel(_, [e1, e2]) | E::Concat([e1, e2]) => {
                    // push in reverse order so e1 is processed before e2
                    self.stack.push(*e2);
                    self.stack.push(*e1);
                }
                E::Val(_) | E::Var(_) => {
                    // leaf nodes - nothing to add to stack
                }
            }
        }

        // if no replacements were made, return None
        if self.replaced.is_empty() {
            self.flattened.clear();
            return None;
        }

        // process flattened nodes in reverse order
        let flattened = self.flattened.drain(..).rev().collect::<Vec<_>>();
        for node in flattened {
            if self.replaced.contains(&node) {
                // nodes already replaced go directly on the stack
                self.stack.push(node);
                continue;
            }

            match *node {
                E::Val(_) | E::Var(_) => {
                    // leaf nodes go directly on the stack
                    self.stack.push(node);
                }
                E::Cast(_, cast) => {
                    let child = self.stack_pop();
                    let new_node = self.sses.cast(child, cast);
                    self.stack.push(new_node);
                }
                E::UnOp(op, _) => {
                    let child = self.stack_pop();
                    let new_node = self.sses.unop(op, child);
                    self.stack.push(new_node);
                }
                E::UnRel(op, _) => {
                    let child = self.stack_pop();
                    let new_node = self.sses.unrel(op, child);
                    self.stack.push(new_node);
                }
                E::BinOp(op, _) => {
                    let e1 = self.stack_pop();
                    let e2 = self.stack_pop();
                    let new_node = self.sses.binop(op, e1, e2);
                    self.stack.push(new_node);
                }
                E::BinRel(op, _) => {
                    let e1 = self.stack_pop();
                    let e2 = self.stack_pop();
                    let new_node = self.sses.binrel(op, e1, e2);
                    self.stack.push(new_node);
                }
                E::Extract(_, loff, hoff) => {
                    let child = self.stack_pop();
                    let new_node = self.sses.extract(child, loff, hoff);
                    self.stack.push(new_node);
                }
                E::Concat(_) => {
                    let e1 = self.stack_pop();
                    let e2 = self.stack_pop();
                    let new_node = self.sses.concat(e1, e2);
                    self.stack.push(new_node);
                }
                E::Load(_, sz) => {
                    let child = self.stack_pop();
                    let new_node = self.sses.load(child, sz);
                    self.stack.push(new_node);
                }
                E::Store(_, sz) => {
                    let child = self.stack_pop();
                    let new_node = self.sses.store(child, sz);
                    self.stack.push(new_node);
                }
            }
        }

        // at this point, the stack contains the final result, and we do not need to maintain the
        // set of replacements
        self.replaced.clear();

        let result = self.stack_pop();
        let simplified = self.simplifier.simplify(result)?;

        if simplified != target {
            Some(simplified)
        } else {
            None
        }
    }

    pub fn replace(
        &mut self,
        target: SSExprRef<'sse>,
        old: SSExprRef<'sse>,
        new: SSExprRef<'sse>,
    ) -> Option<SSExprRef<'sse>> {
        self.replace_map(target, |_, e| (e == old).then_some(new))
    }

    pub fn map_generations(
        &mut self,
        e: SSExprRef<'sse>,
        mut f: impl FnMut(&Var) -> u32,
    ) -> SSExprRef<'sse> {
        self.replace_map(e, |sses, e| {
            if let SSExpr::Var(var) = e.as_ref() {
                Some(sses.var(var.with_generation(f(var))))
            } else {
                None
            }
        })
        .unwrap_or(e)
    }

    pub fn reset_generations(&mut self, e: SSExprRef<'sse>) -> SSExprRef<'sse> {
        self.map_generations(e, |_| 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_reg_space() -> AddressSpaceId {
        AddressSpaceId::register_id(0)
    }

    #[test]
    fn replace_map_noop_keeps_leaf_nodes() {
        let arena = SSExprArena::new();
        let expr = arena.var(Var::new0(test_reg_space(), 0x10, 32));
        let mut replacer = arena.replacer();

        let replaced = replacer.replace_map(expr, |_, e| Some(e));

        assert!(replaced.is_none());
    }

    #[test]
    fn map_generations_preserves_unchanged_binop_child() {
        let arena = SSExprArena::new();
        let lhs = Var::new(test_reg_space(), 0x20, 32, 7);
        let rhs = Var::new(test_reg_space(), 0x24, 32, 9);
        let expr = arena.binop(BinOp::ADD, arena.var(lhs), arena.var(rhs));
        let mut replacer = arena.replacer();

        let mapped = replacer.map_generations(expr, |var| {
            if var.offset() == lhs.offset() {
                11
            } else {
                var.generation()
            }
        });

        match &*mapped {
            SSExpr::BinOp(BinOp::ADD, [l, r]) => {
                assert_eq!(*l, arena.var(lhs.with_generation(11)));
                assert_eq!(*r, arena.var(rhs));
            }
            other => panic!("expected add binop, got {other:?}"),
        }
    }

    #[test]
    fn replace_substitutes_single_binop_child() {
        let arena = SSExprArena::new();
        let lhs = arena.var(Var::new0(test_reg_space(), 0x30, 32));
        let rhs = arena.var(Var::new0(test_reg_space(), 0x34, 32));
        let expr = arena.binop(BinOp::ADD, lhs, rhs);
        let replacement = arena.val(1u32);
        let mut replacer = arena.replacer();

        let replaced = replacer.replace(expr, lhs, replacement).expect("replacement should occur");

        match &*replaced {
            SSExpr::BinOp(BinOp::ADD, [l, r]) => {
                assert_eq!(*l, replacement);
                assert_eq!(*r, rhs);
            }
            other => panic!("expected add binop, got {other:?}"),
        }
    }
}
