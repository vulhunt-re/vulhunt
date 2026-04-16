use crate::prelude::*;

use super::SSE;
use super::arena::{SSEMatcher, SSEReplacer, SSExprArena};
use super::expr::SSExprRef;
use super::validity::{SSEValidity, SSEValidityLocation, SSEValiditySource, SSEValidityState};

pub struct SSEContext<'a> {
    arena: &'a SSExprArena,
    replacer: SSEReplacer<'a>,
    matcher: SSEMatcher<'a>,
    project: &'a Project,
}

impl<'a> SSEContext<'a> {
    pub fn new(arena: &'a SSExprArena, project: &'a Project) -> Self {
        Self::new_with(arena, project, None)
    }

    pub fn new_with(
        arena: &'a SSExprArena,
        project: &'a Project,
        limit: impl Into<Option<usize>>,
    ) -> Self {
        let replacer = SSEReplacer::new_with(arena, limit);
        let matcher = SSEMatcher::new();
        Self {
            arena,
            replacer,
            matcher,
            project,
        }
    }

    pub fn arena(&self) -> &'a SSExprArena {
        self.arena
    }

    pub fn project(&self) -> &'a Project {
        self.project
    }

    pub fn matcher(&mut self) -> &mut SSEMatcher<'a> {
        &mut self.matcher
    }

    pub fn replacer(&mut self) -> &mut SSEReplacer<'a> {
        &mut self.replacer
    }

    pub fn substitute_defs(
        &mut self,
        loc: &Location,
        op: &Term<Stmt>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        // NOTE: we only consider assignments or stores (per rules from Table 2)
        match op.value() {
            Stmt::Assign(var, expr) => self.substitute_defs_assignment(loc, var, expr, sse),
            Stmt::Store(texpr, sexpr, sz, _) => {
                let var = texpr.variable()?;
                self.substitute_defs_store(loc, var, sexpr, *sz, sse)
            }
            _ => None,
        }
    }

    fn substitute_defs_assignment(
        &mut self,
        loc: &Location,
        ri: &Var,
        expr: &Term<Expr>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        match expr.value() {
            Expr::Val(rj, _) => {
                // rule 1
                let rj = self.arena.val(rj.clone());
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 1 (forward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    rj.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, rj, ri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::forward(SSEValidityState::ForwardOnly, *loc),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::Var(rj) => {
                // rule 1
                let rj = self.arena.var(*rj);
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 1 (forward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    rj.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, rj, ri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::forward(SSEValidityState::ForwardOnly, *loc),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::BinOp(op, e1, e2) => {
                // rule 2
                self.substitute_defs_assignment_rule_2(loc, ri, *op, e1, e2, sse)
            }
            Expr::Load(rj, sz, _) => {
                let rj = self.arena.from_expr(rj)?;
                // rule 5
                let r5_tgt = self.arena.load(rj, *sz);
                // rule 7
                let r7_tgt = self.arena.store(rj, *sz);
                let ri = self.arena.var(*ri);
                tracing::trace!(
                    "applying rule 5 (forward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    r5_tgt.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, r5_tgt, ri).or_else(|| {
                    tracing::trace!(
                        "applying rule 7 (forward flow): current = {}, target = {}, replacement = {}",
                        sse.display(self.project),
                        r7_tgt.display(self.project),
                        ri.display(self.project)
                    );
                    self.replacer.replace(sse, r7_tgt, ri)
                })?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::forward(SSEValidityState::ForwardOnly, *loc),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            _ => None,
        }
    }

    fn substitute_defs_assignment_rule_2(
        &mut self,
        loc: &Location,
        ri: &Var,
        op: BinOp,
        e1: &Term<Expr>,
        e2: &Term<Expr>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        // attempt base rule 2 (regular flow)
        if let Some(nsse) = self.substitute_defs_assignment_rule_2_base(loc, ri, op, e1, e2, sse) {
            return Some(nsse);
        }

        // rule 2 failed to apply; we now try some special cases
        match op {
            BinOp::ADD if e2.is_val() => {
                // rule 2 (special case for base with addition)
                // ri = e1 + const → e1 = ri - const
                tracing::trace!("substituting defs with addition; special case 1");

                let tgt = self.arena.from_expr(e1)?;
                let lhs = self.arena.var(*ri);
                let nri = if e2.is_val_with(BitVec::is_zero) {
                    lhs
                } else {
                    self.arena.binop(BinOp::SUB, lhs, self.arena.from_expr(e2)?)
                };

                tracing::trace!(
                    "applying rule 2 (forward flow; base with addition): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    tgt.display(self.project),
                    nri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, tgt, nri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::forward(SSEValidityState::ForwardOnly, *loc),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            BinOp::SUB if e2.is_val() => {
                // rule 2 (special case for base with subtraction)
                tracing::trace!("substituting defs with subtraction; special case 2");

                let tgt = self.arena.from_expr(e1)?;
                let lhs = self.arena.var(*ri);
                let nri = if e2.is_val_with(BitVec::is_zero) {
                    lhs
                } else {
                    self.arena.binop(BinOp::ADD, lhs, self.arena.from_expr(e2)?)
                };

                tracing::trace!(
                    "applying rule 2 (forward flow; base with subtraction): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    tgt.display(self.project),
                    nri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, tgt, nri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::forward(SSEValidityState::ForwardOnly, *loc),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            _ => None,
        }
    }

    fn substitute_defs_assignment_rule_2_base(
        &mut self,
        loc: &Location,
        ri: &Var,
        op: BinOp,
        e1: &Term<Expr>,
        e2: &Term<Expr>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        // rule 2 (regular flow)
        let lhs = self.arena.from_expr(e1)?;
        let rhs = self.arena.from_expr(e2)?;
        let tgt = self.arena.binop(op, lhs, rhs);
        let var = self.arena.var(*ri);

        tracing::trace!(
            "applying rule 2 (forward flow): current = {}, target = {}, replacement = {}",
            sse.display(self.project),
            tgt.display(self.project),
            var.display(self.project)
        );
        let nsse = self.replacer.replace(sse, tgt, var)?;

        Some(
            SSE::new(
                nsse,
                SSEValidity::forward(SSEValidityState::ForwardOnly, *loc),
            )
            .with_source(SSEValiditySource::new(*loc, sse)),
        )
    }

    fn substitute_defs_store(
        &mut self,
        loc: &Location,
        var: &Var,
        expr: &Term<Expr>,
        sz: u32,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        // rule 6
        let rj = self.arena.var(expr.variable().copied()?);
        let var = self.arena.var(*var);
        let store = self.arena.store(var, sz);

        tracing::trace!(
            "applying rule 6 (forward flow): current = {}, target = {}, replacement = {}",
            sse.display(self.project),
            rj.display(self.project),
            store.display(self.project)
        );
        let nsse = self.replacer.replace(sse, rj, store)?;

        Some(
            SSE::new(
                nsse,
                SSEValidity::forward(SSEValidityState::Both, *loc),
            )
            .with_source(SSEValiditySource::new(*loc, sse)),
        )
    }

    pub fn substitute_defs_backward(
        &mut self,
        loc: &Location,
        not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
        op: &Term<Stmt>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        match op.value() {
            Stmt::Assign(var, expr) => self.substitute_defs_backward_assignment(
                loc,
                not_valid_before,
                not_valid_after,
                var,
                expr,
                sse,
            ),
            Stmt::Store(texpr, sexpr, sz, _) => {
                let var = texpr.variable()?;
                self.substitute_defs_backward_store(
                    loc,
                    not_valid_before,
                    not_valid_after,
                    var,
                    sexpr,
                    *sz,
                    sse,
                )
            }
            _ => None,
        }
    }

    fn substitute_defs_backward_assignment(
        &mut self,
        loc: &Location,
        _not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
        ri: &Var,
        expr: &Term<Expr>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        match expr.value() {
            Expr::Val(rj, _) => {
                // rule 1
                let rj = self.arena.val(rj.clone());
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 1 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    rj.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, rj, ri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::ForwardOnly,
                            SSEValidityLocation::from(*loc),
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::Var(rj) => {
                // rule 1
                let rj = self.arena.var(*rj);
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 1 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    rj.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, rj, ri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::ForwardOnly,
                            SSEValidityLocation::from(*loc),
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::BinOp(op, e1, e2) => {
                // rule 2
                let lhs = self.arena.from_expr(e1)?;
                let rhs = self.arena.from_expr(e2)?;
                let tgt = self.arena.binop(*op, lhs, rhs);
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 2 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    tgt.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, tgt, ri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::ForwardOnly,
                            SSEValidityLocation::from(*loc),
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::Load(rj, sz, _) => {
                // rule 5
                let rj = self.arena.from_expr(rj)?;
                let r5_tgt = self.arena.load(rj, *sz);
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 5 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    r5_tgt.display(self.project),
                    ri.display(self.project)
                );
                let nsse = self.replacer.replace(sse, r5_tgt, ri)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::ForwardOnly,
                            SSEValidityLocation::from(*loc),
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            _ => None,
        }
    }

    fn substitute_defs_backward_store(
        &mut self,
        loc: &Location,
        _not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
        var: &Var,
        expr: &Term<Expr>,
        sz: u32,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        // rule 6
        let rj = self.arena.var(expr.variable().copied()?);
        let var = self.arena.var(*var);
        let store = self.arena.store(var, sz);

        tracing::trace!(
            "applying rule 6 (backward flow): current = {}, target = {}, replacement = {}",
            sse.display(self.project),
            rj.display(self.project),
            store.display(self.project)
        );
        let nsse = self.replacer.replace(sse, rj, store)?;

        Some(
            SSE::new(
                nsse,
                SSEValidity::backward(
                    SSEValidityState::Both,
                    SSEValidityLocation::from(*loc),
                    not_valid_after,
                ),
            )
            .with_source(SSEValiditySource::new(*loc, sse)),
        )
    }

    pub fn substitute_uses(
        &mut self,
        loc: &Location,
        not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
        op: &Term<Stmt>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        match op.value() {
            Stmt::Assign(var, expr) => self.substitute_uses_assignment(
                loc,
                not_valid_before,
                not_valid_after,
                var,
                expr,
                sse,
            ),
            Stmt::Store(texpr, sexpr, sz, _) => {
                let var = texpr.variable()?;
                self.substitute_uses_store(
                    loc,
                    not_valid_before,
                    not_valid_after,
                    var,
                    sexpr,
                    *sz,
                    sse,
                )
            }
            _ => None,
        }
    }

    fn substitute_uses_assignment(
        &mut self,
        loc: &Location,
        not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
        ri: &Var,
        expr: &Term<Expr>,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        match expr.value() {
            Expr::Var(rj) => {
                // rule 8
                let ri = self.arena.var(*ri);
                let rj = self.arena.var(*rj);

                tracing::trace!(
                    "applying rule 8 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    ri.display(self.project),
                    rj.display(self.project)
                );
                let nsse = self.replacer.replace(sse, ri, rj)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::Both,
                            not_valid_before,
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::BinOp(op, e1, e2) => {
                // rule 9
                let lhs = self.arena.from_expr(e1)?;
                let rhs = self.arena.from_expr(e2)?;
                let tgt = self.arena.binop(*op, lhs, rhs);
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 8 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    ri.display(self.project),
                    tgt.display(self.project)
                );
                let nsse = self.replacer.replace(sse, ri, tgt)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::Both,
                            not_valid_before,
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            Expr::Load(rj, sz, _) => {
                // rule 12
                let rj = self.arena.from_expr(rj)?;
                let tgt = self.arena.load(rj, *sz);
                let ri = self.arena.var(*ri);

                tracing::trace!(
                    "applying rule 12 (backward flow): current = {}, target = {}, replacement = {}",
                    sse.display(self.project),
                    ri.display(self.project),
                    tgt.display(self.project)
                );
                let nsse = self.replacer.replace(sse, ri, tgt)?;

                Some(
                    SSE::new(
                        nsse,
                        SSEValidity::backward(
                            SSEValidityState::Both,
                            not_valid_before,
                            not_valid_after,
                        ),
                    )
                    .with_source(SSEValiditySource::new(*loc, sse)),
                )
            }
            _ => None,
        }
    }

    fn substitute_uses_store(
        &mut self,
        loc: &Location,
        not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
        var: &Var,
        expr: &Term<Expr>,
        sz: u32,
        sse: SSExprRef<'a>,
    ) -> Option<SSE<'a>> {
        // rule 13
        let rj = self.arena.var(expr.variable().copied()?);
        let var = self.arena.var(*var);
        let store = self.arena.store(var, sz);

        tracing::trace!(
            "applying rule 13 (backward flow): current = {}, target = {}, replacement = {}",
            sse.display(self.project),
            store.display(self.project),
            rj.display(self.project)
        );
        let nsse = self.replacer.replace(sse, store, rj)?;

        Some(
            SSE::new(
                nsse,
                SSEValidity::backward(SSEValidityState::Both, not_valid_before, not_valid_after),
            )
            .with_source(SSEValiditySource::new(*loc, sse)),
        )
    }
}
