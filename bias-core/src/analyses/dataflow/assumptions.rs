use std::borrow::Cow;
use std::collections::hash_map::Entry;

use ahash::{AHashMap as Map, AHashSet as Set};
use fugue::ir::{Address, AddressSpaceId};
use smallvec::SmallVec;

use crate::domains::interval::BitVecInterval;
use crate::ir::{BinOp, BinRel, BitSize, Expr, Insn, Stmt, Term, Type, UnOp, Var};
use crate::kb::block::CodeBlockId;
use crate::kb::function::{Function, FunctionId};
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub const DATAFLOW_ASSUMPTIONS: uuid::Uuid = uuid("651B1139-8394-4EAB-9E4A-9FBBD81672C6");
pub const ASSUMPTION_VAR_INDEX: usize = 0x1000;
pub const ASSUMPTION_BB_LIMIT: usize = 20;

#[derive(Clone, Debug)]
pub struct AssumptionsConfig {
    pub starts: Set<Address>,
    pub propagate_outgoing: bool, // for now this is ignored
}

impl Default for AssumptionsConfig {
    fn default() -> Self {
        Self {
            starts: Set::new(),
            propagate_outgoing: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Assumptions {
    config: AssumptionsConfig,
    mapping: Map<FunctionId, Map<CodeBlockId, Term<Expr>>>,
}

impl Assumptions {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(config: AssumptionsConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn mapping(&self) -> &Map<FunctionId, Map<CodeBlockId, Term<Expr>>> {
        &self.mapping
    }
}

impl AnalysisInfo for Assumptions {
    const NAME: &'static str = "Branch Assumptions";
    const UUID: uuid::Uuid = DATAFLOW_ASSUMPTIONS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for Assumptions {
    fn id(&self) -> &uuid::Uuid {
        &DATAFLOW_ASSUMPTIONS
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if !self.config.starts.is_empty() {
            let starts = std::mem::take(&mut self.config.starts);

            for addr in starts.into_iter() {
                if let Some(f) = project.ftable.get_point(&addr) {
                    let mapping = BlockAssumptions::analyse_function(&project, &self.config, f);
                    self.mapping.insert(f.id(), mapping);
                }
            }
        } else {
            for f in project.ftable.values() {
                let mapping = BlockAssumptions::analyse_function(&project, &self.config, f);
                self.mapping.insert(f.id(), mapping);
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct BlockAssumptions {
    vars: Map<Var, Option<(Address, Term<Expr>)>>,
    cond: Option<Term<Expr>>,
    assumption_space: AddressSpaceId,
    assumption_offset: u64,
    assumption_loads: Map<(Term<Expr>, u32), Var>,
}

impl Default for BlockAssumptions {
    fn default() -> Self {
        Self {
            vars: Default::default(),
            cond: Default::default(),
            assumption_space: AddressSpaceId::unmapped_id(ASSUMPTION_VAR_INDEX),
            assumption_offset: 0,
            assumption_loads: Default::default(),
        }
    }
}

impl BlockAssumptions {
    pub fn is_memory_var(&self, var: &Var) -> bool {
        var.space == self.assumption_space
    }

    pub fn memory_vars(&self) -> impl ExactSizeIterator<Item = (&Term<Expr>, u32, &Var)> {
        self.assumption_loads.iter().map(|((e, b), v)| (e, *b, v))
    }

    pub fn memory_expr(&self, var: &Var) -> Option<(&Term<Expr>, u32)> {
        // this should be fast enough for a block
        self.memory_vars()
            .find_map(|(e, b, v)| if v == var { Some((e, b)) } else { None })
    }

    fn memory_var(&mut self, expr: &Term<Expr>, bits: u32) -> Var {
        let pair = (expr.clone(), bits);
        match self.assumption_loads.entry(pair) {
            Entry::Vacant(entry) => {
                let var = Var::new0(self.assumption_space, self.assumption_offset, bits);
                self.assumption_offset += bits as u64 / 8;
                *entry.insert(var)
            }
            Entry::Occupied(entry) => *entry.get(),
        }
    }

    fn eval_stmt_with<F>(&mut self, addr: Address, stmt: &Term<Stmt>, implicit_cond: bool, mut f: F)
    where
        F: FnMut(Cow<Term<Expr>>) -> Term<Expr>,
    {
        match stmt.value() {
            Stmt::Assign(var, expr) => {
                if let Some(val) = self.eval_expr(expr) {
                    if implicit_cond {
                        if let Some((var, val)) = val.cond_via_and() {
                            self.cond = Some(Expr::int_le(Expr::var(*var), Expr::val(val.clone())));
                        }
                    }
                    self.vars.insert(*var, Some((addr, f(Cow::Owned(val)))));
                } else {
                    self.vars.insert(*var, None);
                }
            }
            Stmt::Store(target, source, bits, _spc) => {
                let var = self.memory_var(target, *bits);
                if let Some(val) = self.eval_expr(source) {
                    self.vars.insert(var, Some((addr, f(Cow::Owned(val)))));
                } else {
                    self.vars.insert(var, None);
                }
            }
            Stmt::CBranch(cond, _) => {
                self.cond = self.eval_expr(cond);
            }
            _ => (),
        }
    }

    fn eval_stmt(&mut self, addr: Address, stmt: &Term<Stmt>) {
        self.eval_stmt_with(addr, stmt, false, |t| t.canonical())
    }

    fn eval_cast(&self, from: Term<Expr>, to: &Term<Type>) -> Option<Term<Expr>> {
        if to.is_bool() {
            return Some(from.into());
        }

        if to.is_float() {
            return None;
        }

        let tbits = to.nbits();

        if tbits == 0 {
            return None;
        }

        let tsign = to.is_signed();

        let fbits = from.nbits();
        let fsign = from.is_signed();

        if fbits == tbits && fsign == tsign {
            // no-op
            Some(from.into())
        } else if tsign {
            // signed cast
            Some(Expr::cast_signed(from, tbits))
        } else {
            // unsigned cast
            Some(Expr::cast_unsigned(from, tbits))
        }
    }

    fn eval_expr(&mut self, expr: &Term<Expr>) -> Option<Term<Expr>> {
        match expr.value() {
            Expr::Var(var) => self
                .vars
                .get(var)
                .and_then(|val| val.as_ref().map(|(_, val)| val.clone()))
                .or_else(|| {
                    if var.is_temporary() {
                        None
                    } else {
                        Some(Expr::var(*var))
                    }
                }),
            Expr::Val(val, _) => Some(Expr::val(val.clone())),
            Expr::Load(lexpr, bits, _) => {
                let lexpr = self.eval_expr(lexpr)?;
                let var = self.memory_var(&lexpr, *bits);
                self.vars
                    .get(&var)
                    .and_then(|val| val.as_ref().map(|(_, val)| val.clone()))
                    .or_else(|| Some(Expr::var(var)))
            }
            Expr::Cast(expr, to) => {
                let from = self.eval_expr(expr)?;
                self.eval_cast(from, to)
            }
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(expr)?;
                match op {
                    UnOp::NOT => {
                        if expr.is_bool() {
                            Some(Expr::bool_not(val))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            Expr::UnRel(_, _expr) => None,
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr)?;
                let rval = self.eval_expr(rexpr)?;

                match op {
                    BinOp::AND => {
                        if lexpr.is_bool() || rexpr.is_bool() {
                            Some(Expr::bool_and(lval, rval))
                        } else {
                            Some(Expr::int_and(lval, rval))
                        }
                    }
                    BinOp::OR => {
                        if lexpr.is_bool() || rexpr.is_bool() {
                            Some(Expr::bool_or(lval, rval))
                        } else {
                            Some(Expr::int_or(lval, rval))
                        }
                    }
                    BinOp::XOR => {
                        if lexpr.is_bool() || rexpr.is_bool() {
                            Some(Expr::bool_xor(lval, rval))
                        } else {
                            Some(Expr::int_xor(lval, rval))
                        }
                    }
                    BinOp::ADD => Some(Expr::int_add(lval, rval)),
                    BinOp::SUB => Some(Expr::int_sub(lval, rval)),
                    _ => None,
                }
            }
            Expr::BinRel(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr)?;
                let rval = self.eval_expr(rexpr)?;

                Some(match op {
                    BinRel::EQ => Expr::int_eq(lval, rval),
                    BinRel::NEQ => Expr::int_neq(lval, rval),
                    BinRel::LT => Expr::int_lt(lval, rval),
                    BinRel::LE => Expr::int_le(lval, rval),
                    BinRel::SLT => Expr::int_slt(lval, rval),
                    BinRel::SLE => Expr::int_sle(lval, rval),
                    BinRel::SBORROW => Expr::int_sborrow(lval, rval),
                    BinRel::CARRY => Expr::int_carry(lval, rval),
                    BinRel::SCARRY => Expr::int_scarry(lval, rval),
                })
            }
            Expr::Extract(v, loff, moff) => {
                let v = self.eval_expr(v)?;
                Some(Expr::extract(v, *loff, *moff))
            }
            Expr::ExtractHigh(v, bits) => {
                let v = self.eval_expr(v)?;
                Some(Expr::extract_high(v, *bits))
            }
            Expr::ExtractLow(v, bits) => {
                let v = self.eval_expr(v)?;
                Some(Expr::extract_low(v, *bits))
            }
            _ => None,
        }
    }

    pub fn analyse_condition<'a, I: 'a>(
        &mut self,
        insns: I,
        invert: bool,
    ) -> Option<(Var, BitVecInterval)>
    where
        I: Iterator<Item = &'a Term<Insn>>,
    {
        self.vars.clear();
        self.cond = None;

        for insn in insns {
            for op in insn.operations() {
                self.eval_stmt(insn.address(), op);
            }
        }

        tracing::trace!("building conditional assumptions");

        self.cond.take().and_then(|cond| {
            if invert {
                BitVecInterval::from_flags(&Expr::bool_not(cond))
            } else {
                BitVecInterval::from_flags(&cond)
            }
        })
    }

    // Backward-bounded version; iteratively increase backward bound until we hit the block end
    // (fail) or get a viable condition.
    pub fn analyse_implicit_condition_bb_with<'a, I: 'a, F>(
        &mut self,
        insns: I,
        mut simplifier: F,
    ) -> Option<(Address, Var, BitVecInterval)>
    where
        I: Iterator<Item = &'a Term<Insn>>,
        F: FnMut(Cow<Term<Expr>>) -> Term<Expr>,
    {
        let insns = SmallVec::<[&'a Term<Insn>; 10]>::from_iter(insns);
        let mut seen_load = false;

        for bb in (0..insns.len().min(ASSUMPTION_BB_LIMIT)).rev() {
            self.vars.clear();
            self.cond = None;

            let off = insns.len() - bb;

            for insn in &insns[off..] {
                for op in insn.operations() {
                    if seen_load {
                        self.eval_stmt_with(insn.address(), op, true, &mut simplifier);
                    } else {
                        seen_load = op.has_load();
                    }
                }
            }

            tracing::trace!(
                "building implicit conditional assumptions with condition: {:#?}",
                self.cond
            );

            let ncond = self.cond.take().and_then(|cond| {
                let (var, vals) = BitVecInterval::from_flags(&cond)?;
                Some((insns[bb].address(), var, vals))
            });

            if ncond.is_some() {
                return ncond;
            }
        }

        None
    }

    // Backward-bounded version; iteratively increase backward bound until we hit the block end
    // (fail) or get a viable condition.
    pub fn analyse_condition_bb_with<'a, I: 'a, F>(
        &mut self,
        insns: I,
        invert: bool,
        mut simplifier: F,
    ) -> Option<(Address, Option<Address>, Var, BitVecInterval)>
    where
        I: Iterator<Item = &'a Term<Insn>>,
        F: FnMut(Cow<Term<Expr>>) -> Term<Expr>,
    {
        let insns = SmallVec::<[&'a Term<Insn>; 10]>::from_iter(insns);

        for bb in 1..=insns.len().min(ASSUMPTION_BB_LIMIT) {
            self.vars.clear();
            self.cond = None;

            let off = insns.len() - bb;

            for insn in &insns[off..] {
                for op in insn.operations() {
                    self.eval_stmt_with(insn.address(), op, false, &mut simplifier);
                }
            }

            tracing::trace!(
                "building conditional assumptions with condition: {:#?}",
                self.cond
            );

            let ncond = self
                .cond
                .take()
                .and_then(|cond| {
                    if invert {
                        BitVecInterval::from_flags_with(&Expr::bool_not(cond), &mut simplifier)
                    } else {
                        BitVecInterval::from_flags_with(&cond, &mut simplifier)
                    }
                })
                .map(|(var, vals)| {
                    (
                        insns[off].address(),
                        self.vars
                            .get(&var)
                            .and_then(|av| av.as_ref().map(|(addr, _)| *addr)),
                        var,
                        vals,
                    )
                });

            if ncond.is_some() {
                return ncond;
            }
        }

        None
    }

    pub fn analyse_condition_with<'a, I: 'a, F>(
        &mut self,
        insns: I,
        invert: bool,
        mut simplifier: F,
    ) -> Option<(Option<Address>, Var, BitVecInterval)>
    where
        I: Iterator<Item = &'a Term<Insn>>,
        F: FnMut(Cow<Term<Expr>>) -> Term<Expr>,
    {
        self.vars.clear();
        self.cond = None;

        for insn in insns {
            for op in insn.operations() {
                self.eval_stmt_with(insn.address(), op, false, &mut simplifier);
            }
        }

        tracing::trace!(
            "building conditional assumptions with condition: {:#?}",
            self.cond
        );

        self.cond
            .take()
            .and_then(|cond| {
                if invert {
                    BitVecInterval::from_flags_with(&Expr::bool_not(cond), simplifier)
                } else {
                    BitVecInterval::from_flags_with(&cond, simplifier)
                }
            })
            .map(|(var, vals)| {
                (
                    self.vars
                        .get(&var)
                        .and_then(|av| av.as_ref().map(|(addr, _)| *addr)),
                    var,
                    vals,
                )
            })
    }

    fn analyse_function(
        project: &Project,
        _config: &AssumptionsConfig,
        f: &Function,
    ) -> Map<CodeBlockId, Term<Expr>> {
        let mut assumptions = Map::new();
        let mut assume = BlockAssumptions::default();

        f.normalised_blocks_with(project, |blk| {
            for insn in blk.insns() {
                for op in insn.operations() {
                    assume.eval_stmt(insn.address(), op);
                }
            }

            if let Some(cond) = assume.cond.take() {
                assumptions.insert(blk.id(), cond);
            }

            assume.vars.clear();
        });

        assumptions
    }
}
