use std::collections::VecDeque;
use std::ops::{Neg, Not};

use ahash::{AHashMap as Map, AHashSet as Set};
use fugue::bv::BitVec;
use fugue::ir::Address;
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;

use crate::inject::{InjectionManager, InjectionStub};
use crate::ir::{BinOp, BinRel, BitSize, Expr, Stmt, Term, ToAddress, Type, UnOp, Var};
use crate::kb::block::CodeBlockId;
use crate::kb::function::{Function, FunctionId, FunctionTable};
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub const DATAFLOW_CONSTANT_FOLD: uuid::Uuid = uuid("7F863EF6-3D4D-4DD8-975F-2A74608E69C2");

#[derive(Clone, Debug)]
pub struct ConstFoldConfig {
    pub starts: Set<Address>,
    pub follow_calls: bool,
    pub follow_switches: bool,
    pub fixed_stack_pointer: Option<Address>,
    pub max_iter: usize,
}

impl Default for ConstFoldConfig {
    fn default() -> Self {
        Self {
            starts: Set::new(),
            follow_calls: false,
            follow_switches: true,
            fixed_stack_pointer: None,
            max_iter: 100,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockConsts {
    incoming: Map<Var, Option<BitVec>>,
    outgoing: Map<Var, Option<BitVec>>,
}

impl BlockConsts {
    pub fn incoming(&self) -> &Map<Var, Option<BitVec>> {
        &self.incoming
    }

    pub fn outgoing(&self) -> &Map<Var, Option<BitVec>> {
        &self.outgoing
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConstFold {
    config: ConstFoldConfig,
    mapping: Map<FunctionId, Map<CodeBlockId, BlockConsts>>,
}

impl ConstFold {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(config: ConstFoldConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn mapping(&self) -> &Map<FunctionId, Map<CodeBlockId, BlockConsts>> {
        &self.mapping
    }
}

impl AnalysisInfo for ConstFold {
    const NAME: &'static str = "Constant Folding";
    const UUID: uuid::Uuid = DATAFLOW_CONSTANT_FOLD;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for ConstFold {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if !self.config.starts.is_empty() {
            let starts = std::mem::take(&mut self.config.starts);

            for addr in starts.into_iter() {
                if let Some(f) = project.ftable.get_point(&addr) {
                    let mapping = ConstFoldVisitor::analyse_function(&project, &self.config, f);
                    self.mapping.insert(f.id(), mapping);
                }
            }
        } else {
            for f in project.ftable.values() {
                let mapping = ConstFoldVisitor::analyse_function(&project, &self.config, f);
                self.mapping.insert(f.id(), mapping);
            }
        }

        Ok(())
    }
}

pub struct ConstFoldVisitor<'a> {
    vars: Map<Var, Option<BitVec>>,
    functions: &'a FunctionTable,
    injections: &'a InjectionManager,
}

impl<'a> ConstFoldVisitor<'a> {
    fn eval_stmt(&mut self, stmt: &Term<Stmt>) {
        match stmt.value() {
            Stmt::Assign(var, expr) => {
                if let Some(val) = self.eval_expr(expr) {
                    self.vars.insert(*var, Some(val));
                } else {
                    self.vars.insert(*var, None);
                }
            }
            Stmt::Call(tgt, _) => {
                let Some(fixup) = tgt.to_address().and_then(|addr| {
                    self.functions.get_point(&addr).and_then(|f| {
                        self.injections
                            .get_function_stub(f.id())
                            .and_then(InjectionStub::fixup)
                    })
                }) else {
                    return;
                };

                for op in fixup.operations() {
                    self.eval_stmt(op);
                }
            }
            _ => (),
        }
    }

    fn eval_cast(&self, from: BitVec, to: &Term<Type>) -> Option<BitVec> {
        if to.is_bool() {
            return Some(if from.is_zero() {
                BitVec::zero(8)
            } else {
                BitVec::one(8)
            });
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
            Some(from)
        } else if tsign {
            // signed cast
            Some(from.signed().cast(tbits as usize))
        } else {
            // unsigned cast
            Some(from.unsigned().cast(tbits as usize))
        }
    }

    fn eval_expr(&mut self, expr: &Term<Expr>) -> Option<BitVec> {
        match expr.value() {
            Expr::Var(var) => self.vars.get(var).and_then(|val| val.as_ref().cloned()),
            Expr::Val(val, _) => Some(val.clone()),
            Expr::Load(_, _, _) => None,
            Expr::Cast(expr, to) => {
                let from = self.eval_expr(expr)?;
                self.eval_cast(from, to)
            }
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(expr)?;
                match op {
                    UnOp::NEG => Some(val.neg()),
                    UnOp::NOT => {
                        if expr.is_bool() {
                            Some(val.not() & BitVec::one(8))
                        } else {
                            Some(val.not())
                        }
                    }
                    UnOp::POPCOUNT(bits) => {
                        Some(BitVec::from_u32(val.count_ones(), *bits as usize))
                    }
                    _ => None,
                }
            }
            Expr::UnRel(_, _expr) => None,
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr)?;
                let rval = self.eval_expr(rexpr)?;

                match op {
                    BinOp::AND => Some(lval & rval),
                    BinOp::OR => Some(lval | rval),
                    BinOp::XOR => Some(lval ^ rval),
                    BinOp::ADD => Some(lval + rval),
                    BinOp::SUB => Some(lval - rval),
                    BinOp::MUL => Some(lval * rval),
                    BinOp::SHL => Some(lval << rval),
                    BinOp::SHR => Some(lval >> rval),
                    BinOp::SAR => Some(lval.signed() >> rval.signed()),
                    BinOp::DIV => {
                        if rval.is_zero() {
                            None
                        } else {
                            Some(lval / rval)
                        }
                    }
                    BinOp::SDIV => {
                        if rval.is_zero() {
                            None
                        } else {
                            Some(lval.signed() / rval.signed())
                        }
                    }
                    BinOp::REM => {
                        if rval.is_zero() {
                            None
                        } else {
                            Some(lval % rval)
                        }
                    }
                    BinOp::SREM => {
                        if rval.is_zero() {
                            None
                        } else {
                            Some(lval.signed() % rval.signed())
                        }
                    }
                }
            }
            Expr::BinRel(op, lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr)?;
                let rval = self.eval_expr(rexpr)?;

                let as_bool = |v: bool| if v { BitVec::one(8) } else { BitVec::zero(8) };

                Some(as_bool(match op {
                    BinRel::EQ => lval == rval,
                    BinRel::NEQ => lval != rval,
                    BinRel::LT => lval < rval,
                    BinRel::LE => lval <= rval,
                    BinRel::SLT => lval.signed() < rval.signed(),
                    BinRel::SLE => lval.signed() <= rval.signed(),
                    BinRel::SBORROW => lval.signed_borrow(&rval),
                    BinRel::CARRY => lval.carry(&rval),
                    BinRel::SCARRY => lval.signed_carry(&rval),
                }))
            }
            Expr::IfElse(cond, texpr, fexpr) => {
                if self.eval_expr(cond)?.is_zero() {
                    self.eval_expr(fexpr)
                } else {
                    self.eval_expr(texpr)
                }
            }
            Expr::Choice(_, _, _, _) => None,
            Expr::Concat(lexpr, rexpr) => {
                let lval = self.eval_expr(lexpr)?;
                let rval = self.eval_expr(rexpr)?;

                let tbits = lval.nbits() + rval.nbits();
                let sbits = rval.nbits();

                let lvex = lval.unsigned().cast(tbits as usize) << sbits;
                let rvex = rval.unsigned().cast(tbits as usize);

                Some(lvex | rvex)
            }
            Expr::Extract(expr, lsb, msb) => {
                let val = self.eval_expr(expr)?;

                if (msb - lsb) == val.nbits() {
                    Some(val)
                } else {
                    Some(if *lsb > 0 {
                        (val >> *lsb).unsigned().cast((msb - lsb) as usize)
                    } else {
                        val.unsigned().cast((msb - lsb) as usize)
                    })
                }
            }
            Expr::ExtractHigh(expr, bits) => {
                let val = self.eval_expr(expr)?;
                let vbits = val.nbits();

                if vbits > *bits {
                    Some((val.unsigned() >> (vbits - bits)).cast(*bits as usize))
                } else {
                    Some(val.unsigned().cast(*bits as usize))
                }
            }
            Expr::ExtractLow(expr, bits) => {
                let val = self.eval_expr(expr)?;

                Some(val.unsigned().cast(*bits as usize))
            }
            Expr::Intrinsic(_, _, _) => None,
        }
    }

    pub fn analyse_function(
        project: &Project,
        config: &ConstFoldConfig,
        f: &Function,
    ) -> Map<CodeBlockId, BlockConsts> {
        let injections = project.injections();
        let functions = project.functions();

        let mut bvmap = Map::new();
        let mut worklist = VecDeque::new();

        let mut normalised_blocks = Map::new();
        let sp = project.lifter().stack_pointer();
        let sp_val = config
            .fixed_stack_pointer
            .map(|addr| BitVec::from_u64(addr.into(), sp.nbits() as usize));

        let mut hits = Map::new();

        f.normalised_blocks_with(&project, |blk| {
            let mut bbvmap = ConstFoldVisitor {
                vars: Default::default(),
                functions,
                injections,
            };

            if blk.address() == f.address() {
                bbvmap.vars.insert(sp, sp_val.clone());
            }

            for insn in blk.insns() {
                for op in insn.operations() {
                    bbvmap.eval_stmt(op);
                }
            }

            hits.insert(blk.id(), 1);

            bvmap.insert(
                blk.id(),
                BlockConsts {
                    incoming: Default::default(),
                    outgoing: bbvmap.vars,
                },
            );

            worklist.push_back(blk.id());
            normalised_blocks.insert(blk.id(), blk);
        });

        while let Some(blk) = worklist.pop_front() {
            let blk = &normalised_blocks[&blk];

            let mut bbvmap = ConstFoldVisitor {
                vars: Default::default(),
                functions,
                injections,
            };

            if blk.address() == f.address() {
                bbvmap.vars.insert(sp, sp_val.clone());
            }

            for pred in project
                .icfg()
                .edges_directed(blk.node(), EdgeDirection::Incoming)
            {
                if let Some(BlockConsts { outgoing, .. }) =
                    bvmap.get(&project.icfg()[pred.source()])
                {
                    for (var, val) in outgoing.iter() {
                        if matches!(bbvmap.vars.get(var), Some(old_val) if old_val != val) {
                            bbvmap.vars.insert(*var, None);
                        } else {
                            bbvmap.vars.insert(*var, val.clone());
                        }
                    }
                }
            }

            let incoming_bbvmap = bbvmap.vars.clone();

            for insn in blk.insns() {
                for op in insn.operations() {
                    bbvmap.eval_stmt(op);
                }
            }

            let mut did_change = true;

            let current_hits = hits.get_mut(&blk.id()).unwrap();
            *current_hits += 1;

            if let Some(BlockConsts { outgoing, .. }) = bvmap.remove(&blk.id()) {
                did_change = outgoing != bbvmap.vars;
                if did_change && *current_hits >= config.max_iter {
                    bbvmap.vars.retain(|k, v| match outgoing.get(k) {
                        None => false,
                        Some(ov) => ov == v,
                    })
                }
            }

            bvmap.insert(
                blk.id(),
                BlockConsts {
                    incoming: incoming_bbvmap,
                    outgoing: bbvmap.vars,
                },
            );

            if did_change {
                for succ in project
                    .icfg()
                    .edges_directed(blk.node(), EdgeDirection::Outgoing)
                {
                    if (!config.follow_switches && succ.weight().is_switch())
                        || (!config.follow_calls && succ.weight().is_call())
                        || !f.blocks().contains_key(&project.icfg()[succ.target()])
                    {
                        continue;
                    }

                    worklist.push_back(project.icfg()[succ.target()]);
                }
            }
        }

        bvmap
    }
}
