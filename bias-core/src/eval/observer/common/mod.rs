use std::borrow::Cow;

use fugue::bv::BitVec;
use uuid::Uuid;

use super::{Observer, ObserverError};
use crate::any::ProvidesStaticType;
use crate::eval::{IRContext, ObserverContext, ObserverState};
use crate::ir::{Address, BitSize, Var};
use crate::lifter::Lifter;
use crate::prelude::visit::VisitMut;
use crate::prelude::{uuid, Expr, Insn, Location, Term};

pub mod stack;

pub struct OverrideVarAt {
    address: Address,
    var: Var,
    val: BitVec,
}

impl OverrideVarAt {
    pub fn new(address: impl Into<Address>, var: Var, val: impl Into<BitVec>) -> Self {
        Self {
            address: address.into(),
            var,
            val: val.into(),
        }
    }

    pub fn new_addr(address: impl Into<Address>, var: Var, val: impl Into<Address>) -> Self {
        let size = var.nbits();
        let value = BitVec::from_u64(u64::from(val.into()), size as usize);

        Self::new(address, var, value)
    }
}

impl Observer for OverrideVarAt {
    fn observe_insn(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        _insn: &Term<Insn>,
    ) -> Result<bool, ObserverError> {
        if self.address == location.address() {
            context.write_var(&self.var, &self.val)?;
        }
        Ok(false)
    }
}

#[derive(Default)]
pub struct OverrideVarCond(Option<(Address, Var, BitVec)>);

impl OverrideVarCond {
    pub fn enable(&mut self, address: impl Into<Address>, var: Var, val: impl Into<BitVec>) {
        self.0 = Some((address.into(), var, val.into()));
    }

    pub fn disable(&mut self) {
        self.0 = None;
    }
}

impl Observer for OverrideVarCond {
    fn restore(&mut self) -> Result<(), ObserverError> {
        self.disable();
        Ok(())
    }

    fn observe_insn(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        _insn: &Term<Insn>,
    ) -> Result<bool, ObserverError> {
        match &self.0 {
            Some((a, var, val)) if *a == location.address() => {
                context.write_var(var, val)?;
            }
            _ => (),
        }
        Ok(false)
    }
}

#[derive(Default)]
pub struct OverrideLoadCond(Option<OverrideLoad>);

impl OverrideLoadCond {
    pub fn enable(&mut self, expr: Term<Expr>, bits: u32, value: BitVec) {
        self.0 = Some(OverrideLoad { expr, bits, value });
    }

    pub fn disable(&mut self) {
        self.0 = None;
    }
}

pub struct OverrideLoad {
    expr: Term<Expr>,
    bits: u32,
    value: BitVec,
}

#[derive(ProvidesStaticType)]
pub struct OverrideLoadCtx<'a>(&'a Lifter);

impl<'a> OverrideLoadCtx<'a> {
    pub fn new(lifter: &'a Lifter) -> Self {
        Self(lifter)
    }
}

pub const OVERRIDE_LOAD: Uuid = uuid("6C08048C-F8C8-4563-9E16-1FF6879417CC");

impl<'a> ObserverState<'a> for OverrideLoadCtx<'a> {
    fn id(&self) -> &Uuid {
        &OVERRIDE_LOAD
    }
}

impl Observer for OverrideLoadCond {
    fn restore(&mut self) -> Result<(), ObserverError> {
        self.disable();
        Ok(())
    }

    fn override_insn_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        insn: &mut Cow<Term<Insn>>,
    ) -> Result<(), ObserverError> {
        if let Some(ref mut slf) = self.0 {
            slf.override_insn_with(context, observer_context, location, insn)?;
        }
        Ok(())
    }
}

impl VisitMut for OverrideLoad {
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
            Expr::Intrinsic(ref mut name, ref mut args, bits) => {
                self.visit_expr_intrinsic_mut(name.as_str(), args, *bits)
            }
        }

        if matches!(&**expr, Expr::Load(lexpr, bits, _) if self.expr == *lexpr && self.bits == *bits)
        {
            *expr = Expr::val(self.value.clone());
        }
    }
}

impl Observer for OverrideLoad {
    fn override_insn_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        _location: Location,
        insn: &mut Cow<Term<Insn>>,
    ) -> Result<(), ObserverError> {
        if insn.has_loop() {
            return Ok(());
        }

        if let Some(lifter_ctx) = observer_context.get::<OverrideLoadCtx>(OVERRIDE_LOAD) {
            let insn = insn.to_mut();

            insn.compact_temporaries(lifter_ctx.0);

            for op in insn.operations_mut() {
                self.visit_stmt_mut(op);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct CallObserver(Option<Address>);

impl CallObserver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn take(&mut self) -> Option<Address> {
        self.0.take()
    }
}

impl Observer for CallObserver {
    fn restore(&mut self) -> Result<(), ObserverError> {
        self.0 = None;
        Ok(())
    }

    fn observe_pre_call(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        _location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        self.0 = Some(target);
        Ok(())
    }
}
