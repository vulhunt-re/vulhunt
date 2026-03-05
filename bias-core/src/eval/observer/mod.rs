use std::borrow::Cow;

use downcast_rs::{impl_downcast, Downcast};
use fugue::bv::BitVec;
use fugue::ir::Address;
use thiserror::Error;
use ustr::Ustr;

use crate::eval::{IRContext, ObserverContext};
use crate::ir::{Expr, Insn, Location, Stmt, Term, Var};
use crate::kb::block::CodeBlock;
use crate::kb::function::Function;
use crate::kb::function_summary::FunctionSummary;

pub mod common;

#[derive(Debug, Error)]
pub enum ObserverError {
    #[error(transparent)]
    Observer(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Tracer(#[from] crate::eval::Error),
    #[error(transparent)]
    TracerState(#[from] crate::eval::StateError),
}

pub trait Observer: Downcast {
    fn restore(&mut self) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_block_entry(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_block_entry_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        self.observe_block_entry(context, location, block)
    }

    #[allow(unused)]
    fn observe_block_exit(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_block_exit_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        self.observe_block_exit(context, location, block)
    }

    #[allow(unused)]
    fn observe_function_entry(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        function: &Function,
        summary: Option<&FunctionSummary>,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_function_entry_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        function: &Function,
        summary: Option<&FunctionSummary>,
    ) -> Result<(), ObserverError> {
        self.observe_function_entry(context, location, function, summary)
    }

    #[allow(unused)]
    fn observe_function_exit(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        function: &Function,
        summary: Option<&FunctionSummary>,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_function_exit_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        function: &Function,
        summary: Option<&FunctionSummary>,
    ) -> Result<(), ObserverError> {
        self.observe_function_exit(context, location, function, summary)
    }

    #[allow(unused)]
    fn observe_pre_var_read(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_pre_var_read_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
    ) -> Result<(), ObserverError> {
        self.observe_pre_var_read(context, location, var)
    }

    #[allow(unused)]
    fn observe_post_var_read(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
        val: &mut BitVec,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_post_var_read_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &mut BitVec,
    ) -> Result<(), ObserverError> {
        self.observe_post_var_read(context, location, var, val)
    }

    #[allow(unused)]
    fn observe_post_var_invalid_read(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
        val: &mut Option<BitVec>,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_post_var_invalid_read_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &mut Option<BitVec>,
    ) -> Result<(), ObserverError> {
        self.observe_post_var_invalid_read(context, location, var, val)
    }

    #[allow(unused)]
    fn observe_pre_var_write(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
        val: &mut BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_pre_var_write_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &mut BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        self.observe_pre_var_write(context, location, var, val, sexpr)
    }

    #[allow(unused)]
    fn observe_post_var_write(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
        val: &BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_post_var_write_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        self.observe_post_var_write(context, location, var, val, sexpr)
    }

    #[allow(unused)]
    fn observe_insn(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        insn: &Term<Insn>,
    ) -> Result<bool, ObserverError> {
        Ok(false)
    }

    #[allow(unused)]
    fn observe_insn_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        insn: &Term<Insn>,
    ) -> Result<bool, ObserverError> {
        self.observe_insn(context, location, insn)
    }

    #[allow(unused)]
    fn override_insn(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        insn: &mut Cow<Term<Insn>>,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn override_insn_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        insn: &mut Cow<Term<Insn>>,
    ) -> Result<(), ObserverError> {
        self.override_insn(context, location, insn)
    }

    #[allow(unused)]
    fn observe_stmt(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        stmt: &Term<Stmt>,
    ) -> Result<bool, ObserverError> {
        Ok(false)
    }

    #[allow(unused)]
    fn observe_stmt_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        stmt: &Term<Stmt>,
    ) -> Result<bool, ObserverError> {
        self.observe_stmt(context, location, stmt)
    }

    #[allow(unused)]
    fn observe_pre_branch(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Location,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_pre_branch_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        target: Location,
    ) -> Result<(), ObserverError> {
        self.observe_pre_branch(context, location, target)
    }

    #[allow(unused)]
    fn observe_pre_cbranch(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        cond: &Term<Expr>,
        cval: &mut BitVec,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_pre_cbranch_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        cond: &Term<Expr>,
        cval: &mut BitVec,
    ) -> Result<(), ObserverError> {
        self.observe_pre_cbranch(context, location, cond, cval)
    }

    #[allow(unused)]
    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        Ok(())
    }

    #[allow(unused)]
    fn observe_pre_call_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        self.observe_pre_call(context, location, target)
    }

    #[allow(unused)]
    fn observe_external(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        summary: &FunctionSummary,
        handled: bool,
    ) -> Result<bool, ObserverError> {
        Ok(handled)
    }

    #[allow(unused)]
    fn observe_external_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        summary: &FunctionSummary,
        handled: bool,
    ) -> Result<bool, ObserverError> {
        self.observe_external(context, location, summary, handled)
    }

    #[allow(unused)]
    fn observe_intrinsic(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        intrinsic: Ustr,
        arguments: &mut [BitVec],
        result: &mut Option<BitVec>,
        handled: bool,
    ) -> Result<bool, ObserverError> {
        Ok(handled)
    }

    #[allow(unused)]
    fn observe_intrinsic_with(
        &mut self,
        context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        intrinsic: Ustr,
        arguments: &mut [BitVec],
        result: &mut Option<BitVec>,
        handled: bool,
    ) -> Result<bool, ObserverError> {
        self.observe_intrinsic(context, location, intrinsic, arguments, result, handled)
    }
}

impl_downcast!(Observer);

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ObserverId(usize);

impl ObserverId {
    pub fn index(&self) -> usize {
        self.0
    }
}

impl From<usize> for ObserverId {
    fn from(index: usize) -> Self {
        Self(index)
    }
}
