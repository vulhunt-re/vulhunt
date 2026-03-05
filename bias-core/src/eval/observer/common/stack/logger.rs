use std::ops::Range;

use ahash::AHashSet;
use fugue::bv::BitVec;
use fugue::ir::Address;

use crate::eval::observer::{Observer, ObserverError};
use crate::eval::{Configuration, IRContext};
use crate::ir::{Expr, Location, Term, Var};
use crate::kb::block::CodeBlock;

pub struct StackLogger {
    stack_start: Address,
    stack_bounds: Range<Address>,
    only_reads_are_variables: bool,
    accesses: AHashSet<(Address, i64)>,
}

impl StackLogger {
    pub fn new(config: &Configuration) -> Self {
        Self::new_with(config, true)
    }

    pub fn new_with(config: &Configuration, only_reads_are_variables: bool) -> Self {
        Self {
            stack_start: config.stack_start,
            stack_bounds: config.stack_base..config.stack_base + config.stack_size,
            only_reads_are_variables,
            accesses: Default::default(),
        }
    }

    pub fn accesses(&self) -> impl ExactSizeIterator<Item = &(Address, i64)> {
        self.accesses.iter()
    }

    pub fn insert(&mut self, location: Location, var: Var) {
        if let Some(addr) = var.address().and_then(|addr| {
            if self.stack_bounds.contains(&addr) {
                Some(addr)
            } else {
                None
            }
        }) {
            let delta = if addr >= self.stack_start {
                // this is an argument
                (addr.offset() - self.stack_start.offset()) as i64
            } else {
                // this is a local
                -((self.stack_start.offset() - addr.offset()) as i64)
            };
            self.accesses.insert((location.address(), delta));
        }
    }
}

impl Observer for StackLogger {
    fn observe_block_entry(
        &mut self,
        context: &mut Box<dyn IRContext>,
        _location: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        tracing::trace!(
            "entering block at {}; stack pointer: {}",
            block.address(),
            context.read_stack_pointer()?
        );
        Ok(())
    }

    fn observe_pre_var_read(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
    ) -> Result<(), ObserverError> {
        self.insert(location, *var);
        Ok(())
    }

    fn observe_pre_var_write(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        location: Location,
        var: &Var,
        _val: &mut BitVec,
        _sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        if !self.only_reads_are_variables {
            self.insert(location, *var)
        }
        Ok(())
    }
}
