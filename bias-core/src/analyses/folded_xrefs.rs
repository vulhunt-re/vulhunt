use std::ops::{Deref, DerefMut};

use fugue::bv::BitVec;
use fugue::ir::Address;

use super::dataflow::constants::DATAFLOW_CONSTANT_FOLD;
use super::dataflow::reaching_constants::ReachingConsts;
use super::xrefs::XRefDB;
use crate::any::ProvidesStaticType;
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::{Bound, IRContext, IREvalConfig, ObserverContext, ObserverState};
use crate::ir::{Expr, Location, Term, ToAddress, Var};
use crate::kb::block::CodeBlockId;
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::kb::xref::XRef;
use crate::project::analysis::{Analysis, AnalysisError};
use crate::project::Project;
use crate::region::Memory;

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct FoldedXRefDB {
    db: XRefDB,
    consts: ReachingConsts,
}

impl Deref for FoldedXRefDB {
    type Target = XRefDB;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for FoldedXRefDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

impl From<FoldedXRefDB> for XRefDB {
    fn from(slf: FoldedXRefDB) -> Self {
        slf.db
    }
}

#[derive(ProvidesStaticType)]
struct XRefContext<'a> {
    id: CodeBlockId,
    xrefs: &'a mut XRefDB,
    memory: &'a Memory,
}

const XREF_CONTEXT: uuid::Uuid = uuid("91093377-AD0B-4DC6-AD04-D30648C89FA7");

impl<'a> ObserverState<'a> for XRefContext<'a> {
    fn id(&self) -> &uuid::Uuid {
        &XREF_CONTEXT
    }
}

impl<'a> XRefContext<'a> {
    fn add_load(&mut self, location: Location, addr: Address) {
        let xref = XRef::load(location, addr);
        self.add_xref(xref);
    }

    fn add_store(&mut self, location: Location, addr: Address) {
        let xref = XRef::store(location, addr);
        self.add_xref(xref);
    }

    fn add_xref(&mut self, xref: XRef) {
        let xid = self.xrefs.xrefs.len();
        self.xrefs.xrefs.push((self.id, xref));
        self.xrefs
            .addr_to_xrefs
            .entry(xref.target())
            .or_default()
            .insert(xid);
    }
}

#[derive(Default)]
struct XRefObserver;

impl Observer for XRefObserver {
    fn observe_pre_var_read_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
    ) -> Result<(), ObserverError> {
        if let Some(addr) = var.address() {
            let ctx = observer_context
                .get_mut::<XRefContext>(XREF_CONTEXT)
                .unwrap();
            if !ctx.memory.contains(addr) {
                return Ok(());
            }

            tracing::trace!("{location}: load via {addr}");
            ctx.add_load(location, addr);
        }
        Ok(())
    }

    fn observe_pre_var_write_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &mut BitVec,
        _sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        if let Some(addr) = var.address() {
            let ctx = observer_context
                .get_mut::<XRefContext>(XREF_CONTEXT)
                .unwrap();
            if !ctx.memory.contains(addr) {
                return Ok(());
            }

            tracing::trace!("{location}: store via {addr}");
            ctx.add_store(location, addr);
        } else if let Some(addr) = val.to_address() {
            // track pointer-hint style loads
            let ctx = observer_context
                .get_mut::<XRefContext>(XREF_CONTEXT)
                .unwrap();
            if !ctx.memory.contains(addr) {
                return Ok(());
            }

            tracing::trace!("{location}: load via {addr}");
            ctx.add_load(location, addr);
        }
        Ok(())
    }
}

pub const FOLDED_XREF_ANALYSIS: uuid::Uuid = uuid("D0BF1749-E36A-4F8A-B97D-036BDB37BA89");

impl Analysis for FoldedXRefDB {
    fn id(&self) -> &uuid::Uuid {
        &FOLDED_XREF_ANALYSIS
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let consts = if let Some(consts) = project
            .analyses()
            .get::<ReachingConsts>(DATAFLOW_CONSTANT_FOLD)
        {
            consts
        } else {
            self.consts.analyse(project)?;
            &self.consts
        };

        let mut eval = project
            .evaluator(IREvalConfig {
                enable_restores: true,
                enable_injections: true,
                ignore_unimplemented_ops: true,
                ignore_divide_by_zero: true,
                ignore_failures: true,
                ignore_invalid_accesses: true,
                ..Default::default()
            })
            .unwrap();

        eval.register_observer(XRefObserver::default());

        for block in project.cbtable.values() {
            let id = block.id();

            let start = self.xrefs.len();

            let block_consts = &consts.mapping()[&block.function()].blocks()[&id];

            for (var, val) in block_consts.incoming_values() {
                eval.context_mut().write_var(var, val).ok();
            }

            {
                let mut obs_ctx = ObserverContext::default();
                obs_ctx.set(
                    XREF_CONTEXT,
                    XRefContext {
                        id,
                        xrefs: &mut self.db,
                        memory: project.memory(),
                    },
                );

                eval.eval_full(
                    project.tables(),
                    &mut obs_ctx,
                    block.address(),
                    Bound::StopAfterOr(block.last_address(), 40),
                )
                .ok();

                eval.restore().ok();
            }

            let end = self.xrefs.len();
            if start != end {
                let idx = self.xrefs_ranges.len();

                self.db.xrefs_ranges.push(start..end);
                self.db.code_to_xrefs.insert(id, idx);
            }
        }

        Ok(())
    }
}
