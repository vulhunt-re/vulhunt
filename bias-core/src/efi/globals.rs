use std::collections::BTreeSet;

use fugue::bv::BitVec;
use fugue::ir::convention::PrototypeOperand;
use fugue::ir::Address;
use itertools::Itertools;
use thiserror::Error;
use uuid::Uuid;

use super::module::EFI_MODULE_INFO_ANALYSIS;
use crate::analyses::symbolic::expr::{AliasValue, AliasVisitor, AliasVisitorContext, Aliases};
use crate::analyses::xrefs::XRefDB;
use crate::any::ProvidesStaticType;
use crate::efi::btree::btreeset_drain_filter;
use crate::efi::guids::{GuidAnalyser, EFI_GUID_XREF_ANALYSIS};
use crate::efi::module::ModuleInfo;
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::strategy::xforce::XForceStrategy;
use crate::eval::{Bound, Configuration, IRContext, IREvaluator, ObserverContext, ObserverState};
use crate::ir::{BitSize, Expr, Insn, Location, Stmt, Term, ToAddress, Type, Var};
use crate::kb::xref::XRef;
use crate::kb::{uuid, AHashMap, AHashSet};
use crate::lifter::PrototypeResolver;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, Schedule};
use crate::region::Memory;
use crate::Project;

#[derive(Debug, Error)]
pub enum Error {
    #[error("type information for {0} is not available")]
    TypeLookup(&'static str),
    #[error(transparent)]
    Tracer(#[from] crate::eval::Error),
    #[error(transparent)]
    TracerState(#[from] crate::eval::StateError),
    #[error("unsupported calling convention")]
    UnsupportedConvention,
}

impl From<Error> for AnalysisError {
    fn from(e: Error) -> Self {
        AnalysisError::Analysis(EFI_GLOBALS_ANALYSIS, Box::new(e))
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct GlobalsAnalyser {
    boot_services: BTreeSet<Address>,
    boot_services_xrefs: BTreeSet<XRef>,

    runtime_services: BTreeSet<Address>,
    runtime_services_xrefs: BTreeSet<XRef>,

    system_table: BTreeSet<Address>,
    system_table_xrefs: BTreeSet<XRef>,

    sm_system_table: BTreeSet<Address>,
    sm_system_table_xrefs: BTreeSet<XRef>,

    pei_services: BTreeSet<Address>,
    pei_services_xrefs: BTreeSet<XRef>,
}

pub const EFI_GLOBALS_ANALYSIS: uuid::Uuid = uuid("6725A5E1-5E98-45BC-B68A-E0A9DF3427B9");

impl GlobalsAnalyser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn boot_services(&self) -> &BTreeSet<Address> {
        &self.boot_services
    }

    pub fn runtime_services(&self) -> &BTreeSet<Address> {
        &self.runtime_services
    }

    pub fn system_table(&self) -> &BTreeSet<Address> {
        &self.system_table
    }

    pub fn sm_system_table(&self) -> &BTreeSet<Address> {
        &self.sm_system_table
    }

    pub fn pei_services(&self) -> &BTreeSet<Address> {
        &self.pei_services
    }

    pub fn boot_services_xrefs(&self) -> &BTreeSet<XRef> {
        &self.boot_services_xrefs
    }

    pub fn runtime_services_xrefs(&self) -> &BTreeSet<XRef> {
        &self.runtime_services_xrefs
    }

    pub fn system_table_xrefs(&self) -> &BTreeSet<XRef> {
        &self.system_table_xrefs
    }

    pub fn sm_system_table_xrefs(&self) -> &BTreeSet<XRef> {
        &self.sm_system_table_xrefs
    }

    pub fn pei_services_xrefs(&self) -> &BTreeSet<XRef> {
        &self.pei_services_xrefs
    }

    pub fn boot_services_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.boot_services
    }

    pub fn runtime_services_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.runtime_services
    }

    pub fn system_table_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.system_table
    }

    pub fn sm_system_table_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.sm_system_table
    }

    pub fn pei_services_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.pei_services
    }

    pub fn boot_services_xrefs_mut(&mut self) -> &mut BTreeSet<XRef> {
        &mut self.boot_services_xrefs
    }

    pub fn runtime_services_xrefs_mut(&mut self) -> &mut BTreeSet<XRef> {
        &mut self.runtime_services_xrefs
    }

    pub fn system_table_xrefs_mut(&mut self) -> &mut BTreeSet<XRef> {
        &mut self.system_table_xrefs
    }

    pub fn sm_system_table_xrefs_mut(&mut self) -> &mut BTreeSet<XRef> {
        &mut self.sm_system_table_xrefs
    }

    pub fn pei_services_xrefs_mut(&mut self) -> &mut BTreeSet<XRef> {
        &mut self.pei_services_xrefs
    }
}

const GLOBALS_OBSERVER_STATE: Uuid = uuid("E0A50418-7651-4C1A-9558-546CA6703719");

struct ObserveDxeGlobals {
    bs_base: Address,
    rt_base: Address,
    st_base: Address,
}

#[derive(ProvidesStaticType)]
struct ObserveDxeGlobalsState<'a> {
    memory: &'a Memory,
    address_bytes: usize,
    boot_services: &'a mut BTreeSet<Address>,
    runtime_services: &'a mut BTreeSet<Address>,
    system_table: &'a mut BTreeSet<Address>,
    xrefs: &'a XRefDB,
}

impl<'a> ObserverState<'a> for ObserveDxeGlobalsState<'a> {
    fn id(&self) -> &uuid::Uuid {
        &GLOBALS_OBSERVER_STATE
    }
}

#[inline]
fn contains_loads(addr: Address, xrefs: &XRefDB) -> bool {
    xrefs.loads_from(addr).next().is_some()
}

impl Observer for ObserveDxeGlobals {
    fn observe_post_var_write_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &BitVec,
        _sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        let state = observer_context
            .get_mut::<ObserveDxeGlobalsState>(GLOBALS_OBSERVER_STATE)
            .unwrap();

        let address = if let Some(address) = var.address() {
            address
        } else {
            return Ok(());
        };

        let written = if let Some(written) = val.to_address() {
            written
        } else {
            return Ok(());
        };

        if !state.memory.contains_range(address, state.address_bytes) {
            return Ok(());
        }

        if written == self.bs_base {
            tracing::trace!(
                "found gBS initialisation at {} via {}",
                address,
                location.address()
            );
            if contains_loads(address, state.xrefs) {
                state.boot_services.insert(address);
            }
        } else if written == self.rt_base {
            tracing::trace!(
                "found gRT initialisation at {} via {}",
                address,
                location.address()
            );
            if contains_loads(address, state.xrefs) {
                state.runtime_services.insert(address);
            }
        } else if written == self.st_base {
            tracing::trace!(
                "found gST initialisation at {} via {}",
                address,
                location.address()
            );
            if contains_loads(address, state.xrefs) {
                state.system_table.insert(address);
            }
        }

        Ok(())
    }
}

struct ObservePeiGlobals {
    pei_base: Address,
}

#[derive(ProvidesStaticType)]
struct ObservePeiGlobalsState<'a> {
    memory: &'a Memory,
    address_bytes: usize,
    pei_services: &'a mut BTreeSet<Address>,
}

impl<'a> ObserverState<'a> for ObservePeiGlobalsState<'a> {
    fn id(&self) -> &uuid::Uuid {
        &GLOBALS_OBSERVER_STATE
    }
}

impl Observer for ObservePeiGlobals {
    fn observe_post_var_write_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        location: Location,
        var: &Var,
        val: &BitVec,
        _sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        let state = observer_context
            .get_mut::<ObservePeiGlobalsState>(GLOBALS_OBSERVER_STATE)
            .unwrap();

        let address = if let Some(address) = var.address() {
            address
        } else {
            return Ok(());
        };

        let written = if let Some(written) = val.to_address() {
            written
        } else {
            return Ok(());
        };

        if !state.memory.contains_range(address, state.address_bytes) {
            return Ok(());
        }

        if written == self.pei_base {
            tracing::trace!(
                "found gPeiServices initialisation at {} via {}",
                address,
                location.address()
            );
            state.pei_services.insert(address);
        }

        Ok(())
    }
}

struct ObserveSmst {
    locate_protocol: Address,
    smst_base_interface: Address,
    smst_get_smst_location: Address,

    arg0: PrototypeOperand,
    arg1: PrototypeOperand,
    arg2: PrototypeOperand,
    retn: PrototypeOperand,

    smst_tables: BTreeSet<Address>,
    resolver: PrototypeResolver,
}

impl Observer for ObserveSmst {
    fn observe_post_var_invalid_read(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        _location: Location,
        var: &Var,
        val: &mut Option<BitVec>,
    ) -> Result<(), ObserverError> {
        *val = Some(BitVec::zero(var.nbits() as usize));
        Ok(())
    }

    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Address, // TODO: add is_invalid argument
    ) -> Result<(), ObserverError> {
        if target == self.locate_protocol {
            tracing::info!("found call to gBS->LocateProtocol at {}", location.address);
            let stack_base = context.read_stack_pointer().unwrap();

            let guid_var = self.resolver.resolve(&self.arg0, stack_base).unwrap();
            let interface_var = self.resolver.resolve(&self.arg2, stack_base).unwrap();

            let guid = [
                0x0B7, 0x0BF, 0x0CC, 0x0F4, 0x0E0, 0x0F6, 0x0FD, 0x47, 0x9D, 0x0D4, 0x10, 0x0A8,
                0x0F1, 0x50, 0x0C1, 0x91,
            ];

            if let Some(addr) = context.read_var(&guid_var).to_address() {
                if !matches!(context.read_bytes(addr, guid.len()), Ok(bytes) if bytes == guid) {
                    return Ok(());
                }
                tracing::info!("matched SMM BASE2 GUID at {addr}");

                if let Some(addr) = context.read_var(&interface_var).to_address() {
                    if addr == Address::from(0u32) {
                        return Ok(());
                    }
                    // write the interface
                    tracing::info!("writing interface variable at {addr}");
                    context.write_pointer(addr, self.smst_base_interface).ok();
                }
            }
        } else if target == self.smst_get_smst_location {
            tracing::info!(
                "found call to gSmmBase2->GetSmstLocation at {}",
                location.address
            );

            let stack_base = context.read_stack_pointer().unwrap();
            let smst_var = self.resolver.resolve(&self.arg1, stack_base).unwrap();

            if let Some(addr) = context.read_var(&smst_var).to_address() {
                tracing::info!("found (possible) gSmst at {addr}");
                self.smst_tables.insert(addr);

                context
                    .write_var(&smst_var, &BitVec::zero(smst_var.nbits() as usize))
                    .ok();
                context.write_pointer(addr, Address::from(0u32)).ok();
            }

            // clear the return value
            let retn_var = self.resolver.resolve(&self.retn, stack_base).unwrap();

            tracing::info!("clearing return value of gSmmBase2->GetSmstLocation at {retn_var}");
            context
                .write_var(&retn_var, &BitVec::zero(retn_var.nbits() as usize))
                .expect("write to return operand");
        }
        Ok(())
    }
}

fn type_for(project: &Project, name: &'static str, bits: u32) -> Result<Term<Type>, AnalysisError> {
    let typ = project
        .typedb
        .get_type_for(name, bits)
        .ok_or_else(|| Error::TypeLookup(name))?;
    Ok(typ)
}

fn prototype_for(
    project: &Project,
    name: &'static str,
    bits: u32,
) -> Result<Term<Type>, AnalysisError> {
    let typ = project
        .typedb
        .get_prototype_for(name, bits)
        .ok_or_else(|| Error::TypeLookup(name))?;
    Ok(typ)
}

fn field_offset(
    typ: &Term<Type>,
    field: &'static str,
    field_path: &'static str,
) -> Result<usize, AnalysisError> {
    let offset = typ
        .offset_of_field(field)
        .ok_or_else(|| Error::TypeLookup(field_path))?;
    Ok(offset)
}

fn write_var(eval: &mut IREvaluator, dest: &Var, value: &BitVec) -> Result<(), AnalysisError> {
    eval.context_mut()
        .write_var(dest, value)
        .map_err(Error::from)
        .map_err(AnalysisError::from)
}

fn write_pointer(
    eval: &mut IREvaluator,
    dest: Address,
    addr: Address,
) -> Result<(), AnalysisError> {
    eval.context_mut()
        .write_pointer(dest, addr)
        .map_err(Error::from)
        .map_err(AnalysisError::from)
}

struct GlobalsVisitor<'a, 'b> {
    analyser: &'a mut GlobalsAnalyser,
    memory: &'b Memory,
    address_bytes: usize,
    bs_foffset: usize,
    rt_foffset: usize,
}

impl<'a, 'b> AliasVisitor<'b> for GlobalsVisitor<'a, 'b> {
    fn visit_aliases_pre(
        &mut self,
        insn: &Term<Insn>,
        _position: usize,
        stmt: &Term<Stmt>,
        state: &AliasVisitorContext<'b>,
    ) {
        let (addr, s) = match &**stmt {
            Stmt::Store(d, s, _, _) => {
                let Some(addr) = d.value().address() else {
                    return;
                };
                (addr, s)
            }
            Stmt::Assign(v, s) => {
                let Some(addr) = v.address() else { return };
                (addr, s)
            }
            _ => return,
        };

        if !self.memory.contains_range(addr, self.address_bytes) {
            return;
        }

        let Some(var) = s.variable() else { return };
        let Some(AliasValue::G(ref v0, ref zero)) = state.get_var_alias(var) else {
            return;
        };

        if !zero.is_zero() {
            return;
        }

        let Some(offset) = v0.offset() else { return };

        if offset == self.bs_foffset {
            tracing::trace!("gBS candidate {addr} @ {}", insn.address());
            self.analyser.boot_services.insert(addr);
        } else if offset == self.rt_foffset {
            tracing::trace!("gRT candidate {addr} @ {}", insn.address());
            self.analyser.runtime_services.insert(addr);
        } else {
            return;
        }

        if let Some(addr) = v0.value().to_address() {
            if self.memory.contains_range(addr, self.address_bytes) {
                tracing::trace!("gST candidate {addr} @ {}", insn.address());
                self.analyser.system_table.insert(addr);
            }
        }
    }
}

impl GlobalsAnalyser {
    fn dxe_table_aliases(&mut self, project: &Project, bs_foffset: usize, rt_foffset: usize) {
        // BS candidates => obtained from C = G->BS
        // RT candidates => obtained from C = G->RT
        // ST candidates => obtained from C = G where G in G->BS or G in G->RT

        let xrefs = project.get_analysis::<XRefDB>();

        // find all blocks that perform global loads/stores
        let stores = xrefs.iter().filter_map(|(bid, xr)| {
            if xr.kind().is_store() {
                Some(bid)
            } else {
                None
            }
        });

        let mut aliases = AHashMap::new();
        let mut blocks = AHashSet::new();

        for bid in stores {
            if !blocks.insert(bid) {
                continue;
            }

            let blk = &project.code_blocks()[bid];
            let fid = blk.function();

            if aliases.contains_key(&fid) {
                continue;
            }

            let fcn = &project.functions()[fid];
            aliases.insert(fid, Aliases::analyse_function(project, fcn));
        }

        let mut ctx = AliasVisitorContext::empty(project.lifter(), project.memory());
        for fmap in aliases.values() {
            for (&bid, baliases) in fmap
                .blocks()
                .iter()
                .filter(|(bid, _blk)| blocks.contains(bid))
            {
                let blk = &project.code_blocks()[bid];
                baliases.reinitialise_context(&mut ctx);

                ctx.visit_block(
                    blk,
                    &mut GlobalsVisitor {
                        analyser: self,
                        memory: project.memory(),
                        address_bytes: project.lifter().address_bytes(),
                        bs_foffset,
                        rt_foffset,
                    },
                );
            }
        }

        for &addr in self
            .boot_services
            .iter()
            .chain(self.runtime_services.iter())
        {
            // NOTE:
            // we might want to only iterate and generate aliases while we have yet
            // to provide proof that a candidate should be preserved.
            //
            for (bid, _) in xrefs.loads_from(addr) {
                let blk = &project.code_blocks()[bid];
                let fid = blk.function();

                tracing::trace!(
                    "adding candidate function {} for {addr}",
                    project.functions()[fid].address()
                );

                if aliases.contains_key(&fid) {
                    continue;
                }

                let fcn = &project.functions()[fid];
                aliases.insert(fid, Aliases::analyse_function(project, fcn));
            }
        }

        let mut bs_kills = self.boot_services.clone();
        let mut rt_kills = self.runtime_services.clone();

        for fmap in aliases.values() {
            for aliases in fmap.blocks().values() {
                let Some(p) = aliases.call_target().and_then(|p| p.global_base_ptr()) else {
                    continue;
                };
                tracing::trace!("{p} preserved");
                bs_kills.remove(&p);
                rt_kills.remove(&p);
            }
        }

        for kill in bs_kills.iter() {
            tracing::trace!("gBS candidate {kill} pruned");
            self.boot_services.remove(kill);
        }

        for kill in rt_kills.iter() {
            tracing::trace!("gRT candidate {kill} pruned");
            self.runtime_services.remove(kill);
        }
    }

    fn analyse_pei(&mut self, project: &mut Project, entry: Address) -> Result<(), AnalysisError> {
        let mut eval = project
            .evaluator(Configuration {
                enable_restores: true,
                ignore_invalid_accesses: true,
                ignore_invalid_branches: true,
                ignore_unimplemented_ops: true,
                ignore_divide_by_zero: true,
                ..Default::default()
            })
            .unwrap();

        let addr_bits = project.lifter().address_bits();
        let addr_bytes = project.lifter().global_space().address_size();

        let ps = type_for(project, "EFI_PEI_SERVICES", addr_bits)?;
        let pei_paddr = eval
            .static_mapping("pei-services", None, ps.nbytes() + addr_bytes)
            .map_err(Error::from)?;
        let pei_base = pei_paddr + addr_bytes;

        let default_proto = project.lifter.default_prototype();

        let stack_base = eval.context().read_stack_pointer().unwrap();

        let arg1 = default_proto
            .resolved_input(0, stack_base)
            .ok_or_else(|| Error::UnsupportedConvention)?;
        let arg2 = default_proto
            .resolved_input(1, stack_base)
            .ok_or_else(|| Error::UnsupportedConvention)?;

        // ImageHandle
        write_var(
            &mut eval,
            &arg1,
            &BitVec::from_u32(0xffff_ffffu32, addr_bits as usize),
        )?;

        // **PeiServices
        write_pointer(&mut eval, pei_paddr, pei_base)?;

        // *PeiServices
        write_var(
            &mut eval,
            &arg2,
            &BitVec::from_u64(pei_paddr.into(), addr_bits as usize),
        )?;

        tracing::trace!("tracking from module entry to locate PEI service globals");
        {
            let mut observer_context = ObserverContext::default();

            observer_context.set(
                GLOBALS_OBSERVER_STATE,
                ObservePeiGlobalsState {
                    memory: &project.memory,
                    address_bytes: project.lifter.address_bytes(),
                    pei_services: &mut self.pei_services,
                },
            );

            // TODO: should we track both **PeiServices and *PeiServices?
            eval.register_observer(ObservePeiGlobals {
                pei_base: pei_paddr,
            });

            let _ = eval.refreeze();

            eval.eval_full_with(
                project.tables(),
                &mut observer_context,
                entry,
                Bound::Count(400),
                XForceStrategy::default(),
            )
            .ok();
        }

        // apply type information
        for &g in self.pei_services.iter() {
            project.type_db_mut().set_data_type_at(
                g,
                Type::pointer(Type::pointer(ps.clone(), addr_bits), addr_bits),
            );
        }

        Ok(())
    }

    fn analyse_dxe(&mut self, project: &mut Project, entry: Address) -> Result<(), AnalysisError> {
        let mut eval = project
            .evaluator(Configuration {
                enable_restores: true,
                ignore_invalid_accesses: true,
                ignore_invalid_branches: true,
                ignore_unimplemented_ops: true,
                ignore_divide_by_zero: true,
                ..Default::default()
            })
            .unwrap();

        let addr_bits = project.lifter().address_bits();
        let addr_bytes = project.lifter().address_bytes();

        let st = type_for(project, "EFI_SYSTEM_TABLE", addr_bits)?;
        let bs = type_for(project, "EFI_BOOT_SERVICES", addr_bits)?;
        let rt = type_for(project, "EFI_RUNTIME_SERVICES", addr_bits)?;
        let smst = type_for(project, "EFI_SMM_SYSTEM_TABLE2", addr_bits)?;

        let bs_foffset = field_offset(&st, "BootServices", "EFI_SYSTEM_TABLE.BootServices")?;
        let rt_foffset = field_offset(&st, "RuntimeServices", "EFI_SYSTEM_TABLE.RuntimeServices")?;

        tracing::trace!("tracking load/store/call behaviour to locate global tables");
        self.dxe_table_aliases(&project, bs_foffset, rt_foffset);

        let smm_base2 = project
            .typedb
            .get_type_for("_EFI_SMM_BASE2_PROTOCOL", addr_bits)
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_BASE2_PROTOCOL"))?;

        let smst_loc_foffset = smm_base2
            .offset_of_field("GetSmstLocation")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_BASE2_PROTOCOL.GetSmstLocation"))?;

        let lp_foffset = bs
            .offset_of_field("LocateProtocol")
            .ok_or_else(|| Error::TypeLookup("EFI_BOOT_SERVICES.LocateProtocol"))?;

        // create mapping for EFI_SYSTEM_TABLE
        let st_base = eval
            .static_mapping("system-table", None, st.nbytes())
            .map_err(Error::from)?;

        // create mapping for EFI_BOOT_SERVICES
        let bs_base = eval
            .static_mapping("boot-services", None, bs.nbytes() + addr_bytes)
            .map_err(Error::from)?;

        // create mapping for EFI_RUNTIME_SERVICES
        let rt_base = eval
            .static_mapping("runtime-services", None, rt.nbytes())
            .map_err(Error::from)?;

        // create mapping for _EFI_SMM_BASE2_PROTOCOL
        let smm_base2_base = eval
            .static_mapping("smm-base2", None, smm_base2.nbytes() + addr_bytes)
            .map_err(Error::from)?;

        let smst_ptr = smm_base2_base + smm_base2.nbytes() + 1usize;
        let lp_ptr = bs_base + bs.nbytes() + 1usize;

        // write pointer for EFI_BOOT_SERVICES
        write_pointer(&mut eval, st_base + bs_foffset, bs_base)?;

        // write pointer for EFI_RUNTIME_SERVICES
        write_pointer(&mut eval, st_base + rt_foffset, rt_base)?;

        // set second argument to entry to EFI_SYSTEM_TABLE
        let default_proto = project.lifter().default_prototype();
        let stack_base = eval.context().read_stack_pointer().unwrap();

        let arg1 = default_proto
            .resolved_input(0, stack_base)
            .ok_or_else(|| Error::UnsupportedConvention)?;
        let arg2 = default_proto
            .resolved_input(1, stack_base)
            .ok_or_else(|| Error::UnsupportedConvention)?;

        // write arguments
        write_var(
            &mut eval,
            &arg1,
            &BitVec::from_u32(0xffff_ffff, addr_bits as usize),
        )?;

        write_var(
            &mut eval,
            &arg2,
            &BitVec::from_u64(st_base.into(), addr_bits as usize),
        )?;

        eval.refreeze();

        // trace module init.
        tracing::trace!("tracking from module entry to locate global tables");
        {
            let mut observer_context = ObserverContext::default();
            let xrefs = project.get_analysis::<XRefDB>();

            observer_context.set(
                GLOBALS_OBSERVER_STATE,
                ObserveDxeGlobalsState {
                    memory: &project.memory,
                    address_bytes: project.lifter.address_bytes(),
                    boot_services: &mut self.boot_services,
                    runtime_services: &mut self.runtime_services,
                    system_table: &mut self.system_table,
                    xrefs: &xrefs,
                },
            );

            eval.register_observer(ObserveDxeGlobals {
                bs_base,
                rt_base,
                st_base,
            });

            eval.eval_full_with(
                project.tables(),
                &mut observer_context,
                entry,
                Bound::Count(250),
                XForceStrategy::default(),
            )
            .ok();

            eval.unregister_observers();
        }

        eval.restore().ok();

        for bs_addr in self.boot_services() {
            tracing::trace!("BS: {} to {}", bs_addr, bs_base);
            eval.context_mut()
                .write_pointer(*bs_addr, bs_base)
                .map_err(Error::from)?;
        }

        for st_addr in self.system_table() {
            tracing::trace!("ST: {} to {}", st_addr, st_base);
            eval.context_mut()
                .write_pointer(*st_addr, st_base)
                .map_err(Error::from)?;
        }

        for rt_addr in self.runtime_services() {
            tracing::trace!("RT: {} to {}", rt_addr, rt_base);
            eval.context_mut()
                .write_pointer(*rt_addr, rt_base)
                .map_err(Error::from)?;
        }

        tracing::trace!("LPO: {} to {}", bs_base + lp_foffset, lp_ptr);

        eval.context_mut()
            .write_pointer(bs_base + lp_foffset, lp_ptr)
            .map_err(Error::from)?;

        tracing::trace!(
            "SMMB2: {} to {}",
            smm_base2_base + smst_loc_foffset,
            smst_ptr
        );
        eval.context_mut()
            .write_pointer(smm_base2_base + smst_loc_foffset, smst_ptr)
            .map_err(Error::from)?;

        let arg0 = default_proto
            .input(0)
            .cloned()
            .ok_or_else(|| Error::UnsupportedConvention)?;
        let arg1 = default_proto
            .input(1)
            .cloned()
            .ok_or_else(|| Error::UnsupportedConvention)?;
        let arg2 = default_proto
            .input(2)
            .cloned()
            .ok_or_else(|| Error::UnsupportedConvention)?;
        let retn = default_proto
            .output(0)
            .cloned()
            .ok_or_else(|| Error::UnsupportedConvention)?;

        let obs = eval.register_observer(ObserveSmst {
            locate_protocol: lp_ptr,
            smst_base_interface: smm_base2_base,
            smst_get_smst_location: smst_ptr,

            arg0,
            arg1,
            arg2,
            retn,

            smst_tables: Default::default(),

            resolver: project.lifter.prototype_resolver(),
        });

        let _ = eval.refreeze();

        eval.eval_with(
            project.tables(),
            entry,
            Bound::Count(400),
            XForceStrategy::default(),
        )
        .ok();

        self.sm_system_table.extend(btreeset_drain_filter(
            &mut eval
                .get_observer_mut::<ObserveSmst>(obs)
                .unwrap()
                .smst_tables,
            |addr| project.memory.contains_range(addr, addr_bytes),
        ));

        let guids = project
            .analyses()
            .get::<GuidAnalyser>(EFI_GUID_XREF_ANALYSIS)
            .unwrap();
        let base2_index = guids
            .guid_db()
            .get_index("EFI_SMM_BASE2_PROTOCOL_GUID")
            .unwrap();
        let funcs = guids
            .xrefs(base2_index)
            .into_iter()
            .flatten()
            .map(|cb| {
                let block = &project.cbtable[*cb];
                project.ftable[block.function()].address()
            })
            .unique();

        for start in funcs {
            eval.restore().ok();

            eval.eval_with(
                project.tables(),
                start,
                Bound::Count(400),
                XForceStrategy::default(),
            )
            .ok();

            self.sm_system_table.extend(btreeset_drain_filter(
                &mut eval
                    .get_observer_mut::<ObserveSmst>(obs)
                    .unwrap()
                    .smst_tables,
                |addr| project.memory.contains_range(addr, addr_bytes),
            ));
        }

        // apply type information
        for &g in self.system_table.iter() {
            project
                .type_db_mut()
                .set_data_type_at(g, Type::pointer(st.clone(), addr_bits));
        }

        for &g in self.boot_services.iter() {
            project
                .type_db_mut()
                .set_data_type_at(g, Type::pointer(bs.clone(), addr_bits));
        }

        for &g in self.runtime_services.iter() {
            project
                .type_db_mut()
                .set_data_type_at(g, Type::pointer(rt.clone(), addr_bits));
        }

        for &g in self.sm_system_table.iter() {
            project
                .type_db_mut()
                .set_data_type_at(g, Type::pointer(smst.clone(), addr_bits));
        }

        Ok(())
    }
}

impl AnalysisInfo for GlobalsAnalyser {
    const NAME: &'static str = "EFI Globals Analyser";
    const UUID: Uuid = EFI_GLOBALS_ANALYSIS;
    const DEPENDENCIES: &'static [Schedule] = &[
        Schedule::after::<GuidAnalyser>(),
        Schedule::after::<XRefDB>(),
        Schedule::after::<ModuleInfo>(),
    ];
}

impl Analysis for GlobalsAnalyser {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[Schedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let module_info = project
            .analyses()
            .get::<ModuleInfo>(EFI_MODULE_INFO_ANALYSIS)
            .unwrap();

        let entry = module_info.entry();
        let is_pei = module_info.is_pei();
        let proto = if is_pei {
            "_PeiModuleEntryPoint"
        } else {
            "_ModuleEntryPoint"
        };

        // mark the entry with the appropriate type
        let addr_bits = project.lifter().address_bits();
        let ptype = prototype_for(project, proto, addr_bits)?.resolve(project.type_db());

        tracing::trace!("marked entry at {entry} as {proto}");
        project.typedb.set_code_type_at(entry, ptype);

        if is_pei {
            self.analyse_pei(project, entry)?;
        } else {
            self.analyse_dxe(project, entry)?;
        }

        let mut xrefs = Vec::new();
        for block in project.cbtable.values() {
            for insn in block.insns() {
                insn.xrefs_into(project.memory(), &mut xrefs);
            }

            for xref in xrefs.drain(..) {
                if !xref.kind().is_load() {
                    continue;
                }

                let target = xref.target();
                if self.system_table().contains(&target) {
                    tracing::trace!("xref to ST at {}", xref.source());
                    self.system_table_xrefs.insert(xref);
                } else if self.boot_services().contains(&target) {
                    tracing::trace!("xref to BS at {}", xref.source());
                    self.boot_services_xrefs.insert(xref);
                } else if self.runtime_services().contains(&target) {
                    tracing::trace!("xref to RT at {}", xref.source());
                    self.runtime_services_xrefs.insert(xref);
                } else if self.sm_system_table().contains(&target) {
                    tracing::trace!("xref to SMST at {}", xref.source());
                    self.sm_system_table_xrefs.insert(xref);
                } else if self.pei_services().contains(&target) {
                    tracing::trace!("xref to PS at {}", xref.source());
                    self.pei_services_xrefs.insert(xref);
                }
            }
        }

        Ok(())
    }
}
