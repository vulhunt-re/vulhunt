use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fugue::bv::BitVec;
use fugue::ir::Address;
use itertools::Itertools;
use thiserror::Error;
use ustr::Ustr;

use super::globals::{GlobalsAnalyser, EFI_GLOBALS_ANALYSIS};
use super::guids::{GuidAnalyser, EFI_GUID_XREF_ANALYSIS};
use super::services::{ServiceInfo, ServicesAnalyser, EFI_SERVICES_ANALYSIS};
use crate::analyses::blocks::{CodeBlockBounds, CODE_BLOCK_BOUNDS};
use crate::analyses::xrefs::{XRefDB, XREF_ANALYSIS};
use crate::efi::btree::{btreeset_drain, btreeset_drain_filter};
use crate::efi::guids::{GuidDB, GUID_LEN};
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::strategy::xforce::XForceStrategy;
use crate::eval::{Bound, Configuration, IRContext, IREvaluator};
use crate::ir::{BitSize, Expr, Location, Term, ToAddress, Var};
use crate::kb::function::FunctionId;
use crate::kb::id::Identifiable;
use crate::kb::{uuid, Lazy};
use crate::lifter::DefaultPrototype;
use crate::prelude::Function;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::project::ProjectContext;
use crate::{lazy_ustr, Project};

pub const LOCATE_PROTOCOL: Lazy<Ustr> = lazy_ustr!("LocateProtocol");
pub const SMM_LOCATE_PROTOCOL: Lazy<Ustr> = lazy_ustr!("SmmLocateProtocol");

pub const ALLOCATE_POOL: Lazy<Ustr> = lazy_ustr!("AllocatePool");
pub const SMM_ALLOCATE_POOL: Lazy<Ustr> = lazy_ustr!("SmmAllocatePool");

pub const ALLOCATE_PAGES: Lazy<Ustr> = lazy_ustr!("AllocatePages");
pub const SMM_ALLOCATE_PAGES: Lazy<Ustr> = lazy_ustr!("SmmAllocatePages");

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
        AnalysisError::Analysis(EFI_SMI_HANDLER_ANALYSIS, Box::new(e))
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct SmiHandlerAnalyser {
    child_sw_smi_handlers: BTreeSet<Address>,
    smi_handlers: BTreeMap<Ustr, BTreeSet<Address>>,
    callouts: BTreeSet<(FunctionId, Location)>,
    in_smram_vars: BTreeSet<Address>,
    smram_map_count_vars: BTreeSet<Address>,
    smram_map_size_vars: BTreeSet<Address>,
    smram_map_vars: BTreeSet<Address>,
}

impl SmiHandlerAnalyser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn child_sw_smi_handlers(&self) -> &BTreeSet<Address> {
        &self.child_sw_smi_handlers
    }

    pub fn smi_handlers(&self) -> &BTreeMap<Ustr, BTreeSet<Address>> {
        &self.smi_handlers
    }

    pub fn smi_handlers_locations(&self) -> impl Iterator<Item = &Address> {
        self.smi_handlers
            .values()
            .flat_map(|hs| hs)
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    pub fn callouts(&self) -> &BTreeSet<(FunctionId, Location)> {
        &self.callouts
    }

    pub fn in_smram_globals(&self) -> &BTreeSet<Address> {
        &self.in_smram_vars
    }

    pub fn smram_map_globals(&self) -> &BTreeSet<Address> {
        &self.smram_map_vars
    }

    pub fn smram_map_size_globals(&self) -> &BTreeSet<Address> {
        &self.smram_map_size_vars
    }

    pub fn smram_map_count_globals(&self) -> &BTreeSet<Address> {
        &self.smram_map_count_vars
    }
}

const ALLOCATE_SENTINEL: u64 = 0xdead_0000_ffff_0000u64;

const SIZE_SENTINEL: u64 = 0xdead_dead_dead_deadu64;
const SIZE_SHIFTED_SENTINEL: u64 = 0x06f5_6ef5_6ef5_6ef5u64;

struct ObserveSmst {
    bs_refs: BTreeSet<Address>,
    bs_addr: Address,
    smst_addr: Address,

    locate_protocol: Address,
    allocate_pool: Address,

    smst_base_interface: Address,
    smst_get_smst_location: Address,
    smst_in_smm: Address,

    smst_tables: BTreeSet<Address>,
    in_smram_vars: BTreeSet<Address>,

    smm_access_interface: Address,
    smm_get_capabilities: Address,
    smram_map_vars: BTreeSet<Address>,
    smram_map_count_vars: BTreeSet<Address>,
    smram_map_size_vars: BTreeSet<Address>,

    sentinel_vars: BTreeMap<Address, BTreeSet<Address>>,
    sentinel_var: Address,

    default_proto: DefaultPrototype,
}

impl Observer for ObserveSmst {
    fn observe_pre_var_read(
        &mut self,
        context: &mut Box<dyn IRContext>,
        _location: Location,
        var: &Var,
    ) -> Result<(), ObserverError> {
        if matches!(var.address(), Some(addr) if self.bs_refs.contains(&addr)) {
            context.write_var(
                var,
                &BitVec::from_u64(u64::from(self.bs_addr), var.nbits() as usize),
            )?;
        }
        Ok(())
    }

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

    fn observe_post_var_write(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        _location: Location,
        var: &Var,
        val: &BitVec,
        _sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        let Some(addr) = var.address() else {
            return Ok(());
        };

        if matches!(val.to_u64(), Some(v) if v == SIZE_SHIFTED_SENTINEL)
            && !self.smram_map_size_vars.is_empty()
        {
            tracing::info!("found (possible) SmramMap count variable at {addr}");
            self.smram_map_count_vars.insert(addr);
            return Ok(());
        }

        let Some(waddr) = val.to_address() else {
            return Ok(());
        };

        let Entry::Occupied(mut known) = self.sentinel_vars.entry(waddr) else {
            return Ok(());
        };

        known.get_mut().insert(addr);

        Ok(())
    }

    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        if target == self.locate_protocol {
            tracing::info!("found call to gBS->LocateProtocol at {}", location.address);
            let stack_base = context.read_stack_pointer().unwrap();

            let guid_var = self.default_proto.resolved_input(0, stack_base).unwrap();
            let interface_var = self.default_proto.resolved_input(2, stack_base).unwrap();

            let base2_guid = [
                0xB7, 0xBF, 0xCC, 0xF4, 0xE0, 0xF6, 0xFD, 0x47, 0x9D, 0xD4, 0x10, 0xA8, 0xF1, 0x50,
                0xC1, 0x91,
            ];

            let access2_guid = [
                0x74, 0x2B, 0x70, 0xC2, 0x0C, 0x80, 0x31, 0x41, 0x87, 0x46, 0x8F, 0xB5, 0xB8, 0x9C,
                0xE4, 0xAC,
            ];

            if let Some(addr) = context.read_var(&guid_var).to_address() {
                let Ok(bytes) = context.read_bytes(addr, GUID_LEN) else {
                    return Ok(());
                };

                let interface = if bytes == base2_guid {
                    tracing::info!("matched SMM BASE2 GUID at {addr}");
                    self.smst_base_interface
                } else if bytes == access2_guid {
                    tracing::info!("matched SMM ACCESS2 GUID at {addr}");
                    self.smm_access_interface
                } else {
                    return Ok(());
                };

                if let Some(addr) = context.read_var(&interface_var).to_address() {
                    if addr == Address::from(0u32) {
                        return Ok(());
                    }
                    // write the interface
                    tracing::info!("writing interface variable at {addr}");
                    context.write_pointer(addr, interface).ok();

                    // clear the return value
                    let retn_var = self.default_proto.resolved_output(0, stack_base).unwrap();

                    tracing::trace!("clearing return value of gBS->LocateProtocol at {retn_var}");
                    context
                        .write_var(&retn_var, &BitVec::zero(retn_var.nbits() as usize))
                        .ok();
                }
            }
        } else if target == self.smst_get_smst_location {
            tracing::info!(
                "found call to gSmmBase2->GetSmstLocation at {}",
                location.address
            );

            let stack_base = context.read_stack_pointer().unwrap();
            let smst_var = self.default_proto.resolved_input(1, stack_base).unwrap();

            if let Some(addr) = context.read_var(&smst_var).to_address() {
                tracing::info!("found (possible) gSmst at {addr}");
                self.smst_tables.insert(addr);

                context.write_pointer(addr, self.smst_addr).ok();
            }

            // clear the return value
            let retn_var = self.default_proto.resolved_output(0, stack_base).unwrap();

            tracing::trace!("clearing return value of gSmmBase2->GetSmstLocation at {retn_var}");
            context
                .write_var(&retn_var, &BitVec::zero(retn_var.nbits() as usize))
                .ok();
        } else if target == self.smst_in_smm {
            tracing::info!("found call to gSmmBase2->InSmm at {}", location.address);

            let stack_base = context.read_stack_pointer().unwrap();
            let in_smram_var = self.default_proto.resolved_input(1, stack_base).unwrap();

            if let Some(addr) = context.read_var(&in_smram_var).to_address() {
                tracing::info!("found (possible) InSmm variable at {addr}");
                self.in_smram_vars.insert(addr);
            }

            // clear the return value
            let retn_var = self.default_proto.resolved_output(0, stack_base).unwrap();

            tracing::trace!("clearing return value of gSmmBase2->InSmm at {retn_var}");
            context
                .write_var(&retn_var, &BitVec::zero(retn_var.nbits() as usize))
                .ok();
        } else if target == self.smm_get_capabilities {
            tracing::info!(
                "found call to gSmmAccess2->GetCapabilities at {}",
                location.address
            );

            let stack_base = context.read_stack_pointer().unwrap();

            let smram_map_size_var = self.default_proto.resolved_input(1, stack_base).unwrap();
            if let Some(addr) = context.read_var(&smram_map_size_var).to_address() {
                tracing::info!("SmramMapSize at {addr} / {}", location.address);
                if addr.offset() != 0 {
                    tracing::info!("found (possible) SmramMapSize variable at {addr}");
                    self.smram_map_size_vars.insert(addr);

                    context.write_addr(addr, &BitVec::from(SIZE_SENTINEL)).ok();
                }
            }

            let smram_map_var = self.default_proto.resolved_input(2, stack_base).unwrap();

            let failed = if let Some(addr) = context.read_var(&smram_map_var).to_address() {
                tracing::info!("SmramMap at {addr} / {}", location.address);
                if let Some(addrs) = self.sentinel_vars.get(&addr) {
                    for &addr in addrs.iter() {
                        tracing::info!("found (possible) SmramMap variable at {addr} (aliased)");
                        self.smram_map_vars.insert(addr);
                    }
                    false
                } else if addr.offset() != 0 {
                    tracing::info!("found (possible) SmramMap variable at {addr}");
                    self.smram_map_vars.insert(addr);
                    false
                } else {
                    true
                }
            } else {
                false
            };

            let retn_var = self.default_proto.resolved_output(0, stack_base).unwrap();

            if !failed {
                tracing::trace!(
                    "clearing return value of gSmmAccess2->GetCapabilities at {retn_var}"
                );
                context
                    .write_var(&retn_var, &BitVec::zero(retn_var.nbits() as usize))
                    .ok();
            } else {
                context
                    .write_var(
                        &retn_var,
                        &BitVec::from_u64(0x8000_0000_0000_0005u64, retn_var.nbits() as usize),
                    )
                    .ok();
            }
        } else if target == self.allocate_pool {
            tracing::info!(
                "found call to gBS->AllocatePool / gSmst->SmmAllocatePool at {}",
                location.address
            );

            let stack_base = context.read_stack_pointer().unwrap();

            let output_loc = self.default_proto.resolved_input(2, stack_base).unwrap();
            let return_loc = self.default_proto.resolved_output(0, stack_base).unwrap();

            if let Some(interface) = context.read_var(&output_loc).to_address() {
                tracing::info!("AllocatePool / SmmAllocatePool sentinel to {interface}");

                context
                    .write_pointer(interface, Address::from(self.sentinel_var))
                    .ok();
                context
                    .write_var(&return_loc, &BitVec::zero(return_loc.nbits() as usize))
                    .ok();

                let mut mapping = BTreeSet::new();
                mapping.insert(interface);

                self.sentinel_vars.insert(self.sentinel_var, mapping);
                self.sentinel_var = self.sentinel_var + 1usize;
            }
        }

        Ok(())
    }
}

struct ObserveSmstCall {
    register: Address,
    locate: Address,

    guid_db: GuidDB,
    smi_handlers: BTreeSet<Address>,

    default_proto: DefaultPrototype,
}

impl Observer for ObserveSmstCall {
    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        if target == self.register {
            tracing::info!(
                "found call to gSmst->SmiHandlerRegister at {}",
                location.address
            );

            let stack_base = context.read_stack_pointer().unwrap();

            let handler_var = self.default_proto.resolved_input(0, stack_base).unwrap();
            let handler_type_var = self.default_proto.resolved_input(1, stack_base).unwrap();

            if let Some(smi_handler) = context.read_var(&handler_var).to_address() {
                tracing::info!("child SW SMI handler found at {smi_handler}");
                self.smi_handlers.insert(smi_handler);
            }

            if let Some(smi_handler_guid) = context.read_var(&handler_type_var).to_address() {
                tracing::info!("SMI handler GUID at {smi_handler_guid}");
            }
        } else if target == self.locate {
            tracing::info!(
                "found call to gSmst->SmmLocateProtocol at {}",
                location.address
            );

            let stack_base = context.read_stack_pointer().unwrap();

            let dispatch_guid = self.default_proto.resolved_input(0, stack_base).unwrap();
            let interface = self.default_proto.resolved_input(2, stack_base).unwrap();
            let return_loc = self.default_proto.resolved_output(0, stack_base).unwrap();

            if let Some(dispatch) = context.read_var(&dispatch_guid).to_address() {
                if let Ok(bytes) = context.read_bytes(dispatch, GUID_LEN) {
                    if let Some(guid) = self.guid_db.get(bytes) {
                        tracing::info!("SMI dispatch protocol found at {dispatch} for {guid}");
                    } else {
                        tracing::info!("SMI dispatch protocol found at {dispatch}");
                    }
                } else {
                    tracing::info!("SMI dispatch protocol found at {dispatch}");
                }
            }

            if let Some(interface) = context.read_var(&interface).to_address() {
                tracing::info!("SMI dispatch interface at {interface}");

                // we should direct this to a bit of memory we later hook?
                context
                    .write_pointer(interface, Address::from(0xf00dfaceu32))
                    .ok();
                context
                    .write_var(&return_loc, &BitVec::zero(return_loc.nbits() as usize))
                    .ok();
            }
        }

        Ok(())
    }
}

struct ObserveXXDispatchCall {
    register: Address,
    register_offset: Address,

    dispatch: &'static str,
    smi_handlers: BTreeSet<Address>,

    default_proto: DefaultPrototype,
}

impl Observer for ObserveXXDispatchCall {
    fn observe_post_var_invalid_read(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        _location: Location,
        var: &Var,
        val: &mut Option<BitVec>,
    ) -> Result<(), ObserverError> {
        if var.nbits() == self.default_proto.address_bits()
            && matches!(var.address(), Some(off) if off == self.register_offset)
        {
            *val = Some(BitVec::from_u64(self.register.into(), var.nbits() as usize));
        }

        Ok(())
    }

    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        if target == self.register {
            tracing::info!(
                "found call to {}->Register at {}",
                self.dispatch,
                location.address,
            );

            let stack_base = context.read_stack_pointer().unwrap();
            let handler_var = self.default_proto.resolved_input(1, stack_base).unwrap();

            if let Some(smi_handler) = context.read_var(&handler_var).to_address() {
                tracing::info!("SMI handler found at {smi_handler} for {}", self.dispatch);
                self.smi_handlers.insert(smi_handler);
            }
        }

        Ok(())
    }
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

pub const EFI_SMI_HANDLER_ANALYSIS: uuid::Uuid = uuid("BE5F1D42-5512-428B-99A7-7EAF594AB21A");

impl AnalysisInfo for SmiHandlerAnalyser {
    const NAME: &'static str = "EFI SMI Handler Analyser";
    const UUID: uuid::Uuid = EFI_SMI_HANDLER_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        AnalysisSchedule::After(XREF_ANALYSIS),
        AnalysisSchedule::After(EFI_GLOBALS_ANALYSIS),
        AnalysisSchedule::After(EFI_GUID_XREF_ANALYSIS),
        AnalysisSchedule::After(EFI_SERVICES_ANALYSIS),
        AnalysisSchedule::After(CODE_BLOCK_BOUNDS),
    ];
}

impl Analysis for SmiHandlerAnalyser {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let globals = project
            .analyses()
            .get::<GlobalsAnalyser>(EFI_GLOBALS_ANALYSIS)
            .unwrap();
        let guids = project
            .analyses()
            .get::<GuidAnalyser>(EFI_GUID_XREF_ANALYSIS)
            .unwrap();
        let xrefs = project.analyses().get::<XRefDB>(XREF_ANALYSIS).unwrap();

        let guid_db = guids.guid_db().clone();

        let addr_bits = project.lifter().address_bits();
        let addr_size = project.lifter().address_bytes();

        // BOOT_SERVICES
        let bs = project
            .typedb
            .get_type_for("EFI_BOOT_SERVICES", addr_bits)
            .ok_or_else(|| Error::TypeLookup("EFI_BOOT_SERVICES"))?;
        let bs_base = Address::from(0xdead_faceu32);
        let bs_size = bs.nbytes();

        let lp_foffset = bs
            .offset_of_field("LocateProtocol")
            .ok_or_else(|| Error::TypeLookup("EFI_BOOT_SERVICES.LocateProtocol"))?;
        let lp_ptr = bs_base + bs_size + 1usize;

        let bs_ap_foffset = bs
            .offset_of_field("AllocatePool")
            .ok_or_else(|| Error::TypeLookup("EFI_BOOT_SERVICES.AllocatePool"))?;
        let ap_ptr = bs_base + bs_size + 2usize;

        // SMM_BASE2
        let smm_base2 = project
            .typedb
            .get_type_for("_EFI_SMM_BASE2_PROTOCOL", addr_bits)
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_BASE2_PROTOCOL"))?;
        let smm_base2_base = Address::from(0xfade_d00du32);
        let smm_base2_size = smm_base2.nbytes();

        let smm_base2_loc_foffset = smm_base2
            .offset_of_field("GetSmstLocation")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_BASE2_PROTOCOL.GetSmstLocation"))?;
        let smm_base2_loc_ptr = smm_base2_base + smm_base2_size + 1usize;

        let smm_base2_inside_foffset = smm_base2
            .offset_of_field("InSmm")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_BASE2_PROTOCOL.InSmm"))?;
        let smm_base2_inside_ptr = smm_base2_base + smm_base2_size + 2usize;

        // SMM_ACCESS2
        let smm_access2 = project
            .typedb
            .get_type_for("_EFI_SMM_ACCESS2_PROTOCOL", addr_bits)
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_ACCESS2_PROTOCOL"))?;
        let smm_access2_base = Address::from(0xfbde_d00du32);
        let smm_access2_size = smm_access2.nbytes();

        let smm_access2_cap_foffset = smm_access2
            .offset_of_field("GetCapabilities")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_ACCESS2_PROTOCOL.GetCapabilities"))?;
        let smm_access2_cap_ptr = smm_access2_base + smm_access2_size + 1usize;

        // SMM_SYSTEM_TABLE2
        let smst = project
            .typedb
            .get_type_for("_EFI_SMM_SYSTEM_TABLE2", addr_bits)
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_SYSTEM_TABLE2"))?;
        let smst_base = Address::from(0xfed1_f00du32);
        let smst_size = smst.nbytes();

        let smst_reg_foffset = smst
            .offset_of_field("SmiHandlerRegister")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_SYSTEM_TABLE2.SmiHandlerRegister"))?;

        let smst_loc_foffset = smst
            .offset_of_field("SmmLocateProtocol")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_SYSTEM_TABLE2.SmmLocateProtocol"))?;

        let smst_ap_foffset = smst
            .offset_of_field("SmmAllocatePool")
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_SYSTEM_TABLE2.SmmAllocatePool"))?;

        let smst_reg_ptr = smst_base + smst_size + 1usize;
        let smst_loc_ptr = smst_base + smst_size + 2usize;

        // Configure evaluator
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

        // Create mappings
        eval.static_mapping("bs", bs_base, bs_size)
            .map_err(Error::from)?;
        eval.static_mapping("smst", smst_base, smst_size)
            .map_err(Error::from)?;
        eval.static_mapping("smm-base2", smm_base2_base, smm_base2_size)
            .map_err(Error::from)?;
        eval.static_mapping("smm-access2", smm_access2_base, smm_access2_size)
            .map_err(Error::from)?;

        // Write gBS pointers
        for bs_addr in globals.boot_services() {
            write_pointer(&mut eval, *bs_addr, bs_base)?;
        }

        write_pointer(&mut eval, bs_base + lp_foffset, lp_ptr)?;

        write_pointer(&mut eval, bs_base + bs_ap_foffset, ap_ptr)?;
        write_pointer(&mut eval, smst_base + smst_ap_foffset, ap_ptr)?;

        // Write pointer for _EFI_SMM_BASE2_PROTOCOL->GetSmstLocation
        write_pointer(
            &mut eval,
            smm_base2_base + smm_base2_loc_foffset,
            smm_base2_loc_ptr,
        )?;

        // Write pointer for _EFI_SMM_BASE2_PROTOCOL->InSmm
        write_pointer(
            &mut eval,
            smm_base2_base + smm_base2_inside_foffset,
            smm_base2_inside_ptr,
        )?;

        // Write pointer for _EFI_SMM_ACCESS2_PROTOCOL->GetCapabilities
        write_pointer(
            &mut eval,
            smm_access2_base + smm_access2_cap_foffset,
            smm_access2_cap_ptr,
        )?;

        // Write gSmst pointers
        for smst in globals.sm_system_table().iter() {
            write_pointer(&mut eval, *smst, smst_base)?;
        }

        write_pointer(&mut eval, smst_base + smst_reg_foffset, smst_reg_ptr)?;
        write_pointer(&mut eval, smst_base + smst_loc_foffset, smst_loc_ptr)?;

        // Register analysis observers
        let obs_id = eval.register_observer(ObserveSmstCall {
            register: smst_reg_ptr,
            locate: smst_loc_ptr,
            guid_db,
            smi_handlers: Default::default(),
            default_proto: project.lifter().default_prototype(),
        });

        let obs_smst_id = eval.register_observer(ObserveSmst {
            bs_refs: globals.boot_services().clone(),
            bs_addr: bs_base,
            smst_addr: smst_base,

            locate_protocol: lp_ptr,
            allocate_pool: ap_ptr,

            smst_base_interface: smm_base2_base,
            smst_get_smst_location: smm_base2_loc_ptr, //smst_loc_ptr,
            smst_in_smm: smm_base2_inside_ptr,

            smm_access_interface: smm_access2_base,
            smm_get_capabilities: smm_access2_cap_ptr,

            smst_tables: Default::default(),
            in_smram_vars: Default::default(),
            smram_map_vars: Default::default(),
            smram_map_size_vars: Default::default(),
            smram_map_count_vars: Default::default(),

            sentinel_vars: Default::default(),
            sentinel_var: Address::from(ALLOCATE_SENTINEL),

            default_proto: project.lifter().default_prototype(),
        });

        // Freeze analyser state
        let original = eval.refreeze();

        // Get child sw smi handlers
        let mut analysed = BTreeSet::new();
        for smst in globals.sm_system_table().iter() {
            for (xref_to, _) in xrefs.loads_from(smst) {
                let blk = &project.cbtable[xref_to];

                if !analysed.insert(blk.address()) {
                    continue;
                }

                tracing::trace!("load from gSmst via block at {}", blk.address());

                eval.eval(
                    project.tables(),
                    blk.address(),
                    Bound::StopAfterOr(blk.last_address(), 40),
                )
                .ok();

                eval.restore().map_err(Error::from)?;
            }
        }

        let base2_index = guids
            .guid_db()
            .get_index("EFI_SMM_BASE2_PROTOCOL_GUID")
            .unwrap();

        let access2_index = guids
            .guid_db()
            .get_index("EFI_SMM_ACCESS2_PROTOCOL_GUID")
            .unwrap();

        let mut a2b2_funcs = BTreeSet::new();
        let mut a2b2_blocks = BTreeSet::new();

        for &cb in guids
            .xrefs(base2_index)
            .into_iter()
            .flatten()
            .chain(guids.xrefs(access2_index).into_iter().flatten())
        {
            let block = &project.cbtable[cb];
            let function = project.ftable[block.function()].address();

            a2b2_blocks.insert(block.address());
            a2b2_funcs.insert(function);
        }

        for smst in globals.sm_system_table().iter() {
            write_pointer(&mut eval, *smst, smst_base)?;
        }

        eval.refreeze();

        for start in a2b2_funcs.into_iter().chain(a2b2_blocks.into_iter()) {
            eval.restore().ok();

            eval.eval_with(
                project.tables(),
                start,
                Bound::Count(250),
                XForceStrategy::default(),
            )
            .ok();
        }

        let obs = eval.get_observer_mut::<ObserveSmstCall>(obs_id).unwrap();
        self.child_sw_smi_handlers
            .extend(btreeset_drain(&mut obs.smi_handlers));

        let obs_smst = eval.get_observer_mut::<ObserveSmst>(obs_smst_id).unwrap();
        self.in_smram_vars
            .extend(btreeset_drain_filter(&mut obs_smst.in_smram_vars, |addr| {
                project.memory().contains(addr)
            }));
        self.smram_map_vars.extend(btreeset_drain_filter(
            &mut obs_smst.smram_map_vars,
            |addr| project.memory().contains(addr),
        ));
        self.smram_map_size_vars.extend(btreeset_drain_filter(
            &mut obs_smst.smram_map_size_vars,
            |addr| project.memory().contains(addr),
        ));
        self.smram_map_count_vars.extend(btreeset_drain_filter(
            &mut obs_smst.smram_map_count_vars,
            |addr| project.memory().contains(addr),
        ));

        // Detection of other kinds of SMI handler
        let dispatchers: BTreeMap<&str, &str> = [
            ("EFI_SMM_GPI_DISPATCH_PROTOCOL", "GpiSmiHandler"),
            ("EFI_SMM_GPI_DISPATCH2_PROTOCOL", "GpiSmiHandler"),
            ("EFI_SMM_ICHN_DISPATCH_PROTOCOL", "IchnSmiHandler"),
            ("EFI_SMM_ICHN_DISPATCH2_PROTOCOL", "IchnSmiHandler"),
            ("EFI_SMM_ICHN_DISPATCH_EX_PROTOCOL", "IchnSmiHandler"),
            ("EFI_SMM_ICHN_DISPATCH2_EX_PROTOCOL", "IchnSmiHandler"),
            ("EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL", "IoTrapSmiHandler"),
            ("EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL", "IoTrapSmiHandler"),
            (
                "EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL",
                "PeriodicTimerSmiHandler",
            ),
            (
                "EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL",
                "PeriodicTimerSmiHandler",
            ),
            (
                "EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL",
                "PowerButtonSmiHandler",
            ),
            (
                "EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL",
                "PowerButtonSmiHandler",
            ),
            (
                "EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL",
                "StandbyButtonSmiHandler",
            ),
            (
                "EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL",
                "StandbyButtonSmiHandler",
            ),
            ("EFI_SMM_SW_DISPATCH_PROTOCOL", "SwSmiHandler"),
            ("EFI_SMM_SW_DISPATCH2_PROTOCOL", "SwSmiHandler"),
            ("EFI_SMM_SX_DISPATCH_PROTOCOL", "SxSmiHandler"),
            ("EFI_SMM_SX_DISPATCH2_PROTOCOL", "SxSmiHandler"),
            ("EFI_SMM_TCO_DISPATCH_PROTOCOL", "TcoSmiHandler"),
            ("EFI_SMM_USB_DISPATCH_PROTOCOL", "UsbSmiHandler"),
            ("EFI_SMM_USB_DISPATCH2_PROTOCOL", "UsbSmiHandler"),
            ("FCH_SMM_APU_RAS_DISPATCH_PROTOCOL", "ApuRasSmiHandler"),
            ("FCH_SMM_GPI_DISPATCH2_PROTOCOL", "GpiSmiHandler"),
            ("FCH_SMM_IO_TRAP_DISPATCH2_PROTOCOL", "IoTrapSmiHandler"),
            (
                "FCH_SMM_PERIODICAL_DISPATCH2_PROTOCOL",
                "PeriodicTimerSmiHandler",
            ),
            (
                "FCH_SMM_PWR_BTN_DISPATCH2_PROTOCOL",
                "PowerButtonSmiHandler",
            ),
            ("FCH_SMM_SW_DISPATCH2_PROTOCOL", "SwSmiHandler"),
            ("FCH_SMM_SX_DISPATCH2_PROTOCOL", "SxSmiHandler"),
            ("FCH_SMM_USB_DISPATCH_PROTOCOL", "UsbSmiHandler"),
            ("FCH_SMM_USB_DISPATCH2_PROTOCOL", "UsbSmiHandler"),
            ("FCH_SMM_MISC_DISPATCH_PROTOCOL", "MiscSmiHandler"),
            ("PCH_ACPI_SMI_DISPATCH_PROTOCOL", "AcpiSmiHandler"),
            ("PCH_ESPI_SMI_DISPATCH_PROTOCOL", "EspiSmiHandler"),
            (
                "PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL",
                "GpioUnlockSmiHandler",
            ),
            ("PCH_PCIE_SMI_DISPATCH_PROTOCOL", "PcieSmiHandler"),
            ("PCH_SMI_DISPATCH_PROTOCOL", "PchSmiHandler"),
            ("PCH_TCO_SMI_DISPATCH_PROTOCOL", "TcoSmiHandler"),
        ]
        .into_iter()
        .collect();

        eval.refreeze_with(original);
        eval.restore().map_err(Error::from)?;

        for smst in globals.sm_system_table().iter() {
            write_pointer(&mut eval, *smst, 0u32.into())?;
        }

        let default_proto = project.lifter().default_prototype();
        let initial = default_proto
            .resolved_output(0, eval.configuration().stack_start)
            .unwrap();

        let rproto = Address::from(0xdeadfaceu32);
        let rproto_len = 32;
        let rproto_ptr = rproto + rproto_len + 1usize;

        eval.static_mapping("dispatch-mapping", rproto, rproto_len)
            .map_err(Error::from)?;

        let obs_id = eval.register_observer(ObserveXXDispatchCall {
            register: Address::from(0u32),
            register_offset: Address::from(0u32),
            smi_handlers: Default::default(),
            default_proto,
            dispatch: "",
        });

        eval.refreeze();

        // Collect interfaces and corresponding dispatch protocols
        // in format (locate protocol call block, interface variable address, dispatch protocol GUID)
        let services = project.analyses().get_by::<ServicesAnalyser>().unwrap();
        let bounds = project.analyses().get_by::<CodeBlockBounds>().unwrap();
        let interfaces = services
            .smm_services()
            .into_iter()
            .filter_map(|(&lp_addr, service)| {
                if service.service() != *SMM_LOCATE_PROTOCOL {
                    return None;
                }
                let guid = service.protocol()?;
                dispatchers.get(guid.trim_end_matches("_GUID"))?;
                let interface = service.params().get(2)?.as_ref()?;
                // get block with call to SmmLocateProtocol
                let (_, block) = bounds.get(lp_addr)?;
                Some((block, interface.source()?, guid))
            })
            .collect::<BTreeSet<_>>();

        // Collect functions that use dispatch interfaces (EfiSmmXxDispatchProtocol->Register())
        // for each dispatch protocol GUID
        let mut functions = BTreeMap::new();
        for (block, addr, guid) in interfaces {
            let funcs = if project.memory().contains(addr) {
                // collect functions that references the global interface
                xrefs
                    .loads_from(addr)
                    .filter_map(|(b, _)| Some(project.code_blocks()[b].function()))
                    .collect::<BTreeSet<_>>()
            } else {
                // if interface is a local variable, add only the current function
                let mut funcs = BTreeSet::new();
                funcs.insert(project.code_blocks()[*block].function());
                funcs
            };
            functions
                .entry(guid)
                .or_insert(BTreeSet::new())
                .extend(funcs)
        }

        // Add functions candidates derived from dispatch protocols xrefs
        // this will prevent SMI handlers to be missed in cases when one of the
        // gSmst/Smst was not found and subsequent SMM services analysis failed
        for dispatch in dispatchers.keys() {
            let guid = format!("{}_GUID", dispatch);
            let guid_idx = guids.guid_db()[&*guid];
            if let Some(blocks) = guids.xrefs(guid_idx) {
                let funcs = blocks
                    .iter()
                    .map(|b| project.code_blocks()[*b].function())
                    .collect::<BTreeSet<_>>();
                functions
                    .entry(Ustr::from(&guid))
                    .or_insert(BTreeSet::new())
                    .extend(funcs);
            }
        }

        // This should be from all blocks, not just those ending with is_indirect_call
        for (guid, funcs) in functions {
            let dispatch = guid.as_str().trim_end_matches("_GUID");
            let tname = format!("_{}", dispatch);
            let register_off = project
                .typedb
                .get_type_for(&*tname, addr_bits)
                .and_then(|dstruct| dstruct.offset_of_field("Register"))
                .unwrap_or(0);

            let obs = eval
                .get_observer_mut::<ObserveXXDispatchCall>(obs_id)
                .unwrap();
            let register_ptr = rproto_ptr + register_off;

            obs.register = register_ptr;
            obs.register_offset = Address::from(register_off as u64);
            obs.dispatch = dispatch;

            for f in funcs {
                let f = &project.functions()[f];
                for blk in f
                    .blocks_with(project.code_blocks())
                    .filter(|blk| blk.last_operation().is_indirect_call())
                {
                    write_var(
                        &mut eval,
                        &initial,
                        &BitVec::from_u64(register_ptr.into(), addr_bits as usize),
                    )?;

                    for offset in (0..rproto_len).step_by(addr_size) {
                        write_pointer(&mut eval, rproto + offset, register_ptr)?;
                    }

                    eval.eval(
                        project.tables(),
                        blk.address(),
                        Bound::Count(40),
                        //Bound::StopAfterOr(blk.last_address(), 40),
                    )
                    .ok();

                    eval.restore().map_err(Error::from)?;
                }
            }

            let obs = eval
                .get_observer_mut::<ObserveXXDispatchCall>(obs_id)
                .unwrap();

            self.smi_handlers
                .entry(Ustr::from(dispatch))
                .or_default()
                .extend(btreeset_drain_filter(&mut obs.smi_handlers, |faddr| {
                    project.ftable.contains_point(faddr)
                }));
        }

        // perform extra checks for callouts via global interfaces obtained using
        // gBS->LocateProtocol, gBS->AllocatePool, gBS->AllocatePages
        let check_buffer = |service: &ServiceInfo, param: usize| -> Option<Address> {
            service.params().get(param).and_then(|v| {
                let v = v.as_ref()?.value()?.to_address()?;
                if project.memory().contains(v) {
                    Some(v)
                } else {
                    None
                }
            })
        };

        let mut global_buffers = BTreeSet::new();
        for service in services.boot_services().values() {
            let addr =
                if service.service() == *LOCATE_PROTOCOL || service.service() == *ALLOCATE_POOL {
                    check_buffer(service, 2)
                } else if service.service() == *ALLOCATE_PAGES {
                    check_buffer(service, 3)
                } else {
                    None
                };

            if let Some(addr) = addr {
                global_buffers.insert(addr);
            }
        }

        for h in self.child_sw_smi_handlers.iter() {
            check_callout(
                h,
                globals,
                xrefs,
                &global_buffers,
                &mut self.callouts,
                project.tables(),
            );
        }

        // check only unique locations
        for h in self
            .smi_handlers
            .iter()
            .flat_map(|(_, h)| h)
            .collect::<BTreeSet<_>>()
        {
            check_callout(
                h,
                globals,
                xrefs,
                &global_buffers,
                &mut self.callouts,
                project.tables(),
            );
        }

        // add symbols in project
        for h in self.child_sw_smi_handlers.iter().sorted() {
            let Some(fcn) = project.functions_mut().get_point_mut(h) else {
                continue;
            };
            if fcn.name().is_none() {
                let fid = fcn.id();
                let name = project
                    .symbols_mut()
                    .insert_fresh_with_prefix("ChildSwSmiHandler", fid);
                project.functions_mut()[fid].update_name(name);
            }
        }

        for (kind, handlers) in self.smi_handlers.iter() {
            let Some(base_name) = dispatchers.get(kind.as_ref()) else {
                continue;
            };
            for h in handlers.iter().sorted() {
                let Some(fcn) = project.functions_mut().get_point_mut(h) else {
                    continue;
                };
                if fcn.name().is_none() {
                    let fid = fcn.id();
                    let name = project
                        .symbols_mut()
                        .insert_fresh_with_prefix(base_name, fid);
                    project.functions_mut()[fid].update_name(name);
                }
            }
        }

        let handler_t = project
            .typedb
            .get_type_for("EFI_SMM_HANDLER_ENTRY_POINT2", addr_bits)
            .ok_or_else(|| Error::TypeLookup("EFI_SMM_HANDLER_ENTRY_POINT2"))?;

        if let Some(handler_t) = handler_t.pointee() {
            for addr in self
                .child_sw_smi_handlers()
                .iter()
                .chain(self.smi_handlers_locations())
            {
                project.typedb.set_code_type_at(*addr, handler_t.to_owned());
            }
        }

        Ok(())
    }
}

fn check_callout_blocks(
    hid: FunctionId,
    fcn: &Function,
    globals: &GlobalsAnalyser,
    xrefs: &XRefDB,
    global_buffers: &BTreeSet<Address>,
    callouts: &mut BTreeSet<(FunctionId, Location)>,
) {
    for blk in fcn.blocks().keys() {
        for xref in xrefs.xrefs_from(*blk) {
            if globals.boot_services().contains(&xref.target()) {
                tracing::info!("potential callout via gBS from {}", xref.source());
                callouts.insert((hid, xref.source()));
            } else if globals.runtime_services().contains(&xref.target()) {
                tracing::info!("potential callout via gRT from {}", xref.source());
                callouts.insert((hid, xref.source()));
            } else if global_buffers.contains(&xref.target()) {
                tracing::info!("potential callout via global buffer from {}", xref.source());
                callouts.insert((hid, xref.source()));
            }
        }
    }
}

fn check_callout(
    f: &Address,
    globals: &GlobalsAnalyser,
    xrefs: &XRefDB,
    global_buffers: &BTreeSet<Address>,
    callouts: &mut BTreeSet<(FunctionId, Location)>,
    context: ProjectContext,
) {
    if let Some(fcn) = context.ftable.get_point(f) {
        let mut checks = VecDeque::new();
        let mut processed = BTreeSet::new();
        let hid = fcn.id();

        checks.push_back(fcn);

        while let Some(fcn) = checks.pop_front() {
            let fid = fcn.id();
            if processed.contains(&fid) {
                continue;
            }

            check_callout_blocks(hid, fcn, globals, xrefs, global_buffers, callouts);
            processed.insert(fid);

            context
                .icfg
                .for_each_called_by(hid, context, |fcn, _context| {
                    checks.push_back(fcn);
                })
        }
    }
}
