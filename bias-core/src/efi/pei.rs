use fugue::bv::BitVec;
use once_cell::sync::Lazy;
use ustr::Ustr;

use crate::arch::aarch64::ARCH_AARCH64;
use crate::efi::module::ModuleInfo;
use crate::efi::services::{PeiDescriptor, ServiceData, ServicesAnalyser, EFI_SERVICES_ANALYSIS};
use crate::eval::observer::{Observer, ObserverError, ObserverId};
use crate::eval::{Error, IRContext, IREvaluator};
use crate::ir::traits::ToAddress;
use crate::ir::{Address, Expr, InsnTarget, Location, Stmt, Term, Var};
use crate::kb::block::CodeBlock;
use crate::kb::{ustr, uuid, AHashSet, Uuid};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::project::ProjectContext;
use crate::{lazy_ustr, Project};

pub static SIDT: Lazy<Ustr> = lazy_ustr!("InterruptDescriptorTableRegister");

pub struct SIDTHandler {
    idt_address: BitVec,
}

impl SIDTHandler {
    pub fn install<'p, C, A>(
        project: C,
        evaluator: &mut IREvaluator,
        service_address: A,
    ) -> Result<ObserverId, Error>
    where
        C: Into<ProjectContext<'p>>,
        A: Into<Address>,
    {
        let project = project.into();

        let address_bytes = project.lifter.address_bytes();
        let pei_service_addr =
            evaluator.static_mapping("PS-IDT", None, address_bytes + 256 * address_bytes * 2)?;

        evaluator
            .context_mut()
            .write_pointer(pei_service_addr, service_address.into())?;

        let address_bits = project.lifter.address_bits() as usize;
        let address_bytes = project.lifter.address_bytes();

        let mut bytes = [0u8; 10];
        let rbytes = &mut bytes[..address_bytes + 2];
        let idt_address =
            BitVec::from_u64(u64::from(pei_service_addr + address_bytes), address_bits);

        idt_address.to_le_bytes(&mut rbytes[2..]);

        let idtr = BitVec::from_le_bytes(&rbytes);

        let id = evaluator.register_observer(Self { idt_address: idtr });

        Ok(id)
    }

    pub fn matches(stmt: &Term<Stmt>) -> bool {
        matches!(&**stmt, Stmt::Assign(_, expr) if matches!(&**expr, Expr::Intrinsic(name, _, _) if *name == *SIDT))
    }

    pub fn idt(&self) -> &BitVec {
        &self.idt_address
    }
}

impl Observer for SIDTHandler {
    fn observe_intrinsic(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        _location: Location,
        intrinsic: Ustr,
        _arguments: &mut [BitVec],
        result: &mut Option<BitVec>,
        handled: bool,
    ) -> Result<bool, ObserverError> {
        if !handled && intrinsic == *SIDT {
            tracing::trace!("handling sidt; table address at: {:x}", self.idt_address);
            *result = Some(self.idt_address.clone());
            Ok(true)
        } else {
            Ok(handled)
        }
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct GetPeiServicesFinder {
    candidates: AHashSet<Address>,
}

impl GetPeiServicesFinder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn matches(&self, block: &CodeBlock) -> bool {
        block
            .last_insn()
            .branch_targets()
            .iter()
            .any(|(_, target)| {
                let InsnTarget::InterSub(target) = target else {
                    return false;
                };
                let Some(addr) = target.to_address() else {
                    return false;
                };
                self.candidates.contains(&addr)
            })
    }

    pub fn install<'p>(
        &self,
        project: impl Into<ProjectContext<'p>>,
        evaluator: &mut IREvaluator,
        service_address: impl Into<Address>,
    ) -> Result<(), Error> {
        let project = project.into();
        let service_address = service_address.into();

        let Some(tpidr_el0) = project.lifter.register_var("tpidr_el0") else {
            return Ok(());
        };

        struct GetPeiServicesHook {
            addr: BitVec,
            tpidr_el0: Var,
        }

        impl Observer for GetPeiServicesHook {
            fn observe_post_var_read(
                &mut self,
                _context: &mut Box<dyn IRContext>,
                _location: Location,
                var: &Var,
                val: &mut BitVec,
            ) -> Result<(), ObserverError> {
                if *var != self.tpidr_el0 {
                    return Ok(());
                }

                val.clone_from(&self.addr);

                Ok(())
            }
        }

        evaluator.register_observer(GetPeiServicesHook {
            addr: BitVec::from_u64(service_address.into(), project.lifter.address_bits() as _),
            tpidr_el0,
        });

        Ok(())
    }
}

impl AnalysisInfo for GetPeiServicesFinder {
    const NAME: &'static str = "GetPeiServices finder for AArch64-based PEIMs";
    const UUID: Uuid = uuid("22044372-70E3-47DE-AB8B-AF29425DF20B");
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[AnalysisSchedule::after::<ModuleInfo>()];
}

impl Analysis for GetPeiServicesFinder {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if project.lifter().arch().id() != ARCH_AARCH64 {
            return Ok(());
        }

        if !project.get_analysis::<ModuleInfo>().is_pei() {
            return Ok(());
        }

        let Some(x0) = project.lifter().register_var("x0") else {
            return Ok(());
        };

        let Some(tpidr_el0) = project.lifter().register_var("tpidr_el0") else {
            return Ok(());
        };

        // look for functions with a single block where there's
        // an assignment to x0 from tpidr_el0
        //

        for f in project.functions().values() {
            if f.blocks().len() != 1 {
                continue;
            }

            let Some(block) = f.blocks_with(project.code_blocks()).next() else {
                continue;
            };

            if !block.is_return() {
                continue;
            }

            let Some(stmt) = block.insns()[0].first_operation() else {
                continue;
            };

            if matches!(&**stmt, Stmt::Assign(v1, expr) if *v1 == x0 && matches!(&**expr, Expr::Var(v2) if *v2 == tpidr_el0))
            {
                tracing::trace!("GetPeiServices candidate at {}", f.address());
                self.candidates.insert(f.address());
            }
        }

        Ok(())
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct PeiEntryPoints {
    notifications: AHashSet<PeiDescriptor>,
    ppis: AHashSet<PeiDescriptor>,
}

pub const EFI_PEI_ENTRY_POINTS: Uuid = uuid("3E403527-E09A-4C77-B957-EEB2F0DCB6FF");

impl PeiEntryPoints {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn notifications(&self) -> impl ExactSizeIterator<Item = &PeiDescriptor> {
        self.notifications.iter()
    }

    pub fn ppis(&self) -> impl ExactSizeIterator<Item = &PeiDescriptor> {
        self.ppis.iter()
    }

    fn update_ppis(&mut self, data: &[ServiceData]) {
        for svc in data {
            if let Some(d) = svc.ppi_descriptor_list() {
                self.ppis.extend(d.iter().cloned());
            }
        }
    }

    fn update_notifications(&mut self, data: &[ServiceData]) {
        for svc in data {
            if let Some(d) = svc.pei_notify_list() {
                self.notifications.extend(d.iter().cloned());
            }
        }
    }
}

impl AnalysisInfo for PeiEntryPoints {
    const NAME: &'static str = "EFI PEI Module Entrypoints";
    const UUID: uuid::Uuid = EFI_PEI_ENTRY_POINTS;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::After(EFI_SERVICES_ANALYSIS)];
}

impl Analysis for PeiEntryPoints {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let services = project
            .analyses()
            .get::<ServicesAnalyser>(EFI_SERVICES_ANALYSIS)
            .unwrap();

        let notify = ustr("NotifyPpi");
        let ppi = ustr("InstallPpi");

        for service in services.pei_services().values() {
            if service.service() == notify {
                self.update_notifications(service.data());
            } else if service.service() == ppi {
                self.update_ppis(service.data());
            }
        }

        Ok(())
    }
}
