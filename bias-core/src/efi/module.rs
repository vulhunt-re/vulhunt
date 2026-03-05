use thiserror::Error;
use uuid::Uuid;

use crate::efi::image::depex::DepExOpcode;
use crate::efi::EFIModuleType;
use crate::ir::Address;
use crate::kb::uuid;
use crate::loader::efi::LoadedEFIModule;
use crate::loader::LoadedBinary;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

#[derive(Debug, Error)]
pub enum Error {
    #[error("loaded binary does not have an entry-point")]
    NoEntryPoint,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ModuleInfo {
    entry: Address,
    depex: Vec<DepExOpcode>,
    module_kind: EFIModuleType,
}

impl TryFrom<&'_ LoadedEFIModule<'_>> for ModuleInfo {
    type Error = Error;

    fn try_from(binary: &'_ LoadedEFIModule) -> Result<Self, Self::Error> {
        Self::new_with(binary, binary.module_type(), binary.depex())
    }
}

impl ModuleInfo {
    pub fn new<L>(binary: &L, module_kind: EFIModuleType) -> Result<Self, Error>
    where
        L: LoadedBinary,
    {
        Self::new_with(binary, module_kind, Vec::with_capacity(0))
    }

    pub fn new_with<L>(
        binary: &L,
        module_kind: EFIModuleType,
        depex: impl Into<Vec<DepExOpcode>>,
    ) -> Result<Self, Error>
    where
        L: LoadedBinary,
    {
        if let Some(entry) = binary.entry_point() {
            Ok(Self {
                entry,
                module_kind,
                depex: depex.into(),
            })
        } else {
            Err(Error::NoEntryPoint)
        }
    }

    pub fn is_pei(&self) -> bool {
        matches!(
            self.module_kind,
            EFIModuleType::PeiCore | EFIModuleType::PeiModule | EFIModuleType::CombinedPeiDxe
        )
    }

    pub fn is_dxe(&self) -> bool {
        matches!(
            self.module_kind,
            EFIModuleType::DxeCore
                | EFIModuleType::DxeDriver
                | EFIModuleType::CombinedPeiDxe
                | EFIModuleType::CombinedSmmDxe
                | EFIModuleType::Application
        )
    }

    pub fn is_smm(&self) -> bool {
        matches!(
            self.module_kind,
            EFIModuleType::SmmCore
                | EFIModuleType::SmmModule
                | EFIModuleType::CombinedSmmDxe
                | EFIModuleType::SmmStandaloneModule
                | EFIModuleType::SmmStandaloneCore
        )
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn depex(&self) -> &[DepExOpcode] {
        &self.depex
    }

    pub fn kind(&self) -> EFIModuleType {
        self.module_kind
    }
}

pub const EFI_MODULE_INFO_ANALYSIS: Uuid = uuid("6CB8298A-7699-47B3-B98C-5A8ADAA0FD93");

impl AnalysisInfo for ModuleInfo {
    const NAME: &'static str = "EFI Module Information";
    const UUID: Uuid = EFI_MODULE_INFO_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for ModuleInfo {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, _project: &mut Project) -> Result<(), AnalysisError> {
        Ok(())
    }
}
