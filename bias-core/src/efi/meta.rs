use ahash::AHashSet;
use sha2::{Digest, Sha256};
use ustr::Ustr;

use super::services::{GET_VARIABLE, SET_VARIABLE};
use crate::efi::guids::{GuidAnalyser, GuidDB, GuidSignature, EFI_GUID_XREF_ANALYSIS};
use crate::efi::services::{ServicesAnalyser, EFI_SERVICES_ANALYSIS};
use crate::kb::uuid;
use crate::project::analysis::{
    Analysis, AnalysisInfo, AnalysisSchedule, Error as AnalysisError, Schedule,
};
use crate::Project;

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct ModuleSignature {
    guid_signature: GuidSignature,
    variable_info: AHashSet<(Option<Ustr>, Ustr)>,
    digest: [u8; 32],
}

pub const EFI_MODULE_SIGNATURE_ANALYSIS: uuid::Uuid = uuid("457E46BB-E9C5-48FE-BDC1-8BF349355094");

impl AnalysisInfo for ModuleSignature {
    const NAME: &'static str = "EFI Module Signature";
    const UUID: uuid::Uuid = EFI_MODULE_SIGNATURE_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        AnalysisSchedule::After(EFI_GUID_XREF_ANALYSIS),
        AnalysisSchedule::After(EFI_SERVICES_ANALYSIS),
    ];
}

impl Analysis for ModuleSignature {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[Schedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let guids = project
            .analyses()
            .get::<GuidAnalyser>(EFI_GUID_XREF_ANALYSIS)
            .unwrap();

        let services = project
            .analyses()
            .get::<ServicesAnalyser>(EFI_SERVICES_ANALYSIS)
            .unwrap();

        self.guid_signature.update(guids, services);

        for rts in services
            .runtime_services()
            .values()
            .filter(|svc| svc.service() == *GET_VARIABLE || svc.service() == *SET_VARIABLE)
        {
            /*
            if let Some(name) = rts.variable_name() {
                self.variable_info.insert((rts.variable_guid(), name));
            }
            */
            for guid_name in rts.variables() {
                self.variable_info.insert(guid_name);
            }
        }

        let mut hasher = Sha256::default();
        for region in project.memory().regions().values(..) {
            hasher.update(region.bytes());
        }

        self.digest.copy_from_slice(&hasher.finalize()[..]);

        Ok(())
    }
}

impl ModuleSignature {
    pub fn new(guids: &GuidDB) -> Self {
        Self {
            guid_signature: GuidSignature::new(guids),
            variable_info: AHashSet::default(),
            digest: Default::default(),
        }
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn signature(&self) -> &GuidSignature {
        &self.guid_signature
    }

    pub fn variable_info(&self) -> &AHashSet<(Option<Ustr>, Ustr)> {
        &self.variable_info
    }
}

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct FirmwareSignature {
    guid_signature: GuidSignature,
    variable_info: AHashSet<(Option<Ustr>, Ustr)>,
    digests: AHashSet<[u8; 32]>,
}

impl FirmwareSignature {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_from(&mut self, project: &Project) {
        let msig = project
            .analyses()
            .get::<ModuleSignature>(EFI_MODULE_SIGNATURE_ANALYSIS)
            .unwrap();

        self.guid_signature.combine(msig.signature());
        self.variable_info.extend(msig.variable_info());
        self.digests.insert(*msig.digest());
    }

    pub fn signature(&self) -> &GuidSignature {
        &self.guid_signature
    }

    pub fn digests(&self) -> &AHashSet<[u8; 32]> {
        &self.digests
    }

    pub fn variable_info(&self) -> &AHashSet<(Option<Ustr>, Ustr)> {
        &self.variable_info
    }
}
