use std::fmt::Display;
use std::ops::{Deref, DerefMut};

use bias_core::efi::guids::{GuidAnalyser, EFI_GUID_XREF_ANALYSIS};
use bias_core::efi::services::{ServicesAnalyser, EFI_SERVICES_ANALYSIS};
use bias_core::kb::{Ustr, Uuid};
use bias_core::Project;

use crate::group::Groups;
use crate::matcher::MatchContext;
use crate::schema::*;
use crate::MatchesRule;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    getset::Getters,
    getset::MutGetters,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct NvramService {
    #[getset(get = "pub", get_mut = "pub")]
    name: String,
}

impl Display for NvramService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

impl Deref for NvramService {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl DerefMut for NvramService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.name
    }
}

impl From<String> for NvramService {
    fn from(name: String) -> Self {
        Self { name }
    }
}

impl From<NvramService> for String {
    fn from(slf: NvramService) -> Self {
        slf.name
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    getset::Getters,
    getset::MutGetters,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct Nvram {
    #[getset(get = "pub", get_mut = "pub")]
    name: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(deserialize_with = "crate::guids::deserialize_guid")]
    guid: Uuid,
    #[getset(get = "pub", get_mut = "pub")]
    service: NvramService,
}

impl Nvram {
    pub fn new(service: impl Into<String>, name: impl Into<String>, guid: Uuid) -> Self {
        Self {
            name: name.into(),
            guid,
            service: NvramService {
                name: service.into(),
            },
        }
    }

    pub fn group() -> Groups<Nvram> {
        Groups::default()
    }
}

impl MatchesRule for Nvram {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        let services = project
            .analyses()
            .get::<ServicesAnalyser>(EFI_SERVICES_ANALYSIS)
            .unwrap();

        let guid_db = project
            .analyses()
            .get::<GuidAnalyser>(EFI_GUID_XREF_ANALYSIS)
            .unwrap()
            .guid_db();

        tracing::trace!(
            "searching for use of NVRAM variable {}/{} with {}",
            self.name(),
            self.guid(),
            self.service().name()
        );

        let name_str = Ustr::from(&self.name());
        let guid_str = guid_db
            .name_for(self.guid)
            .map(|guid| Ustr::from(guid))
            .unwrap_or_else(|| Ustr::from(&self.guid.as_hyphenated().to_string()));

        let addr = services.find(|info| {
            info.service().as_str() == self.service().name()
                && matches!(info.variable_name(), Some(name) if name == name_str)
                && matches!(info.variable_guid(), Some(guid) if guid == guid_str)
        });

        if let Some(addr) = addr {
            context.describe(FwHuntCheckMatch::NvramVariable {
                value: self.name.to_owned(),
                location: FwHuntCheckLocation::FunctionCall {
                    value: Box::new(FwHuntCallLocations {
                        location: FwHuntCheckLocation::Address {
                            value: addr.offset(),
                        },
                        target: FwHuntCheckLocation::FunctionName {
                            value: self.service().name().to_owned(),
                        },
                    }),
                },
            });
            context.push_provenance(addr);
            true
        } else {
            false
        }
    }
}
