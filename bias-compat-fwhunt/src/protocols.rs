use std::fmt::Display;
use std::ops::{Deref, DerefMut};

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
pub struct ProtocolService {
    #[getset(get = "pub", get_mut = "pub")]
    name: String,
}

impl Display for ProtocolService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

impl Deref for ProtocolService {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl DerefMut for ProtocolService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.name
    }
}

impl From<String> for ProtocolService {
    fn from(name: String) -> Self {
        Self { name }
    }
}

impl From<ProtocolService> for String {
    fn from(slf: ProtocolService) -> Self {
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
pub struct Protocol {
    #[getset(get = "pub", get_mut = "pub")]
    name: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(deserialize_with = "crate::guids::deserialize_guid")]
    value: Uuid,
    #[getset(get = "pub", get_mut = "pub")]
    service: ProtocolService,
}

impl Protocol {
    pub fn new(service: impl Into<String>, name: impl Into<String>, guid: Uuid) -> Self {
        Self {
            name: name.into(),
            value: guid,
            service: ProtocolService {
                name: service.into(),
            },
        }
    }

    pub fn group() -> Groups<Protocol> {
        Groups::default()
    }
}

impl MatchesRule for Protocol {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        let services = project
            .analyses()
            .get::<ServicesAnalyser>(EFI_SERVICES_ANALYSIS)
            .unwrap();

        tracing::trace!(
            "searching for use of protocol {}/{} with service {}",
            self.name(),
            self.value(),
            self.service().name()
        );

        let guid_str = Ustr::from(&self.value.as_hyphenated().to_string());

        let addr = services.find(|info| {
            info.service().as_str() == self.service().name()
                && matches!(info.protocol(), Some(protocol) if protocol.as_str() == self.name() || guid_str == protocol)
        });

        if let Some(addr) = addr {
            context.describe(FwHuntCheckMatch::Protocol {
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
