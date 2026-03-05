use bias_core::efi::guids::{GuidAnalyser, EFI_GUID_XREF_ANALYSIS};
use bias_core::prelude::efi::GuidDB;
use bias_core::Project;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer};
use uuid::Uuid;

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
pub struct Guid {
    #[getset(get = "pub", get_mut = "pub")]
    name: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(deserialize_with = "deserialize_guid")]
    value: Uuid,
}

impl Guid {
    pub fn new(uuid: Uuid) -> Self {
        Self::new_with(uuid, None)
    }

    pub fn group() -> Groups<Guid> {
        Groups::default()
    }

    pub fn new_with(uuid: Uuid, name: impl Into<Option<String>>) -> Self {
        Self {
            name: name.into().unwrap_or_else(|| uuid.to_string()),
            value: uuid,
        }
    }

    pub fn from_db(uuid: Uuid, db: &GuidDB) -> Self {
        Self::new_with(uuid, db.name_for(uuid).map(ToOwned::to_owned))
    }
}

pub(crate) fn deserialize_guid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let guidstr = String::deserialize(deserializer)?.replace("-", "");
    Uuid::deserialize(guidstr.into_deserializer())
}

impl MatchesRule for Guid {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        let guids = project
            .analyses()
            .get::<GuidAnalyser>(EFI_GUID_XREF_ANALYSIS)
            .unwrap();
        if let Some(index) = guids.guid_db().get_index(&**self.name()) {
            guids
                .xrefs(index)
                .map(|xs| {
                    let result = !xs.is_empty();
                    if result {
                        context.describe(FwHuntCheckMatch::Guid {
                            value: self.name.to_owned(),
                            locations: context
                                .pending_provenance_iter()
                                .map(|addr| FwHuntCheckLocation::Address {
                                    value: addr.offset(),
                                })
                                .collect::<Vec<_>>(),
                        });
                        xs.iter().for_each(|&id| {
                            let blk = project.code_blocks()[id].address();
                            context.push_provenance(blk);
                        });
                    }
                    result
                })
                .unwrap_or(false)
        } else {
            false
        }
    }
}
