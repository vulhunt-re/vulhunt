use std::ops::Range;

use fugue::ir::Address;
use iset::IntervalMap;

use crate::analyses::xrefs::XRefDB;
use crate::kb::block::CodeBlockId;
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::project::Project;

pub const CODE_BLOCK_BOUNDS: uuid::Uuid = uuid("9B3CFE56-DE34-48D7-934D-C35954BBC044");

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct CodeBlockBounds {
    mapping: IntervalMap<Address, CodeBlockId>,
}

impl CodeBlockBounds {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(project: &Project) -> Self {
        Self {
            mapping: project
                .cbtable
                .values()
                .map(|cb| (cb.address()..cb.next_address(), cb.id()))
                .collect(),
        }
    }

    pub fn get<A: Into<Address>>(&self, address: A) -> Option<(Range<Address>, &CodeBlockId)> {
        self.get_all(address).next()
    }

    #[inline]
    pub fn get_all<A: Into<Address>>(
        &self,
        address: A,
    ) -> impl Iterator<Item = (Range<Address>, &CodeBlockId)> {
        let address = address.into();
        self.mapping.overlap(address)
    }

    pub fn len(&self) -> usize {
        self.mapping.len()
    }
}

impl AnalysisInfo for CodeBlockBounds {
    const NAME: &'static str = "Code Block Bounds Analyser";
    const UUID: uuid::Uuid = CODE_BLOCK_BOUNDS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[AnalysisSchedule::before::<XRefDB>()];
}

impl Analysis for CodeBlockBounds {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        self.mapping = project
            .cbtable
            .values()
            .map(|cb| (cb.address()..cb.next_address(), cb.id()))
            .collect();
        Ok(())
    }
}
