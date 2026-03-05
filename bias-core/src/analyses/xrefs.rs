use std::borrow::Borrow;
use std::ops::Range;

use ahash::{AHashMap, AHashSet};
use fugue::ir::Address;

use crate::analyses::folded_xrefs::FoldedXRefDB;
use crate::ir::insn::VisitXRefs;
use crate::kb::block::CodeBlockId;
use crate::kb::id::Identifiable;
use crate::kb::uuid;
use crate::kb::xref::XRef;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct XRefDB {
    folded: bool,

    pub(crate) xrefs: Vec<(CodeBlockId, XRef)>,
    pub(crate) xrefs_ranges: Vec<Range<usize>>,

    pub(crate) addr_to_xrefs: AHashMap<Address, AHashSet<usize>>,
    pub(crate) code_to_xrefs: AHashMap<CodeBlockId, usize>,
}

struct XRefDBVisitor<'a> {
    id: CodeBlockId,
    db: &'a mut XRefDB,
}

impl<'a> VisitXRefs for XRefDBVisitor<'a> {
    fn visit_xref(&mut self, xref: XRef) {
        let target = xref.target();

        let xid = self.db.xrefs.len();
        self.db.xrefs.push((self.id, xref));
        self.db.addr_to_xrefs.entry(target).or_default().insert(xid);
    }
}

impl XRefDB {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn folded() -> Self {
        Self {
            folded: true,
            ..Default::default()
        }
    }

    pub fn stores_to<A>(&self, addr: A) -> impl Iterator<Item = (CodeBlockId, &XRef)>
    where
        A: Borrow<Address>,
    {
        self.xrefs_to(addr)
            .filter(|(_, xref)| xref.kind().is_store())
    }

    pub fn loads_from<A>(&self, addr: A) -> impl Iterator<Item = (CodeBlockId, &XRef)>
    where
        A: Borrow<Address>,
    {
        self.xrefs_to(addr)
            .filter(|(_, xref)| xref.kind().is_load())
    }

    pub fn xrefs_to<A>(&self, addr: A) -> impl Iterator<Item = (CodeBlockId, &XRef)>
    where
        A: Borrow<Address>,
    {
        self.addr_to_xrefs
            .get(addr.borrow())
            .into_iter()
            .flatten()
            .map(|id| {
                let xr = &self.xrefs[*id];
                (xr.0, &xr.1)
            })
    }

    pub fn xrefs_from(&self, blk: CodeBlockId) -> impl Iterator<Item = &XRef> {
        self.code_to_xrefs
            .get(&blk)
            .into_iter()
            .flat_map(|id| {
                let rng = &self.xrefs_ranges[*id];
                &self.xrefs[rng.start..rng.end]
            })
            .map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (CodeBlockId, &XRef)> {
        self.xrefs.iter().map(|(id, v)| (*id, v))
    }

    pub fn iter_by_block(
        &self,
    ) -> impl ExactSizeIterator<Item = (CodeBlockId, &[(CodeBlockId, XRef)])> {
        self.xrefs_ranges.iter().map(|rng| {
            let slice = &self.xrefs[rng.start..rng.end];
            (slice[0].0, slice)
        })
    }

    pub fn len(&self) -> usize {
        self.xrefs.len()
    }
}

pub const XREF_ANALYSIS: uuid::Uuid = uuid("BCA6A9B1-68DD-4D7E-814B-A325D6CFCC2B");

impl AnalysisInfo for XRefDB {
    const NAME: &'static str = "X-Ref. Analyser";
    const UUID: uuid::Uuid = XREF_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for XRefDB {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if self.folded {
            let mut folded = FoldedXRefDB::default();
            folded.analyse(project)?;
            *self = folded.into();
        } else {
            for block in project.cbtable.values() {
                let id = block.id();

                let start = self.xrefs.len();

                let mut visitor = XRefDBVisitor { id, db: self };

                for insn in block.insns() {
                    insn.visit_xrefs(project.memory(), &mut visitor);
                }

                let end = self.xrefs.len();
                if start != end {
                    let idx = self.xrefs_ranges.len();

                    self.xrefs_ranges.push(start..end);
                    self.code_to_xrefs.insert(id, idx);
                }
            }
        }

        Ok(())
    }
}
