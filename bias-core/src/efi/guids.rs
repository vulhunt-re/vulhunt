use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::BufReader;
use std::marker::PhantomData;
use std::ops::Index;
use std::path::Path;
use std::sync::Arc;

use ahash::AHashMap;
use fixedbitset::FixedBitSet;
use fst::Map;
use serde::de::{MapAccess, Visitor};
use serde::Deserialize;
use thiserror::Error;
use ustr::{Ustr, UstrMap};
use uuid::Uuid;

use crate::analyses::xrefs::{XRefDB, XREF_ANALYSIS};
use crate::efi::services::ServicesAnalyser;
use crate::ir::Address;
use crate::kb::block::CodeBlockId;
use crate::kb::uuid;
use crate::project::analysis::{
    Analysis, AnalysisInfo, AnalysisSchedule, Error as AnalysisError, Schedule,
};
use crate::Project;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Deserialisation(#[from] serde_json::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
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
        AnalysisError::Analysis(EFI_GUID_XREF_ANALYSIS, Box::new(e))
    }
}

type GuidParts = (u32, u16, u16, u8, u8, u8, u8, u8, u8, u8, u8);
pub const GUID_LEN: usize = 16usize;

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
struct GuidDBInner {
    names: Vec<Ustr>,
    uuids: AHashMap<Uuid, usize>,
    names_to_id: UstrMap<usize>,
    #[serde(with = "ser")]
    fst: Map<Vec<u8>>,
}

mod ser {
    use fst::raw::Fst;
    use fst::Map;
    use serde::de::Error;
    use serde::{Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(fst: &Map<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(fst.as_fst().as_inner()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Map<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Fst::new(serde_bytes::deserialize(deserializer)?)
            .map_err(|e| Error::custom(e.to_string()))?
            .into())
    }
}

struct GuidDBJson(Arc<GuidDBInner>);

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct GuidDB(Arc<GuidDBInner>);

impl GuidDB {
    pub fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let f = BufReader::new(File::open(path)?);
        Ok(Self(serde_json::from_reader::<_, GuidDBJson>(f)?.0))
    }

    pub fn contains(&self, bytes: &[u8]) -> bool {
        self.get(bytes).is_some()
    }

    pub fn name(&self, index: usize) -> Option<&str> {
        self.0.names.get(index).map(|v| v.as_ref())
    }

    pub fn known_name(&self, index: usize) -> Ustr {
        self.0.names.get(index).copied().unwrap()
    }

    pub fn name_for(&self, uuid: Uuid) -> Option<&str> {
        self.0.uuids.get(&uuid).copied().and_then(|i| self.name(i))
    }

    pub fn index(&self, bytes: &[u8]) -> Option<usize> {
        if bytes.len() < GUID_LEN {
            None
        } else {
            self.0.fst.get(&bytes[..GUID_LEN]).map(|v| v as usize)
        }
    }

    pub fn get(&self, bytes: &[u8]) -> Option<&str> {
        self.index(bytes).map(|idx| &*self.0.names[idx])
    }

    pub fn get_index<S>(&self, name: S) -> Option<usize>
    where
        S: Borrow<str>,
    {
        let Some(name) = Ustr::from_existing(name.borrow()) else {
            return None;
        };
        self.0.names_to_id.get(&name).copied()
    }

    pub fn len(&self) -> usize {
        self.0.names.len()
    }

    pub fn analyser(&self) -> GuidAnalyser {
        GuidAnalyser {
            db: self.clone(), // cheap due to Arc
            xrefs: Default::default(),
            addrs: Default::default(),
        }
    }
}

impl Index<&str> for GuidDB {
    type Output = usize;

    fn index(&self, index: &str) -> &Self::Output {
        self.0.names_to_id.get(&Ustr::from(index)).unwrap()
    }
}

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct GuidSignature {
    referenced: FixedBitSet,
}

impl Display for GuidSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.referenced)
    }
}

impl GuidSignature {
    pub fn new(guids: &GuidDB) -> Self {
        Self {
            referenced: FixedBitSet::with_capacity(guids.len()),
        }
    }

    pub fn update(&mut self, guids: &GuidAnalyser, _services: &ServicesAnalyser) {
        self.referenced.extend(guids.xrefs.keys().copied());
    }

    pub fn combine(&mut self, other: &GuidSignature) {
        self.referenced.union_with(&other.referenced);
    }

    pub fn distance(&self, other: &Self) -> f64 {
        // jaccard similarity
        let intersection = self.referenced.intersection(&other.referenced).count();
        let denominator =
            (self.referenced.count_ones(..) + other.referenced.count_ones(..)) - intersection;

        1f64 - (intersection as f64 / denominator as f64)
    }

    pub fn features(&self) -> &FixedBitSet {
        &self.referenced
    }
}

impl From<FixedBitSet> for GuidSignature {
    fn from(referenced: FixedBitSet) -> Self {
        Self {
            referenced,
            ..Default::default()
        }
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GuidAnalyser {
    db: GuidDB,
    addrs: BTreeMap<Address, Ustr>,
    xrefs: AHashMap<usize, Vec<CodeBlockId>>,
}

pub const EFI_GUID_XREF_ANALYSIS: uuid::Uuid = uuid("F774F779-05F5-46F7-9BFB-3616EA1F896A");

impl GuidAnalyser {
    #[inline]
    pub fn guid_db(&self) -> &GuidDB {
        &self.db
    }

    #[inline]
    pub fn xrefs(&self, index: usize) -> Option<&[CodeBlockId]> {
        self.xrefs.get(&index).map(|v| v.as_ref())
    }

    #[inline]
    pub fn xrefs_iter(&self, guid: impl Borrow<str>) -> impl Iterator<Item = &CodeBlockId> {
        self.db
            .get_index(guid)
            .and_then(|id| self.xrefs(id))
            .into_iter()
            .flatten()
    }

    #[inline]
    pub fn referenced(&self, guid: impl Borrow<str>) -> bool {
        self.db
            .get_index(guid)
            .map(|id| matches!(self.xrefs(id), Some(xs) if !xs.is_empty()))
            .unwrap_or(false)
    }

    #[inline]
    pub fn guid_names<'a>(&'a self) -> impl ExactSizeIterator<Item = Ustr> + 'a {
        self.xrefs.keys().map(|index| self.db.known_name(*index))
    }

    #[inline]
    pub fn guids<'a>(&'a self) -> impl ExactSizeIterator<Item = (Address, Ustr)> + 'a {
        self.addrs.iter().map(|(&k, &v)| (k, v))
    }

    #[inline]
    pub fn guid_at(&self, addr: impl AsRef<Address>) -> Option<Ustr> {
        self.addrs.get(addr.as_ref()).copied()
    }
}

impl AnalysisInfo for GuidAnalyser {
    const NAME: &'static str = "EFI GUID X-Ref. Analyser";
    const UUID: Uuid = EFI_GUID_XREF_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[AnalysisSchedule::After(XREF_ANALYSIS)];
}

impl Analysis for GuidAnalyser {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[Schedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let xrefs = project.analyses().get::<XRefDB>(XREF_ANALYSIS).unwrap();

        tracing::trace!("analysing GUID xrefs");

        for (id, xref) in xrefs.iter().filter(|(_, xref)| xref.kind().is_load()) {
            let target = xref.target();
            if let Some(bytes) = project
                .memory()
                .find_region(&target)
                .and_then(|r| r.view_bytes(&target, GUID_LEN).ok())
            {
                if let Some(idx) = self.db.index(bytes) {
                    tracing::trace!(
                        "found xref at {} from {} / {}",
                        target,
                        xref.source(),
                        self.db.name(idx).unwrap()
                    );
                    self.xrefs.entry(idx).or_default().push(id);
                    self.addrs.insert(target, self.db.known_name(idx));
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct GuidDBVisitor<'de>(PhantomData<&'de ()>);

impl<'de> Visitor<'de> for GuidDBVisitor<'de> {
    type Value = GuidDBJson;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("unexpected GUID format")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut names = Vec::with_capacity(access.size_hint().unwrap_or(0));
        let mut guids = Vec::with_capacity(names.capacity());

        while let Some((key, value)) = access.next_entry::<String, GuidParts>()? {
            let uuid = Uuid::from_fields(
                value.0,
                value.1,
                value.2,
                &[
                    value.3, value.4, value.5, value.6, value.7, value.8, value.9, value.10,
                ],
            );

            guids.push((uuid, names.len() as u64));
            names.push(Ustr::from(&*key));
        }

        guids.sort_by_key(|&(uuid, _)| uuid.to_bytes_le());

        Ok(GuidDBJson(Arc::new(GuidDBInner {
            names_to_id: names
                .iter()
                .enumerate()
                .map(|(i, n)| (n.clone(), i))
                .collect(),
            names,
            fst: Map::from_iter(guids.iter().map(|(uuid, id)| (uuid.to_bytes_le(), *id))).unwrap(),
            uuids: guids.into_iter().map(|(k, v)| (k, v as usize)).collect(),
        })))
    }
}

impl<'de> Deserialize<'de> for GuidDBJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(GuidDBVisitor::default())
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs::File;
    use std::io::BufReader;

    use super::*;

    #[test]
    fn test_guids_load() -> Result<(), Box<dyn std::error::Error>> {
        let data = env::var("BIAS_DATA")?;
        let guids = Path::new(&data).join("platforms/uefi/auxiliary/guids.json");
        let f = BufReader::new(File::open(guids)?);
        let _guids = serde_json::from_reader::<_, GuidDBJson>(f)?;

        Ok(())
    }
}
