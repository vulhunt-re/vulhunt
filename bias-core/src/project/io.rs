use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::marker::PhantomData;
use std::ops::Range;

use semver::BuildMetadata;
use serde::de::{self, *};
use serde::ser::*;
use slab::Slab;
use smallvec::SmallVec;
use thiserror::Error;

use crate::arch::ErasedArch;
use crate::kb::table::*;
use crate::kb::*;
use crate::prelude::*;
use crate::project::analysis::{AnalysisState, AnalysisStateInfo};

#[derive(Debug, Error)]
pub enum ProjectIOError {
    #[error("compress: {0}")]
    Compress(std::io::Error),
    #[error("decompress: {0}")]
    Decompress(std::io::Error),
    #[error("deserialise: {0}")]
    Deserialise(postcard::Error),
    #[error("serialise: {0}")]
    Serialise(postcard::Error),
    #[error("inconsistent serialised data: {0}")]
    InconsistentData(&'static str),
    #[error("invalid version tag: {0}")]
    InvalidVersionTag(semver::Error),
}

struct VecMapVisitor<K, V> {
    _marker: PhantomData<(K, V)>,
}

impl<K, V> VecMapVisitor<K, V> {
    fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<'de, K, V> Visitor<'de> for VecMapVisitor<K, V>
where
    K: Deserialize<'de>,
    V: Deserialize<'de>,
{
    type Value = Vec<(K, V)>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Map<K, V>")
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<Vec<(K, V)>, E> {
        Ok(Vec::new())
    }

    #[inline]
    fn visit_seq<T>(self, mut access: T) -> Result<Vec<(K, V)>, T::Error>
    where
        T: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_element::<(K, V)>()? {
            values.push((key, value));
        }

        Ok(values)
    }

    #[inline]
    fn visit_map<T>(self, mut access: T) -> Result<Vec<(K, V)>, T::Error>
    where
        T: MapAccess<'de>,
    {
        let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            values.push((key, value));
        }

        Ok(values)
    }
}

struct VecMapWrapper<K, V>(Vec<(K, V)>);

impl<'de, K, V> Deserialize<'de> for VecMapWrapper<K, V>
where
    K: Deserialize<'de>,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VecMapVisitor::new()).map(Self)
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[repr(transparent)]
pub struct UstrId(usize);

impl From<usize> for UstrId {
    fn from(value: usize) -> Self {
        Self(value as _)
    }
}

impl From<UstrId> for usize {
    fn from(value: UstrId) -> Self {
        value.0
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[repr(transparent)]
pub struct StmtId(usize);

impl From<usize> for StmtId {
    fn from(value: usize) -> Self {
        Self(value as _)
    }
}

impl From<StmtId> for usize {
    fn from(value: StmtId) -> Self {
        value.0
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[repr(transparent)]
pub struct InsnId(usize);

impl From<usize> for InsnId {
    fn from(value: usize) -> Self {
        Self(value as _)
    }
}

impl From<InsnId> for usize {
    fn from(value: InsnId) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum InsnOperandData {
    Address(Address, Option<Range<u32>>),
    Group(Vec<InsnOperandData>),
    Register(UstrId, Option<Range<u32>>),
    Value(i64, Option<Range<u32>>),
}

impl InsnOperandData {
    pub fn from_with(opnd: &InsnOperand, ir: &mut IRData) -> Self {
        match opnd {
            InsnOperand::Address(addr, range) => Self::Address(*addr, range.clone()),
            InsnOperand::Group(group) => {
                Self::Group(group.iter().map(|e| Self::from_with(e, ir)).collect())
            }
            InsnOperand::Register(reg, range) => {
                Self::Register(ir.insert_ustr(*reg), range.clone())
            }
            InsnOperand::Value(val, range) => Self::Value(*val, range.clone()),
        }
    }

    pub fn into_with(&self, ir: &IRData) -> InsnOperand {
        match self {
            Self::Address(addr, range) => InsnOperand::Address(*addr, range.clone()),
            Self::Group(group) => {
                InsnOperand::Group(group.iter().map(|e| e.into_with(ir)).collect())
            }
            Self::Register(reg, range) => InsnOperand::Register(ir.get_ustr(*reg), range.clone()),
            Self::Value(val, range) => InsnOperand::Value(*val, range.clone()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum InsnTokenData {
    Address(Address),
    Register(UstrId),
    Symbol(UstrId),
    Value(i64),
}

impl InsnTokenData {
    pub fn from_with(tok: &InsnToken, ir: &mut IRData) -> Self {
        match tok {
            InsnToken::Address(addr) => Self::Address(*addr),
            InsnToken::Register(reg) => Self::Register(ir.insert_ustr(*reg)),
            InsnToken::Symbol(sym) => Self::Symbol(ir.insert_ustr(*sym)),
            InsnToken::Value(val) => Self::Value(*val),
        }
    }

    pub fn into_with(&self, ir: &IRData) -> InsnToken {
        match self {
            Self::Address(addr) => InsnToken::Address(*addr),
            Self::Register(reg) => InsnToken::Register(ir.get_ustr(*reg)),
            Self::Symbol(sym) => InsnToken::Symbol(ir.get_ustr(*sym)),
            Self::Value(val) => InsnToken::Value(*val),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct InsnData {
    pub address: Address,
    pub operations: SmallVec<[StmtId; 6]>,
    pub delay_slots: u8,
    pub length: u8,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct InsnInfoData {
    pub id: InsnInfoId,
    pub insn_id: InsnId,
    pub properties: FlowInfo,
    pub targets: SmallVec<[(usize, InsnTarget); 2]>,
}

impl Identifiable for InsnInfoData {
    type Key = InsnInfoId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }

    fn update_id(&mut self, id: Self::Key) {
        self.id = id;
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct CodeBlockData {
    pub id: CodeBlockId,
    pub fid: FunctionId,

    pub node: NodeIndex,
    pub phis: Vec<Phi>,
    pub insns: SmallVec<[InsnId; 1]>,

    pub size: usize,
}

impl Identifiable for CodeBlockData {
    type Key = CodeBlockId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }

    fn update_id(&mut self, id: Self::Key) {
        self.id = id;
    }
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
pub struct IRData {
    ustrs: IndexSet<Ustr>,
    stmts: IndexSet<Term<Stmt>>,
    insns: IndexSet<InsnData>,
}

pub struct IRDataCache<'a> {
    ir: &'a IRData,
    insns: AHashMap<InsnId, Term<Insn>>,
}

impl<'a> IRDataCache<'a> {
    pub fn new(ir: &'a IRData) -> Self {
        Self {
            ir,
            insns: AHashMap::with_capacity(ir.insns.len()),
        }
    }

    #[inline]
    pub fn get_ustr(&self, id: UstrId) -> Ustr {
        self.ir.get_ustr(id)
    }

    #[inline]
    pub fn get_stmt(&self, id: StmtId) -> Term<Stmt> {
        self.ir.get_stmt(id)
    }

    #[inline]
    pub fn get_insn(&mut self, id: InsnId) -> Term<Insn> {
        match self.insns.entry(id) {
            Entry::Vacant(v) => {
                let insn = self.ir.get_insn(id);
                v.insert(insn.clone());
                insn
            }
            Entry::Occupied(v) => v.get().clone(),
        }
    }
}

impl IRData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(insns: usize) -> Self {
        Self {
            insns: IndexSet::with_capacity(insns),
            ..Default::default()
        }
    }

    #[inline]
    pub fn insert_ustr(&mut self, ustr: Ustr) -> UstrId {
        self.ustrs.insert_full(ustr).0.into()
    }

    #[inline]
    pub fn get_ustr(&self, id: UstrId) -> Ustr {
        self.ustrs
            .get_index(id.into())
            .copied()
            .expect("UstrId should always be valid")
    }

    #[inline]
    pub fn insert_stmt(&mut self, stmt: &Term<Stmt>) -> StmtId {
        self.stmts.insert_full(stmt.to_owned()).0.into()
    }

    #[inline]
    pub fn get_stmt(&self, id: StmtId) -> Term<Stmt> {
        self.stmts
            .get_index(id.into())
            .cloned()
            .expect("StmtId should always be valid")
    }

    #[inline]
    pub fn insert_insn(&mut self, insn: &Term<Insn>) -> InsnId {
        let insn = InsnData {
            address: insn.address,
            operations: insn
                .operations
                .iter()
                .map(|stmt| self.insert_stmt(stmt))
                .collect(),
            delay_slots: insn.delay_slots,
            length: insn.length,
        };
        self.insns.insert_full(insn).0.into()
    }

    #[inline]
    pub fn get_insn(&self, id: InsnId) -> Term<Insn> {
        let insn = self
            .insns
            .get_index(id.into())
            .expect("InsnId should always be valid");
        Insn {
            address: insn.address,
            operations: insn
                .operations
                .iter()
                .map(|&stmt| self.get_stmt(stmt))
                .collect(),
            delay_slots: insn.delay_slots,
            length: insn.length,
        }
        .into()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
struct UuidWithName(Uuid, Option<Ustr>);

impl From<Uuid> for UuidWithName {
    fn from(value: Uuid) -> Self {
        UuidWithName(value, None)
    }
}

impl UuidWithName {
    pub fn new(uuid: Uuid, name: impl Into<Ustr>) -> Self {
        Self(uuid, Some(name.into()))
    }

    pub fn try_new(uuid: Uuid, name: impl AsRef<str>) -> Option<Self> {
        let name = Ustr::from_existing(name.as_ref())?;
        Some(Self(uuid, Some(name)))
    }
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
pub struct AnalysisStore {
    analyses: AHashMap<UuidWithName, AnalysisData>,
    analysis_data: AHashMap<UuidWithName, AnalysisStateData>,
    session: u64,
    order: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AnalysisData {
    bytes: Vec<u8>,
    order: u64,
    session: u64,
    provided: bool,
    version: AnalysisVersion,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AnalysisStateData {
    bytes: Vec<u8>,
    version: AnalysisVersion,
}

impl AnalysisStore {
    pub fn new(project: &Project) -> Self {
        let manager = project.analyses();
        Self {
            session: manager.session(),
            order: manager.order(),
            ..Default::default()
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.order = self.order.max(other.order);
        self.session = self.session.max(other.session);

        for (k, v) in other.analyses {
            self.analyses.insert(k, v);
        }

        for (k, v) in other.analysis_data {
            self.analysis_data.insert(k, v);
        }
    }

    pub fn reconfigure_analysis_schedule(&self, manager: &mut AnalysisManager) {
        manager.reconfigure_schedule(self.order, self.session);
    }

    pub fn put_analysis_schedule(&mut self, project: &Project) {
        let manager = project.analyses();

        self.order = self.order.max(manager.order());
        self.session = self.order.max(manager.session());
    }

    pub fn put<A>(&mut self, project: &Project)
    where
        A: Analysis + AnalysisInfo + serde::Serialize,
    {
        self.put_via::<A>(project, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_named<A>(&mut self, name: impl Into<String>, project: &Project)
    where
        A: Analysis + AnalysisInfo + serde::Serialize,
    {
        self.put_named_via::<A>(name, project, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_with_tag<A>(
        &mut self,
        project: &Project,
        tag: impl AsRef<str>,
    ) -> Result<(), ProjectIOError>
    where
        A: Analysis + AnalysisInfo + serde::Serialize,
    {
        self.put_with_tag_via::<A>(project, tag, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_named_with_tag<A>(
        &mut self,
        name: impl Into<String>,
        project: &Project,
        tag: impl AsRef<str>,
    ) -> Result<(), ProjectIOError>
    where
        A: Analysis + AnalysisInfo + serde::Serialize,
    {
        self.put_named_with_tag_via::<A>(name, project, tag, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_with_version<A>(&mut self, project: &Project, version: AnalysisVersion)
    where
        A: Analysis + AnalysisInfo + serde::Serialize,
    {
        self.put_with_version_via::<A>(project, version, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_named_with_version<A>(
        &mut self,
        name: impl Into<String>,
        project: &Project,
        version: AnalysisVersion,
    ) where
        A: Analysis + AnalysisInfo + serde::Serialize,
    {
        self.put_named_with_version_via::<A>(name, project, version, |t| {
            postcard::to_stdvec(t).unwrap()
        })
    }

    pub fn put_state<'a, A>(&mut self, context: &AnalysisContext<'a>)
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + serde::Serialize,
    {
        self.put_state_via::<A>(context, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_named_state<'a, A>(&mut self, name: impl Into<String>, context: &AnalysisContext<'a>)
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + serde::Serialize,
    {
        self.put_named_state_via::<A>(name, context, |t| postcard::to_stdvec(t).unwrap())
    }

    pub fn put_via<A>(&mut self, project: &Project, via: impl FnOnce(&A) -> Vec<u8>)
    where
        A: Analysis + AnalysisInfo,
    {
        self.put_with_version_via::<A>(project, A::VERSION, via)
    }

    pub fn put_named_via<A>(
        &mut self,
        name: impl Into<String>,
        project: &Project,
        via: impl FnOnce(&A) -> Vec<u8>,
    ) where
        A: Analysis + AnalysisInfo,
    {
        self.put_named_with_version_via::<A>(name, project, A::VERSION, via)
    }

    pub fn put_with_tag_via<A>(
        &mut self,
        project: &Project,
        tag: impl AsRef<str>,
        via: impl Fn(&A) -> Vec<u8>,
    ) -> Result<(), ProjectIOError>
    where
        A: Analysis + AnalysisInfo,
    {
        let version = AnalysisVersion {
            build: BuildMetadata::new(tag.as_ref()).map_err(ProjectIOError::InvalidVersionTag)?,
            ..A::VERSION
        };
        self.put_with_version_via::<A>(project, version, via);
        Ok(())
    }

    pub fn put_named_with_tag_via<A>(
        &mut self,
        name: impl Into<String>,
        project: &Project,
        tag: impl AsRef<str>,
        via: impl Fn(&A) -> Vec<u8>,
    ) -> Result<(), ProjectIOError>
    where
        A: Analysis + AnalysisInfo,
    {
        let version = AnalysisVersion {
            build: BuildMetadata::new(tag.as_ref()).map_err(ProjectIOError::InvalidVersionTag)?,
            ..A::VERSION
        };
        self.put_named_with_version_via::<A>(name, project, version, via);
        Ok(())
    }

    pub fn put_with_version_via<A>(
        &mut self,
        project: &Project,
        version: AnalysisVersion,
        via: impl FnOnce(&A) -> Vec<u8>,
    ) where
        A: Analysis + AnalysisInfo,
    {
        let m = project.analyses();
        let Some(t) = m.get_ref::<A>() else { return };

        self.order = self.order.max(m.order());
        self.session = self.session.max(m.session());

        self.analyses.insert(
            UuidWithName::from(A::UUID),
            AnalysisData {
                bytes: via(t.analysis()),
                order: t.order(),
                session: t.session(),
                provided: t.provided(),
                version,
            },
        );
    }

    pub fn put_named_with_version_via<A>(
        &mut self,
        name: impl Into<String>,
        project: &Project,
        version: AnalysisVersion,
        via: impl FnOnce(&A) -> Vec<u8>,
    ) where
        A: Analysis + AnalysisInfo,
    {
        let m = project.analyses();
        let Some(t) = m.get_ref::<A>() else { return };

        self.order = self.order.max(m.order());
        self.session = self.session.max(m.session());

        self.analyses.insert(
            UuidWithName::new(A::UUID, name.into()),
            AnalysisData {
                bytes: via(t.analysis()),
                order: t.order(),
                session: t.session(),
                provided: t.provided(),
                version,
            },
        );
    }

    pub fn put_state_via<'a, A>(
        &mut self,
        context: &AnalysisContext<'a>,
        via: impl FnOnce(&A) -> Vec<u8>,
    ) where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        let Some(t) = context.get_by::<A>() else {
            return;
        };

        self.analysis_data.insert(
            UuidWithName::from(A::UUID),
            AnalysisStateData {
                bytes: via(t),
                version: A::VERSION,
            },
        );
    }

    pub fn put_named_state_via<'a, A>(
        &mut self,
        name: impl Into<String>,
        context: &AnalysisContext<'a>,
        via: impl FnOnce(&A) -> Vec<u8>,
    ) where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        let Some(t) = context.get_by::<A>() else {
            return;
        };

        self.analysis_data.insert(
            UuidWithName::new(A::UUID, name.into()),
            AnalysisStateData {
                bytes: via(t),
                version: A::VERSION,
            },
        );
    }

    pub fn get<A>(&self) -> Option<A>
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.get_via::<A>(|t| postcard::from_bytes(t).ok())
    }

    pub fn get_named<A>(&self, name: impl AsRef<str>) -> Option<A>
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.get_named_via::<A>(name, |t| postcard::from_bytes(t).ok())
    }

    pub fn get_state<'a, A>(&self) -> Option<A>
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.get_state_via::<A>(|t| postcard::from_bytes(t).ok())
    }

    pub fn get_named_state<'a, A>(&self, name: impl AsRef<str>) -> Option<A>
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.get_named_state_via::<A>(name, |t| postcard::from_bytes(t).ok())
    }

    pub fn get_full<A>(&self) -> Option<(&AnalysisVersion, A)>
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.get_full_via::<A>(|t| postcard::from_bytes(t).ok())
    }

    pub fn get_named_full<A>(&self, name: impl AsRef<str>) -> Option<(&AnalysisVersion, A)>
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.get_named_full_via::<A>(name, |t| postcard::from_bytes(t).ok())
    }

    pub fn get_via<A>(&self, via: impl FnOnce(&[u8]) -> Option<A>) -> Option<A>
    where
        A: Analysis + AnalysisInfo,
    {
        self.analyses
            .get(&UuidWithName::from(A::UUID))
            .and_then(|data| via(&data.bytes))
    }

    pub fn get_named_via<A>(
        &self,
        name: impl AsRef<str>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> Option<A>
    where
        A: Analysis + AnalysisInfo,
    {
        let key = UuidWithName::try_new(A::UUID, name)?;
        self.analyses.get(&key).and_then(|data| via(&data.bytes))
    }

    pub fn get_state_via<'a, A>(&self, via: impl FnOnce(&[u8]) -> Option<A>) -> Option<A>
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        self.analysis_data
            .get(&UuidWithName::from(A::UUID))
            .and_then(|data| via(&data.bytes))
    }

    pub fn get_named_state_via<'a, A>(
        &self,
        name: impl AsRef<str>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> Option<A>
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        let key = UuidWithName::try_new(A::UUID, name)?;
        self.analysis_data
            .get(&key)
            .and_then(|data| via(&data.bytes))
    }

    pub fn get_full_via<A>(
        &self,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> Option<(&AnalysisVersion, A)>
    where
        A: Analysis + AnalysisInfo,
    {
        self.analyses
            .get(&UuidWithName::from(A::UUID))
            .and_then(|data| via(&data.bytes).map(|v| (&data.version, v)))
    }

    pub fn get_named_full_via<A>(
        &self,
        name: impl AsRef<str>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> Option<(&AnalysisVersion, A)>
    where
        A: Analysis + AnalysisInfo,
    {
        let key = UuidWithName::try_new(A::UUID, name)?;
        self.analyses
            .get(&key)
            .and_then(|data| via(&data.bytes).map(|v| (&data.version, v)))
    }

    pub fn version<A>(&self) -> Option<&AnalysisVersion>
    where
        A: Analysis + AnalysisInfo,
    {
        self.analyses
            .get(&UuidWithName::from(A::UUID))
            .map(|data| &data.version)
    }

    pub fn named_version<A>(&self, name: &str) -> Option<&AnalysisVersion>
    where
        A: Analysis + AnalysisInfo,
    {
        let key = UuidWithName::try_new(A::UUID, name)?;
        self.analyses.get(&key).map(|data| &data.version)
    }

    pub fn state_version<'a, A>(&self) -> Option<&AnalysisVersion>
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        self.analysis_data
            .get(&UuidWithName::from(A::UUID))
            .map(|data| &data.version)
    }

    pub fn named_state_version<'a, A>(&self, name: impl AsRef<str>) -> Option<&AnalysisVersion>
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        let key = UuidWithName::try_new(A::UUID, name)?;
        self.analysis_data.get(&key).map(|data| &data.version)
    }

    pub fn restore_state<'a, A>(&mut self, context: &mut AnalysisContext<'a>) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_state_via::<A>(context, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_named_state<'a, A>(
        &mut self,
        name: impl AsRef<str>,
        context: &mut AnalysisContext<'a>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_named_state_via::<A>(name, context, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_state_unchecked<'a, A>(&mut self, context: &mut AnalysisContext<'a>) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_state_unchecked_via::<A>(context, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_named_state_unchecked<'a, A>(
        &mut self,
        name: impl AsRef<str>,
        context: &mut AnalysisContext<'a>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_named_state_unchecked_via::<A>(name, context, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_state_with<'a, A>(
        &mut self,
        context: &mut AnalysisContext<'a>,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_state_with_via::<A>(context, version_check, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_named_state_with<'a, A>(
        &mut self,
        name: impl AsRef<str>,
        context: &mut AnalysisContext<'a>,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_named_state_with_via::<A>(name, context, version_check, |t| {
            postcard::from_bytes(t).ok()
        })
    }

    pub fn restore_state_via<'a, A>(
        &mut self,
        context: &mut AnalysisContext<'a>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_state_with_via::<A>(
            context,
            |expected, actual| expected.major == actual.major,
            via,
        )
    }

    pub fn restore_named_state_via<'a, A>(
        &mut self,
        name: impl AsRef<str>,
        context: &mut AnalysisContext<'a>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_named_state_with_via::<A>(
            name,
            context,
            |expected, actual| expected.major == actual.major,
            via,
        )
    }

    pub fn restore_state_unchecked_via<'a, A>(
        &mut self,
        context: &mut AnalysisContext<'a>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_state_with_via::<A>(context, |_, _| true, via)
    }

    pub fn restore_named_state_unchecked_via<'a, A>(
        &mut self,
        name: impl AsRef<str>,
        context: &mut AnalysisContext<'a>,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.restore_named_state_with_via::<A>(name, context, |_, _| true, via)
    }

    pub fn restore_state_with_via<'a, A>(
        &mut self,
        context: &mut AnalysisContext<'a>,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        let Some(t) = self.analysis_data.get(&UuidWithName::from(A::UUID)) else {
            return false;
        };
        let Some(state) = via(&t.bytes) else {
            return false;
        };

        if version_check(&A::VERSION, &t.version) {
            context.set_by(state);
            true
        } else {
            false
        }
    }

    pub fn restore_named_state_with_via<'a, A>(
        &mut self,
        name: impl AsRef<str>,
        context: &mut AnalysisContext<'a>,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a>,
    {
        let Some(key) = UuidWithName::try_new(A::UUID, name) else {
            return false;
        };
        let Some(t) = self.analysis_data.get(&key) else {
            return false;
        };
        let Some(state) = via(&t.bytes) else {
            return false;
        };

        if version_check(&A::VERSION, &t.version) {
            context.set_by(state);
            true
        } else {
            false
        }
    }

    /// Restores the `Analysis` if the major version matches the one this binary
    /// was compiled with.
    ///
    pub fn restore<A>(&self, manager: &mut AnalysisManager) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.restore_via::<A>(manager, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_named<A>(&self, name: impl AsRef<str>, manager: &mut AnalysisManager) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.restore_named_via::<A>(name, manager, |t| postcard::from_bytes(t).ok())
    }

    /// Restores the `Analysis` irrespective of the version.
    ///
    pub fn restore_unchecked<A>(&self, manager: &mut AnalysisManager) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.restore_unchecked_via::<A>(manager, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_named_unchecked<A>(
        &self,
        name: impl AsRef<str>,
        manager: &mut AnalysisManager,
    ) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.restore_named_unchecked_via::<A>(name, manager, |t| postcard::from_bytes(t).ok())
    }

    /// Restores the `Analysis` if `version_check` yields true; where `version_check`
    /// receives:
    /// - The expected version
    /// - The actual version
    ///
    pub fn restore_with<A>(
        &self,
        manager: &mut AnalysisManager,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
    ) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.restore_with_via::<A>(manager, version_check, |t| postcard::from_bytes(t).ok())
    }

    pub fn restore_named_with<A>(
        &self,
        name: impl AsRef<str>,
        manager: &mut AnalysisManager,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
    ) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.restore_named_with_via::<A>(name, manager, version_check, |t| {
            postcard::from_bytes(t).ok()
        })
    }

    /// Restores the `Analysis` if the major version matches the one this binary
    /// was compiled with.
    ///
    pub fn restore_via<A>(
        &self,
        manager: &mut AnalysisManager,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: Analysis + AnalysisInfo,
    {
        self.restore_with_via::<A>(
            manager,
            |expected, actual| expected.major == actual.major,
            via,
        )
    }

    pub fn restore_named_via<A>(
        &self,
        name: impl AsRef<str>,
        manager: &mut AnalysisManager,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: Analysis + AnalysisInfo,
    {
        self.restore_named_with_via::<A>(
            name,
            manager,
            |expected, actual| expected.major == actual.major,
            via,
        )
    }

    /// Restores the `Analysis` irrespective of the version.
    ///
    pub fn restore_unchecked_via<A>(
        &self,
        manager: &mut AnalysisManager,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: Analysis + AnalysisInfo,
    {
        self.restore_with_via::<A>(manager, |_, _| true, via)
    }

    pub fn restore_named_unchecked_via<A>(
        &self,
        name: impl AsRef<str>,
        manager: &mut AnalysisManager,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: Analysis + AnalysisInfo,
    {
        self.restore_named_with_via::<A>(name, manager, |_, _| true, via)
    }

    /// Restores the `Analysis` if `version_check` yields true; where `version_check`
    /// receives:
    /// - The expected version
    /// - The actual version
    ///
    pub fn restore_with_via<A>(
        &self,
        manager: &mut AnalysisManager,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: Analysis + AnalysisInfo,
    {
        let Some(t) = self.analyses.get(&UuidWithName::from(A::UUID)) else {
            tracing::trace!(
                "could not restore analysis {}--not found in analysis store",
                A::UUID
            );
            return false;
        };

        let analysis = match via(&t.bytes) {
            Some(analysis) => analysis,
            None => {
                tracing::trace!(
                    "could not restore analysis {}--deserialisation failed",
                    A::UUID,
                );
                return false;
            }
        };

        if version_check(&A::VERSION, &t.version) {
            tracing::trace!("restored analysis {}", A::UUID);
            manager.insert(analysis, t.order, t.session, t.provided);
            true
        } else {
            tracing::trace!(
                "could not restore analysis {}--incompatible analysis version",
                A::UUID
            );
            false
        }
    }

    pub fn restore_named_with_via<A>(
        &self,
        name: impl AsRef<str>,
        manager: &mut AnalysisManager,
        version_check: impl Fn(&AnalysisVersion, &AnalysisVersion) -> bool,
        via: impl FnOnce(&[u8]) -> Option<A>,
    ) -> bool
    where
        A: Analysis + AnalysisInfo,
    {
        let name = name.as_ref();
        let Some(key) = UuidWithName::try_new(A::UUID, name) else {
            tracing::trace!(
                "could not restore named analysis `{name}`: {}--not found in analysis store",
                A::UUID
            );
            return false;
        };

        let Some(t) = self.analyses.get(&key) else {
            tracing::trace!(
                "could not restore named analysis `{name}`: {}--not found in analysis store",
                A::UUID
            );
            return false;
        };

        let analysis = match via(&t.bytes) {
            Some(analysis) => analysis,
            None => {
                tracing::trace!(
                    "could not named restore analysis `{name}`: {}--deserialisation failed",
                    A::UUID,
                );
                return false;
            }
        };

        if version_check(&A::VERSION, &t.version) {
            tracing::trace!("restored analysis {}", A::UUID);
            manager.insert(analysis, t.order, t.session, t.provided);
            true
        } else {
            tracing::trace!(
                "could not restore analysis `{name}`: {}--incompatible analysis version",
                A::UUID
            );
            false
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct LifterData<'a> {
    arch: ArchitectureDef,
    arch_info: Box<dyn ErasedArch>,
    convention: String,
    spaces: Cow<'a, SpaceManager>,
}

impl<'a> LifterData<'a> {
    pub fn new(value: &'a Lifter) -> Self {
        Self {
            arch: value.translator().architecture().to_owned(),
            arch_info: value.arch().clone(),
            convention: value.convention().name().to_string(),
            spaces: Cow::Borrowed(value.translator().manager()),
        }
    }

    pub fn merge(self, mut lifter: Lifter) -> Result<Lifter, ProjectIOError> {
        let arch = lifter.translator().architecture();

        if arch.processor() != self.arch.processor()
            || arch.endian() != self.arch.endian()
            || arch.bits() != self.arch.bits()
            || arch.variant() != self.arch.variant()
        {
            return Err(ProjectIOError::InconsistentData(
                "lifter architecture is not compatible with the serialised lifter architecture",
            ));
        }

        if lifter.convention().name() != self.convention {
            return Err(ProjectIOError::InconsistentData(
                "lifter convention is not compatible with the serialised lifter convention",
            ));
        }

        for (s1, s2) in self
            .spaces
            .spaces()
            .iter()
            .zip(lifter.translator().manager().spaces().iter())
        {
            if s1 != s2 {
                return Err(ProjectIOError::InconsistentData(
                    "lifter address space mapping is not compatible with the serialised lifter",
                ));
            }
        }

        if self.spaces.spaces().len() > lifter.translator().manager().spaces().len() {
            lifter
                .translator_mut()
                .manager_mut()
                .clone_from(self.spaces.as_ref());
        }

        Ok(lifter)
    }
}

struct InsnTableConverter<'a, 'b> {
    cache: &'b mut IRDataCache<'a>,
}

impl<'a, 'b, 'de> DeserializeSeed<'de> for InsnTableConverter<'a, 'b> {
    type Value = InsnTermTable;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // If we deserialized IRData, then we deserialize InsnTermTable via UPointTable.
        //
        // We have two fields: points and values. Points we take as-is, values we deserialize
        // directly into a Vec of InsnTerm.

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Points,
            Values,
        }

        struct UPointTableVisitor<'a, 'b>(&'b mut IRDataCache<'a>);

        impl<'a, 'b, 'de> Visitor<'de> for UPointTableVisitor<'a, 'b> {
            type Value = UPointTable<Address, InsnTerm>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct UPointTable")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let points = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let values = seq
                    .next_element::<Vec<InsnInfoData>>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let values = values
                    .into_iter()
                    .map(|data| InsnTerm {
                        id: data.id,
                        insn: self.0.get_insn(data.insn_id),
                        properties: data.properties,
                        targets: data.targets,
                    })
                    .collect();

                Ok(UPointTable::from_parts(points, values))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut points = None;
                let mut values = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Points => {
                            if points.is_some() {
                                return Err(de::Error::duplicate_field("points"));
                            }
                            points = Some(map.next_value()?);
                        }
                        Field::Values => {
                            if values.is_some() {
                                return Err(de::Error::duplicate_field("values"));
                            }
                            values = Some(
                                map.next_value::<Vec<InsnInfoData>>()?
                                    .into_iter()
                                    .map(|data| InsnTerm {
                                        id: data.id,
                                        insn: self.0.get_insn(data.insn_id),
                                        properties: data.properties,
                                        targets: data.targets,
                                    })
                                    .collect(),
                            );
                        }
                    }
                }
                let points = points.ok_or_else(|| de::Error::missing_field("points"))?;
                let values = values.ok_or_else(|| de::Error::missing_field("values"))?;
                Ok(UPointTable::from_parts(points, values))
            }
        }

        const FIELDS: &'static [&'static str] = &["points", "values"];
        deserializer.deserialize_struct("UPointTable", FIELDS, UPointTableVisitor(self.cache))
    }
}

struct CodeBlockTableConverter<'a, 'b> {
    cache: &'b mut IRDataCache<'a>,
}

impl<'a, 'b, 'de> DeserializeSeed<'de> for CodeBlockTableConverter<'a, 'b> {
    type Value = CodeBlockTable;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // If we deserialized IRData, then we deserialize CodeBlockTable via MPointTable.
        //
        // We have two fields: points and values. Points we take as-is, values we deserialize
        // directly into a Slab of CodeBlock.

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Points,
            Values,
        }

        struct MPointTableVisitor<'a, 'b>(&'b mut IRDataCache<'a>);

        impl<'a, 'b, 'de> Visitor<'de> for MPointTableVisitor<'a, 'b> {
            type Value = MPointTable<Address, CodeBlock>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct MPointTable")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let points = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let values = seq
                    .next_element::<VecMapWrapper<usize, CodeBlockData>>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let values = values
                    .0
                    .into_iter()
                    .map(|(id, data)| {
                        (
                            id,
                            CodeBlock {
                                id: data.id,
                                fid: data.fid,
                                node: data.node,
                                phis: data.phis,
                                insns: data
                                    .insns
                                    .into_iter()
                                    .map(|id| self.0.get_insn(id))
                                    .collect(),
                                size: data.size,
                            },
                        )
                    })
                    .collect::<Slab<CodeBlock>>();

                Ok(MPointTable::from_parts(points, values))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut points = None;
                let mut values = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Points => {
                            if points.is_some() {
                                return Err(de::Error::duplicate_field("points"));
                            }
                            points = Some(map.next_value()?);
                        }
                        Field::Values => {
                            if values.is_some() {
                                return Err(de::Error::duplicate_field("values"));
                            }
                            values = Some(
                                map.next_value::<VecMapWrapper<usize, CodeBlockData>>()?
                                    .0
                                    .into_iter()
                                    .map(|(id, data)| {
                                        (
                                            id,
                                            CodeBlock {
                                                id: data.id,
                                                fid: data.fid,
                                                node: data.node,
                                                phis: data.phis,
                                                insns: data
                                                    .insns
                                                    .into_iter()
                                                    .map(|id| self.0.get_insn(id))
                                                    .collect(),
                                                size: data.size,
                                            },
                                        )
                                    })
                                    .collect::<Slab<CodeBlock>>(),
                            );
                        }
                    }
                }
                let points = points.ok_or_else(|| de::Error::missing_field("points"))?;
                let values = values.ok_or_else(|| de::Error::missing_field("values"))?;
                Ok(MPointTable::from_parts(points, values))
            }
        }

        const FIELDS: &'static [&'static str] = &["points", "values"];
        deserializer.deserialize_struct("MPointTable", FIELDS, MPointTableVisitor(self.cache))
    }
}

pub struct ProjectDataConverter<'a, L> {
    pub binary: &'a L,
    pub lifter: Lifter,
}

impl<'a, 'de, L> DeserializeSeed<'de> for ProjectDataConverter<'a, L>
where
    L: LoadedBinary,
{
    type Value = ProjectWithAnalyses;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            IR,
            Lifter,
            ITable,
            CBTable,
            FTable,
            FSTable,
            ICFG,
            Symtab,
            DataDB,
            TypeDB,
            Entry,
            ID,
            Analyses,
            Injections,
        }

        struct ProjectVisitor<'a, L>(ProjectDataConverter<'a, L>)
        where
            L: LoadedBinary;

        impl<'a, 'de, L> Visitor<'de> for ProjectVisitor<'a, L>
        where
            L: LoadedBinary,
        {
            type Value = ProjectWithAnalyses;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ProjectData")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let ir = seq
                    .next_element::<IRData>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let mut ir_cache = IRDataCache::new(&ir);

                let lifter_data = seq
                    .next_element::<LifterData>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let itable = seq
                    .next_element_seed(InsnTableConverter {
                        cache: &mut ir_cache,
                    })?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                let cbtable = seq
                    .next_element_seed(CodeBlockTableConverter {
                        cache: &mut ir_cache,
                    })?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                let ftable = seq
                    .next_element::<FunctionTable>()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;

                let fstable = seq
                    .next_element::<FunctionSummaryTable>()?
                    .ok_or_else(|| de::Error::invalid_length(5, &self))?;

                let icfg = seq
                    .next_element::<ICFG>()?
                    .ok_or_else(|| de::Error::invalid_length(6, &self))?;

                let symtab = seq
                    .next_element::<SymbolTable>()?
                    .ok_or_else(|| de::Error::invalid_length(7, &self))?;

                let datadb = seq
                    .next_element::<DataTypeDB>()?
                    .ok_or_else(|| de::Error::invalid_length(8, &self))?;

                let typedb = seq
                    .next_element::<TypeDB>()?
                    .ok_or_else(|| de::Error::invalid_length(9, &self))?;

                let entry = seq
                    .next_element::<Option<Address>>()?
                    .ok_or_else(|| de::Error::invalid_length(10, &self))?;

                let id = seq
                    .next_element::<Uuid>()?
                    .ok_or_else(|| de::Error::invalid_length(11, &self))?;

                let analyses = seq
                    .next_element::<AnalysisStore>()?
                    .ok_or_else(|| de::Error::invalid_length(12, &self))?;

                let injections = seq
                    .next_element::<InjectionManager>()?
                    .ok_or_else(|| de::Error::invalid_length(13, &self))?;

                let mut memory = Memory::new();

                self.0.binary.for_each_region(|r| {
                    let region = Region::new_with(
                        r.name.as_deref().unwrap_or("unnamed"),
                        r.bounds.start,
                        r.uninitialised.clone(),
                        r.endian,
                        r.code,
                        r.read_only,
                        &*r.bytes,
                    );

                    memory.add_region(region);
                });

                let lifter = lifter_data
                    .merge(self.0.lifter)
                    .map_err(de::Error::custom)?;

                Ok(ProjectWithAnalyses {
                    project: Project {
                        id,
                        icfg,
                        itable,
                        cbtable,
                        ftable,
                        fstable,
                        symtab,
                        entry,
                        datadb,
                        lifter,
                        memory,
                        typedb,
                        manager: AnalysisManager::from_parts(analyses.session, analyses.order),
                        injections,
                    },
                    analyses,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let Some(Field::IR) = map.next_key()? else {
                    return Err(de::Error::missing_field("ir"))?;
                };

                let ir = map.next_value::<IRData>()?;

                let mut ir_cache = IRDataCache::new(&ir);

                let mut lifter_data = None;
                let mut itable = None;
                let mut cbtable = None;
                let mut ftable = None;
                let mut fstable = None;
                let mut icfg = None;
                let mut symtab = None;
                let mut datadb = None;
                let mut typedb = None;
                let mut entry = None;
                let mut id = None;
                let mut analyses = None;
                let mut injections = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Lifter => {
                            if lifter_data.is_some() {
                                return Err(de::Error::duplicate_field("lifter"));
                            }
                            lifter_data = Some(map.next_value::<LifterData>()?);
                        }
                        Field::ITable => {
                            if itable.is_some() {
                                return Err(de::Error::duplicate_field("itable"));
                            }
                            itable = Some(map.next_value_seed(InsnTableConverter {
                                cache: &mut ir_cache,
                            })?);
                        }
                        Field::CBTable => {
                            if cbtable.is_some() {
                                return Err(de::Error::duplicate_field("cbtable"));
                            }
                            cbtable = Some(map.next_value_seed(CodeBlockTableConverter {
                                cache: &mut ir_cache,
                            })?);
                        }
                        Field::FTable => {
                            if ftable.is_some() {
                                return Err(de::Error::duplicate_field("ftable"));
                            }
                            ftable = Some(map.next_value()?);
                        }
                        Field::FSTable => {
                            if fstable.is_some() {
                                return Err(de::Error::duplicate_field("fstable"));
                            }
                            fstable = Some(map.next_value()?);
                        }
                        Field::ICFG => {
                            if icfg.is_some() {
                                return Err(de::Error::duplicate_field("icfg"));
                            }
                            icfg = Some(map.next_value()?);
                        }
                        Field::Symtab => {
                            if symtab.is_some() {
                                return Err(de::Error::duplicate_field("symtab"));
                            }
                            symtab = Some(map.next_value()?);
                        }
                        Field::DataDB => {
                            if datadb.is_some() {
                                return Err(de::Error::duplicate_field("datadb"));
                            }
                            datadb = Some(map.next_value()?);
                        }
                        Field::TypeDB => {
                            if typedb.is_some() {
                                return Err(de::Error::duplicate_field("typedb"));
                            }
                            typedb = Some(map.next_value()?);
                        }
                        Field::Entry => {
                            if entry.is_some() {
                                return Err(de::Error::duplicate_field("entry"));
                            }
                            entry = Some(map.next_value()?);
                        }
                        Field::ID => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value()?);
                        }
                        Field::Analyses => {
                            if analyses.is_some() {
                                return Err(de::Error::duplicate_field("analyses"));
                            }
                            analyses = Some(map.next_value::<AnalysisStore>()?);
                        }
                        Field::Injections => {
                            if injections.is_some() {
                                return Err(de::Error::duplicate_field("injections"));
                            }
                            injections = Some(map.next_value::<InjectionManager>()?);
                        }
                        _ => {
                            return Err(de::Error::duplicate_field("ir"));
                        }
                    }
                }

                let lifter_data =
                    lifter_data.ok_or_else(|| de::Error::missing_field("lifter_data"))?;
                let itable = itable.ok_or_else(|| de::Error::missing_field("itable"))?;
                let cbtable = cbtable.ok_or_else(|| de::Error::missing_field("cbtable"))?;
                let ftable = ftable.ok_or_else(|| de::Error::missing_field("ftable"))?;
                let fstable = fstable.ok_or_else(|| de::Error::missing_field("fstable"))?;
                let icfg = icfg.ok_or_else(|| de::Error::missing_field("icfg"))?;
                let symtab = symtab.ok_or_else(|| de::Error::missing_field("symtab"))?;
                let datadb = datadb.ok_or_else(|| de::Error::missing_field("datadb"))?;
                let typedb = typedb.ok_or_else(|| de::Error::missing_field("typedb"))?;
                let entry = entry.ok_or_else(|| de::Error::missing_field("entry"))?;
                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
                let analyses = analyses.ok_or_else(|| de::Error::missing_field("analyses"))?;
                let injections =
                    injections.ok_or_else(|| de::Error::missing_field("injections"))?;

                let mut memory = Memory::new();

                self.0.binary.for_each_region(|r| {
                    let region = Region::new_with(
                        r.name.as_deref().unwrap_or("unnamed"),
                        r.bounds.start,
                        r.uninitialised.clone(),
                        r.endian,
                        r.code,
                        r.read_only,
                        &*r.bytes,
                    );

                    memory.add_region(region);
                });

                let lifter = lifter_data
                    .merge(self.0.lifter)
                    .map_err(de::Error::custom)?;

                Ok(ProjectWithAnalyses {
                    project: Project {
                        id,
                        icfg,
                        itable,
                        cbtable,
                        ftable,
                        fstable,
                        symtab,
                        entry,
                        datadb,
                        typedb,
                        lifter,
                        memory,
                        manager: AnalysisManager::from_parts(analyses.session, analyses.order),
                        injections,
                    },
                    analyses,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "ir",
            "lifter",
            "itable",
            "cbtable",
            "ftable",
            "fstable",
            "icfg",
            "symtab",
            "datadb",
            "typedb",
            "entry",
            "id",
            "analyses",
            "injections",
        ];
        deserializer.deserialize_struct("ProjectData", FIELDS, ProjectVisitor(self))
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct ProjectData<'a> {
    ir: IRData,
    lifter: LifterData<'a>,

    itable: UPointTable<Address, InsnInfoData>,
    cbtable: MPointTable<Address, CodeBlockData>,

    ftable: Cow<'a, FunctionTable>,
    fstable: Cow<'a, FunctionSummaryTable>,

    icfg: Cow<'a, ICFG>,

    symtab: Cow<'a, SymbolTable>,

    datadb: Cow<'a, DataTypeDB>,
    typedb: Cow<'a, TypeDB>,

    entry: Option<Address>,

    id: Uuid,

    analyses: AnalysisStore,

    injections: Cow<'a, InjectionManager>,
}

impl<'a> ProjectData<'a> {
    pub fn new(project: &'a Project) -> Self {
        let mut ir = IRData::with_capacity(project.instructions().len());
        let lifter = LifterData::new(project.lifter());

        let itable = {
            let itable = project.instructions();
            let (points, values) = itable.parts();

            let points = points.to_owned();
            let values = values
                .iter()
                .map(|insn| InsnInfoData {
                    id: insn.id,
                    insn_id: ir.insert_insn(&insn.insn),
                    properties: insn.properties,
                    targets: insn.targets.clone(),
                })
                .collect();

            UPointTable::from_parts(points, values)
        };

        let cbtable = {
            let cbtable = project.code_blocks();
            let (points, values) = cbtable.parts();

            let points = points.to_owned();
            let values = values
                .iter()
                .map(|(idx, block)| {
                    (
                        idx,
                        CodeBlockData {
                            id: block.id,
                            fid: block.fid,
                            node: block.node,
                            phis: block.phis.clone(),
                            insns: block
                                .insns
                                .iter()
                                .map(|insn| ir.insert_insn(insn))
                                .collect(),
                            size: block.size,
                        },
                    )
                })
                .collect::<Slab<_>>();

            MPointTable::from_parts(points, values)
        };

        Self {
            ir,

            lifter,
            itable,
            cbtable,

            ftable: Cow::Borrowed(project.functions()),
            fstable: Cow::Borrowed(project.function_summaries()),
            symtab: Cow::Borrowed(project.symbols()),

            datadb: Cow::Borrowed(project.data_db()),
            typedb: Cow::Borrowed(project.type_db()),

            icfg: Cow::Borrowed(project.icfg()),

            entry: project.entry_point(),

            id: project.id,

            analyses: AnalysisStore::default(),

            injections: Cow::Borrowed(project.injections()),
        }
    }

    pub fn merge_analyses(&mut self, store: AnalysisStore) {
        self.analyses.merge(store);
    }

    pub fn store_analysis<A>(&mut self, project: &Project)
    where
        A: Analysis + AnalysisInfo + Serialize,
    {
        self.analyses.put::<A>(project)
    }

    pub fn store_analysis_state<'b, A>(&mut self, context: &AnalysisContext<'b>)
    where
        A: AnalysisState<'b> + AnalysisStateInfo<'b> + Serialize,
    {
        self.analyses.put_state::<A>(context)
    }

    pub fn analyses(&self) -> &AnalysisStore {
        &self.analyses
    }

    pub fn analyses_mut(&mut self) -> &mut AnalysisStore {
        &mut self.analyses
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProjectIOError> {
        let bytes = postcard::to_stdvec(self).map_err(ProjectIOError::Serialise)?;
        zstd::encode_all(Cursor::new(bytes), 0).map_err(ProjectIOError::Compress)
    }

    pub fn from_bytes<L>(
        lifter: Lifter,
        binary: &L,
        bytes: &[u8],
    ) -> Result<ProjectWithAnalyses, ProjectIOError>
    where
        L: LoadedBinary,
    {
        Self::from_reader(lifter, binary, BufReader::new(Cursor::new(bytes)))
    }

    pub fn to_writer<'w, W>(&self, writer: W) -> Result<(), ProjectIOError>
    where
        W: 'w + Write,
    {
        struct Wr<'a, W>(zstd::Encoder<'a, W>)
        where
            W: 'a + Write;

        impl<'a, W> postcard::ser_flavors::Flavor for Wr<'a, W>
        where
            W: 'a + Write,
        {
            type Output = ();

            #[inline]
            fn try_push(&mut self, data: u8) -> postcard::Result<()> {
                self.0.write_all(&[data]).map_err(postcard::Error::custom)?;
                Ok(())
            }

            #[inline]
            fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
                self.0.write_all(data).map_err(postcard::Error::custom)?;
                Ok(())
            }

            #[inline]
            fn finalize(self) -> postcard::Result<Self::Output> {
                let mut w = self.0.finish().map_err(postcard::Error::custom)?;
                w.flush().map_err(postcard::Error::custom)?;
                Ok(())
            }
        }

        let w = Wr(zstd::Encoder::new(writer, 0).map_err(ProjectIOError::Compress)?);
        postcard::serialize_with_flavor(self, w).map_err(ProjectIOError::Serialise)
    }

    pub fn from_reader<'r, L, R>(
        lifter: Lifter,
        binary: &L,
        reader: R,
    ) -> Result<ProjectWithAnalyses, ProjectIOError>
    where
        L: LoadedBinary,
        R: 'r + BufRead,
    {
        let converter = ProjectDataConverter { lifter, binary };

        let buf = zstd::decode_all(reader).map_err(ProjectIOError::Decompress)?;
        let mut de = postcard::Deserializer::from_bytes(&buf);

        converter
            .deserialize(&mut de)
            .map_err(ProjectIOError::Deserialise)
    }
}

pub struct ProjectWithAnalyses {
    project: Project,
    analyses: AnalysisStore,
}

impl ProjectWithAnalyses {
    pub fn analyses(&self) -> &AnalysisStore {
        &self.analyses
    }

    pub fn analyses_mut(&mut self) -> &mut AnalysisStore {
        &mut self.analyses
    }

    pub fn restore_analysis<A>(&mut self) -> bool
    where
        A: Analysis + AnalysisInfo + DeserializeOwned,
    {
        self.analyses.restore::<A>(&mut self.project.manager)
    }

    pub fn restore_analysis_state<'a, A>(&mut self, state: &mut AnalysisContext<'a>) -> bool
    where
        A: AnalysisState<'a> + AnalysisStateInfo<'a> + DeserializeOwned,
    {
        self.analyses.restore_state::<A>(state)
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn project_mut(&mut self) -> &mut Project {
        &mut self.project
    }

    pub fn into_project(self) -> Project {
        self.project
    }

    pub fn into_parts(self) -> (Project, AnalysisStore) {
        (self.project, self.analyses)
    }
}
