use std::mem::MaybeUninit;
use std::ops::{Index, IndexMut};

use crate::analyses::stack::aliases::{FunctionStackAccesses, FunctionStackRefs};
use crate::analyses::stack::possibly_uninit::FunctionUninitUses;
use crate::analyses::stack::reaching_constants::FunctionReachingStackConsts;
use crate::analyses::stack::reaching_definitions::FunctionReachingStackDefs;
use crate::analyses::stack::reaching_uninit::FunctionReachingUninitValues;
use crate::cio::Prototype;
use crate::define_mtable_key;
use crate::kb::function::{Function, FunctionId};
use crate::kb::id::Identifiable;
use crate::kb::operand::Operand;
use crate::kb::table::MTable;
use crate::kb::{AHashMap, Ustr};

define_mtable_key!(FunctionSummaryId, "8C977DD9-13B7-48ED-816D-53323CA00002");

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct FunctionSideEffects {
    clobbered_operands: Vec<Operand>,
    free_operands: Vec<Operand>,
}

impl FunctionSideEffects {
    pub fn clobbered_operands(&mut self) -> &[Operand] {
        &self.clobbered_operands
    }

    pub fn clobbered_operands_mut(&mut self) -> &mut Vec<Operand> {
        &mut self.clobbered_operands
    }

    pub fn free_operands(&mut self) -> &[Operand] {
        &self.free_operands
    }

    pub fn free_operands_mut(&mut self) -> &mut Vec<Operand> {
        &mut self.free_operands
    }
}

#[derive(
    Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum FunctionRef {
    External(Ustr),
    Function(FunctionId),
}

impl FunctionRef {
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External(_))
    }

    pub fn is_function(&self) -> bool {
        matches!(self, Self::Function(_))
    }

    #[inline]
    pub fn external<T, F>(&self, mut f: F) -> Option<T>
    where
        F: FnMut(Ustr) -> T,
    {
        let Self::External(id) = *self else {
            return None;
        };
        Some(f(id))
    }

    #[inline]
    pub fn into_external(self) -> Option<Ustr> {
        self.external(|v| v)
    }

    #[inline]
    pub fn function<T, F>(&self, mut f: F) -> Option<T>
    where
        F: FnMut(FunctionId) -> T,
    {
        let Self::Function(id) = *self else {
            return None;
        };
        Some(f(id))
    }

    #[inline]
    pub fn into_function(self) -> Option<FunctionId> {
        self.function(|v| v)
    }
}

impl From<Ustr> for FunctionRef {
    fn from(f: Ustr) -> Self {
        FunctionRef::External(f)
    }
}

impl From<FunctionId> for FunctionRef {
    fn from(f: FunctionId) -> Self {
        FunctionRef::Function(f)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FunctionSummary {
    id: FunctionSummaryId,
    function: FunctionRef,

    prototype: Option<Prototype>,
    arguments: Vec<Operand>,
    preserved_or_restored: Vec<Operand>,
    definitely_killed: Vec<Operand>,

    stack_shift: i64,
    stack_accesses: Option<FunctionStackAccesses>,

    refs: Option<FunctionStackRefs>,
    csts: Option<FunctionReachingStackConsts>,
    rdefs: Option<FunctionReachingStackDefs>,
    uninit_values: Option<FunctionReachingUninitValues>,
    uninit_uses: Option<FunctionUninitUses>,
}

impl FunctionSummary {
    pub fn new<F>(id: FunctionSummaryId, function: F) -> Self
    where
        F: Into<FunctionRef>,
    {
        Self {
            id,
            function: function.into(),
            prototype: None,
            arguments: Vec::with_capacity(0),
            preserved_or_restored: Vec::with_capacity(0),
            definitely_killed: Vec::with_capacity(0),
            stack_shift: 0,
            stack_accesses: None,
            refs: None,
            csts: None,
            rdefs: None,
            uninit_values: None,
            uninit_uses: None,
        }
    }

    pub fn for_external<S>(id: FunctionSummaryId, symbol: S) -> Self
    where
        S: Into<Ustr>,
    {
        Self::new(id, symbol.into())
    }

    pub fn for_function(id: FunctionSummaryId, function: FunctionId) -> Self {
        Self::new(id, function)
    }

    pub fn is_external(&self) -> bool {
        self.function.is_external()
    }

    pub fn prototype(&self) -> &Option<Prototype> {
        &self.prototype
    }

    pub fn prototype_mut(&mut self) -> &mut Option<Prototype> {
        &mut self.prototype
    }

    pub fn arguments(&self) -> &[Operand] {
        &self.arguments
    }

    pub fn arguments_mut(&mut self) -> &mut Vec<Operand> {
        &mut self.arguments
    }

    pub fn preserved_or_restored(&self) -> &Vec<Operand> {
        &self.preserved_or_restored
    }

    pub fn preserved_or_restored_mut(&mut self) -> &mut Vec<Operand> {
        &mut self.preserved_or_restored
    }

    pub fn definitely_killed(&self) -> &Vec<Operand> {
        &self.definitely_killed
    }

    pub fn definitely_killed_mut(&mut self) -> &mut Vec<Operand> {
        &mut self.definitely_killed
    }

    pub fn stack_shift(&self) -> i64 {
        self.stack_shift
    }

    pub fn set_stack_shift(&mut self, value: i64) {
        self.stack_shift = value;
    }

    pub fn stack_accesses(&self) -> &Option<FunctionStackAccesses> {
        &self.stack_accesses
    }

    pub fn stack_accesses_mut(&mut self) -> &mut Option<FunctionStackAccesses> {
        &mut self.stack_accesses
    }

    pub fn stack_references(&self) -> &Option<FunctionStackRefs> {
        &self.refs
    }

    pub fn stack_references_mut(&mut self) -> &mut Option<FunctionStackRefs> {
        &mut self.refs
    }

    pub fn reaching_constants(&self) -> &Option<FunctionReachingStackConsts> {
        &self.csts
    }

    pub fn reaching_constants_mut(&mut self) -> &mut Option<FunctionReachingStackConsts> {
        &mut self.csts
    }

    pub fn reaching_definitions(&self) -> &Option<FunctionReachingStackDefs> {
        &self.rdefs
    }

    pub fn reaching_definitions_mut(&mut self) -> &mut Option<FunctionReachingStackDefs> {
        &mut self.rdefs
    }

    pub fn reaching_uninit_values(&self) -> &Option<FunctionReachingUninitValues> {
        &self.uninit_values
    }

    pub fn reaching_uninit_values_mut(&mut self) -> &mut Option<FunctionReachingUninitValues> {
        &mut self.uninit_values
    }

    pub fn uninit_uses(&self) -> &Option<FunctionUninitUses> {
        &self.uninit_uses
    }

    pub fn uninit_uses_mut(&mut self) -> &mut Option<FunctionUninitUses> {
        &mut self.uninit_uses
    }
}

impl Identifiable for FunctionSummary {
    type Key = FunctionSummaryId;

    fn id(&self) -> Self::Key {
        self.id
    }

    fn id_mut(&mut self) -> &mut Self::Key {
        &mut self.id
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct FunctionSummaryTable {
    inner: MTable<FunctionSummary>,
    functions: AHashMap<FunctionId, FunctionSummaryId>,
}

impl Default for FunctionSummaryTable {
    fn default() -> Self {
        FunctionSummaryTable {
            inner: MTable::default(),
            functions: AHashMap::default(),
        }
    }
}

impl FunctionSummaryTable {
    pub fn reserve(&mut self, n: usize) {
        self.functions.reserve(n);
        self.inner.reserve(n);
    }

    pub fn insert_for_external<F>(&mut self, f: F) -> FunctionSummaryId
    where
        F: FnOnce(FunctionSummaryId) -> FunctionSummary,
    {
        let k = self.inner.insert(f);
        k
    }

    pub fn insert_for_function<F>(&mut self, id: FunctionId, f: F) -> FunctionSummaryId
    where
        F: FnOnce(FunctionSummaryId, FunctionId) -> FunctionSummary,
    {
        let k = self.inner.insert(|k| f(k, id));
        self.functions.insert(id, k);
        k
    }

    pub fn contains(&self, id: FunctionSummaryId) -> bool {
        self.inner.contains(id)
    }

    pub fn contains_function(&self, function: FunctionId) -> bool {
        self.functions.contains_key(&function)
    }

    pub fn id(&self, function: FunctionId) -> Option<FunctionSummaryId> {
        self.functions.get(&function).copied()
    }

    pub fn get(&self, id: FunctionSummaryId) -> Option<&FunctionSummary> {
        self.inner.get(id)
    }

    pub fn get_for_function(&self, function: FunctionId) -> Option<&FunctionSummary> {
        self.functions
            .get(&function)
            .and_then(|id| self.inner.get(*id))
    }

    pub fn get_mut(&mut self, id: FunctionSummaryId) -> Option<&mut FunctionSummary> {
        self.inner.get_mut(id)
    }

    pub fn get_for_function_mut(&mut self, function: FunctionId) -> Option<&mut FunctionSummary> {
        self.functions
            .get(&function)
            .and_then(|id| self.inner.get_mut(*id))
    }

    pub fn get_disjoint_mut<const N: usize>(
        &mut self,
        ids: [FunctionSummaryId; N],
    ) -> Option<[&mut FunctionSummary; N]> {
        self.inner.get_disjoint_mut(ids)
    }

    pub fn try_get_disjoint_mut(
        &mut self,
        ids: &[FunctionSummaryId],
    ) -> Option<Vec<&mut FunctionSummary>> {
        self.inner.try_get_disjoint_mut(ids)
    }

    pub fn get_disjoint_for_functions_mut<const N: usize>(
        &mut self,
        functions: [FunctionId; N],
    ) -> Option<[&mut FunctionSummary; N]> {
        // NOTE: replace with MaybeUninit::uninit_array when stable
        let mut maybe_ids: [MaybeUninit<FunctionSummaryId>; N] =
            unsafe { MaybeUninit::<[MaybeUninit<FunctionSummaryId>; N]>::uninit().assume_init() };

        // LEAKS on failure: V::Key is Copy---no need for Drop.
        for (id, function) in maybe_ids.iter_mut().zip(functions.iter()) {
            id.write(*self.functions.get(function)?);
        }

        // NOTE: replace with MaybeUninit::array_assume_init when stable
        let ids = unsafe { (&maybe_ids as *const _ as *const [FunctionSummaryId; N]).read() };

        self.get_disjoint_mut(ids)
    }

    pub fn values(&self) -> impl ExactSizeIterator<Item = &FunctionSummary> {
        self.inner.iter()
    }

    pub fn values_mut(&mut self) -> impl ExactSizeIterator<Item = &mut FunctionSummary> {
        self.inner.iter_mut()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&FunctionSummary),
    {
        for v in self.inner.iter() {
            f(v);
        }
    }

    pub fn for_each_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut FunctionSummary),
    {
        for v in self.inner.iter_mut() {
            f(v);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Index<FunctionSummaryId> for FunctionSummaryTable {
    type Output = FunctionSummary;

    fn index(&self, id: FunctionSummaryId) -> &Self::Output {
        self.get(id).unwrap()
    }
}

impl IndexMut<FunctionSummaryId> for FunctionSummaryTable {
    fn index_mut(&mut self, id: FunctionSummaryId) -> &mut Self::Output {
        self.get_mut(id).unwrap()
    }
}

impl Index<FunctionId> for FunctionSummaryTable {
    type Output = FunctionSummary;

    fn index(&self, id: FunctionId) -> &Self::Output {
        self.get_for_function(id).unwrap()
    }
}

impl IndexMut<FunctionId> for FunctionSummaryTable {
    fn index_mut(&mut self, id: FunctionId) -> &mut Self::Output {
        self.get_for_function_mut(id).unwrap()
    }
}

impl Index<&'_ Function> for FunctionSummaryTable {
    type Output = FunctionSummary;

    fn index(&self, function: &Function) -> &Self::Output {
        self.get_for_function(function.id()).unwrap()
    }
}

impl IndexMut<&'_ Function> for FunctionSummaryTable {
    fn index_mut(&mut self, function: &Function) -> &mut Self::Output {
        self.get_for_function_mut(function.id()).unwrap()
    }
}
