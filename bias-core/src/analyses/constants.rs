use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::any::ProvidesStaticType;
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::{Bound, IRContext, IREvalConfig, ObserverContext, ObserverState};
use crate::ir::{BitVec, Expr, Location, Term, ValHint, Var};
use crate::kb::block::CodeBlockId;
use crate::kb::id::Identifiable;
use crate::kb::{uuid, Uuid};
use crate::prelude::{AnalysisInfo, AnalysisSchedule};
use crate::project::analysis::{Analysis, AnalysisError};
use crate::project::Project;

#[derive(Default)]
struct ConstObserver;

impl Observer for ConstObserver {
    fn observe_pre_var_write_with(
        &mut self,
        _context: &mut Box<dyn IRContext>,
        observer_context: &mut ObserverContext,
        _location: Location,
        _var: &Var,
        _val: &mut BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        let v = match sexpr.as_ref() {
            Expr::Val(BitVec::N(v), ValHint::CONSTANT) => v,
            Expr::BinOp(_, e1, e2) | Expr::BinRel(_, e1, e2) => {
                if let Expr::Val(BitVec::N(v), ValHint::CONSTANT) = e2.as_ref() {
                    v
                } else if let Expr::Val(BitVec::N(v), ValHint::CONSTANT) = e1.as_ref() {
                    v
                } else {
                    return Ok(());
                }
            }
            _ => return Ok(()),
        };

        let ctx = observer_context
            .get_mut::<ConstContext>(CONSTANTS_CONTEXT)
            .expect("invalid context");

        ctx.add_const(*v.as_raw());

        Ok(())
    }
}

pub type Constants = BTreeMap<CodeBlockId, BTreeSet<u64>>;
pub type CodeBlocksWithConsts = BTreeSet<CodeBlockId>;
pub type ConstsForCodeBlock = BTreeSet<u64>;

pub trait ConstsQuery {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool;
}

impl ConstsQuery for BTreeSet<u64> {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        BTreeSet::is_subset(self, consts)
    }
}

impl<S> ConstsQuery for HashSet<u64, S> {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter().all(|v| consts.contains(v))
    }
}

impl<const N: usize> ConstsQuery for [u64; N] {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter().all(|v| consts.contains(v))
    }
}

impl ConstsQuery for [u64] {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter().all(|v| consts.contains(v))
    }
}

pub trait ConstsQueryOps {
    fn any_of(&self, consts: &ConstsForCodeBlock) -> bool;

    fn all_of(&self, consts: &ConstsForCodeBlock) -> bool;

    fn none_of(&self, consts: &ConstsForCodeBlock) -> bool {
        !self.any_of(consts)
    }
}

impl<const N: usize> ConstsQueryOps for [&[u64]; N] {
    fn any_of(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter()
            .any(|slice| slice.iter().all(|v| consts.contains(v)))
    }

    fn all_of(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter()
            .all(|slice| slice.iter().all(|v| consts.contains(v)))
    }
}

impl ConstsQueryOps for [&[u64]] {
    fn any_of(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter()
            .any(|slice| slice.iter().all(|v| consts.contains(v)))
    }

    fn all_of(&self, consts: &ConstsForCodeBlock) -> bool {
        self.iter()
            .all(|slice| slice.iter().all(|v| consts.contains(v)))
    }
}

pub struct AnyOf<T>(T);

impl<T> AnyOf<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for AnyOf<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> AsRef<AnyOf<T>> for AnyOf<T> {
    fn as_ref(&self) -> &Self {
        self
    }
}

pub struct AllOf<T>(T);

impl<T> AllOf<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for AllOf<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> AsRef<AllOf<T>> for AllOf<T> {
    fn as_ref(&self) -> &Self {
        self
    }
}

pub struct NoneOf<T>(T);

impl<T> NoneOf<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for NoneOf<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> AsRef<NoneOf<T>> for NoneOf<T> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<T: ConstsQueryOps> ConstsQuery for AnyOf<T> {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        self.0.any_of(consts)
    }
}

impl<T: ConstsQueryOps> ConstsQuery for AllOf<T> {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        self.0.all_of(consts)
    }
}

impl<T: ConstsQueryOps> ConstsQuery for NoneOf<T> {
    fn is_subset(&self, consts: &ConstsForCodeBlock) -> bool {
        self.0.none_of(consts)
    }
}

impl<T: WordsQueryOps> WordsQuery for AnyOf<T> {
    fn is_subset(&self, words: &WordsForCodeBlock) -> bool {
        self.0.any_of(words)
    }
}

impl<T: WordsQueryOps> WordsQuery for AllOf<T> {
    fn is_subset(&self, words: &WordsForCodeBlock) -> bool {
        self.0.all_of(words)
    }
}

impl<T: WordsQueryOps> WordsQuery for NoneOf<T> {
    fn is_subset(&self, words: &WordsForCodeBlock) -> bool {
        self.0.none_of(words)
    }
}

pub type WordsForCodeBlock = BTreeSet<u16>;

pub trait WordsQuery {
    fn is_subset(&self, consts: &WordsForCodeBlock) -> bool;
}

impl WordsQuery for BTreeSet<u16> {
    fn is_subset(&self, consts: &WordsForCodeBlock) -> bool {
        BTreeSet::is_subset(self, consts)
    }
}

impl<S> WordsQuery for HashSet<u16, S> {
    fn is_subset(&self, consts: &WordsForCodeBlock) -> bool {
        self.iter().all(|v| consts.contains(v))
    }
}

impl<const N: usize> WordsQuery for [u16; N] {
    fn is_subset(&self, consts: &WordsForCodeBlock) -> bool {
        self.iter().all(|v| consts.contains(v))
    }
}

impl WordsQuery for [u16] {
    fn is_subset(&self, consts: &WordsForCodeBlock) -> bool {
        self.iter().all(|v| consts.contains(v))
    }
}

pub trait WordsQueryOps {
    fn any_of(&self, words: &WordsForCodeBlock) -> bool;

    fn all_of(&self, words: &WordsForCodeBlock) -> bool;

    fn none_of(&self, words: &WordsForCodeBlock) -> bool {
        !self.any_of(words)
    }
}

impl<const N: usize> WordsQueryOps for [&[u16]; N] {
    fn any_of(&self, words: &WordsForCodeBlock) -> bool {
        self.iter()
            .any(|slice| slice.iter().all(|v| words.contains(v)))
    }

    fn all_of(&self, words: &WordsForCodeBlock) -> bool {
        self.iter()
            .all(|slice| slice.iter().all(|v| words.contains(v)))
    }
}

impl WordsQueryOps for [&[u16]] {
    fn any_of(&self, words: &WordsForCodeBlock) -> bool {
        self.iter()
            .any(|slice| slice.iter().all(|v| words.contains(v)))
    }

    fn all_of(&self, words: &WordsForCodeBlock) -> bool {
        self.iter()
            .all(|slice| slice.iter().all(|v| words.contains(v)))
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct ConstsDB {
    consts: Constants,
}

impl ConstsDB {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_const(&mut self, id: CodeBlockId, value: u64) {
        self.consts.entry(id).or_default().insert(value);
    }

    pub fn consts(&self) -> &Constants {
        &self.consts
    }

    #[inline]
    fn words(values: &BTreeSet<u64>) -> WordsForCodeBlock {
        // get words from each value and insert them into the resulting set:
        // value & 0xffff, (value >> 16) & 0xffff, (value >> 32) & 0xffff, (value >> 48) & 0xffff,
        values
            .iter()
            .flat_map(|&value| (0..4).map(move |i| ((value >> (i * 16)) & 0xffff) as u16))
            .collect()
    }

    pub fn find<'a, Q, T>(&'a self, values: Q) -> impl Iterator<Item = CodeBlockId> + 'a
    where
        Q: AsRef<T> + 'a,
        T: ConstsQuery + ?Sized + 'a,
    {
        self.consts.iter().filter_map(move |(&bid, constants)| {
            let values = values.as_ref();
            if values.is_subset(constants) {
                Some(bid)
            } else {
                None
            }
        })
    }

    pub fn find_into<Q, T>(&self, values: Q, blocks: &mut CodeBlocksWithConsts)
    where
        Q: AsRef<T>,
        T: ConstsQuery + ?Sized,
    {
        blocks.extend(self.find(values));
    }

    pub fn find_words<'a, Q, T>(&'a self, values: Q) -> impl Iterator<Item = CodeBlockId> + 'a
    where
        Q: AsRef<T> + 'a,
        T: WordsQuery + ?Sized + 'a,
    {
        self.consts.iter().filter_map(move |(&bid, constants)| {
            let values = values.as_ref();
            let words = Self::words(constants);
            if values.is_subset(&words) {
                Some(bid)
            } else {
                None
            }
        })
    }

    pub fn find_words_into<Q, T>(&self, values: Q, blocks: &mut CodeBlocksWithConsts)
    where
        Q: AsRef<T>,
        T: WordsQuery + ?Sized,
    {
        blocks.extend(self.find_words(values));
    }

    pub fn matches<'a, Q1, Q2, T1, T2>(
        &'a self,
        all: Q1,
        not: Q2,
    ) -> impl Iterator<Item = CodeBlockId> + 'a
    where
        Q1: AsRef<T1> + 'a,
        T1: ConstsQuery + ?Sized + 'a,
        Q2: AsRef<T2> + 'a,
        T2: ConstsQuery + ?Sized + 'a,
    {
        self.consts.iter().filter_map(move |(&bid, constants)| {
            let all = all.as_ref();
            let not = not.as_ref();
            if all.is_subset(constants) && !not.is_subset(constants) {
                Some(bid)
            } else {
                None
            }
        })
    }

    pub fn matches_into<Q1, Q2, T1, T2>(&self, all: Q1, not: Q2, blocks: &mut CodeBlocksWithConsts)
    where
        Q1: AsRef<T1>,
        T1: ConstsQuery + ?Sized,
        Q2: AsRef<T2>,
        T2: ConstsQuery + ?Sized,
    {
        blocks.extend(self.matches(all, not));
    }

    pub fn matches_words<'a, Q1, Q2, T1, T2>(
        &'a self,
        all: Q1,
        not: Q2,
    ) -> impl Iterator<Item = CodeBlockId> + 'a
    where
        Q1: AsRef<T1> + 'a,
        T1: WordsQuery + ?Sized + 'a,
        Q2: AsRef<T2> + 'a,
        T2: WordsQuery + ?Sized + 'a,
    {
        self.consts.iter().filter_map(move |(&bid, constants)| {
            let all = all.as_ref();
            let not = not.as_ref();
            let words = Self::words(constants);
            if all.is_subset(&words) && !not.is_subset(&words) {
                Some(bid)
            } else {
                None
            }
        })
    }

    pub fn matches_words_into<Q1, Q2, T1, T2>(
        &self,
        all: Q1,
        not: Q2,
        blocks: &mut CodeBlocksWithConsts,
    ) where
        Q1: AsRef<T1>,
        T1: WordsQuery + ?Sized,
        Q2: AsRef<T2>,
        T2: WordsQuery + ?Sized,
    {
        blocks.extend(self.matches_words(all, not));
    }
}

#[derive(ProvidesStaticType)]
struct ConstContext<'a> {
    id: CodeBlockId,
    consts: &'a mut ConstsDB,
}

const CONSTANTS_CONTEXT: Uuid = uuid("792A8205-38C3-4603-B32F-5E4B5F304E9B");

impl<'a> ObserverState<'a> for ConstContext<'a> {
    fn id(&self) -> &Uuid {
        &CONSTANTS_CONTEXT
    }
}

impl<'a> ConstContext<'a> {
    fn add_const(&mut self, value: u64) {
        self.consts.add_const(self.id, value);
    }
}

pub const CONSTANTS_ANALYSIS: Uuid = uuid("0584DF2F-091D-46EA-8942-33BE44EA9646");

impl AnalysisInfo for ConstsDB {
    const NAME: &'static str = "Constants Analyser";
    const UUID: Uuid = CONSTANTS_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for ConstsDB {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut eval = project
            .evaluator(IREvalConfig {
                enable_restores: true,
                ignore_unimplemented_ops: true,
                ignore_divide_by_zero: true,
                ignore_failures: true,
                ignore_invalid_accesses: true,
                ..Default::default()
            })
            .unwrap();

        eval.register_observer(ConstObserver::default());

        for block in project.code_blocks().values() {
            let id = block.id();

            let mut obs_ctx = ObserverContext::default();
            obs_ctx.set(CONSTANTS_CONTEXT, ConstContext { id, consts: self });

            eval.eval_full(
                project.tables(),
                &mut obs_ctx,
                block.address(),
                Bound::StopAfterOr(block.last_address(), 40),
            )
            .ok();

            eval.restore().ok();
        }

        Ok(())
    }
}
