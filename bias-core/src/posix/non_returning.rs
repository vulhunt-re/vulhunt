use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ustr::UstrSet;

use crate::cfg::non_returning::{
    NonReturningFunctions, NonReturningPropagator, PropagatedNonReturning,
};
use crate::kb::function::{FunctionId, FunctionTable};
use crate::kb::{ustr, uuid, Lazy, Uuid};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

pub const POSIX_NON_RETURNING: Lazy<UstrSet> = Lazy::new(|| {
    UstrSet::from_iter([
        ustr("exit"),
        ustr("_exit"),
        ustr("cexit"),
        ustr("_cexit"),
        ustr("c_exit"),
        ustr("_c_exit"),
        ustr("xexit"),
        ustr("_xexit"),
        ustr("abort"),
        ustr("reboot"),
        ustr("longjmp"),
        ustr("__longjmp"),
        ustr("longjmp_chk"),
        ustr("__longjmp_chk"),
        ustr("siglongjmp"),
        ustr("panic"),
        ustr("stack_chk_fail"),
        ustr("__stack_chk_fail"),
        ustr("cxa_throw"),
        ustr("__cxa_throw"),
        ustr("cxa_terminate"),
        ustr("__cxa_terminate"),
        ustr("cxa_call_unexpected"),
        ustr("__cxa_call_unexpected"),
        ustr("cxa_bad_cast"),
        ustr("__cxa_bad_cast"),
        ustr("Unwind_Resume"),
        ustr("_Unwind_Resume"),
        ustr("assert_fail"),
        ustr("__assert_fail"),
        ustr("assert_rtn"),
        ustr("__assert_rtn"),
        ustr("fortify_fail"),
        ustr("__fortify_fail"),
        ustr("ZSt9terminatev"),
        ustr("_ZSt9terminatev"),
        ustr("ZN10__cxxabiv111__terminateEPFvvE"),
        ustr("_ZN10__cxxabiv111__terminateEPFvvE"),
        ustr("pthread_exit"),
    ])
});

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[repr(transparent)]
pub struct PosixNonReturningExternals(NonReturningFunctions);

impl PosixNonReturningExternals {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, fid: &FunctionId) -> bool {
        self.0.contains(fid)
    }

    pub fn functions(&self) -> &NonReturningFunctions {
        &self.0
    }

    pub fn mark_non_returning(&self, functions: &mut FunctionTable) {
        for fid in self.0.iter().copied() {
            functions[fid].mark_non_returning();
        }
    }
}

impl AsRef<BTreeSet<FunctionId>> for PosixNonReturningExternals {
    fn as_ref(&self) -> &BTreeSet<FunctionId> {
        &self.0
    }
}

impl Deref for PosixNonReturningExternals {
    type Target = BTreeSet<FunctionId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> IntoIterator for &'a PosixNonReturningExternals {
    type Item = FunctionId;
    type IntoIter = PosixNonReturningExternalsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PosixNonReturningExternalsIter {
            iter: self.0.iter(),
        }
    }
}

#[repr(transparent)]
pub struct PosixNonReturningExternalsIter<'a> {
    iter: std::collections::btree_set::Iter<'a, FunctionId>,
}

impl<'a> Iterator for PosixNonReturningExternalsIter<'a> {
    type Item = FunctionId;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for PosixNonReturningExternalsIter<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

pub const POSIX_NON_RETURNING_EXTERNALS: Uuid = uuid("96896B9E-5914-4E6A-A490-75B069BCE4AF");

impl AnalysisInfo for PosixNonReturningExternals {
    const NAME: &'static str = "POSIX non-returning external function identification";
    const UUID: Uuid = POSIX_NON_RETURNING_EXTERNALS;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::before::<PropagatedNonReturning<Self>>()];
}

impl Analysis for PosixNonReturningExternals {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let symbols = project.symbols();

        for name in POSIX_NON_RETURNING.iter() {
            if let Some(fid) = symbols
                .lookup(name)
                .and_then(|sym| sym.referent().get_function())
            {
                Arc::make_mut(&mut self.0).insert(fid);
            }
        }

        Ok(())
    }
}

pub type PropagatedPosixNonReturningExternals = PropagatedNonReturning<PosixNonReturningExternals>;

impl NonReturningPropagator for PosixNonReturningExternals {
    fn non_returning_functions(&self) -> NonReturningFunctions {
        self.0.clone()
    }
}
