use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ustr::UstrSet;

use crate::cfg::non_returning::{
    NonReturningFunctions, NonReturningPropagator, PropagatedNonReturning,
};
use crate::kb::{ustr, uuid, Lazy, Uuid};
use crate::prelude::FunctionId;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::Project;

const WINDOWS_NON_RETURNING: Lazy<UstrSet> = Lazy::new(|| {
    UstrSet::from_iter([
        ustr("abort"),
        ustr("CxxThrowException"),
        ustr("_CxxThrowException"),
        ustr("CxxThrowException@8"),
        ustr("_CxxThrowException@8"),
        ustr("CxxFrameHandler3"),
        ustr("__CxxFrameHandler3"),
        ustr("crtExitProcess"),
        ustr("__crtExitProcess"),
        ustr("ExitProcess"),
        ustr("ExitThread"),
        ustr("exit"),
        ustr("_exit"),
        ustr("ExRaiseAccessViolation"),
        ustr("ExRaiseDatatypeMisalignment"),
        ustr("ExRaiseStatus"),
        ustr("FreeLibraryAndExitThread"),
        ustr("invalid_parameter_noinfo_noreturn"),
        ustr("_invalid_parameter_noinfo_noreturn"),
        ustr("invoke_watson"),
        ustr("_invoke_watson"),
        ustr("KeBugCheck"),
        ustr("KeBugCheckEx"),
        ustr("longjmp"),
        ustr("__longjmp"),
        ustr("quick_exit"),
        ustr("RpcRaiseException"),
        ustr("terminate"),
    ])
});

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[repr(transparent)]
pub struct WindowsNonReturningExternals(NonReturningFunctions);

impl WindowsNonReturningExternals {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, fid: &FunctionId) -> bool {
        self.0.contains(fid)
    }

    pub fn functions(&self) -> &NonReturningFunctions {
        &self.0
    }
}

impl AsRef<BTreeSet<FunctionId>> for WindowsNonReturningExternals {
    fn as_ref(&self) -> &BTreeSet<FunctionId> {
        &self.0
    }
}

impl Deref for WindowsNonReturningExternals {
    type Target = BTreeSet<FunctionId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> IntoIterator for &'a WindowsNonReturningExternals {
    type Item = FunctionId;
    type IntoIter = WindowsNonReturningExternalsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        WindowsNonReturningExternalsIter {
            iter: self.0.iter(),
        }
    }
}

#[repr(transparent)]
pub struct WindowsNonReturningExternalsIter<'a> {
    iter: std::collections::btree_set::Iter<'a, FunctionId>,
}

impl<'a> Iterator for WindowsNonReturningExternalsIter<'a> {
    type Item = FunctionId;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for WindowsNonReturningExternalsIter<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

pub const WINDOWS_NON_RETURNING_EXTERNALS: Uuid = uuid("C3EF18A4-5072-4037-B899-862C1FAD9784");

impl AnalysisInfo for WindowsNonReturningExternals {
    const NAME: &'static str = "Windows non-returning external function identification";
    const UUID: Uuid = WINDOWS_NON_RETURNING_EXTERNALS;
    const DEPENDENCIES: &'static [AnalysisSchedule] =
        &[AnalysisSchedule::before::<PropagatedNonReturning<Self>>()];
}

impl Analysis for WindowsNonReturningExternals {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let symbols = project.symbols();

        for name in WINDOWS_NON_RETURNING.iter() {
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

pub type PropagatedWindowsNonReturningExternals =
    PropagatedNonReturning<WindowsNonReturningExternals>;

impl NonReturningPropagator for WindowsNonReturningExternals {
    fn non_returning_functions(&self) -> NonReturningFunctions {
        self.0.clone()
    }
}
