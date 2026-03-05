use std::ops::Range;

use iset::IntervalSet;

use crate::ir::Address;
use crate::kb::{uuid, Uuid};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::project::Project;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TypesForImports {
    ranges: IntervalSet<Address>,
}

impl FromIterator<Range<Address>> for TypesForImports {
    fn from_iter<T: IntoIterator<Item = Range<Address>>>(iter: T) -> Self {
        Self {
            ranges: IntervalSet::from_iter(iter),
        }
    }
}

impl TypesForImports {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_import_range(&mut self, range: impl Into<Range<Address>>) {
        self.ranges.insert(range.into());
    }

    #[inline]
    fn in_import_range(&self, addr: impl Into<Address>) -> bool {
        let saddr = addr.into();
        let eaddr = saddr + 1usize;

        self.ranges.is_empty() || (saddr < eaddr && self.ranges.has_overlap(saddr..eaddr))
    }
}

impl AnalysisInfo for TypesForImports {
    const NAME: &'static str = "Apply types for imported functions";
    const UUID: Uuid = uuid("9090C2E8-FBBD-4376-A1DD-7BCDD5BF7279");
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for TypesForImports {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let bits = project.lifter().address_bits();
        let p = project.tables_mut();

        for (faddr, fname) in p.ftable.values().filter_map(|f| {
            if self.in_import_range(f.address()) {
                f.name().map(|name| (f.address(), name))
            } else {
                None
            }
        }) {
            let fname = fname.as_str();
            let fname_no_prefix = fname.strip_prefix("imp.").unwrap_or(fname);

            let Some(t) = p.typedb.get_prototype_for(fname_no_prefix, bits) else {
                continue;
            };
            if !t.is_function() {
                continue;
            }

            tracing::trace!("applying type {t} to {fname} at {faddr}");
            p.typedb.set_code_type_at(faddr, t);
        }

        Ok(())
    }
}
