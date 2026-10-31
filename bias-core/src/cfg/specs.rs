use fugue::specs::common::{GroupOrValueVisitor, LanguageSpec, PlatformConstraint};
use fugue::specs::{FunctionProperties, FunctionSpec};
use ustr::{Ustr, UstrSet};

use super::icfg::Configuration;
use crate::kb::id::Identifiable;
use crate::kb::symbol::SymbolRef;
use crate::lifter::Lifter;
use crate::region::SegmentCursor;
use crate::symbols::{Symbolise, SymboliseError};
use crate::Project;

struct ArchWithPlatform<'a> {
    arch: LanguageSpec,
    platform: Option<&'a str>,
}

impl GroupOrValueVisitor<PlatformConstraint> for ArchWithPlatform<'_> {
    fn matches_value(&self, value: &PlatformConstraint) -> bool {
        match value {
            PlatformConstraint::Language(arch) => arch.matches(&self.arch),
            PlatformConstraint::Platform(platform) => {
                self.platform.map(|p| p == platform).unwrap_or(true)
            }
        }
    }
}

pub struct FunctionSpecManager<'a> {
    selector: ArchWithPlatform<'a>,
    specs: Vec<&'a FunctionSpec>,
    named_non_returning: UstrSet,
    named_return_thunks: UstrSet,
}

impl<'a> FunctionSpecManager<'a> {
    pub fn new(config: &'a Configuration<'_>, lifter: &Lifter) -> Self {
        let language = lifter.language();
        let conv = lifter.convention().name();
        let selector = ArchWithPlatform {
            arch: LanguageSpec::new_with(
                language.processor(),
                lifter.endian(),
                language.bits(),
                language.variant().to_owned(),
                conv.to_owned(),
            ),
            platform: config.platform,
        };

        let mut specs = Vec::new();
        let mut named_non_returning = UstrSet::default();
        let mut named_return_thunks = UstrSet::default();

        for spec in config.use_function_specifications.iter() {
            if !spec.can_match(&selector) {
                continue;
            }

            for fspec in spec.functions().iter().filter(|f| f.matches(&selector)) {
                tracing::trace!("adding specification for {}", fspec.name());
                specs.push(fspec);

                let properties = fspec.properties();

                if properties.contains(FunctionProperties::NON_RETURNING) {
                    named_non_returning.insert(fspec.name().into());
                    named_non_returning
                        .extend(fspec.aliases().iter().map(|v| Ustr::from(v.as_str())));
                } else if properties.contains(FunctionProperties::RETURN_THUNK) {
                    // it shouldn't overlap with non-returning
                    named_return_thunks.insert(fspec.name().into());
                    named_return_thunks
                        .extend(fspec.aliases().iter().map(|v| Ustr::from(v.as_str())));
                }
            }
        }

        Self {
            selector,
            specs,
            named_non_returning,
            named_return_thunks,
        }
    }

    pub fn matches_bytes(&self, bytes: SegmentCursor<'_, '_>) -> Option<&FunctionSpec> {
        self.specs.iter().find_map(|f| {
            if f.patterns()
                .matches_cursor(&self.selector.arch, bytes.clone())
            {
                Some(*f)
            } else {
                None
            }
        })
    }

    pub fn named_non_returning(&self) -> &UstrSet {
        &self.named_non_returning
    }

    pub fn is_non_returning(&self, f: impl AsRef<str>) -> bool {
        Ustr::from_existing(f.as_ref())
            .map_or_else(|| false, |name| self.named_non_returning.contains(&name))
    }

    pub fn named_return_thunks(&self) -> &UstrSet {
        &self.named_return_thunks
    }

    pub fn is_return_thunks(&self, f: impl AsRef<str>) -> bool {
        Ustr::from_existing(f.as_ref())
            .map_or_else(|| false, |name| self.named_return_thunks.contains(&name))
    }
}

impl Symbolise for FunctionSpecManager<'_> {
    fn apply_symbols(&self, target: &mut Project) -> Result<(), SymboliseError> {
        let mut reader = target.memory.reader();
        for f in target.ftable.values_mut().filter(|f| f.name().is_none()) {
            let addr = f.address();

            tracing::trace!("attempting to apply symbol to function at {addr}");

            let Some(bytes) = f.bytes(&target.cbtable, &mut reader) else {
                continue;
            };

            let Some(spec) = self.matches_bytes(SegmentCursor::new(&bytes)) else {
                continue;
            };

            let name = spec.name();
            if target.symtab.contains(&name) {
                tracing::trace!("symbol {name} already exists in symbol table");
                continue;
            }

            tracing::trace!("applying symbol `{name}` from specification at {addr}");

            f.update_name(name);
            target.symtab.insert(name, SymbolRef::function(f.id()));

            if spec
                .properties()
                .contains(FunctionProperties::NON_RETURNING)
            {
                f.mark_non_returning();
            }

            if spec.properties().contains(FunctionProperties::RETURN_THUNK) {
                f.mark_tail();
            }
        }
        Ok(())
    }
}
