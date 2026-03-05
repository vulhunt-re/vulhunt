pub mod attr;
pub mod bmatch;
pub mod code;
pub mod group;
pub mod guids;
pub mod matcher;
pub mod meta;
pub mod nvram;
pub mod ppi;
pub mod protocols;
pub mod rule;
pub mod schema;
pub mod strings;
pub mod traits;

pub(crate) mod severity;

use std::ops::{Deref, DerefMut};

use ahash::AHashSet;

use bias_core::kb::{uuid, Uuid};
use bias_core::prelude::efi::*;
use bias_core::prelude::*;
use bias::util::tags::BlobTag;

pub use self::matcher::MatchContext;
pub use self::meta::RuleTarget;
pub use self::rule::{Rule, RuleSet};
pub use self::traits::MatchesRule;

pub const FWHUNT_RULESET_ANALYSIS: Uuid = uuid("EE615DA4-B767-48E1-86D2-127FE0D738D6");
pub const FWHUNT_RULESET_VARIANT_ANALYSIS: Uuid = uuid("1A038EA3-1764-4FB1-B5CD-9CA56ADBB4B9");

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RuleSetAnalyser {
    #[serde(skip, default)]
    rules: RuleSet,
    target: Option<RuleTarget>,
    standalone: bool,
    scanned: AHashSet<String>,
    detected: AHashMap<String, MatchContext>,
    filtered: Option<Uuid>,
}

impl RuleSetAnalyser {
    pub fn new(rules: RuleSet) -> Self {
        Self::new_with(rules, None)
    }

    pub fn new_with(rules: RuleSet, filtered: impl Into<Option<Uuid>>) -> Self {
        Self {
            rules,
            target: None,
            standalone: false,
            scanned: Default::default(),
            detected: Default::default(),
            filtered: filtered.into(),
        }
    }

    pub fn update_rules(&mut self, rules: RuleSet) {
        self.rules = rules;
    }

    pub fn scanned(&self) -> impl ExactSizeIterator<Item = &String> {
        self.scanned.iter()
    }

    pub fn scanned_rules(&self) -> &AHashSet<String> {
        &self.scanned
    }

    pub fn detected(&self) -> impl ExactSizeIterator<Item = &String> {
        self.detected.keys()
    }

    pub fn detected_rules(&self) -> &AHashMap<String, MatchContext> {
        &self.detected
    }

    pub fn all_rules(&self) -> &AHashMap<String, Rule> {
        self.rules.all_rules()
    }

    pub fn set_target(&mut self, target: RuleTarget) {
        self.target = Some(target);
    }

    pub fn with_target(mut self, target: RuleTarget) -> Self {
        self.set_target(target);
        self
    }

    pub fn set_standalone(&mut self, standalone: bool) {
        self.standalone = standalone;
    }

    pub fn with_standalone(mut self, standalone: bool) -> Self {
        self.set_standalone(standalone);
        self
    }
}

impl<S> FromIterator<(S, Rule)> for RuleSetAnalyser
where
    S: Into<String>,
{
    fn from_iter<T: IntoIterator<Item = (S, Rule)>>(iter: T) -> Self {
        Self::new(RuleSet::from_iter(iter))
    }
}

impl AnalysisInfo for RuleSetAnalyser {
    const NAME: &'static str = "FwHunt Ruleset Analysis";
    const UUID: Uuid = FWHUNT_RULESET_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        AnalysisSchedule::After(EFI_SERVICES_ANALYSIS),
        AnalysisSchedule::After(EFI_GUID_XREF_ANALYSIS),
        AnalysisSchedule::After(EFI_GLOBALS_ANALYSIS),
        AnalysisSchedule::After(EFI_SMI_HANDLER_ANALYSIS),
    ];
}

impl Analysis for RuleSetAnalyser {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if let Some(guid) = &self.filtered {
            for (name, rule) in self.rules.rules().filter(|(_, rule)| {
                rule.meta().should_scan(&guid) && rule.meta().should_scan_arch(project.lifter())
            }) {
                tracing::info!("scanning with rule {name}");
                self.scanned.insert(name.to_owned());

                let mut context = MatchContext::new();
                if rule.matches_rule(&mut context, project) {
                    self.detected.insert(name.to_owned(), context);
                }
            }
        } else {
            for (name, rule) in self.rules.rules() {
                tracing::info!("scanning with rule {name}");
                self.scanned.insert(name.to_owned());

                let mut context = MatchContext::new();
                if rule.matches_rule(&mut context, project) {
                    self.detected.insert(name.to_owned(), context);
                }
            }
        }

        Ok(())
    }
}

impl RuleSetAnalyser {
    pub fn tag(&self) -> &BlobTag {
        self.rules.tag()
    }

    pub fn analyse_filtered(
        &mut self,
        project: &mut Project,
        guid: &Uuid,
    ) -> Result<(), AnalysisError> {
        for (name, rule) in self.rules.rules().filter(|(_, rule)| {
            rule.meta().should_scan(&guid) && rule.meta().should_scan_arch(project.lifter())
        }) {
            tracing::info!("scanning with rule {name}");
            self.scanned.insert(name.to_owned());

            let mut context = MatchContext::new();
            if rule.matches_rule(&mut context, project) {
                self.detected.insert(name.to_owned(), context);
            }
        }

        Ok(())
    }

    pub fn analyse_bootloader(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        for (name, rule) in self
            .rules
            .rules()
            .filter(|(_, rule)| rule.meta().target().is_bootloader())
        {
            tracing::info!("scanning with rule {name}");
            self.scanned.insert(name.to_owned());

            let mut context = MatchContext::new();
            if rule.matches_rule(&mut context, project) {
                self.detected.insert(name.to_owned(), context);
            }
        }

        Ok(())
    }

    pub fn analyse_container(&mut self, bytes: &[u8]) -> Result<(), AnalysisError> {
        for (name, rule) in self
            .rules
            .rules()
            .filter(|(_, rule)| rule.meta().target().is_firmware())
        {
            tracing::info!("scanning with rule {name}");
            self.scanned.insert(name.to_owned());

            let mut context = MatchContext::new();
            if rule.matches_bytes(&mut context, bytes) {
                self.detected.insert(name.to_owned(), context);
            }
        }

        Ok(())
    }

    pub fn analyse_raw_section_or_variable(
        &mut self,
        guid: &Uuid,
        bytes: &[u8],
    ) -> Result<(), AnalysisError> {
        for (name, rule) in self.rules.rules().filter(|(_, rule)| {
            rule.meta().target().is_raw_section_or_variable()
                && rule.meta().should_scan_raw_section(guid)
        }) {
            tracing::info!("scanning with rule {name}");
            self.scanned.insert(name.to_owned());

            let mut context = MatchContext::new();
            if rule.matches_bytes(&mut context, bytes) {
                self.detected.insert(name.to_owned(), context.clone());
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RuleSetVariantAnalyser {
    analyser: RuleSetAnalyser,
    detected_variants: AHashMap<(String, String), MatchContext>,
}

impl AnalysisInfo for RuleSetVariantAnalyser {
    const NAME: &'static str = "FwHunt Ruleset Variant Analysis";
    const UUID: Uuid = FWHUNT_RULESET_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        AnalysisSchedule::After(EFI_SERVICES_ANALYSIS),
        AnalysisSchedule::After(EFI_GUID_XREF_ANALYSIS),
        AnalysisSchedule::After(EFI_GLOBALS_ANALYSIS),
        AnalysisSchedule::After(EFI_SMI_HANDLER_ANALYSIS),
    ];
}

impl Analysis for RuleSetVariantAnalyser {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if let Some(guid) = &self.analyser.filtered {
            for (name, rule) in self.analyser.rules.rules().filter(|(_, rule)| {
                rule.meta().should_scan(&guid) && rule.meta().should_scan_arch(project.lifter())
            }) {
                tracing::info!("scanning with rule {name}");
                self.analyser.scanned.insert(name.to_owned());

                let mut first_match = true;
                for (variant, rule) in rule.body().iter() {
                    let mut context = MatchContext::new();
                    if rule.matches_rule(&mut context, project) {
                        if first_match {
                            self.analyser
                                .detected
                                .insert(name.to_owned(), context.clone());
                            first_match = false;
                        }
                        self.detected_variants
                            .insert((name.to_owned(), variant.to_owned()), context);
                    }
                }
            }
        } else if self.analyser.standalone {
            for (name, rule) in self.analyser.rules.rules().filter(|(_, rule)| {
                rule.meta().should_scan_standalone()
                    && rule.meta().should_scan_arch(project.lifter())
            }) {
                tracing::info!("scanning with rule {name}");
                self.analyser.scanned.insert(name.to_owned());

                let mut first_match = true;
                for (variant, rule) in rule.body().iter() {
                    let mut context = MatchContext::new();
                    if rule.matches_rule(&mut context, project) {
                        if first_match {
                            self.analyser
                                .detected
                                .insert(name.to_owned(), context.clone());
                            first_match = false;
                        }
                        self.detected_variants
                            .insert((name.to_owned(), variant.to_owned()), context);
                    }
                }
            }
        } else {
            for (name, rule) in self.analyser.rules.rules() {
                tracing::info!("scanning with rule {name}");
                self.analyser.scanned.insert(name.to_owned());

                let mut first_match = true;
                for (variant, rule) in rule.body().iter() {
                    let mut context = MatchContext::new();
                    if rule.matches_rule(&mut context, project) {
                        if first_match {
                            self.analyser
                                .detected
                                .insert(name.to_owned(), context.clone());
                            first_match = false;
                        }
                        self.detected_variants
                            .insert((name.to_owned(), variant.to_owned()), context);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Deref for RuleSetVariantAnalyser {
    type Target = RuleSetAnalyser;

    fn deref(&self) -> &Self::Target {
        &self.analyser
    }
}

impl DerefMut for RuleSetVariantAnalyser {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.analyser
    }
}

impl From<RuleSetAnalyser> for RuleSetVariantAnalyser {
    fn from(analyser: RuleSetAnalyser) -> Self {
        Self {
            analyser,
            detected_variants: Default::default(),
        }
    }
}

impl RuleSetVariantAnalyser {
    pub fn new(analyser: RuleSetAnalyser) -> Self {
        Self::from(analyser)
    }

    pub fn detected_variants(&self) -> impl ExactSizeIterator<Item = &(String, String)> {
        self.detected_variants.keys()
    }

    pub fn detected_variants_with_context(
        &self,
    ) -> impl ExactSizeIterator<Item = (&(String, String), &MatchContext)> {
        self.detected_variants.iter()
    }

    pub fn analyse_raw_section_or_variable_variants(
        &mut self,
        guid: &Uuid,
        bytes: &[u8],
    ) -> Result<(), AnalysisError> {
        for (name, rule) in self.analyser.rules.rules().filter(|(_, rule)| {
            rule.meta().target().is_raw_section_or_variable()
                && rule.meta().should_scan_raw_section(guid)
        }) {
            tracing::info!("scanning with rule {name}");
            self.analyser.scanned.insert(name.to_owned());

            let mut first_match = true;
            for (variant, rule) in rule.body().iter() {
                let mut context = MatchContext::new();
                if rule.matches_bytes(&mut context, bytes) {
                    if first_match {
                        self.analyser
                            .detected
                            .insert(name.to_owned(), context.clone());
                        first_match = false;
                    }
                    self.detected_variants
                        .insert((name.to_owned(), variant.to_owned()), context);
                }
            }
        }

        Ok(())
    }

    pub fn analyse_container_variants(&mut self, bytes: &[u8]) -> Result<(), AnalysisError> {
        for (name, rule) in self
            .analyser
            .rules
            .rules()
            .filter(|(_, rule)| rule.meta().target().is_firmware())
        {
            tracing::info!("scanning with rule {name}");
            self.analyser.scanned.insert(name.to_owned());

            let mut first_match = true;
            for (variant, rule) in rule.body().iter() {
                let mut context = MatchContext::new();
                if rule.matches_bytes(&mut context, bytes) {
                    if first_match {
                        self.analyser
                            .detected
                            .insert(name.to_owned(), context.clone());
                        first_match = false;
                    }
                    self.detected_variants
                        .insert((name.to_owned(), variant.to_owned()), context);
                }
            }
        }

        Ok(())
    }
}

