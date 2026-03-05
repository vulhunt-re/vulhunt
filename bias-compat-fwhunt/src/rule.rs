use std::borrow::Borrow;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use ahash::AHashMap as Map;
use bias_core::prelude::Lifter;
use bias_core::Project;
use bias::util::tags::{BlobTag, TagBuilder};
use serde_with::serde_as;
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::attr::ValWithAttr;
use crate::code::Code;
use crate::group::Groups;
use crate::guids::Guid;
use crate::meta::{Meta, RuleTarget};
use crate::nvram::Nvram;
use crate::ppi::Ppi;
use crate::protocols::Protocol;
use crate::strings::{AsciiString, HexString, WideString};
use crate::traits::MatchesRule;
use crate::MatchContext;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Deserialise(String),
    #[error(transparent)]
    DirScan(#[from] walkdir::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("cannot serialise rule: {0}")]
    Serialise(#[from] serde_yaml::ser::Error),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct RuleSet {
    rules: Arc<Map<String, Rule>>,
    tag: BlobTag,
}

impl RuleSet {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Self::from_file_aux(path).map(|(rules, tag)| Self {
            rules: Arc::new(rules),
            tag: TagBuilder::from_single(tag),
        })
    }

    fn from_file_aux<P: AsRef<Path>>(path: P) -> Result<(Map<String, Rule>, BlobTag), Error> {
        let bytes = fs::read(path)?;
        let rule = serde_yaml::from_slice(&bytes).map_err(|e| Error::Deserialise(e.to_string()))?;
        Ok((rule, BlobTag::new(bytes)))
    }

    pub fn from_directory<P: AsRef<Path>>(root: P) -> Result<Self, Error> {
        Self::from_directory_with(root, true)
    }

    pub fn from_directory_with<P: AsRef<Path>>(root: P, skip_errors: bool) -> Result<Self, Error> {
        let mut rules = Map::new();
        let mut builder = TagBuilder::new();

        let walker = WalkDir::new(root).follow_links(true).into_iter();

        for entry in walker.filter_entry(|e| {
            !e.file_type().is_file()
                || e.file_name()
                    .to_str()
                    .map(|s| s.ends_with(".yml"))
                    .unwrap_or(false)
        }) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }

            match Self::from_file_aux(entry.path()) {
                Ok((rset, tag)) => {
                    rules.extend(rset);
                    builder.insert(tag);
                }
                Err(err) => {
                    if !skip_errors {
                        return Err(err.into());
                    }
                }
            }
        }

        Ok(Self {
            rules: Arc::new(rules),
            tag: builder.build(),
        })
    }

    pub fn tag(&self) -> &BlobTag {
        &self.tag
    }

    pub fn get<S: Borrow<str>>(&self, id: S) -> Option<&Rule> {
        self.rules.get(id.borrow())
    }

    pub fn rules(&self) -> RuleSetIter {
        RuleSetIter(self.rules.iter())
    }

    pub fn all_rules(&self) -> &Map<String, Rule> {
        self.rules.as_ref()
    }

    pub fn should_scan(&self, uuid: &Uuid) -> bool {
        self.rules().any(|(_, r)| r.meta().should_scan(uuid))
    }

    pub fn should_scan_arch(&self, lifter: &Lifter) -> bool {
        self.rules().any(|(_, r)| r.meta().should_scan_arch(lifter))
    }

    pub fn should_scan_target(&self, target: &RuleTarget) -> bool {
        self.rules()
            .any(|(_, r)| r.meta().should_scan_target(target))
    }

    pub fn should_scan_standalone(&self) -> bool {
        self.rules().any(|(_, r)| r.meta().should_scan_standalone())
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

impl<S> FromIterator<(S, Rule)> for RuleSet
where
    S: Into<String>,
{
    fn from_iter<T: IntoIterator<Item = (S, Rule)>>(iter: T) -> Self {
        Self {
            rules: Arc::new(iter.into_iter().map(|(n, r)| (n.into(), r)).collect()),
            tag: TagBuilder::from_none(),
        }
    }
}

pub struct RuleSetIter<'a>(std::collections::hash_map::Iter<'a, String, Rule>);

impl<'a> Iterator for RuleSetIter<'a> {
    type Item = (&'a str, &'a Rule);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (k.as_ref(), v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> ExactSizeIterator for RuleSetIter<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    getset::Getters,
    getset::MutGetters,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Rule {
    #[getset(get = "pub", get_mut = "pub")]
    meta: Meta,
    #[serde(flatten)]
    #[getset(get = "pub", get_mut = "pub")]
    body: RuleVariants,
}

impl Rule {
    pub fn name(&self) -> &str {
        self.meta.name()
    }

    pub fn variant(&self, variant: impl AsRef<str>) -> Option<&RuleBody> {
        let variant = variant.as_ref();
        match self.body() {
            RuleVariants::Rule(r) if variant == "default" => Some(r),
            RuleVariants::Rules(rs) => rs.variants.get(variant),
            _ => None,
        }
    }

    pub fn to_yaml(&self) -> Result<String, Error> {
        let yaml = serde_yaml::to_string(&ValWithAttr {
            val: self,
            attr: self.name(),
        })?;
        Ok(yaml)
    }
}

impl MatchesRule for Rule {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        self.body.matches_rule(context, project)
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        self.body.matches_bytes(context, bytes)
    }
}

#[derive(Clone)]
pub struct RuleBuilder {
    meta: Meta,
    variants: Map<String, RuleBody>,
}

#[derive(Debug, Error)]
pub enum RuleBuilderError {
    #[error("rule contains no checks in any variant")]
    NoChecks,
    #[error("rule contains no variants")]
    NoVariants,
}

impl RuleBuilder {
    pub fn new(meta: Meta) -> Self {
        Self {
            meta,
            variants: Default::default(),
        }
    }

    pub fn with_variant(mut self, name: impl Into<String>, body: RuleBody) -> Self {
        self.variants.insert(name.into(), body);
        self
    }

    pub fn with(self, body: RuleBody) -> Self {
        self.with_variant("default", body)
    }

    pub fn build(self) -> Result<Rule, RuleBuilderError> {
        if self.variants.is_empty() {
            return Err(RuleBuilderError::NoVariants);
        }

        Ok(Rule {
            meta: self.meta,
            body: if self.variants.len() == 1 && self.variants.contains_key("default") {
                let default = self.variants.into_values().next().unwrap();
                RuleVariants::Rule(default)
            } else {
                RuleVariants::Rules(RuleList {
                    variants: self.variants,
                })
            },
        })
    }
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    getset::Getters,
    getset::MutGetters,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct RuleBody {
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    code: Groups<Code>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    strings: Groups<AsciiString>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    wide_strings: Groups<WideString>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    hex_strings: Groups<HexString>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    nvram: Groups<Nvram>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    protocols: Groups<Protocol>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    ppi: Groups<Ppi>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    guids: Groups<Guid>,
}

impl RuleBody {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_code(mut self, code: Groups<Code>) -> Self {
        self.code = code;
        self
    }

    pub fn with_strings(mut self, strings: Groups<AsciiString>) -> Self {
        self.strings = strings;
        self
    }

    pub fn with_wide_strings(mut self, wide_strings: Groups<WideString>) -> Self {
        self.wide_strings = wide_strings;
        self
    }

    pub fn with_hex_strings(mut self, hex_strings: Groups<HexString>) -> Self {
        self.hex_strings = hex_strings;
        self
    }

    pub fn with_nvram(mut self, nvram: Groups<Nvram>) -> Self {
        self.nvram = nvram;
        self
    }

    pub fn with_protocols(mut self, protocols: Groups<Protocol>) -> Self {
        self.protocols = protocols;
        self
    }

    pub fn with_ppis(mut self, ppis: Groups<Ppi>) -> Self {
        self.ppi = ppis;
        self
    }

    pub fn with_guids(mut self, guids: Groups<Guid>) -> Self {
        self.guids = guids;
        self
    }
}

impl MatchesRule for RuleBody {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        let checkpoint = context.begin(self);
        let result = self.code().matches_rule(context, project)
            && self.strings().matches_rule(context, project)
            && self.wide_strings().matches_rule(context, project)
            && self.hex_strings().matches_rule(context, project)
            && self.nvram().matches_rule(context, project)
            && self.protocols().matches_rule(context, project)
            && self.ppi().matches_rule(context, project)
            && self.guids().matches_rule(context, project);
        if result {
            context.commit(checkpoint);
        } else {
            context.discard(checkpoint);
        }
        result
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        let checkpoint = context.begin(self);
        let result = self.code().matches_bytes(context, bytes)
            && self.strings().matches_bytes(context, bytes)
            && self.wide_strings().matches_bytes(context, bytes)
            && self.hex_strings().matches_bytes(context, bytes)
            && self.nvram().matches_bytes(context, bytes)
            && self.protocols().matches_bytes(context, bytes)
            && self.ppi().matches_bytes(context, bytes)
            && self.guids().matches_bytes(context, bytes);
        if result {
            context.commit(checkpoint);
        } else {
            context.discard(checkpoint);
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleList {
    variants: Map<String, RuleBody>,
}

impl MatchesRule for RuleList {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        self.variants.iter().any(|(name, rule)| {
            tracing::trace!("scanning rule variant {name}");
            let checkpoint = context.begin(self);
            let outcome = rule.matches_rule(context, project);
            if outcome {
                tracing::info!("triggered rule variant {name}");
                context.commit(checkpoint);
            } else {
                context.discard(checkpoint);
            }
            outcome
        })
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        self.variants.iter().any(|(name, rule)| {
            tracing::trace!("scanning rule variant {name}");
            let checkpoint = context.begin(self);
            let outcome = rule.matches_bytes(context, bytes);
            if outcome {
                tracing::info!("triggered rule variant {name}");
                context.commit(checkpoint);
            } else {
                context.discard(checkpoint);
            }
            outcome
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RuleVariants {
    Rules(RuleList),
    Rule(RuleBody),
}

impl RuleVariants {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &RuleBody)> {
        match self {
            Self::Rule(rule) => {
                Box::new(std::iter::once(("default", rule))) as Box<dyn ExactSizeIterator<Item = _>>
            }
            Self::Rules(rules) => Box::new(rules.variants.iter().map(|(k, v)| (k.as_ref(), v)))
                as Box<dyn ExactSizeIterator<Item = _>>,
        }
    }
}

impl MatchesRule for RuleVariants {
    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        match self {
            Self::Rule(rule) => rule.matches_rule(context, project),
            Self::Rules(rules) => rules.matches_rule(context, project),
        }
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        match self {
            Self::Rule(rule) => rule.matches_bytes(context, bytes),
            Self::Rules(rules) => rules.matches_bytes(context, bytes),
        }
    }
}
