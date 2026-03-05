use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use bias_core::kb::function::Function;
use bias_core::kb::{Lazy, Uuid};
use bias::pipeline::types::artefact::BIAS_ARTEFACT_NAMESPACE;
use bias::pipeline::types::property::annotation::{
    FunctionAnalysisLocation, FunctionMetadata,
};
use bias::pipeline::types::property::{
    FINDING_KNOWN_THREAT, FINDING_KNOWN_VULNERABILITY, FINDING_KNOWN_VULNERABILITY_PATCH,
};
pub use bias::pipeline::types::standards::cvss::CVSS;
pub use bias::pipeline::types::standards::cwe::CWE;
pub use bias::pipeline::types::standards::mbc::MBC;
use bias::pipeline::types::{
    Annotation, CodeRange, EvidenceBuilder, Finding, FindingClassification, FindingIdentifier,
    FindingMetric, FindingVariant, Note, Reference, ReferencedArtefact, ReferencedArtefactLinkage,
    ReferencedArtefactProvenance, Severity,
};
use bias::types::standards::{CPE, PURL};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::serde_as;

pub mod efi;
pub mod posix;

pub static DECOMPILER_TIMEOUT: Lazy<Duration> = Lazy::new(|| {
    let timeout = env::var("BIAS_DECOMPILER_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60000u64); // 60 seconds in milliseconds

    Duration::from_millis(timeout)
});

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Provenance {
    #[serde(default)]
    kind: Option<String>, // kind of the component found, e.g. posix.ELF, posix.lib, etc.
    linkage: ReferencedArtefactLinkage,
    vendor: String,  // the vendor producing this component
    product: String, // the product this component is a part of
    #[serde(default)]
    version: Option<String>, // the version of this specific component
    #[serde(default)]
    license: Option<String>, // the license of this (sub-)component
    #[serde(default)]
    affected_versions: Vec<String>, // list of affected versions that this component
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    #[serde(default)]
    cpe: Option<CPE>, // cpe of this specific component
    #[serde_as(as = "Option<serde_with::DisplayFromStr>")]
    #[serde(default)]
    purl: Option<PURL>, // purl of this specific component
}

impl Provenance {
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    pub fn linkage(&self) -> ReferencedArtefactLinkage {
        self.linkage
    }

    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    pub fn product(&self) -> &str {
        &self.product
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    pub fn affected_versions(&self) -> impl ExactSizeIterator<Item = &str> {
        self.affected_versions
            .iter()
            .map(|version| version.as_ref())
    }

    pub fn cpe(&self) -> Option<&CPE> {
        self.cpe.as_ref()
    }

    pub fn purl(&self) -> Option<&PURL> {
        self.purl.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct VariantData {
    #[serde(default)]
    pub(crate) severity: Option<Severity>, // Severity
    #[serde(default)]
    pub(crate) description: Option<String>, // Description of the variant
    #[serde(default)]
    pub(crate) cvss: Option<CVSS>, // CVSS score
    #[serde(default)]
    pub(crate) identifiers: Vec<String>, // Alternate identifiers (can be custom)
    #[serde(default)]
    pub(crate) references: BTreeMap<String, String>, // Additional references (title, url) pairs
    #[serde(default)]
    pub(crate) notes: BTreeMap<String, String>, // Notes related to this finding variant
    #[serde(default)]
    pub(crate) source: Option<String>, // Source of the variant data, e.g., vendor name, etc.
}

impl From<&VariantData> for FindingVariant {
    fn from(value: &VariantData) -> Self {
        let mut variant = FindingVariant::default();

        if let Some(severity) = value.severity {
            variant.set_severity(severity);
        }

        if let Some(ref cvss) = value.cvss {
            variant.add_metric(FindingMetric::new_cvss(cvss.to_owned()));
        }

        for ident in value.identifiers.iter() {
            variant.add_identifier(ident);
        }

        for (title, url) in value.references.iter() {
            variant.add_reference(Reference::new_url(title, url));
        }

        for (title, note) in value.notes.iter() {
            variant.add_note(Note::new(title, note));
        }

        if let Some(ref description) = value.description {
            variant.set_description(description.to_owned());
        }

        if let Some(ref source) = value.source {
            variant.set_source(source.to_owned());
        }

        variant
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum FindingKind {
    #[serde(rename = "vulnerability")]
    #[default]
    Vulnerability,
    #[serde(rename = "patch")]
    Patch,
    #[serde(rename = "malware")]
    Malware,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FindingData {
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) advisory: Option<String>, // URL to advisory
    #[serde(default)]
    pub(crate) patch: Option<String>, // URL to patch
    #[serde(default)]
    pub(crate) source: Option<String>, // URL to source file or repository
    #[serde(default)]
    pub(crate) cvss: Option<CVSS>, // CVSS score
    #[serde(default)]
    pub(crate) cwes: Vec<CWE>, // List of applicable CWEs
    #[serde(default)]
    pub(crate) mbcs: Vec<MBC>, // List of applicable MBC identifiers
    #[serde(default)]
    pub(crate) identifiers: Vec<String>, // List of additional identifiers (BRLY-, GHSA-, ...)
    #[serde(default)]
    pub(crate) provenance: Option<Provenance>, // Provenance information if this is an embedded component
    #[serde(default)]
    pub(crate) variants: BTreeMap<String, VariantData>, // List of variants of this finding
    #[serde(default)]
    pub(crate) references: BTreeMap<String, String>, // Additional references (title, url) pairs
    #[serde(default)]
    pub(crate) notes: BTreeMap<String, String>, // Notes related to this finding
    #[serde(default)]
    pub(crate) kind: FindingKind, // Kind of the finding
}

impl FindingData {
    pub fn apply(&self, finding: &mut Finding) {
        if let Some(ref cvss) = self.cvss {
            finding.add_metric(FindingMetric::new_cvss(cvss.to_owned()));
        }

        if !self.cwes.is_empty() {
            finding.add_classifications(
                self.cwes
                    .iter()
                    .map(CWE::as_str)
                    .map(FindingClassification::new_cwe),
            );
        }

        if !self.mbcs.is_empty() {
            finding.add_classifications(
                self.mbcs
                    .iter()
                    .map(MBC::as_str)
                    .map(FindingClassification::new_mbc),
            );
        }

        if let Some(ref advisory) = self.advisory {
            finding.add_reference(Reference::new_url("Advisory", advisory));
        }

        if let Some(ref patch) = self.patch {
            finding.add_reference(Reference::new_url("Patch", patch));
        }

        if let Some(ref source) = self.source {
            finding.add_reference(Reference::new_url("Source", source));
        }

        for (title, url) in self.references.iter() {
            finding.add_reference(Reference::new_url(title.to_owned(), url));
        }

        for identifier in self.identifiers.iter() {
            if let Some(id) = parse_valid_identifier(&identifier) {
                finding.add_identifier(id);
            }
        }

        for (title, note) in self.notes.iter() {
            finding.add_note(Note::new(title, note));
        }

        for (name, variant) in self.variants.iter() {
            finding.add_variant(name.to_owned(), FindingVariant::from(variant));
        }

        finding.set_description(self.description.to_owned());
    }

    pub fn finding_name(&self) -> &'static str {
        match self.kind {
            FindingKind::Vulnerability => FINDING_KNOWN_VULNERABILITY,
            FindingKind::Patch => FINDING_KNOWN_VULNERABILITY_PATCH,
            FindingKind::Malware => FINDING_KNOWN_THREAT,
        }
    }

    pub fn severity(&self, existing: Severity) -> Severity {
        // NOTE: we obtain severity from the CVSS score and override the rule's default severity
        match self.kind {
            FindingKind::Vulnerability => self
                .cvss
                .as_ref()
                .and_then(|cvss| cvss.severity())
                .unwrap_or(existing),
            FindingKind::Patch => Severity::None,
            FindingKind::Malware => Severity::High,
        }
    }

    pub fn provenance_artefact(&self, parent: Uuid) -> Option<(Uuid, ReferencedArtefact)> {
        let prov = self.provenance()?;
        let linkage = prov.linkage();
        let kind = prov.kind().unwrap_or("unsupported");

        // NOTE: artefact is unique with respect to parent/kind
        let artefact_id = serde_json::to_vec(&json!({
            "vendor": prov.vendor(),
            "product": prov.product(),
            "version": prov.version(),
            "linkage": linkage,
            "kind": kind,
            "parent": parent,
        }))
        .map(|bytes| Uuid::new_v5(&BIAS_ARTEFACT_NAMESPACE, &bytes))
        .ok()
        .unwrap_or_else(Uuid::new_v4);

        let mut provenance =
            ReferencedArtefactProvenance::new(prov.vendor().to_owned(), prov.product().to_owned());

        if let Some(version) = prov.version() {
            provenance.set_version(version.to_owned());
        }

        if let Some(license) = prov.license() {
            if !provenance.try_set_license(license) {
                tracing::warn!("license `{license}` contains an invalid SPDX identifier")
            }
        }

        if let Some(cpe) = prov.cpe().cloned() {
            provenance.set_cpe(cpe);
        }

        if let Some(purl) = prov.purl().cloned() {
            provenance.set_purl(purl);
        }

        let referenced_artefact = ReferencedArtefact::new(
            artefact_id,
            parent,
            prov.product().to_owned(),
            kind.to_owned(),
        )
        .with_linkage(linkage)
        .with_provenance(provenance);

        Some((artefact_id, referenced_artefact))
    }

    pub fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
    }
}

pub(crate) fn add_function_metadata(
    ebuilder: &mut EvidenceBuilder,
    fcn: &Function,
    span: CodeRange,
    index: usize,
) {
    let addr = fcn.address();
    let offset = addr.offset();

    ebuilder.add_annotation(
        Annotation::new_function_metadata(
            format!("Metadata for function at {addr}"),
            span,
            FunctionMetadata::new(
                fcn.name()
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| format!("sub_{offset:x}")),
                None,
                FunctionAnalysisLocation::new_address(addr),
            ),
        )
        .with_artefact_index(index),
    );
}

pub(crate) fn parse_valid_identifier(identifier: &str) -> Option<FindingIdentifier> {
    if let Ok(id) = identifier.parse::<FindingIdentifier>() {
        return Some(id);
    }

    let valid_identifiers = FindingIdentifier::KINDS.join(", ");
    tracing::warn!(
        "identifier `{identifier}` is invalid; valid identifiers start with: {valid_identifiers}"
    );

    None
}

#[cfg(test)]
mod test {
    use mlua::prelude::*;

    use super::*;
    use crate::lua::CheckResult;

    #[test]
    fn parse_vuln_data() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        let chunk = lua.load(
            r#"
cvss = { }

function cvss:check_score (score)
  if score == nil or type(score) ~= "string" or string.len(score) == 0 then
    error "cvss: invalid score"
  end

  -- check range
  local value = tonumber(score)
  if value == nil or value < 0.0 or value > 10.0 then
    error "cvss: invalid score range"
  end

  return score
end

function cvss:check_vector (vector)
  if vector == nil or type(vector) ~= "string" or string.len(vector) == 0 then
    error "cvss: invalid vector"
  end

  return vector
end

function cvss:v2 (v)
  if type(v) ~= "table" then
    error "cvss: invalid cvss data"
  end

  local version = "2.0"
  local base = v["base"]
  local exploitability = v["exploitability"]
  local impact = v["impact"]
  local vector = v["vector"]

  return {
    v2 = {
      version = version,
      base_score = cvss:check_score (base),
      exploitability_score = cvss:check_score (exploitability),
      impact_score = cvss:check_score (impact),
      vector = cvss:check_vector (vector),
    }
  }
end

return {
  name = "CVE-2024-1337",
  severity = "high",
  description = "This is the only required field in this table.",
  provenance = {
    -- NOTE:
    -- we don't need kind here--the artefact just signifies this vuln.
    -- is direct on the component, but we would include it if we find
    -- a vuln. from a third-party product inside this component, e.g.,
    -- zlib embedded inside something.
    --
    kind = "posix.ELF",
    linkage = "project", -- We use this linkage for "self/direct"
    vendor = "some-random-vendor",
    product = "some-random-product",
    -- NOTE: we don't need version, but if we know it, why not?
    version = "1.2.3.1337",
    -- NOTE: license is also optional...and we support expressions
    -- such as what we have below!
    license = "MIT OR Apache-2.0",
    -- NOTE: we can also specify the range or set of affected
    -- versions, but it's unclear how to report such information
    -- at the moment. We probably want something like references
    -- but "notes" that we can use to add arbitrary comments. This
    -- could also be used for adding remediation information.
    affected_versions = { },
    cpe = "cpe:2.3:a:some-random-vendor:some-random-product:1.2.3.1337:*:*:*:*:*:*:*",
    purl = "pkg:generic/some-random-vendor/some-random-product@1.2.3.1337",
  },
  cwes = { "CWE-5", "CWE-1334" },
  cvss = cvss:v2 {
    base = "10.0",
    exploitability = "10.0",
    impact = "8.0",
    vector = "Blahhh"
  },
  advisory = "https://random.org/security/RND-000-1337",
  identifiers = { "GHSA-BLAH-BLAH", "BRLY-2024-1337" },
  variants = {
    ["Binarly"] = {
      identifiers = { "CUSTOM-IDENTIFIERS-ALLOWED" },
      notes = {
        ["Some note"] = "We included this because we disagreed with the vendor."
      }
    }
  },
  references = {
    ["Product URL"] = "https://random.org/some-random-product/"
  },
  notes = {
    ["Some title"] = "This is the content of a note."
  }
}

"#,
        );

        let result = chunk.eval::<mlua::Value>()?;
        let result = lua.from_value::<CheckResult>(result)?;
        let (_name, _severity, _evidence, value) = result.into_parts();

        println!("{value:#?}");

        let mut finding = Finding::new_with(value.severity(Severity::None));

        value.apply(&mut finding);

        println!("{finding:#?}");

        let artefact = value
            .provenance_artefact(Uuid::new_v4())
            .expect("finding has a valid artefact");

        println!("{:#?}", artefact);

        Ok(())
    }
}
