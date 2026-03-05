use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;

use bias_core::kb::Lazy;
use debversion::Version;
use regex::Regex;
use thiserror::Error;

static MONTH_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|June|July|August|September|October|November|December)\b").unwrap()
});

static MONTHS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    [
        ("jan", "01"),
        ("feb", "02"),
        ("mar", "03"),
        ("apr", "04"),
        ("may", "05"),
        ("jun", "06"),
        ("jul", "07"),
        ("aug", "08"),
        ("sep", "09"),
        ("oct", "10"),
        ("nov", "11"),
        ("dec", "12"),
        ("january", "01"),
        ("february", "02"),
        ("march", "03"),
        ("april", "04"),
        ("june", "06"),
        ("july", "07"),
        ("august", "08"),
        ("september", "09"),
        ("october", "10"),
        ("november", "11"),
        ("december", "12"),
    ]
    .iter()
    .cloned()
    .collect::<HashMap<_, _>>()
});

#[derive(Debug, Copy, Clone, Default)]
pub struct VersionMatchConfig {
    strip_prefix: bool,
}

impl VersionMatchConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_strip_prefix(&mut self, strip_prefix: bool) {
        self.strip_prefix = strip_prefix;
    }

    pub fn with_strip_prefix(mut self) -> Self {
        self.set_strip_prefix(true);
        self
    }

    pub fn strip_prefix(&self) -> bool {
        self.strip_prefix
    }
}

pub trait Versions {
    fn is_wild(&self) -> bool;

    fn any_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool;

    fn all_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool;
}

impl<S> Versions for [S]
where
    S: AsRef<str>,
{
    fn is_wild(&self) -> bool {
        self.iter().find(|v| v.as_ref() == "*").is_some()
    }

    fn any_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool {
        self.iter().any(|v| version.matches_with(v, config))
    }

    fn all_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool {
        self.iter().all(|v| version.matches_with(v, config))
    }
}

impl<S> Versions for Vec<S>
where
    S: AsRef<str>,
{
    fn is_wild(&self) -> bool {
        <[S]>::is_wild(self)
    }

    fn any_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool {
        <[S]>::any_matches_with(self, version, config)
    }

    fn all_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool {
        <[S]>::all_matches_with(self, version, config)
    }
}

impl<S, const N: usize> Versions for [S; N]
where
    S: AsRef<str>,
{
    fn is_wild(&self) -> bool {
        <[S]>::is_wild(self)
    }

    fn any_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool {
        <[S]>::any_matches_with(self, version, config)
    }

    fn all_matches_with(&self, version: &FuzzyVersion, config: &VersionMatchConfig) -> bool {
        <[S]>::all_matches_with(self, version, config)
    }
}

#[derive(Debug, Error)]
#[error("unparsable version string: {0}")]
pub struct VersionParseError(<Version as FromStr>::Err);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionReq {
    si: UnsetOr,
    se: UnsetOr,
    ei: UnsetOr,
    ee: UnsetOr,
}

impl VersionReq {
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_with(s, &VersionMatchConfig::default())
    }

    pub fn parse_with(s: &str, config: &VersionMatchConfig) -> Option<Self> {
        let mut si = UnsetOr::Unset;
        let mut se = UnsetOr::Unset;
        let mut ei = UnsetOr::Unset;
        let mut ee = UnsetOr::Unset;

        for part in s.split(',').map(|s| s.trim()) {
            if let Some(v) = part.strip_prefix(">=") {
                if !se.is_unset() {
                    return None;
                }
                if let Ok(ver) = sanitise_version(v, config).parse::<Version>() {
                    si = UnsetOr::Version(ver);
                } else {
                    si = UnsetOr::Unset;
                }
                continue;
            }

            if let Some(v) = part.strip_prefix(">") {
                if !si.is_unset() {
                    return None;
                }
                if let Ok(ver) = sanitise_version(v, config).parse::<Version>() {
                    se = UnsetOr::Version(ver);
                } else {
                    se = UnsetOr::Unset;
                }
                continue;
            }

            if let Some(v) = part.strip_prefix("<=") {
                if !ee.is_unset() {
                    return None;
                }
                if let Ok(ver) = sanitise_version(v, config).parse::<Version>() {
                    ei = UnsetOr::Version(ver);
                } else {
                    ei = UnsetOr::Unset;
                }
                continue;
            }

            if let Some(v) = part.strip_prefix("<") {
                if !ei.is_unset() {
                    return None;
                }
                if let Ok(ver) = sanitise_version(v, config).parse::<Version>() {
                    ee = UnsetOr::Version(ver);
                } else {
                    ee = UnsetOr::Unset;
                }
                continue;
            }

            return None;
        }

        Some(Self { si, se, ei, ee })
    }

    fn parse_parts_with(
        from: Option<(Cow<str>, bool)>,
        to: Option<(Cow<str>, bool)>,
        config: &VersionMatchConfig,
    ) -> Result<Self, VersionParseError> {
        let mut si = UnsetOr::Unset;
        let mut se = UnsetOr::Unset;
        let mut ei = UnsetOr::Unset;
        let mut ee = UnsetOr::Unset;

        if let Some((from, inclusive)) = from {
            let start = if inclusive { &mut si } else { &mut se };
            *start = UnsetOr::Version(
                sanitise_version(from.as_ref(), config)
                    .parse::<Version>()
                    .map_err(VersionParseError)?,
            );
        }

        if let Some((to, inclusive)) = to {
            let end = if inclusive { &mut ei } else { &mut ee };
            *end = UnsetOr::Version(
                sanitise_version(to.as_ref(), config)
                    .parse::<Version>()
                    .map_err(VersionParseError)?,
            );
        }

        Ok(Self { si, se, ei, ee })
    }

    fn normalise_range(i: &UnsetOr, e: &UnsetOr) -> Option<(UnsetOr, bool)> {
        let (v, inc) = match (i, e) {
            (UnsetOr::Version(_), UnsetOr::Version(_)) => return None,
            (UnsetOr::Version(_), _) => (i, true),
            (_, UnsetOr::Version(_)) => (e, false),
            _ => (i, true),
        };
        Some((v.to_owned(), inc))
    }

    pub fn overlaps(&self, si: &str, ei: &str, se: &str, ee: &str) -> bool {
        self.overlaps_with(si, ei, se, ee, &VersionMatchConfig::default())
    }

    pub fn overlaps_with(
        &self,
        si: &str,
        ei: &str,
        se: &str,
        ee: &str,
        config: &VersionMatchConfig,
    ) -> bool {
        let Some(si) = UnsetOr::parse_with(si, config) else {
                        if !is_valid_hex_string(si) {
                tracing::warn!("cannot parse version range {si:?}");
            }
            return false;
        };

        let Some(se) = UnsetOr::parse_with(se, config) else {
                        if !is_valid_hex_string(se) {
                tracing::warn!("cannot parse version range {se:?}");
            }
            return false;
        };

        let Some(ei) = UnsetOr::parse_with(ei, config) else {
                        if !is_valid_hex_string(ei) {
                tracing::warn!("cannot parse version range {ei:?}");
            }
            return false;
        };

        let Some(ee) = UnsetOr::parse_with(ee, config) else {
                        if !is_valid_hex_string(ee) {
                tracing::warn!("cannot parse version range {ee:?}");
            }
            return false;
        };

        let Some((s1, si1)) = Self::normalise_range(&self.si, &self.se) else {
            return false;
        };
        let Some((e1, ei1)) = Self::normalise_range(&self.ei, &self.ee) else {
            return false;
        };

        let Some((s2, si2)) = Self::normalise_range(&si, &se) else {
            return false;
        };
        let Some((e2, ei2)) = Self::normalise_range(&ei, &ee) else {
            return false;
        };

        if si.is_unset() && se.is_unset() && ei.is_unset() && ee.is_unset() {
            return false;
        }

        if s1.is_match(|s1| e2.is_match(|e2| s1 > e2))
            || (s1.is_match(|s1| e2.is_match(|e2| s1 == e2)) && (!si1 || !ei2))
        {
            return false;
        }

        if s2.is_match(|s2| e1.is_match(|e1| s2 > e1))
            || (s2.is_match(|s2| e1.is_match(|e1| s2 == e1)) && (!si2 || !ei1))
        {
            return false;
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FuzzyVersion<'a> {
    Version(Version, Option<Version>),
    VersionReq(VersionReq),
    VersionRaw(Cow<'a, str>),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum UnsetOr {
    Unset,
    Version(Version),
}

impl UnsetOr {
    fn parse_with(r: &str, config: &VersionMatchConfig) -> Option<UnsetOr> {
        if r.is_empty() || is_valid_hex_string(r) || r == "-" || r == "*" {
            Some(UnsetOr::Unset)
        } else {
            if let Ok(ver) = sanitise_version(r, config).parse::<Version>() {
                Some(ver).map(UnsetOr::Version)
            } else {
                Some(UnsetOr::Unset)
            }
        }
    }

    fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }

    fn is_match(&self, f: impl FnOnce(&Version) -> bool) -> bool {
        matches!(self, Self::Version(version) if f(version))
    }
}

impl<'a> FuzzyVersion<'a> {
    pub fn new(version: impl Into<Cow<'a, str>>) -> Self {
        Self::new_with(version, &VersionMatchConfig::default())
    }

    pub fn new_with(version: impl Into<Cow<'a, str>>, config: &VersionMatchConfig) -> Self {
        let version = version.into();
        if version == "*" || version == "" {
            return Self::Any;
        }

        if let Some(req) = VersionReq::parse_with(version.as_ref(), config) {
            return Self::VersionReq(req);
        }

        let sanitised_version = sanitise_version(&version, config);
        if let Some(ver) = sanitised_version.parse::<Version>().ok() {
            // OpenSSL-style version
            // we extract prefix from input version, that contains space
            let prefix = version
                .split_once(' ')
                .and_then(|(p, _)| p.parse::<Version>().ok());
            return Self::Version(ver, prefix);
        }

        Self::VersionRaw(version)
    }

    pub fn into_owned(self) -> FuzzyVersion<'static> {
        match self {
            FuzzyVersion::Version(version, prefix) => FuzzyVersion::Version(version, prefix),
            FuzzyVersion::VersionReq(req) => FuzzyVersion::VersionReq(req),
            FuzzyVersion::VersionRaw(version) => {
                FuzzyVersion::VersionRaw(Cow::Owned(version.into_owned()))
            }
            FuzzyVersion::Any => FuzzyVersion::Any,
        }
    }

    pub fn is_wild(&self) -> bool {
        matches!(self, Self::Any)
    }

    pub fn overlaps_range_or_versions(
        &self,
        si: impl AsRef<str>,
        ei: impl AsRef<str>,
        se: impl AsRef<str>,
        ee: impl AsRef<str>,
        versions: &impl Versions,
    ) -> bool {
        self.overlaps_range_or_versions_with(
            si,
            ei,
            se,
            ee,
            versions,
            &VersionMatchConfig::default(),
        )
    }

    pub fn overlaps_range_or_versions_with(
        &self,
        si: impl AsRef<str>,
        ei: impl AsRef<str>,
        se: impl AsRef<str>,
        ee: impl AsRef<str>,
        versions: &impl Versions,
        config: &VersionMatchConfig,
    ) -> bool {
        let ranges_not_present = si.as_ref().is_empty()
            && ei.as_ref().is_empty()
            && se.as_ref().is_empty()
            && ee.as_ref().is_empty();

        if versions.is_wild() && !ranges_not_present {
            self.overlaps_with(si, ei, se, ee, config)
        } else {
            self.overlaps_with(si, ei, se, ee, config) || versions.any_matches_with(self, config)
        }
    }

    pub fn overlaps_range_inclusive(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> bool {
        self.overlaps(from, to, "", "")
    }

    pub fn overlaps_range_exclusive(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> bool {
        self.overlaps("", "", from, to)
    }

    pub fn overlaps_range_inclusive_exclusive(
        &self,
        from: impl AsRef<str>,
        to: impl AsRef<str>,
    ) -> bool {
        self.overlaps(from, "", "", to)
    }

    pub fn overlaps_range_exclusive_inclusive(
        &self,
        from: impl AsRef<str>,
        to: impl AsRef<str>,
    ) -> bool {
        self.overlaps("", from, to, "")
    }

    pub fn overlaps(
        &self,
        si: impl AsRef<str>,
        ei: impl AsRef<str>,
        se: impl AsRef<str>,
        ee: impl AsRef<str>,
    ) -> bool {
        self.overlaps_with(si, ei, se, ee, &VersionMatchConfig::default())
    }

    pub fn overlaps_with(
        &self,
        si: impl AsRef<str>,
        ei: impl AsRef<str>,
        se: impl AsRef<str>,
        ee: impl AsRef<str>,
        config: &VersionMatchConfig,
    ) -> bool {
        let si = si.as_ref();
        let se = se.as_ref();
        let ei = ei.as_ref();
        let ee = ee.as_ref();

        let mut pass_s = false;
        let mut pass_e = false;

        let to_match = match self {
            // even if we have prefix, we compare by full version
            Self::Version(v, _) => v,
            Self::VersionRaw(_raw) => {
                                tracing::warn!("unimplemented overlaps for unparsable version: {_raw}");
                return false;
            }
            Self::VersionReq(req) => return req.overlaps_with(si, ei, se, ee, config),
            Self::Any => return true,
        };

        let Some(si) = UnsetOr::parse_with(si, config) else {
                        if !is_valid_hex_string(si) {
                tracing::warn!("cannot parse version range {si:?}");
            }
            return false;
        };

        let Some(se) = UnsetOr::parse_with(se, config) else {
                        if !is_valid_hex_string(se) {
                tracing::warn!("cannot parse version range {se:?}");
            }
            return false;
        };

        let Some(ei) = UnsetOr::parse_with(ei, config) else {
                        if !is_valid_hex_string(ei) {
                tracing::warn!("cannot parse version range {ei:?}");
            }
            return false;
        };

        let Some(ee) = UnsetOr::parse_with(ee, config) else {
                        if !is_valid_hex_string(ee) {
                tracing::warn!("cannot parse version range {ee:?}");
            }
            return false;
        };

        let ranges_not_present = si.is_unset() && se.is_unset() && ei.is_unset() && ee.is_unset();

        pass_s |= si.is_match(|v| to_match >= v);
        pass_s |= se.is_match(|v| to_match > v);
        pass_s |= si.is_unset() && se.is_unset();

        pass_e |= ei.is_match(|v| to_match <= v);
        pass_e |= ee.is_match(|v| to_match < v);
        pass_e |= ei.is_unset() && ee.is_unset();

        pass_s && pass_e && !ranges_not_present
    }

    pub fn matches_any(&self, iter: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
        self.matches_any_with(iter, &VersionMatchConfig::default())
    }

    pub fn matches_any_with(
        &self,
        iter: impl IntoIterator<Item = impl AsRef<str>>,
        config: &VersionMatchConfig,
    ) -> bool {
        iter.into_iter()
            .any(|version| self.matches_with(version, config))
    }

    pub fn matches_all(&self, iter: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
        self.matches_all_with(iter, &VersionMatchConfig::default())
    }

    pub fn matches_all_with(
        &self,
        iter: impl IntoIterator<Item = impl AsRef<str>>,
        config: &VersionMatchConfig,
    ) -> bool {
        iter.into_iter()
            .all(|version| self.matches_with(version, config))
    }

    pub fn matches(&self, version: impl AsRef<str>) -> bool {
        self.matches_with(version, &VersionMatchConfig::default())
    }

    pub fn matches_with(&self, version: impl AsRef<str>, config: &VersionMatchConfig) -> bool {
        if version.as_ref() == "*" {
            return true;
        }
        self.overlaps_with(&version, &version, "", "", config)
    }

    pub fn queries<'q>(&'q self) -> impl ExactSizeIterator<Item = Cow<'q, str>> {
        match self {
            Self::Version(version, version_opt) => {
                let mut v = vec![Cow::Borrowed(version.upstream_version.as_str())];
                if let Some(version_opt) = version_opt {
                    v.push(Cow::Borrowed(version_opt.upstream_version.as_str()));
                }
                v.into_iter()
            }
            Self::VersionRaw(version) => vec![Cow::Borrowed(version.as_ref())].into_iter(),
            _ => vec![].into_iter(),
        }
    }
}

fn sanitise_version(version: &str, config: &VersionMatchConfig) -> String {
    let version = if config.strip_prefix() {
        version.strip_prefix('v').unwrap_or(version)
    } else {
        version
    };

    replace_months_with_numbers(
        &version
            .trim()
            .replace(['_', ' '], ".")
            .replace(['(', ')'], ""),
    )
}

fn replace_months_with_numbers(input: &str) -> String {
    MONTH_REGEX
        .replace_all(input, |caps: &regex::Captures| {
            let month_name = &caps[0].to_lowercase();
            if let Some(replace) = MONTHS.get(month_name.as_str()) {
                replace.to_string()
            } else {
                month_name.to_string()
            }
        })
        .to_string()
}

fn is_valid_hex_string(s: &str) -> bool {
    if s.len() < 12 || s.len() > 40 {
        return false;
    }

    s.chars().all(|c| c.is_ascii_hexdigit())
}

pub struct FuzzyVersionBuilder<'a> {
    from: Option<(Cow<'a, str>, bool)>,
    to: Option<(Cow<'a, str>, bool)>,
}

impl<'a> FuzzyVersionBuilder<'a> {
    pub fn new() -> Self {
        Self {
            from: None,
            to: None,
        }
    }

    pub fn inclusive_from(mut self, from: impl Into<Cow<'a, str>>) -> Self {
        self.from = Some((from.into(), true));
        self
    }

    pub fn exclusive_from(mut self, from: impl Into<Cow<'a, str>>) -> Self {
        self.from = Some((from.into(), false));
        self
    }

    pub fn inclusive_to(mut self, to: impl Into<Cow<'a, str>>) -> Self {
        self.to = Some((to.into(), true));
        self
    }

    pub fn exclusive_to(mut self, to: impl Into<Cow<'a, str>>) -> Self {
        self.to = Some((to.into(), false));
        self
    }

    pub fn build(self) -> Result<FuzzyVersion<'a>, VersionParseError> {
        self.build_with(&VersionMatchConfig::default())
    }

    pub fn build_with(self, config: &VersionMatchConfig) -> Result<FuzzyVersion<'a>, VersionParseError> {
        VersionReq::parse_parts_with(self.from, self.to, config).map(FuzzyVersion::VersionReq)
    }
}

impl<'a> Default for FuzzyVersionBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn normalised_version(version: impl AsRef<str>) -> Option<String> {
    let version = version.as_ref();

    if version == "unknown" {
        return None;
    }

    // default VersionMatchConfig fits for normalised versions
    match FuzzyVersion::new(version) {
        FuzzyVersion::Version(version, prefix) => {
            // when version has prefix, we use it as normalised version
            if let Some(prefix) = prefix {
                Some(prefix.upstream_version)
            } else {
                Some(version.upstream_version)
            }
        }
        // raw version | versions range | wildcard version – can't normalise
        FuzzyVersion::VersionRaw(_) | FuzzyVersion::VersionReq(_) | FuzzyVersion::Any => None,
    }
}

#[cfg(test)]
mod test {
    use super::{
        normalised_version, FuzzyVersion, FuzzyVersionBuilder, VersionMatchConfig, VersionReq,
    };
    #[test]
    fn test_builder() {
        let version = FuzzyVersionBuilder::new()
            .inclusive_from("18.0.0")
            .inclusive_to("19.0.0")
            .build()
            .unwrap();
        assert!(version.overlaps_range_inclusive("18.0.0", "19.0.0"));
    }

    #[test]
    fn test_overlaps() {
        let lzma = VersionReq::parse(">=18.0.0,<=19.0.0").unwrap();

        assert!(lzma.overlaps("18.0.0", "19.0.0", "", ""));
        assert!(lzma.overlaps("18.0.0", "", "", ""));
        assert!(lzma.overlaps("17.0.0", "", "", ""));

        assert!(lzma.overlaps("", "19.0.0", "", ""));
        assert!(lzma.overlaps("", "20.0.0", "", ""));
        assert!(lzma.overlaps("17.0.0", "20.0.0", "", ""));

        assert!(lzma.overlaps("17.0.0", "", "", "19.0.0"));
        assert!(lzma.overlaps("", "", "", "19.0.0"));
        assert!(lzma.overlaps("", "", "18.0.0", ""));
        assert!(lzma.overlaps("", "", "18.1.0", ""));

        assert!(!lzma.overlaps("", "", "19.0.0", ""));
        assert!(!lzma.overlaps("", "", "", ""));

        assert!(!lzma.overlaps("v18.0.0", "v19.0.0", "", ""));
        assert!(lzma.overlaps_with(
            "v18.0.0",
            "v19.0.0",
            "",
            "",
            &VersionMatchConfig::new().with_strip_prefix()
        ));

        let wpa_supplicant = VersionReq::parse(">=2.6,<=2.10").unwrap();
        assert!(wpa_supplicant.overlaps("2.5", "2.7", "", ""));
    }

    #[test]
    fn test_fuzzy() {
        let lzma = FuzzyVersion::new("19.0.0");
        assert!(lzma.overlaps("19.0.0", "", "", ""));
        assert!(lzma.overlaps("", "19.0.0", "", ""));
        assert!(!lzma.overlaps("", "", "19.0.0", ""));
        assert!(!lzma.overlaps("", "", "", "19.0.0"));
    }

    #[test]
    fn test_fuzzy_debian_1() {
        let lzma = FuzzyVersion::new("2.40.0+dfsg-3ubuntu0.5");
        assert!(lzma.overlaps("", "2.42.8+dfsg-1ubuntu0.3", "", ""));
    }

    #[test]
    fn test_fuzzy_debian_2() {
        let lzma = FuzzyVersion::new("2.42.8+dfsg-1ubuntu0.3");
        assert!(!lzma.overlaps("", "2.40.0+dfsg-3ubuntu0.5", "", ""));
    }

    #[test]
    fn test_fuzzy_debian_3() {
        let lzma = FuzzyVersion::new("2.42.8+dfsg-1ubuntu0.2");
        assert!(lzma.overlaps("", "2.42.8+dfsg-1ubuntu0.3", "", ""));
    }

    #[test]
    fn test_fuzzy_debian_4() {
        let lzma = FuzzyVersion::new("5.4.13-1");
        assert!(!lzma.overlaps("", "3.2.30-1", "", ""));
    }

    #[test]
    fn test_fuzzy_debian_5() {
        let lzma = FuzzyVersion::new("2.42.8+dfsg-1ubuntu0.2");
        assert!(lzma.overlaps("2.42.8+dfsg-0ubuntu0.2", "2.42.8+dfsg-1ubuntu0.2", "", ""));
    }

    #[test]
    fn test_fuzzy_redhat_1() {
        let lzma = FuzzyVersion::new("0:0.0.99.4-5.module+el8.9.0+1445+07728297");
        assert!(lzma.overlaps("", "0:0.2.6-20.module+el8.9.0+1420+91577025", "", ""));
    }

    #[test]
    fn test_fuzzy_redhat_2() {
        let lzma = FuzzyVersion::new("2:1.10.3-1.module+el8.10.0+1815+5fe7415e");
        assert!(lzma.overlaps("", "2:1.14.3-2.module+el8.10.0+1815+5fe7415e", "", ""));
    }

    #[test]
    fn test_fuzzy_redhat_3() {
        let lzma = FuzzyVersion::new("2.33-100.el9");
        assert!(lzma.overlaps("", "2.33-100.el9_4.2", "", ""));
    }

    #[test]
    fn test_fuzzy_redhat_4() {
        let lzma = FuzzyVersion::new("2.33-100.el9");
        assert!(lzma.overlaps("", "2.33-100.el9_4.2", "", ""));
        assert!(lzma.overlaps("", "2.33-101.el9_4.2", "", ""));
    }

    #[test]
    fn test_almalinux_1() {
        let lzma = FuzzyVersion::new("9.27-13.el8_10");
        assert!(lzma.overlaps("", "9.27-15.el8_10", "", ""));
    }

    #[test]
    fn test_almalinux_2() {
        let lzma = FuzzyVersion::new("3:2.1.10-1.module_el8.10.0+3845+87b84552");
        assert!(lzma.overlaps("", "3:2.1.10-1.module_el8.10.0+3858+6ad51f9f", "", ""));
    }

    #[test]
    fn test_almalinux_3() {
        let lzma = FuzzyVersion::new("3:2.1.10-1.module_el8.10.0+3845+87b84552");
        assert!(lzma.overlaps("", "3:2.1.10-1.module_el8.10.0+3858+6ad51f9f", "", ""));
    }

    #[test]
    fn test_almalinux_4() {
        let lzma = FuzzyVersion::new("20230404-117.git2e92a49f.el8_8.alma.1");
        assert!(lzma.overlaps("", "20240111-121.gitb3132c18.el8", "", ""));
    }

    #[test]
    fn test_trim() {
        let lzma = FuzzyVersion::new("1.0.2k 26 Jan 2017");
        assert!(lzma.overlaps("", "1.0.3", "", ""));
        assert!(lzma.overlaps("", "1.0.2l", "", ""));
        assert!(!lzma.overlaps("", "1.0.2a", "", ""));
        assert!(lzma.overlaps("", "1.0.2k 30 Jan 2017", "", ""));
        assert!(!lzma.overlaps("", "1.0.2k 20 Jan 2017", "", ""));
    }

    #[test]
    fn test_case_openssl_1() {
        let openssl = FuzzyVersion::new("1.1.1t");
        assert!(openssl.overlaps("1.1.1", "", "", "1.1.1za"));
    }

    #[test]
    fn test_case_openssl_2() {
        let openssl = FuzzyVersion::new("1.1.1f");
        assert!(openssl.overlaps("1.1.1", "", "", "1.1.1za"));
    }

    #[test]
    fn test_case_openssl_3() {
        let openssl = FuzzyVersion::new("1.1.1za");
        assert!(!openssl.overlaps("1.1.1", "", "", "1.1.1za"));
    }

    #[test]
    fn test_case_openssl_4() {
        let openssl = FuzzyVersion::new("1.1.1a");
        assert!(!openssl.overlaps("1.1.1f", "", "", "1.1.1za"));
    }

    #[test]
    fn test_case_with_a_date_in_braces() {
        let vim: FuzzyVersion<'_> = FuzzyVersion::new("8.2 (2019 Dec 12)");
        assert!(vim.overlaps("", "8.3", "", ""));
        assert!(vim.overlaps("", "", "", "8.3"));
        assert!(vim.overlaps("", "", "", "8.2 (2019 Dec 31)"));
        assert!(vim.overlaps("", "", "", "8.2 (2020 Dec 12)"));
        assert!(!vim.overlaps("", "", "", "8.1"));
        assert!(!vim.overlaps("", "", "", "8.2"));
        assert!(!vim.overlaps("", "", "", "8.2 (2018 Dec 12)"));
        assert!(!vim.overlaps("", "", "", "8.2 (2019 Oct 12)"));
        assert!(!vim.overlaps("", "", "", "8.2 (2019 Aug 01)"));
    }

    #[test]
    fn test_commit_hash() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new("5.15.67");
        assert!(!linux_kernel.overlaps("", "", "", "31cb32a590d6")); // commit hash has to fail
        assert!(!linux_kernel.overlaps("", "", "", "5.15.8"));
    }

    #[test]
    fn test_wrong_version_panic() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new("5.15.67");
        assert!(!linux_kernel.overlaps("", "", "", "75a422165477")); // commit hash has to fail
    }

    #[test]
    fn test_wildcard_version() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new("*");
        assert!(linux_kernel.overlaps("", "", "", "75a422165477"));
    }

    #[test]
    fn test_bad_version_range_from_vdb() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new("5.15.67");
        assert!(!linux_kernel.overlaps("", "", "", "-"));
    }

    #[test]
    fn test_overlaps_range_against_iter() {
        let lzma = FuzzyVersion::new(">=5.18.2,<=5.26.2");
        assert!(!lzma.matches_any(&vec!["5.15.1"]));
        assert!(!lzma.matches_any(&vec!["5.26.3"]));
        assert!(lzma.matches_any(&vec!["5.19.1"]));
    }

    #[test]
    fn test_matches_any_range() {
        let lzma = FuzzyVersion::new(">=5.18.2,<=5.26.2");
        assert!(lzma.matches_any(&vec!["5.26.3", "5.19.3"]));
    }

    #[test]
    fn test_matches_any_version() {
        let lzma: FuzzyVersion<'_> = FuzzyVersion::new("5.15.67");
        assert!(lzma.matches_any(&vec!["5.15.67", "5.19.3"]));
        assert!(!lzma.matches_any(&vec!["5.15.67.1", "5.19.6"]));
    }

    #[test]
    fn test_matches_all_versions() {
        let lzma = FuzzyVersion::new(">=5.18.2,<=5.26.2");
        assert!(lzma.matches_all(&vec!["5.18.3", "5.26.2", "5.20"]));
        assert!(!lzma.matches_all(&vec!["5.14.3", "5.26.2", "4.0.0"]));
    }

    #[test]
    fn test_fuzzy_ranges_matches() {
        let lzma = FuzzyVersion::new(">=5.18.2,<=5.26.2");
        assert!(lzma.matches("5.18.3"));
        assert!(lzma.matches("5.25.30"));
        assert!(!lzma.matches("4.18.3"));
    }

    #[test]
    fn test_fuzzy_matches() {
        let lzma = FuzzyVersion::new("5.18.2");
        assert!(lzma.matches("5.18.2"));
        assert!(lzma.matches("5.18.2-0"));
        assert!(!lzma.matches("5.18.3"));
        assert!(!lzma.matches("4.18.3"));
    }

    #[test]
    fn test_against_empty() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new("5.15.67");
        assert!(!linux_kernel.overlaps("", "", "", ""));
        assert!(!linux_kernel.matches_any([""]));
        assert!(!linux_kernel.matches_all([""]));
        assert!(!linux_kernel.matches(""));
    }

    #[test]
    fn test_against_empty_ranges() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new(">=5.18.2,<=5.26.2");
        assert!(!linux_kernel.overlaps("", "", "", ""));
        assert!(!linux_kernel.matches_any([""]));
        assert!(!linux_kernel.matches_all([""]));
        assert!(!linux_kernel.matches(""));
    }

    #[test]
    fn test_against_wildcard() {
        let linux_kernel: FuzzyVersion<'_> = FuzzyVersion::new(">=5.18.2,<=5.26.2");
        assert!(linux_kernel.overlaps("*", "5.29", "", ""));
        assert!(!linux_kernel.overlaps("*", "5.15", "", ""));
        assert!(linux_kernel.overlaps("", "", "*", "5.29"));
        assert!(!linux_kernel.overlaps("", "", "*", "5.15"));
        assert!(linux_kernel.matches_any(["*", "4.2"]));
        assert!(linux_kernel.matches_all(["*"]));
        assert!(linux_kernel.matches("*"));
    }

    #[test]
    fn test_overlaps_range_or_versions() {
        let gnutls = FuzzyVersion::new("3.8.3");
        assert!(!gnutls.overlaps_range_or_versions(
            "3.6.3",
            "",
            "",
            "3.7.1",
            &[String::from("*")].to_vec()
        ));
        assert!(gnutls.overlaps_range_or_versions(
            "3.6.3",
            "",
            "",
            "3.9.0",
            &[String::from("*")].to_vec()
        ));
        assert!(gnutls.overlaps_range_or_versions(
            "3.8.3",
            "",
            "",
            "",
            &[String::from("*")].to_vec()
        ));
        assert!(gnutls.overlaps_range_or_versions(
            "",
            "3.8.3",
            "",
            "",
            &[String::from("*")].to_vec()
        ));
        assert!(!gnutls.overlaps_range_or_versions(
            "",
            "",
            "3.8.3",
            "",
            &[String::from("*")].to_vec()
        ));
        assert!(!gnutls.overlaps_range_or_versions(
            "",
            "",
            "",
            "3.8.3",
            &[String::from("*")].to_vec()
        ));
        assert!(gnutls.overlaps_range_or_versions(
            "",
            "",
            "",
            "",
            &[String::from("3.8.3")].to_vec()
        ));
    }

    #[test]
    fn test_overflow_parsing_panic() {
        let lzma = FuzzyVersion::new("2.9.9070701022");
        assert!(lzma.overlaps_range_or_versions("0", "2.9.9070701022", "", "", &["".to_string()]));
    }

    #[test]
    fn test_normalise_version() {
        assert_eq!(normalised_version("unknown"), None);
        assert_eq!(normalised_version("2.14.1").unwrap(), "2.14.1");
        assert_eq!(normalised_version("05.05.39").unwrap(), "05.05.39");
        assert_eq!(normalised_version("0.9.8l 5 Nov 2009").unwrap(), "0.9.8l");
    }
}
