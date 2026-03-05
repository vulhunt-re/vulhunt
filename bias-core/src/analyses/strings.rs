use regex::bytes::Regex;

use crate::kb::string_xref::StringXRef;
use crate::kb::{uuid, Lazy};
use crate::prelude::*;
use crate::project::analysis::{AnalysisError, AnalysisInfo, AnalysisSchedule};

const STR_MIN: usize = 3;
const STR_MAX: usize = 256;

pub const ASCII_RE: &'static str =
    "(?:[[:alnum:]]|[[:blank:]]|[[:punctuation:]]|[!\"#\\$%&\'\\[\\]\\(\\)\\*\\+,-\\./:;<=>\\?^_`\r\n])";
pub static ASCII_RE_4: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!("^(?-u){ASCII_RE}{{{STR_MIN},}}\x00")).unwrap());
pub static UTF16LE_RE_4: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!("^(?-u)(?:{ASCII_RE}\x00){{{STR_MIN},}}\x00")).unwrap());
pub static UTF16BE_RE_4: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!("^(?-u)(?:\x00{ASCII_RE}){{{STR_MIN},}}\x00")).unwrap());

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct StringsXRefDB {
    xrefs: Vec<StringXRef>,
    addr_to_xrefs: AHashMap<Address, usize>,
    code_to_xrefs: AHashMap<Address, usize>,
}

impl StringsXRefDB {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_string(&self, address: Address) -> bool {
        self.string_at(address).is_some()
    }

    pub fn string_at(&self, address: Address) -> Option<&str> {
        self.addr_to_xrefs
            .get(&address)
            .and_then(|idx| Some(self.xrefs[*idx].string()))
    }

    pub fn ascii_xrefs(&self) -> impl Iterator<Item = &StringXRef> {
        self.xrefs.iter().filter(|x| x.kind() == StringData::Ascii)
    }

    pub fn utf16le_xrefs(&self) -> impl Iterator<Item = &StringXRef> {
        self.xrefs
            .iter()
            .filter(|x| x.kind() == StringData::Utf16Le)
    }

    pub fn utf16be_xrefs(&self) -> impl Iterator<Item = &StringXRef> {
        self.xrefs
            .iter()
            .filter(|x| x.kind() == StringData::Utf16Be)
    }

    // Address points to the code
    pub fn xrefs_from(&self, address: Address) -> Option<&str> {
        self.code_to_xrefs
            .get(&address)
            .and_then(|idx| Some(self.xrefs[*idx].string()))
    }

    // Address points to the string
    pub fn xrefs_to(&self, address: Address) -> impl Iterator<Item = &Address> {
        self.code_to_xrefs.iter().filter_map(move |(addr, idx)| {
            if self.xrefs[*idx].xref().target() == address {
                Some(addr)
            } else {
                None
            }
        })
    }

    fn visit_string_xref(&mut self, project: &Project, xref: XRef) {
        if let Ok(buf) = project.memory.view_bytes_from(xref.target()) {
            let buf = &buf[..buf.len().min(STR_MAX + 1)];
            let sx_ref = if let Some(m) = ASCII_RE_4.find_at(buf, 0) {
                StringXRef::new(
                    xref,
                    StringData::Ascii.decode(m.as_bytes()).unwrap(),
                    StringData::Ascii,
                )
            } else if let Some(m) = UTF16LE_RE_4.find_at(buf, 0) {
                StringXRef::new(
                    xref,
                    StringData::Utf16Le.decode(m.as_bytes()).unwrap(),
                    StringData::Utf16Le,
                )
            } else if let Some(m) = UTF16BE_RE_4.find_at(buf, 0) {
                StringXRef::new(
                    xref,
                    StringData::Utf16Be.decode(m.as_bytes()).unwrap(),
                    StringData::Utf16Be,
                )
            } else {
                return;
            };

            let idx = self.xrefs.len();
            self.xrefs.push(sx_ref);
            self.addr_to_xrefs.insert(xref.target(), idx);
            self.code_to_xrefs.insert(xref.source().address(), idx);
        }
    }
}

pub const STRINGS_XREF_ANALYSIS: uuid::Uuid = uuid("4A2D4B3E-877C-0797-891E-AD27ACF99047");

impl AnalysisInfo for StringsXRefDB {
    const NAME: &'static str = "Strings XRefs Recovery";
    const UUID: uuid::Uuid = STRINGS_XREF_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[AnalysisSchedule::After(XREF_ANALYSIS)];
}

impl Analysis for StringsXRefDB {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let xrefs = project.get_analysis::<XRefDB>();
        for (_, &xref) in xrefs.iter() {
            self.visit_string_xref(project, xref);
        }
        Ok(())
    }
}
