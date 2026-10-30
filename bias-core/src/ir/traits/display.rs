use std::borrow::Cow;
use std::fmt::{self, Write};

use fugue::bv::BitVec;
use fugue::lifter::runtime::language::Language;

#[derive(Clone, Default)]
pub struct LanguageFormatter<'t> {
    pub language: Option<&'static Language>,
    pub branch_start: &'t str,
    pub branch_end: &'t str,
    pub keyword_start: &'t str,
    pub keyword_end: &'t str,
    pub location_start: &'t str,
    pub location_end: &'t str,
    pub type_start: &'t str,
    pub type_end: &'t str,
    pub value_start: &'t str,
    pub value_end: &'t str,
    pub variable_start: &'t str,
    pub variable_end: &'t str,
}

impl From<&'static Language> for LanguageFormatter<'_> {
    fn from(language: &'static Language) -> Self {
        Self {
            language: Some(language),
            ..Default::default()
        }
    }
}

impl From<Option<&'static Language>> for LanguageFormatter<'_> {
    fn from(language: Option<&'static Language>) -> Self {
        Self {
            language,
            ..Default::default()
        }
    }
}

pub trait LanguageDisplay<'v, 't> {
    type Target: fmt::Display;

    fn display_with(&'v self, language: Option<&'static Language>) -> Self::Target {
        self.display_full(Cow::Owned(LanguageFormatter::from(language)))
    }

    fn display_full(&'v self, display: Cow<'t, LanguageFormatter<'t>>) -> Self::Target;
}

pub struct BitVecFormatter<'v, 't> {
    bv: &'v BitVec,
    fmt: Cow<'t, LanguageFormatter<'t>>,
}

struct ResidueWriter<'a, 'b> {
    output: &'a mut fmt::Formatter<'b>,
    finished: bool,
}

impl Write for ResidueWriter<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.finished {
            return Ok(());
        }
        match s.split_once(':') {
            Some((residue, _)) => {
                self.finished = true;
                self.output.write_str(residue)
            }
            None => self.output.write_str(s),
        }
    }
}

impl fmt::Display for BitVecFormatter<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.fmt.value_start)?;
        write!(
            ResidueWriter {
                output: f,
                finished: false,
            },
            "{:#x}",
            self.bv
        )?;
        write!(
            f,
            "{}:{}{}{}",
            self.fmt.value_end,
            self.fmt.value_start,
            self.bv.bits(),
            self.fmt.value_end
        )
    }
}

impl<'v, 't> LanguageDisplay<'v, 't> for BitVec {
    type Target = BitVecFormatter<'v, 't>;

    fn display_full(&'v self, fmt: Cow<'t, LanguageFormatter<'t>>) -> Self::Target {
        BitVecFormatter { bv: self, fmt }
    }
}
