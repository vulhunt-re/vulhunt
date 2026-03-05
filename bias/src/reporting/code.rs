use std::fmt::{self, Debug, Display, Write};
use std::ops::{Range, RangeInclusive};

use crate::types::CodeRange;
use miette::{
    GraphicalReportHandler, JSONReportHandler, LabeledSpan, MietteDiagnostic,
    NarratableReportHandler, SourceOffset, SourceSpan,
};
use serde::Serialize;

pub trait CodeAnnotationRange {
    fn offset(&self) -> usize;
    fn length(&self) -> usize;
}

impl CodeAnnotationRange for CodeRange {
    fn offset(&self) -> usize {
        self.start() as _
    }

    fn length(&self) -> usize {
        self.end().checked_sub(self.start()).unwrap_or_default() as _
    }
}

impl CodeAnnotationRange for Range<usize> {
    fn offset(&self) -> usize {
        self.start
    }

    fn length(&self) -> usize {
        self.end.checked_sub(self.start).unwrap_or_default()
    }
}

impl CodeAnnotationRange for RangeInclusive<usize> {
    fn offset(&self) -> usize {
        *self.start()
    }

    fn length(&self) -> usize {
        (1 + self.end())
            .checked_sub(*self.start())
            .unwrap_or_default()
    }
}

#[derive(Clone, Default)]
pub struct CodeReportBuilder {
    name: Option<String>,
    labels: Vec<LabeledSpan>,
    source: String,
}

impl CodeReportBuilder {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            ..Default::default()
        }
    }

    pub fn set_issue(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    pub fn with_issue(mut self, name: impl Into<String>) -> Self {
        self.set_issue(name);
        self
    }

    pub fn append_source(&mut self, source: impl AsRef<str>) -> usize {
        self.source.push_str("\n\n");

        let offset = self.source.len();
        self.source.push_str(source.as_ref());

        offset
    }

    pub fn push_annotation(&mut self, range: impl CodeAnnotationRange, message: impl Into<String>) {
        let offset = SourceOffset::from(range.offset());
        let length = SourceOffset::from(range.length());

        self.labels.push(LabeledSpan::at(
            SourceSpan::new(offset, length),
            message.into(),
        ));
    }

    pub fn with_annotation(
        mut self,
        range: impl CodeAnnotationRange,
        message: impl Into<String>,
    ) -> Self {
        self.push_annotation(range, message);
        self
    }

    pub fn push_annotations(
        &mut self,
        iter: impl Iterator<Item = (impl CodeAnnotationRange, impl Into<String>)>,
    ) {
        iter.for_each(|(range, message)| {
            self.push_annotation(range, message);
        });
    }

    pub fn with_annotations(
        mut self,
        iter: impl Iterator<Item = (impl CodeAnnotationRange, impl Into<String>)>,
    ) -> Self {
        self.push_annotations(iter);
        self
    }

    pub fn into_report(self, description: impl Into<String>) -> CodeReport {
        let mut diagnostic = MietteDiagnostic::new(description)
            .with_labels(self.labels)
            .with_source_code(self.source);

        diagnostic = if let Some(name) = self.name {
            diagnostic.with_code(name)
        } else {
            diagnostic
        };

        CodeReport { diagnostic }
    }
}

#[derive(Clone)]
pub struct CodeReport {
    diagnostic: MietteDiagnostic,
}

impl Display for CodeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.diagnostic, f)
    }
}

impl CodeReport {
    pub fn description(&self) -> &str {
        &self.diagnostic.message
    }

    pub fn issue(&self) -> Option<&str> {
        self.diagnostic.code.as_deref()
    }

    pub fn annotations(&self) -> impl Iterator<Item = (Range<usize>, &str)> {
        self.diagnostic
            .labels
            .as_ref()
            .into_iter()
            .flatten()
            .filter_map(|span| {
                span.label()
                    .map(|label| (span.offset()..(span.offset() + span.len()), label))
            })
    }

    pub fn source(&self) -> &str {
        &self
            .diagnostic
            .source_code
            .as_deref()
            .expect("source_code set by constructor")
    }
}

impl Serialize for CodeReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct AnnotationT<'a> {
            start: usize,
            end: usize,
            text: &'a str,
        }

        #[derive(Serialize)]
        struct CodeReportT<'a> {
            issue: Option<&'a str>,
            description: &'a str,
            listing: &'a str,
            annotations: Vec<AnnotationT<'a>>,
        }

        let t = CodeReportT {
            issue: self.issue(),
            description: self.description(),
            listing: self.source(),
            annotations: self
                .annotations()
                .map(|(range, text)| AnnotationT {
                    start: range.start,
                    end: range.end,
                    text,
                })
                .collect::<Vec<_>>(),
        };

        t.serialize(serializer)
    }
}

pub enum CodeReportRenderer {
    Fancy(GraphicalReportHandler),
    Json(JSONReportHandler),
    Simple(NarratableReportHandler),
}

impl CodeReportRenderer {
    pub fn json() -> Self {
        Self::Json(JSONReportHandler::new())
    }

    pub fn fancy() -> Self {
        Self::fancy_with(2, 120, 5)
    }

    pub fn simple() -> Self {
        Self::simple_with(5)
    }

    pub fn fancy_with(tab_width: usize, width: usize, context: usize) -> Self {
        let handler = GraphicalReportHandler::new()
            .tab_width(tab_width)
            .with_width(width)
            .with_context_lines(context);

        Self::Fancy(handler)
    }

    pub fn simple_with(context: usize) -> Self {
        let handler = NarratableReportHandler::new().with_context_lines(context);

        Self::Simple(handler)
    }

    pub fn render(&self, report: &CodeReport, mut writer: impl Write) -> fmt::Result {
        match self {
            Self::Json(handler) => handler.render_report(&mut writer, &report.diagnostic),
            Self::Fancy(handler) => handler.render_report(&mut writer, &report.diagnostic),
            Self::Simple(handler) => handler.render_report(&mut writer, &report.diagnostic),
        }
    }

    pub fn render_string(&self, report: CodeReport) -> String {
        let mut output = String::new();

        match self {
            Self::Json(handler) => handler.render_report(&mut output, &report.diagnostic),
            Self::Fancy(handler) => handler.render_report(&mut output, &report.diagnostic),
            Self::Simple(handler) => handler.render_report(&mut output, &report.diagnostic),
        }
        .expect("render to String");

        output
    }
}
