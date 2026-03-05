use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::Path;

use bias_core::decompiler::DecompilerConfig;
use bias_core::prelude::*;

use bias::component::LoadedBinaryComponent;
use bias::pipeline::analysis::{AnalysisGroupAnalyserForCode, PrefilterWith};
use bias::pipeline::property::{Properties, PropertySet};
use bias::pipeline::types::property::ARTEFACT_RELATED_COMPONENT;
use bias::pipeline::types::{
    Annotation, Artefact, CodeListing, CodeRange, EvidenceBuilder, Finding, Property,
};
use bias::pipeline::PipelineError;
use bias::platform::common::flirt::FLIRTSymbolManager;
use bias::platform::common::types::{TypeManager, TypeManagerError};
use bias::platform::posix::analysis::PosixBinaryAnalysis;
use bias::platform::posix::PosixBinary;
use bias::platform::{PlatformAttributes, PlatformProvider};
use bias::reporting::{CodeReportBuilder, CodeReportRenderer};

use thiserror::Error;

use crate::analysis::{add_function_metadata, parse_valid_identifier, DECOMPILER_TIMEOUT};
use crate::lua::api::{CheckEvidenceBuilders, CheckEvidenceLocation};
use crate::lua::project::PlatformApi;
use crate::{CheckerDB, VulHuntModuleDir};

pub struct VulHuntPosixAnalyser {
    config: VulHuntPosixAnalyserConfig,
    checkers: CheckerDB,
    analyses: PosixBinaryAnalysis,
    symbols: FLIRTSymbolManager,
    types: TypeManager,
}

#[derive(Debug, Error)]
pub enum VulhuntPosixAnalyserError {
    #[error("cannot initialise type manager: {0}")]
    Types(#[from] TypeManagerError),
}

#[derive(Debug, Clone, Default)]
pub struct VulHuntPosixAnalyserConfig {
    pub render: bool,
    pub ignore_errors: bool,
    pub module_directory: VulHuntModuleDir,
}

impl VulHuntPosixAnalyserConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_render(mut self, render: bool) -> Self {
        self.render = render;
        self
    }

    pub fn with_ignore_errors(mut self, ignore_errors: bool) -> Self {
        self.ignore_errors = ignore_errors;
        self
    }

    pub fn with_module_directory(mut self, module_directory: impl Into<VulHuntModuleDir>) -> Self {
        self.module_directory = module_directory.into();
        self
    }
}

impl VulHuntPosixAnalyser {
    pub fn new(
        checkers: impl AsRef<Path>,
        analyses: PosixBinaryAnalysis,
    ) -> Result<Self, PipelineError> {
        Self::new_with(checkers, analyses, Default::default())
    }

    pub fn new_with(
        checkers: impl AsRef<Path>,
        analyses: PosixBinaryAnalysis,
        config: VulHuntPosixAnalyserConfig,
    ) -> Result<Self, PipelineError> {
        let data = analyses.platform_data_provider();

        let symbols = FLIRTSymbolManager::new(data.clone()).map_err(PipelineError::analysis)?;
        let types = TypeManager::new(data.clone()).map_err(PipelineError::analysis)?;

        let checkers = CheckerDB::from_directory_and_module_directory(
            checkers,
            &symbols,
            config.ignore_errors,
            &config.module_directory,
        )
        .map_err(PipelineError::analysis)?;

        Ok(Self {
            checkers,
            analyses,
            config,
            symbols,
            types,
        })
    }
}

impl AnalysisGroupAnalyserForCode for VulHuntPosixAnalyser {
    fn decompiler_configuration(&self) -> Cow<'_, DecompilerConfig> {
        Cow::Owned(DecompilerConfig::default())
    }

    fn analyse_and_check(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Properties, PipelineError> {
        let mut properties = Properties::new();
        let mut property_set = PropertySet::new(component.id());

        let decompiler_config = self.decompiler_configuration();

        if let Ok(Some(symbols)) = self.analyses.apply_symbols(component, project) {
            property_set.push(symbols);
        }

        self.analyses.register_analyses(component, project)?;

        project.analyse()?;

        let mut engine = self.checkers.engine::<PosixBinary>(
            &component,
            &project,
            self.symbols.clone(),
            self.types.clone(),
        );

        let attributes = component.container();
        let results = engine.run(&attributes).map_err(PipelineError::analysis)?;

        let mut artefacts = BTreeMap::new();

        // We need one for each type library
        let mut evidence_builders =
            CheckEvidenceBuilders::new(&project, &decompiler_config, attributes, &engine);

        for result in results {
            let id = result.rule();
            let builder = evidence_builders
                .get_for(id)
                .map_err(PipelineError::analysis)?;

            let (name, severity, evidence, data) = result.into_parts();
            let mut ebuilder = EvidenceBuilder::new();
            let mut report = None::<CodeReportBuilder>;
            let mut listings = BTreeMap::new();

            for (loc, annots) in evidence.as_ref().into_iter().flat_map(|f| f.functions()) {
                let report_ref = &mut report;

                let anno = builder
                    .decompile_with(loc, annots, *DECOMPILER_TIMEOUT)
                    .map_err(PipelineError::analysis)?;

                if let CheckEvidenceLocation::Address(addr) = loc {
                    let (index, offset) = *listings.entry(addr).or_insert_with(|| {
                        let index = ebuilder.add_artefact(Artefact::new_code_listing(
                            CodeListing::new(anno.source()),
                        ));

                        if let Some(fcn) = builder.resolve_function(loc) {
                            add_function_metadata(
                                &mut ebuilder,
                                fcn,
                                CodeRange::new(0, anno.source().len() as _),
                                index,
                            );
                        }

                        // if we add a new listing, then extend our report
                        let offset = if let Some(ref mut report) = report_ref.as_mut() {
                            report.append_source(anno.source())
                        } else {
                            *report_ref =
                                Some(CodeReportBuilder::new(anno.source()).with_issue(&name));
                            0
                        };

                        (index, offset)
                    });

                    let Some(report) = report.as_mut() else {
                        continue;
                    };

                    for annot in anno.annotations() {
                        let Some(range) = annot.maximal_range() else {
                            continue;
                        };

                        let start = *range.start();
                        let end = *range.end();
                        report.push_annotation(offset + start..offset + end, annot.message());

                        ebuilder.add_annotation(
                            Annotation::new(annot.message())
                                .with_artefact_index(index)
                                .with_span(CodeRange::from(start..end)),
                        );
                    }
                }
            }

            self.config
                .render
                .then(|| CodeReportRenderer::fancy_with(2, 120, 10))
                .and_then(|renderer| {
                    report.map(|report| {
                        ebuilder.set_attr(
                            "rendered",
                            renderer.render_string(report.into_report(&data.description)),
                        );
                    })
                });

            let artefact_info = data.provenance_artefact(component.id());

            if let Some((artefact_id, _)) = &artefact_info {
                ebuilder.add_artefact(Artefact::new_artefact_ref(*artefact_id));
            }

            let evidence = match ebuilder.build() {
                Ok(evidence) => evidence,
                Err(e) => {
                    tracing::warn!("failed to build evidence: {e}");
                    // We ignore this finding, but proceed with the rest
                    continue;
                }
            };

            // NOTE: since we are definitely able to add this finding, we ensure it gets linked
            // to the correct artefact at this point.

            if let Some((artefact_id, artefact)) = artefact_info {
                artefacts.insert(artefact_id, artefact);
            }

            let mut finding = Finding::new_with(data.severity(severity)).with_evidence(evidence);

            data.apply(&mut finding);

            if let Some(id) = parse_valid_identifier(&name) {
                finding.add_identifier(id);
            }

            property_set.push(Property::new_finding(
                component.id(),
                data.finding_name(),
                finding,
            ));
        }

        drop(evidence_builders);

        let mut artefact_set = PropertySet::new(component.id());

        for artefact in artefacts.into_values() {
            artefact_set.push(Property::new_artefact_ref(
                component.id(),
                ARTEFACT_RELATED_COMPONENT,
                artefact,
            ));
        }

        properties.push(artefact_set);
        properties.push(property_set);

        Ok(properties)
    }

    fn configuration<'b>(
        &'b self,
        _component: &LoadedBinaryComponent,
    ) -> Cow<'b, ProjectConfig<'b>> {
        Cow::Borrowed(self.analyses.configuration())
    }

    fn should_analyse(&self, platform: &PlatformAttributes) -> bool {
        self.checkers.iter().any(|checker| {
            checker.platform() == PosixBinary::NAME
                && PosixBinary::should_check(checker.architecture(), checker.conditions(), platform)
                    .unwrap_or(false)
        })
    }

    fn analyse_and_prefilter(
        &self,
        component: &mut LoadedBinaryComponent,
        _lifter: &Lifter,
    ) -> Result<PrefilterWith<Properties>, PipelineError> {
        let platform = component.container();
        for checker in self.checkers.iter() {
            if checker.platform() == PosixBinary::NAME
                && PosixBinary::should_check(
                    checker.architecture(),
                    checker.conditions(),
                    &platform,
                )
                .unwrap_or(false)
                && checker.conditions().validate(component).unwrap_or(false)
            {
                return Ok(PrefilterWith::continue_analysis());
            }
        }

        Ok(PrefilterWith::skip_analysis())
    }
}
