use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::types::artefact::{
    Artefact, ArtefactError, CodeListing, DisassemblyListing, IRListing, RawData, StructuredData,
};
use crate::types::common::{AttributeMap, Fingerprint, FingerprintBuilder};
use crate::types::property::{Annotation, AnnotationError};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Evidence {
    artefacts: Vec<Artefact>,
    annotations: Vec<Annotation>,
    attributes: AttributeMap,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvidenceBuilder {
    artefacts: Vec<Artefact>,
    annotations: Vec<Annotation>,
    attributes: AttributeMap,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error(transparent)]
    InvalidArtefact(#[from] ArtefactError),
    #[error(transparent)]
    InvalidAnnotation(#[from] AnnotationError),
    #[error("evidence contains no artefacts")]
    NoArtefacts,
    #[error("evidence contains no annotations")]
    NoAnnotations,
    #[error("artefact/annotation mismatch")]
    ArtefactAnnotationMismatch,
    #[error("annotation refers to artefact that does not exist")]
    UndefinedArtefactIndex,
}

impl EvidenceBuilder {
    pub fn new() -> Self {
        Self {
            artefacts: Vec::new(),
            annotations: Vec::new(),
            attributes: AttributeMap::new(),
        }
    }

    pub fn add_annotation(&mut self, annotation: impl Into<Annotation>) {
        self.annotations.push(annotation.into());
    }

    pub fn with_annotation(mut self, annotation: impl Into<Annotation>) -> Self {
        self.add_annotation(annotation);
        self
    }

    pub fn add_annotations<T>(&mut self, annotations: impl IntoIterator<Item = T>)
    where
        T: Into<Annotation>,
    {
        for annotation in annotations.into_iter() {
            self.add_annotation(annotation);
        }
    }

    pub fn with_annotations<T>(mut self, annotations: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<Annotation>,
    {
        self.add_annotations(annotations);
        self
    }

    pub fn add_artefact(&mut self, artefact: impl Into<Artefact>) -> usize {
        let id = self.artefacts.len();
        self.artefacts.push(artefact.into());
        id
    }

    pub fn with_artefact(mut self, artefact: impl Into<Artefact>) -> Self {
        self.add_artefact(artefact);
        self
    }

    pub fn add_artefacts<T>(&mut self, artefacts: impl IntoIterator<Item = T>)
    where
        T: Into<Artefact>,
    {
        for artefact in artefacts.into_iter() {
            self.add_artefact(artefact);
        }
    }

    pub fn with_artefacts<T>(mut self, artefacts: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<Artefact>,
    {
        self.add_artefacts(artefacts);
        self
    }

    pub fn set_attr(&mut self, name: impl Into<Cow<'static, str>>, value: impl Serialize) {
        self.attributes
            .insert(name.into(), serde_json::json!(value));
    }

    pub fn get_attr<V: DeserializeOwned>(&self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .get(name.as_ref())
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }

    pub fn set_attrs(&mut self, values: impl Serialize) {
        let serde_json::Value::Object(object) = serde_json::json!(values) else {
            return;
        };

        self.attributes
            .extend(object.into_iter().map(|(k, v)| (Cow::Owned(k), v)));
    }

    pub fn get_attrs<V: DeserializeOwned>(&self) -> Option<V> {
        let object = serde_json::Value::Object(
            self.attributes
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.to_owned()))
                .collect(),
        );

        serde_json::from_value(object).ok()
    }

    pub fn build(self) -> Result<Evidence, EvidenceError> {
        if self.artefacts.is_empty() {
            return Err(EvidenceError::NoArtefacts);
        }

        if self.annotations.is_empty() {
            return Err(EvidenceError::NoAnnotations);
        }

        // check validity of annotations with this set of artefacts
        let max_index = self.artefacts.len();

        for annotation in self.annotations.iter() {
            if annotation.artefact_index() >= max_index {
                return Err(EvidenceError::UndefinedArtefactIndex);
            }

            if !annotation.is_valid_for(&self.artefacts[annotation.artefact_index()]) {
                return Err(EvidenceError::ArtefactAnnotationMismatch);
            }
        }

        Ok(Evidence {
            artefacts: self.artefacts,
            annotations: self.annotations,
            attributes: self.attributes,
        })
    }
}

impl Evidence {
    pub fn get_annotation(&self, index: usize) -> Option<&Annotation> {
        self.annotations.get(index)
    }

    pub fn annotations(&self) -> &[Annotation] {
        &self.annotations
    }

    pub fn annotations_for(&self, index: usize) -> impl Iterator<Item = &Annotation> {
        self.annotations
            .iter()
            .filter(move |annotation| annotation.artefact_index() == index)
    }

    pub fn get_artefact(&self, index: usize) -> Option<&Artefact> {
        self.artefacts.get(index)
    }

    pub fn artefacts(&self) -> &[Artefact] {
        &self.artefacts
    }

    fn artefacts_filtered<'a, T: 'a>(
        &'a self,
        f: impl Fn(&'a Artefact) -> Option<T>,
    ) -> impl Iterator<Item = (usize, T, impl Iterator<Item = &'a Annotation>)> {
        self.artefacts
            .iter()
            .enumerate()
            .filter_map(move |(i, artefact)| {
                f(artefact).map(|listing| (i, listing, self.annotations_for(i)))
            })
    }

    pub fn data_artefacts(
        &self,
    ) -> impl Iterator<Item = (usize, &RawData, impl Iterator<Item = &Annotation>)> {
        self.artefacts_filtered(Artefact::data)
    }

    pub fn code_listing_artefacts(
        &self,
    ) -> impl Iterator<Item = (usize, &CodeListing, impl Iterator<Item = &Annotation>)> {
        self.artefacts_filtered(Artefact::code_listing)
    }

    pub fn disassembly_listing_artefacts(
        &self,
    ) -> impl Iterator<
        Item = (
            usize,
            &DisassemblyListing,
            impl Iterator<Item = &Annotation>,
        ),
    > {
        self.artefacts_filtered(Artefact::disassembly_listing)
    }

    pub fn ir_listing_artefacts(
        &self,
    ) -> impl Iterator<Item = (usize, &IRListing, impl Iterator<Item = &Annotation>)> {
        self.artefacts_filtered(Artefact::ir_listing)
    }

    pub fn component_ref_artefacts(
        &self,
    ) -> impl Iterator<Item = (usize, Uuid, impl Iterator<Item = &Annotation>)> {
        self.artefacts_filtered(Artefact::component_ref)
    }

    pub fn artefact_ref_artefacts(
        &self,
    ) -> impl Iterator<Item = (usize, Uuid, impl Iterator<Item = &Annotation>)> {
        self.artefacts_filtered(Artefact::artefact_ref)
    }

    pub fn structured_data_artefacts(
        &self,
    ) -> impl Iterator<Item = (usize, &StructuredData, impl Iterator<Item = &Annotation>)> {
        self.artefacts_filtered(Artefact::structured_data)
    }

    pub fn set_attr(&mut self, name: impl Into<Cow<'static, str>>, value: impl Serialize) {
        self.attributes
            .insert(name.into(), serde_json::json!(value));
    }

    pub fn get_attr<V: DeserializeOwned>(&self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .get(name.as_ref())
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }

    pub fn set_attrs(&mut self, values: impl Serialize) {
        let serde_json::Value::Object(object) = serde_json::json!(values) else {
            return;
        };

        self.attributes
            .extend(object.into_iter().map(|(k, v)| (Cow::Owned(k), v)));
    }

    pub fn get_attrs<V: DeserializeOwned>(&self) -> Option<V> {
        let object = serde_json::Value::Object(
            self.attributes
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.to_owned()))
                .collect(),
        );

        serde_json::from_value(object).ok()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut builder = FingerprintBuilder::new();

        builder.push_fingerprint(Fingerprint::new_attrs(&self.attributes));
        for artefact in self.artefacts() {
            if let Some(fingerprint) = artefact.fingerprint() {
                builder.push_fingerprint(fingerprint);
            }
        }

        builder.build()
    }
}
