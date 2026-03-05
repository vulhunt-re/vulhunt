use std::ops::{Deref, DerefMut};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::component::{Component, ComponentWith};
use crate::package::PackageComponentData;

pub use super::types::Property;
use super::PipelineError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct PropertySet {
    pub(crate) target: Uuid,
    pub(crate) properties: Vec<Property>,
}

impl PropertySet {
    pub fn new(target: Uuid) -> Self {
        Self {
            target,
            properties: Vec::with_capacity(0),
        }
    }

    pub fn new_with(target: Uuid, properties: impl Iterator<Item = impl Into<Property>>) -> Self {
        Self {
            target,
            properties: properties
                .into_iter()
                .map(|property| property.into())
                .collect(),
        }
    }

    pub fn singleton(target: Uuid, property: impl Into<Property>) -> Self {
        Self {
            target,
            properties: vec![property.into()],
        }
    }

    pub fn push(&mut self, property: impl Into<Property>) {
        self.properties.push(property.into());
    }

    pub fn extend(&mut self, properties: impl IntoIterator<Item = impl Into<Property>>) {
        self.properties
            .extend(properties.into_iter().map(|property| property.into()));
    }

    pub fn target(&self) -> Uuid {
        self.target
    }

    pub fn properties(&self) -> &[Property] {
        &self.properties
    }

    pub fn into_properties(self) -> Vec<Property> {
        self.properties
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Properties(Vec<PropertySet>);

impl Properties {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn new_for(target: Uuid, properties: impl Iterator<Item = impl Into<Property>>) -> Self {
        Self(vec![PropertySet::new_with(target, properties)])
    }

    pub fn singleton(target: Uuid, property: impl Into<Property>) -> Self {
        Self(vec![PropertySet::singleton(target, property)])
    }

    pub fn merge(&mut self, other: Properties) {
        self.0.extend(other.0);
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PipelineError> {
        rmp_serde::to_vec(self).map_err(PipelineError::io)
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PipelineError> {
        rmp_serde::from_slice(bytes.as_ref()).map_err(PipelineError::io)
    }
}

impl Deref for Properties {
    type Target = Vec<PropertySet>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Properties {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for Properties {
    type IntoIter = std::vec::IntoIter<PropertySet>;
    type Item = PropertySet;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub type ComponentWithProperties = ComponentWith<Properties>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ComponentsAndProperties {
    components: Vec<Component>,
    properties: Properties,
}

impl ComponentsAndProperties {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            properties: Properties::new(),
        }
    }

    pub fn for_skipped(component: PackageComponentData<'_>, property: impl Into<Property>) -> Self {
        let cid = component.id();
        ComponentsAndProperties::new()
            .with_component(component.component.into_owned())
            .with_properties(Properties::singleton(cid, property))
    }

    pub fn add_component(&mut self, component: impl Into<Component>) {
        self.components.push(component.into());
    }

    pub fn with_component(mut self, component: impl Into<Component>) -> Self {
        self.components.push(component.into());
        self
    }

    pub fn add_properties(&mut self, properties: impl Into<Properties>) {
        self.properties.extend(properties.into());
    }

    pub fn with_properties(mut self, properties: impl Into<Properties>) -> Self {
        self.properties.extend(properties.into());
        self
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &Component> {
        self.components.iter()
    }

    pub fn properties(&self) -> impl ExactSizeIterator<Item = &PropertySet> {
        self.properties.iter()
    }

    pub fn merge(mut self, other: ComponentsAndProperties) -> Self {
        self.components.extend(other.components);
        self.properties.extend(other.properties);
        self
    }

    pub fn into_parts(self) -> (Vec<Component>, Properties) {
        (self.components, self.properties)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PipelineError> {
        rmp_serde::to_vec(self).map_err(PipelineError::io)
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PipelineError> {
        rmp_serde::from_slice(bytes.as_ref()).map_err(PipelineError::io)
    }
}

impl From<Properties> for ComponentsAndProperties {
    fn from(properties: Properties) -> Self {
        Self {
            components: Vec::new(),
            properties,
        }
    }
}

pub struct PropertyTransformation {
    // This is the base property
    property: Property,
    // These are the derived properties
    properties: Vec<Property>,
}

impl PropertyTransformation {
    pub fn new(property: impl Into<Property>) -> Self {
        Self {
            property: property.into(),
            properties: Vec::new(),
        }
    }

    pub fn add_property(&mut self, property: impl Into<Property>) {
        self.properties.push(property.into());
    }

    pub fn add_properties<P>(&mut self, properties: impl IntoIterator<Item = P>)
    where
        P: Into<Property>,
    {
        for property in properties.into_iter() {
            self.add_property(property);
        }
    }

    pub fn with_property(mut self, property: impl Into<Property>) -> Self {
        self.add_property(property);
        self
    }

    pub fn with_properties<P>(mut self, properties: impl IntoIterator<Item = P>) -> Self
    where
        P: Into<Property>,
    {
        self.add_properties(properties);
        self
    }

    pub fn into_parts(self) -> (Property, Vec<Property>) {
        (self.property, self.properties)
    }
}

#[async_trait]
pub trait PropertyTransformer: Send + Sync + 'static {
    // Takes a single property and its target and derives additional properties.
    //
    // This for example, might be used to take a meta-data property (i.e., X component contains Y),
    // and produce additional properties about the component found.
    async fn transform_property(
        &self,
        target: Uuid,
        property: Property,
    ) -> Result<PropertyTransformation, PipelineError>;
}
