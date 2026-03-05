use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::ops::{Bound, Range, RangeBounds};

use bias_core::prelude::graph::visit::{IntoEdgeReferences, IntoNodeReferences};
use bias_core::prelude::*;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::common::{AttributeMap, Fingerprint};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct LocationRange {
    start: Location,
    end: Location,
}

#[derive(Debug, Error)]
pub enum LocationRangeError {
    #[error("empty range; start >= end")]
    Empty,
    #[error("missing bound")]
    Missing,
}

impl From<Range<Location>> for LocationRange {
    fn from(value: Range<Location>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<LocationRange> for Range<Location> {
    fn from(value: LocationRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl RangeBounds<Location> for LocationRange {
    fn start_bound(&self) -> Bound<&Location> {
        Bound::Included(&self.start)
    }

    fn end_bound(&self) -> Bound<&Location> {
        Bound::Excluded(&self.end)
    }
}

impl LocationRange {
    pub fn new(start: impl Into<Location>, end: impl Into<Location>) -> Self {
        let start = start.into();
        let end = end.into();

        assert!(start < end);

        Self { start, end }
    }

    pub fn start(&self) -> Location {
        self.start
    }

    pub fn end(&self) -> Location {
        self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IRListing {
    root: u64,
    blocks: Vec<IRBlock>,
    edges: Vec<IREdge>,
    description: Option<Cow<'static, str>>,
    source: Option<String>,
    variant_of: Option<usize>,
    attributes: AttributeMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IROperation {
    location: Location,
    value: String,
}

#[derive(Debug, Error)]
pub enum IROperationError {
    #[error("operation has no location")]
    NoLocation,
    #[error("operation has no rendered representation")]
    NoRendered,
}

impl Display for IROperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.value.as_ref())
    }
}

impl IROperation {
    pub fn location(&self) -> Location {
        self.location
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub type IRBlockId = u64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IRBlock {
    operations: Vec<IROperation>,
    attributes: AttributeMap,
}

#[derive(Debug, Error)]
pub enum IRBlockError {
    #[error(transparent)]
    Operation(#[from] IROperationError),
    #[error("basic block contains no operations")]
    NoOperations,
}

impl IRBlock {
    pub fn location(&self) -> Location {
        self.operations[0].location()
    }

    pub fn operations(&self) -> &[IROperation] {
        &self.operations
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

    pub fn remove_attr(&mut self, name: impl AsRef<str>) -> Option<serde_json::Value> {
        self.attributes.remove(name.as_ref())
    }

    pub fn remove_attr_as<V: DeserializeOwned>(&mut self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .remove(name.as_ref())
            .and_then(|v| serde_json::from_value(v).ok())
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
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IREdge {
    source: IRBlockId,
    target: IRBlockId,
    attributes: AttributeMap,
}

impl IREdge {
    pub fn source(&self) -> IRBlockId {
        self.source
    }

    pub fn target(&self) -> IRBlockId {
        self.target
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

    pub fn remove_attr(&mut self, name: impl AsRef<str>) -> Option<serde_json::Value> {
        self.attributes.remove(name.as_ref())
    }

    pub fn remove_attr_as<V: DeserializeOwned>(&mut self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .remove(name.as_ref())
            .and_then(|v| serde_json::from_value(v).ok())
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
}

#[derive(Debug, Error)]
pub enum IRListingError {
    #[error(transparent)]
    Block(#[from] IRBlockError),
    #[error("invalid artefact variant index")]
    InvalidVariantIndex,
    #[error("root block is not contained in list of basic blocks")]
    NoRoot,
    #[error("listing contains no basic blocks")]
    NoBlocks,
}

impl IRListing {
    pub fn new(project: &Project, f: &Function) -> Self {
        let mut slf = Self {
            root: 0,
            blocks: Vec::default(),
            edges: Vec::default(),
            description: None,
            source: None,
            variant_of: None,
            attributes: AttributeMap::new(),
        };

        let cfg = f.iicfg(project.icfg(), project.code_blocks());
        let lifter = project.lifter();

        let mut ids = BTreeMap::new(); // NodeIndex -> IRBlockId (u64)
        let entry = Location::from(f.address());

        for (nx, chunk) in cfg.node_references() {
            let id = slf.push_block(lifter, chunk);
            ids.insert(nx, id);

            if slf.blocks[id as usize].operations[0].location == entry {
                slf.root = id;
            }
        }

        for edge in cfg.edge_references() {
            let s = ids[&edge.source()];
            let t = ids[&edge.target()];
            slf.push_edge(s, t, edge.weight());
        }

        slf
    }

    fn push_block(&mut self, lifter: &Lifter, chunk: &InsnChunks<CodeBlockId>) -> IRBlockId {
        let id = self.blocks.len();
        self.blocks.push(IRBlock {
            operations: chunk
                .iter()
                .flat_map(|chunk| {
                    let loc = chunk.location;
                    chunk
                        .operations
                        .iter()
                        .enumerate()
                        .map(move |(i, op)| (loc + i, op))
                })
                .map(|(loc, op)| IROperation {
                    location: loc,
                    value: op.display_with(Some(lifter.translator())).to_string(),
                })
                .collect(),
            attributes: AttributeMap::new(),
        });
        id as _
    }

    fn push_edge(&mut self, source: IRBlockId, target: IRBlockId, _: &FlowKind) {
        self.edges.push(IREdge {
            source,
            target,
            attributes: AttributeMap::new(),
        })
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_description(&mut self, description: impl Into<Cow<'static, str>>) {
        self.description = Some(description.into());
    }

    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.set_description(description);
        self
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn set_source(&mut self, source: impl Into<String>) {
        self.source = Some(source.into());
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.set_source(source);
        self
    }

    pub fn variant_of(&self) -> Option<usize> {
        self.variant_of
    }

    pub fn set_variant_of(&mut self, index: usize) {
        self.variant_of = Some(index);
    }

    pub fn with_variant_of(mut self, index: usize) -> Self {
        self.set_variant_of(index);
        self
    }

    pub fn entry(&self) -> Option<&IRBlock> {
        self.blocks.get(self.root as usize)
    }

    pub fn blocks(&self) -> &[IRBlock] {
        &self.blocks
    }

    pub fn edges(&self) -> &[IREdge] {
        &self.edges
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

    pub fn remove_attr(&mut self, name: impl AsRef<str>) -> Option<serde_json::Value> {
        self.attributes.remove(name.as_ref())
    }

    pub fn remove_attr_as<V: DeserializeOwned>(&mut self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .remove(name.as_ref())
            .and_then(|v| serde_json::from_value(v).ok())
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

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        Some(Fingerprint::new_attrs(&self.attributes))
    }
}
