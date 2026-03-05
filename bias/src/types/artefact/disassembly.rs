use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::ops::{Bound, Range, RangeBounds};

use bias_core::fugue::ir::disassembly::{ContextDatabase, IRBuilderArena, ParserContext};
use bias_core::prelude::graph::visit::{IntoEdgeReferences, IntoNodeReferences};
use bias_core::prelude::*;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::common::{AttributeMap, Fingerprint};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct AddressRange {
    start: Address,
    end: Address,
}

#[derive(Debug, Error)]
#[error("empty range; start >= end")]
pub struct AddressRangeError;

impl From<Range<Address>> for AddressRange {
    fn from(value: Range<Address>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<AddressRange> for Range<Address> {
    fn from(value: AddressRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl RangeBounds<Address> for AddressRange {
    fn start_bound(&self) -> Bound<&Address> {
        Bound::Included(&self.start)
    }

    fn end_bound(&self) -> Bound<&Address> {
        Bound::Excluded(&self.end)
    }
}

impl AddressRange {
    pub fn new(start: impl Into<Address>, end: impl Into<Address>) -> Self {
        let start = start.into();
        let end = end.into();

        assert!(start < end);

        Self { start, end }
    }

    pub fn new_from(start: impl Into<Address>, bytes: usize) -> Self {
        let start = start.into();
        Self::new(start, start + bytes)
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn end(&self) -> Address {
        self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DisassemblyListing {
    root: u64,
    blocks: Vec<DisassemblyBlock>,
    edges: Vec<DisassemblyEdge>,
    description: Option<Cow<'static, str>>,
    source: Option<String>,
    variant_of: Option<usize>,
    attributes: AttributeMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Instruction {
    address: Address,
    value: String,
}

#[derive(Debug, Error)]
#[error("instruction has no rendered representation")]
pub struct InstructionError;

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.value.as_ref())
    }
}

impl Instruction {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub type DisassemblyBlockId = u64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DisassemblyBlock {
    instructions: Vec<Instruction>,
    attributes: AttributeMap,
}

#[derive(Debug, Error)]
pub enum DisassemblyBlockError {
    #[error(transparent)]
    Instruction(#[from] InstructionError),
    #[error("basic block contains no instructions")]
    NoInstructions,
}

impl DisassemblyBlock {
    pub fn address(&self) -> Address {
        self.instructions[0].address()
    }

    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
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
pub struct DisassemblyEdge {
    source: DisassemblyBlockId,
    target: DisassemblyBlockId,
    attributes: AttributeMap,
}

impl DisassemblyEdge {
    pub fn source(&self) -> DisassemblyBlockId {
        self.source
    }

    pub fn target(&self) -> DisassemblyBlockId {
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
pub enum DisassemblyListingError {
    #[error(transparent)]
    Block(#[from] DisassemblyBlockError),
    #[error("invalid artefact variant index")]
    InvalidVariantIndex,
    #[error("root block is not contained in list of basic blocks")]
    NoRoot,
    #[error("listing contains no basic blocks")]
    NoBlocks,
}

impl DisassemblyListing {
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

        let cfg = f.cfg(project.icfg(), project.code_blocks());

        let mut ids = BTreeMap::new(); // NodeIndex -> DisassemblyBlockId (u64)
        let blks = project.code_blocks();

        let irb = project.lifter().irb(1024);
        let mut pctx = ParserContext::empty(&irb, project.lifter().translator().manager());
        let mut dctx = project.lifter().context();

        for (nx, &bid) in cfg.node_references() {
            ids.insert(
                nx,
                slf.push_block(project, &irb, &mut pctx, &mut dctx, &blks[bid]),
            );
        }

        for edge in cfg.edge_references() {
            let s = ids[&edge.source()];
            let t = ids[&edge.target()];
            slf.push_edge(s, t, edge.weight());
        }

        slf.root = ids[&cfg.entry()];
        slf
    }

    fn push_block<'ad, 'ap>(
        &mut self,
        project: &'ad Project,
        irb: &'ad IRBuilderArena,
        pctx: &mut ParserContext<'ad, 'ap>,
        dctx: &mut ContextDatabase,
        blk: &CodeBlock,
    ) -> DisassemblyBlockId {
        let id = self.blocks.len();

        self.blocks.push(DisassemblyBlock {
            instructions: blk
                .insns()
                .iter()
                .map(|insn| Instruction {
                    address: insn.address,
                    value: {
                        let bytes = project.memory().view_bytes_from(insn.address()).unwrap();
                        let insnt = Insn::disassemble(
                            project.lifter(),
                            &irb,
                            dctx,
                            pctx,
                            insn.address(),
                            bytes,
                        )
                        .unwrap();

                        if insnt.operands.is_empty() {
                            String::from(&*insnt.mnemonic)
                        } else {
                            format!("{} {}", insnt.mnemonic, insnt.operands)
                        }
                    },
                })
                .collect(),
            attributes: AttributeMap::new(),
        });
        id as _
    }

    fn push_edge(&mut self, source: DisassemblyBlockId, target: DisassemblyBlockId, _: &FlowKind) {
        self.edges.push(DisassemblyEdge {
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

    pub fn entry(&self) -> Option<&DisassemblyBlock> {
        self.blocks.get(self.root as usize)
    }

    pub fn blocks(&self) -> &[DisassemblyBlock] {
        &self.blocks
    }

    pub fn edges(&self) -> &[DisassemblyEdge] {
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
