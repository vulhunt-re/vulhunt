use std::collections::BTreeMap;
use std::ops::Range;

use iset::IntervalMap;

use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct AnnotationRef {
    name: String,
    offset: Address,
}

impl AnnotationRef {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn offset(&self) -> Address {
        self.offset
    }
}

#[derive(Debug, Clone, Default)]
struct AnnotationScope {
    start: usize,

    offsets: Vec<Address>,
    calls: Vec<Address>,

    constants: Vec<AnnotationRef>,

    globals: Vec<AnnotationRef>,
    locals: Vec<String>,

    function_names: Vec<AnnotationRef>,
    params: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DecompilerAnnotationDB {
    offsets: IntervalMap<usize, Address>,
    offsets_to_positions: BTreeMap<Address, Vec<Range<usize>>>,

    calls: IntervalMap<usize, Address>,
    calls_to_positions: BTreeMap<Address, Vec<Range<usize>>>,

    constants: IntervalMap<usize, AnnotationRef>,

    globals: IntervalMap<usize, AnnotationRef>,
    globals_to_positions: BTreeMap<Address, Vec<Range<usize>>>,

    locals: IntervalMap<usize, String>,
    locals_to_positions: AHashMap<String, Vec<Range<usize>>>,

    function_names: IntervalMap<usize, AnnotationRef>,
    params: IntervalMap<usize, String>,

    scopes: Vec<AnnotationScope>,

    source: String,
}

impl DecompilerAnnotationDB {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            ..Default::default()
        }
    }

    pub(crate) fn open_scope(&mut self, start: usize) {
        self.scopes.push(AnnotationScope {
            start,
            ..Default::default()
        })
    }

    fn current_scope(&mut self) -> &mut AnnotationScope {
        self.scopes.last_mut().unwrap()
    }

    pub(crate) fn close_scope(&mut self, end: usize) {
        let Some(scope) = self.scopes.pop() else {
            return;
        };
        let start = scope.start;

        for offset in scope.offsets {
            self.offsets_to_positions
                .entry(offset)
                .or_default()
                .push(start..end + 1);
            self.offsets.insert(start..end + 1, offset);
        }

        for call in scope.calls {
            self.calls_to_positions
                .entry(call)
                .or_default()
                .push(start..end + 1);
            self.calls.insert(start..end + 1, call);
        }

        for constant in scope.constants {
            self.constants.insert(start..end + 1, constant);
        }

        for global in scope.globals {
            self.globals_to_positions
                .entry(global.offset())
                .or_default()
                .push(start..end + 1);
            self.globals.insert(start..end + 1, global);
        }

        for local in scope.locals {
            self.locals_to_positions
                .entry(local.clone())
                .or_default()
                .push(start..end + 1);
            self.locals.insert(start..end + 1, local);
        }

        for name in scope.function_names {
            self.function_names.insert(start..end + 1, name);
        }

        for param in scope.params {
            self.params.insert(start..end + 1, param);
        }

        if self.scopes.is_empty() {
            self.scopes = Vec::with_capacity(0);
        }
    }

    pub(crate) fn annotate_offset(&mut self, offset: u64) {
        self.current_scope().offsets.push(offset.into());
    }

    pub(crate) fn annotate_function_call(&mut self, offset: u64) {
        self.current_scope().calls.push(offset.into());
    }

    pub(crate) fn annotate_constant(&mut self, name: String, value: u64) {
        self.current_scope().constants.push(AnnotationRef {
            name,
            offset: value.into(),
        });
    }

    pub(crate) fn annotate_function_name(&mut self, name: String, value: u64) {
        self.current_scope().function_names.push(AnnotationRef {
            name,
            offset: value.into(),
        });
    }

    pub(crate) fn annotate_global_variable(&mut self, name: String, value: u64) {
        self.current_scope().globals.push(AnnotationRef {
            name,
            offset: value.into(),
        });
    }

    pub(crate) fn annotate_local_variable(&mut self, name: String) {
        self.current_scope().locals.push(name);
    }

    pub(crate) fn annotate_function_parameter(&mut self, name: String) {
        self.current_scope().params.push(name);
    }

    pub(crate) fn annotate_source(&mut self, code: String) {
        self.source = code;
    }

    pub fn call_positions(&self) -> &BTreeMap<Address, Vec<Range<usize>>> {
        &self.calls_to_positions
    }

    pub fn calls(&self) -> &IntervalMap<usize, Address> {
        &self.calls
    }

    pub fn global_variable_positions(&self) -> &BTreeMap<Address, Vec<Range<usize>>> {
        &self.globals_to_positions
    }

    pub fn global_variables(&self) -> &IntervalMap<usize, AnnotationRef> {
        &self.globals
    }

    pub fn local_variable_positions(&self) -> &AHashMap<String, Vec<Range<usize>>> {
        &self.locals_to_positions
    }

    pub fn local_variables(&self) -> &IntervalMap<usize, String> {
        &self.locals
    }

    pub fn position_to_address(&self) -> &IntervalMap<usize, Address> {
        &self.offsets
    }

    pub fn address_to_position(&self) -> &BTreeMap<Address, Vec<Range<usize>>> {
        &self.offsets_to_positions
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}
