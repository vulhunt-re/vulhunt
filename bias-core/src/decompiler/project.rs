use std::collections::BTreeSet;
use std::mem::transmute;
use std::time::Duration;

use crate::decompiler::error::DecompilerError;
use crate::decompiler::ffi::{AddressRange, GhidraDecompiler, VariableNameRef};
use crate::decompiler::symbols::DecompilerSymbolResolver;
use crate::decompiler::types::{
    DataType, DataTypeRef, DecompilerTypeDB, DecompilerTypeResolver, SpaceKind, VarInfo,
};
use crate::prelude::*;

pub trait DecompilerResolver: DecompilerSymbolResolver + DecompilerTypeResolver {}

impl<T> DecompilerResolver for T where T: DecompilerSymbolResolver + DecompilerTypeResolver {}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefaultDecompilerResolver;

impl DecompilerSymbolResolver for DefaultDecompilerResolver {}
impl DecompilerTypeResolver for DefaultDecompilerResolver {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecompilerConfig {
    pub fail_fast: bool,
    pub timeout: Option<Duration>,
    pub read_only_regions: Option<BTreeSet<(u64, usize)>>,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompilerConfig {
    pub fn new() -> Self {
        Self {
            fail_fast: false,
            timeout: None,
            read_only_regions: None,
        }
    }

    pub fn with_fail_fast(self, toggle: bool) -> Self {
        Self {
            fail_fast: toggle,
            ..self
        }
    }

    pub fn with_timeout(self, duration: impl Into<Option<Duration>>) -> Self {
        Self {
            timeout: duration.into(),
            ..self
        }
    }

    pub fn timeout(&self) -> u64 {
        self.timeout
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn without_read_only_regions() -> Self {
        Self::default().with_read_only_regions([])
    }

    pub fn clear_read_only_regions(&mut self) {
        self.read_only_regions = None
    }

    pub fn set_read_only_regions(
        &mut self,
        read_only_regions: impl IntoIterator<Item = (u64, usize)>,
    ) {
        self.read_only_regions = Some(
            read_only_regions
                .into_iter()
                .scan(0u64, |prev_end, (start, size)| {
                    (start >= *prev_end && size > 0).then(|| {
                        *prev_end = start.saturating_add(size as u64);
                        (start, size)
                    })
                })
                .collect(),
        )
    }

    pub fn with_read_only_regions(
        mut self,
        read_only_regions: impl IntoIterator<Item = (u64, usize)>,
    ) -> Self {
        self.set_read_only_regions(read_only_regions);
        self
    }
}

pub struct DecompilerProjectRef<'a> {
    project: Option<&'a Project>,
    memory: Option<&'a Memory>,
    typedb: Option<&'a TypeDB>,
    resolver: Box<dyn DecompilerResolver>,
    config: DecompilerConfig,
}

impl<'a> DecompilerProjectRef<'a> {
    pub(crate) fn boxed<T>(
        project: &'a Project,
        typedb: &'a TypeDB,
        resolver: T,
        config: DecompilerConfig,
    ) -> Box<Self>
    where
        T: DecompilerResolver + 'static,
    {
        Box::new(Self {
            project: Some(project),
            memory: Some(project.memory()),
            typedb: Some(typedb),
            resolver: Box::new(resolver),
            config,
        })
    }

    pub(crate) fn minimal(memory: &'a Memory, typedb: &'a TypeDB) -> Box<Self> {
        Box::new(Self {
            project: None,
            memory: Some(memory),
            typedb: Some(typedb),
            resolver: Box::new(DefaultDecompilerResolver::default()),
            config: DecompilerConfig::default(),
        })
    }

    pub(crate) fn invalidate(&mut self) {
        self.project = None;
        self.memory = None;
        self.typedb = None;
    }

    pub(crate) fn set_typedb(&mut self, typedb: &'a TypeDB) {
        self.typedb = Some(typedb);
    }

    pub(crate) fn set_project(&mut self, project: &'a Project) {
        self.project = Some(project);
        self.memory = Some(project.memory());
        self.typedb = Some(project.type_db());
    }

    pub(crate) fn set_memory_and_typedb(&mut self, memory: &'a Memory, typedb: &'a TypeDB) {
        self.project = None;
        self.memory = Some(memory);
        self.typedb = Some(typedb);
    }

    pub(crate) fn read_only_regions(&self) -> Vec<AddressRange> {
        if let Some(regions) = self.config.read_only_regions.as_ref() {
            regions
                .into_iter()
                .map(|(addr, size)| AddressRange {
                    addr: *addr,
                    size: *size,
                })
                .collect()
        } else {
            self.regions_where(|r| r.is_code() || r.is_read_only())
        }
    }

    pub(crate) fn config(&self) -> &DecompilerConfig {
        &self.config
    }

    pub(crate) fn code_regions(&self) -> Vec<AddressRange> {
        self.regions_where(|r| r.is_code())
    }

    fn regions_where<F>(&self, f: F) -> Vec<AddressRange>
    where
        F: Fn(&Region) -> bool,
    {
        self.memory
            .expect("valid state")
            .regions()
            .unsorted_values()
            .filter_map(|v| {
                if f(v) {
                    Some(AddressRange {
                        addr: v.address().offset(),
                        size: v.len(),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    pub(crate) fn read_bytes(
        &self,
        address: u64,
        size: usize,
        into: *mut u8,
    ) -> Result<(), DecompilerError> {
        if into.is_null() {
            return Err(DecompilerError::Ffi("nullptr passed to read_bytes"));
        }

        let memory = self.memory.expect("valid state");

        let region = memory
            .find_region(Address::from(address))
            .ok_or_else(|| DecompilerError::Ffi("invalid address range"))?;

        if let Some(bytes) = region.view_bytes(Address::from(address), size).ok() {
            // fast path

            let into = unsafe { std::slice::from_raw_parts_mut(into, size) };
            into.copy_from_slice(bytes);

            return Ok(());
        }

        // could not read contiguous region; get region containing second part
        let end_address = Address::from(address) + size;

        if let Some(region_rest) = memory.find_region(end_address) {
            let into = unsafe { std::slice::from_raw_parts_mut(into, size) };

            let first = region.view_bytes_from(Address::from(address)).unwrap();
            into[..first.len()].copy_from_slice(first);
            into[first.len()..].fill(0);

            let second_range = usize::from(end_address - region_rest.address());
            if second_range != 0 {
                let second = region_rest
                    .view_bytes(region_rest.address(), second_range)
                    .unwrap();
                into[size - second_range..].copy_from_slice(second);
            }
        } else {
            // no second part that overlaps; copy what we can
            let rest = region.view_bytes_from(Address::from(address)).unwrap();
            let into = unsafe { std::slice::from_raw_parts_mut(into, size) };

            into[..rest.len()].copy_from_slice(rest);
            into[rest.len()..].fill(0);
        }

        Ok(())
    }

    pub(crate) fn update_name(
        &self,
        _decompiler: *mut GhidraDecompiler<'a>,
        var: VarInfo,
        name: VariableNameRef,
        uses: &[u64],
        dtype: *mut DataType,
    ) -> Result<String, DecompilerError> {
        let empty = String::with_capacity(0); // will not allocate
        let Some(project) = self.project.as_ref() else {
            return Ok(empty);
        };

        let name = name.to_string_lossy();
        let Some(type_) = DataTypeRef::new(dtype) else {
            return Ok(empty);
        };

        if let Some(n) = match var.space {
            SpaceKind::Global => self.resolver.resolve_global_variable_symbol(
                project,
                name.as_ref(),
                unsafe { transmute(uses) },
                var.offset.into(),
                type_,
                var.size as _,
            ),
            SpaceKind::Stack => self.resolver.resolve_stack_variable_symbol(
                project,
                name.as_ref(),
                unsafe { transmute(uses) },
                var.offset as i64,
                type_,
                var.size as _,
            ),
            SpaceKind::Register => {
                if project
                    .lifter()
                    .translator()
                    .registers()
                    .get(var.offset, var.size as _)
                    .is_some()
                {
                    self.resolver.resolve_register_symbol(
                        project,
                        name.as_ref(),
                        unsafe { transmute(uses) },
                        Var::new0(project.lifter().register_space(), var.offset, var.size * 8),
                        type_,
                    )
                } else {
                    None
                }
            }
            SpaceKind::Unique => self.resolver.resolve_temporary_symbol(
                project,
                name.as_ref(),
                unsafe { transmute(uses) },
                Var::new0(project.lifter().temporary_space(), var.offset, var.size * 8),
                type_,
            ),
            _ => None,
        } {
            return Ok(n);
        }
        Ok(empty)
    }

    pub(crate) fn type_at(
        &self,
        decompiler: *mut GhidraDecompiler<'a>,
        at: u64,
        var: VarInfo,
    ) -> Result<*mut DataType, DecompilerError> {
        let tdb = self.typedb.expect("valid state");

        let mut typedb = DecompilerTypeDB {
            typedb: tdb,
            ghidra: unsafe {
                decompiler
                    .as_mut()
                    .ok_or_else(|| DecompilerError::Ffi("nullptr passed to type_at"))?
            },
        };

        let Some(project) = self.project else {
            // apply a best-effort for global variables
            if var.space == SpaceKind::Global {
                if let Some(t) = tdb.get_data_type_at(var.offset.into()) {
                    return typedb.build_type_checked(&t);
                }
            }
            return Ok(std::ptr::null_mut());
        };

        if let Some(t) = match var.space {
            SpaceKind::Global => self.resolver.resolve_global_variable_type(
                project,
                at.into(),
                var.offset.into(),
                var.size as _,
            ),
            SpaceKind::Stack => self.resolver.resolve_stack_variable_type(
                project,
                at.into(),
                var.offset as i64,
                var.size as _,
            ),
            SpaceKind::Register => {
                if project
                    .lifter()
                    .translator()
                    .registers()
                    .get(var.offset, var.size as _)
                    .is_some()
                {
                    self.resolver.resolve_register_type(
                        project,
                        at.into(),
                        Var::new0(project.lifter().register_space(), var.offset, var.size * 8),
                    )
                } else {
                    None
                }
            }
            SpaceKind::Unique => self.resolver.resolve_temporary_type(
                project,
                at.into(),
                Var::new0(project.lifter().temporary_space(), var.offset, var.size * 8),
            ),
            _ => None,
        } {
            Ok(typedb
                .build_type_checked(&t)
                .unwrap_or_else(|_| std::ptr::null_mut()))
        } else {
            Ok(std::ptr::null_mut())
        }
    }
}
