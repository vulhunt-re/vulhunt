use std::collections::HashSet;
use std::marker::PhantomData;
use std::mem;
use std::path::Path;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use replace_with::replace_with_or_abort_and_return;

use crate::fugue::ir::LanguageDB;
use crate::kb::Lazy;
use crate::prelude::*;

mod ffi;
pub use ffi::FlowOverride;

pub mod annotation;

pub mod platform;
pub use annotation::DecompilerAnnotationDB;

pub mod analyses;

pub mod ast;
pub use ast::DecompilerAst;
use ast::HighVarInfo;

pub mod compiler;
pub use compiler::SleighCompiler;

pub mod error;
pub use error::DecompilerError;

mod project;
use project::DecompilerProjectRef;
pub use project::{DecompilerConfig, DecompilerResolver, DefaultDecompilerResolver};

pub mod signature;
pub use signature::{FunctionSignature, FunctionSignatureConfig};

pub mod symbols;
pub use symbols::DecompilerSymbolResolver;

pub mod types;
pub use types::{
    DataTypeKind, DataTypeRef, DataTypeSubKind, DecompilerTypeDB, DecompilerTypeResolver,
    DefaultDecompilerTypeResolver,
};

static DECOMPILER_MUTEX: Lazy<Arc<Mutex<HashSet<String>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashSet::new())));
static DECOMPILER_INIT: Once = Once::new();

#[inline(always)]
fn ensure_init() {
    unsafe {
        DECOMPILER_INIT
            .call_once(|| ffi::ghidra_decompiler_init().expect("decompiler initialisation"))
    }
}

pub fn add_search_paths(root: impl AsRef<Path>) -> Result<(), DecompilerError> {
    let ldb = LanguageDB::from_directory_with(root.as_ref(), true)
        .map_err(DecompilerError::SearchPathDiscover)?;

    let mut roots = HashSet::new();

    for builder in ldb.iter() {
        if let Some(root) = builder
            .language()
            .sla_file()
            .parent()
            .and_then(|root| root.to_str())
        {
            if roots.insert(root) {
                add_search_path_hint(root)?;
            }
        }
    }

    Ok(())
}

pub fn add_search_path_hint(root: impl AsRef<Path>) -> Result<(), DecompilerError> {
    ensure_init();

    let Some(path) = root.as_ref().to_str() else {
        return Err(DecompilerError::Ffi(
            "cannot convert search path hint to valid C++ string",
        ));
    };

    let mut mutex = DECOMPILER_MUTEX.lock().unwrap();

    let result = if !mutex.contains(path) {
        cxx::let_cxx_string!(cxx_path = path);

        let result = unsafe { ffi::ghidra_decompiler_scan_for_sleigh_directories(&cxx_path) };
        if result.is_ok() {
            mutex.insert(path.to_owned());
        }

        result
    } else {
        Ok(())
    };

    drop(mutex);

    result.map_err(DecompilerError::SearchPath)
}

pub fn add_search_path(path: impl AsRef<Path>) -> Result<(), DecompilerError> {
    ensure_init();

    let Some(path) = path.as_ref().to_str() else {
        return Err(DecompilerError::Ffi(
            "cannot convert search path to valid C++ string",
        ));
    };

    let mut mutex = DECOMPILER_MUTEX.lock().unwrap();

    let result = if !mutex.contains(path) {
        cxx::let_cxx_string!(cxx_path = path);

        let result = unsafe { ffi::ghidra_decompiler_push_sleigh_path(&cxx_path) };
        if result.is_ok() {
            mutex.insert(path.to_owned());
        }

        result
    } else {
        Ok(())
    };

    result.map_err(DecompilerError::SearchPath)
}

pub struct DecompilerState {
    ghidra: cxx::UniquePtr<ffi::GhidraDecompiler<'static>>,
    _marker: PhantomData<&'static Project>,
}

#[cfg(not(doctest))]
impl DecompilerState {
    /// This function essentially performs an in-place map over the decompiler state:
    ///
    /// ```
    /// let mut decompiler = Decompiler::from_state(self, project);
    /// let result = f(&mut decompiler);
    /// self = decompiler.into_state();
    /// result
    /// ```
    ///
    /// # Safety
    ///
    /// If `f` panics, then we trigger a `std::process::abort`, since the state owned by
    /// `DecompilerState` cannot be safely restored.
    ///
    pub fn apply<'a, T, E, F>(&'a mut self, project: &'a Project, mut f: F) -> Result<T, E>
    where
        F: FnMut(&mut Decompiler<'a>) -> Result<T, E>,
    {
        replace_with_or_abort_and_return(self, |state| {
            let mut decompiler = Decompiler::from_state(state, project);
            let result = f(&mut decompiler);
            let state = decompiler.into_state();
            (result, state)
        })
    }

    /// This function essentially performs an in-place map over the decompiler state:
    ///
    /// ```
    /// let mut decompiler = Decompiler::from_minimal_state(self, memory, typedb);
    /// let result = f(&mut decompiler);
    /// self = decompiler.into_state();
    /// result
    /// ```
    ///
    /// # Safety
    ///
    /// If `f` panics, then we trigger a `std::process::abort`, since the state owned by
    /// `DecompilerState` cannot be safely restored.
    ///
    pub fn apply_minimal<'a, T, E, F>(
        &'a mut self,
        memory: &'a Memory,
        typedb: &'a TypeDB,
        mut f: F,
    ) -> Result<T, E>
    where
        F: FnMut(&mut Decompiler<'a>) -> Result<T, E>,
    {
        replace_with_or_abort_and_return(self, |state| {
            let mut decompiler = Decompiler::from_minimal_state(state, memory, typedb);
            let result = f(&mut decompiler);
            let state = decompiler.into_state();
            (result, state)
        })
    }

    /// This function essentially performs an in-place map over the decompiler state:
    ///
    /// ```
    /// let mut decompiler = Decompiler::from_state_with_types(self, project, typedb);
    /// let result = f(&mut decompiler);
    /// self = decompiler.into_state();
    /// result
    /// ```
    ///
    /// # Safety
    ///
    /// If `f` panics, then we trigger a `std::process::abort`, since the state owned by
    /// `DecompilerState` cannot be safely restored.
    ///
    pub fn apply_with_types<'a, T, E, F>(
        &'a mut self,
        project: &'a Project,
        typedb: &'a TypeDB,
        mut f: F,
    ) -> Result<T, E>
    where
        F: FnMut(&mut Decompiler<'a>) -> Result<T, E>,
    {
        replace_with_or_abort_and_return(self, |state| {
            let mut decompiler = Decompiler::from_state_with_types(state, project, typedb);
            let result = f(&mut decompiler);
            let state = decompiler.into_state();
            (result, state)
        })
    }
}

pub struct Decompiler<'a> {
    ghidra: cxx::UniquePtr<ffi::GhidraDecompiler<'a>>,
    typedb: &'a TypeDB,
    config: DecompilerConfig,
}

impl<'a> Decompiler<'a> {
    pub fn new(project: &'a Project) -> Result<Self, DecompilerError> {
        Self::new_with(project, DefaultDecompilerResolver::default())
    }

    pub fn new_with<T>(project: &'a Project, resolver: T) -> Result<Self, DecompilerError>
    where
        T: DecompilerResolver + 'static,
    {
        Self::new_with_types(project, project.type_db(), resolver)
    }

    pub fn new_with_types<T>(
        project: &'a Project,
        typedb: &'a TypeDB,
        resolver: T,
    ) -> Result<Self, DecompilerError>
    where
        T: DecompilerResolver + 'static,
    {
        Self::new_with_config(project, typedb, resolver, DecompilerConfig::default())
    }

    pub fn new_with_config<T>(
        project: &'a Project,
        typedb: &'a TypeDB,
        resolver: T,
        config: DecompilerConfig,
    ) -> Result<Self, DecompilerError>
    where
        T: DecompilerResolver + 'static,
    {
        ensure_init();

        let arch = project.lifter().translator().architecture();
        let conv = project.lifter().convention().name();
        let spec = format!(
            "{}:{}:{}:{}:{}",
            arch.processor(),
            if arch.endian().is_little() {
                "LE"
            } else {
                "BE"
            },
            arch.bits(),
            arch.variant(),
            conv,
        );

        cxx::let_cxx_string!(cxx_spec = spec);

        let proj = DecompilerProjectRef::boxed(project, typedb, resolver, config.to_owned());

        let lock = DECOMPILER_MUTEX.lock().unwrap();

        let result = unsafe { ffi::ghidra_decompiler_new(&cxx_spec, proj) }
            .map_err(|e| DecompilerError::Init(e));

        drop(lock);

        let ghidra = result?;

        Ok(Self {
            ghidra,
            typedb,
            config,
        })
    }

    pub fn minimal(
        lifter: &Lifter,
        memory: &'a Memory,
        typedb: &'a TypeDB,
    ) -> Result<Self, DecompilerError> {
        ensure_init();

        let arch = lifter.translator().architecture();
        let conv = lifter.convention().name();
        let spec = format!(
            "{}:{}:{}:{}:{}",
            arch.processor(),
            if arch.endian().is_little() {
                "LE"
            } else {
                "BE"
            },
            arch.bits(),
            arch.variant(),
            conv,
        );

        cxx::let_cxx_string!(cxx_spec = spec);

        let proj = DecompilerProjectRef::minimal(memory, typedb);

        let lock = DECOMPILER_MUTEX.lock().unwrap();

        let result = unsafe { ffi::ghidra_decompiler_new(&cxx_spec, proj) }
            .map_err(|e| DecompilerError::Init(e));

        drop(lock);

        let ghidra = result?;

        Ok(Self {
            ghidra,
            typedb,
            config: DecompilerConfig::default(),
        })
    }

    pub fn from_minimal_state(
        mut state: DecompilerState,
        memory: &'a Memory,
        typedb: &'a TypeDB,
    ) -> Self {
        unsafe {
            let pr = state.ghidra.pin_mut().project_ref();
            let config = pr.config().clone();
            pr.set_memory_and_typedb(memory, typedb);

            Self {
                ghidra: mem::transmute(state.ghidra),
                typedb,
                config,
            }
        }
    }

    pub fn from_state(state: DecompilerState, project: &'a Project) -> Self {
        Self::from_state_with_types(state, project, project.type_db())
    }

    pub fn from_state_with_types(
        mut state: DecompilerState,
        project: &'a Project,
        typedb: &'a TypeDB,
    ) -> Self {
        unsafe {
            let pr = state.ghidra.pin_mut().project_ref();
            let config = pr.config().clone();
            pr.set_project(project);
            pr.set_typedb(typedb);

            Self {
                ghidra: mem::transmute(state.ghidra),
                typedb,
                config,
            }
        }
    }

    pub fn into_state(mut self) -> DecompilerState {
        unsafe {
            self.ghidra.pin_mut().project_ref().invalidate();
        }
        DecompilerState {
            ghidra: unsafe { mem::transmute(self.ghidra) },
            _marker: PhantomData::default(),
        }
    }

    fn type_db<'b>(&'b mut self) -> DecompilerTypeDB<'b, 'a> {
        DecompilerTypeDB {
            ghidra: unsafe { self.ghidra.pin_mut().get_unchecked_mut() },
            typedb: self.typedb,
        }
    }

    pub fn set_typedb(&mut self, typedb: &'a TypeDB) {
        self.typedb = typedb;
        unsafe { self.ghidra.pin_mut().project_ref().set_typedb(typedb) };
    }

    pub fn try_decompile_at(
        &mut self,
        address: impl Into<Address>,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<String, DecompilerError> {
        let address = address.into();
        let timeout_ms = timeout
            .into()
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|| self.config.timeout());

        unsafe {
            self.ghidra
                .pin_mut()
                .decompile(address.offset(), timeout_ms)
        }
        .map_err(|e| DecompilerError::Decompile(address, e))
    }

    pub fn decompile_at(&mut self, address: impl Into<Address>) -> Result<String, DecompilerError> {
        self.try_decompile_at(address, None)
    }

    pub fn try_debug_decompile_at(
        &mut self,
        address: impl Into<Address>,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<String, DecompilerError> {
        let address = address.into();
        let timeout_ms = timeout
            .into()
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|| self.config.timeout());

        unsafe {
            self.ghidra
                .pin_mut()
                .decompile_xml(address.offset(), timeout_ms)
        }
        .map_err(|e| DecompilerError::Decompile(address, e))
    }

    pub fn debug_decompile_at(
        &mut self,
        address: impl Into<Address>,
    ) -> Result<String, DecompilerError> {
        self.try_debug_decompile_at(address, None)
    }

    pub fn try_decompile_ast_at(
        &mut self,
        address: impl Into<Address>,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<DecompilerAst, DecompilerError> {
        let address = address.into();
        let timeout_ms = timeout
            .into()
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|| self.config.timeout());

        let mut annotations = DecompilerAnnotationDB::new();
        let mut tables = Vec::new();
        let mut params = Vec::new();
        let mut vars = Vec::new();

        unsafe {
            self.ghidra.pin_mut().decompile_ast(
                address.offset(),
                timeout_ms,
                &mut annotations,
                &mut tables,
                &mut params,
                &mut vars,
            )
        }
        .map_err(|e| DecompilerError::Decompile(address, e))?;

        let bits = unsafe {
            self.ghidra
                .address_bits()
                .map_err(|e| DecompilerError::GetArchInfo(e))?
        };

        let vars = vars
            .into_iter()
            .map(|v| HighVarInfo::new(v, self.typedb, bits))
            .collect();

        DecompilerAst::new(annotations, tables, params, vars)
    }

    pub fn decompile_ast_at(
        &mut self,
        address: impl Into<Address>,
    ) -> Result<DecompilerAst, DecompilerError> {
        self.try_decompile_ast_at(address, None)
    }

    pub fn try_debug_decompile(
        &mut self,
        f: &'a Function,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<String, DecompilerError> {
        if let Some(name) = f.name() {
            // no override
            self.try_add_function_symbol(name, f.address(), false)?;
        }

        if f.is_tmode() {
            self.set_context_variable("TMode", f.address(), 1)?;
        }

        self.try_debug_decompile_at(f.address(), timeout)
    }

    pub fn debug_decompile(&mut self, f: &'a Function) -> Result<String, DecompilerError> {
        self.try_debug_decompile(f, None)
    }

    pub fn try_decompile(
        &mut self,
        f: &'a Function,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<String, DecompilerError> {
        if let Some(name) = f.name() {
            // no override
            self.try_add_function_symbol(name, f.address(), false)?;
        }

        if f.is_tmode() {
            self.set_context_variable("TMode", f.address(), 1)?;
        }

        self.try_decompile_at(f.address(), timeout)
    }

    pub fn decompile(&mut self, f: &'a Function) -> Result<String, DecompilerError> {
        self.try_decompile(f, None)
    }

    pub fn try_decompile_ast(
        &mut self,
        f: &'a Function,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<DecompilerAst, DecompilerError> {
        if let Some(name) = f.name() {
            // no override
            self.try_add_function_symbol(name, f.address(), false)?;
        }

        if f.is_tmode() {
            self.set_context_variable("TMode", f.address(), 1)?;
        }

        self.try_decompile_ast_at(f.address(), timeout)
    }

    pub fn decompile_ast(&mut self, f: &'a Function) -> Result<DecompilerAst, DecompilerError> {
        self.try_decompile_ast(f, None)
    }

    pub fn generate_signature(
        &mut self,
        f: &'a Function,
        config: FunctionSignatureConfig,
    ) -> Result<FunctionSignature, DecompilerError> {
        self.try_generate_signature(f, None, config)
    }

    pub fn try_generate_signature(
        &mut self,
        f: &'a Function,
        timeout: impl Into<Option<Duration>>,
        config: FunctionSignatureConfig,
    ) -> Result<FunctionSignature, DecompilerError> {
        if f.is_tmode() {
            self.set_context_variable("TMode", f.address(), 1)?;
        }
        self.try_generate_signature_at(f.address(), timeout, config)
    }

    pub fn generate_signature_at(
        &mut self,
        address: impl Into<Address>,
        config: FunctionSignatureConfig,
    ) -> Result<FunctionSignature, DecompilerError> {
        self.try_generate_signature_at(address, None, config)
    }

    pub fn try_generate_signature_at(
        &mut self,
        address: impl Into<Address>,
        timeout: impl Into<Option<Duration>>,
        config: FunctionSignatureConfig,
    ) -> Result<FunctionSignature, DecompilerError> {
        let address = address.into();
        let timeout_ms = timeout
            .into()
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|| self.config.timeout());

        let mut sig = ffi::FunctionSignature::default();

        unsafe {
            self.ghidra.pin_mut().function_signature(
                address.offset(),
                timeout_ms,
                config.settings(),
                config.max_dfg_iters.max(1),
                config.max_block_iters.max(1),
                config.max_varnodes.max(0),
                &mut sig,
            )
        }
        .map_err(|e| DecompilerError::GenerateSignature(address, e))?;

        Ok(FunctionSignature::from(sig))
    }

    pub fn set_function_variable_type_at(
        &mut self,
        address: impl Into<Address>,
        var_name: impl AsRef<str>,
        type_: &Term<Type>,
    ) -> Result<(), DecompilerError> {
        let dtype = self.type_db().build_type_checked(type_)?;

        cxx::let_cxx_string!(cxx_name = var_name.as_ref());
        let func_start = address.into();

        unsafe {
            self.ghidra.pin_mut().set_function_variable_type_at(
                u64::from(func_start),
                &cxx_name,
                dtype,
            )
        }
        .map_err(|e| DecompilerError::SetType(func_start, e))?;

        Ok(())
    }

    pub fn set_function_variable_type(
        &mut self,
        f: &'a Function,
        var_name: impl AsRef<str>,
        type_: &Term<Type>,
    ) -> Result<(), DecompilerError> {
        self.set_function_variable_type_at(f.address(), var_name, type_)
    }

    pub fn get_context_variable(
        &self,
        var: impl AsRef<str>,
        at: impl Into<Address>,
    ) -> Result<u32, DecompilerError> {
        let address = at.into();
        cxx::let_cxx_string!(name = var.as_ref());
        self.ghidra
            .get_variable(&name, address.offset())
            .map_err(DecompilerError::GetContext)
    }

    pub fn set_context_variable(
        &mut self,
        var: impl AsRef<str>,
        at: impl Into<Address>,
        val: u32,
    ) -> Result<(), DecompilerError> {
        let address = at.into();
        cxx::let_cxx_string!(name = var.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .set_variable(&name, address.offset(), val)
                .map_err(DecompilerError::SetContext)?;
        }
        Ok(())
    }

    pub fn add_type(&mut self, t: &Term<Type>) -> Result<(), DecompilerError> {
        if matches!(
            t.kind(),
            TypeKind::Named(_, _)
                | TypeKind::Struct(_, _, _)
                | TypeKind::Enum(_, _, _)
                | TypeKind::Union(_, _, _)
        ) {
            self.type_db().build_type_checked(t)?;
        }
        Ok(())
    }

    pub fn remove_type(&mut self, t: &Term<Type>) -> Result<(), DecompilerError> {
        let nm = match t.kind() {
            TypeKind::Enum(nm, _, _)
            | TypeKind::Named(nm, _)
            | TypeKind::Struct(nm, _, _)
            | TypeKind::Union(nm, _, _) => nm,
            _ => {
                return Ok(());
            }
        };
        let Ok(dt) = self.type_db().get_type_checked(nm) else {
            return Ok(());
        };
        self.type_db().remove_type(dt)
    }

    pub fn add_function_symbol(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        self.try_add_function_symbol(name, addr, true)
    }

    pub fn add_function_symbol_with(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        type_: &Term<Type>,
        variadic: bool,
    ) -> Result<(), DecompilerError> {
        self.try_add_function_symbol_with(name, addr, type_, variadic, true)
    }

    pub fn try_add_function_symbol(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        force: bool,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_function_symbol(&name, addr.offset(), force)
                .map_err(|e| DecompilerError::SetSymbol(addr, e))
        }
    }

    pub fn try_add_function_symbol_with(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        type_: &Term<Type>,
        variadic: bool,
        force: bool,
    ) -> Result<(), DecompilerError> {
        let TypeKind::Function(rt, args) = type_.kind() else {
            return Err(DecompilerError::InvalidFunctionType);
        };

        let addr = addr.into();

        let mut input_names = Vec::new();
        let mut input_types = Vec::new();

        for (i, arg) in args.iter().enumerate() {
            let name = arg
                .name()
                .unwrap_or_else(|| Ustr::from(&*compact_str::format_compact!("arg_{i}")));
            let type_ = self.type_db().build_type_checked(arg.type_())?;

            input_names.push(name.as_str());
            input_types.push(type_);
        }

        let rtype = self.type_db().build_type_checked(rt)?;

        cxx::let_cxx_string!(name = name.as_ref());

        unsafe {
            self.ghidra
                .pin_mut()
                .add_function_symbol_with(
                    &name,
                    addr.offset(),
                    rtype,
                    &input_names,
                    &input_types,
                    variadic,
                    force,
                )
                .map_err(|e| DecompilerError::SetSymbol(addr, e))
        }
    }

    pub fn register_call_fixup(
        &mut self,
        name: impl AsRef<str>,
        fixup: impl AsRef<str>,
    ) -> Result<(), DecompilerError> {
        cxx::let_cxx_string!(name = name.as_ref());
        cxx::let_cxx_string!(fixup = fixup.as_ref());

        unsafe {
            self.ghidra
                .pin_mut()
                .register_call_fixup(&name, &fixup)
                .map_err(|e| DecompilerError::RegisterFixup(e))
        }
    }

    pub fn apply_call_fixup(
        &mut self,
        fixup: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(fixup = fixup.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .apply_call_fixup(&fixup, addr.offset())
                .map_err(|e| DecompilerError::ApplyFixup(e))
        }
    }

    pub fn apply_call_fixup_to_function(
        &mut self,
        fixup: impl AsRef<str>,
        f: &Function,
    ) -> Result<(), DecompilerError> {
        let addr = f.address();
        self.apply_call_fixup(fixup, addr)
    }

    pub fn clear_call_fixup(&mut self, addr: impl Into<Address>) -> Result<(), DecompilerError> {
        let addr = addr.into();
        unsafe {
            self.ghidra
                .pin_mut()
                .clear_call_fixup(addr.offset())
                .map_err(|e| DecompilerError::ClearFixup(e))
        }
    }

    pub fn clear_call_fixup_from_function(&mut self, f: &Function) -> Result<(), DecompilerError> {
        let addr = f.address();
        self.clear_call_fixup(addr)
    }

    pub fn add_extern(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_extern(&name, addr.offset())
                .map_err(|e| DecompilerError::SetSymbol(addr, e))
        }
    }

    pub fn add_global(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        t: &Term<Type>,
    ) -> Result<(), DecompilerError> {
        let t = self.type_db().build_type_checked(t)?;
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global(&name, addr.offset(), t)
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_const(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        t: &Term<Type>,
    ) -> Result<(), DecompilerError> {
        let t = self.type_db().build_type_checked(t)?;
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_with(&name, addr.offset(), t, true)
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_ascii_char(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_ascii_char(&name, addr.offset())
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_ascii_string(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        size: usize,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        if size == 0 {
            return Ok(());
        }

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_ascii_string(&name, addr.offset(), size)
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_ascii_pointer<const N: usize>(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_ascii_pointer(&name, addr.offset(), N)
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_utf16_char(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_utf16_char(&name, addr.offset())
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_utf16_string(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
        size: usize,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        if size == 0 {
            return Ok(());
        }

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_utf16_string(&name, addr.offset(), size)
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_utf16_pointer<const N: usize>(
        &mut self,
        name: impl AsRef<str>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        cxx::let_cxx_string!(name = name.as_ref());
        unsafe {
            self.ghidra
                .pin_mut()
                .add_global_utf16_pointer(&name, addr.offset(), N)
                .map_err(|e| DecompilerError::SetType(addr, e))
        }
    }

    pub fn add_comment(
        &mut self,
        comment: impl AsRef<str>,
        f: &Function,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let faddr = f.address();
        let addr = addr.into();
        let comment = comment.as_ref();

        unsafe {
            self.ghidra
                .pin_mut()
                .add_comment(comment, faddr.offset(), addr.offset())
                .map_err(|e| DecompilerError::SetComment(addr, faddr, e))
        }
    }

    pub fn add_comment_at(
        &mut self,
        comment: impl AsRef<str>,
        faddr: impl Into<Address>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let faddr = faddr.into();
        let addr = addr.into();
        let comment = comment.as_ref();

        unsafe {
            self.ghidra
                .pin_mut()
                .add_comment(comment, faddr.offset(), addr.offset())
                .map_err(|e| DecompilerError::SetComment(addr, faddr, e))
        }
    }

    pub fn remove_comments(
        &mut self,
        f: &Function,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let faddr = f.address();
        let addr = addr.into();

        unsafe {
            self.ghidra
                .pin_mut()
                .remove_comments(faddr.offset(), addr.offset())
                .map_err(|e| DecompilerError::DeleteComment(addr, faddr, e))
        }
    }

    pub fn remove_comments_at(
        &mut self,
        faddr: impl Into<Address>,
        addr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let faddr = faddr.into();
        let addr = addr.into();

        unsafe {
            self.ghidra
                .pin_mut()
                .remove_comments(faddr.offset(), addr.offset())
                .map_err(|e| DecompilerError::DeleteComment(addr, faddr, e))
        }
    }

    pub fn set_range_read_only(
        &mut self,
        addr: impl Into<Address>,
        size: usize,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        unsafe {
            self.ghidra
                .pin_mut()
                .set_range_read_only(addr.offset(), size)
                .map_err(|e| DecompilerError::SetRangeProperty(addr, size, e))
        }
    }

    pub fn set_range_writable(
        &mut self,
        addr: impl Into<Address>,
        size: usize,
    ) -> Result<(), DecompilerError> {
        let addr = addr.into();

        unsafe {
            self.ghidra
                .pin_mut()
                .set_range_writable(addr.offset(), size)
                .map_err(|e| DecompilerError::SetRangeProperty(addr, size, e))
        }
    }

    pub fn mark_function_as_non_returning(&mut self, f: &Function) -> Result<(), DecompilerError> {
        let faddr = f.address();
        self.mark_function_as_non_returning_at(faddr)
    }

    pub fn mark_function_as_non_returning_at(
        &mut self,
        faddr: impl Into<Address>,
    ) -> Result<(), DecompilerError> {
        let addr = faddr.into();

        unsafe {
            self.ghidra
                .pin_mut()
                .set_non_returning_function(addr.offset())
                .map_err(|e| DecompilerError::SetNonReturningFunction(addr, e))
        }
    }

    pub fn mark_functions_as_non_returning<'fcns>(
        &mut self,
        fcns: impl Iterator<Item = &'fcns Function>,
    ) -> Result<(), DecompilerError> {
        for f in fcns {
            self.mark_function_as_non_returning(f)?;
        }
        Ok(())
    }

    pub fn override_function_flow(
        &mut self,
        f: &Function,
        branch_addr: impl Into<Address>,
        kind: FlowOverride,
    ) -> Result<(), DecompilerError> {
        self.override_function_flow_at(f.address(), branch_addr, kind)
    }

    pub fn override_function_flow_at(
        &mut self,
        faddr: impl Into<Address>,
        branch_addr: impl Into<Address>,
        kind: FlowOverride,
    ) -> Result<(), DecompilerError> {
        let faddr = faddr.into();
        let branch_addr = branch_addr.into();

        unsafe {
            self.ghidra
                .pin_mut()
                .override_flow(faddr.offset(), branch_addr.offset(), kind)
                .map_err(|e| DecompilerError::FlowOverride(branch_addr, faddr, e))?
        }

        Ok(())
    }

    pub fn override_jump_table(
        &mut self,
        f: &Function,
        switch_addr: impl Into<Address>,
        addr_table: impl IntoIterator<Item = impl Into<Address>>,
    ) -> Result<(), DecompilerError> {
        self.override_jump_table_at(f.address(), switch_addr, addr_table)
    }

    pub fn override_jump_table_at(
        &mut self,
        faddr: impl Into<Address>,
        switch_addr: impl Into<Address>,
        addr_table: impl IntoIterator<Item = impl Into<Address>>,
    ) -> Result<(), DecompilerError> {
        let faddr = faddr.into();
        let switch_addr = switch_addr.into();
        let addr_table = addr_table
            .into_iter()
            .map(|addr| addr.into().offset())
            .collect();

        unsafe {
            self.ghidra
                .pin_mut()
                .override_jump_table(faddr.offset(), switch_addr.offset(), addr_table)
                .map_err(|e| DecompilerError::JumpTableOverride(switch_addr, faddr, e))?
        }

        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), DecompilerError> {
        unsafe {
            self.ghidra
                .pin_mut()
                .clear_all()
                .map_err(|e| DecompilerError::ClearAll(e))?;
        }

        Ok(())
    }
}
