use std::borrow::Cow;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::mem;
use std::str::FromStr;
use std::sync::Arc;

use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::analyses::strings::StringsXRefDB;
use bias_core::prelude::*;

use bias_core::decompiler::types::{
    DecompilerResolverAdaptor, DecompilerTypeResolver, DefaultDecompilerTypeResolver,
};
use bias_core::decompiler::{Decompiler, DecompilerConfig};

use bias_compat_fwhunt::bmatch::BMatcher;
use bias_compat_fwhunt::strings::{AsciiString, WideString};
use bias_compat_fwhunt::{MatchContext, MatchesRule};

use bias::platform::common::flirt::FunctionSymbolMapping;
use bias::platform::common::types::FunctionTypeMapping;
use bias::platform::{PlatformAttributes, PlatformProvider};

use mlua::{
    Error, IntoLua, LuaSerdeExt, Table, UserData, UserDataFields, UserDataMethods, Value, Variadic,
};
use parking_lot::Mutex;

use crate::analysis::DECOMPILER_TIMEOUT;
use crate::lua::scope::{AnnotatingPlatformTypeResolver, CheckScopeCallsAnnotations};
use crate::lua::types::{IRTerm, IRVar};
use crate::lua::{CallSiteQuery, CallsFromQuery, CallsToQuery, FunctionQuery};

use super::api::{AddressValue, DecompiledFunction, Instruction};
use super::scope::CheckScopeProjectData;
use super::{CallSiteContext, CheckerArch, CheckerError, FunctionContext};

pub mod decompiler;
pub use decompiler::{DynamicDecompilerContext, DynamicResolver};

pub mod efi;
pub mod posix;

mod attrs;

pub struct PlatformTypeResolver<'a> {
    resolver: Box<dyn ContextualTypeResolver<'a> + 'a>,
}

impl<'a> PlatformTypeResolver<'a> {
    pub fn new<R>(resolver: R) -> Self
    where
        R: ContextualTypeResolver<'a> + 'a,
    {
        Self {
            resolver: Box::new(resolver),
        }
    }
}

impl<'a> ContextualTypeResolver<'a> for PlatformTypeResolver<'a> {
    fn resolve_type_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        target: Option<Address>,
        t: &Term<Type>,
    ) -> Option<ResolvedType> {
        self.resolver.resolve_type_with(context, target, t)
    }

    fn resolve_entry_type(&self, context: &mut AliasTypingContext<'a>, function: &'a Function) {
        self.resolver.resolve_entry_type(context, function)
    }

    fn resolve_intrinsic_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        name: Ustr,
        arguments: Vec<TypedAliasValue>,
        bits: Option<u32>,
    ) -> Option<TypedAliasValue> {
        self.resolver
            .resolve_intrinsic_with(context, name, arguments, bits)
    }
}

pub struct ProjectHandle<'a, 'd, T: PlatformApi<'a> + ?Sized> {
    project: &'a Project,
    symbols: &'a FunctionSymbolMapping,
    types: &'a FunctionTypeMapping,
    decompiler: Option<Arc<Mutex<&'d mut Decompiler<'a>>>>,
    _platform: PhantomData<T>,
}

pub trait PlatformApi<'a>: PlatformProvider {
    #[allow(unused)]
    fn should_check(
        arch: &[CheckerArch],
        data: &CheckScopeProjectData,
        attrs: &PlatformAttributes,
    ) -> Result<bool, CheckerError> {
        Ok(true)
    }

    #[allow(unused)]
    fn type_resolver(project: &'a Project) -> PlatformTypeResolver<'a> {
        PlatformTypeResolver::new(DEFAULT_TYPE_RESOLVER)
    }

    #[allow(unused)]
    fn configure_decompiler<'d>(
        decompiler: &mut Decompiler<'d>,
        project: &'d Project,
        attributes: &PlatformAttributes<'_>,
        symbol_mapping: Option<&'d FunctionSymbolMapping>,
        type_mapping: Option<&'d FunctionTypeMapping>,
    ) -> Result<(), CheckerError> {
        decompiler.set_typedb(
            type_mapping
                .as_ref()
                .map(|tm| tm.types())
                .unwrap_or(project.type_db()),
        );

        for f in project.functions().values() {
            let Some(name) = symbol_mapping
                .and_then(|syms| syms.function_mapping().get(&f.id()).copied())
                .or_else(|| f.name())
            else {
                continue;
            };

            if let Some(t) = type_mapping.as_ref().and_then(|tm| tm.type_by_id(f.id())) {
                decompiler
                    .add_function_symbol_with(name, f.address(), &t, t.is_variadic_function())
                    .ok();
            } else if let Some(t) = project.type_db().get_code_type_at(f.address()) {
                decompiler
                    .add_function_symbol_with(name, f.address(), &t, t.is_variadic_function())
                    .ok();
            } else {
                decompiler.add_function_symbol(name, f.address()).ok();
            }

            if let Some(fixup) = project.lifter().call_fixup_for(name) {
                decompiler
                    .apply_call_fixup_to_function(fixup.name(), f)
                    .ok();
            }
        }

        if let Some(strings) = project.try_get_analysis::<StringsXRefDB>() {
            for ascii in strings.ascii_xrefs() {
                let addr = ascii.xref().target();
                decompiler
                    .add_ascii_string(
                        compact_str::format_compact!("str{addr}"),
                        addr,
                        ascii.string().len(),
                    )
                    .ok();
            }

            for unicode in strings.utf16le_xrefs() {
                let addr = unicode.xref().target();
                decompiler
                    .add_utf16_string(
                        compact_str::format_compact!("str{addr}"),
                        addr,
                        unicode.string().len(),
                    )
                    .ok();
            }
        }

        Ok(())
    }

    #[allow(unused)]
    fn decompiler(
        project: &'a Project,
        config: DecompilerConfig,
        attributes: &PlatformAttributes<'a>,
        symbol_mapping: Option<&'a FunctionSymbolMapping>,
        type_mapping: Option<&'a FunctionTypeMapping>,
    ) -> Result<(Decompiler<'a>, DynamicDecompilerContext), CheckerError> {
        struct Resolver;

        impl DecompilerTypeResolver for Resolver {
            fn resolve_global_variable_type(
                &self,
                project: &Project,
                use_at: Address,
                global: Address,
                bytes: usize,
            ) -> Option<Term<Type>> {
                let known = DefaultDecompilerTypeResolver
                    .resolve_global_variable_type(project, use_at, global, bytes);
                if known.is_some() {
                    return known;
                }

                None
            }
        }

        let resolver = DynamicResolver::new(project, DecompilerResolverAdaptor::from(Resolver));
        let context = resolver.context();

        let mut decompiler = Decompiler::new_with_config(
            project,
            type_mapping
                .as_ref()
                .map(|tm| tm.types())
                .unwrap_or(project.type_db()),
            resolver,
            config,
        )
        .map_err(CheckerError::decompiler)?;

        for f in project.functions().values() {
            let Some(name) = symbol_mapping
                .and_then(|syms| syms.function_mapping().get(&f.id()).copied())
                .or_else(|| f.name())
            else {
                continue;
            };

            if let Some(t) = type_mapping.as_ref().and_then(|tm| tm.type_by_id(f.id())) {
                decompiler
                    .add_function_symbol_with(name, f.address(), &t, t.is_variadic_function())
                    .ok();
            } else if let Some(t) = project.type_db().get_code_type_at(f.address()) {
                decompiler
                    .add_function_symbol_with(name, f.address(), &t, t.is_variadic_function())
                    .ok();
            } else {
                decompiler.add_function_symbol(name, f.address()).ok();
            }

            if let Some(fixup) = project.lifter().call_fixup_for(name) {
                decompiler
                    .apply_call_fixup_to_function(fixup.name(), f)
                    .ok();
            }
        }

        if let Some(strings) = project.try_get_analysis::<StringsXRefDB>() {
            for ascii in strings.ascii_xrefs() {
                let addr = ascii.xref().target();
                decompiler
                    .add_ascii_string(
                        compact_str::format_compact!("str{addr}"),
                        addr,
                        ascii.string().len(),
                    )
                    .ok();
            }

            for unicode in strings.utf16le_xrefs() {
                let addr = unicode.xref().target();
                decompiler
                    .add_utf16_string(
                        compact_str::format_compact!("str{addr}"),
                        addr,
                        unicode.string().len(),
                    )
                    .ok();
            }
        }

        Ok((decompiler, context))
    }

    #[allow(unused)]
    fn add_fields<'d, F: UserDataFields<ProjectHandle<'a, 'd, Self>>>(fields: &mut F)
    where
        'a: 'd,
    {
    }

    #[allow(unused)]
    fn add_methods<'d, M: UserDataMethods<ProjectHandle<'a, 'd, Self>>>(methods: &mut M)
    where
        'a: 'd,
    {
    }
}

impl<'a, 'd, T> ProjectHandle<'a, 'd, T>
where
    T: PlatformApi<'a>,
{
    pub fn new(
        project: &'a Project,
        symbols: &'a FunctionSymbolMapping,
        types: &'a FunctionTypeMapping,
    ) -> ProjectHandle<'a, 'd, T> {
        Self {
            project,
            symbols,
            types,
            decompiler: None,
            _platform: PhantomData,
        }
    }

    pub fn project(&self) -> &'a Project {
        self.project
    }

    pub fn set_decompiler(
        &mut self,
        decompiler: &'d mut Decompiler<'a>,
    ) -> Arc<Mutex<&'d mut Decompiler<'a>>> {
        let decompiler = Arc::new(Mutex::new(decompiler));
        self.decompiler = Some(decompiler.clone());

        decompiler
    }
}

impl<'a, 'd, T> UserData for ProjectHandle<'a, 'd, T>
where
    T: PlatformApi<'a>,
{
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        // TODO: we should use ffi.cast() to get a ULL for AddressValue rather than
        // hammering the registry to clean-up boxed u64s...
        //
        /*
        fields.add_field_method_get("functions", |lua, this| {
            let functions = lua.create_table()?;
            for f in this.project.functions().values() {
                let ftbl = lua.create_table()?;
                let addr = AddressValue::new_ser(lua, f.address())?;

                ftbl.set("address", addr.clone())?;
                if let Some(name) = f.name().as_ref() {
                    ftbl.set("name", name.as_str())?;
                }

                functions.set(addr, ftbl)?;
            }
            Ok(functions)
        });
        */

        fields.add_field_method_get("architecture", |_lua, this| {
            let architecture = this.project.lifter().translator().architecture();
            let arch = format!(
                "{}:{}:{}",
                architecture.processor(),
                if architecture.is_little() { "LE" } else { "BE" },
                architecture.bits()
            );
            Ok(arch)
        });

        T::add_fields(fields);
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("disassemble", |lua, this, options: Table| {
            let start = options.get::<AddressValue>("start").map(Address::from)?;
            let stop = options.get::<AddressValue>("stop").map(Address::from)?;
            let limit = options.get::<Option<usize>>("limit")?;

            if start >= stop {
                return Err(Error::runtime("disassemble requires start < stop"));
            }

            let instructions = Instruction::disassemble_range(this.project, start, stop, limit)?;

            lua.create_sequence_from(instructions)
        });

        methods.add_method("bytes_at", |lua, this, options: Table| {
            let address = options.get::<AddressValue>("address").map(Address::from)?;
            let size = options.get::<usize>("size")?;

            if size == 0 {
                return Err(Error::runtime("size must be greater than zero"));
            }

            let memory = this.project.memory();
            let bytes = memory.view_bytes(address, size).map_err(|e| {
                Error::runtime(format!("cannot read {size:#x} bytes at {address}: {e}"))
            })?;

            lua.create_string(bytes)
        });

        methods.add_method("size_of", |_lua, this, (tname,): (String,)| {
            Ok(this
                .types
                .types()
                .get_type_for(tname, this.project.lifter().address_bits())
                .map(|t| t.nbytes()))
        });

        methods.add_method("lookup_prototype", |_lua, this, (tname,): (String,)| {
            Ok(this
                .types
                .types()
                .get_prototype_for(tname, this.project.lifter().address_bits())
                .map(IRTerm::new))
        });

        methods.add_method("lookup_type", |_lua, this, (tname,): (String,)| {
            Ok(this
                .types
                .types()
                .get_type_for(tname, this.project.lifter().address_bits())
                .map(IRTerm::new))
        });

        methods.add_method("register_name", |_lua, this, (term,): (Value,)| {
            let Some(ud) = term.as_userdata() else {
                return Ok(None);
            };

            let names = this.project.lifter().translator().registers();
            let lookup_name = |var: &Var| {
                if !var.is_register() {
                    return None;
                }

                let nbytes = var.nbits() as usize / 8;
                let offset = var.offset();

                names.get(offset, nbytes).map(|name| name.to_owned())
            };

            if let Some(term) = ud.borrow::<IRTerm>().ok() {
                let Some(var) = term.as_term().get_variable() else {
                    return Ok(None);
                };

                return Ok(lookup_name(var));
            }

            if let Some(var) = ud.borrow::<IRVar>().ok() {
                return Ok(lookup_name(&*var));
            }

            Ok(None)
        });

        methods.add_method("resolve_type", |_lua, this, (t,): (IRTerm,)| {
            Ok(t.as_term()
                .get_expanded_type(this.types.types())
                .map(IRTerm::new))
        });

        // SAFETY: this is safe iff the VM will not outlive the data borrowed from the project
        // handle, which is guaranteed in VulHunt's current architecture, however, care must be
        // taken to ensure this guarantee is upheld if the API is used in other contexts.
        methods.add_method("decompile", |lua, this, (arg,): (Value,)| {
            let Some(decompiler) = this.decompiler.as_ref() else {
                return Err(Error::runtime("decompiler extension API unavailable"));
            };

            let (query, all) = lua.from_value::<FunctionQuery>(arg)?.into_parts();

            let functions = query
                .targets(this.project, this.symbols)
                .map_err(Error::external)?;

            let mut d = decompiler.lock_arc();

            if all {
                let table = lua.create_table()?;
                let mut index = 1usize;

                for f in functions {
                    if let Ok(output) = d.decompile_ast(f) {
                        table.raw_set(
                            index,
                            DecompiledFunction::new(
                                unsafe {
                                    mem::transmute(FunctionContext::new_with(
                                        f,
                                        this.project,
                                        this.symbols,
                                    ))
                                },
                                output,
                            ),
                        )?;

                        index += 1;
                    }
                }

                Ok(Value::Table(table))
            } else {
                let Some(f) = functions.get(0) else {
                    return Ok(Value::Nil);
                };

                let output = d
                    .try_decompile_ast(f, *DECOMPILER_TIMEOUT)
                    .map_err(Error::external)?;

                DecompiledFunction::new(
                    unsafe {
                        mem::transmute(FunctionContext::new_with(f, this.project, this.symbols))
                    },
                    output,
                )
                .into_lua(lua)
            }
        });

        // SAFETY: this is safe iff the VM will not outlive the data borrowed from the project
        // handle, which is guaranteed in VulHunt's current architecture, however, care must be
        // taken to ensure this guarantee is upheld if the API is used in other contexts.
        methods.add_method("functions", |lua, this, (arg,): (Option<Value>,)| {
            let Some(arg) = arg else {
                return lua
                    .create_sequence_from(this.project.functions().values().map(|f| unsafe {
                        mem::transmute::<_, FunctionContext<'static>>(FunctionContext::new_with(
                            f,
                            this.project,
                            this.symbols,
                        ))
                    }))
                    .map(Value::Table);
            };

            let (query, all) = lua.from_value::<FunctionQuery>(arg)?.into_parts();

            let functions = query
                .targets(this.project, this.symbols)
                .map_err(Error::external)?;

            if all {
                lua.create_sequence_from(functions.iter().map(|f| unsafe {
                    mem::transmute::<_, FunctionContext<'static>>(FunctionContext::new_with(
                        f,
                        this.project,
                        this.symbols,
                    ))
                }))
                .map(Value::Table)
            } else {
                let Some(f) = functions.get(0) else {
                    return Ok(Value::Nil);
                };

                let fctx = unsafe {
                    mem::transmute::<_, FunctionContext<'static>>(FunctionContext::new_with(
                        f,
                        this.project,
                        this.symbols,
                    ))
                };

                fctx.into_lua(lua)
            }
        });

        // SAFETY: this is safe iff the VM will not outlive the data borrowed from the project
        // handle, which is guaranteed in VulHunt's current architecture, however, care must be
        // taken to ensure this guarantee is upheld if the API is used in other contexts.
        methods.add_method("functions_where", |lua, this, cond: Value| {
            if let Some(fcond) = cond.as_function() {
                let table = lua.create_table()?;
                let mut index = 1usize;

                for f in this.project.functions().values() {
                    let fctx =
                        unsafe {
                            mem::transmute::<_, FunctionContext<'static>>(
                                FunctionContext::new_with(f, this.project, this.symbols),
                            )
                        };

                    if fcond.call::<bool>(fctx.clone())? {
                        table.raw_set(index, fctx)?;
                        index += 1;
                    }
                }
                Ok(table)
            } else {
                Err(Error::runtime("criteria must be a function"))
            }
        });

        // SAFETY: this is safe iff the VM will not outlive the data borrowed from the project
        // handle, which is guaranteed in VulHunt's current architecture, however, care must be
        // taken to ensure this guarantee is upheld if the API is used in other contexts.
        methods.add_method(
            "calls_matching",
            |lua, this, cond: Table| -> Result<Value, Error> {
                // to -> CallsToQuery
                // where -> function (optional)
                // using -> annotations (optional)
                // debug -> produce debug string (optional)

                let Ok(to) = cond
                    .get::<Value>("to")
                    .and_then(|value| lua.from_value::<CallsToQuery>(value))
                else {
                    return Err(Error::runtime(
                        "to missing or invalid; expected symbol name or address",
                    ));
                };

                let Ok(where_) = cond.get::<Option<mlua::Function>>("where") else {
                    return Err(Error::runtime("where invalid; expected a function"));
                };

                let Ok(using) = cond
                    .get::<Value>("using")
                    .and_then(|value| lua.from_value::<Option<CheckScopeCallsAnnotations>>(value))
                else {
                    return Err(Error::runtime(
                        "using invalid; expected a table of specifications",
                    ));
                };

                let Ok(debug) = cond
                    .get::<Option<bool>>("debug")
                    .map(Option::unwrap_or_default)
                else {
                    return Err(Error::runtime("debug invalid; expected a boolean"));
                };

                let (targets, with_jumps) = to
                    .targets_with(this.project, this.symbols, true)
                    .map_err(Error::external)?;

                let functions = this.project.functions();
                let blocks = this.project.code_blocks();
                let icfg = this.project.icfg();

                let table = lua.create_table()?;
                let mut index = 1usize;

                let using = using.unwrap_or_default();
                for to in targets {
                    let entry = blocks[to.entry()].node();
                    let mut candidates = BTreeMap::<_, Vec<_>>::new();

                    for (fid, blk) in
                        icfg.edges_directed(entry, Direction::Incoming)
                            .filter_map(|edge| {
                                if edge.weight().is_call()
                                    || (with_jumps && edge.weight().is_branch())
                                {
                                    let blk = &blocks[icfg[edge.source()]];
                                    let fid = blk.function();
                                    Some((fid, blk))
                                } else {
                                    None
                                }
                            })
                    {
                        candidates.entry(fid).or_default().push(blk);
                    }

                    if candidates.is_empty() {
                        // nothing to check beyond here
                        continue;
                    }

                    let resolver = AnnotatingPlatformTypeResolver::new_with(
                        T::type_resolver(this.project),
                        &this.project,
                        Cow::Owned(using.clone()), // Avoid clone
                        Some(&*this.symbols),
                        Some(&*this.types.types()),
                    );

                    for (fid, blks) in candidates {
                        let f = &functions[fid];

                        let fctx = unsafe {
                            mem::transmute::<_, FunctionContext<'static>>(
                                FunctionContext::new_with(f, this.project, this.symbols),
                            )
                        };

                        if matches!(where_.as_ref(), Some(f) if !f.call::<bool>(fctx.clone())?) {
                            continue;
                        }

                        let aliases =
                            TypedAliases::analyse_function_with(&*this.project, f, &resolver);

                        let debug = debug.then(|| aliases.display_with(this.project).to_string());

                        for blk in blks {
                            let aliases = &aliases.blocks()[&blk.id()];
                            let fcctx = CallSiteContext::new(
                                this.project,
                                f,
                                blk,
                                aliases,
                                this.symbols,
                                this.types.types(),
                            );

                            let inputs = fcctx
                                .inputs()
                                .into_iter()
                                .map(|opnd| opnd.to_table(lua))
                                .collect::<Result<Vec<Table>, _>>()?;

                            let output = fcctx.output().to_table(lua)?;

                            let operands = lua.create_table()?;

                            operands.raw_set(
                                "call_address",
                                lua.create_ser_userdata(AddressValue::from(blk.last_address()))?,
                            )?;
                            operands.raw_set(
                                "name",
                                this.symbols
                                    .function_mapping()
                                    .get(&fid)
                                    .copied()
                                    .or_else(|| f.name())
                                    .map(|v| v.as_str()),
                            )?;
                            operands.raw_set(
                                "caller_address",
                                lua.create_ser_userdata(AddressValue::from(f.address()))?,
                            )?;
                            operands.raw_set("caller", fctx.clone())?;
                            operands.raw_set("inputs", inputs)?;
                            operands.raw_set("output", output)?;

                            if let Some(debug) = debug.as_ref() {
                                operands.raw_set("debug", lua.create_string(debug)?)?;
                            }

                            table.raw_set(index, operands)?;
                            index += 1;
                        }
                    }
                }

                Ok(Value::Table(table))
            },
        );

        // SAFETY: this is safe iff the VM will not outlive the data borrowed from the project
        // handle, which is guaranteed in VulHunt's current architecture, however, care must be
        // taken to ensure this guarantee is upheld if the API is used in other contexts.
        methods.add_method(
            "callees_matching",
            |lua, this, cond: Table| -> Result<Value, Error> {
                // from -> CallsFromQuery
                // where -> function (optional)
                // using -> annotations (optional)
                // debug -> produce debug string (optional)

                let Ok(from) = cond
                    .get::<Value>("from")
                    .and_then(|value| lua.from_value::<CallsFromQuery>(value))
                else {
                    return Err(Error::runtime(
                        "from missing or invalid; expected symbol name or address",
                    ));
                };

                let Ok(where_) = cond.get::<Option<mlua::Function>>("where") else {
                    return Err(Error::runtime("where invalid; expected a function"));
                };

                let Ok(using) = cond
                    .get::<Value>("using")
                    .and_then(|value| lua.from_value::<Option<CheckScopeCallsAnnotations>>(value))
                else {
                    return Err(Error::runtime(
                        "using invalid; expected a table of specifications",
                    ));
                };

                let Ok(debug) = cond
                    .get::<Option<bool>>("debug")
                    .map(Option::unwrap_or_default)
                else {
                    return Err(Error::runtime("debug invalid; expected a boolean"));
                };

                let (targets, with_jumps) = from
                    .targets_with(this.project, this.symbols, true)
                    .map_err(Error::external)?;

                let functions = this.project.functions();
                let blocks = this.project.code_blocks();
                let icfg = this.project.icfg();

                let table = lua.create_table()?;
                let mut index = 1usize;

                let using = using.unwrap_or_default();
                for from in targets {
                    let resolver = AnnotatingPlatformTypeResolver::new_with(
                        T::type_resolver(this.project),
                        &this.project,
                        Cow::Owned(using.clone()),
                        Some(&*this.symbols),
                        Some(&*this.types.types()),
                    );

                    let aliases =
                        TypedAliases::analyse_function_with(&*this.project, from, &resolver);

                    let debug =
                        debug.then(|| aliases.display_with(this.project).to_string());

                    for blk in from.blocks_with(blocks) {
                        for edge in icfg.edges_directed(blk.node(), Direction::Outgoing) {
                            if !(edge.weight().is_call()
                                || (with_jumps && edge.weight().is_branch()))
                            {
                                continue;
                            }

                            let callee_blk = &blocks[icfg[edge.target()]];
                            let callee_fid = callee_blk.function();
                            let callee_f = &functions[callee_fid];

                            let callee_fctx = unsafe {
                                mem::transmute::<_, FunctionContext<'static>>(
                                    FunctionContext::new_with(
                                        callee_f,
                                        this.project,
                                        this.symbols,
                                    ),
                                )
                            };

                            if matches!(where_.as_ref(), Some(f) if !f.call::<bool>(callee_fctx.clone())?)
                            {
                                continue;
                            }

                            let aliases = &aliases.blocks()[&blk.id()];
                            let fcctx = CallSiteContext::new(
                                this.project,
                                from,
                                blk,
                                aliases,
                                this.symbols,
                                this.types.types(),
                            );

                            let inputs = fcctx
                                .inputs()
                                .into_iter()
                                .map(|opnd| opnd.to_table(lua))
                                .collect::<Result<Vec<Table>, _>>()?;

                            let output = fcctx.output().to_table(lua)?;

                            let operands = lua.create_table()?;

                            operands.raw_set(
                                "call_address",
                                lua.create_ser_userdata(AddressValue::from(blk.last_address()))?,
                            )?;
                            operands.raw_set(
                                "name",
                                this.symbols
                                    .function_mapping()
                                    .get(&callee_fid)
                                    .copied()
                                    .or_else(|| callee_f.name())
                                    .map(|v| v.as_str()),
                            )?;
                            operands.raw_set(
                                "callee_address",
                                lua.create_ser_userdata(AddressValue::from(callee_f.address()))?,
                            )?;
                            operands.raw_set("callee", callee_fctx.clone())?;
                            operands.raw_set("inputs", inputs)?;
                            operands.raw_set("output", output)?;

                            if let Some(debug) = debug.as_ref() {
                                operands.raw_set("debug", lua.create_string(debug)?)?;
                            }

                            table.raw_set(index, operands)?;
                            index += 1;
                        }
                    }
                }

                Ok(Value::Table(table))
            },
        );

        // SAFETY: this is safe iff the VM will not outlive the data borrowed from the project
        // handle, which is guaranteed in VulHunt's current architecture, however, care must be
        // taken to ensure this guarantee is upheld if the API is used in other contexts.
        methods.add_method(
            "callee_at",
            |lua, this, cond: Table| -> Result<Value, Error> {
                // target -> CallSiteQuery
                // debug -> produce debug string (optional)

                let Ok(target) = cond
                    .get::<Value>("target")
                    .and_then(|value| lua.from_value::<CallSiteQuery>(value))
                else {
                    return Err(Error::runtime(
                        "target missing or invalid; expected address",
                    ));
                };

                let Ok(debug) = cond
                    .get::<Option<bool>>("debug")
                    .map(Option::unwrap_or_default)
                else {
                    return Err(Error::runtime("debug invalid; expected a boolean"));
                };

                let (addr, with_jumps) = target.target();

                let functions = this.project.functions();
                let blocks = this.project.code_blocks();
                let icfg = this.project.icfg();

                // As non-exact location of the call site can be provided
                // (e.g. when the address comes from decompiled-source mapping)
                // we search for the block that contains it.
                let Some(blk) = this
                    .project
                    .get_analysis::<CodeBlockBounds>()
                    .get(addr)
                    .map(|(_, &bid)| &blocks[bid])
                else {
                    return Ok(Value::Nil);
                };

                for edge in icfg.edges_directed(blk.node(), Direction::Outgoing) {
                    if !(edge.weight().is_call() || (with_jumps && edge.weight().is_branch())) {
                        continue;
                    }

                    let from = &functions[blk.function()];

                    let callee_fid = blocks[icfg[edge.target()]].function();
                    let callee_f = &functions[callee_fid];

                    let callee_fctx =
                        unsafe {
                            mem::transmute::<_, FunctionContext<'static>>(
                                FunctionContext::new_with(callee_f, this.project, this.symbols),
                            )
                        };

                    let resolver = AnnotatingPlatformTypeResolver::new_with(
                        T::type_resolver(this.project),
                        &this.project,
                        Cow::Owned(CheckScopeCallsAnnotations::default()),
                        Some(&*this.symbols),
                        Some(&*this.types.types()),
                    );

                    let aliases =
                        TypedAliases::analyse_function_with(&*this.project, from, &resolver);

                    let debug = debug.then(|| aliases.display_with(this.project).to_string());

                    let aliases = &aliases.blocks()[&blk.id()];

                    let fcctx = CallSiteContext::new(
                        this.project,
                        from,
                        blk,
                        aliases,
                        this.symbols,
                        this.types.types(),
                    );

                    let inputs = fcctx
                        .inputs()
                        .into_iter()
                        .map(|opnd| opnd.to_table(lua))
                        .collect::<Result<Vec<Table>, _>>()?;

                    let output = fcctx.output().to_table(lua)?;

                    let operands = lua.create_table()?;

                    operands.raw_set(
                        "name",
                        this.symbols
                            .function_mapping()
                            .get(&callee_fid)
                            .copied()
                            .or_else(|| callee_f.name())
                            .map(|v| v.as_str()),
                    )?;
                    operands.raw_set(
                        "callee_address",
                        lua.create_ser_userdata(AddressValue::from(callee_f.address()))?,
                    )?;
                    operands.raw_set("callee", callee_fctx)?;
                    operands.raw_set("inputs", inputs)?;
                    operands.raw_set("output", output)?;

                    if let Some(debug) = debug.as_ref() {
                        operands.raw_set("debug", lua.create_string(debug)?)?;
                    }

                    return Ok(Value::Table(operands));
                }

                Ok(Value::Nil)
            },
        );

        methods.add_method(
            "search_bytes",
            |_, this, value: String| -> Result<bool, Error> {
                let matcher = BMatcher::from_str(&value).map_err(Error::external)?;
                let mut context = MatchContext::new();
                let _checkpoint = context.begin(&matcher);
                Ok(matcher.matches_rule(&mut context, this.project()))
            },
        );

        methods.add_method(
            "search_string",
            |_, this, value: (String, Variadic<String>)| -> Result<bool, Error> {
                let result = if let Some(kind) = value.1.first() {
                    let kind = match &**kind {
                        "ascii" => StringData::Ascii,
                        "utf8" => StringData::Utf8,
                        "utf16" | "utf16-le" | "utf16le" => StringData::Utf16Le,
                        "utf16-be" | "utf16be" => StringData::Utf16Be,
                        enc => {
                            return Err(Error::external(format!("invalid string encoding `{enc}`")))
                        }
                    };
                    let searcher = WideString::new_with(value.0, kind);
                    let mut context = MatchContext::new();
                    let _checkpoint = context.begin(&searcher);
                    searcher.matches_rule(&mut context, this.project())
                } else {
                    let searcher = AsciiString::new(value.0);
                    let mut context = MatchContext::new();
                    let _checkpoint = context.begin(&searcher);
                    searcher.matches_rule(&mut context, this.project())
                };
                Ok(result)
            },
        );

        methods.add_method(
            "find_bytes",
            |lua, this, value: String| -> Result<Table, Error> {
                let table = lua.create_table()?;

                if value.is_empty() {
                    return Ok(table);
                }

                let matcher = BMatcher::from_str(&value).map_err(Error::external)?;
                let mut index = 1usize;
                for (_, region) in this.project().memory().regions().iter(..) {
                    let bytes = region.bytes();
                    let base = *region.address();
                    let mut offset = 0usize;
                    while let Some(found) = matcher.position_from(bytes, offset) {
                        let addr = base + found;
                        table.raw_set(index, lua.create_ser_userdata(AddressValue::from(addr))?)?;
                        index += 1;
                        offset = found + 1;
                    }
                }

                Ok(table)
            },
        );

        methods.add_method(
            "find_string",
            |lua, this, value: (String, Variadic<String>)| -> Result<Table, Error> {
                let needle = if let Some(kind) = value.1.first() {
                    let kind = match &**kind {
                        "ascii" => StringData::Ascii,
                        "utf8" => StringData::Utf8,
                        "utf16" | "utf16-le" | "utf16le" => StringData::Utf16Le,
                        "utf16-be" | "utf16be" => StringData::Utf16Be,
                        enc => {
                            return Err(Error::external(format!("invalid string encoding `{enc}`")))
                        }
                    };
                    kind.encode(value.0).map_err(Error::external)?
                } else {
                    value.0.into_bytes()
                };

                let table = lua.create_table()?;

                if needle.is_empty() {
                    return Ok(table);
                }

                let matcher = BMatcher::from(needle);
                let mut index = 1usize;
                for (_, region) in this.project().memory().regions().iter(..) {
                    let bytes = region.bytes();
                    let base = *region.address();
                    let mut offset = 0usize;
                    while let Some(found) = matcher.position_from(bytes, offset) {
                        let addr = base + found;
                        table.raw_set(index, lua.create_ser_userdata(AddressValue::from(addr))?)?;
                        index += 1;
                        offset = found + 1;
                    }
                }

                Ok(table)
            },
        );

        T::add_methods(methods);
    }
}
