use bias_core::analyses::strings::StringsXRefDB;
use bias_core::loader::elf::ELFExternalSymbolsRef;
use bias_core::posix::non_returning::PropagatedPosixNonReturningExternals;
use bias_core::prelude::*;

use bias_core::decompiler::{Decompiler, DecompilerConfig, DefaultDecompilerResolver};

use bias::platform::common::flirt::FunctionSymbolMapping;
use bias::platform::common::types::FunctionTypeMapping;
use bias::platform::posix::{
    PosixBinary, PosixComponentArch, PosixComponentLinkedPaths, PosixComponentName,
};
use bias::platform::PlatformAttributes;

use mlua::{Error, UserDataMethods, Variadic};

use crate::lua::api::FindCodeResult;
use crate::lua::project::attrs::name::{matches_name, matches_name_with_prefix};
use crate::lua::scope::CheckScopeProjectData;
use crate::lua::{CheckerArch, CheckerError};

use super::{DynamicDecompilerContext, DynamicResolver, PlatformApi, ProjectHandle};

impl<'a, 'd> ProjectHandle<'a, 'd, PosixBinary> {
    fn find_code(
        &self,
        value: (String, Variadic<String>),
    ) -> Result<Option<FindCodeResult>, Error> {
        FindCodeResult::find(self.project(), value.0)
    }
}

impl<'a> PlatformApi<'a> for PosixBinary {
    fn should_check(
        arch: &[CheckerArch],
        data: &CheckScopeProjectData,
        attrs: &PlatformAttributes,
    ) -> Result<bool, CheckerError> {
        if let Some(larch) = attrs.get_attr::<PosixComponentArch>() {
            if !arch.iter().any(|arch| arch.matches_with(larch)) {
                return Ok(false);
            }
        }

        if data.name().is_none() && data.name_with_prefix().is_none() {
            return Ok(true);
        }

        let Some(actual_name) = attrs.get_attr::<PosixComponentName>() else {
            return Ok(false);
        };

        if let Some(name) = data.name() {
            let matches = |name: &str| -> bool {
                name == &**actual_name
                    || matches!(attrs.get_attr::<PosixComponentLinkedPaths>(), Some(links) if links.contains_name(name))
            };

            if matches_name(name, matches)? {
                return Ok(true);
            }
        }

        if let Some(prefix) = data.name_with_prefix() {
            let matches_prefix = |prefix: &str| -> bool {
                actual_name.starts_with(prefix)
                    || matches!(attrs.get_attr::<PosixComponentLinkedPaths>(), Some(links) if links.names().any(|n| n.starts_with(prefix)))
            };

            if matches_name_with_prefix(prefix, matches_prefix)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

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

        if let Some(externs) = attributes.get_attr::<ELFExternalSymbolsRef>() {
            for (addr, sym) in externs.iter() {
                decompiler.add_extern(sym, addr).ok();
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

        if let Some(non_returning_functions) =
            project.try_get_analysis::<PropagatedPosixNonReturningExternals>()
        {
            for fid in non_returning_functions {
                decompiler
                    .mark_function_as_non_returning(&project.functions()[fid])
                    .ok();
            }
        }

        Ok(())
    }

    fn decompiler(
        project: &'a Project,
        config: DecompilerConfig,
        attributes: &PlatformAttributes<'a>,
        symbol_mapping: Option<&'a FunctionSymbolMapping>,
        type_mapping: Option<&'a FunctionTypeMapping>,
    ) -> Result<(Decompiler<'a>, DynamicDecompilerContext), CheckerError> {
        let resolver = DynamicResolver::new(project, DefaultDecompilerResolver::default());
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

        if let Some(externs) = attributes.get_attr::<ELFExternalSymbolsRef>() {
            for (addr, sym) in externs.iter() {
                decompiler.add_extern(sym, addr).ok();
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

        if let Some(non_returning_functions) =
            project.try_get_analysis::<PropagatedPosixNonReturningExternals>()
        {
            for fid in non_returning_functions {
                decompiler
                    .mark_function_as_non_returning(&project.functions()[fid])
                    .ok();
            }
        }

        Ok((decompiler, context))
    }

    fn add_methods<'d, T: UserDataMethods<ProjectHandle<'a, 'd, Self>>>(methods: &mut T)
    where
        'a: 'd,
    {
        methods.add_method("search_code", |_, this, value| {
            tracing::warn!("`search_code` is deprecated; use `find_code` instead");
            this.find_code(value)
        });
        methods.add_method("find_code", |_, this, value| this.find_code(value));
    }
}
