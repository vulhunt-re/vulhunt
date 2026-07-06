use bias_core::efi::aliases::EFITypeResolver;
use bias_core::kb::Uuid;
use bias_core::prelude::*;

use bias_core::decompiler::platform::efi::{annotate_globals, EFIProtocolTypeResolver};
use bias_core::decompiler::{Decompiler, DecompilerConfig};

use bias_compat_fwhunt::code::CodeLocation;
use bias_compat_fwhunt::guids::Guid;
use bias_compat_fwhunt::nvram::Nvram;
use bias_compat_fwhunt::ppi::Ppi;
use bias_compat_fwhunt::protocols::Protocol;
use bias_compat_fwhunt::{MatchContext, MatchesRule};

use bias::platform::common::flirt::FunctionSymbolMapping;
use bias::platform::common::types::FunctionTypeMapping;
use bias::platform::efi::{
    EFIComponentArch, EFIComponentGuid, EFIComponentName, EFIModule, EFIStandaloneName,
};
use bias::platform::PlatformAttributes;

use mlua::{Error, UserDataMethods, Variadic};

use crate::lua::api::SearchCodeResult;
use crate::lua::project::attrs::name::{matches_name, matches_name_with_prefix};
use crate::lua::scope::CheckScopeProjectData;
use crate::lua::{CheckerArch, CheckerError};

use super::{
    DynamicDecompilerContext, DynamicResolver, PlatformApi, PlatformTypeResolver, ProjectHandle,
};

impl<'a, 'd> ProjectHandle<'a, 'd, EFIModule> {
    fn find_code(
        &self,
        value: (String, Variadic<String>),
    ) -> Result<Option<SearchCodeResult>, Error> {
        let matcher = value.0;
        if let Some(loc) = value.1.first() {
            let place = match &**loc {
                "sw_smi_handlers" => CodeLocation::SwSmiHandlers,
                "child_sw_smi_handlers" => CodeLocation::ChildSwSmiHandlers,
                _ => return Err(Error::external("invalid location to search")),
            };

            SearchCodeResult::search_with(self.project(), matcher, place)
        } else {
            SearchCodeResult::search(self.project(), matcher)
        }
    }

    fn contains_guid(&self, value: (String, String)) -> Result<bool, Error> {
        let uuid = Uuid::parse_str(&value.0.replace("-", ""))
            .map_err(|_| Error::external("invalid GUID format"))?;
        let name = value.1;

        let guid = Guid::new_with(uuid, name);

        let mut context = MatchContext::new();
        let _checkpoint = context.begin(&guid);
        Ok(guid.matches_rule(&mut context, self.project()))
    }

    fn uses_nvram_variable(&self, value: (String, String, String)) -> Result<bool, Error> {
        let service = value.0;
        let name = value.1;
        let uuid = Uuid::parse_str(&value.2.replace("-", ""))
            .map_err(|_| Error::external("invalid GUID format"))?;

        let nvram = Nvram::new(service, name, uuid);

        let mut context = MatchContext::new();
        let _checkpoint = context.begin(&nvram);
        Ok(nvram.matches_rule(&mut context, self.project()))
    }

    fn uses_ppi(&self, value: (String, String, String)) -> Result<bool, Error> {
        let service = value.0;
        let name = value.1;
        let uuid = Uuid::parse_str(&value.2.replace("-", ""))
            .map_err(|_| Error::external("invalid GUID format"))?;

        let ppi = Ppi::new(service, name, uuid);

        let mut context = MatchContext::new();
        let _checkpoint = context.begin(&ppi);
        Ok(ppi.matches_rule(&mut context, self.project()))
    }

    fn uses_protocol(&self, value: (String, String, String)) -> Result<bool, Error> {
        let service = value.0;
        let name = value.1;
        let uuid = Uuid::parse_str(&value.2.replace("-", ""))
            .map_err(|_| Error::external("invalid GUID format"))?;

        let proto = Protocol::new(service, name, uuid);

        let mut context = MatchContext::new();
        let _checkpoint = context.begin(&proto);
        Ok(proto.matches_rule(&mut context, self.project()))
    }
}

impl<'a> PlatformApi<'a> for EFIModule {
    fn should_check(
        arch: &[CheckerArch],
        data: &CheckScopeProjectData,
        attrs: &PlatformAttributes,
    ) -> Result<bool, CheckerError> {
        if let Some(larch) = attrs.get_attr::<EFIComponentArch>() {
            if !arch.iter().any(|arch| arch.matches_with(larch)) {
                return Ok(false);
            }
        }

        if let Some(guids) = data.get("volume_guids") {
            let guids_s = guids.as_slice().ok_or_else(|| {
                CheckerError::malformed_condition_with("invalid `volume_guids` format")
            })?;

            if guids_s.is_empty() {
                return Ok(false);
            }

            let Some(actual_guid) = attrs.get_attr::<EFIComponentGuid>() else {
                return Ok(false);
            };

            let guids = guids_s
                .iter()
                .map(|guid| {
                    let guid_str = guid.as_str().ok_or_else(|| {
                        CheckerError::malformed_condition_with("invalid `volume_guids` format")
                    })?;
                    Uuid::parse_str(guid_str).map_err(CheckerError::malformed_condition)
                })
                .collect::<Result<Vec<Uuid>, _>>()?;

            if !guids.into_iter().any(|guid| guid == **actual_guid) {
                return Ok(false);
            }
        }

        if data.name().is_none() && data.name_with_prefix().is_none() {
            return Ok(true);
        }

        let Some(actual_name) = attrs
            .get_attr::<EFIComponentName>()
            .map(|name| name.as_ref())
            .or_else(|| {
                attrs
                    .get_attr::<EFIStandaloneName>()
                    .map(|name| name.as_ref())
            })
        else {
            return Ok(false);
        };

        if let Some(name) = data.name() {
            if matches_name(name, |n| n == actual_name)? {
                return Ok(true);
            }
        }

        if let Some(prefix) = data.name_with_prefix() {
            if matches_name_with_prefix(prefix, |p| actual_name.starts_with(p))? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn type_resolver(project: &'a Project) -> PlatformTypeResolver<'a> {
        PlatformTypeResolver::new(EFITypeResolver::new(project))
    }

    fn configure_decompiler<'d>(
        decompiler: &mut Decompiler<'d>,
        project: &'d Project,
        _attributes: &PlatformAttributes<'_>,
        symbol_mapping: Option<&'d FunctionSymbolMapping>,
        type_mapping: Option<&'d FunctionTypeMapping>,
    ) -> Result<(), CheckerError> {
        decompiler.set_typedb(
            type_mapping
                .as_ref()
                .map(|tm| tm.types())
                .unwrap_or(project.type_db()),
        );

        annotate_globals(decompiler, project);

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

        Ok(())
    }

    fn decompiler(
        project: &'a Project,
        config: DecompilerConfig,
        _attributes: &PlatformAttributes<'a>,
        symbol_mapping: Option<&'a FunctionSymbolMapping>,
        type_mapping: Option<&'a FunctionTypeMapping>,
    ) -> Result<(Decompiler<'a>, DynamicDecompilerContext), CheckerError> {
        let resolver = DynamicResolver::new(project, EFIProtocolTypeResolver::new(project));
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

        annotate_globals(&mut decompiler, project);

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
        methods.add_method("find_code", |_, this, value: (String, Variadic<String>)| {
            this.find_code(value)
        });

        methods.add_method("search_guid", |_, this, value| {
            tracing::warn!("`search_guid` is deprecated; use `contains_guid` instead");
            this.contains_guid(value)
        });
        methods.add_method("contains_guid", |_, this, value| this.contains_guid(value));

        methods.add_method("search_nvram", |_, this, value| {
            tracing::warn!("`search_nvram` is deprecated; use `uses_nvram_variable` instead");
            this.uses_nvram_variable(value)
        });
        methods.add_method("uses_nvram_variable", |_, this, value| {
            this.uses_nvram_variable(value)
        });

        methods.add_method("search_ppi", |_, this, value| {
            tracing::warn!("`search_ppi` is deprecated; use `uses_ppi` instead");
            this.uses_ppi(value)
        });
        methods.add_method("uses_ppi", |_, this, value| this.uses_ppi(value));

        methods.add_method("search_protocol", |_, this, value| {
            tracing::warn!("`search_protocol` is deprecated; use `uses_protocol` instead");
            this.uses_protocol(value)
        });
        methods.add_method("uses_protocol", |_, this, value| this.uses_protocol(value));
    }
}
