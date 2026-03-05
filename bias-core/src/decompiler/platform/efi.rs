use std::sync::{Arc, RwLock};

use convert_case::{Case, Casing};

use crate::analyses::blocks::CodeBlockBounds;
use crate::analyses::stack::aliases::*;
use crate::analyses::strings::StringsXRefDB;
use crate::decompiler::{
    DataTypeRef, Decompiler, DecompilerSymbolResolver, DecompilerTypeResolver,
};
use crate::efi::services::{ServiceData, ServiceInfo, ServiceParamValue};
use crate::efi::smi::{LOCATE_PROTOCOL, SMM_LOCATE_PROTOCOL};
use crate::prelude::efi::*;
use crate::prelude::*;

#[inline]
pub fn format_guid(guid: impl AsRef<str>) -> String {
    let guid = guid.as_ref();
    let s = guid.replace("-", "_");
    if s != guid {
        format!("g{}", s.to_uppercase())
    } else {
        s
    }
}

pub struct EFIProtocolTypeResolver {
    bounds: CodeBlockBounds,
    stack_refs: Arc<RwLock<AHashMap<FunctionId, FunctionStackRefs>>>,
    resolver: DefaultPrototype,
    uses: AHashMap<Address, (Option<Address>, Ustr)>,
}

impl EFIProtocolTypeResolver {
    pub fn new(project: &Project) -> Self {
        let resolver = project.lifter().default_prototype();
        let bounds = CodeBlockBounds::new_with(&project);

        let mut uses = AHashMap::new();

        let services = project.get_analysis::<ServicesAnalyser>();

        for (&addr, svc) in services.boot_services().iter() {
            if svc.service() != *LOCATE_PROTOCOL {
                continue;
            }

            let Some(guid) = svc.protocol() else { continue };
            let paddr = svc
                .params()
                .get(2)
                .and_then(|v| v.as_ref().and_then(|v| v.source()));

            uses.insert(addr, (paddr, guid));
        }

        for (&addr, svc) in services.smm_services().iter() {
            if svc.service() != *SMM_LOCATE_PROTOCOL {
                continue;
            }

            let Some(guid) = svc.protocol() else { continue };
            let paddr = svc
                .params()
                .get(2)
                .and_then(|v| v.as_ref().and_then(|v| v.source()));

            uses.insert(addr, (paddr, guid));
        }

        Self {
            bounds,
            stack_refs: Default::default(),
            resolver,
            uses,
        }
    }

    #[inline]
    fn stack_accesses(&self, project: &Project, block: &CodeBlock) -> Option<StackAccesses> {
        let mut stack_accesses =
            StackAccessVisitor::new(project.lifter(), project.functions(), project.injections());

        let rlock = self.stack_refs.read().ok()?;
        if let Some(srefs) = rlock.get(&block.function()) {
            let refs = srefs.blocks().get(&block.id())?;
            let accesses = stack_accesses.analyse_block(refs, block);
            return Some(accesses);
        }
        drop(rlock);

        let f = project.functions().get(block.function())?;
        let srefs = StackRefs::analyse_function(project, f);
        let refs = srefs.blocks().get(&block.id())?;
        let accesses = stack_accesses.analyse_block(refs, block);

        let mut wlock = self.stack_refs.write().ok()?;
        wlock.insert(f.id(), srefs);
        drop(wlock);

        Some(accesses)
    }
}

impl DecompilerTypeResolver for EFIProtocolTypeResolver {
    fn resolve_global_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        global: Address,
        size: usize,
    ) -> Option<Term<Type>> {
        match project.type_db().get_data_type_at(global) {
            Some(t) => Some(t),
            None => {
                let abits = project.lifter().address_bits();
                let tbits = (size as u32) * 8;
                if tbits != abits {
                    return None;
                }

                if let Some((Some(paddr), guid)) = self.uses.get(&use_at) {
                    if *paddr != global {
                        return None;
                    }

                    let tname = guid.strip_suffix("_GUID")?;
                    let proto = Type::pointer(project.type_db().get_type_for(tname, abits)?, abits);

                    return Some(proto);
                }

                None
            }
        }
    }

    fn resolve_stack_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        offset: i64,
        size: usize,
    ) -> Option<Term<Type>> {
        let abits = project.lifter().address_bits();
        let tbits = (size as u32) * 8;
        if tbits != abits {
            return None;
        }

        let tname = self
            .uses
            .get(&use_at)
            .map(|(_, g)| g)?
            .strip_suffix("_GUID")?;
        let proto = Type::pointer(project.type_db().get_type_for(tname, abits)?, abits);

        let bid = self.bounds.get(use_at).map(|(_, bid)| *bid)?;
        let blk = project.code_blocks().get(bid)?;
        let operand = self.resolver.input(2)?;

        let accesses = self.stack_accesses(project, blk)?;

        let found = accesses
            .call_states()
            .keys()
            .filter_map(|loc| {
                if loc.address() == use_at {
                    accesses.resolve_at(operand, project.lifter(), loc)
                } else {
                    None
                }
            })
            .any(|param_offset| param_offset == offset);

        if found {
            Some(proto)
        } else {
            None
        }
    }
}

fn get_name_from_type(type_: DataTypeRef) -> Option<String> {
    let t = type_.name()?;

    t.strip_prefix("EFI_")
        .or_else(|| t.strip_prefix("_EFI_"))
        .map(|s| s.to_case(Case::Pascal))
}

fn type_noptr(type_: DataTypeRef) -> DataTypeRef {
    let mut t = type_;
    while t.name().is_none() {
        let Some(noptr) = t.pointee() else { break };
        t = noptr;
    }
    t
}

impl DecompilerSymbolResolver for EFIProtocolTypeResolver {
    fn resolve_stack_variable_symbol(
        &self,
        _project: &Project,
        _name: &str,
        _uses: &[Address],
        _offset: i64,
        type_: DataTypeRef,
        _size: usize,
    ) -> Option<String> {
        get_name_from_type(type_noptr(type_))
    }

    fn resolve_register_symbol(
        &self,
        _project: &Project,
        _name: &str,
        _uses: &[Address],
        _register: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        get_name_from_type(type_noptr(type_))
    }

    fn resolve_temporary_symbol(
        &self,
        _project: &Project,
        _name: &str,
        _uses: &[Address],
        _temporary: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        get_name_from_type(type_noptr(type_))
    }

    fn resolve_global_variable_symbol(
        &self,
        _project: &Project,
        _name: &str,
        _uses: &[Address],
        _global: Address,
        type_: DataTypeRef,
        _size: usize,
    ) -> Option<String> {
        let Some(name) = get_name_from_type(type_noptr(type_)) else {
            return None;
        };
        Some(format!("g{name}"))
    }
}

fn annotate_interface(
    decompiler: &mut Decompiler,
    target: &Project,
    service: &ServiceInfo,
    i: usize,
) -> Option<()> {
    let guid = service.protocol()?;

    let interface = service
        .params()
        .iter()
        .find(|p| matches!(p, Some(p) if p.name() == "Interface"))?
        .as_ref()?;

    let addr = interface.value()?.to_address()?;

    if !target.memory().contains(addr) {
        return None;
    }

    let tname = guid.as_ref().strip_suffix("_GUID")?;
    let bits = target.lifter().address_bits();

    let interface_t = if let Some(type_) = target.type_db().get_type_for(tname, bits) {
        if interface.type_().pointee().is_some_and(|t| t.is_pointer()) {
            Type::pointer(type_, bits)
        } else {
            type_
        }
    } else {
        Type::pointer(Type::void(), bits)
    };

    let name = tname
        .strip_prefix("EFI_")
        .or_else(|| tname.strip_prefix("_EFI_"))
        .unwrap_or(tname)
        .to_case(Case::Pascal);

    decompiler
        .add_global(
            compact_str::format_compact!("g{name}{i}"),
            addr,
            &interface_t,
        )
        .ok()
}

pub fn annotate_globals(decompiler: &mut Decompiler, target: &Project) {
    let globals = target.get_analysis::<GlobalsAnalyser>();
    let guids = target.get_analysis::<GuidAnalyser>();
    let services = target.get_analysis::<ServicesAnalyser>();
    let strings = target.try_get_analysis::<StringsXRefDB>();

    let bits = target.lifter().address_bits();

    let guid_t = target.type_db().get_type_for("EFI_GUID", bits).unwrap();

    let ps_t = Type::npointer::<2>(
        target
            .type_db()
            .get_type_for("_EFI_PEI_SERVICES", bits)
            .unwrap(),
        bits,
    );
    let st_t = Type::pointer(
        target
            .type_db()
            .get_type_for("EFI_SYSTEM_TABLE", bits)
            .unwrap(),
        bits,
    );
    let bs_t = Type::pointer(
        target
            .type_db()
            .get_type_for("EFI_BOOT_SERVICES", bits)
            .unwrap(),
        bits,
    );
    let rt_t = Type::pointer(
        target
            .type_db()
            .get_type_for("EFI_RUNTIME_SERVICES", bits)
            .unwrap(),
        bits,
    );
    let sm_t = Type::pointer(
        target
            .type_db()
            .get_type_for("_EFI_SMM_SYSTEM_TABLE2", bits)
            .unwrap(),
        bits,
    );

    for (i, g) in globals
        .pei_services()
        .iter()
        .copied()
        .filter(|g| target.memory().contains(g))
        .enumerate()
    {
        decompiler
            .add_global(compact_str::format_compact!("gPeiServices{i}"), g, &ps_t)
            .ok();
    }

    for (i, g) in globals
        .system_table()
        .iter()
        .copied()
        .filter(|g| target.memory().contains(g))
        .enumerate()
    {
        decompiler
            .add_global(compact_str::format_compact!("gST{i}"), g, &st_t)
            .ok();
    }

    for (i, g) in globals
        .boot_services()
        .iter()
        .copied()
        .filter(|g| target.memory().contains(g))
        .enumerate()
    {
        decompiler
            .add_global(compact_str::format_compact!("gBS{i}"), g, &bs_t)
            .ok();
    }

    for (i, g) in globals
        .runtime_services()
        .iter()
        .copied()
        .filter(|g| target.memory().contains(g))
        .enumerate()
    {
        decompiler
            .add_global(compact_str::format_compact!("gRT{i}"), g, &rt_t)
            .ok();
    }

    for (i, g) in globals
        .sm_system_table()
        .iter()
        .copied()
        .filter(|g| target.memory().contains(g))
        .enumerate()
    {
        decompiler
            .add_global(compact_str::format_compact!("gSmst{i}"), g, &sm_t)
            .ok();
    }

    // GUIDs
    let exclude = guids.guid_db().get(&[0u8; 16]).map(ustr);
    for (addr, guid) in guids
        .guids()
        .filter(|(_, guid)| !matches!(exclude, Some(ex) if ex == *guid))
    {
        if decompiler.add_const(guid.as_str(), addr, &guid_t).is_err() {
            decompiler
                .add_const(compact_str::format_compact!("{guid}_{addr}"), addr, &guid_t)
                .ok();
        }
    }

    // Variables
    for svc in services
        .pei_services()
        .values()
        .chain(services.boot_services().values())
        .chain(services.runtime_services().values())
        .chain(services.smm_services().values())
    {
        for v in svc.params().iter() {
            let Some(v) = v else { continue };
            let Some(ServiceParamValue::ServiceData(data)) = v.value() else {
                continue;
            };

            if !matches!(data, ServiceData::VariableName(_)) {
                continue;
            }

            let Some(addr) = v.source() else { continue };

            if !target.memory().contains(&addr) {
                continue;
            }

            decompiler
                .add_utf16_pointer::<0>(compact_str::format_compact!("str{addr}"), addr)
                .ok();
        }
    }

    // Strings
    if let Some(strings) = strings {
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

    // Function names
    for (addr, name) in target
        .functions()
        .values()
        .filter_map(|f| f.name().map(|name| (f.address(), name)))
    {
        if let Some(t) = target.type_db().get_code_type_at(addr) {
            decompiler
                .add_function_symbol_with(name, addr, &t, t.is_variadic_function())
                .ok();
        } else {
            decompiler.add_function_symbol(name, addr).ok();
        }

        if let Some(fixup) = target.lifter().call_fixup_for(name) {
            decompiler.apply_call_fixup(fixup.name(), addr).ok();
        }
    }

    // Global interfaces
    for (i, (_, service)) in services
        .boot_services()
        .iter()
        .chain(services.smm_services())
        .filter(|(_, s)| s.protocol().is_some())
        .enumerate()
    {
        annotate_interface(decompiler, target, service, i);
    }
}
