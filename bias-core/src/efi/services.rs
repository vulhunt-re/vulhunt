use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::mem::{swap, take};

use fugue::bv::BitVec;
use fugue::ir::Address;
use thiserror::Error;

use super::globals::{GlobalsAnalyser, EFI_GLOBALS_ANALYSIS};
use super::guids::{GuidAnalyser, EFI_GUID_XREF_ANALYSIS};
use super::module::EFI_MODULE_INFO_ANALYSIS;
use super::pei::{GetPeiServicesFinder, SIDTHandler};
use crate::analyses::dataflow::reaching_constants::{ReachingConsts, DATAFLOW_REACHING_CONSTS};
use crate::analyses::xrefs::{XRefDB, XREF_ANALYSIS};
use crate::cio::TypeDB;
use crate::data::strings::StringData;
use crate::efi::btree::btreemap_drain;
use crate::efi::guids::{GuidDB, GUID_LEN};
use crate::efi::module::ModuleInfo;
use crate::eval::observer::common::OverrideVarAt;
use crate::eval::observer::{Observer, ObserverError, ObserverId};
use crate::eval::resolver::{CallSiteResolver, DataResolver, ResolverError};
use crate::eval::strategy::xforce::XForceStrategy;
use crate::eval::{Bound, Configuration, IRContext, IREvaluator};
use crate::ir::types::StructField;
use crate::ir::{BinOp, Expr, InsnTarget, Location, Stmt, Term, ToAddress, Type, Var};
use crate::kb::id::Identifiable;
use crate::kb::{ustr, uuid, Lazy, Ustr, Uuid};
use crate::lifter::DefaultPrototype;
use crate::prelude::{BitSize, CodeBlockId};
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::{lazy_ustr, Project};

pub const READ_SAVE_STATE: Lazy<Ustr> = lazy_ustr!("ReadSaveState");
pub const WRITE_SAVE_STATE: Lazy<Ustr> = lazy_ustr!("WriteSaveState");

pub const GET_VARIABLE: Lazy<Ustr> = lazy_ustr!("GetVariable");
pub const SET_VARIABLE: Lazy<Ustr> = lazy_ustr!("SetVariable");
pub const SMM_GET_VARIABLE: Lazy<Ustr> = lazy_ustr!("SmmGetVariable");
pub const SMM_SET_VARIABLE: Lazy<Ustr> = lazy_ustr!("SmmSetVariable");

pub const GET_SET_VARIABLE_API: Lazy<[Ustr; 4]> = Lazy::new(|| {
    [
        ustr("GetVariable"),
        ustr("SetVariable"),
        ustr("SmmGetVariable"),
        ustr("SmmSetVariable"),
    ]
});

pub const EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST: u32 = 0x80000000u32;
pub const EFI_PEI_PPI_DESCRIPTOR_LIST_LIMIT: usize = 10;

const INSN_BOUND: usize = 40;
const INTERFACE_CALL_INSN_BOUND: usize = 80;
const XFORCE_EXPLORATION_BOUND: usize = 150;
const FORWARD_EXPLORATION_BOUND: usize = 3;

#[derive(Debug, Error)]
pub enum Error {
    #[error("type information for {0} is not available")]
    TypeLookup(&'static str),
    #[error(transparent)]
    Tracer(#[from] crate::eval::Error),
    #[error(transparent)]
    TracerState(#[from] crate::eval::StateError),
    #[error("unsupported calling convention")]
    UnsupportedConvention,
}

impl From<Error> for AnalysisError {
    fn from(e: Error) -> Self {
        AnalysisError::Analysis(EFI_SERVICES_ANALYSIS, Box::new(e))
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct PeiDescriptor {
    flags: BitVec,
    guid: Ustr,
    address: Address,
}

impl PeiDescriptor {
    pub fn flags(&self) -> &BitVec {
        &self.flags
    }

    pub fn is_terminal(&self) -> bool {
        (self.flags.unsigned_cast(32).to_u32().unwrap() & EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST)
            != 0
    }

    pub fn guid(&self) -> Ustr {
        self.guid
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum ServiceData {
    PeiDescriptorList(Vec<PeiDescriptor>),
    Protocol(Ustr),
    VariableGuid(Ustr),
    VariableName(Ustr),
}

impl ServiceData {
    pub fn pei_notify_list(&self) -> Option<&[PeiDescriptor]> {
        if let Self::PeiDescriptorList(ref xs) = self {
            Some(xs)
        } else {
            None
        }
    }

    pub fn ppi_descriptor_list(&self) -> Option<&[PeiDescriptor]> {
        if let Self::PeiDescriptorList(ref xs) = self {
            Some(xs)
        } else {
            None
        }
    }

    pub fn variable_guid(&self) -> Option<Ustr> {
        if let Self::VariableGuid(guid) = self {
            Some(*guid)
        } else {
            None
        }
    }

    pub fn variable_name(&self) -> Option<Ustr> {
        if let Self::VariableName(name) = self {
            Some(*name)
        } else {
            None
        }
    }

    pub fn protocol(&self) -> Option<Ustr> {
        if let Self::Protocol(proto) = self {
            Some(*proto)
        } else {
            None
        }
    }
}

impl Display for ServiceData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(p) => p.fmt(f),
            Self::VariableGuid(p) => p.fmt(f),
            Self::VariableName(n) => n.fmt(f),
            Self::PeiDescriptorList(descrs) => write!(f, "{:#?}", descrs),
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct ServiceInfo {
    service: Ustr,
    data: Vec<ServiceData>,
    params: Vec<Option<ServiceParam>>,
    possible_data: BTreeSet<(Vec<ServiceData>, Vec<Option<ServiceParam>>)>,
}

impl Display for ServiceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.data.is_empty() {
            write!(f, "{} with {:#?}", self.service, self.data)?;
            for (d, _) in self.possible_data.iter() {
                if !d.is_empty() {
                    writeln!(f)?;
                    write!(f, "{} with {:#?}", self.service, d)?;
                }
            }
            Ok(())
        } else {
            write!(f, "{}", self.service)
        }
    }
}

impl ServiceInfo {
    pub fn new<S>(service: S) -> Self
    where
        S: Into<Ustr>,
    {
        Self {
            service: service.into(),
            data: Default::default(),
            params: Default::default(),
            possible_data: Default::default(),
        }
    }

    pub fn new_with<S, D>(service: S, data: D) -> Self
    where
        S: Into<Ustr>,
        D: Into<ServiceData>,
    {
        Self {
            service: service.into(),
            data: vec![data.into()],
            params: Default::default(),
            possible_data: Default::default(),
        }
    }

    pub fn data(&self) -> &[ServiceData] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut Vec<ServiceData> {
        &mut self.data
    }

    pub fn variable_guid(&self) -> Option<Ustr> {
        self.data.iter().find_map(|d| d.variable_guid())
    }

    pub fn variable_guids<'a>(&'a self) -> impl Iterator<Item = Ustr> + 'a {
        self.data
            .iter()
            .find_map(|d| d.variable_guid())
            .into_iter()
            .chain(
                self.possible_data
                    .iter()
                    .filter_map(|(d, _)| d.iter().find_map(|d| d.variable_guid())),
            )
    }

    pub fn variable_name(&self) -> Option<Ustr> {
        self.data.iter().find_map(|d| d.variable_name())
    }

    pub fn variable_names<'a>(&'a self) -> impl Iterator<Item = Ustr> + 'a {
        self.data
            .iter()
            .find_map(|d| d.variable_name())
            .into_iter()
            .chain(
                self.possible_data
                    .iter()
                    .filter_map(|(d, _)| d.iter().find_map(|d| d.variable_name())),
            )
    }

    pub fn variables<'a>(&'a self) -> impl Iterator<Item = (Option<Ustr>, Ustr)> + 'a {
        self.data
            .iter()
            .find_map(|d| d.variable_name().map(|v| (d.variable_guid(), v)))
            .into_iter()
            .chain(self.possible_data.iter().filter_map(|(d, _)| {
                d.iter()
                    .find_map(|d| d.variable_name().map(|v| (d.variable_guid(), v)))
            }))
    }

    pub fn protocol(&self) -> Option<Ustr> {
        self.data.iter().find_map(|d| d.protocol())
    }

    pub fn service(&self) -> Ustr {
        self.service
    }

    pub fn params(&self) -> &[Option<ServiceParam>] {
        &self.params
    }

    pub fn params_mut(&mut self) -> &mut Vec<Option<ServiceParam>> {
        &mut self.params
    }

    pub fn merge(&mut self, mut other: ServiceInfo) {
        assert_eq!(self.service, other.service);

        if self.data.len() < other.data.len() {
            swap(&mut self.data, &mut other.data);
            swap(&mut self.params, &mut other.params);
        }

        if self.data != other.data {
            self.possible_data.insert((other.data, other.params));
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum ServiceParamValue {
    Address(Address),
    ServiceData(ServiceData),
    Value(BitVec),
}

impl ToAddress for ServiceParamValue {
    fn to_address(&self) -> Option<Address> {
        match self {
            Self::Address(addr) => Some(*addr),
            Self::Value(bv) => bv.to_address(),
            _ => None,
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct ServiceParam {
    name: Ustr,
    type_: Term<Type>,
    source: Option<Address>,
    value: Option<ServiceParamValue>,
}

impl ServiceParam {
    pub fn new<N, A, V>(name: N, type_: Term<Type>, source: A, value: V) -> Self
    where
        N: Into<Ustr>,
        A: Into<Option<Address>>,
        V: Into<Option<ServiceParamValue>>,
    {
        Self {
            name: name.into(),
            type_,
            source: source.into(),
            value: value.into(),
        }
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn type_(&self) -> &Term<Type> {
        &self.type_
    }

    pub fn source(&self) -> Option<Address> {
        self.source
    }

    pub fn value(&self) -> Option<&ServiceParamValue> {
        self.value.as_ref()
    }

    pub fn into_value(self) -> Option<ServiceParamValue> {
        self.value
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum ServiceKind {
    Protocol,
    Variable,
}

impl ServiceKind {
    pub fn is_variable(&self) -> bool {
        matches!(self, Self::Variable)
    }

    pub fn is_protocol(&self) -> bool {
        matches!(self, Self::Protocol)
    }
}

impl Default for ServiceKind {
    fn default() -> Self {
        Self::Protocol
    }
}

pub struct ServiceDataResolver {
    param_values: Vec<Option<ServiceParam>>,
    service_kind: ServiceKind,
    service_data: Vec<ServiceData>,
    type_db: TypeDB,
    guid_db: GuidDB,

    ppi_descr_type: Term<Type>,
    pei_notify_type: Term<Type>,

    char16_type: Term<Type>,
    guid_type: Term<Type>,
}

impl ServiceDataResolver {
    pub fn new(project: &Project, guid_db: &GuidDB) -> Result<Self, Error> {
        let bits = project.lifter().address_bits();
        let typedb = project.type_db();
        let guid_type = typedb
            .get_type_for("EFI_GUID", bits)
            .ok_or_else(|| Error::TypeLookup("EFI_GUID"))?
            .resolve(typedb);
        let char16_type = typedb
            .get_type_for("CHAR16", bits)
            .ok_or_else(|| Error::TypeLookup("CHAR16"))?
            .resolve(typedb);
        let ppi_descr_type = typedb
            .get_type_for("EFI_PEI_PPI_DESCRIPTOR", bits)
            .ok_or_else(|| Error::TypeLookup("EFI_PEI_PPI_DESCRIPTOR"))?
            .resolve(typedb);
        let pei_notify_type = typedb
            .get_type_for("EFI_PEI_NOTIFY_DESCRIPTOR", bits)
            .ok_or_else(|| Error::TypeLookup("EFI_PEI_NOTIFY_DESCRIPTOR"))?
            .resolve(typedb);

        Ok(Self {
            param_values: Vec::default(),
            service_kind: Default::default(),
            service_data: Vec::default(),
            type_db: typedb.clone(),
            guid_db: guid_db.clone(),
            ppi_descr_type,
            pei_notify_type,
            char16_type,
            guid_type,
        })
    }

    pub fn resolve_call(
        &mut self,
        service: Ustr,
        call_resolver: &CallSiteResolver,
        context: &Box<dyn IRContext>,
        ftype: &Term<Type>,
    ) {
        self.service_data.clear();
        self.param_values.clear();
        self.service_kind = if GET_SET_VARIABLE_API.contains(&service) {
            ServiceKind::Variable
        } else {
            ServiceKind::Protocol
        };

        let fptyp = ftype.resolve(&self.type_db);
        tracing::trace!("resolved type: {fptyp}");

        if let Some(ftyp) = fptyp.pointee() {
            call_resolver.visit_args(context, &ftyp, self).ok();
        }
    }

    pub fn param_values(&self) -> &[Option<ServiceParam>] {
        &self.param_values
    }

    pub fn param_values_mut(&mut self) -> &mut Vec<Option<ServiceParam>> {
        &mut self.param_values
    }

    pub fn service_data(&self) -> &[ServiceData] {
        &self.service_data
    }

    pub fn service_data_mut(&mut self) -> &mut Vec<ServiceData> {
        &mut self.service_data
    }
}

impl ServiceDataResolver {
    fn resolve_char16_str(
        &self,
        context: &Box<dyn IRContext>,
        addr: Address,
    ) -> Option<ServiceData> {
        if let Some(varn) = context
            .read_bytes(addr, 128)
            .ok()
            .and_then(|buf| StringData::Utf16Le.decode(buf).ok())
        {
            Some(ServiceData::VariableName(varn.into()))
        } else {
            None
        }
    }

    fn resolve_guid(&self, context: &Box<dyn IRContext>, addr: Address) -> Option<Ustr> {
        if let Ok(bytes) = context.read_bytes(addr, GUID_LEN) {
            let service_data = if let Some(guid) = self.guid_db.get(bytes) {
                guid.into()
            } else {
                let guid = Uuid::from_bytes_le(bytes.try_into().unwrap());
                guid.hyphenated().to_string().into()
            };
            Some(service_data)
        } else {
            None
        }
    }

    fn resolve_ppi_descr_list(
        &self,
        context: &Box<dyn IRContext>,
        typedb: &TypeDB,
        addr: Address,
    ) -> Result<Option<Vec<PeiDescriptor>>, ResolverError> {
        let stype = self.ppi_descr_type.resolve(typedb);
        let fields = stype.struct_fields().unwrap();
        let size = stype.nbytes();

        let mut elems = Vec::with_capacity(0);
        let mut addr = addr;
        let mut done = false;

        while !done && elems.len() < EFI_PEI_PPI_DESCRIPTOR_LIST_LIMIT {
            let flags = addr + fields[0].offset();
            let guidp = addr + fields[1].offset();
            let ppi = addr + fields[2].offset();

            let flags = context.read_addr(flags, fields[0].nbits())?;

            let guidp = context.read_pointer(guidp)?;
            let guid = if let Some(guid) = self.resolve_guid(context, guidp) {
                guid
            } else {
                return Ok(None);
            };

            let address = context.read_pointer(ppi)?;

            let descr = PeiDescriptor {
                flags,
                guid,
                address,
            };

            done = descr.is_terminal();

            elems.push(descr);

            addr += size;
        }

        Ok(if elems.is_empty() { None } else { Some(elems) })
    }

    fn resolve_pei_notify_list(
        &self,
        context: &Box<dyn IRContext>,
        typedb: &TypeDB,
        addr: Address,
    ) -> Result<Option<Vec<PeiDescriptor>>, ResolverError> {
        let stype = self.pei_notify_type.resolve(typedb);
        let fields = stype.struct_fields().unwrap();
        let size = stype.nbytes();

        let mut elems = Vec::with_capacity(0);
        let mut addr = addr;
        let mut done = false;

        while !done && elems.len() < EFI_PEI_PPI_DESCRIPTOR_LIST_LIMIT {
            let flags = addr + fields[0].offset();
            let guidp = addr + fields[1].offset();
            let entry = addr + fields[2].offset();

            let flags = context.read_addr(flags, fields[0].nbits())?;

            let guidp = context.read_pointer(guidp)?;
            let guid = if let Some(guid) = self.resolve_guid(context, guidp) {
                guid
            } else {
                return Ok(None);
            };

            let address = context.read_pointer(entry)?;

            let descr = PeiDescriptor {
                flags,
                guid,
                address,
            };

            done = descr.is_terminal();

            elems.push(descr);

            addr += size;
        }

        Ok(if elems.is_empty() { None } else { Some(elems) })
    }

    pub fn resolve_source_and_value(
        &self,
        val: BitVec,
        typ: &Term<Type>,
    ) -> (Option<Address>, ServiceParamValue) {
        if typ.is_pointer() {
            if let Some(addr) = val.to_address() {
                return (Some(addr), ServiceParamValue::Address(addr));
            }
        }
        (None, ServiceParamValue::Value(val))
    }
}

impl DataResolver for ServiceDataResolver {
    fn resolve(
        &mut self,
        _context: &Box<dyn IRContext>,
        _typedb: &TypeDB,
        _var: Var,
        _typ: Term<Type>,
    ) -> Result<(), ResolverError> {
        self.param_values.push(None);
        Ok(())
    }

    fn resolve_named(
        &mut self,
        context: &Box<dyn IRContext>,
        typedb: &TypeDB,
        var: Var,
        name: Option<Ustr>,
        typ: Term<Type>,
    ) -> Result<(), ResolverError> {
        if let Some(name) = name {
            if typ.is_pointer_kind(|typ| typ.resolve(typedb) == self.guid_type) {
                if let Some(addr) = context.read_var(&var).ok().to_address() {
                    if let Some(guid) = self.resolve_guid(context, addr) {
                        let guid = if self.service_kind.is_variable() {
                            ServiceData::VariableGuid(guid)
                        } else {
                            ServiceData::Protocol(guid)
                        };
                        tracing::trace!("- {name}: {typ} = {guid}");
                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::ServiceData(guid.clone()),
                        )));
                        self.service_data.push(guid);
                    } else {
                        tracing::trace!("- {name}: {typ} = {addr}");
                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::Address(addr),
                        )));
                    }
                    return Ok(());
                }
            } else if typ.is_pointer_kind(|typ| typ.resolve(typedb) == self.char16_type) {
                if let Some(addr) = context.read_var(&var).ok().to_address() {
                    if let Some(varn) = self.resolve_char16_str(context, addr) {
                        tracing::trace!("- {name}: {typ} = {varn}");
                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::ServiceData(varn.clone()),
                        )));
                        self.service_data.push(varn);
                    } else {
                        tracing::trace!("- {name}: {typ} = {addr}");

                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::Address(addr),
                        )));
                    }
                    return Ok(());
                }
            } else if typ.is_pointer_kind(|typ| typ.resolve(typedb) == self.ppi_descr_type) {
                if let Some(addr) = context.read_var(&var).ok().to_address() {
                    if let Some(descrs) = self
                        .resolve_ppi_descr_list(context, typedb, addr)
                        .ok()
                        .flatten()
                    {
                        for (i, descr) in descrs.iter().enumerate() {
                            tracing::trace!("- {name}[{i}]: {}", self.ppi_descr_type);
                            tracing::trace!("  - Flags: {:x}", descr.flags());
                            tracing::trace!("  - Guid:  {}", descr.guid());
                            tracing::trace!("  - Ppi:   {}", descr.address());
                        }
                        let data = ServiceData::PeiDescriptorList(descrs);
                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::ServiceData(data.clone()),
                        )));
                        self.service_data.push(data);
                    } else {
                        tracing::trace!("- {name}: {typ} = {addr}");

                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::Address(addr),
                        )));
                    }
                    return Ok(());
                }
            } else if typ.is_pointer_kind(|typ| typ.resolve(typedb) == self.pei_notify_type) {
                if let Some(addr) = context.read_var(&var).ok().to_address() {
                    if let Some(descrs) = self
                        .resolve_pei_notify_list(context, typedb, addr)
                        .ok()
                        .flatten()
                    {
                        for (i, descr) in descrs.iter().enumerate() {
                            tracing::trace!("- {name}[{i}]: {}", self.pei_notify_type);
                            tracing::trace!("  - Flags:  {:x}", descr.flags());
                            tracing::trace!("  - Guid:   {}", descr.guid());
                            tracing::trace!("  - Notify: {}", descr.address());
                        }
                        let data = ServiceData::PeiDescriptorList(descrs);
                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::ServiceData(data.clone()),
                        )));
                        self.service_data.push(data);
                    } else {
                        tracing::trace!("- {name}: {typ} = {addr}");

                        self.param_values.push(Some(ServiceParam::new(
                            name,
                            typ,
                            addr,
                            ServiceParamValue::Address(addr),
                        )));
                    }
                    return Ok(());
                }
            } else {
                if let Some(val) = context.read_var(&var).ok() {
                    tracing::trace!("- {name}: {typ} = {val:x}");
                    let (source, value) = self.resolve_source_and_value(val, &typ);
                    self.param_values
                        .push(Some(ServiceParam::new(name, typ, source, value)));
                    return Ok(());
                }
            }
            self.param_values
                .push(Some(ServiceParam::new(name, typ, None, None)));
        } else {
            self.resolve(context, typedb, var, typ)?;
        }
        Ok(())
    }
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct ServicesAnalyser {
    boot_services: BTreeMap<Address, ServiceInfo>,
    runtime_services: BTreeMap<Address, ServiceInfo>,
    smm_services: BTreeMap<Address, ServiceInfo>,
    pei_services: BTreeMap<Address, ServiceInfo>,
    pattern_based: bool,
}

pub const EFI_SERVICES_ANALYSIS: uuid::Uuid = uuid("286CD607-96C0-4D4D-A022-2AA9465B85ED");

fn service_fields<'a>(typ: &'a Term<Type>, typedb: &TypeDB) -> Vec<&'a StructField> {
    if let Some(fields) = typ.struct_fields() {
        fields
            .iter()
            .filter_map(|field| {
                if field.type_().resolve(typedb).is_function_pointer() {
                    Some(field)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    } else {
        Vec::with_capacity(0)
    }
}

fn service_pointers<'a>(
    context: &mut Box<dyn IRContext>,
    base: Address,
    ttype: &Term<Type>,
    fields: &[&'a StructField],
) -> Result<BTreeMap<Address, (Ustr, Term<Type>)>, Error> {
    let mut mapping = BTreeMap::new();
    let service_start = base + ttype.nbytes() + 1usize;

    for (i, field) in fields.iter().enumerate() {
        let ptr = service_start + i;
        mapping.insert(ptr, (field.name(), field.type_().clone()));
        tracing::debug!(
            "writing service pointer {ptr} for {} @ {}",
            field.name(),
            base + field.offset()
        );
        context
            .write_pointer(base + field.offset(), ptr)
            .map_err(Error::from)?;
    }

    Ok(mapping)
}

struct ObserveServiceCall {
    services_ptrs: BTreeMap<Address, (Ustr, Term<Type>)>,
    services_list: BTreeMap<Address, ServiceInfo>, // output services list
    call_resolver: CallSiteResolver,
    data_resolver: ServiceDataResolver,
}

impl Observer for ObserveServiceCall {
    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        if let Some((service, stype)) = self.services_ptrs.get(&target) {
            tracing::trace!("service call to {service}: {stype}");
            self.data_resolver
                .resolve_call(*service, &self.call_resolver, &context, stype);

            let info = ServiceInfo {
                service: *service,
                data: take(self.data_resolver.service_data_mut()),
                params: take(self.data_resolver.param_values_mut()),
                possible_data: Default::default(),
            };

            match self.services_list.entry(location.address) {
                Entry::Vacant(data) => {
                    data.insert(info);
                }
                Entry::Occupied(mut data) => {
                    let ndata = data.get_mut();
                    let old_svc = ndata.service();
                    let new_svc = info.service();

                    if old_svc != new_svc {
                        tracing::debug!(
                            "service call conflict at {location}: could be {old_svc} or {new_svc}"
                        );
                        data.remove();
                    } else {
                        ndata.merge(info);
                    }
                }
            }
        }
        Ok(())
    }

    fn observe_pre_branch(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        target: Location,
    ) -> Result<(), ObserverError> {
        if target.position() != 0 {
            return Ok(());
        }

        self.observe_pre_call(context, location, target.address())
    }
}

struct ObserveVariableCall {
    locate_var_svc: BTreeSet<Address>,
    variable: Address,
    prototype: DefaultPrototype,
    index: usize,
}

impl Observer for ObserveVariableCall {
    fn observe_pre_call(
        &mut self,
        context: &mut Box<dyn IRContext>,
        location: Location,
        _target: Address,
    ) -> Result<(), ObserverError> {
        if self.locate_var_svc.contains(&location.address()) {
            // this is a LocatePpi/SmmLocateProtocol call; set return value to point correctly

            let retvp = self
                .prototype
                .resolved_input(self.index, context.read_stack_pointer()?) // FIXME: get the offset from the type
                .unwrap();
            if let Ok(retv) = context.read_var_addr(&retvp) {
                context.write_pointer(retv, self.variable)?;
            }
        }
        Ok(())
    }
}

struct ObserveTableWrite {
    bs_globals: BTreeSet<Address>,
    bs_mapping: Address,

    rt_globals: BTreeSet<Address>,
    rt_mapping: Address,

    smst_globals: BTreeSet<Address>,
    smst_mapping: Address,
}

impl ObserveTableWrite {
    pub fn new(
        globals: &GlobalsAnalyser,
        bs_mapping: Address,
        rt_mapping: Address,
        smst_mapping: Address,
    ) -> Self {
        Self {
            bs_globals: globals.boot_services().clone(),
            bs_mapping,
            rt_globals: globals.runtime_services().clone(),
            rt_mapping,
            smst_globals: globals.sm_system_table().clone(),
            smst_mapping,
        }
    }

    pub fn rewrite(&mut self, target: &Var, value: &mut BitVec) -> bool {
        if let Some(addr) = target.address() {
            let naddr = if self.bs_globals.contains(&addr) {
                self.bs_mapping
            } else if self.rt_globals.contains(&addr) {
                self.rt_mapping
            } else if self.smst_globals.contains(&addr) {
                self.smst_mapping
            } else {
                return false;
            };

            let aval = BitVec::from_u64(naddr.offset(), value.nbits() as usize);

            if *value != aval {
                *value = aval;
                return true;
            }
        }
        false
    }
}

impl Observer for ObserveTableWrite {
    fn observe_pre_var_write(
        &mut self,
        context: &mut Box<dyn IRContext>,
        _location: Location,
        var: &Var,
        val: &mut BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        if self.rewrite(var, val) {
            if let Some(fix) = sexpr.variable() {
                // also update the source of the write
                context.write_var(fix, val)?;
            }
        }
        Ok(())
    }
}

impl ServicesAnalyser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(pattern_based: bool) -> Self {
        Self {
            pattern_based,
            ..Default::default()
        }
    }

    pub fn with_pattern_based(&mut self, toggle: bool) -> &mut Self {
        self.pattern_based = toggle;
        self
    }

    pub fn boot_services(&self) -> &BTreeMap<Address, ServiceInfo> {
        &self.boot_services
    }

    pub fn runtime_services(&self) -> &BTreeMap<Address, ServiceInfo> {
        &self.runtime_services
    }

    pub fn smm_services(&self) -> &BTreeMap<Address, ServiceInfo> {
        &self.smm_services
    }

    pub fn pei_services(&self) -> &BTreeMap<Address, ServiceInfo> {
        &self.pei_services
    }

    pub fn contains<F>(&self, f: F) -> bool
    where
        F: Fn(&ServiceInfo) -> bool,
    {
        self.find(f).is_some()
    }

    pub fn find<F>(&self, f: F) -> Option<Address>
    where
        F: Fn(&ServiceInfo) -> bool,
    {
        self.boot_services()
            .iter()
            .find_map(|(a, p)| if f(p) { Some(*a) } else { None })
            .or_else(|| {
                self.runtime_services()
                    .iter()
                    .find_map(|(a, p)| if f(p) { Some(*a) } else { None })
            })
            .or_else(|| {
                self.smm_services()
                    .iter()
                    .find_map(|(a, p)| if f(p) { Some(*a) } else { None })
            })
            .or_else(|| {
                self.pei_services()
                    .iter()
                    .find_map(|(a, p)| if f(p) { Some(*a) } else { None })
            })
    }

    pub fn find_at<F>(&self, f: F) -> Option<(Address, &ServiceInfo)>
    where
        F: Fn(Address, &ServiceInfo) -> bool,
    {
        self.boot_services()
            .iter()
            .find_map(|(a, p)| if f(*a, p) { Some((*a, p)) } else { None })
            .or_else(|| {
                self.runtime_services()
                    .iter()
                    .find_map(|(a, p)| if f(*a, p) { Some((*a, p)) } else { None })
            })
            .or_else(|| {
                self.smm_services()
                    .iter()
                    .find_map(|(a, p)| if f(*a, p) { Some((*a, p)) } else { None })
            })
            .or_else(|| {
                self.pei_services()
                    .iter()
                    .find_map(|(a, p)| if f(*a, p) { Some((*a, p)) } else { None })
            })
    }

    fn find_smm_services_with(
        &self,
        project: &Project,
        guids: &GuidAnalyser,
        xrefs: &XRefDB,
        eval: &mut IREvaluator,
        obs_id: ObserverId,
        type_str: &'static str,
        guid_str: &'static str,
    ) -> Result<(), AnalysisError> {
        let addr_bytes = project.lifter().global_space().address_size();
        let addr_bits = addr_bytes as u32 * 8;

        let Some(idx) = guids.guid_db().get_index(guid_str) else {
            return Ok(());
        };

        let ty = project
            .type_db()
            .get_type_for(format!("_{type_str}"), addr_bits)
            .ok_or_else(|| Error::TypeLookup(type_str))?;
        let base = eval
            .static_mapping(type_str.to_lowercase(), None, ty.nbytes())
            .map_err(Error::from)?;

        let fields = service_fields(&ty, project.type_db());
        let ptrs = service_pointers(eval.context_mut(), base, &ty, &fields)?;

        let obs = eval
            .get_observer_mut::<ObserveServiceCall>(obs_id)
            .ok_or_else(|| AnalysisError::MissingContext)?;

        obs.services_ptrs.extend(ptrs);

        // collect unique addresses of Protocol interfaces and their locators
        let (locate_var_svc, interfaces) = obs
            .services_list
            .iter()
            .filter_map(|(addr, svc)| {
                if svc.service() == "SmmLocateProtocol" && svc.protocol()? == guid_str {
                    Some((*addr, svc.params().get(2)?.as_ref()?.source()?))
                } else {
                    None
                }
            })
            .fold(
                (BTreeSet::new(), BTreeSet::new()),
                |(mut locate_var_svc, mut interfaces), (call, interface)| {
                    locate_var_svc.insert(call);
                    interfaces.insert(interface);
                    (locate_var_svc, interfaces)
                },
            );

        for interface in interfaces.iter() {
            eval.context_mut().write_pointer(*interface, base).ok();
        }

        // collect all xrefs to protocol
        // thus when protocol is a global variable, we will cover all possible
        // calls of protocol interface functions
        let mut locations = interfaces
            .iter()
            .flat_map(|interface| xrefs.loads_from(interface).map(|(cb, _)| cb))
            .collect::<BTreeSet<_>>();

        if let Some(guid_xrefs) = guids.xrefs(idx) {
            // extend with xref to PROTOCOL_GUID
            // to cover cases when protocol is a local variable
            // in this case, we should evaluate from the block that contains the call to SmmLocateProtocol
            locations.extend(guid_xrefs);
        }

        let prototype = project.lifter().default_prototype();

        tracing::debug!(
            "locating interface calls; identified {} SmmLocateProtocol uses",
            locate_var_svc.len()
        );

        if let Some(fp) = project.lifter().frame_pointer() {
            let spv = eval
                .context()
                .read_stack_pointer()
                .map_err(Error::TracerState)?;

            tracing::debug!("setting frame pointer {fp} to {spv}");

            eval.context_mut()
                .write_var_addr(&fp, &spv)
                .map_err(Error::TracerState)?;
        }

        // this observer should only be triggered for
        // gSmst->SmmLocateProtocol(&PROTOCOL_GUID, 0LL, &Protocol)
        eval.register_observer(ObserveVariableCall {
            locate_var_svc,
            variable: base,
            prototype,
            index: 2,
        });

        eval.refreeze();

        // collect all start locations in BTreeSet to avoid
        // inconsistent resolution of the arguments
        let starts = locations
            .iter()
            .filter_map(|cb| {
                let block = &project.code_blocks()[*cb];
                let (start, _end) = project
                    .icfg
                    .non_strict_bounds(block.id(), project.tables())?;
                Some(start)
            })
            .collect::<BTreeSet<_>>();

        for start in starts {
            tracing::debug!("analysing xref to protocol from {start}");

            eval.configuration_mut().ignore_failures = true;
            eval.eval_with(
                project.tables(),
                start,
                Bound::Count(INTERFACE_CALL_INSN_BOUND),
                XForceStrategy::default(),
            )
            .ok();
            eval.configuration_mut().ignore_failures = false;

            eval.restore().map_err(Error::from)?;
        }

        Ok(())
    }
}

impl AnalysisInfo for ServicesAnalyser {
    const NAME: &'static str = "EFI Serivices Analyser";
    const UUID: uuid::Uuid = EFI_SERVICES_ANALYSIS;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        AnalysisSchedule::after::<XRefDB>(),
        AnalysisSchedule::after::<GlobalsAnalyser>(),
        AnalysisSchedule::after::<GuidAnalyser>(),
        AnalysisSchedule::after::<ModuleInfo>(),
        AnalysisSchedule::prefer_after::<GetPeiServicesFinder>(),
    ];
}

impl Analysis for ServicesAnalyser {
    fn id(&self) -> &uuid::Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut analysed = BTreeSet::new();
        let xrefs = project.analyses().get::<XRefDB>(XREF_ANALYSIS).unwrap();
        let module_info = project
            .analyses()
            .get::<ModuleInfo>(EFI_MODULE_INFO_ANALYSIS)
            .unwrap();

        let globals = project
            .analyses()
            .get::<GlobalsAnalyser>(EFI_GLOBALS_ANALYSIS)
            .unwrap();
        let guids = project
            .analyses()
            .get::<GuidAnalyser>(EFI_GUID_XREF_ANALYSIS)
            .unwrap();

        let guid_db = guids.guid_db().clone();

        let addr_bytes = project.lifter().global_space().address_size();
        let addr_bits = addr_bytes as u32 * 8;

        let bs = project
            .typedb
            .get_type_for("EFI_BOOT_SERVICES", addr_bits)
            .ok_or_else(|| Error::TypeLookup("EFI_BOOT_SERVICES"))?;
        let rt = project
            .typedb
            .get_type_for("EFI_RUNTIME_SERVICES", addr_bits)
            .ok_or_else(|| Error::TypeLookup("EFI_RUNTIME_SERVICES"))?;
        let smst = project
            .typedb
            .get_type_for("_EFI_SMM_SYSTEM_TABLE2", addr_bits)
            .ok_or_else(|| Error::TypeLookup("_EFI_SMM_SYSTEM_TABLE2"))?;
        let pei = project
            .typedb
            .get_type_for("_EFI_PEI_SERVICES", addr_bits)
            .ok_or_else(|| Error::TypeLookup("EFI_PEI_SERVICES"))?;

        let st = project
            .typedb
            .get_type_for("EFI_SYSTEM_TABLE", addr_bits)
            .ok_or_else(|| Error::TypeLookup("EFI_SYSTEM_TABLE"))?;
        let bs_foffset = st
            .offset_of_field("BootServices")
            .ok_or_else(|| Error::TypeLookup("EFI_SYSTEM_TABLE.BootServices"))?;
        let rt_foffset = st
            .offset_of_field("RuntimeServices")
            .ok_or_else(|| Error::TypeLookup("EFI_SYSTEM_TABLE.RuntimeServices"))?;

        let st_addr = Address::from(0xbaad_cafeu32);
        let bs_addr = Address::from(0xdead_faceu32);
        let rt_addr = Address::from(0xdead_cafeu32);
        let smst_addr = Address::from(0xf0d0_f00du32);

        let pei_addr = Address::from(0xfade_fadeu32);
        let pei_paddr = pei_addr - addr_bytes;

        let mut eval = project
            .evaluator(Configuration {
                enable_restores: true,
                ignore_invalid_accesses: true,
                ignore_invalid_branches: true,
                ignore_unimplemented_ops: true,
                ignore_divide_by_zero: true,
                ..Default::default()
            })
            .unwrap();

        if module_info.is_pei() {
            eval.static_mapping("pei", pei_paddr, pei.nbytes() + addr_bytes)
                .map_err(Error::from)?;

            tracing::trace!("writing gPeiServices pointer for entry");
            eval.context_mut()
                .write_pointer(pei_paddr, pei_addr)
                .map_err(Error::from)?;

            for ps in globals.pei_services().iter() {
                tracing::trace!("writing gPeiServices pointer at {ps}");
                eval.context_mut()
                    .write_pointer(*ps, pei_paddr)
                    .map_err(Error::from)?;
            }
        } else {
            eval.static_mapping("st", st_addr, st.nbytes())
                .map_err(Error::from)?;
            eval.static_mapping("bs", bs_addr, bs.nbytes())
                .map_err(Error::from)?;
            eval.static_mapping("rt", rt_addr, rt.nbytes())
                .map_err(Error::from)?;
            eval.static_mapping("smst", smst_addr, smst.nbytes())
                .map_err(Error::from)?;

            for st in globals.system_table().iter() {
                tracing::trace!("writing gST pointer at {st}");
                eval.context_mut()
                    .write_pointer(*st, st_addr)
                    .map_err(Error::from)?;
            }

            tracing::trace!("writing gBS pointer at {}", st_addr + bs_foffset);
            eval.context_mut()
                .write_pointer(st_addr + bs_foffset, bs_addr)
                .map_err(Error::from)?;

            tracing::trace!("writing gRT pointer at {}", st_addr + rt_foffset);
            eval.context_mut()
                .write_pointer(st_addr + rt_foffset, rt_addr)
                .map_err(Error::from)?;

            for bs in globals.boot_services().iter() {
                tracing::trace!("writing gBS pointer at {bs}");
                eval.context_mut()
                    .write_pointer(*bs, bs_addr)
                    .map_err(Error::from)?;
            }

            for rt in globals.runtime_services().iter() {
                tracing::trace!("writing gRT pointer at {rt}");
                eval.context_mut()
                    .write_pointer(*rt, rt_addr)
                    .map_err(Error::from)?;
            }

            for smst in globals.sm_system_table().iter() {
                tracing::trace!("writing gSmst pointer at {smst}");
                eval.context_mut()
                    .write_pointer(*smst, smst_addr)
                    .map_err(Error::from)?;
            }
        }

        let bs_services = service_fields(&bs, project.type_db());
        let rt_services = service_fields(&rt, project.type_db());
        let smst_services = service_fields(&smst, project.type_db());
        let pei_services = service_fields(&pei, project.type_db());

        let mut bs_services_ptrs = BTreeMap::new();
        let mut rt_services_ptrs = BTreeMap::new();
        let mut smst_services_ptrs = BTreeMap::new();
        let mut pei_services_ptrs = BTreeMap::new();

        if module_info.is_pei() {
            // write pointers of pei services
            pei_services_ptrs =
                service_pointers(eval.context_mut(), pei_addr, &pei, &pei_services)?;
        } else {
            // write pointers of boot services
            bs_services_ptrs = service_pointers(eval.context_mut(), bs_addr, &bs, &bs_services)?;

            // write pointers of runtime services
            rt_services_ptrs = service_pointers(eval.context_mut(), rt_addr, &rt, &rt_services)?;

            // write pointers of SMM services
            smst_services_ptrs =
                service_pointers(eval.context_mut(), smst_addr, &smst, &smst_services)?;
        }

        if module_info.is_pei() {
            // search for pei services
            let pei_obs_id = eval.register_observer(ObserveServiceCall {
                services_ptrs: pei_services_ptrs,
                services_list: Default::default(),
                data_resolver: ServiceDataResolver::new(&project, &guid_db)?,
                call_resolver: CallSiteResolver::new(&project),
            });

            eval.refreeze();

            // handles special case where if we are analysing the entry block,
            // we know that gPeiServices is in arg1.

            let stack_base = eval.context().read_stack_pointer().unwrap();
            let default_proto = project.lifter.default_prototype();
            let arg1 = default_proto
                .resolved_input(1, stack_base)
                .ok_or_else(|| Error::UnsupportedConvention)?;
            let entry = module_info.entry();

            for ps in globals.pei_services() {
                for (xref_to, _) in xrefs.loads_from(ps) {
                    let blk = &project.cbtable[xref_to];

                    if !analysed.insert(blk.address()) {
                        continue; // already analysed
                    }

                    tracing::debug!("load from gPeiServices via block at {}", blk.address());

                    if blk.address() == entry {
                        eval.context_mut()
                            .write_var(
                                &arg1,
                                &BitVec::from_u64(pei_paddr.into(), addr_bits as usize),
                            )
                            .map_err(Error::from)?;
                    }

                    eval.eval(
                        project.tables(),
                        blk.address(),
                        Bound::StopAfterOr(blk.last_address(), INSN_BOUND),
                    )
                    .ok();
                    eval.restore().map_err(Error::from)?;
                }

                for (xref_from, _) in xrefs.stores_to(ps) {
                    if let Some((start, end)) =
                        project.icfg.non_strict_bounds(xref_from, project.tables())
                    {
                        tracing::debug!("store to gPeiServices via block at {start}-{end}");

                        if start == entry {
                            eval.context_mut()
                                .write_var(
                                    &arg1,
                                    &BitVec::from_u64(pei_paddr.into(), addr_bits as usize),
                                )
                                .map_err(Error::from)?;
                        }

                        eval.eval(project.tables(), start, Bound::StopAfterOr(end, 40))
                            .ok();
                        eval.restore().map_err(Error::from)?;
                    }
                }
            }

            SIDTHandler::install(project.tables(), &mut eval, pei_paddr).map_err(Error::Tracer)?;

            // many uses of SIDT write to stack variables--hence we need a viable frame pointer
            if let Some(fp) = project.lifter().frame_pointer() {
                let spv = eval
                    .context()
                    .read_stack_pointer()
                    .map_err(Error::TracerState)?;
                tracing::debug!("setting frame pointer {fp} to {spv}");
                eval.context_mut()
                    .write_var_addr(&fp, &spv)
                    .map_err(Error::TracerState)?;
            }

            eval.refreeze();

            if self.pattern_based {
                // find possible service calls using indirect call offsets
                let sptrs = pei_services
                    .iter()
                    .filter_map(|s| {
                        let typ = s.type_().resolve(&project.typedb);
                        if typ.is_function_pointer() {
                            Some((Address::from(s.offset() as u64), (s.name(), typ)))
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeMap<Address, (Ustr, Term<Type>)>>();

                for block in project.code_blocks().values() {
                    if block.insns().len() <= 1 {
                        continue;
                    }

                    if block.last_operation().is_indirect_call() {
                        // candidates

                        let mut insn = block.last_insn().clone();
                        insn.compact_temporaries(project.lifter());

                        if let Some((target, _)) = insn
                            .last_operation()
                            .and_then(|op| op.indirect_call_target())
                            .and_then(|op| op.load_source())
                        {
                            if let Some((reg, offset)) = match &**target {
                                Expr::BinOp(BinOp::ADD, a, b) | Expr::BinOp(BinOp::ADD, b, a)
                                    if a.is_var_with(|v| v.is_register()) && b.is_val() =>
                                {
                                    (**b)
                                        .value()
                                        .to_address()
                                        .map(|offset| (*a.variable().unwrap(), offset))
                                }
                                Expr::Var(a) if a.is_register() => {
                                    // offset is 0
                                    Some((*a, Address::from(0u32)))
                                }
                                _ => None,
                            } {
                                // 1. this is the call target;
                                if let Some((svc, _typ)) = sptrs.get(&offset) {
                                    // 2. this is the sanity where gPeiServices is assigned in the block
                                    //
                                    // we scan the block to determine if `register` is set by a
                                    // load

                                    if let Some(gps) = block.insns().iter().rev().find_map(|insn| {
                                        let mut old = insn.clone();
                                        old.compact_temporaries(project.lifter());

                                        old.operations().iter().find_map(|op| {
                                            if let Stmt::Assign(var, expr) = &**op {
                                                if *var != reg {
                                                    return None;
                                                }
                                                if let Some((tgt, _)) = expr.load_source() {
                                                    tgt.variable().and_then(|var| {
                                                        if var.is_register() {
                                                            Some(*var)
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        })
                                    }) {
                                        tracing::trace!(
                                            "possible service call at {} (name: {svc}; gPeiServices at {gps})",
                                            block.last_insn().address()
                                        );

                                        let start = block.address();
                                        let end = block.last_address();

                                        eval.context_mut()
                                            .write_var_addr(&gps, &pei_paddr)
                                            .map_err(Error::TracerState)?;
                                        eval.eval(
                                            project.tables(),
                                            start,
                                            Bound::StopAfterOr(end, INSN_BOUND),
                                        )
                                        .ok();
                                        eval.restore().map_err(Error::from)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            tracing::debug!("analysing use of sidt to obtain location of gPeiServices");

            // now let's analyse gPeiServices being resolved via IDT- address_size
            for block in project.code_blocks().values() {
                if !block
                    .insns()
                    .iter()
                    .any(|insn| insn.operations().iter().any(SIDTHandler::matches))
                {
                    continue;
                }

                if let Some((start, end)) =
                    project.icfg.non_strict_bounds(block.id(), project.tables())
                {
                    tracing::debug!("analysing use of sidt in block at {start}-{end}");

                    if matches!(project.itable.get_point(block.last_address()), Some(insn) if insn.target_matches(InsnTarget::indirect_or_unresolved))
                    {
                        tracing::debug!("analysing use of sidt through intraprocedural analysis; last instruction at {}", block.last_address());

                        eval.eval(project.tables(), start, Bound::StopAfterOr(end, 40))
                            .ok();
                    } else {
                        // when we have a block not ending in an indirect call, we perform a
                        // XForce-style exploration
                        tracing::debug!("analysing use of sidt through interprocedural analysis");

                        eval.configuration_mut().ignore_failures = true;
                        eval.eval_with(
                            project.tables(),
                            start,
                            Bound::Count(XFORCE_EXPLORATION_BOUND),
                            XForceStrategy::default(),
                        )
                        .ok();
                        eval.configuration_mut().ignore_failures = false;
                    }

                    eval.restore().map_err(Error::from)?;
                }
            }

            if let Some(get_pei_services) = project.try_get_analysis::<GetPeiServicesFinder>() {
                get_pei_services
                    .install(project.tables(), &mut eval, pei_paddr)
                    .map_err(Error::Tracer)?;

                for block in project.code_blocks().values() {
                    if !get_pei_services.matches(block) {
                        continue;
                    }

                    let start = block.address();

                    tracing::debug!("analysing use of GetPeiServices through interprocedural analysis from {start}");

                    eval.configuration_mut().ignore_failures = true;
                    eval.eval_with(
                        project.tables(),
                        start,
                        Bound::Count(XFORCE_EXPLORATION_BOUND),
                        XForceStrategy::default(),
                    )
                    .ok();

                    eval.configuration_mut().ignore_failures = false;
                    eval.restore().map_err(Error::from)?;
                }
            }

            // xrefs to EFI_PEI_READ_ONLY_VARIABLE2_PPI_GUID
            if let Some(idx) = guid_db.get_index("EFI_PEI_READ_ONLY_VARIABLE2_PPI_GUID") {
                let variable2_ty = project
                    .type_db()
                    .get_type_for("_EFI_PEI_READ_ONLY_VARIABLE2_PPI", addr_bits)
                    .ok_or_else(|| Error::TypeLookup("EFI_PEI_READ_ONLY_VARIABLE2_PPI"))?;
                let variable2 = eval
                    .static_mapping("variable2", None, variable2_ty.nbytes())
                    .map_err(Error::from)?;

                let variable2_fields = service_fields(&variable2_ty, project.type_db());

                let variable2_ptrs = service_pointers(
                    eval.context_mut(),
                    variable2,
                    &variable2_ty,
                    &variable2_fields,
                )?;

                let obs = eval
                    .get_observer_mut::<ObserveServiceCall>(pei_obs_id)
                    .unwrap();

                obs.services_ptrs.extend(variable2_ptrs);

                let locate_ppi = obs
                    .services_list
                    .iter()
                    .filter_map(|(addr, svc)| {
                        if svc.service() == "LocatePpi" {
                            Some(*addr)
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeSet<Address>>();

                let prototype = project.lifter().default_prototype();

                tracing::debug!(
                    "locating GetVariable calls; identified {} LocatePpi uses",
                    locate_ppi.len()
                );

                eval.register_observer(ObserveVariableCall {
                    locate_var_svc: locate_ppi,
                    variable: variable2,
                    prototype,
                    index: 4,
                });

                eval.refreeze();

                for cb in guids.xrefs(idx).unwrap_or_default().iter() {
                    let block = &project.code_blocks()[*cb];

                    tracing::debug!(
                        "analysing xref to EFI_PEI_READ_ONLY_VARIABLE2_PPI_GUID at block {}",
                        block.address()
                    );

                    if let Some((start, _end)) =
                        project.icfg.non_strict_bounds(block.id(), project.tables())
                    {
                        eval.configuration_mut().ignore_failures = true;
                        eval.eval_with(
                            project.tables(),
                            start,
                            Bound::Count(INTERFACE_CALL_INSN_BOUND),
                            XForceStrategy::default(),
                        )
                        .ok();
                        eval.configuration_mut().ignore_failures = false;

                        eval.restore().map_err(Error::from)?;
                    }
                }

                if self.pattern_based {
                    // apply pattern analysis for GetVariable

                    let sptrs = variable2_fields
                        .iter()
                        .filter_map(|s| {
                            let typ = s.type_().resolve(&project.typedb);
                            if typ.is_function_pointer() {
                                Some((Address::from(s.offset() as u64), (s.name(), typ)))
                            } else {
                                None
                            }
                        })
                        .collect::<BTreeMap<Address, (Ustr, Term<Type>)>>();

                    for block in project.code_blocks().values() {
                        if block.insns().len() <= 1 {
                            continue;
                        }

                        if block.last_operation().is_indirect_call() {
                            // candidates

                            let mut insn = block.last_insn().clone();
                            insn.compact_temporaries(project.lifter());

                            if let Some((target, _)) = insn
                                .last_operation()
                                .and_then(|op| op.indirect_call_target())
                                .and_then(|op| op.load_source())
                            {
                                if let Some((reg, offset)) = match &**target {
                                    Expr::BinOp(BinOp::ADD, a, b)
                                    | Expr::BinOp(BinOp::ADD, b, a)
                                        if a.is_var_with(|v| v.is_register()) && b.is_val() =>
                                    {
                                        (**b)
                                            .value()
                                            .to_address()
                                            .map(|offset| (*a.variable().unwrap(), offset))
                                    }
                                    Expr::Var(a) if a.is_register() => {
                                        // offset is 0
                                        Some((*a, Address::from(0u32)))
                                    }
                                    _ => None,
                                } {
                                    // 1. this is the call target;
                                    if let Some((svc, _typ)) = sptrs.get(&offset) {
                                        // 2. this is the sanity where VariablePPI is assigned in the block
                                        //
                                        // we scan the block to determine if `register` is set by a
                                        // load

                                        tracing::trace!(
                                            "possible GetVariable call at {}",
                                            insn.address()
                                        );

                                        if let Some(gps) =
                                            block.insns().iter().rev().find_map(|insn| {
                                                let mut old = insn.clone();
                                                old.compact_temporaries(project.lifter());

                                                old.operations().iter().find_map(|op| {
                                                    if let Stmt::Store(_, expr, _, _) = &**op {
                                                        if let Some(tgt) = expr.variable() {
                                                            if *tgt == reg {
                                                                Some(insn.address())
                                                            } else {
                                                                None
                                                            }
                                                        } else {
                                                            None
                                                        }
                                                    } else {
                                                        None
                                                    }
                                                })
                                            })
                                        {
                                            tracing::trace!(
                                                "possible service call at {} (name: {svc} via {gps})",
                                                block.last_insn().address()
                                            );

                                            let start = block.address();
                                            let end = block.last_address();

                                            eval.register_observer(OverrideVarAt::new_addr(
                                                gps, reg, variable2,
                                            ));
                                            eval.eval(
                                                project.tables(),
                                                start,
                                                Bound::StopAfterOr(end, 40),
                                            )
                                            .ok();
                                            eval.restore().map_err(Error::from)?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let obs = eval
                .get_observer_mut::<ObserveServiceCall>(pei_obs_id)
                .unwrap();

            self.pei_services
                .extend(btreemap_drain(&mut obs.services_list));
        } else {
            eval.register_observer(ObserveTableWrite::new(globals, bs_addr, rt_addr, smst_addr));
            eval.refreeze();

            // search for boot services
            let bs_obs_id = eval.register_observer(ObserveServiceCall {
                services_ptrs: bs_services_ptrs,
                services_list: Default::default(),
                data_resolver: ServiceDataResolver::new(&project, &guid_db)?,
                call_resolver: CallSiteResolver::new(&project),
            });

            eval.refreeze();

            let mut block_analyser = BlockAnalyser {
                project,
                xrefs,
                consts: project
                    .analyses()
                    .get::<ReachingConsts>(DATAFLOW_REACHING_CONSTS),
                evaluator: &mut eval,
                analysed: &mut analysed,
                services: bs_services.as_ref(),
                services_address: bs_addr,
                services_observer: bs_obs_id,
                known_globals: globals
                    .boot_services()
                    .iter()
                    .copied()
                    .chain(globals.runtime_services().iter().copied())
                    .chain(globals.sm_system_table().iter().copied())
                    .chain(globals.system_table().iter().copied())
                    .collect(),
                pattern_based: self.pattern_based
                    && globals.boot_services().is_empty()
                    && globals.runtime_services().is_empty(),
            };

            block_analyser.analyse_table(globals.boot_services())?;

            let obs = block_analyser
                .evaluator
                .get_observer_mut::<ObserveServiceCall>(bs_obs_id)
                .unwrap();
            self.boot_services
                .extend(btreemap_drain(&mut obs.services_list));

            // search for gST->BootServices
            block_analyser.evaluator.refreeze();
            block_analyser.analyse_table(globals.system_table())?;

            let obs = block_analyser
                .evaluator
                .get_observer_mut::<ObserveServiceCall>(bs_obs_id)
                .unwrap();
            self.boot_services
                .extend(btreemap_drain(&mut obs.services_list));

            // search for runtime services
            let rt_obs_id = block_analyser
                .evaluator
                .register_observer(ObserveServiceCall {
                    services_ptrs: rt_services_ptrs,
                    services_list: Default::default(),
                    data_resolver: ServiceDataResolver::new(&project, &guid_db)?,
                    call_resolver: CallSiteResolver::new(&project),
                });

            block_analyser.evaluator.refreeze();
            block_analyser.services = rt_services.as_ref();
            block_analyser.services_address = rt_addr;
            block_analyser.services_observer = rt_obs_id;

            block_analyser.analyse_table(globals.runtime_services())?;

            let obs = block_analyser
                .evaluator
                .get_observer_mut::<ObserveServiceCall>(rt_obs_id)
                .unwrap();
            self.runtime_services
                .extend(btreemap_drain(&mut obs.services_list));

            // search for gST->RuntimeServices
            block_analyser.analysed.clear();
            block_analyser.evaluator.refreeze();
            block_analyser.analyse_table(globals.system_table())?;

            let obs = block_analyser
                .evaluator
                .get_observer_mut::<ObserveServiceCall>(rt_obs_id)
                .unwrap();
            self.runtime_services
                .extend(btreemap_drain(&mut obs.services_list));

            // search for SMM services
            let smst_obs_id = block_analyser
                .evaluator
                .register_observer(ObserveServiceCall {
                    services_ptrs: smst_services_ptrs,
                    services_list: Default::default(),
                    data_resolver: ServiceDataResolver::new(&project, &guid_db)?,
                    call_resolver: CallSiteResolver::new(&project),
                });

            block_analyser.services = smst_services.as_ref();
            block_analyser.services_address = smst_addr;
            block_analyser.services_observer = smst_obs_id;
            block_analyser.analysed.clear();
            block_analyser.evaluator.refreeze();

            for smst in globals.sm_system_table() {
                for (xref_to, _) in xrefs.loads_from(smst) {
                    block_analyser.analyse_load(xref_to)?;
                }
            }

            // search for SMM protocol interfaces by protocol name/GUID
            for (type_str, guid_str) in [
                (
                    "EFI_SMM_VARIABLE_PROTOCOL",
                    "EFI_SMM_VARIABLE_PROTOCOL_GUID",
                ),
                ("EFI_SMM_CPU_PROTOCOL", "EFI_SMM_CPU_PROTOCOL_GUID"),
            ] {
                self.find_smm_services_with(
                    project,
                    guids,
                    xrefs,
                    &mut eval,
                    smst_obs_id,
                    type_str,
                    guid_str,
                )
                .ok();
            }

            let obs = eval
                .get_observer_mut::<ObserveServiceCall>(smst_obs_id)
                .unwrap();
            self.smm_services
                .extend(btreemap_drain(&mut obs.services_list));
        }

        Ok(())
    }
}

struct BlockAnalyser<'a> {
    project: &'a Project,
    xrefs: &'a XRefDB,
    consts: Option<&'a ReachingConsts>,
    evaluator: &'a mut IREvaluator,
    analysed: &'a mut BTreeSet<Address>,
    services: &'a [&'a StructField],
    services_address: Address,
    services_observer: ObserverId,
    known_globals: BTreeSet<Address>,
    pattern_based: bool,
}

impl<'a> BlockAnalyser<'a> {
    #[inline]
    fn analyse_table(&mut self, globals: &BTreeSet<Address>) -> Result<(), Error> {
        for global in globals {
            for (xref_to, _) in self.xrefs.loads_from(global) {
                self.analyse_load(xref_to)?;
            }

            for (xref_from, _) in self.xrefs.stores_to(global) {
                self.analyse_store(xref_from)?;
            }
        }

        let obs = self
            .evaluator
            .get_observer::<ObserveServiceCall>(self.services_observer)
            .unwrap();

        if self.pattern_based && obs.services_list.is_empty() && globals.is_empty() {
            // find possible service calls using indirect call offsets
            let sptrs = self
                .services
                .iter()
                .filter_map(|s| {
                    let typ = s.type_().resolve(&self.project.typedb);
                    if typ.is_function_pointer() {
                        Some((Address::from(s.offset() as u64), (s.name(), typ)))
                    } else {
                        None
                    }
                })
                .collect::<BTreeMap<Address, (Ustr, Term<Type>)>>();

            for block in self.project.code_blocks().values() {
                if block.insns().len() <= 1 {
                    continue;
                }

                if block.last_operation().is_indirect_call() {
                    // candidates

                    let mut insn = block.last_insn().clone();
                    insn.compact_temporaries(self.project.lifter());

                    if let Some((target, _)) = insn
                        .last_operation()
                        .and_then(|op| op.indirect_call_target())
                        .and_then(|op| op.load_source())
                    {
                        if let Some((reg, offset)) = match &**target {
                            Expr::BinOp(BinOp::ADD, a, b) | Expr::BinOp(BinOp::ADD, b, a)
                                if a.is_var_with(|v| v.is_register()) && b.is_val() =>
                            {
                                (**b)
                                    .value()
                                    .to_address()
                                    .map(|offset| (*a.variable().unwrap(), offset))
                            }
                            Expr::Var(a) if a.is_register() => {
                                // offset is 0
                                Some((*a, Address::from(0u32)))
                            }
                            _ => None,
                        } {
                            // 1. this is the call target;
                            if let Some((svc, _typ)) = sptrs.get(&offset) {
                                // 2. this is the sanity where the service pointer is assigned in the block

                                if let Some(gsp) = block.insns().iter().rev().find_map(|insn| {
                                    let mut old = insn.clone();
                                    old.compact_temporaries(self.project.lifter());

                                    old.operations().iter().find_map(|op| {
                                        if let Stmt::Assign(var, expr) = &**op {
                                            if *var != reg {
                                                return None;
                                            }

                                            if let Some((tgt, _)) = expr.load_source() {
                                                if let Some(var) = tgt.variable() {
                                                    if var.is_register() {
                                                        Some(*var)
                                                    } else {
                                                        None
                                                    }
                                                } else if let Some(addr) =
                                                    tgt.constant().to_address()
                                                {
                                                    if self.project.memory.contains(addr)
                                                        && !self.known_globals.contains(&addr)
                                                    {
                                                        Some(Var::new0(
                                                            self.project.lifter.global_space_id(),
                                                            addr.offset(),
                                                            self.project.lifter.address_bits(),
                                                        ))
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else if let Some(avar) =
                                                expr.variable().and_then(|avar| avar.address())
                                            {
                                                if self.project.memory.contains(avar)
                                                    && !self.known_globals.contains(&avar)
                                                {
                                                    Some(Var::new0(
                                                        self.project.lifter.global_space_id(),
                                                        avar.offset(),
                                                        self.project.lifter.address_bits(),
                                                    ))
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                }) {
                                    tracing::trace!(
                                        "possible service call at {} (name: {svc}; service pointer at {gsp})",
                                        block.last_insn().address()
                                    );

                                    let start = block.address();
                                    let end = block.last_address();

                                    self.evaluator
                                        .context_mut()
                                        .write_var_addr(&gsp, &self.services_address)
                                        .map_err(Error::TracerState)?;
                                    self.evaluator
                                        .eval(
                                            self.project.tables(),
                                            start,
                                            Bound::StopAfterOr(end, INSN_BOUND),
                                        )
                                        .ok();
                                    self.evaluator.restore().map_err(Error::from)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[inline]
    fn analyse_load(&mut self, block: CodeBlockId) -> Result<(), Error> {
        let mut blk = &self.project.cbtable[block];

        let mut count = 0;
        let mut flows_inter = false;
        let mut next_addr = None;

        if let Some(consts) = self.consts {
            let cs = &consts.mapping()[&blk.function()].blocks()[&block];
            for (v, c) in cs.incoming_values() {
                self.evaluator.context_mut().write_var(v, c)?;
            }
        }

        while !flows_inter && count < FORWARD_EXPLORATION_BOUND {
            if !self.analysed.insert(blk.address()) {
                self.evaluator.restore()?;
                return Ok(());
            }

            tracing::debug!("analysing block at {}", blk.address());

            let bounds = self
                .project
                .icfg
                .non_strict_chain(blk.id(), 1, self.project.tables());
            let expected_end = bounds
                .last()
                .map(|(_, end)| *end)
                .unwrap_or_else(|| blk.last_address());

            if bounds.is_empty() {
                next_addr = self
                    .evaluator
                    .eval(
                        self.project.tables(),
                        blk.address(),
                        Bound::StopAfterOr(expected_end, INSN_BOUND),
                    )
                    .ok();
                flows_inter = blk.flows_inter() || blk.is_indirect_jump()
            } else {
                for (start, end) in bounds.iter() {
                    next_addr = self
                        .evaluator
                        .eval(
                            self.project.tables(),
                            *start,
                            Bound::StopAfterOr(*end, INSN_BOUND),
                        )
                        .ok();

                    flows_inter |= self
                        .project
                        .cbtable
                        .get_point(start)
                        .map(|blk| blk.is_call() || blk.is_indirect_jump())
                        .unwrap_or_default();
                }

                if next_addr != Some(expected_end) && flows_inter {
                    // Re-run the last block in parts and skip calls.
                    //
                    // NOTE: since flow_inter is true, will end the
                    // forward exploration after this extra analysis.
                    //
                    // We use this extra analysis to handle cases where
                    // we have multiple calls in a block that clobber
                    // constants that should be preserved, or flow into
                    // a call that does not return within `INSN_BOUND`.
                    //
                    // For soundness, we should restrict the restoration
                    // to unaffected registers, as defined by the calling
                    // convention.

                    self.evaluator.restore().map_err(Error::from)?;

                    if let Some(consts) = self.consts {
                        let cs = &consts.mapping()[&blk.function()].blocks()[&blk.id()];
                        for (v, c) in cs.incoming_values() {
                            self.evaluator.context_mut().write_var(v, c)?;
                        }
                    }

                    let bounds = self
                        .project
                        .icfg
                        .non_strict_blocks(blk.id(), self.project.tables());
                    for (start, end) in bounds.iter() {
                        self.evaluator
                            .eval(
                                self.project.tables(),
                                *start,
                                Bound::StopAfterOr(*end, INSN_BOUND),
                            )
                            .ok();

                        // pop the stack depending on the calling convention
                        let sp = self.evaluator.context().read_stack_pointer()?;
                        self.evaluator.context_mut().write_stack_pointer(
                            sp + self
                                .project
                                .lifter
                                .convention()
                                .default_prototype()
                                .extra_pop(),
                        )?;
                    }
                }
            };

            // ensure that we are following a path
            if self.evaluator.context().read_program_counter()? != expected_end {
                break;
            }

            // ensure that the next address is a viable block
            if let Some(next_blk) = next_addr.and_then(|addr| self.project.cbtable.get_point(addr))
            {
                // ensure we only explore the current function
                if next_blk.function() != blk.function() {
                    break;
                }
                blk = next_blk;
            } else {
                break;
            }

            count += 1;
        }

        self.evaluator.restore().map_err(Error::from)?;

        Ok(())
    }

    #[inline]
    fn analyse_store(&mut self, block: CodeBlockId) -> Result<(), Error> {
        if let Some((start, end)) = self
            .project
            .icfg
            .non_strict_bounds(block, self.project.tables())
        {
            self.evaluator
                .eval(
                    self.project.tables(),
                    start,
                    Bound::StopAfterOr(end, INSN_BOUND),
                )
                .ok();
            self.evaluator.restore().map_err(Error::from)?;
        }

        Ok(())
    }
}
