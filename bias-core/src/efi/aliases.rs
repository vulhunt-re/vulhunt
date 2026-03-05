use crate::analyses::symbolic::typed::*;
use crate::efi::pei::SIDT;
use crate::efi::services::EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST;
use crate::prelude::efi::*;
use crate::prelude::*;

pub struct EFITypeResolver<'a> {
    guiddb: &'a GuidDB,
}

impl<'a> EFITypeResolver<'a> {
    pub fn new(project: &'a Project) -> Self {
        Self {
            guiddb: project
                .analyses()
                .get_by::<GuidAnalyser>()
                .unwrap()
                .guid_db(),
        }
    }

    #[inline]
    pub fn resolve_protocol_type(
        &self,
        context: &AliasTypingContext,
        guid: &[u8],
    ) -> Option<Term<Type>> {
        let bytes = &guid[..guid.len().min(16)];
        let proto = self.guiddb.get(bytes)?.strip_suffix("_GUID")?;

        context
            .typedb
            .get_type_for(proto, context.lifter.address_bits())
    }

    #[inline]
    pub fn resolve_protocol_via_guid(
        &self,
        context: &AliasTypingContext,
        from: &AliasValue,
    ) -> Option<Term<Type>> {
        context
            .with_bytes(from, |bytes| self.resolve_protocol_type(context, bytes))
            .flatten()
    }

    #[inline]
    pub fn resolve_ppi_descriptors(
        &self,
        context: &AliasTypingContext,
        from: &AliasValue,
        notify: bool,
    ) -> Vec<Address> {
        context
            .with_bytes(from, |bytes| {
                let t = context
                    .typedb
                    .get_type_for("EFI_PEI_PPI_DESCRIPTOR", context.address_bits())
                    .unwrap()
                    .resolve(context.typedb);

                let fields = t.struct_fields().unwrap();
                let type_bytes = t.nbytes();

                let flags = &fields[0];
                let guidp = &fields[1];
                let pointer = &fields[2];

                let mut ppis = Vec::new();

                for ppi_bytes in bytes.chunks_exact(type_bytes) {
                    let flags_bytes =
                        &ppi_bytes[flags.offset()..flags.offset() + flags.type_().nbytes()];
                    let guidp_bytes =
                        &ppi_bytes[guidp.offset()..guidp.offset() + guidp.type_().nbytes()];
                    let pointer_bytes =
                        &ppi_bytes[pointer.offset()..pointer.offset() + pointer.type_().nbytes()];

                    // TODO: make endianness generic
                    let flags = BitVec::from_le_bytes(flags_bytes).to_u32().unwrap();
                    let _guidp = BitVec::from_le_bytes(guidp_bytes).to_address().unwrap();
                    let pointer = BitVec::from_le_bytes(pointer_bytes).to_address().unwrap();

                    if notify {
                        ppis.push(pointer);
                    } else {
                        if let Some(addr_bytes) = context
                            .memory
                            .view_bytes(pointer, context.address_bytes())
                            .ok()
                        {
                            let pointer = BitVec::from_le_bytes(addr_bytes).to_address().unwrap();
                            ppis.push(pointer);
                        }
                    }

                    if (flags & EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST) != 0 {
                        break;
                    }
                }

                ppis
            })
            .unwrap_or_default()
    }
}

impl IntraContextualTypeResolver for EFITypeResolver<'_> {
    type Resolver<'a> = EFITypeResolver<'a>;

    fn resolve_with_context<'a, 'c: 'a>(
        project: &'a Project,
        _context: &mut AnalysisContext<'c>,
    ) -> EFITypeResolver<'a> {
        EFITypeResolver::new(project)
    }
}

impl InterContextualTypeResolver for EFITypeResolver<'_> {
    type Resolver<'a> = EFITypeResolver<'a>;

    fn resolve_with_context<'a, 'c: 'a>(
        project: &'a Project,
        _contexts: CallSiteContextsRef<'a>,
        _rcontexts: IncomingContextsRef<'a>,
        _context: &mut AnalysisContext<'c>,
    ) -> EFITypeResolver<'a> {
        EFITypeResolver::new(project)
    }
}

impl<'a> ContextualTypeResolver<'a> for EFITypeResolver<'a> {
    fn resolve_type_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        target: Option<Address>,
        t: &Term<Type>,
    ) -> Option<ResolvedType> {
        if t.is_named_with(|name| name == "EFI_LOCATE_PROTOCOL") {
            if let Some(protocol) = context
                .input_operand_value(0)
                .and_then(|v| self.resolve_protocol_via_guid(context, v))
            {
                let t = t.resolve(context.typedb).pointee().unwrap().clone();
                let mut args = t.function_args().unwrap().to_vec();

                let vtt = Type::pointer(
                    Type::pointer(protocol, context.stack_pointer.nbits()),
                    context.stack_pointer.nbits(),
                );

                args[2] = FunctionArg::new(args[2].name(), vtt.clone());

                if let Some(vtv) = context.input_operand_value(2).cloned() {
                    let vtt = AliasType::typed(vtt);
                    context.update_aliases(vtv, vtt, true);
                }

                return Some(
                    Type::function(t.function_return().unwrap().clone(), args.into_iter()).into(),
                );
            } else {
                if let Some(vtv) = context.input_operand_value(2).cloned() {
                    let vtt = AliasType::typed(Type::pointer(
                        Type::pointer(Type::void(), context.stack_pointer.nbits()),
                        context.stack_pointer.nbits(),
                    ));

                    context.update_aliases(vtv, vtt, true);
                }
            }
        }

        if t.is_named_with(|name| name == "EFI_PEI_LOCATE_PPI") {
            if let Some(protocol) = context
                .input_operand_value(1)
                .and_then(|v| self.resolve_protocol_via_guid(context, v))
            {
                let t = t.resolve(context.typedb).pointee().unwrap().clone();
                let mut args = t.function_args().unwrap().to_vec();

                let vtt = Type::npointer::<2>(protocol, context.stack_pointer.nbits());

                args[4] = FunctionArg::new(args[4].name(), vtt.clone());

                if let Some(vtv) = context.input_operand_value(4).cloned() {
                    let vtt = AliasType::typed(vtt);
                    context.update_aliases(vtv, vtt, true);
                }

                return Some(
                    Type::function(t.function_return().unwrap().clone(), args.into_iter()).into(),
                );
            } else {
                if let Some(vtv) = context.input_operand_value(4).cloned() {
                    let vtt = AliasType::typed(Type::npointer::<2>(
                        Type::void(),
                        context.stack_pointer.nbits(),
                    ));

                    context.update_aliases(vtv, vtt, true);
                }
            }
        }

        if t.is_named_with(|name| name == "EFI_PEI_INSTALL_PPI") {
            if let Some(descriptors) = context
                .input_operand_value(1)
                .map(|v| self.resolve_ppi_descriptors(context, v, false))
            {
                let t = context
                    .typedb
                    .get_type_for("EFI_PEIM_NOTIFY_ENTRY_POINT", context.address_bits())
                    .unwrap()
                    .resolve(context.typedb)
                    .pointee()
                    .unwrap()
                    .resolve(context.typedb);

                for descriptor in descriptors
                    .into_iter()
                    .filter(|addr| context.functions.contains_point(addr))
                {
                    context.global_variables.insert(
                        descriptor,
                        TypedAliasValue::typed_top(
                            t.clone(),
                            AliasOrigin::new_for(context.location, descriptor, 1),
                        ),
                    );
                }
            }
        }

        if t.is_named_with(|name| name == "EFI_PEI_NOTIFY_PPI") {
            if let Some(descriptors) = context
                .input_operand_value(1)
                .map(|v| self.resolve_ppi_descriptors(context, v, true))
            {
                let t = context
                    .typedb
                    .get_type_for("EFI_PEIM_NOTIFY_ENTRY_POINT", context.address_bits())
                    .unwrap()
                    .resolve(context.typedb)
                    .pointee()
                    .unwrap()
                    .resolve(context.typedb);

                for descriptor in descriptors
                    .into_iter()
                    .filter(|addr| context.functions.contains_point(addr))
                {
                    context.global_variables.insert(
                        descriptor,
                        TypedAliasValue::typed_top(
                            t.clone(),
                            AliasOrigin::new_for(context.location, descriptor, 1),
                        ),
                    );
                }
            }
        }

        DEFAULT_TYPE_RESOLVER.resolve_type_with(context, target, t)
    }

    fn resolve_intrinsic_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        name: Ustr,
        arguments: Vec<TypedAliasValue>,
        bits: Option<u32>,
    ) -> Option<TypedAliasValue> {
        if name == *SIDT {
            let t = context
                .typedb
                .get_type_for("EFI_PEI_SIDT", context.address_bits())
                .unwrap()
                .resolve(context.typedb)
                .pointee()
                .unwrap()
                .resolve(context.typedb);

            Some(TypedAliasValue::new(
                AliasValue::Bot,
                AliasType::typed(t),
                context.location,
            ))
        } else {
            DEFAULT_TYPE_RESOLVER.resolve_intrinsic_with(context, name, arguments, bits)
        }
    }

    fn resolve_entry_type(&self, context: &mut AliasTypingContext<'a>, function: &'a Function) {
        DEFAULT_TYPE_RESOLVER.resolve_entry_type(context, function)
    }
}

pub type IEFITypeResolver<'a> = ITypeResolver<'a, EFITypeResolver<'a>>;

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct EFITypedAliases {
    aliases: TypedAliases,
    config: EFITypedAliasesConfig,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct EFITypedAliasesConfig {
    pub update_globals: bool,
    pub update_indirects: bool,
}

impl EFITypedAliasesConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_update_globals(&mut self, update_globals: bool) {
        self.update_globals = update_globals
    }

    pub fn with_update_globals(mut self, update_globals: bool) -> Self {
        self.set_update_globals(update_globals);
        self
    }

    pub fn set_update_indirects(&mut self, update_indirects: bool) {
        self.update_indirects = update_indirects
    }

    pub fn with_update_indirects(mut self, update_indirects: bool) -> Self {
        self.set_update_indirects(update_indirects);
        self
    }
}

impl Default for EFITypedAliasesConfig {
    fn default() -> Self {
        Self {
            update_globals: true,
            update_indirects: false,
        }
    }
}

impl EFITypedAliases {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(config: EFITypedAliasesConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, TypedFunctionAliases> {
        self.aliases.mapping()
    }
}

impl AnalysisInfo for EFITypedAliases {
    const UUID: Uuid = uuid("20815A3E-9733-4F54-B592-7D700BCA4897");
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[
        Schedule::After(EFI_GUID_XREF_ANALYSIS),
        Schedule::After(EFI_GLOBALS_ANALYSIS),
        Schedule::After(EFI_SERVICES_ANALYSIS),
    ];
    const NAME: &'static str = "Interprocedural typed aliases";
}

impl Analysis for EFITypedAliases {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let cg = CallGraph::new_with(&project);

        self.aliases.analyse_slice_with::<IEFITypeResolver>(
            project,
            &cg,
            self.config.update_globals,
        );

        if self.config.update_indirects {
            self.aliases.update_indirects(project);
        }

        Ok(())
    }
}
