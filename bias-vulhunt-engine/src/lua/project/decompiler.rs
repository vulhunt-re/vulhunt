use std::collections::BTreeMap;
use std::sync::Arc;

use bias_core::{ir::VisitVars, prelude::*};
use bias_core::decompiler::{
    DataTypeRef, DecompilerResolver, DecompilerSymbolResolver, DecompilerTypeResolver,
};

use iset::IntervalMap;
use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

enum FunctionAnnotation {
    Def {
        name: String,
    },
    #[allow(unused)]
    Use {
        name: String,
        index: usize,
    },
}

#[derive(Default)]
struct FunctionAnnotations {
    symbols: BTreeMap<Address, Vec<FunctionAnnotation>>,
}

struct DynamicDecompilerContextT {
    annotations: RwLock<BTreeMap<FunctionId, FunctionAnnotations>>,
    mapping: IntervalMap<Address, FunctionId>,
}

#[derive(Clone)]
pub struct DynamicDecompilerContext(Arc<DynamicDecompilerContextT>);

impl DynamicDecompilerContext {
    pub fn new(project: &Project) -> Self {
        let mut mapping = IntervalMap::new();
        for blk in project.code_blocks().values() {
            let range = blk.address()..blk.next_address();
            mapping.insert(range, blk.function());
        }

        Self(Arc::new(DynamicDecompilerContextT {
            annotations: RwLock::new(BTreeMap::new()),
            mapping,
        }))
    }

    fn get<'a>(
        &'a self,
        address: impl Into<Address>,
    ) -> Option<MappedRwLockReadGuard<'a, FunctionAnnotations>> {
        let start = address.into();
        let end = start + 1usize;

        if end < start {
            return None;
        }

        let fid = self.0.mapping.values(start..end).next()?;
        let lock = self.0.annotations.read();

        RwLockReadGuard::try_map(lock, |annotations| annotations.get(fid)).ok()
    }

    fn get_symbol<'a>(
        &'a self,
        address: impl Into<Address>,
    ) -> Option<MappedRwLockReadGuard<'a, Vec<FunctionAnnotation>>> {
        let address = address.into();
        self.get(address).and_then(|lock| {
            MappedRwLockReadGuard::try_map(lock, |annotations| annotations.symbols.get(&address))
                .ok()
        })
    }

    fn get_assignment_symbol<'a>(
        &'a self,
        address: impl Into<Address>,
    ) -> Option<MappedRwLockReadGuard<'a, String>> {
        let address = address.into();
        self.get_symbol(address).and_then(|lock| {
            MappedRwLockReadGuard::try_map(lock, |symbols| {
                symbols.iter().find_map(|symbol| {
                    let FunctionAnnotation::Def { name } = symbol else {
                        return None;
                    };
                    Some(name)
                })
            })
            .ok()
        })
    }

    fn get_mut<'a>(
        &'a self,
        address: impl Into<Address>,
    ) -> Option<MappedRwLockWriteGuard<'a, FunctionAnnotations>> {
        let start = address.into();
        let end = start + 1usize;

        if end < start {
            return None;
        }

        let fid = *self.0.mapping.values(start..end).next()?;
        let lock = self.0.annotations.write();

        Some(RwLockWriteGuard::map(lock, |annotations| {
            annotations.entry(fid).or_default()
        }))
    }

    fn get_symbol_mut<'a>(
        &'a self,
        address: impl Into<Address>,
    ) -> Option<MappedRwLockWriteGuard<'a, Vec<FunctionAnnotation>>> {
        let address = address.into();
        self.get_mut(address).map(|lock| {
            MappedRwLockWriteGuard::map(lock, |annotations| {
                annotations.symbols.entry(address).or_default()
            })
        })
    }

    pub fn set_assignment_symbol(&self, address: impl Into<Address>, symbol: impl Into<String>) {
        let Some(mut symbols) = self.get_symbol_mut(address) else {
            return;
        };

        if let Some(FunctionAnnotation::Def { name }) = symbols
            .iter_mut()
            .filter(|v| matches!(v, FunctionAnnotation::Def { .. }))
            .next()
        {
            *name = symbol.into();
        } else {
            symbols.push(FunctionAnnotation::Def {
                name: symbol.into(),
            });
        }
    }
}

pub struct DynamicResolver<T>
where
    T: DecompilerResolver,
{
    context: DynamicDecompilerContext,
    resolver: T,
}

impl<T> DynamicResolver<T>
where
    T: DecompilerResolver,
{
    pub fn new(project: &Project, resolver: T) -> Self {
        Self {
            context: DynamicDecompilerContext::new(project),
            resolver,
        }
    }

    pub fn context(&self) -> DynamicDecompilerContext {
        self.context.clone()
    }
}

impl<T> DecompilerSymbolResolver for DynamicResolver<T>
where
    T: DecompilerResolver,
{
    fn resolve_global_variable_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        global: Address,
        type_: DataTypeRef,
        size: usize,
    ) -> Option<String> {
        self.resolver
            .resolve_global_variable_symbol(project, name, uses, global, type_, size)
    }

    fn resolve_stack_variable_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        offset: i64,
        type_: DataTypeRef,
        size: usize,
    ) -> Option<String> {
        self.resolver
            .resolve_stack_variable_symbol(project, name, uses, offset, type_, size)
    }

    fn resolve_register_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        register: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        struct VisitDefs {
            target: Var,
            found: bool,
        }

        impl<'ir> VisitVars<'ir> for VisitDefs {
            fn visit_def(&mut self, var: &'ir Var) {
                self.found |= *var == self.target;
            }
        }

        let mut visitor = VisitDefs {
            target: register,
            found: false,
        };

        for usage in uses {
            // check if there is a symbol available at this point
            let Some(symbol) = self.context.get_assignment_symbol(*usage) else {
                continue;
            };

            // now check if this address defs this variable
            let Some(insn) = project.instructions().get_point(usage) else {
                continue;
            };

            insn.insn().visit_vars(&mut visitor);

            // matching def. found at this point; perform the mapping
            if visitor.found {
                return Some(symbol.to_owned());
            }
        }

        self.resolver
            .resolve_register_symbol(project, name, uses, register, type_)
    }

    fn resolve_temporary_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        temporary: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        self.resolver
            .resolve_temporary_symbol(project, name, uses, temporary, type_)
    }
}

impl<T> DecompilerTypeResolver for DynamicResolver<T>
where
    T: DecompilerResolver,
{
    fn resolve_global_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        global: Address,
        size: usize,
    ) -> Option<Term<Type>> {
        self.resolver
            .resolve_global_variable_type(project, use_at, global, size)
    }

    fn resolve_stack_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        offset: i64,
        size: usize,
    ) -> Option<Term<Type>> {
        self.resolver
            .resolve_stack_variable_type(project, use_at, offset, size)
    }

    fn resolve_register_type(
        &self,
        project: &Project,
        use_at: Address,
        register: Var,
    ) -> Option<Term<Type>> {
        self.resolver
            .resolve_register_type(project, use_at, register)
    }

    fn resolve_temporary_type(
        &self,
        project: &Project,
        use_at: Address,
        temporary: Var,
    ) -> Option<Term<Type>> {
        self.resolver
            .resolve_temporary_type(project, use_at, temporary)
    }
}
