use std::ops::{Deref, DerefMut};

use crate::decompiler::types::{DataTypeRef, DecompilerTypeResolver};
use crate::prelude::*;

pub trait DecompilerSymbolResolver: Send + Sync + 'static {
    #[allow(unused)]
    fn resolve_global_variable_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        global: Address,
        type_: DataTypeRef,
        size: usize,
    ) -> Option<String> {
        None
    }

    #[allow(unused)]
    fn resolve_stack_variable_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        offset: i64,
        type_: DataTypeRef,
        size: usize,
    ) -> Option<String> {
        None
    }

    #[allow(unused)]
    fn resolve_register_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        register: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        None
    }

    #[allow(unused)]
    fn resolve_temporary_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        temporary: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        None
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefaultDecompilerSymbolResolver;

impl DecompilerSymbolResolver for DefaultDecompilerSymbolResolver {}
impl DecompilerTypeResolver for DefaultDecompilerSymbolResolver {}

#[repr(transparent)]
pub struct DecompilerResolverAdaptor<T>(T)
where
    T: DecompilerSymbolResolver;

impl<T> From<T> for DecompilerResolverAdaptor<T>
where
    T: DecompilerSymbolResolver,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for DecompilerResolverAdaptor<T>
where
    T: DecompilerSymbolResolver,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for DecompilerResolverAdaptor<T>
where
    T: DecompilerSymbolResolver,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> DecompilerResolverAdaptor<T>
where
    T: DecompilerSymbolResolver,
{
    pub fn new(resolver: T) -> Self {
        Self::from(resolver)
    }
}

impl<T> DecompilerTypeResolver for DecompilerResolverAdaptor<T> where T: DecompilerSymbolResolver {}

impl<T> DecompilerSymbolResolver for DecompilerResolverAdaptor<T>
where
    T: DecompilerSymbolResolver,
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
        self.0
            .resolve_global_variable_symbol(project, name, uses, global, type_, size)
    }

    #[allow(unused)]
    fn resolve_stack_variable_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        offset: i64,
        type_: DataTypeRef,
        size: usize,
    ) -> Option<String> {
        self.0
            .resolve_stack_variable_symbol(project, name, uses, offset, type_, size)
    }

    #[allow(unused)]
    fn resolve_register_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        register: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        self.0
            .resolve_register_symbol(project, name, uses, register, type_)
    }

    #[allow(unused)]
    fn resolve_temporary_symbol(
        &self,
        project: &Project,
        name: &str,
        uses: &[Address],
        temporary: Var,
        type_: DataTypeRef,
    ) -> Option<String> {
        self.0
            .resolve_temporary_symbol(project, name, uses, temporary, type_)
    }
}
