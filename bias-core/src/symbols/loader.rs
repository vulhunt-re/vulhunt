use crate::cfg::context::ICFGExtendedContext;
use crate::ir::Address;
use crate::loader::{
    LoadedBinary, LoaderBlock, LoaderBytes, LoaderContainer, LoaderExport, LoaderFunction,
    LoaderImport, LoaderRegion,
};
use crate::Project;

use super::{Symbolise, SymboliseError};

#[repr(transparent)]
pub struct SymbolisingLoadedBinary<T>
where
    T: LoadedBinary + Symbolise,
{
    binary: T,
}

impl<T> SymbolisingLoadedBinary<T>
where
    T: LoadedBinary + Symbolise,
{
    pub fn new(binary: T) -> Self {
        Self { binary }
    }

    pub fn binary(&self) -> &T {
        &self.binary
    }

    pub fn binary_mut(&mut self) -> &mut T {
        &mut self.binary
    }

    pub fn into_inner(self) -> T {
        self.binary
    }
}

impl<T> LoadedBinary for SymbolisingLoadedBinary<T>
where
    T: LoadedBinary + Symbolise,
{
    fn for_each_region<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
        self.binary.for_each_region(f);
    }

    fn for_each_region_with<'a, A, F>(&'a self, rebase: A, f: F)
    where
        A: Into<Option<Address>>,
        F: FnMut(&LoaderRegion<'a>),
    {
        self.binary.for_each_region_with(rebase, f);
    }

    fn for_each_block<F>(&self, f: F)
    where
        F: FnMut(&LoaderBlock),
    {
        self.binary.for_each_block(f);
    }

    fn for_each_function<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderFunction<'a>),
    {
        self.binary.for_each_function(f);
    }

    fn for_each_import<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderImport<'a>),
    {
        self.binary.for_each_import(f);
    }

    fn for_each_export<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderExport<'a>),
    {
        self.binary.for_each_export(f);
    }

    fn for_each_critical_function<'a, F>(&'a self, context: &mut ICFGExtendedContext, f: F)
    where
        F: FnMut(Address),
    {
        self.binary.for_each_critical_function(context, f);
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        self.binary.bytes()
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        self.binary.container()
    }

    fn entry_point(&self) -> Option<Address> {
        self.binary.entry_point()
    }
}

impl<T> Symbolise for SymbolisingLoadedBinary<T, U>
where
    T: LoadedBinary + Symbolise,
{
    fn apply_symbols(&self, target: &mut Project) -> Result<(), SymboliseError> {
        self.symbols.apply_symbols(target)
    }
}
