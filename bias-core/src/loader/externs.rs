use thiserror::Error;

use super::{LoadedBinary, RelocatableBinary, RelocationError};
use crate::inject::externs::ExternalFunction;
use crate::ir::Address;
use crate::kb::id::Identifiable;
use crate::kb::Ustr;
use crate::lifter::Lifter;
use crate::project::analysis::AnalysisError;
use crate::project::Project;
use crate::symbols::{Symbolise, SymboliseError};

#[derive(Debug, Error)]
pub enum ExternalsProviderError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("target project and externals provider have different architectures")]
    IncompatibleArch,
    #[error("target project and externals provider have different comventions")]
    IncompatibleConvention,
    #[error("target project memory mapping has insufficient space to map externals")]
    InsufficientSpace,
    #[error(transparent)]
    Rebase(#[from] RelocationError),
    #[error(transparent)]
    Symbols(#[from] SymboliseError),
}

pub trait ExternalLoader {}

pub trait HasExternals {
    fn externs(&self) -> &impl ExternalSymbols;
    fn has_externs(&self) -> bool {
        self.externs().number_of_symbols() > 0
    }
}

pub trait ExternalSymbols {
    fn base(&self) -> Address;
    fn size(&self) -> usize;

    fn address(&self, sym: impl AsRef<str>) -> Option<Address>;
    fn symbol(&self, addr: impl Into<Address>) -> Option<Ustr>;

    fn contains_address(&self, addr: impl Into<Address>) -> bool;
    fn contains_symbol(&self, sym: impl AsRef<str>) -> bool;

    fn symbols<'a>(&'a self) -> impl Iterator<Item = (Address, Ustr)> + 'a;
    fn number_of_symbols(&self) -> usize;
}

pub trait ExternalsProvider: LoadedBinary + RelocatableBinary + Symbolise + Sized {
    fn apply_externs<E>(
        mut self,
        lifter: Lifter,
        target: &mut Project,
        target_externs: &E,
    ) -> Result<(), ExternalsProviderError>
    where
        E: HasExternals + ?Sized,
    {
        tracing::trace!(
            "loading stubs from provider ({}:{})",
            lifter.translator().architecture(),
            lifter.convention().name()
        );

        tracing::trace!("checking lifter architecture compatibility");
        if lifter.arch().id() != target.lifter().arch().id() {
            return Err(ExternalsProviderError::IncompatibleArch);
        }

        tracing::trace!("checking lifter convention compatibility");
        if lifter.convention() != target.lifter().convention() {
            return Err(ExternalsProviderError::IncompatibleConvention);
        }

        tracing::trace!("checking target binary has (potentially) unresolved externals");
        if !target_externs.has_externs() {
            return Ok(());
        }

        let source_size = self.mapping_size();
        let source_alignment = self.mapping_alignment();

        tracing::trace!("mapping size for provider is {source_size} bytes; alignment is {source_alignment} bytes");

        let Some(source_base) = target.memory().find_free_region(
            source_size,
            source_alignment,
            target
                .lifter()
                .translator()
                .manager()
                .default_space_ref()
                .highest_offset(),
        ) else {
            return Err(ExternalsProviderError::InsufficientSpace);
        };

        tracing::trace!("free region in target found at {source_base}");

        tracing::trace!("rebasing provider to use {source_base} as its base address");
        self.rebase(source_base)?;

        let mut source = Project::new(&self, lifter);

        tracing::trace!("applying symbol information from provider");
        source.load_symbols(&self)?;

        // merge memory mappings
        tracing::trace!("merging memory maps");
        source
            .memory
            .into_iter()
            .for_each(|(_, r)| target.memory.add_region(r));

        // merge instruction tables
        tracing::trace!("merging instruction tables");
        target.itable.reserve(source.itable.len());
        source.itable.into_values().for_each(|mut insn| {
            target.itable.insert(insn.address(), |id| {
                insn.update_id(id);
                insn
            });
        });

        let wanted_externs = target_externs.externs();

        tracing::trace!("adding unresolved externals from provider as injections");
        for f in source.ftable.values() {
            let Some(name) = f.name() else {
                continue;
            };

            let address = f.address();

            tracing::trace!("checking if provider function {name} at {address} corresponds to an unresolved external");
            if !wanted_externs.contains_symbol(name) {
                continue;
            }

            let Some(fid) = target
                .symbols()
                .lookup(name)
                .and_then(|sym| sym.referent().get_function())
            else {
                continue;
            };

            // check that we are (not) remapping an existing external (sanity)
            if !target.functions()[fid].is_extern() {
                tracing::trace!("remapping/injection already exists for {name}; skipping");
                continue;
            }

            tracing::trace!(
                "injecting function stub {name} at {address} from provider at {} in target",
                target.functions()[fid].address()
            );

            target
                .injections_mut()
                .add_function_stub(fid, ExternalFunction::new(address, name));
        }

        Ok(())
    }
}

impl<T> ExternalsProvider for T where T: LoadedBinary + RelocatableBinary + Symbolise {}
