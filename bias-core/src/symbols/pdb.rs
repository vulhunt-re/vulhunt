use std::cell::RefCell;

use fugue::ir::Address;
use pdb::{FallibleIterator, Source, PDB};
use thiserror::Error;
use ustr::Ustr;
use uuid::Uuid;

use super::{Symbolise, SymboliseError};
use crate::kb::debug::file_info::SourceFileInfo;
use crate::kb::id::Identifiable;
use crate::Project;

#[derive(Debug, Error)]
pub enum SymbolisePDBError {
    #[error("PDB file is invalid: {0}")]
    PDB(#[from] pdb::Error),
    #[error("the PDB signature does not match the signature from the binary")]
    PDBSignatureMismatch,
}

impl From<SymbolisePDBError> for SymboliseError {
    fn from(e: SymbolisePDBError) -> Self {
        SymboliseError::other(e)
    }
}

pub struct PDBSymboliser<'a, S>
where
    S: Source<'a> + 'a,
{
    pdb: RefCell<PDB<'a, S>>,
    base: Address,
    sig: Option<Uuid>,
}

impl<'a, S> PDBSymboliser<'a, S>
where
    S: Source<'a> + 'a,
{
    pub fn new(pdb: PDB<'a, S>, base: impl Into<Address>) -> Self {
        Self::new_with(pdb, base, None)
    }

    pub fn new_with(
        pdb: PDB<'a, S>,
        base: impl Into<Address>,
        sig: impl Into<Option<Uuid>>,
    ) -> Self {
        Self {
            pdb: RefCell::new(pdb),
            base: base.into(),
            sig: sig.into(),
        }
    }

    pub fn open(source: S, base: impl Into<Address>) -> Result<Self, SymbolisePDBError> {
        Ok(Self::new(PDB::open(source)?, base))
    }

    pub fn open_with(
        source: S,
        base: impl Into<Address>,
        sig: impl Into<Option<Uuid>>,
    ) -> Result<Self, SymbolisePDBError> {
        Ok(Self::new_with(PDB::open(source)?, base, sig))
    }

    fn apply(&self, project: &mut Project) -> Result<(), SymbolisePDBError> {
        let mut pdb = self.pdb.borrow_mut();
        let meta = pdb.pdb_information()?;

        if matches!(self.sig, Some(sig) if meta.guid != sig) {
            return Err(SymbolisePDBError::PDBSignatureMismatch);
        }

        tracing::trace!("signature from loaded binary matches PDB signature");

        let address_map = pdb.address_map()?;

        let dbi = pdb.debug_information()?;
        let string_table = pdb.string_table()?;
        let mut modules = dbi.modules()?;

        // Iterate through the Modules defined in the PDB.
        while let Some(module) = modules.next()? {
            tracing::trace!("module: {}", module.module_name());
            let info = match pdb.module_info(&module)? {
                Some(info) => info,
                None => continue,
            };

            let program = info.line_program()?;
            let mut symbols = info.symbols()?;

            while let Some(symbol) = symbols.next()? {
                let (data_offset, data_name) = match symbol.parse() {
                    Ok(pdb::SymbolData::Procedure(data)) => (data.offset, data.name),
                    Ok(pdb::SymbolData::Label(data)) => (data.offset, data.name),
                    _ => continue,
                };

                if let Some(rva) = data_offset.to_rva(&address_map) {
                    let addr = self.base + (rva.0 as u64);

                    if let Some(fcn) = project.functions_mut().get_point_mut(&addr) {
                        let fcn_name = Ustr::from(&data_name.to_string());
                        let fcn_id = fcn.id();

                        tracing::trace!("applying symbol {fcn_name} to function at {addr}");
                        fcn.update_name(fcn_name);

                        // Sorting Lines to find the first line where the symbol was defined.
                        let result = program
                            .lines_for_symbol(data_offset)
                            .iterator()
                            .filter(|r| r.is_ok())
                            .min_by_key(|x| x.as_ref().unwrap().line_start);

                        if let Some(Ok(line_info)) = result {
                            let file_info = program.get_file_info(line_info.file_index)?;
                            let file_name =
                                file_info.name.to_string_lossy(&string_table)?.into_owned();

                            tracing::trace!(
                                "found function {:?} at address {addr} defined {file_name}:{}",
                                fcn_name,
                                line_info.line_start
                            );

                            fcn.update_source_info(SourceFileInfo::new(
                                file_name,
                                line_info.line_start,
                            ));
                        }

                        project.symbols_mut().insert(fcn_name, fcn_id);
                    }
                }
            }
        }

        Ok(())
    }
}

impl<'a, S> Symbolise for PDBSymboliser<'a, S>
where
    S: Source<'a> + 'a,
{
    fn apply_symbols(&self, target: &mut Project) -> Result<(), SymboliseError> {
        self.apply(target).map_err(SymboliseError::from)
    }
}
