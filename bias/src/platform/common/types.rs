use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use bias_core::cio::{TypeError, TypeInfo, TypeInfoDB};
use bias_core::prelude::*;

use dashmap::mapref::one::Ref;
use dashmap::DashMap;

use thiserror::Error;

use crate::platform::common::data::{PlatformDataProvider, PlatformDataProviderError};

const PLATFORM_TYPES_PATH: &'static str = "/types";

#[derive(Debug, Clone)]
pub struct TypeManager {
    databases: Arc<DashMap<String, TypeInfoDB>>,
    platform_data: PlatformDataProvider,
}

#[derive(Debug, Error)]
pub enum TypeManagerError {
    #[error("type database `{0}` could not be loaded: {1}")]
    DatabaseLoad(String, TypeError),
    #[error("platform directory does not exist")]
    InvalidPlatformDirectory,
    #[error("type database `{0}` does not exist")]
    InvalidTypeDB(String),
    #[error(transparent)]
    PlatformData(#[from] PlatformDataProviderError),
}

#[derive(Debug, Clone)]
pub struct FunctionTypeMapping {
    id_to_type: BTreeMap<FunctionId, Term<Type>>,
    database: TypeDB,
    bits: u32,
}

impl FunctionTypeMapping {
    pub fn new(types: &TypeInfoDB, project: &Project) -> Self {
        let mut database = TypeDB::new();
        database.import_types(types);

        let mut slf = Self {
            id_to_type: Default::default(),
            database,
            bits: project.lifter().address_bits(),
        };

        slf.update(project);
        slf
    }

    // NOTE: this gives us a default mapping that we can add to later
    pub fn from_project(project: &Project) -> Self {
        let mut slf = Self {
            id_to_type: Default::default(),
            database: project.type_db().clone(),
            bits: project.lifter().address_bits(),
        };

        slf.update(project);
        slf
    }

    pub fn import_types(&mut self, types: &TypeInfoDB) {
        self.database.import_new_types(types);
    }

    // We may merge multiple type databases and then want to recompute
    // the mapping of all functions.
    pub fn update(&mut self, project: &Project) {
        self.id_to_type.clear();

        for (fid, faddr, fname) in project
            .functions()
            .values()
            .filter_map(|f| f.name().map(|name| (f.id(), f.address(), name)))
        {
            let fname = fname.as_str();
            let fname_no_prefix = fname.strip_prefix("imp.").unwrap_or(fname);

            let Some(t) = self.database.get_prototype_for(fname_no_prefix, self.bits) else {
                continue;
            };
            if !t.is_function() {
                continue;
            }

            tracing::trace!("applying type {t} to {fname} at {faddr}");
            self.id_to_type.insert(fid, t.clone());
            self.database.set_code_type_at(faddr, t);
        }
    }

    pub fn update_with(&mut self, types: &TypeInfoDB, project: &Project) {
        self.database.import_types(types);
        self.update(project)
    }

    pub fn mapping(&self) -> &BTreeMap<FunctionId, Term<Type>> {
        &self.id_to_type
    }

    pub fn mapping_mut(&mut self) -> &mut BTreeMap<FunctionId, Term<Type>> {
        &mut self.id_to_type
    }

    pub fn type_by_id(&self, id: FunctionId) -> Option<Term<Type>> {
        self.id_to_type.get(&id).cloned()
    }

    pub fn type_by_address(&self, addr: impl Into<Address>) -> Option<Term<Type>> {
        self.database.get_code_type_at(addr.into())
    }

    pub fn type_by_name(&self, name: impl AsRef<str>) -> Option<Term<Type>> {
        let name = Ustr::from_existing(name.as_ref())?;
        self.database.get_prototype_for(name.as_ref(), self.bits)
    }

    pub fn types(&self) -> &TypeDB {
        &self.database
    }

    pub fn types_mut(&mut self) -> &mut TypeDB {
        &mut self.database
    }

    pub fn address_bits(&self) -> u32 {
        self.bits
    }
}

impl TypeManager {
    pub fn new(platform_data: PlatformDataProvider) -> Result<Self, TypeManagerError> {
        if !platform_data.exists(PLATFORM_TYPES_PATH) {
            return Err(TypeManagerError::InvalidPlatformDirectory);
        }

        Ok(Self {
            platform_data,
            databases: Arc::new(DashMap::new()),
        })
    }

    pub fn get_ref(
        &self,
        prefix: impl AsRef<str>,
    ) -> Result<Ref<'_, String, TypeInfoDB>, TypeManagerError> {
        let prefix = prefix.as_ref();
        let database = Path::new(PLATFORM_TYPES_PATH)
            .join(prefix)
            .with_extension("h");

        let database = self.platform_data.resolve(database)?;

        self.databases
            .entry(prefix.to_owned())
            .or_try_insert_with(|| {
                TypeInfoDB::from_file(&database)
                    .map_err(|e| TypeManagerError::DatabaseLoad(prefix.to_owned(), e))
            })
            .map(|r| r.downgrade())
    }

    pub fn get(&self, prefix: impl AsRef<str>) -> Result<TypeInfoDB, TypeManagerError> {
        // TypeInfoDB is a cheap clone--it is just an Arc
        Ok(self.get_ref(prefix)?.value().to_owned())
    }

    pub fn get_and_merge(
        &self,
        prefix: impl AsRef<str>,
        project: &mut Project,
    ) -> Result<(), TypeManagerError> {
        let typedb = self.get_ref(prefix)?;

        project.type_db_mut().import_types(typedb.value());

        Ok(())
    }

    pub fn type_for(&self, name: impl AsRef<str>, bits: u32) -> Option<Term<Type>> {
        self.with_named_type(name, |_db, t| Some(t.to(bits)))
    }

    pub fn prototype_for(&self, name: impl AsRef<str>, bits: u32) -> Option<Term<Type>> {
        self.with_named_prototype(name, |_db, t| Some(t.to(bits)))
    }

    pub fn type_and_database_for(
        &self,
        name: impl AsRef<str>,
        bits: u32,
    ) -> Option<(Term<Type>, TypeInfoDB)> {
        self.with_named_type(name, |db, t| Some((t.to(bits), db.to_owned())))
    }

    pub fn prototype_and_database_for(
        &self,
        name: impl AsRef<str>,
        bits: u32,
    ) -> Option<(Term<Type>, TypeInfoDB)> {
        self.with_named_prototype(name, |db, t| Some((t.to(bits), db.to_owned())))
    }

    pub fn with_named_type<F, T>(&self, name: impl AsRef<str>, f: F) -> Option<T>
    where
        F: Fn(&TypeInfoDB, &TypeInfo) -> Option<T>,
    {
        let name = Ustr::from_existing(name.as_ref())?;
        self.databases.iter().find_map(|kdb| {
            let t = kdb.value().types().get(&name)?;
            f(kdb.value(), t)
        })
    }

    pub fn with_named_prototype<F, T>(&self, name: impl AsRef<str>, f: F) -> Option<T>
    where
        F: Fn(&TypeInfoDB, &TypeInfo) -> Option<T>,
    {
        let name = Ustr::from_existing(name.as_ref())?;
        self.databases.iter().find_map(|kdb| {
            let t = kdb.value().prototypes().get(&name)?;
            f(kdb.value(), t)
        })
    }

    pub fn function_type_mapping(
        &self,
        prefix: impl AsRef<str>,
        project: &Project,
    ) -> Result<FunctionTypeMapping, TypeManagerError> {
        let types = self.get_ref(prefix)?;
        let mapping = FunctionTypeMapping::new(types.value(), project);

        Ok(mapping)
    }

    pub fn ensure_available(&self, prefix: impl AsRef<str>) -> Result<(), TypeManagerError> {
        drop(self.get_ref(prefix)?);
        Ok(())
    }
}
