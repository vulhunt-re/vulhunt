use std::borrow::{Borrow, Cow};
use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::num::ParseIntError;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use ahash::AHashMap;
use fugue::bv::BitVec;
use fugue::ir::Address;
use once_cell::sync::Lazy;
use regex::Regex;
use thiserror::Error;
use ustr::{Ustr, UstrMap};

use crate::ir::types::{EnumVariant, FunctionArgProps, StructField, UnionVariant};
use crate::ir::{Term, Type, TypeKind};

#[cfg(feature = "import-c")]
pub mod clang;
#[cfg(feature = "import-c")]
pub use self::clang::ClangError;

#[derive(Debug, Error)]
pub enum TypeError {
    #[cfg(feature = "import-c")]
    #[error(transparent)]
    Clang(#[from] ClangError),
    #[error("failed to deserialise type database: {0}; regenerate it using bias-tutil")]
    Deserialisation(#[from] rmp_serde::decode::Error),
    #[error(transparent)]
    IO(#[from] io::Error),
    #[error("failed to serialise type database: {0}")]
    Serialisation(#[from] rmp_serde::encode::Error),
    #[error("build configuration does not support header parsing")]
    Unsupported,
}

pub type Error = TypeError;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum TypeInfo {
    Enum(Enum),
    Struct(Struct),
    Prototype(Prototype),
    TypeDef(TypeDef),
    Union(Union),
}

impl From<Enum> for TypeInfo {
    fn from(enumer: Enum) -> Self {
        Self::Enum(enumer)
    }
}

impl From<Struct> for TypeInfo {
    fn from(struc: Struct) -> Self {
        Self::Struct(struc)
    }
}

impl From<Prototype> for TypeInfo {
    fn from(proto: Prototype) -> Self {
        Self::Prototype(proto)
    }
}

impl From<TypeDef> for TypeInfo {
    fn from(typedef: TypeDef) -> Self {
        Self::TypeDef(typedef)
    }
}

impl From<Union> for TypeInfo {
    fn from(union_: Union) -> Self {
        Self::Union(union_)
    }
}

impl TypeInfo {
    pub fn is_prototype(&self) -> bool {
        matches!(self, TypeInfo::Prototype(_))
    }

    pub fn is_enum(&self) -> bool {
        matches!(self, TypeInfo::Enum(_))
    }

    pub fn is_struct(&self) -> bool {
        matches!(self, TypeInfo::Struct(_))
    }

    pub fn is_typedef(&self) -> bool {
        matches!(self, TypeInfo::TypeDef(_))
    }

    pub fn is_union(&self) -> bool {
        matches!(self, TypeInfo::Union(_))
    }
}

impl TypeInfo {
    pub fn enum_variant<S>(&self, name: S, bits: u32) -> Option<(&BitVec, &BitVec, Term<Type>)>
    where
        S: Borrow<str>,
    {
        if bits == 64 {
            self.enum_variant_64(name)
        } else {
            assert!(bits == 32);
            self.enum_variant_32(name)
        }
    }

    pub fn enum_variant_32<S>(&self, name: S) -> Option<(&BitVec, &BitVec, Term<Type>)>
    where
        S: Borrow<str>,
    {
        match self {
            TypeInfo::Enum(ref e) => {
                let name = Ustr::from(name.borrow());
                e.variants_32.iter().find_map(|f| {
                    if f.name == name {
                        Some((
                            &f.signed,
                            &f.unsigned,
                            Type::named_32(format!("{}::{}", e.name, name), e.size_32 as u32 * 8),
                        ))
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    pub fn enum_variant_64<S>(&self, name: S) -> Option<(&BitVec, &BitVec, Term<Type>)>
    where
        S: Borrow<str>,
    {
        match self {
            TypeInfo::Enum(ref e) => {
                let name = Ustr::from(name.borrow());
                e.variants_64.iter().find_map(|f| {
                    if f.name == name {
                        Some((
                            &f.signed,
                            &f.unsigned,
                            Type::named_64(format!("{}::{}", e.name, name), e.size_64 as u32 * 8),
                        ))
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    pub fn field<S>(&self, name: S, bits: u32) -> Option<(usize, Term<Type>)>
    where
        S: Borrow<str>,
    {
        if bits == 64 {
            self.field_64(name)
        } else {
            assert!(bits == 32);
            self.field_32(name)
        }
    }

    pub fn field_32<S>(&self, name: S) -> Option<(usize, Term<Type>)>
    where
        S: Borrow<str>,
    {
        let name = Ustr::from(name.borrow());
        match self {
            TypeInfo::Struct(ref s) => s.fields_32.iter().find_map(|f| {
                if f.name == name {
                    Some((f.offset, f.typ.clone()))
                } else {
                    None
                }
            }),
            _ => None,
        }
    }

    pub fn field_64<S>(&self, name: S) -> Option<(usize, Term<Type>)>
    where
        S: Borrow<str>,
    {
        let name = Ustr::from(name.borrow());
        match self {
            TypeInfo::Struct(ref s) => s.fields_64.iter().find_map(|f| {
                if f.name == name {
                    Some((f.offset, f.typ.clone()))
                } else {
                    None
                }
            }),
            _ => None,
        }
    }

    pub fn to_32(&self) -> Term<Type> {
        match self {
            TypeInfo::Enum(e) => e.to_32(),
            TypeInfo::Struct(ref s) => s.to_32(),
            TypeInfo::Prototype(ref p) => p.to_32(),
            TypeInfo::TypeDef(ref t) => t.to_32(),
            TypeInfo::Union(ref u) => u.to_32(),
        }
    }

    pub fn to_64(&self) -> Term<Type> {
        match self {
            TypeInfo::Enum(e) => e.to_64(),
            TypeInfo::Struct(ref s) => s.to_64(),
            TypeInfo::Prototype(ref p) => p.to_64(),
            TypeInfo::TypeDef(ref t) => t.to_64(),
            TypeInfo::Union(ref u) => u.to_64(),
        }
    }

    pub fn to(&self, bits: u32) -> Term<Type> {
        if bits == 64 {
            self.to_64()
        } else {
            // 32-bit
            assert!(bits == 32);
            self.to_32()
        }
    }

    pub fn to_32_with(&self, tdb: &TypeDB) -> Term<Type> {
        match self {
            TypeInfo::Enum(e) => e.to_32(),
            TypeInfo::Struct(ref s) => s.to_32(),
            TypeInfo::Prototype(ref p) => p.to_32_with(tdb),
            TypeInfo::TypeDef(ref t) => t.to_32(),
            TypeInfo::Union(ref u) => u.to_32(),
        }
    }

    pub fn to_64_with(&self, tdb: &TypeDB) -> Term<Type> {
        match self {
            TypeInfo::Enum(e) => e.to_64(),
            TypeInfo::Struct(ref s) => s.to_64(),
            TypeInfo::Prototype(ref p) => p.to_64_with(tdb),
            TypeInfo::TypeDef(ref t) => t.to_64(),
            TypeInfo::Union(ref u) => u.to_64(),
        }
    }

    pub fn to_with(&self, tdb: &TypeDB, bits: u32) -> Term<Type> {
        if bits == 64 {
            self.to_64_with(tdb)
        } else {
            // 32-bit
            assert!(bits == 32);
            self.to_32_with(tdb)
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum TypeRef {
    Type(Term<Type>),
    TRef(Address, usize),
}

impl TypeRef {
    pub fn has_parent(&self) -> bool {
        matches!(self, Self::TRef(_, _))
    }
}

#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct TypeInfoDB(Arc<TypeInfoDBInner>);

#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct TypeInfoDBInner {
    pub types: UstrMap<TypeInfo>,
    pub prototypes: UstrMap<TypeInfo>,
}

#[derive(Debug, Clone)]
pub struct TypeDBConfig<'a> {
    header: bool,
    use_mxx: bool,
    m32_arguments: Cow<'a, [&'a str]>,
    m64_arguments: Cow<'a, [&'a str]>,
    /// Enables permissive parsing of struct fields: when encountering an error,
    /// a field will be skipped instead of discarding the whole struct
    relaxed_struct_parsing: bool,
}

impl<'a> Default for TypeDBConfig<'a> {
    fn default() -> Self {
        #[cfg(feature = "import-c")]
        let arguments = Cow::Borrowed(clang::CLANG_DEFAULT_ARGS);
        #[cfg(not(feature = "import-c"))]
        let arguments = Cow::<'a, [&'a str]>::Borrowed(&[]);

        Self {
            header: false,
            use_mxx: true,
            m32_arguments: arguments.clone(),
            m64_arguments: arguments,
            relaxed_struct_parsing: false,
        }
    }
}

impl<'a> TypeDBConfig<'a> {
    pub fn new(header: bool) -> Self {
        Self {
            header,
            use_mxx: false,
            m32_arguments: Cow::<'a, [&'a str]>::Borrowed(&[]),
            m64_arguments: Cow::<'a, [&'a str]>::Borrowed(&[]),
            relaxed_struct_parsing: false,
        }
    }

    pub fn with_mxx(mut self, mxx: bool) -> Self {
        self.set_mxx(mxx);
        self
    }

    pub fn set_mxx(&mut self, mxx: bool) {
        self.use_mxx = mxx;
    }

    pub fn with_header(mut self, header: bool) -> Self {
        self.set_header(header);
        self
    }

    pub fn set_header(&mut self, header: bool) {
        self.header = header;
    }

    pub fn with_arg(mut self, arg: &'a str) -> Self {
        self.push_arg(arg);
        self
    }

    pub fn push_arg(&mut self, arg: &'a str) {
        self.push_arg32(arg);
        self.push_arg64(arg);
    }

    pub fn with_arg32(mut self, arg: &'a str) -> Self {
        self.push_arg32(arg);
        self
    }

    pub fn push_arg32(&mut self, arg: &'a str) {
        self.m32_arguments.to_mut().push(arg.as_ref());
    }

    pub fn with_arg64(mut self, arg: &'a str) -> Self {
        self.push_arg64(arg);
        self
    }

    pub fn push_arg64(&mut self, arg: &'a str) {
        self.m64_arguments.to_mut().push(arg.as_ref());
    }

    pub fn with_args(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.extend_args(args);
        self
    }

    pub fn extend_args(&mut self, args: impl IntoIterator<Item = &'a str>) {
        for arg in args.into_iter() {
            self.push_arg(arg);
        }
    }

    pub fn with_args32(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.extend_args32(args);
        self
    }

    pub fn extend_args32(&mut self, args: impl IntoIterator<Item = &'a str>) {
        self.m32_arguments.to_mut().extend(args);
    }

    pub fn with_args64(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.extend_args64(args);
        self
    }

    pub fn extend_args64(&mut self, args: impl IntoIterator<Item = &'a str>) {
        self.m64_arguments.to_mut().extend(args);
    }

    pub fn clear_args(&mut self) {
        self.clear_args32();
        self.clear_args64();
    }

    pub fn clear_args32(&mut self) {
        self.m32_arguments.to_mut().clear();
    }

    pub fn clear_args64(&mut self) {
        self.m64_arguments.to_mut().clear();
    }

    pub fn header(&self) -> bool {
        self.header
    }

    pub fn args32(&self) -> &[&str] {
        self.m32_arguments.as_ref()
    }

    pub fn args64(&self) -> &[&str] {
        self.m64_arguments.as_ref()
    }

    pub fn with_relaxed_struct_parsing(mut self, relaxed: bool) -> Self {
        self.set_relaxed_struct_parsing(relaxed);
        self
    }

    pub fn set_relaxed_struct_parsing(&mut self, relaxed: bool) {
        self.relaxed_struct_parsing = relaxed;
    }
}

impl TypeInfoDB {
    #[cfg(feature = "import-c")]
    pub(crate) fn new(types: UstrMap<TypeInfo>, prototypes: UstrMap<TypeInfo>) -> Self {
        Self(Arc::new(TypeInfoDBInner { types, prototypes }))
    }

    pub fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::from_file_with(path, false)
    }

    pub fn from_file_with<P>(path: P, header: bool) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::from_file_with_config(
            path,
            &TypeDBConfig {
                header,
                ..Default::default()
            },
        )
    }

    pub fn from_file_with_config<P>(path: P, config: &TypeDBConfig) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        if config.header {
            // force header
            #[cfg(feature = "import-c")]
            {
                let cio = clang::CIOImporter::new()?;
                return Ok(cio.import_with(
                    path,
                    config.use_mxx,
                    &config.m32_arguments,
                    &config.m64_arguments,
                    config.relaxed_struct_parsing,
                )?);
            }
            #[cfg(not(feature = "import-c"))]
            return Err(Error::Unsupported);
        }

        let cached = path.with_extension("bin");

        let e = if cached.exists() {
            let import = || -> Result<TypeInfoDB, Error> {
                let file = File::open(&cached)?;
                let reader = BufReader::new(file);

                Ok(rmp_serde::decode::from_read(reader)?)
            };

            match import() {
                Ok(db) => return Ok(db),
                Err(e) => Some(e),
            }
        } else {
            None
        };

        if path != cached {
            #[cfg(feature = "import-c")]
            {
                let cio = clang::CIOImporter::new()?;
                return Ok(cio.import_with(
                    path,
                    config.use_mxx,
                    &config.m32_arguments,
                    &config.m64_arguments,
                    config.relaxed_struct_parsing,
                )?);
            }

            #[cfg(not(feature = "import-c"))]
            if path.exists() {
                return Err(Error::Unsupported);
            }
        }

        if let Some(e) = e {
            Err(e)
        } else {
            Err(Error::IO(io::Error::new(
                io::ErrorKind::NotFound,
                "header (or cached variant) not found",
            )))
        }
    }

    pub fn merge_from_file<P>(&mut self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let other = Self::from_file(path)?;

        let (types, prototypes) = other.into_parts();
        let inner = Arc::make_mut(&mut self.0);

        inner.types.extend(types.into_iter());
        inner.prototypes.extend(prototypes.into_iter());

        Ok(())
    }

    pub fn merge(&mut self, other: &Self) {
        let inner = Arc::make_mut(&mut self.0);

        inner
            .types
            .extend(other.0.types.iter().map(|(k, v)| (k.clone(), v.clone())));
        inner.prototypes.extend(
            other
                .0
                .prototypes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }

    pub fn merge_new(&mut self, other: &Self) {
        let inner = Arc::make_mut(&mut self.0);

        for (nm, ty) in other.0.types.iter() {
            inner.types.entry(*nm).or_insert_with(|| ty.clone());
        }

        for (nm, proto) in other.0.prototypes.iter() {
            inner.prototypes.entry(*nm).or_insert_with(|| proto.clone());
        }
    }

    pub fn merge_into(&mut self, mut other: Self) {
        let inner = Arc::make_mut(&mut self.0);
        let other = Arc::make_mut(&mut other.0);

        inner.types.extend(other.types.drain());
        inner.prototypes.extend(other.prototypes.drain());
    }

    pub fn cache<P: AsRef<Path>>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        rmp_serde::encode::write(&mut writer, self)?;

        Ok(())
    }

    pub fn types(&self) -> &UstrMap<TypeInfo> {
        &self.0.types
    }

    pub fn prototypes(&self) -> &UstrMap<TypeInfo> {
        &self.0.prototypes
    }

    pub fn len(&self) -> usize {
        self.0.types.len() + self.0.prototypes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.types.is_empty() && self.0.prototypes.is_empty()
    }

    fn into_parts(self) -> (UstrMap<TypeInfo>, UstrMap<TypeInfo>) {
        let inner = Arc::try_unwrap(self.0).unwrap();
        (inner.types, inner.prototypes)
    }
}

impl Deref for TypeInfoDB {
    type Target = TypeInfoDBInner;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for TypeInfoDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TypeDB {
    inner: TypeInfoDB,
    code: AHashMap<Address, Term<Type>>,
    data: AHashMap<Address, TypeRef>,
}

impl Default for TypeDB {
    fn default() -> Self {
        Self {
            inner: TypeInfoDB::default(),
            code: AHashMap::default(),
            data: AHashMap::default(),
        }
    }
}

pub type TypeDBKeys<'a> = std::collections::hash_map::Keys<'a, Ustr, TypeInfo>;
pub type TypeDBIter<'a> = std::collections::hash_map::Iter<'a, Ustr, TypeInfo>;
pub type TypeDBIterMut<'a> = std::collections::hash_map::IterMut<'a, Ustr, TypeInfo>;
pub type TypeDBValues<'a> = std::collections::hash_map::Values<'a, Ustr, TypeInfo>;
pub type TypeDBValuesMut<'a> = std::collections::hash_map::ValuesMut<'a, Ustr, TypeInfo>;

impl TypeDB {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: TypeInfoDB::from_file(path)?,
            ..Default::default()
        })
    }

    pub fn from_file_with<P>(path: P, header: bool) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: TypeInfoDB::from_file_with(path, header)?,
            ..Default::default()
        })
    }

    pub fn from_file_with_config<P>(path: P, config: &TypeDBConfig) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: TypeInfoDB::from_file_with_config(path, config)?,
            ..Default::default()
        })
    }

    pub fn load_file<P>(&mut self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        if self.inner.is_empty() {
            self.inner = TypeInfoDB::from_file(path)?;
        } else {
            self.inner.merge_from_file(path)?;
        }
        Ok(())
    }

    pub fn import_types(&mut self, tidb: &TypeInfoDB) {
        if self.inner.is_empty() {
            self.inner = tidb.clone();
        } else {
            self.inner.merge(tidb);
        }
    }

    pub fn import_new_types(&mut self, tidb: &TypeInfoDB) {
        if self.inner.is_empty() {
            self.inner = tidb.clone();
        } else {
            self.inner.merge_new(tidb);
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.inner.merge_into(other.inner);
    }

    pub fn insert_type<S, T>(&mut self, name: S, type_: T) -> Option<TypeInfo>
    where
        S: Into<Ustr>,
        T: Into<TypeInfo>,
    {
        let type_ = type_.into();

        // soft assert that we are not inserting a prototype as a type
        debug_assert!(!type_.is_prototype(), "cannot insert prototype as type");

        self.inner.types.insert(name.into(), type_)
    }

    pub fn type_names(&self) -> TypeDBKeys<'_> {
        self.inner.types.keys()
    }

    pub fn type_iter(&self) -> TypeDBIter<'_> {
        self.inner.types.iter()
    }

    pub fn type_iter_mut(&mut self) -> TypeDBIterMut<'_> {
        self.inner.types.iter_mut()
    }

    pub fn types(&self) -> TypeDBValues<'_> {
        self.inner.types.values()
    }

    pub fn types_mut(&mut self) -> TypeDBValuesMut<'_> {
        self.inner.types.values_mut()
    }

    pub fn insert_prototype<S>(&mut self, name: S, type_: Prototype) -> Option<TypeInfo>
    where
        S: Into<Ustr>,
    {
        self.inner.prototypes.insert(name.into(), type_.into())
    }

    pub fn prototype_names(&self) -> TypeDBKeys<'_> {
        self.inner.prototypes.keys()
    }

    pub fn prototype_iter(&self) -> TypeDBIter<'_> {
        self.inner.prototypes.iter()
    }

    pub fn prototype_iter_mut(&mut self) -> TypeDBIterMut<'_> {
        self.inner.prototypes.iter_mut()
    }

    pub fn prototypes(&self) -> TypeDBValues<'_> {
        self.inner.prototypes.values()
    }

    pub fn get_type<S>(&self, name: S) -> Option<&TypeInfo>
    where
        S: Borrow<str>,
    {
        let name = Ustr::from_existing(name.borrow())?;
        self.inner.types.get(&name)
    }

    pub fn get_type_for<S>(&self, name: S, bits: u32) -> Option<Term<Type>>
    where
        S: Borrow<str>,
    {
        // handle type normalisation here to deal with delayed type resolution
        self.get_type(name).map(|info| info.to_with(self, bits))
    }

    pub fn get_typedef_for<S>(&self, name: S, bits: u32) -> Option<Term<Type>>
    where
        S: Borrow<str>,
    {
        let name = name.borrow();
        let bytes = self.get_type_for(name, bits)?.nbytes() as u32;
        if bits == 32 {
            Some(Type::named_32(name, bytes))
        } else if bits == 64 {
            Some(Type::named_64(name, bytes))
        } else {
            None
        }
    }

    pub fn get_prototype<S>(&self, name: S) -> Option<&TypeInfo>
    where
        S: Borrow<str>,
    {
        let name = Ustr::from_existing(name.borrow())?;
        self.inner.prototypes.get(&name)
    }

    pub fn get_prototype_for<S>(&self, name: S, bits: u32) -> Option<Term<Type>>
    where
        S: Borrow<str>,
    {
        self.get_prototype(name)
            .map(|info| info.to_with(self, bits))
    }

    pub fn set_code_type_at(&mut self, address: Address, type_: Term<Type>) {
        self.code.insert(address, type_);
    }

    pub fn get_code_type_at(&self, address: Address) -> Option<Term<Type>> {
        self.code.get(&address).cloned()
    }

    pub fn set_data_type_at(&mut self, address: Address, type_: Term<Type>) {
        // TODO: types really need to have byte-size accessors
        let sz = type_.nbytes();

        self.data.insert(address, TypeRef::Type(type_));

        for off in 1..sz {
            // set tref back to Address
            self.data.insert(address + off, TypeRef::TRef(address, off));
        }
    }

    pub fn get_data_type_at(&self, address: Address) -> Option<Term<Type>> {
        match self.data.get(&address)? {
            TypeRef::Type(ref t) => Some(t.clone()),
            TypeRef::TRef(paddr, offset) => {
                if let Some(TypeRef::Type(ref t)) = self.data.get(paddr) {
                    t.type_at_offset(*offset)
                } else {
                    // panic!("invalid reference to parent type")
                    None
                }
            }
        }
    }

    pub fn resolve_pointer_type(
        &self,
        rtype: &Term<Type>,
        offsets: &[i64],
    ) -> Option<(Term<Type>, Option<Ustr>)> {
        let (last, offsets) = offsets.split_last()?;

        let mut typ = rtype.clone();
        let mut last_field = None;

        for offset in offsets {
            typ = typ.resolve(self);
            typ = typ.pointee()?.resolve(self);
            (typ, last_field) = typ.field_and_type_at_offset(*offset as usize)?;
        }

        typ = typ.resolve(self);
        if *last == 0 {
            typ = typ.type_at_offset(*last as usize)?;
        } else {
            (typ, last_field) = typ.field_and_type_at_offset(*last as usize)?;
        }

        Some((typ, last_field))
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Enum {
    pub name: Ustr,
    pub size_32: usize,
    pub size_64: usize,
    pub variants_32: Arc<[EnumVariant]>,
    pub variants_64: Arc<[EnumVariant]>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Struct {
    pub name: Ustr,
    pub size_32: usize, // bytes
    pub size_64: usize,
    pub fields_32: Vec<Field>,
    pub fields_64: Vec<Field>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Field {
    pub name: Ustr,
    pub properties: Vec<Property>,
    pub offset: usize,
    pub size: usize,
    pub typ: Term<Type>,
    pub bit_field: Option<(usize, usize)>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Prototype {
    pub name: Ustr,
    pub rtype_32: Term<Type>,
    pub rtype_64: Term<Type>,
    pub atypes_32: Vec<Arg>,
    pub atypes_64: Vec<Arg>,
    pub variadic: bool,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Arg {
    pub name: Ustr,
    pub properties: FunctionArgProps,
    pub typ: Term<Type>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TypeDef {
    pub name: Ustr,
    pub type_32: Term<Type>,
    pub type_64: Term<Type>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Union {
    pub name: Ustr,
    pub size_32: usize,
    pub size_64: usize,
    pub variants_32: Vec<UnionVariant>,
    pub variants_64: Vec<UnionVariant>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum Property {
    ShiftedPointer(i64),
    ShiftedPointerUsize(bool),
}

#[derive(Debug, Error)]
pub enum PropertyParseError {
    #[error("error parsing integer part of property: {0}")]
    ParseIntProperty(#[from] ParseIntError),
    #[error("unexpected property")]
    UnexpectedProperty,
}

impl FromStr for Property {
    type Err = PropertyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static SHIFTED_POINTER: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^__shifted\(\s*([-+]?[0-9]+)\s*\)$").unwrap());

        static SHIFTED_POINTER_PSIZE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^__shifted\(\s*([-+])pointer-size\s*\)$").unwrap());

        if let Some(matched) = SHIFTED_POINTER.captures(s) {
            let value = i64::from_str(&matched[1])?;
            Ok(Self::ShiftedPointer(value))
        } else if let Some(matched) = SHIFTED_POINTER_PSIZE.captures(s) {
            let sign = &matched[1] == "-";
            Ok(Self::ShiftedPointerUsize(sign))
        } else {
            Err(PropertyParseError::UnexpectedProperty)
        }
    }
}

impl Property {
    pub fn apply(&self, bits: u32, t: Term<Type>) -> Term<Type> {
        match self {
            Self::ShiftedPointer(shift) if t.is_pointer() => t.apply_shift(*shift).unwrap_or(t),
            Self::ShiftedPointerUsize(negative) if t.is_pointer() => {
                let shift = (bits / 8) as i64 * if *negative { -1 } else { 1 };
                t.apply_shift(shift).unwrap_or(t)
            }
            _ => t,
        }
    }
}

impl Struct {
    pub fn to_32(&self) -> Term<Type> {
        Type::struct_from_fields(
            &*self.name,
            self.fields_32.iter().map(|f| {
                if let Some((off, sz)) = f.bit_field {
                    StructField::new_bit_field(
                        f.name,
                        f.offset,
                        off,
                        sz,
                        f.properties
                            .iter()
                            .fold(f.typ.clone(), |t, p| p.apply(32, t)),
                    )
                } else {
                    StructField::new(
                        f.name,
                        f.offset,
                        f.properties
                            .iter()
                            .fold(f.typ.clone(), |t, p| p.apply(32, t)),
                    )
                }
            }),
            self.size_32 as u32,
        )
    }

    pub fn to_64(&self) -> Term<Type> {
        Type::struct_from_fields(
            &*self.name,
            self.fields_64.iter().map(|f| {
                if let Some((off, sz)) = f.bit_field {
                    StructField::new_bit_field(
                        f.name,
                        f.offset,
                        off,
                        sz,
                        f.properties
                            .iter()
                            .fold(f.typ.clone(), |t, p| p.apply(64, t)),
                    )
                } else {
                    StructField::new(
                        f.name,
                        f.offset,
                        f.properties
                            .iter()
                            .fold(f.typ.clone(), |t, p| p.apply(64, t)),
                    )
                }
            }),
            self.size_64 as u32,
        )
    }
}

impl Prototype {
    pub fn to_32(&self) -> Term<Type> {
        Type::function_with(
            self.rtype_32.clone(),
            self.atypes_32
                .iter()
                .map(|f| (f.name, f.properties, f.typ.clone())),
            self.variadic,
        )
    }

    pub fn to_32_with(&self, t: &TypeDB) -> Term<Type> {
        let args = if self.atypes_32.len() == 1 && self.atypes_32[0].typ.resolve(t).is_void() {
            &[]
        } else {
            &*self.atypes_32
        };

        Type::function_with(
            self.rtype_32.clone(),
            args.iter().map(|f| (f.name, f.properties, f.typ.clone())),
            self.variadic,
        )
    }

    pub fn to_64(&self) -> Term<Type> {
        Type::function_with(
            self.rtype_64.clone(),
            self.atypes_64
                .iter()
                .map(|f| (f.name, f.properties, f.typ.clone())),
            self.variadic,
        )
    }

    pub fn to_64_with(&self, t: &TypeDB) -> Term<Type> {
        let args = if self.atypes_64.len() == 1 && self.atypes_64[0].typ.resolve(t).is_void() {
            &[]
        } else {
            &*self.atypes_64
        };

        Type::function_with(
            self.rtype_64.clone(),
            args.iter().map(|f| (f.name, f.properties, f.typ.clone())),
            self.variadic,
        )
    }
}

impl Enum {
    pub fn to_32(&self) -> Term<Type> {
        TypeKind::Enum(self.name, self.variants_32.clone(), self.size_32 as u32 * 8).into()
    }

    pub fn to_64(&self) -> Term<Type> {
        TypeKind::Enum(self.name, self.variants_64.clone(), self.size_64 as u32 * 8).into()
    }
}

impl TypeDef {
    pub fn to_32(&self) -> Term<Type> {
        self.type_32.clone()
    }

    pub fn to_64(&self) -> Term<Type> {
        self.type_64.clone()
    }
}

impl Union {
    pub fn to_32(&self) -> Term<Type> {
        TypeKind::Union(
            self.name,
            self.variants_32.iter().cloned().collect(),
            self.size_32 as u32 * 8,
        )
        .into()
    }

    pub fn to_64(&self) -> Term<Type> {
        TypeKind::Union(
            self.name,
            self.variants_64.iter().cloned().collect(),
            self.size_64 as u32 * 8,
        )
        .into()
    }
}
