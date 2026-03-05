use std::borrow::Cow;
use std::mem::take;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::AHashMap;
use clang::{Clang, Entity, EntityKind, EntityVisitResult, Index, TranslationUnit, TypeKind};
use itertools::{Itertools, Position};
use thiserror::Error;
use ustr::{Ustr, UstrMap};

use super::{Arg, Enum, Field, Property, Prototype, Struct, TypeDef, TypeInfo, TypeInfoDB, Union};
use crate::ir::types::{EnumVariant, FunctionArgProps, UnionVariant};
use crate::ir::{BitVec, Term, Type};

// macros for struct field parsing
macro_rules! try_opt {
    ($opt:expr, $relaxed:expr, $msg:expr) => {
        match $opt {
            Some(v) => v,
            None if $relaxed => return None,
            None => return Some(Err(ClangError::ClangBackend($msg.into()))),
        }
    };
}

macro_rules! try_res {
    ($res:expr, $relaxed:expr) => {
        match $res {
            Ok(v) => v,
            Err(_) if $relaxed => return None,
            Err(e) => return Some(Err(e.into())),
        }
    };
}

#[derive(Debug, Error)]
pub enum ClangError {
    #[error(transparent)]
    Clang(#[from] clang::SourceError),
    #[error(transparent)]
    ClangSizeOf(#[from] clang::SizeofError),
    #[error(transparent)]
    ClangOffset(#[from] clang::OffsetofError),
    #[error("{0}")]
    ClangBackend(String),
    #[error("header with path {} does not exist", _0.display())]
    DoesNotExist(PathBuf),
    #[error("parsed struct has an incomplete array member that is not in the last position")]
    StructWithInvalidFlexArrayMember,
}

struct TranslationUnitMulti<'a> {
    m32: TranslationUnit<'a>,
    m64: TranslationUnit<'a>,
    relaxed_struct_parsing: bool,
}

#[derive(Debug)]
struct CFieldInfo<'a> {
    name: Ustr,
    properties: Vec<Property>,
    offset: usize,
    size: usize,
    typ: clang::Type<'a>,
    bit_field: Option<(usize, usize)>, // (offset, width)
}

#[derive(Debug)]
struct CArgInfo<'a> {
    name: Ustr,
    properties: FunctionArgProps,
    typ: clang::Type<'a>,
}

pub const CLANG_DEFAULT_M32: &[&str] = &["-m32"];
pub const CLANG_DEFAULT_M64: &[&str] = &["-m64"];

pub const CLANG_DEFAULT_ARGS: &[&str] = &[
    "-xc",
    "-DEFIAPI=",
    "-DCONST=const",
    "-DIN=__attribute((annotate(\"IN\")))",
    "-DOUT=__attribute((annotate(\"OUT\")))",
    "-D__shifted(x)=*__attribute((annotate(\"__shifted(\"#x\")\")))",
];

impl<'a> TranslationUnitMulti<'a> {
    fn new(
        index: &'a Index,
        path: impl AsRef<Path>,
        mxx: bool,
        m32_arguments: &[impl AsRef<str>],
        m64_arguments: &[impl AsRef<str>],
        relaxed_struct_parsing: bool,
    ) -> Result<TranslationUnitMulti<'a>, ClangError> {
        let path = path.as_ref();

        let m32_arguments = if mxx { CLANG_DEFAULT_M32 } else { &[] }
            .into_iter()
            .copied()
            .chain(m32_arguments.into_iter().map(|s| s.as_ref()))
            .collect::<Vec<_>>();

        let m64_arguments = if mxx { CLANG_DEFAULT_M64 } else { &[] }
            .into_iter()
            .copied()
            .chain(m64_arguments.into_iter().map(|s| s.as_ref()))
            .collect::<Vec<_>>();

        Ok(TranslationUnitMulti {
            m32: index
                .parser(&path)
                .include_attributed_types(true)
                .arguments(&m32_arguments)
                .parse()?,
            m64: index
                .parser(&path)
                .include_attributed_types(true)
                .arguments(&m64_arguments)
                .parse()?,
            relaxed_struct_parsing,
        })
    }

    #[inline]
    fn is_anonymous(e: &Entity) -> bool {
        e.get_name().is_none() || e.is_anonymous()
    }

    fn normalise_unnamed(name: &str) -> Cow<str> {
        if let Some((_, suf)) = name.rsplit_once(" at ") {
            // split out the path part
            let mut pfx = String::from("__anon_ty_");
            let suf = suf.strip_suffix(")").unwrap_or(suf);
            pfx += &base32::encode(
                base32::Alphabet::Rfc4648HexLower { padding: false },
                suf.as_bytes(),
            );
            Cow::Owned(pfx)
        } else {
            let tcname = name.strip_prefix("const ").unwrap_or(name);
            let tsname = tcname.strip_prefix("struct ").unwrap_or(tcname);
            let tsuname = tcname.strip_prefix("union ").unwrap_or(tsname);
            let tseuname = tcname.strip_prefix("enum ").unwrap_or(tsuname);
            Cow::Borrowed(tseuname)
        }
    }

    // build map for those we can determine the size of
    fn build_struct_map<'b>(tu: &'b TranslationUnit<'b>) -> AHashMap<String, (usize, Entity<'b>)> {
        let mut m = AHashMap::<String, (usize, Entity)>::new();

        for s in tu.get_entity().get_children().into_iter() {
            if s.get_kind() == EntityKind::StructDecl {
                let name = s.get_name();
                let size = s.get_type().map(|t| t.get_sizeof());
                if !(name.is_none() || size.is_none() || size.as_ref().unwrap().is_err()) {
                    m.insert(
                        Self::normalise_unnamed(&name.unwrap()).into_owned(),
                        (size.unwrap().unwrap(), s),
                    );
                }
            } else if s.get_kind() == EntityKind::TypedefDecl
                && s.get_children().len() == 1
                && matches!(s.get_child(0), Some(sc) if sc.get_kind() == EntityKind::StructDecl && Self::is_anonymous(&sc))
            {
                let name = s.get_name();
                let size = s.get_type().map(|t| t.get_sizeof());
                if !(name.is_none() || size.is_none() || size.as_ref().unwrap().is_err()) {
                    let inner = s.get_child(0).unwrap();
                    m.insert(
                        Self::normalise_unnamed(&name.unwrap()).into_owned(),
                        (size.unwrap().unwrap(), inner),
                    );
                }
            }

            s.visit_children(|_p, s| {
                if s.get_kind() == EntityKind::StructDecl {
                    let name = s.get_name();
                    let size = s.get_type().map(|t| t.get_sizeof());
                    if name.is_none() || size.is_none() || size.as_ref().unwrap().is_err() {
                        return EntityVisitResult::Recurse;
                    }
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), (size.unwrap().unwrap(), s));
                } else if
                    s.get_kind() == EntityKind::TypedefDecl &&
                        s.get_children().len() == 1 &&
                        matches!(s.get_child(0), Some(sc) if sc.get_kind() == EntityKind::StructDecl && Self::is_anonymous(&sc))
                {
                    let name = s.get_name();
                    let size = s.get_type().map(|t| t.get_sizeof());
                    if name.is_none() || size.is_none() || size.as_ref().unwrap().is_err() {
                        return EntityVisitResult::Recurse;
                    }

                    let inner = s.get_child(0).unwrap();
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), (size.unwrap().unwrap(), inner));
                }
                EntityVisitResult::Recurse
            });
        }
        m
    }

    fn build_proto_map<'b>(tu: &'b TranslationUnit<'b>) -> AHashMap<String, Entity<'b>> {
        let mut m = AHashMap::<String, Entity>::new();

        for f in tu
            .get_entity()
            .get_children()
            .into_iter()
            .filter(|e| e.get_kind() == EntityKind::FunctionDecl)
        {
            let name = f.get_name();
            if name.is_none() {
                continue;
            }
            m.insert(name.unwrap(), f);
        }

        for f in tu
            .get_entity()
            .get_children()
            .into_iter()
            .filter(|e| {
                e.get_kind() == EntityKind::TypedefDecl &&
                e.get_children().len() == 1 &&
                matches!(e.get_child(0), Some(s) if s.get_kind() == EntityKind::FunctionDecl && Self::is_anonymous(&s))
            })
        {
            let name = f.get_name();
            if name.is_none() {
                continue;
            }

            let inner = f.get_child(0).unwrap();

            m.insert(name.unwrap(), inner);
        }

        m
    }

    fn build_enum_map<'b>(tu: &'b TranslationUnit<'b>) -> AHashMap<String, Entity<'b>> {
        let mut m = AHashMap::<String, Entity>::new();

        for s in tu.get_entity().get_children().into_iter() {
            if s.get_kind() == EntityKind::EnumDecl {
                let name = s.get_name();
                let size = s.get_type().map(|t| t.get_sizeof());
                if !(name.is_none() || size.is_none() || size.as_ref().unwrap().is_err()) {
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), s);
                }
            } else if s.get_kind() == EntityKind::TypedefDecl
                && s.get_children().len() == 1
                && matches!(s.get_child(0), Some(sc) if sc.get_kind() == EntityKind::EnumDecl && Self::is_anonymous(&sc))
            {
                let name = s.get_name();
                let size = s.get_type().map(|t| t.get_sizeof());
                if !(name.is_none() || size.is_none() || size.as_ref().unwrap().is_err()) {
                    let inner = s.get_child(0).unwrap();
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), inner);
                }
            }

            s.visit_children(|_p, s| {
                if s.get_kind() == EntityKind::EnumDecl {
                    let name = s.get_name();
                    let size = s.get_type().map(|t| t.get_sizeof());
                    if name.is_none() || size.is_none() || size.as_ref().unwrap().is_err() {
                        return EntityVisitResult::Recurse;
                    }
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), s);
                } else if
                    s.get_kind() == EntityKind::TypedefDecl &&
                    s.get_children().len() == 1 &&
                    matches!(s.get_child(0), Some(sc) if sc.get_kind() == EntityKind::EnumDecl && Self::is_anonymous(&sc))
                {
                    let name = s.get_name();
                    let size = s.get_type().map(|t| t.get_sizeof());
                    if name.is_none() || size.is_none() || size.as_ref().unwrap().is_err() {
                        return EntityVisitResult::Recurse;
                    }
                    let inner = s.get_child(0).unwrap();
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), inner);
                }
                EntityVisitResult::Recurse
            });
        }
        m
    }

    fn build_typedef_map<'b>(
        tu: &'b TranslationUnit<'b>,
    ) -> AHashMap<String, (Entity<'b>, Vec<(String, FunctionArgProps)>)> {
        let mut m = AHashMap::<String, (Entity, Vec<(String, FunctionArgProps)>)>::new();

        for td in tu
            .get_entity()
            .get_children()
            .into_iter()
            .filter(|e| {
                e.get_kind() == EntityKind::TypedefDecl &&
                !(
                    e.get_children().len() == 1 &&
                    matches!(e.get_child(0), Some(s) if (s.get_kind() == EntityKind::FunctionDecl || s.get_kind() == EntityKind::EnumDecl || s.get_kind() == EntityKind::FunctionDecl) && Self::is_anonymous(&s))
                )
            })
        {
            let name = td.get_name();
            if name.is_none() {
                continue;
            }

            // collect parameter names and properties
            let params = td.get_children().into_iter()
                .filter_map(|e| if e.get_kind() == EntityKind::ParmDecl {
                    let props = Self::function_arg_properties(&e);
                    Some((e.get_name().unwrap_or_default(), props))
                } else {
                    None
                })
            .collect();

            m.insert(name.unwrap(), (td, params));
        }

        m
    }

    fn build_union_map<'b>(tu: &'b TranslationUnit<'b>) -> AHashMap<String, (usize, Entity<'b>)> {
        let mut m = AHashMap::<String, (usize, Entity)>::new();

        for u in tu.get_entity().get_children().into_iter() {
            if u.get_kind() == EntityKind::UnionDecl {
                let name = u.get_name();
                let size = u.get_type().map(|t| t.get_sizeof());
                if !(name.is_none() || size.is_none() || size.as_ref().unwrap().is_err()) {
                    m.insert(
                        Self::normalise_unnamed(&name.unwrap()).into_owned(),
                        (size.unwrap().unwrap(), u),
                    );
                }
            } else if u.get_kind() == EntityKind::TypedefDecl
                && u.get_children().len() == 1
                && matches!(u.get_child(0), Some(uc) if uc.get_kind() == EntityKind::UnionDecl && Self::is_anonymous(&uc))
            {
                let name = u.get_name();
                let size = u.get_type().map(|t| t.get_sizeof());
                if !(name.is_none() || size.is_none() || size.as_ref().unwrap().is_err()) {
                    let inner = u.get_child(0).unwrap();
                    m.insert(
                        Self::normalise_unnamed(&name.unwrap()).into_owned(),
                        (size.unwrap().unwrap(), inner),
                    );
                }
            }

            u.visit_children(|_p, u| {
                if u.get_kind() == EntityKind::UnionDecl {
                    let name = u.get_name();
                    let size = u.get_type().map(|t| t.get_sizeof());
                    if name.is_none() || size.is_none() || size.as_ref().unwrap().is_err() {
                        return EntityVisitResult::Recurse;
                    }
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), (size.unwrap().unwrap(), u));
                } else if
                    u.get_kind() == EntityKind::TypedefDecl &&
                    u.get_children().len() == 1 &&
                    matches!(u.get_child(0), Some(uc) if uc.get_kind() == EntityKind::UnionDecl && Self::is_anonymous(&uc))
                {
                    let name = u.get_name();
                    let size = u.get_type().map(|t| t.get_sizeof());
                    if name.is_none() || size.is_none() || size.as_ref().unwrap().is_err() {
                        return EntityVisitResult::Recurse;
                    }
                    let inner = u.get_child(0).unwrap();
                    m.insert(Self::normalise_unnamed(&name.unwrap()).into_owned(), (size.unwrap().unwrap(), inner));
                }
                EntityVisitResult::Recurse
            });
        }
        m
    }

    fn enum_variants<'b>(enumer: &'b Entity<'b>) -> Arc<[EnumVariant]> {
        let bits = enumer.get_type().unwrap().get_sizeof().unwrap() * 8;
        enumer
            .get_children()
            .iter()
            .filter_map(|c| {
                let name = c.get_name()?.into();
                let (signed, unsigned) = c.get_enum_constant_value()?;
                Some(EnumVariant {
                    name,
                    signed: BitVec::from_i64(signed, bits),
                    unsigned: BitVec::from_u64(unsigned, bits),
                })
            })
            .collect()
    }

    fn proto<'b>(proto: &'b Entity<'b>) -> (clang::Type<'b>, Vec<CArgInfo<'b>>, bool) {
        let args = proto
            .get_arguments()
            .map(|args| {
                args.iter()
                    .map(|c| {
                        let name = c.get_name().unwrap_or_default().into();
                        let typ = c.get_type().unwrap(); //.get_canonical_type();
                        let properties = Self::function_arg_properties(&c);

                        CArgInfo {
                            name,
                            properties,
                            typ,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let rtyp = proto.get_result_type().unwrap(); //.get_canonical_type();
        let variadic = proto.is_variadic();

        (rtyp, args, variadic)
    }

    fn struct_fields<'b>(&self, strct: &'b Entity<'b>) -> Result<Vec<CFieldInfo<'b>>, ClangError> {
        let relaxed = self.relaxed_struct_parsing;
        let styp = strct.get_type().unwrap();
        strct
            .get_children()
            .iter()
            .filter(|c| c.get_kind() == EntityKind::FieldDecl)
            .with_position()
            .filter_map(|(position, c)| {
                let name = try_opt!(c.get_name(), relaxed, "missing field name").into();
                let typ = try_opt!(c.get_type(), relaxed, "missing field type"); //.get_canonical_type();
                let properties = Self::properties(c);
                let offset = try_res!(styp.get_offsetof(&name), relaxed) / 8;
                let size = if typ.get_kind() == TypeKind::IncompleteArray
                    || (typ.get_kind() == TypeKind::ConstantArray
                        && typ.get_size().unwrap_or(0) == 0)
                {
                    if !matches!(position, Position::Last | Position::Only) {
                        return Some(Err(ClangError::StructWithInvalidFlexArrayMember));
                    }
                    // sizeof(struct) excludes flexible array member
                    0
                } else {
                    try_res!(typ.get_sizeof(), relaxed)
                };

                Some(Ok(CFieldInfo {
                    // TODO: this is where we should handle bit fields
                    offset,
                    properties,
                    name,
                    size,
                    typ,
                    bit_field: c.get_bit_field_width().and_then(|w| {
                        // NOTE: this offset is from the beginning of the struct; so we need
                        // to adjust it to be relative to the offset from the byte offset
                        // reported on our type.
                        //
                        let soff = c.get_offset_of_field().ok()?;
                        let off = soff - (offset * 8);

                        Some((off, w))
                    }),
                }))
            })
            .collect()
    }

    fn union_variants<'b>(u: &'b Entity<'b>) -> Vec<(Ustr, usize, clang::Type<'b>)> {
        u.get_children()
            .iter()
            .filter_map(|c| {
                if c.get_kind() != EntityKind::FieldDecl {
                    return None;
                }

                let name = c.get_name()?.into();
                let typ = c.get_type()?;
                let size = typ.get_sizeof().ok()?;

                Some((name, size, typ))
            })
            .collect()
    }

    fn properties(e: &Entity) -> Vec<Property> {
        let mut properties = Vec::new();

        if e.has_attributes() {
            for p in e
                .get_children()
                .into_iter()
                .filter(|e| e.get_kind() == EntityKind::AnnotateAttr)
            {
                if let Some(p) = p
                    .get_display_name()
                    .as_deref()
                    .and_then(|p| p.parse::<Property>().ok())
                {
                    properties.push(p);
                }
            }
        }

        properties
    }

    fn function_arg_properties(e: &Entity) -> FunctionArgProps {
        let mut properties = FunctionArgProps::default();

        if e.has_attributes() {
            for p in e
                .get_children()
                .into_iter()
                .filter(|e| e.get_kind() == EntityKind::AnnotateAttr)
            {
                match p.get_display_name().map(|s| s.to_lowercase()).as_deref() {
                    Some("in") => properties.insert(FunctionArgProps::IN),
                    Some("out") => properties.insert(FunctionArgProps::OUT),
                    _ => (),
                }
            }
        }

        properties
    }

    fn resolve_type<'b>(
        resolved: &UstrMap<TypeInfo>,
        typ32: &'b clang::Type<'b>,
        typ64: &'b clang::Type<'b>,
    ) -> Option<(Term<Type>, Term<Type>)> {
        let mut params = Vec::with_capacity(0);
        Self::resolve_type_with(resolved, typ32, typ64, &mut params)
    }

    fn resolve_type_with<'b>(
        resolved: &UstrMap<TypeInfo>,
        typ32: &'b clang::Type<'b>,
        typ64: &'b clang::Type<'b>,
        params: &mut Vec<(String, FunctionArgProps)>,
    ) -> Option<(Term<Type>, Term<Type>)> {
        let dup2 = |t: Term<Type>| (t.clone(), t);
        let (mut t32, mut t64) = match typ32.get_kind() {
            TypeKind::Void => dup2(Type::void()),
            TypeKind::CharS | TypeKind::SChar => dup2(Type::char()),
            TypeKind::CharU | TypeKind::UChar => dup2(Type::unsigned_char()),
            TypeKind::Char16 => dup2(Type::char16()),
            TypeKind::Char32 => dup2(Type::char32()),
            TypeKind::Short | TypeKind::Int | TypeKind::Long | TypeKind::LongLong => {
                let sz32 = typ32.get_sizeof().unwrap() as u32;
                let sz64 = typ64.get_sizeof().unwrap() as u32;

                if sz32 != sz64 {
                    (Type::signed(sz32 * 8), Type::signed(sz64 * 8))
                } else if sz32 == 2 {
                    dup2(Type::signed(16))
                } else if sz32 == 4 {
                    dup2(Type::signed(32))
                } else if sz32 == 8 {
                    dup2(Type::signed(64))
                } else {
                    (
                        Type::named_32(typ32.get_display_name(), sz32),
                        Type::named_64(typ64.get_display_name(), sz64),
                    )
                }
            }
            TypeKind::WChar => {
                let sz32 = typ32.get_sizeof().unwrap() as u32 * 8;
                let sz64 = typ64.get_sizeof().unwrap() as u32 * 8;

                // can these be different?
                let sn32 = typ32.is_signed_integer();
                let sn64 = typ64.is_signed_integer();

                (Type::wchar(sz32, sn32), Type::wchar(sz64, sn64))
            }
            TypeKind::UShort | TypeKind::UInt | TypeKind::ULong | TypeKind::ULongLong => {
                let sz32 = typ32.get_sizeof().unwrap() as u32;
                let sz64 = typ64.get_sizeof().unwrap() as u32;

                if sz32 != sz64 {
                    (Type::unsigned(sz32 * 8), Type::unsigned(sz64 * 8))
                } else if sz32 == 2 {
                    dup2(Type::unsigned(16))
                } else if sz32 == 4 {
                    dup2(Type::unsigned(32))
                } else if sz32 == 8 {
                    dup2(Type::unsigned(64))
                } else {
                    (
                        Type::named_32(typ32.get_display_name(), sz32),
                        Type::named_64(typ64.get_display_name(), sz64),
                    )
                }
            }
            TypeKind::Pointer => {
                let e32 = typ32.get_pointee_type().unwrap();
                let e64 = typ64.get_pointee_type().unwrap();

                let (etyp1, etyp2) = Self::resolve_type_with(resolved, &e32, &e64, params)?;

                (Type::pointer(etyp1, 32), Type::pointer(etyp2, 64))
            }
            TypeKind::ConstantArray => {
                let e32 = typ32.get_element_type().unwrap();
                let e64 = typ64.get_element_type().unwrap();

                let (etyp1, etyp2) = Self::resolve_type_with(resolved, &e32, &e64, params)?;
                let n32 = typ32.get_size().unwrap() as u32;
                let n64 = typ64.get_size().unwrap() as u32;

                // treat `array[0]` as incomplete per clang's fstrict-flex-arrays level 2 (default)
                (
                    if n32 == 0 {
                        Type::incomplete_array(etyp1)
                    } else {
                        Type::array(etyp1, n32)
                    },
                    if n64 == 0 {
                        Type::incomplete_array(etyp2)
                    } else {
                        Type::array(etyp2, n64)
                    },
                )
            }
            TypeKind::IncompleteArray => {
                let e32 = typ32.get_element_type().unwrap();
                let e64 = typ64.get_element_type().unwrap();

                let (etyp1, etyp2) = Self::resolve_type_with(resolved, &e32, &e64, params)?;

                (Type::incomplete_array(etyp1), Type::incomplete_array(etyp2))
            }
            TypeKind::VariableArray => {
                let e32 = typ32.get_element_type().unwrap();
                let e64 = typ64.get_element_type().unwrap();

                let (etyp1, etyp2) = Self::resolve_type_with(resolved, &e32, &e64, params)?;

                (
                    Type::variable_sized_array(etyp1),
                    Type::variable_sized_array(etyp2),
                )
            }
            TypeKind::FunctionPrototype => {
                let r32 = typ32.get_result_type().unwrap();
                let r64 = typ64.get_result_type().unwrap();

                let param_names = take(params);

                let (rtyp1, rtyp2) = Self::resolve_type_with(resolved, &r32, &r64, params)?;

                let a32 = typ32.get_argument_types().unwrap();
                let a64 = typ64.get_argument_types().unwrap();

                let variadic = typ32.is_variadic();

                if !param_names.is_empty() && param_names.len() == a32.len() {
                    let (atyp1, atyp2): (Vec<_>, Vec<_>) = param_names
                        .into_iter()
                        .map(|(s, p)| (Ustr::from(&s), p))
                        .zip(a32.iter().zip(a64.iter()))
                        .map(|((name, props), (a32, a64))| {
                            let (t32, t64) =
                                Self::resolve_type_with(resolved, a32, a64, params).unwrap();
                            ((name, props, t32), (name, props, t64))
                        })
                        .unzip();
                    (
                        Type::function_with(rtyp1, atyp1.into_iter(), variadic),
                        Type::function_with(rtyp2, atyp2.into_iter(), variadic),
                    )
                } else {
                    let (atyp1, atyp2): (Vec<_>, Vec<_>) = a32
                        .iter()
                        .zip(a64.iter())
                        .map(|(a32, a64)| {
                            Self::resolve_type_with(resolved, a32, a64, params).unwrap()
                        })
                        .unzip();
                    (
                        Type::function_with(rtyp1, atyp1.into_iter(), variadic),
                        Type::function_with(rtyp2, atyp2.into_iter(), variadic),
                    )
                }
            }
            kind => {
                if let Ok((sz32, sz64)) = typ32
                    .get_sizeof()
                    .and_then(|sz32| typ64.get_sizeof().map(|sz64| (sz32, sz64)))
                {
                    let tname = typ32.get_display_name();
                    let trname = Self::normalise_unnamed(&tname);

                    (
                        Type::named_32(trname.as_ref(), sz32 as u32),
                        Type::named_64(trname.as_ref(), sz64 as u32),
                    )
                } else if typ32.get_kind() == TypeKind::Typedef
                    || typ32.get_kind() == TypeKind::Elaborated
                {
                    // assume that if we reach here, this is a forward declaration
                    // we do not know the correct size, hence provide a zero-sized
                    // type to indicate this
                    let tname = typ32.get_display_name();
                    let trname = Self::normalise_unnamed(&tname);

                    (
                        Type::named_32(trname.as_ref(), 0),
                        Type::named_64(trname.as_ref(), 0),
                    )
                } else {
                    tracing::warn!(
                        "could not resolve type {} with kind {:?}",
                        typ32.get_display_name(),
                        kind
                    );
                    return None;
                }
            }
        };

        if typ32.is_const_qualified() {
            t32 = t32.const_();
            t64 = t64.const_();
        }

        if typ32.is_volatile_qualified() {
            t32 = t32.volatile();
            t64 = t64.volatile();
        }

        Some((t32, t64))
    }

    pub fn build(self) -> TypeInfoDB {
        let m32 = Self::build_struct_map(&self.m32);
        let m64 = Self::build_struct_map(&self.m64);

        let mut types = UstrMap::default();
        let mut prototypes = UstrMap::default();

        let td32 = Self::build_typedef_map(&self.m32);
        let td64 = Self::build_typedef_map(&self.m64);

        'touter: for (n, (m32_e, mut params)) in td32.into_iter() {
            if let Some((m64_e, _)) = td64.get(&n) {
                let n_id = n;

                let typ32 = m32_e.get_typedef_underlying_type().unwrap();
                let typ64 = m64_e.get_typedef_underlying_type().unwrap();

                let (type_32, type_64) = if let Some((t32, t64)) =
                    Self::resolve_type_with(&types, &typ32, &typ64, &mut params)
                {
                    (t32, t64)
                } else {
                    continue 'touter;
                };

                let name = Ustr::from(&*n_id);
                types.insert(
                    name,
                    TypeDef {
                        name,
                        type_32,
                        type_64,
                    }
                    .into(),
                );
            }
        }

        'outer: for (n, (m32_sz, m32_e)) in m32.iter() {
            if let Some((m64_sz, m64_e)) = m64.get(n) {
                let n_id = n;

                let m32_fields = match self.struct_fields(m32_e) {
                    Ok(fields) => fields,
                    Err(err) => {
                        tracing::warn!("failed to parse struct `{n_id}`, skipping: {err}");
                        continue 'outer;
                    }
                };
                let m64_fields = match self.struct_fields(m64_e) {
                    Ok(fields) => fields,
                    Err(err) => {
                        tracing::warn!("failed to parse struct `{n_id}`, skipping: {err}");
                        continue 'outer;
                    }
                };

                // sanity check
                if m32_fields.len() != m64_fields.len() {
                    continue 'outer;
                }

                // sanity check
                for (n32, n64) in m32_fields.iter().zip(m64_fields.iter()) {
                    if n32.name != n64.name {
                        continue 'outer;
                    }
                }

                let mut m32_body = Vec::new();
                let mut m64_body = Vec::new();

                m32_fields.into_iter().zip(m64_fields.into_iter()).for_each(
                    |(m32_field, m64_field)| {
                        let name = m32_field.name;

                        let m32_offset = m32_field.offset;
                        let m32_size = m32_field.size;

                        let m64_offset = m64_field.offset;
                        let m64_size = m64_field.size;

                        let (ty32, ty64) = if let Some((t32, t64)) =
                            Self::resolve_type(&types, &m32_field.typ, &m64_field.typ)
                        {
                            (t32, t64)
                        } else {
                            let tname32 = m32_field.typ.get_display_name();
                            let tname64 = m64_field.typ.get_display_name();
                            (
                                Type::named_32(tname32, m32_size as u32),
                                Type::named_64(tname64, m64_size as u32),
                            )
                        };

                        // TODO: actually obtain the mask...
                        let bit_field = m32_field.bit_field;

                        m32_body.push(Field {
                            name,
                            properties: m32_field.properties,
                            size: m32_size,
                            offset: m32_offset,
                            typ: ty32,
                            bit_field,
                        });
                        m64_body.push(Field {
                            name,
                            properties: m64_field.properties,
                            size: m64_size,
                            offset: m64_offset,
                            typ: ty64,
                            bit_field,
                        });
                    },
                );

                let name = Ustr::from(&*n_id);
                types.insert(
                    name,
                    Struct {
                        name,
                        size_32: *m32_sz,
                        size_64: *m64_sz,
                        fields_32: m32_body,
                        fields_64: m64_body,
                    }
                    .into(),
                );
            }
        }

        let fm32 = Self::build_proto_map(&self.m32);
        let fm64 = Self::build_proto_map(&self.m64);

        'pouter: for (n, m32_e) in fm32.iter() {
            if let Some(m64_e) = fm64.get(n) {
                let n_id = n;
                let (m32_rtyp, m32_args, m32_variadic) = Self::proto(m32_e);
                let (m64_rtyp, m64_args, m64_variadic) = Self::proto(m64_e);

                // sanity check
                if m32_args.len() != m64_args.len() || m32_variadic != m64_variadic {
                    continue 'pouter;
                }

                let (rtype_32, rtype_64) =
                    if let Some((t32, t64)) = Self::resolve_type(&types, &m32_rtyp, &m64_rtyp) {
                        (t32, t64)
                    } else {
                        let tname32 = m32_rtyp.get_display_name();
                        let tname64 = m64_rtyp.get_display_name();

                        let m32_size = m32_rtyp.get_sizeof().unwrap_or(0);
                        let m64_size = m64_rtyp.get_sizeof().unwrap_or(0);
                        (
                            Type::named_32(tname32, m32_size as u32),
                            Type::named_64(tname64, m64_size as u32),
                        )
                    };

                let mut atypes_32 = Vec::new();
                let mut atypes_64 = Vec::new();

                m32_args
                    .iter()
                    .zip(m64_args.iter())
                    .for_each(|(m32_arg, m64_arg)| {
                        let name = m32_arg.name;

                        let (ty32, ty64) = if let Some((t32, t64)) =
                            Self::resolve_type(&types, &m32_arg.typ, &m64_arg.typ)
                        {
                            (t32, t64)
                        } else {
                            let tname32 = m32_arg.typ.get_display_name();
                            let tname64 = m64_arg.typ.get_display_name();

                            let m32_size = m32_arg.typ.get_sizeof().unwrap_or(0);
                            let m64_size = m64_arg.typ.get_sizeof().unwrap_or(0);
                            (
                                Type::named_32(tname32, m32_size as u32),
                                Type::named_64(tname64, m64_size as u32),
                            )
                        };

                        atypes_32.push(Arg {
                            name,
                            properties: m32_arg.properties,
                            typ: ty32,
                        });
                        atypes_64.push(Arg {
                            name,
                            properties: m64_arg.properties,
                            typ: ty64,
                        });
                    });

                let name = Ustr::from(&*n_id);
                prototypes.insert(
                    name,
                    Prototype {
                        name,
                        rtype_32,
                        rtype_64,
                        atypes_32,
                        atypes_64,
                        variadic: m32_variadic,
                    }
                    .into(),
                );
            }
        }

        let em32 = Self::build_enum_map(&self.m32);
        let em64 = Self::build_enum_map(&self.m64);

        'eouter: for (n, m32_e) in em32.iter() {
            if let Some(m64_e) = em64.get(n) {
                let n_id = n;

                let size_32 = m32_e.get_type().unwrap().get_sizeof().unwrap_or(0);
                let size_64 = m64_e.get_type().unwrap().get_sizeof().unwrap_or(0);

                if size_32 == 0 || size_64 == 0 {
                    continue 'eouter;
                }

                let variants_32 = Self::enum_variants(m32_e);
                let variants_64 = Self::enum_variants(m64_e);

                let name = Ustr::from(&*n_id);
                types.insert(
                    name,
                    Enum {
                        name,
                        size_32,
                        size_64,
                        variants_32,
                        variants_64,
                    }
                    .into(),
                );
            }
        }

        let u32 = Self::build_union_map(&self.m32);
        let u64 = Self::build_union_map(&self.m64);

        'uouter: for (n, (u32_sz, u32_e)) in u32.iter() {
            if let Some((u64_sz, u64_e)) = u64.get(n) {
                let n_id = n;
                let u32_variants = Self::union_variants(u32_e);
                let u64_variants = Self::union_variants(u64_e);

                // NOTE: on reflection, it may be that these sanity checks are too aggressive

                // sanity check
                if u32_variants.len() != u64_variants.len() {
                    continue 'uouter;
                }

                // sanity check
                for (n32, n64) in u32_variants.iter().zip(u64_variants.iter()) {
                    // name check
                    if n32.0 != n64.0 {
                        continue 'uouter;
                    }
                }

                let mut u32_parts = Vec::new();
                let mut u64_parts = Vec::new();

                u32_variants
                    .into_iter()
                    .zip(u64_variants.into_iter())
                    .for_each(|(u32_variant, u64_variant)| {
                        let (name, u32_size, u32_typ) = u32_variant;
                        let (_, u64_size, u64_typ) = u64_variant;

                        let (ty32, ty64) = if let Some((t32, t64)) =
                            Self::resolve_type(&types, &u32_typ, &u64_typ)
                        {
                            (t32, t64)
                        } else {
                            let tname32 = u32_typ.get_display_name();
                            let tname64 = u64_typ.get_display_name();
                            (
                                Type::named_32(tname32, u32_size as u32),
                                Type::named_64(tname64, u64_size as u32),
                            )
                        };

                        u32_parts.push(UnionVariant::new(name, ty32));
                        u64_parts.push(UnionVariant::new(name, ty64));
                    });

                let name = Ustr::from(&*n_id);

                types.insert(
                    name,
                    Union {
                        name,
                        size_32: *u32_sz,
                        size_64: *u64_sz,
                        variants_32: u32_parts,
                        variants_64: u64_parts,
                    }
                    .into(),
                );
            }
        }

        TypeInfoDB::new(types, prototypes)
    }
}

pub struct CIOImporter {
    clang: Clang,
}

impl CIOImporter {
    pub fn new() -> Result<Self, ClangError> {
        Ok(Self {
            clang: Clang::new().map_err(ClangError::ClangBackend)?,
        })
    }

    pub fn import<P: AsRef<Path>>(&self, path: P) -> Result<TypeInfoDB, ClangError> {
        self.import_with(path, true, CLANG_DEFAULT_ARGS, CLANG_DEFAULT_ARGS, false)
    }

    pub fn import_permissive<P: AsRef<Path>>(&self, path: P) -> Result<TypeInfoDB, ClangError> {
        self.import_with(path, true, CLANG_DEFAULT_ARGS, CLANG_DEFAULT_ARGS, true)
    }

    pub fn import_with<P: AsRef<Path>>(
        &self,
        path: P,
        mxx: bool,
        m32_args: &[impl AsRef<str>],
        m64_args: &[impl AsRef<str>],
        relaxed_struct_parsing: bool,
    ) -> Result<TypeInfoDB, ClangError> {
        // NOTE:
        // the error reporting for clang-rs is not great: not found gives an
        // unknown error, so we check first here to provide a better error.
        //
        let path = path.as_ref();
        if !path.exists() {
            return Err(ClangError::DoesNotExist(path.to_owned()));
        }

        let index = Index::new(&self.clang, false, false);
        let multi = TranslationUnitMulti::new(
            &index,
            path,
            mxx,
            m32_args,
            m64_args,
            relaxed_struct_parsing,
        )?;
        Ok(multi.build())
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::sync::Mutex;

    use super::*;
    use crate::cio::TypeDB;
    use crate::ir::types::TypeDisplay;

    // Clang::new() uses a global singleton - only one instance can exist at a time.
    // This mutex serializes test execution so each test can create/drop its own Clang.
    static CLANG_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_basic_header() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = CLANG_LOCK.lock().unwrap();

        let data = env::var("BIAS_DATA")?;
        let types = Path::new(&data).join("platforms/uefi/types/edk.h");

        let cio = CIOImporter::new()?;
        let structs = cio.import(types)?;

        for s in structs.types().values() {
            println!("{:#?}", s);
        }

        Ok(())
    }

    #[test]
    fn test_flex_array_member() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = CLANG_LOCK.lock().unwrap();

        let data = env::var("BIAS_DATA")?;
        let types = Path::new(&data).join("platforms/posix/types/types.h");

        let cio = CIOImporter::new()?;
        let structs = cio.import(types)?;

        let mut tbd = TypeDB::new();
        tbd.import_types(&structs);

        let linux_dirent64 = tbd
            .get_type_for("linux_dirent64", 64)
            .unwrap()
            .resolve(&tbd);

        println!("Expecting `attrs: INCOMPLETE` on field `d_name`:");
        println!("{}", TypeDisplay::new_with(&linux_dirent64, &tbd, 2));

        Ok(())
    }

    #[test]
    fn test_behemoth() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = CLANG_LOCK.lock().unwrap();

        let data = env::var("BIAS_DATA")?;
        let types = Path::new(&data).join("platforms/uefi/types/edk.h");

        let cio = CIOImporter::new()?;
        let structs = cio.import(types)?;

        let smm = structs
            .types()
            .get(&Ustr::from("_EFI_SMM_SYSTEM_TABLE2"))
            .unwrap();

        println!("{:#?}", smm);

        let mty = structs.types().get(&Ustr::from("EFI_MEMORY_TYPE")).unwrap();

        println!("{:#?}", mty);

        let ehp = structs
            .types()
            .get(&Ustr::from("EFI_BOOT_SERVICES"))
            .unwrap();

        println!("{:#?}", ehp);

        let dispatch = "EFI_SMM_SW_DISPATCH2_PROTOCOL";
        let tname = format!("_{}", dispatch);
        let addr_bits = 64;

        let mut tdb = TypeDB::new();
        tdb.import_types(&structs);

        let dstruct = tdb.get_type_for(&*tname, addr_bits).unwrap();

        println!("{dstruct}");
        println!("{:#?}", dstruct.struct_fields());

        let register_off = dstruct.offset_of_field("Register").unwrap();

        println!("Register: {register_off}");

        let prim = tdb.get_type_for("UINT32", addr_bits).unwrap().resolve(&tdb);
        println!("UINT32: {prim:#?}");

        let prim = tdb.get_type_for("UINT64", addr_bits).unwrap().resolve(&tdb);
        println!("UINT64: {prim:#?}");

        let prim = tdb.get_type_for("UINTN", addr_bits).unwrap().resolve(&tdb);
        println!("UINTN: {prim:#?}");

        let prim = tdb
            .get_type_for("BOOLEAN", addr_bits)
            .unwrap()
            .resolve(&tdb);
        println!("BOOL: {prim:#?}");

        let prim = tdb.get_type_for("VOID", addr_bits).unwrap().resolve(&tdb);
        println!("VOID: {prim:#?}");

        let prim = tdb.get_type_for("CHAR8", addr_bits).unwrap().resolve(&tdb);
        println!("CHAR8: {prim:#?}");

        let prim = tdb
            .get_type_for("EFI_BOOT_KEY_DATA", addr_bits)
            .unwrap()
            .resolve(&tdb);

        println!("EFI_BOOT_KEY_DATA: {prim:#?}");

        let parts = prim.union_variants().unwrap();

        for variant in parts.iter() {
            println!("{} -> {:#?}", variant.name(), variant.type_().resolve(&tdb));
        }

        println!(
            "EFI_BOOT_KEY_DATA: {}",
            TypeDisplay::new_with(&prim, &tdb, 2)
        );

        println!("{tname}: {}", TypeDisplay::new_with(&dstruct, &tdb, 2));

        let efi_dhcp4_build = tdb
            .get_type_for("EFI_DHCP4_BUILD", addr_bits)
            .unwrap()
            .resolve(&tdb);

        println!(
            "EFI_DHCP4_BUILD: {}",
            TypeDisplay::new_with(&efi_dhcp4_build, &tdb, 2)
        );

        for arg in efi_dhcp4_build.pointee().unwrap().function_args().unwrap() {
            println!(
                "{}",
                TypeDisplay::new_with(&arg.type_().resolve(&tdb), &tdb, 2)
            );
        }

        Ok(())
    }
}
