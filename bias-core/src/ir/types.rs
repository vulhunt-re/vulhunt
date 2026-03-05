use std::borrow::{Borrow, Cow};
use std::fmt::{self, Display};
use std::ops::Deref;
use std::sync::Arc;

use ahash::AHashSet;
use bitflags::bitflags;
use fugue::bv::BitVec;
use fugue::ir::float_format::FloatFormat;
use smallvec::SmallVec;
use ustr::Ustr;

use crate::cio::{TypeDB, TypeInfo};
use crate::ir::term::arena::Arena;
use crate::ir::term::{Term, TermMut};
use crate::ir::traits::*;
use crate::ir::Expr;

thread_local! {
    static TYPE: Arena<Type> = Default::default();
    static FFMT: Arena<FloatFormat> = Default::default();
}

pub(crate) fn collect_garbage() {
    FFMT.with(|v| v.shrink_to_fit());
    TYPE.with(|v| v.shrink_to_fit());
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct FloatKind(Term<FloatFormat>);

impl<'de> serde::Deserialize<'de> for FloatKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(FloatFormat::deserialize(deserializer)?.into())
    }
}

impl From<FloatFormat> for Term<FloatFormat> {
    fn from(f: FloatFormat) -> Self {
        FFMT.with(|a| Term::new(&*a, f))
    }
}

crate::impl_term_mut!(FFMT for FloatFormat);

impl Borrow<FloatFormat> for FloatKind {
    fn borrow(&self) -> &FloatFormat {
        &*self.0
    }
}

impl Borrow<FloatFormat> for &'_ FloatKind {
    fn borrow(&self) -> &FloatFormat {
        &*self.0
    }
}

impl Deref for FloatKind {
    type Target = FloatFormat;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl BitSize for FloatKind {
    fn nbits(&self) -> u32 {
        self.0.bits() as u32
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct EnumVariant {
    pub name: Ustr,
    pub signed: BitVec,
    pub unsigned: BitVec,
}

impl EnumVariant {
    pub fn new(
        name: impl Into<Ustr>,
        signed: impl Into<BitVec>,
        unsigned: impl Into<BitVec>,
    ) -> Self {
        Self {
            name: name.into(),
            signed: signed.into(),
            unsigned: unsigned.into(),
        }
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn signed_value(&self) -> &BitVec {
        &self.signed
    }

    pub fn unsigned_value(&self) -> &BitVec {
        &self.unsigned
    }
}

impl BitSize for EnumVariant {
    fn nbits(&self) -> u32 {
        self.unsigned.nbits()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct FunctionArg {
    name: Option<Ustr>,
    properties: FunctionArgProps,
    typ: Term<Type>,
}

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize)]
    pub struct FunctionArgProps: u8 {
        const IN     = 0b0000_0001;
        const OUT    = 0b0000_0010;

        const IN_OUT = Self::IN.bits() | Self::OUT.bits();
    }
}

impl Display for FunctionArgProps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "")
        } else {
            if self.contains(Self::IN_OUT) {
                write!(f, "<IN|OUT>")
            } else if self.contains(Self::IN) {
                write!(f, "<IN>")
            } else if self.contains(Self::OUT) {
                write!(f, "<OUT>")
            } else {
                write!(f, "<?>")
            }
        }
    }
}

impl Display for FunctionArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name {
            write!(f, "{}: {}", name, self.typ)
        } else {
            write!(f, "_: {}", self.typ)
        }
    }
}

impl From<Term<Type>> for FunctionArg {
    fn from(typ: Term<Type>) -> Self {
        Self {
            name: None,
            properties: Default::default(),
            typ,
        }
    }
}

impl From<(Ustr, Term<Type>)> for FunctionArg {
    fn from(parts: (Ustr, Term<Type>)) -> Self {
        Self {
            name: if parts.0.is_empty() {
                None
            } else {
                Some(parts.0)
            },
            properties: Default::default(),
            typ: parts.1,
        }
    }
}

impl From<(Ustr, FunctionArgProps, Term<Type>)> for FunctionArg {
    fn from(parts: (Ustr, FunctionArgProps, Term<Type>)) -> Self {
        Self {
            name: if parts.0.is_empty() {
                None
            } else {
                Some(parts.0)
            },
            properties: parts.1,
            typ: parts.2,
        }
    }
}

impl FunctionArg {
    pub fn new(name: impl Into<Option<Ustr>>, typ: impl Into<Term<Type>>) -> Self {
        Self::new_with(name, Default::default(), typ)
    }

    pub fn new_with(
        name: impl Into<Option<Ustr>>,
        properties: FunctionArgProps,
        typ: impl Into<Term<Type>>,
    ) -> Self {
        let name = name.into();
        Self {
            name: if name.is_none() {
                name
            } else {
                name.and_then(|n| if n.is_empty() { None } else { Some(n) })
            },
            properties,
            typ: typ.into(),
        }
    }

    pub fn name(&self) -> Option<Ustr> {
        self.name
    }

    pub fn is_input(&self) -> bool {
        self.properties.contains(FunctionArgProps::IN)
    }

    pub fn is_output(&self) -> bool {
        self.properties.contains(FunctionArgProps::OUT)
    }

    pub fn is_input_and_output(&self) -> bool {
        self.properties.contains(FunctionArgProps::IN_OUT)
    }

    pub fn type_(&self) -> &Term<Type> {
        &self.typ
    }
}

impl BitSize for FunctionArg {
    fn nbits(&self) -> u32 {
        self.typ.nbits()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct StructField {
    name: Ustr,
    typ: Term<Type>, // backing type if bit field (max is u64)
    offset: u32,
    boffset: u32,
    bsize: u32,
}

impl StructField {
    pub fn new(name: impl Into<Ustr>, offset: usize, typ: impl Into<Term<Type>>) -> Self {
        Self {
            name: name.into(),
            offset: offset as _,
            typ: typ.into(),
            boffset: 0,
            bsize: 0,
        }
    }

    pub fn new_bit_field(
        name: impl Into<Ustr>,
        base_offset: usize,
        boffset: usize,
        bsize: usize,
        typ: impl Into<Term<Type>>,
    ) -> Self {
        let typ = typ.into();

        Self {
            name: name.into(),
            offset: base_offset as _,
            typ: typ.into(),
            boffset: boffset as _,
            bsize: bsize as _,
        }
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn offset(&self) -> usize {
        self.offset as _
    }

    pub fn type_(&self) -> &Term<Type> {
        &self.typ
    }

    pub fn is_bit_field(&self) -> bool {
        self.bsize != 0
    }

    pub fn bit_field_offset(&self) -> Option<u32> {
        self.is_bit_field().then_some(self.boffset)
    }

    pub fn bit_field_width(&self) -> Option<u32> {
        self.is_bit_field().then_some(self.bsize)
    }

    /*
    pub fn bit_field_mask(&self) -> Option<BitVec> {
        if !self.is_bit_field() {
            return None;
        }

        Some(BitVec::from_u64(self.bmask, self.typ.nbits() as _))
    }

    pub fn resolve_bit_field(&self, val: &BitVec) -> Option<BitVec> {
        if !self.is_bit_field() {
            return None;
        }

        if self.typ.nbits() != val.nbits() {
            return None;
        }

        // TODO: check if the shift is correct!

        let shift = self.bmask.trailing_zeros();
        let masked = (val & &BitVec::from_u64(self.bmask, val.nbits() as _)) >> shift;

        Some(masked)
    }
    */
}

impl BitSize for StructField {
    fn nbits(&self) -> u32 {
        if let Some(bsize) = self.bit_field_width() {
            bsize
        } else {
            self.typ.nbits()
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct UnionVariant {
    name: Ustr,
    typ: Term<Type>,
}

impl UnionVariant {
    pub fn new(name: impl Into<Ustr>, typ: impl Into<Term<Type>>) -> Self {
        Self {
            name: name.into(),
            typ: typ.into(),
        }
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn type_(&self) -> &Term<Type> {
        &self.typ
    }
}

impl BitSize for UnionVariant {
    fn nbits(&self) -> u32 {
        self.typ.nbits()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum TypeKind {
    Void,
    Bool, // T -> Bool

    Signed(u32),   // sign-extension
    Unsigned(u32), // zero-extension

    Float(FloatKind), // T -> FloatFormat::T

    Array(Term<Type>, u32),

    Pointer(Term<Type>, u32),
    ShiftedPointer(Term<Type>, i64, u32),

    Function(Term<Type>, SmallVec<[FunctionArg; 4]>),

    Struct(Ustr, SmallVec<[StructField; 4]>, u32),
    Union(Ustr, SmallVec<[UnionVariant; 4]>, u32),
    Enum(Ustr, Arc<[EnumVariant]>, u32),

    Named(Ustr, u32), // typedef
}

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize)]
    pub struct TypeAttrs: u16 {
        const CHAR       = 0b0000_0000_0000_0001; // utf-16 == char + size 16, etc.
        const WCHAR      = 0b0000_0000_0000_0010;

        const CONST      = 0b0000_0001_0000_0000;
        const VOLATILE   = 0b0000_0010_0000_0000;
        const VARSIZED   = 0b0000_0100_0000_0000;
        const INCOMPLETE = 0b0000_1000_0000_0000; // "incomplete" array, e.g. `int[]`

        const VARIADIC   = 0b0001_0000_0000_0000;

        const TYPE32     = 0b0100_0000_0000_0000;
        const TYPE64     = 0b1000_0000_0000_0000;
    }
}

impl Display for TypeAttrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut it = self.iter_names();
        if let Some((first, _)) = it.next() {
            f.write_str(first)?;
        }
        while let Some((name, _)) = it.next() {
            write!(f, "+ {name}")?;
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct Type {
    kind: TypeKind,
    attrs: TypeAttrs,
}

impl Deref for Type {
    type Target = TypeKind;

    fn deref(&self) -> &Self::Target {
        &self.kind
    }
}

impl From<Type> for Term<Type> {
    fn from(t: Type) -> Self {
        TYPE.with(|a| Term::new(a, t))
    }
}

impl From<TypeKind> for Type {
    fn from(kind: TypeKind) -> Self {
        Self {
            kind,
            attrs: TypeAttrs::default(),
        }
    }
}

impl From<TypeKind> for Term<Type> {
    fn from(t: TypeKind) -> Self {
        TYPE.with(|a| Term::new(a, t.into()))
    }
}

crate::impl_term_mut!(TYPE for Type);

impl TermMut<Type> for Term<Type> {
    fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<Type>),
    {
        TYPE.with(|a| self.update_with(a, |_, v| f(v)))
    }
}

impl From<FloatFormat> for FloatKind {
    fn from(f: FloatFormat) -> Self {
        Self(FFMT.with(|a| Term::new(a, f)))
    }
}

impl Type {
    pub fn kind(&self) -> &TypeKind {
        &self.kind
    }

    pub fn apply<E>(&self, e: E) -> Term<Expr>
    where
        E: Into<Term<Expr>>,
    {
        let e = e.into();

        match &**self {
            TypeKind::Bool => Expr::cast_bool(e),
            TypeKind::Signed(bits) => Expr::cast_signed(e, *bits),
            TypeKind::Unsigned(bits) => Expr::cast_unsigned(e, *bits),
            TypeKind::Pointer(_, bits) => {
                Expr::Cast(Expr::cast_unsigned(e, *bits), self.clone().into()).into()
            }
            _ => Expr::Cast(e, self.clone().into()).into(),
        }
    }

    pub fn is_void(&self) -> bool {
        matches!(self.kind(), TypeKind::Void)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self.kind(), TypeKind::Bool)
    }

    pub fn is_wchar(&self) -> bool {
        self.attrs.contains(TypeAttrs::WCHAR)
    }

    pub fn is_unsigned_char_n(&self, n: u32) -> bool {
        self.is_unsigned_with(n) && self.attrs.contains(TypeAttrs::CHAR)
    }

    pub fn is_char_n(&self, n: u32) -> bool {
        self.is_signed_with(n) && self.attrs.contains(TypeAttrs::CHAR)
    }

    pub fn is_char(&self) -> bool {
        self.is_char_n(8)
    }

    pub fn is_char16(&self) -> bool {
        self.is_char_n(16)
    }

    pub fn is_char32(&self) -> bool {
        self.is_char_n(32)
    }

    pub fn is_unsigned_char(&self) -> bool {
        self.is_unsigned_char_n(8)
    }

    pub fn is_unsigned_char16(&self) -> bool {
        self.is_unsigned_char_n(16)
    }

    pub fn is_unsigned_char32(&self) -> bool {
        self.is_unsigned_char_n(32)
    }

    pub fn is_signed(&self) -> bool {
        matches!(self.kind(), TypeKind::Signed(_))
    }

    pub fn is_signed_with(&self, bits: u32) -> bool {
        matches!(self.kind(), TypeKind::Signed(b) if *b == bits)
    }

    pub fn is_unsigned(&self) -> bool {
        matches!(self.kind(), TypeKind::Unsigned(_))
    }

    pub fn is_unsigned_with(&self, bits: u32) -> bool {
        matches!(self.kind(), TypeKind::Unsigned(b) if *b == bits)
    }

    pub fn is_float(&self) -> bool {
        matches!(self.kind(), TypeKind::Float(_))
    }

    pub fn is_float_with(&self, bits: u32) -> bool {
        matches!(self.kind(), TypeKind::Float(f) if f.nbits() == bits)
    }

    pub fn is_float_kind<F>(&self, fmt: F) -> bool
    where
        F: Borrow<FloatFormat>,
    {
        matches!(self.kind(), TypeKind::Float(f) if &**f == fmt.borrow())
    }

    pub fn is_pointer(&self) -> bool {
        matches!(
            self.kind(),
            TypeKind::Pointer(_, _) | TypeKind::ShiftedPointer(_, _, _)
        )
    }

    pub fn is_pointer_with(&self, bits: u32) -> bool {
        matches!(self.kind(), TypeKind::Pointer(_, b) | TypeKind::ShiftedPointer(_, _, b) if *b == bits)
    }

    pub fn is_pointer_kind<F>(&self, f: F) -> bool
    where
        F: Fn(&Self) -> bool,
    {
        matches!(self.kind(), TypeKind::Pointer(t, _) if f(t))
    }

    pub fn is_function(&self) -> bool {
        matches!(self.kind(), TypeKind::Function(_, _))
    }

    pub fn is_variadic_function(&self) -> bool {
        self.is_function() && self.attrs.contains(TypeAttrs::VARIADIC)
    }

    pub fn is_function_kind<F>(&self, f: F) -> bool
    where
        F: Fn(&Self, &[FunctionArg]) -> bool,
    {
        matches!(self.kind(), TypeKind::Function(rt, ats) if f(rt, ats))
    }

    pub fn is_function_pointer(&self) -> bool {
        self.is_pointer_kind(Type::is_function)
    }

    pub fn is_array(&self) -> bool {
        matches!(self.kind(), TypeKind::Array(_, _))
    }

    // (type, count, var-sized)
    pub fn is_array_kind<F>(&self, f: F) -> bool
    where
        F: Fn(&Self, u32, bool) -> bool,
    {
        matches!(
            self.kind(),
            TypeKind::Array(typ, cnt) if f(typ, *cnt, self.attrs.contains(TypeAttrs::VARSIZED))
        )
    }

    pub fn is_struct(&self) -> bool {
        matches!(self.kind(), TypeKind::Struct(_, _, _))
    }

    pub fn is_struct_kind<F>(&self, f: F) -> bool
    where
        F: Fn(Ustr, &[StructField]) -> bool,
    {
        matches!(self.kind(), TypeKind::Struct(nm, flds, _) if f(*nm, flds))
    }

    pub fn is_enum(&self) -> bool {
        matches!(self.kind(), TypeKind::Enum(_, _, _))
    }

    pub fn is_enum_kind<F>(&self, f: F) -> bool
    where
        F: Fn(Ustr, &[EnumVariant]) -> bool,
    {
        matches!(self.kind(), TypeKind::Enum(nm, vars, _) if f(*nm, vars))
    }

    pub fn is_union(&self) -> bool {
        matches!(self.kind(), TypeKind::Union(_, _, _))
    }

    pub fn is_union_kind<F>(&self, f: F) -> bool
    where
        F: Fn(Ustr, &[UnionVariant]) -> bool,
    {
        matches!(self.kind(), TypeKind::Union(nm, vars, _) if f(*nm, vars))
    }

    pub fn name(&self) -> Option<Ustr> {
        if let TypeKind::Named(nm, _) = &**self {
            Some(*nm)
        } else {
            None
        }
    }

    pub fn is_named(&self) -> bool {
        matches!(self.kind(), TypeKind::Named(_, _))
    }

    pub fn is_named_with<F>(&self, f: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        matches!(self.kind(), TypeKind::Named(nm, _) if f(nm))
    }

    pub fn const_(&self) -> Term<Self> {
        Self {
            kind: self.kind.clone(),
            attrs: self.attrs | TypeAttrs::CONST,
        }
        .into()
    }

    pub fn is_const(&self) -> bool {
        self.attrs.contains(TypeAttrs::CONST)
    }

    pub fn is_const_pointee(&self) -> bool {
        matches!(self.kind(), TypeKind::Pointer(t, _) if t.is_const())
    }

    pub fn volatile(&self) -> Term<Self> {
        Self {
            kind: self.kind.clone(),
            attrs: self.attrs | TypeAttrs::VOLATILE,
        }
        .into()
    }

    pub fn is_volatile(&self) -> bool {
        self.attrs.contains(TypeAttrs::VOLATILE)
    }

    pub fn bool() -> Term<Self> {
        TypeKind::Bool.into()
    }

    pub fn void() -> Term<Self> {
        TypeKind::Void.into()
    }

    pub fn char() -> Term<Self> {
        Self {
            kind: TypeKind::Signed(8),
            attrs: TypeAttrs::CHAR,
        }
        .into()
    }

    pub fn char16() -> Term<Self> {
        Self {
            kind: TypeKind::Signed(16),
            attrs: TypeAttrs::CHAR,
        }
        .into()
    }

    pub fn char32() -> Term<Self> {
        Self {
            kind: TypeKind::Signed(32),
            attrs: TypeAttrs::CHAR,
        }
        .into()
    }

    pub fn unsigned_char() -> Term<Self> {
        Self {
            kind: TypeKind::Unsigned(8),
            attrs: TypeAttrs::CHAR,
        }
        .into()
    }

    pub fn wchar(bits: u32, signed: bool) -> Term<Self> {
        Self {
            kind: if signed {
                TypeKind::Signed(bits)
            } else {
                TypeKind::Unsigned(bits)
            },
            attrs: TypeAttrs::WCHAR,
        }
        .into()
    }

    pub fn ascii_string(bits: u32) -> Term<Self> {
        Self::pointer(Self::char().const_(), bits)
    }

    pub fn is_ascii_string(&self) -> bool {
        self.is_pointer_kind(|t| t.is_char())
    }

    pub fn c_string(bits: u32) -> Term<Self> {
        Self::pointer(Self::char().const_(), bits)
    }

    pub fn is_c_string(&self) -> bool {
        self.is_pointer_kind(|t| t.is_char())
    }

    pub fn is_wide_string(&self) -> bool {
        self.is_pointer_kind(|t| t.is_wchar())
    }

    pub fn signed(bits: u32) -> Term<Self> {
        TypeKind::Signed(bits).into()
    }

    pub fn unsigned(bits: u32) -> Term<Self> {
        TypeKind::Unsigned(bits).into()
    }

    pub fn float<K>(fmt: K) -> Term<Self>
    where
        K: Into<FloatKind>,
    {
        TypeKind::Float(fmt.into()).into()
    }

    pub fn pointer<T>(t: T, bits: u32) -> Term<Self>
    where
        T: Into<Term<Self>>,
    {
        TypeKind::Pointer(t.into(), bits).into()
    }

    pub fn shifted_pointer<T>(t: T, offset: i64, bits: u32) -> Term<Self>
    where
        T: Into<Term<Self>>,
    {
        if offset == 0 {
            TypeKind::Pointer(t.into(), bits).into()
        } else {
            TypeKind::ShiftedPointer(t.into(), offset, bits).into()
        }
    }

    pub fn npointer<const N: usize>(t: impl Into<Term<Self>>, bits: u32) -> Term<Self> {
        let mut t = t.into();
        let mut n = N;

        while n > 0 {
            t = Type::pointer(t, bits);
            n -= 1;
        }

        t
    }

    pub fn array<T>(t: T, count: u32) -> Term<Self>
    where
        T: Into<Term<Self>>,
    {
        TypeKind::Array(t.into(), count).into()
    }

    pub fn incomplete_array<T>(t: T) -> Term<Self>
    where
        T: Into<Term<Self>>,
    {
        Self {
            kind: TypeKind::Array(t.into(), 0),
            attrs: TypeAttrs::INCOMPLETE,
        }
        .into()
    }

    pub fn is_incomplete_array(&self) -> bool {
        self.is_array() && self.attrs.contains(TypeAttrs::INCOMPLETE)
    }

    pub fn variable_sized_array<T>(t: T) -> Term<Self>
    where
        T: Into<Term<Self>>,
    {
        Self {
            kind: TypeKind::Array(t.into(), 0),
            attrs: TypeAttrs::VARSIZED,
        }
        .into()
    }

    pub fn has_flexible_array_member(&self) -> bool {
        self.struct_fields()
            .and_then(|fields| {
                if fields.len() > 1 {
                    Some(fields.last()?.type_().is_incomplete_array())
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }

    pub fn is_variable_sized_array(&self) -> bool {
        self.is_array() && self.attrs.contains(TypeAttrs::VARSIZED)
    }

    pub fn function<R, I, A>(ret: R, args: I) -> Term<Self>
    where
        R: Into<Term<Self>>,
        I: ExactSizeIterator<Item = A>,
        A: Into<FunctionArg>,
    {
        Self::function_with(ret, args, false)
    }

    pub fn function_with<R, I, A>(ret: R, args: I, variadic: bool) -> Term<Self>
    where
        R: Into<Term<Self>>,
        I: ExactSizeIterator<Item = A>,
        A: Into<FunctionArg>,
    {
        Self {
            kind: TypeKind::Function(ret.into(), args.map(|arg| arg.into()).collect()),
            attrs: if variadic {
                TypeAttrs::VARIADIC
            } else {
                TypeAttrs::default()
            },
        }
        .into()
    }

    pub fn variadic_function<R, I, A>(ret: R, args: I) -> Term<Self>
    where
        R: Into<Term<Self>>,
        I: ExactSizeIterator<Item = A>,
        A: Into<FunctionArg>,
    {
        Self::function_with(ret, args, true)
    }

    pub fn variadic(&self) -> Option<Term<Self>> {
        if !self.is_function() {
            return None;
        }

        Some(
            Self {
                kind: self.kind.clone(),
                attrs: self.attrs | TypeAttrs::VARIADIC,
            }
            .into(),
        )
    }

    pub fn struct_<N, I, FN, T>(name: N, fields: I, bytes: u32) -> Term<Self>
    where
        N: Into<Ustr>,
        I: ExactSizeIterator<Item = (FN, usize, T)>,
        FN: Into<Ustr>,
        T: Into<Term<Self>>,
    {
        TypeKind::Struct(
            name.into(),
            fields
                .into_iter()
                .map(|(name, offset, t)| StructField::new(name, offset, t))
                .collect(),
            bytes * 8,
        )
        .into()
    }

    pub fn struct_from_fields<N, I>(name: N, fields: I, bytes: u32) -> Term<Self>
    where
        N: Into<Ustr>,
        I: ExactSizeIterator<Item = StructField>,
    {
        TypeKind::Struct(name.into(), fields.into_iter().collect(), bytes * 8).into()
    }

    pub fn union_<N, I, FN, T>(name: N, variants: I, bytes: u32) -> Term<Self>
    where
        N: Into<Ustr>,
        I: ExactSizeIterator<Item = (FN, T)>,
        FN: Into<Ustr>,
        T: Into<Term<Self>>,
    {
        TypeKind::Union(
            name.into(),
            variants
                .into_iter()
                .map(|(name, t)| UnionVariant {
                    name: name.into(),
                    typ: t.into(),
                })
                .collect(),
            bytes * 8,
        )
        .into()
    }

    pub fn enum_<N, I, V>(name: N, variants: I, bytes: u32) -> Term<Self>
    where
        N: Into<Ustr>,
        I: ExactSizeIterator<Item = V>,
        V: Into<EnumVariant>,
    {
        TypeKind::Enum(name.into(), variants.map(|v| v.into()).collect(), bytes * 8).into()
    }

    pub fn named_32<N>(name: N, bytes: u32) -> Term<Self>
    where
        N: Into<Ustr>,
    {
        Type {
            kind: TypeKind::Named(name.into(), bytes * 8),
            attrs: TypeAttrs::TYPE32,
        }
        .into()
    }

    pub fn named_64<N>(name: N, bytes: u32) -> Term<Self>
    where
        N: Into<Ustr>,
    {
        Type {
            kind: TypeKind::Named(name.into(), bytes * 8),
            attrs: TypeAttrs::TYPE64,
        }
        .into()
    }

    pub fn named_bits(&self) -> Option<u32> {
        if self.attrs.contains(TypeAttrs::TYPE32) {
            Some(32)
        } else if self.attrs.contains(TypeAttrs::TYPE64) {
            Some(64)
        } else {
            None
        }
    }

    pub fn value_of_variant<N>(&self, name: N) -> Option<(&BitVec, &BitVec)>
    where
        N: Into<Ustr>,
    {
        match self.kind() {
            TypeKind::Enum(_, variants, _) => {
                let name = name.into();
                variants.iter().find_map(|variant| {
                    if variant.name == name {
                        Some((&variant.signed, &variant.unsigned))
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    pub fn offset_of_field<N>(&self, name: N) -> Option<usize>
    where
        N: Into<Ustr>,
    {
        match self.kind() {
            TypeKind::Struct(_, fields, _) => {
                let name = name.into();
                fields.iter().find_map(|field| {
                    if field.name() == name {
                        Some(field.offset())
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    pub fn type_of_field<N>(&self, name: N) -> Option<Term<Self>>
    where
        N: Into<Ustr>,
    {
        self.offset_of_field(name)
            .and_then(|offset| self.type_at_offset(offset))
    }

    pub fn type_of_variant<N>(&self, name: N) -> Option<Term<Self>>
    where
        N: Into<Ustr>,
    {
        if let TypeKind::Union(_, variants, _) = self.kind() {
            let name = name.into();
            variants.iter().find_map(|variant| {
                if variant.name() == name {
                    Some(variant.type_().clone())
                } else {
                    None
                }
            })
        } else {
            None
        }
    }

    pub fn apply_shift(&self, offset: i64) -> Option<Term<Self>> {
        if offset > 0 {
            self.type_at_offset(offset as usize)
        } else {
            match self.kind() {
                TypeKind::Pointer(typ, sz) => Some(Type::shifted_pointer(typ.clone(), offset, *sz)),
                TypeKind::ShiftedPointer(typ, off, sz) => {
                    let noff = offset - *off;
                    Some(Type::shifted_pointer(typ.clone(), noff, *sz))
                }
                _ => None,
            }
        }
    }

    pub fn field_and_type_at_offset(&self, offset: usize) -> Option<(Term<Self>, Option<Ustr>)> {
        match self.kind() {
            // TODO: how should we handle bit field resolution? A tricky case:
            //
            // ```c
            // struct t {
            //   char f0 : 7;
            //   short f1 : 2;
            // }
            // ```
            //
            // Where we have the following layout:
            //
            // offset: 0
            //   mask: 11111110 00000000
            // offset: 0
            //   mask: 00000001 10000000
            //
            // Here both f0 and f1 share the same base offset; for now we return f0;
            // if a user of this API needs to resolve the bit field, they will need
            // to use custom logic for now.
            //
            TypeKind::Struct(_, fields, _) => fields.iter().find_map(|field| {
                if field.offset() == offset {
                    Some((field.typ.clone(), Some(field.name)))
                } else if offset > field.offset() && (offset - field.offset()) < field.typ.nbytes()
                {
                    field.typ.field_and_type_at_offset(offset - field.offset())
                } else {
                    None
                }
            }),
            TypeKind::Array(typ, len) => {
                let tsz = typ.nbits() as usize / 8;
                if offset % tsz != 0 || offset > tsz * (*len as usize - 1) {
                    None
                } else {
                    Some((typ.clone(), None))
                }
            }
            TypeKind::Pointer(typ, sz) if offset > 0 => {
                Some((Type::shifted_pointer(typ.clone(), offset as i64, *sz), None))
            }
            TypeKind::ShiftedPointer(typ, off, sz) => {
                let offset = offset as i64 - off;
                Some((Type::shifted_pointer(typ.clone(), offset, *sz), None))
            }
            _ if offset == 0 => Some((self.clone().into(), None)),
            _ => None,
        }
    }

    pub fn type_at_offset(&self, offset: usize) -> Option<Term<Self>> {
        match self.kind() {
            TypeKind::Struct(_, fields, _) => fields.iter().find_map(|field| {
                if field.offset() == offset {
                    Some(field.typ.clone())
                } else if offset > field.offset() && (offset - field.offset()) < field.typ.nbytes()
                {
                    field.typ.type_at_offset(offset - field.offset())
                } else {
                    None
                }
            }),
            TypeKind::Array(typ, len) => {
                let tsz = typ.nbits() as usize / 8;
                if offset % tsz != 0 || offset > tsz * (*len as usize - 1) {
                    None
                } else {
                    Some(typ.clone())
                }
            }
            TypeKind::Pointer(typ, sz) if offset > 0 => {
                Some(Type::shifted_pointer(typ.clone(), offset as i64, *sz))
            }
            TypeKind::ShiftedPointer(typ, off, sz) => {
                let offset = offset as i64 - off;
                Some(Type::shifted_pointer(typ.clone(), offset, *sz))
            }
            _ if offset == 0 => Some(self.clone().into()),
            _ => None,
        }
    }

    // TODO: add resolve with for bit size
    pub fn resolve(&self, typedb: &TypeDB) -> Term<Self> {
        let mut t = Term::from(self.to_owned());
        let mut seen = AHashSet::new();

        loop {
            let TypeKind::Named(name, _sz) = t.kind() else {
                return t;
            };

            if !seen.insert(t.clone()) {
                // recursive type; return current
                return t;
            }

            let Some(nt) = typedb.get_type(&**name) else {
                // type not found in the database; return self
                return t;
            };

            let Some(bits) = t.named_bits() else {
                // if we don't have a bit size, return the type as is
                return t;
            };

            let tt = match nt {
                TypeInfo::Struct(ref s) => {
                    if bits == 32 {
                        Some(s.to_32())
                    } else if bits == 64 {
                        Some(s.to_64())
                    } else {
                        // probably should never happen
                        None
                    }
                }

                TypeInfo::Union(ref u) => {
                    if bits == 32 {
                        Some(u.to_32())
                    } else if bits == 64 {
                        Some(u.to_64())
                    } else {
                        // probably should never happen
                        None
                    }
                }

                // NOTE: Might result in a unwanted behaviour if number
                // of enum fields is different between 32/64 bits
                TypeInfo::Enum(ref n) => {
                    if bits == 32 {
                        Some(n.to_32())
                    } else if bits == 64 {
                        Some(n.to_64())
                    } else {
                        // probably should never happen
                        None
                    }
                }

                TypeInfo::TypeDef(ref td) => {
                    if bits == 32 {
                        t = td.to_32();
                        continue;
                    } else if bits == 64 {
                        t = td.to_64();
                        continue;
                    } else {
                        None
                    }
                }
                _ => None,
            };

            return tt.unwrap_or(t);
        }
    }

    pub fn pointee(&self) -> Option<&Term<Self>> {
        if let TypeKind::Pointer(typ, _) | TypeKind::ShiftedPointer(typ, 0, _) = self.kind() {
            Some(typ)
        } else {
            None
        }
    }

    pub fn struct_fields(&self) -> Option<&[StructField]> {
        if let TypeKind::Struct(_, fields, _) = self.kind() {
            Some(fields)
        } else {
            None
        }
    }

    pub fn struct_as_bits(&self) -> Option<&Term<Type>> {
        let TypeKind::Struct(_, fields, sz) = self.kind() else {
            return None;
        };

        let field0 = fields.first()?;
        let type_ = field0.type_();

        if field0.is_bit_field() && field0.offset() == 0 && type_.nbits() == *sz {
            Some(type_)
        } else {
            None
        }
    }

    pub fn enum_variants(&self) -> Option<&[EnumVariant]> {
        if let TypeKind::Enum(_, variants, _) = self.kind() {
            Some(variants)
        } else {
            None
        }
    }

    pub fn union_variants(&self) -> Option<&[UnionVariant]> {
        if let TypeKind::Union(_, variants, _) = self.kind() {
            Some(variants)
        } else {
            None
        }
    }

    pub fn function_args(&self) -> Option<&[FunctionArg]> {
        if let TypeKind::Function(_, args) = self.kind() {
            Some(args)
        } else {
            None
        }
    }

    pub fn function_return(&self) -> Option<&Term<Self>> {
        if let TypeKind::Function(rtyp, _) = self.kind() {
            Some(rtyp)
        } else {
            None
        }
    }

    pub fn nbytes(&self) -> usize {
        self.nbits() as usize / 8
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: handle const/volatile modifiers
        match self.kind() {
            TypeKind::Void => write!(f, "void"),
            TypeKind::Bool => write!(f, "bool"),
            TypeKind::Float(format) => write!(f, "float{}", format.nbits()),
            TypeKind::Signed(_) if self.is_char() => write!(f, "char"),
            TypeKind::Signed(bits) => write!(f, "int{}", bits),
            TypeKind::Unsigned(_) if self.is_unsigned_char() => write!(f, "uchar"),
            TypeKind::Unsigned(bits) => write!(f, "uint{}", bits),
            TypeKind::Pointer(typ, _) => write!(f, "ptr<{}>", typ),
            TypeKind::ShiftedPointer(typ, off, _) => write!(f, "ptr<{}>@{}", typ, off),
            TypeKind::Function(typ, args) => {
                write!(f, "fn(")?;
                if !args.is_empty() {
                    write!(f, "{}", args[0])?;
                    for arg in &args[1..] {
                        write!(f, ", {}", arg)?;
                    }

                    if typ.attrs.contains(TypeAttrs::VARIADIC) {
                        f.write_str(", ...")?;
                    }
                } else if typ.attrs.contains(TypeAttrs::VARIADIC) {
                    f.write_str("...")?;
                }
                write!(f, ") -> {}", typ)
            }
            TypeKind::Array(typ, count) => write!(f, "array<{}, {}>", typ, count),
            TypeKind::Struct(name, _, _) => write!(f, "struct<{}>", name),
            TypeKind::Union(name, _, _) => write!(f, "union<{}>", name),
            TypeKind::Enum(name, _, _) => write!(f, "enum<{}>", name),
            TypeKind::Named(name, _) => write!(f, "{}", name),
        }
    }
}

impl BitSize for Type {
    fn nbits(&self) -> u32 {
        match self.kind() {
            TypeKind::Void | TypeKind::Function(_, _) => 0, // do not have a size
            TypeKind::Bool /* | TypeKind::Char | TypeKind::UnsignedChar */ => 8,
            TypeKind::Float(format) => format.nbits(),
            TypeKind::Signed(bits)
            | TypeKind::Unsigned(bits)
            | TypeKind::Pointer(_, bits)
            | TypeKind::ShiftedPointer(_, _, bits)
            | TypeKind::Struct(_, _, bits)
            | TypeKind::Union(_, _, bits) => *bits,
            TypeKind::Enum(_, _, bits) => *bits,
            TypeKind::Array(typ, count) => typ.nbits() * count,
            TypeKind::Named(_, bits) => *bits,
        }
    }
}

pub struct TypeDisplay<'a> {
    depth: usize,
    indent: usize,
    t: &'a Term<Type>,
    typedb: &'a TypeDB,
}

impl<'a> TypeDisplay<'a> {
    const INDENT_STEP: usize = 2;

    pub fn new(t: &'a Term<Type>, typedb: &'a TypeDB) -> Self {
        Self::new_with(t, typedb, 0)
    }

    pub fn new_with(t: &'a Term<Type>, typedb: &'a TypeDB, depth: usize) -> Self {
        Self {
            depth,
            indent: 0,
            t,
            typedb,
        }
    }

    #[inline]
    fn next_pad(&self) -> Self {
        TypeDisplay {
            t: self.t,
            typedb: self.typedb,
            indent: self.indent + Self::INDENT_STEP,
            depth: self.depth,
        }
    }

    #[inline]
    fn with_type<'b>(&'b self, t: &'b Term<Type>) -> TypeDisplay<'b> {
        TypeDisplay {
            t,
            typedb: self.typedb,
            indent: self.indent + Self::INDENT_STEP,
            depth: self.depth - 1,
        }
    }

    #[inline]
    fn pad(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..self.indent {
            f.fill().fmt(f)?;
        }
        Ok(())
    }
}

impl<'a> Display for TypeDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // we use regular display for this first:
        self.t.fmt(f)?;
        writeln!(f)?;

        self.pad(f)?;
        writeln!(f, "- size: {}", self.t.nbytes())?;

        if !self.t.attrs.is_empty() {
            self.pad(f)?;
            writeln!(f, "- attrs: {}", self.t.attrs)?;
        }

        if self.depth == 0 {
            return Ok(());
        }

        // if we have depth, then unpack
        match self.t.kind() {
            TypeKind::Struct(_, fields, _) => {
                self.pad(f)?;
                writeln!(f, "- fields:")?;
                let slf = self.next_pad();
                for field in fields {
                    slf.pad(f)?;
                    write!(
                        f,
                        "- {:03} {}: {}",
                        field.offset(),
                        if field.name().is_empty() {
                            "_"
                        } else {
                            field.name().as_str()
                        },
                        slf.with_type(field.type_()),
                    )?;
                }
            }
            TypeKind::Union(_, fields, _) => {
                self.pad(f)?;
                writeln!(f, "- variants:")?;
                let slf = self.next_pad();
                for field in fields {
                    slf.pad(f)?;
                    write!(
                        f,
                        "- {}: {}",
                        if field.name().is_empty() {
                            "_"
                        } else {
                            field.name().as_str()
                        },
                        slf.with_type(field.type_()),
                    )?;
                }
            }
            TypeKind::Enum(_, variants, _) => {
                self.pad(f)?;
                writeln!(f, "- variants:")?;
                let slf = self.next_pad();
                for variant in variants.iter() {
                    slf.pad(f)?;
                    writeln!(
                        f,
                        "- {} ({} / {})",
                        variant.name(),
                        variant.unsigned_value(),
                        variant.signed_value()
                    )?;
                }
            }
            TypeKind::Named(_, _) => {
                let t = self.t.resolve(self.typedb);
                self.pad(f)?;
                write!(f, "- typedef: {}", self.with_type(&t),)?;
            }
            _ => {}
        }
        Ok(())
    }
}
