use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;

use bitflags::bitflags;
use itertools::Itertools;
use thiserror::Error;
use ustr::UstrMap;

use crate::decompiler::error::DecompilerError;
pub(crate) use crate::decompiler::ffi::DataType;
use crate::decompiler::ffi::{self, DataMetaType, DataSubMetaType, FunctionType, GhidraDecompiler};
pub use crate::decompiler::ffi::{
    DataMetaType as DataTypeKind, DataSubMetaType as DataTypeSubKind, DataTypeField, SpaceKind,
    VarInfo,
};
use crate::decompiler::symbols::DecompilerSymbolResolver;
use crate::prelude::*;

pub struct DecompilerTypeDB<'a, 'b> {
    pub(crate) ghidra: &'a mut GhidraDecompiler<'b>,
    pub(crate) typedb: &'b TypeDB,
}

impl<'a, 'b> DecompilerTypeDB<'a, 'b> {
    pub(crate) fn get_type_checked(
        &self,
        name: impl AsRef<str>,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = self.get_type_aux(name)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected primitive type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn get_type_aux(
        &self,
        name: impl AsRef<str>,
    ) -> Result<*mut DataType, DecompilerError> {
        cxx::let_cxx_string!(cxx_name = name.as_ref());

        self.ghidra
            .get_type(&cxx_name)
            .map_err(|e| DecompilerError::TypeBuilder(e))
    }

    pub(crate) fn get_type_aux_or_pending(
        &self,
        name: Ustr,
        pending: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        if let Some(t) = pending.get(&name) {
            Ok(*t)
        } else {
            self.get_type_aux(name)
        }
    }

    pub(crate) fn build_array_type_checked(
        &mut self,
        t: *mut DataType,
        n: usize,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = self.build_array_type_aux(t, n)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected array type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn build_array_type_aux(
        &mut self,
        t: *mut DataType,
        n: usize,
    ) -> Result<*mut DataType, DecompilerError> {
        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .build_array_type(t, n)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }
    }

    pub(crate) fn build_pointer_type_checked(
        &mut self,
        t: *mut DataType,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = self.build_pointer_type_aux(t)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected pointer type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn build_pointer_type_aux(
        &mut self,
        t: *mut DataType,
    ) -> Result<*mut DataType, DecompilerError> {
        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .build_pointer_type(t)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }
    }

    pub(crate) fn build_struct_type_aux(
        &mut self,
        name: Ustr,
        fields: &[StructField],
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        cxx::let_cxx_string!(sname = name.as_ref());

        let t = unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .begin_struct_type(&sname)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }?;

        if t.is_null() {
            return Err(DecompilerError::Ffi(
                "invariant violation: expected struct type",
            ));
        }

        if pending.insert(name, t).is_some() {
            // duplicate!
            return Err(DecompilerError::Ffi(
                "invariant violation: recursive struct type",
            ));
        }

        let mut sfields = Vec::with_capacity(fields.len());
        let mut fiter = fields.into_iter().peekable();

        while let Some(field) = fiter.next() {
            if field.is_bit_field() {
                // NOTE: Ghidra's decompiler does not support bitfields, so we convert
                // ranges that would otherwise be bitfields into named ranges.
                let type_ = field.type_();
                let size = type_.nbytes();

                let offset = field.offset();
                let ftype =
                    self.build_type_aux_with(field.type_(), pending, incomplete_typedefs)?;

                let noffset = offset + size;

                // NOTE: we now drop neighbouring fields that are contained in the
                // same bitfield.
                let _ = (&mut fiter).peeking_take_while(|f| f.offset() < noffset);

                sfields.push(ffi::StructField {
                    offset,
                    type_: ftype,
                    name: Ustr::from(&compact_str::format_compact!(
                        "__bitfield_{offset}_{size}__"
                    ))
                    .as_str(),
                });

                continue;
            }

            sfields.push(ffi::StructField {
                offset: field.offset(),
                type_: self.build_type_aux_with(field.type_(), pending, incomplete_typedefs)?,
                name: field.name().as_str(),
            });
        }

        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .end_struct_type(t, &sfields)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }
    }

    pub(crate) fn build_struct_type_checked(
        &mut self,
        name: Ustr,
        fields: &[StructField],
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = self.build_struct_type_aux(name, fields, pending, incomplete_typedefs)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected struct type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn build_union_type_aux(
        &mut self,
        name: Ustr,
        variants: &[UnionVariant],
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        cxx::let_cxx_string!(sname = name.as_ref());

        let t = unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .begin_union_type(&sname)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }?;

        if t.is_null() {
            return Err(DecompilerError::Ffi(
                "invariant violation: expected union type",
            ));
        }

        if pending.insert(name, t).is_some() {
            // duplicate!
            return Err(DecompilerError::Ffi(
                "invariant violation: recursive union type",
            ));
        }

        let variants = variants
            .iter()
            .map(|variant| {
                Ok(ffi::UnionVariant {
                    type_: self.build_type_aux_with(
                        variant.type_(),
                        pending,
                        incomplete_typedefs,
                    )?,
                    name: variant.name().as_str(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .end_union_type(t, &variants)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }
    }

    pub(crate) fn build_union_type_checked(
        &mut self,
        name: Ustr,
        variants: &[UnionVariant],
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = self.build_union_type_aux(name, variants, pending, incomplete_typedefs)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected union type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn build_function_type_aux(
        &mut self,
        output: &Term<Type>,
        inputs: &[FunctionArg],
        variadic: bool,
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let input_types = inputs
            .iter()
            .map(|input| self.build_type_aux_with(input.type_(), pending, incomplete_typedefs))
            .collect::<Result<Vec<_>, _>>()?;

        let input_names = inputs
            .iter()
            .map(|input| input.name().map(|s| s.as_str()).unwrap_or(""))
            .collect::<Vec<_>>();

        let output = self.build_type_aux_with(output, pending, incomplete_typedefs)?;

        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .build_function_type(output, &input_names, &input_types, variadic)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }
    }

    pub(crate) fn build_function_type_checked(
        &mut self,
        output: &Term<Type>,
        inputs: &[FunctionArg],
        variadic: bool,
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let t =
            self.build_function_type_aux(output, inputs, variadic, pending, incomplete_typedefs)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected function type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn build_typedef_aux(
        &mut self,
        name: impl AsRef<str>,
        t: &Term<Type>,
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = self.build_type_checked_with(t, pending, incomplete_typedefs)?;

        let r = self.get_type_aux(name.as_ref())?;
        if !r.is_null() {
            return Ok(r);
        }

        cxx::let_cxx_string!(name = name.as_ref());

        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .build_typedef(&name, t)
                .map_err(|e| DecompilerError::TypeBuilder(e))
        }
    }

    pub(crate) fn build_typedef_checked(
        &mut self,
        name: impl AsRef<str>,
        t: &Term<Type>,
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let name = name.as_ref();
        let t = self.build_typedef_aux(name, t, pending, incomplete_typedefs)?;
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected typedef type",
            ))
        } else {
            if DataTypeRef::new(t)
                .map(|t| t.is_incomplete())
                .unwrap_or(false)
            {
                incomplete_typedefs.insert(name.into(), t);
            }

            Ok(t)
        }
    }

    pub(crate) fn build_type_aux_with(
        &mut self,
        t: &Term<Type>,
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        match t.kind() {
            TypeKind::Void => self.get_type_checked("void"),
            TypeKind::Bool => self.get_type_checked("bool"),
            TypeKind::Signed(_) if t.is_char() => self.get_type_checked("char"),
            TypeKind::Unsigned(_) if t.is_unsigned_char() => self.get_type_checked("unsigned char"),
            TypeKind::Signed(bits) => {
                self.get_type_checked(compact_str::format_compact!("int{bits}_t"))
            }
            TypeKind::Unsigned(bits) => {
                self.get_type_checked(compact_str::format_compact!("uint{bits}_t"))
            }
            TypeKind::Enum(_, _, bits) => {
                self.get_type_checked(compact_str::format_compact!("uint{bits}_t"))
            }
            TypeKind::Function(rt, args) => {
                let variadic = t.is_variadic_function();
                self.build_function_type_checked(rt, args, variadic, pending, incomplete_typedefs)
            }
            TypeKind::Array(t, n) => {
                let t = self.build_type_checked_with(t, pending, incomplete_typedefs)?;
                self.build_array_type_checked(t, *n as _)
            }
            TypeKind::Pointer(t, _) => {
                let t = self.build_type_checked_with(t, pending, incomplete_typedefs)?;
                self.build_pointer_type_checked(t)
            }
            TypeKind::Struct(name, fields, _) => {
                let gt = self.get_type_aux_or_pending(*name, pending)?;
                if gt.is_null() {
                    if let Some(t) = t.struct_as_bits() {
                        self.build_type_checked_with(t, pending, incomplete_typedefs)
                    } else {
                        self.build_struct_type_checked(*name, fields, pending, incomplete_typedefs)
                    }
                } else {
                    Ok(gt)
                }
            }
            TypeKind::Union(name, variants, _) => {
                let t = self.get_type_aux_or_pending(*name, pending)?;
                if t.is_null() {
                    self.build_union_type_checked(*name, variants, pending, incomplete_typedefs)
                } else {
                    Ok(t)
                }
            }
            TypeKind::Named(name, _) => {
                let tt = self.get_type_aux_or_pending(*name, pending)?;
                if tt.is_null() {
                    let resolved = t.resolve(self.typedb);
                    if let TypeKind::Named(_, bits) = resolved.kind() {
                        // NOTE: in this case, we cannot resolve the typedef to
                        // a concrete type. This is a bug in the provided type
                        // library, but if we attempt to use the resolved type,
                        // we will cause a loop in type resolution.
                        //
                        // To handle this case, we apply a simple rule: if we cannot
                        // resolve a type via a typedef, then we resolve it to void
                        // if it has 0 as a size, and a unsigned integer variant
                        // otherwise.
                        //

                        tracing::warn!("cannot resolve named type `{name}`; the type library is incomplete and should be updated");

                        let resolved = if *bits == 0 {
                            Type::void()
                        } else {
                            Type::unsigned(*bits)
                        };
                        self.build_typedef_checked(name, &resolved, pending, incomplete_typedefs)
                    } else {
                        self.build_typedef_checked(name, &resolved, pending, incomplete_typedefs)
                    }
                } else {
                    Ok(tt)
                }
            }
            _ => Err(DecompilerError::Ffi("unsupported type")),
        }
    }

    fn update_typedefs(&mut self, incomplete_typedefs: &mut UstrMap<*mut DataType>) {
        let mut to_remove = Vec::new();

        for (&nm, &typedef) in incomplete_typedefs.iter() {
            let Some(tdef) = DataTypeRef::new(typedef) else {
                continue;
            };

            let Some((name, t)) = tdef.name().zip(tdef.typedef()) else {
                continue;
            };

            if !tdef.is_incomplete() || t.is_incomplete() {
                // if the typedef is complete or the type is incomplete,
                // there is no point in rebuilding the typedef
                tracing::debug!("attempting to update complete typedef {name} or build it from an incomplete type");
                continue;
            }

            cxx::let_cxx_string!(name = name.as_ref());

            if unsafe { Pin::new_unchecked(&mut *self.ghidra).build_typedef_with(&name, t.t, true) }
                .is_ok()
            {
                to_remove.push(nm);
            }
        }

        for nm in to_remove {
            incomplete_typedefs.remove(&nm);
        }
    }

    pub(crate) fn build_type_checked_with(
        &mut self,
        t: &Term<Type>,
        pending: &mut UstrMap<*mut DataType>,
        incomplete_typedefs: &mut UstrMap<*mut DataType>,
    ) -> Result<*mut DataType, DecompilerError> {
        let t = match self.build_type_aux_with(t, pending, incomplete_typedefs) {
            Ok(t) => {
                self.update_typedefs(incomplete_typedefs);
                t
            }
            Err(e) => {
                self.purge_incomplete_types(pending);
                return Err(e);
            }
        };
        if t.is_null() {
            Err(DecompilerError::Ffi(
                "invariant violation: expected constructed type",
            ))
        } else {
            Ok(t)
        }
    }

    pub(crate) fn build_type_checked(
        &mut self,
        t: &Term<Type>,
    ) -> Result<*mut DataType, DecompilerError> {
        let mut pending = UstrMap::<*mut DataType>::default();
        let mut incomplete_typedefs = UstrMap::<*mut DataType>::default();
        self.build_type_checked_with(t, &mut pending, &mut incomplete_typedefs)
    }

    pub(crate) fn remove_type(&mut self, dt: *mut DataType) -> Result<(), DecompilerError> {
        if dt.is_null() {
            return Ok(());
        }

        unsafe {
            Pin::new_unchecked(&mut *self.ghidra)
                .remove_type(dt)
                .map_err(DecompilerError::RemoveType)
        }
    }

    fn purge_incomplete_types(&mut self, pending: &mut UstrMap<*mut DataType>) {
        for (name, dt) in pending.drain() {
            let Some(t) = DataTypeRef::new(dt) else {
                continue;
            };

            if t.is_incomplete() {
                tracing::warn!("removing incomplete type `{name}`; the type library is inconsistent and should be updated");
                // NOTE: we may want to handle this case, but it's unclear what to do--if we
                // bail here, then we will leave incomplete types in the database.
                self.remove_type(t.t).ok();
            }
        }
    }
}

pub struct DataTypeRef<'a> {
    t: *mut DataType,
    _marker: PhantomData<&'a DataType>,
}

#[derive(Debug, Error)]
pub enum DecompilerTypeError {
    #[error("unable to resolve array element count")]
    ElementCount,
    #[error("unable to resolve array element type")]
    ElementType,
    #[error("unable to resolve enum variants")]
    EnumVariants,
    #[error("unable to resolve function prototype")]
    FunctionProto,
    #[error("unable to determine correct type size; mismatch between decompiler and type library")]
    NamedSizeInconsistent,
    #[error("unable to resolve struct fields")]
    StructFields,
    #[error("unable to resolve pointee type")]
    PointeeType,
    #[error("unable to resolve union variants")]
    UnionVariants,
    #[error("unable to determine size of type")]
    Unsized,
    #[error("unable to resolve type; representation unsupported")]
    Unsupported,
}

bitflags! {
    #[derive(Debug, Copy, Clone)]
    pub struct DataTypeFlags: u32 {
        const CORETYPE = 1;  // this is a basic type which will never be redefined
        const CHARTYPE = 2;  // ascii character data
        const ENUMTYPE = 4;  // an enumeration type (as well as an integer)
        const POWEROFTWO = 8;  // an enumeration type where all values are of 2^^n form
        const UTF16 = 16;   // 16-bit wide chars in unicode utf16
        const UTF32 = 32;   // 32-bit wide chars in unicode utf32
        const OPAQUE_STRING = 64;  // structure that should be treated as a string
        const VARIABLE_LENGTH = 128; // may be other structures with same name different lengths
        const HAS_STRIPPED = 0x100; // datatype has a stripped form for formal declarations
        const IS_PTRREL = 0x200;  // datatype is a type POINTERREL
        const TYPE_INCOMPLETE = 0x400; // set if \b this (recursive) data-type has not been fully defined yet
        const NEEDS_RESOLUTION = 0x800; // datatype (union, pointer to union) needs resolution before propagation
        const FORCE_FORMAT = 0x7000; // 3-bits encoding display format, 0=none, 1=hex, 2=dec, 3=oct, 4=bin, 5=char
        const TRUNCATE_BIGENDIAN = 0x8000; // pointer can be truncated and is big endian
        const POINTER_TO_ARRAY = 0x10000; // data-type is a pointer to array
    }
}

unsafe impl Send for DataTypeRef<'_> {}
unsafe impl Sync for DataTypeRef<'_> {}

impl<'a> DataTypeRef<'a> {
    pub(crate) fn new(t: *mut DataType) -> Option<Self> {
        if t.is_null() {
            None
        } else {
            Some(Self {
                t,
                _marker: PhantomData,
            })
        }
    }

    pub fn name(&self) -> Option<Ustr> {
        let n = unsafe { ffi::ghidra_decompiler_get_type_name(self.t).ok()? };

        if n.is_empty() {
            None
        } else {
            Some(Ustr::from(&n))
        }
    }

    pub fn flags(&self) -> DataTypeFlags {
        let v = unsafe { ffi::ghidra_decompiler_get_type_flags(self.t).unwrap_or_default() };
        DataTypeFlags::from_bits_retain(v)
    }

    pub fn is_incomplete(&self) -> bool {
        self.flags().contains(DataTypeFlags::TYPE_INCOMPLETE)
    }

    pub fn is_char(&self) -> bool {
        matches!(
            self.sub_kind(),
            DataSubMetaType::Char | DataSubMetaType::UnsignedChar
        )
    }

    pub fn is_struct(&self) -> bool {
        matches!(self.kind(), DataMetaType::Struct)
    }

    pub fn is_union(&self) -> bool {
        matches!(self.kind(), DataMetaType::Union)
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self.kind(), DataMetaType::Pointer)
    }

    pub fn is_array(&self) -> bool {
        matches!(self.kind(), DataMetaType::Array)
    }

    pub fn is_unicode(&self) -> bool {
        matches!(
            self.sub_kind(),
            DataSubMetaType::Unicode | DataSubMetaType::UnsignedUnicode
        )
    }

    pub fn is_enum(&self) -> bool {
        matches!(
            self.sub_kind(),
            DataSubMetaType::Enum | DataSubMetaType::UnsignedEnum
        )
    }

    pub fn is_unsigned(&self) -> bool {
        matches!(
            self.sub_kind(),
            DataSubMetaType::UnsignedChar
                | DataSubMetaType::UnsignedInt
                | DataSubMetaType::UnsignedEnum
                | DataSubMetaType::UnsignedUnicode
        )
    }

    pub fn kind(&self) -> DataTypeKind {
        let t = unsafe { ffi::ghidra_decompiler_get_type_metatype(self.t) };
        t.unwrap_or(DataTypeKind::Unknown)
    }

    pub fn sub_kind(&self) -> DataTypeSubKind {
        let t = unsafe { ffi::ghidra_decompiler_get_type_submetatype(self.t) };
        t.unwrap_or(DataTypeSubKind::Unknown)
    }

    pub fn pointee(&self) -> Option<Self> {
        let t = unsafe { ffi::ghidra_decompiler_get_type_pointee(self.t).ok()? };
        Self::new(t)
    }

    pub fn typedef(&self) -> Option<Self> {
        let t = unsafe { ffi::ghidra_decompiler_get_type_typedef(self.t).ok()? };
        Self::new(t)
    }

    // SAFETY: the return value does not encode the lifetime of the decompiler instance
    // the type was obtained from; for use in type conversion where the lifetime is known
    // and bounded only.
    //
    unsafe fn field(&self, n: usize) -> Option<DataTypeField> {
        unsafe { ffi::ghidra_decompiler_get_type_field(self.t, n as _).ok() }
    }

    // SAFETY: the return value does not encode the lifetime of the decompiler instance
    // the type was obtained from; for use in type conversion where the lifetime is known
    // and bounded only.
    //
    unsafe fn struct_field(&self, n: usize) -> Option<DataTypeField> {
        self.field(n)
    }

    // SAFETY: the return value does not encode the lifetime of the decompiler instance
    // the type was obtained from; for use in type conversion where the lifetime is known
    // and bounded only.
    //
    unsafe fn union_variant(&self, n: usize) -> Option<DataTypeField> {
        self.field(n)
    }

    fn field_count(&self) -> Option<usize> {
        unsafe {
            ffi::ghidra_decompiler_get_type_num_fields(self.t)
                .map(|v| v as usize)
                .ok()
        }
    }

    fn struct_field_count(&self) -> Option<usize> {
        self.field_count()
    }

    fn union_variant_count(&self) -> Option<usize> {
        self.field_count()
    }

    fn array_element_type(&self) -> Option<Self> {
        let t = unsafe { ffi::ghidra_decompiler_get_type_array_base(self.t).ok()? };
        Self::new(t)
    }

    fn array_element_count(&self) -> Option<u32> {
        unsafe {
            ffi::ghidra_decompiler_get_type_array_num_elements(self.t)
                .map(|v| v as u32)
                .ok()
        }
    }

    // SAFETY: the return value does not encode the lifetime of the decompiler instance
    // the type was obtained from; for use in type conversion where the lifetime is known
    // and bounded only.
    //
    unsafe fn enum_variants(&self) -> Option<Vec<ffi::EnumVariant>> {
        let mut variants = Vec::new();
        unsafe { ffi::ghidra_decompiler_get_type_enum_variants(self.t, &mut variants).ok()? }
        if variants.is_empty() {
            None
        } else {
            Some(variants)
        }
    }

    // SAFETY: the return value does not encode the lifetime of the decompiler instance
    // the type was obtained from; for use in type conversion where the lifetime is known
    // and bounded only.
    //
    unsafe fn function_type(&self) -> Option<FunctionType> {
        let mut ft = FunctionType::default();
        unsafe { ffi::ghidra_decompiler_get_type_function(self.t, &mut ft).ok()? };
        Some(ft)
    }

    pub fn alignment(&self) -> Option<usize> {
        unsafe {
            ffi::ghidra_decompiler_get_type_alignment(self.t)
                .map(|v| v as usize)
                .ok()
        }
    }

    pub fn aligned_size(&self) -> Option<usize> {
        unsafe {
            ffi::ghidra_decompiler_get_type_align_size(self.t)
                .map(|v| v as usize)
                .ok()
        }
    }

    pub fn size(&self) -> Option<usize> {
        unsafe {
            ffi::ghidra_decompiler_get_type_size(self.t)
                .map(|v| v as usize)
                .ok()
        }
    }

    pub fn to_type(&self, tdb: &TypeDB, bits: u32) -> Result<Term<Type>, DecompilerTypeError> {
        self.to_type_with(tdb, bits, true)
    }

    pub fn to_resolved_type(
        &self,
        tdb: &TypeDB,
        bits: u32,
    ) -> Result<Term<Type>, DecompilerTypeError> {
        self.to_type_with(tdb, bits, false)
    }

    fn to_known_type(
        &self,
        tdb: &TypeDB,
        bits: u32,
        typedef: bool,
    ) -> Result<Option<Term<Type>>, DecompilerTypeError> {
        let Some(nm) = self.name() else {
            return Ok(None);
        };

        let Some(size) = self.aligned_size() else {
            return Ok(None);
        };

        let Some(t) = tdb.get_type_for(nm.as_ref(), bits) else {
            return Ok(None);
        };

        if t.nbytes() != size {
            return Err(DecompilerTypeError::NamedSizeInconsistent);
        }

        return Ok(if typedef {
            if bits == 32 {
                Some(Type::named_32(nm, t.nbytes() as _))
            } else if bits == 64 {
                Some(Type::named_64(nm, t.nbytes() as _))
            } else {
                None
            }
        } else {
            Some(t)
        });
    }

    pub fn to_type_with(
        &self,
        tdb: &TypeDB,
        bits: u32,
        resolve_names: bool,
    ) -> Result<Term<Type>, DecompilerTypeError> {
        if let Some(td) = self.typedef() {
            if !resolve_names {
                return td.to_type_with(tdb, bits, resolve_names);
            }

            return if let Some(resolved) = self.to_known_type(tdb, bits, true)? {
                Ok(resolved)
            } else {
                td.to_type_with(tdb, bits, resolve_names)
            };
        }

        let flags = self.flags();

        let t = match self.kind() {
            DataTypeKind::Void => Type::void(),
            DataTypeKind::Bool => Type::bool(),
            DataTypeKind::Int | DataTypeKind::UnsignedInt if self.is_enum() => {
                let size = self.aligned_size().ok_or(DecompilerTypeError::Unsized)?;
                let name = self.name();
                let variants = unsafe { self.enum_variants() }
                    .ok_or(DecompilerTypeError::EnumVariants)?
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let value = BitVec::from(v.value);
                        let name = if v.name.is_empty() {
                            format!("__unnamed_enum_variant_{i}")
                        } else {
                            v.name
                        };
                        EnumVariant::new(
                            name,
                            value.signed_cast(size * 8),
                            value.unsigned_cast(size * 8),
                        )
                    });

                Type::enum_(name.as_deref().unwrap_or_default(), variants, size as _)
            }
            DataTypeKind::Int => {
                let size = self.aligned_size().ok_or(DecompilerTypeError::Unsized)?;
                let is_unicode = self.is_unicode();

                if self.is_char() {
                    Type::char()
                } else if is_unicode && size == 2 {
                    Type::char16()
                } else if is_unicode && size == 4 {
                    Type::char32()
                } else {
                    Type::signed(size as u32 * 8)
                }
            }
            DataTypeKind::UnsignedInt => {
                let size = self.aligned_size().ok_or(DecompilerTypeError::Unsized)?;

                if self.is_char() {
                    Type::unsigned_char()
                } else {
                    Type::unsigned(size as u32 * 8)
                }
            }
            DataTypeKind::Pointer => {
                let base = self.pointee().ok_or(DecompilerTypeError::PointeeType)?;
                let t = base.to_type_with(tdb, bits, resolve_names)?;
                Type::pointer(t, bits)
            }
            DataTypeKind::Array => {
                let elem = self
                    .array_element_type()
                    .ok_or(DecompilerTypeError::ElementType)?;
                let t = elem.to_type_with(tdb, bits, resolve_names)?;

                if flags.contains(DataTypeFlags::VARIABLE_LENGTH) {
                    Type::variable_sized_array(t)
                } else {
                    let count = self
                        .array_element_count()
                        .ok_or(DecompilerTypeError::ElementCount)?;
                    Type::array(t, count)
                }
            }
            DataTypeKind::Struct => {
                if let Some(resolved) = self.to_known_type(tdb, bits, false)? {
                    return Ok(resolved);
                }

                let size = self.aligned_size().ok_or(DecompilerTypeError::Unsized)?;
                let name = self.name();

                let n = self
                    .struct_field_count()
                    .ok_or(DecompilerTypeError::StructFields)?;

                let mut fields = Vec::new();
                for i in 0..n {
                    let field =
                        unsafe { self.struct_field(i) }.ok_or(DecompilerTypeError::StructFields)?;
                    let field_type =
                        Self::new(field.type_).ok_or(DecompilerTypeError::StructFields)?;

                    let name = if field.name.is_empty() {
                        format!("__unnamed_struct_field_{i}")
                    } else {
                        field.name
                    };
                    let offset = field.offset;
                    let t = field_type.to_type_with(tdb, bits, resolve_names)?;

                    fields.push((name, offset, t));
                }

                Type::struct_(
                    name.as_deref().unwrap_or_default(),
                    fields.into_iter(),
                    size as _,
                )
            }
            DataTypeKind::Union => {
                if let Some(resolved) = self.to_known_type(tdb, bits, false)? {
                    return Ok(resolved);
                }

                let size = self.aligned_size().ok_or(DecompilerTypeError::Unsized)?;
                let n = self
                    .union_variant_count()
                    .ok_or(DecompilerTypeError::UnionVariants)?;
                let name = self.name();

                let mut variants = Vec::new();
                for i in 0..n {
                    let variant = unsafe { self.union_variant(i) }
                        .ok_or(DecompilerTypeError::UnionVariants)?;
                    let variant_type =
                        Self::new(variant.type_).ok_or(DecompilerTypeError::UnionVariants)?;

                    let name = if variant.name.is_empty() {
                        format!("__unnamed_union_variant_{i}")
                    } else {
                        variant.name
                    };
                    let t = variant_type.to_type_with(tdb, bits, resolve_names)?;

                    variants.push((name, t));
                }

                Type::union_(
                    name.as_deref().unwrap_or_default(),
                    variants.into_iter(),
                    size as _,
                )
            }
            DataTypeKind::Code => {
                // NOTE: if we have no FunctionProto, then it means we have funcptr_t.
                let Some(ft) = (unsafe { self.function_type() }) else {
                    return Ok(Type::function(
                        Type::void(),
                        std::iter::empty::<FunctionArg>(),
                    ));
                };

                let output = Self::new(ft.output_type)
                    .ok_or(DecompilerTypeError::FunctionProto)?
                    .to_type_with(tdb, bits, resolve_names)?;

                let inputs = ft
                    .inputs
                    .into_iter()
                    .map(|input| {
                        let dt =
                            Self::new(input.type_).ok_or(DecompilerTypeError::FunctionProto)?;
                        let t = dt.to_type_with(tdb, bits, resolve_names)?;
                        Ok(FunctionArg::new(Ustr::from(&input.name), t))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Type::function_with(output, inputs.into_iter(), ft.is_variadic)
            }
            DataTypeKind::Unknown => {
                let size = self.aligned_size().ok_or(DecompilerTypeError::Unsized)?;
                Type::unsigned(size as u32 * 8)
            }
            _ => {
                return Err(DecompilerTypeError::Unsupported);
            }
        };

        Ok(t)
    }
}

pub trait DecompilerTypeResolver: Send + Sync + 'static {
    #[allow(unused)]
    fn resolve_global_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        global: Address,
        size: usize,
    ) -> Option<Term<Type>> {
        project.type_db().get_data_type_at(global)
    }

    #[allow(unused)]
    fn resolve_stack_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        offset: i64,
        size: usize,
    ) -> Option<Term<Type>> {
        None
    }

    #[allow(unused)]
    fn resolve_register_type(
        &self,
        project: &Project,
        use_at: Address,
        register: Var,
    ) -> Option<Term<Type>> {
        None
    }

    #[allow(unused)]
    fn resolve_temporary_type(
        &self,
        project: &Project,
        use_at: Address,
        temporary: Var,
    ) -> Option<Term<Type>> {
        None
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefaultDecompilerTypeResolver;

impl DecompilerSymbolResolver for DefaultDecompilerTypeResolver {}
impl DecompilerTypeResolver for DefaultDecompilerTypeResolver {}

#[repr(transparent)]
pub struct DecompilerResolverAdaptor<T>(T)
where
    T: DecompilerTypeResolver;

impl<T> From<T> for DecompilerResolverAdaptor<T>
where
    T: DecompilerTypeResolver,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for DecompilerResolverAdaptor<T>
where
    T: DecompilerTypeResolver,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for DecompilerResolverAdaptor<T>
where
    T: DecompilerTypeResolver,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> DecompilerResolverAdaptor<T>
where
    T: DecompilerTypeResolver,
{
    pub fn new(resolver: T) -> Self {
        Self::from(resolver)
    }
}

impl<T> DecompilerSymbolResolver for DecompilerResolverAdaptor<T> where T: DecompilerTypeResolver {}

impl<T> DecompilerTypeResolver for DecompilerResolverAdaptor<T>
where
    T: DecompilerTypeResolver,
{
    fn resolve_global_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        global: Address,
        size: usize,
    ) -> Option<Term<Type>> {
        self.0
            .resolve_global_variable_type(project, use_at, global, size)
    }

    fn resolve_stack_variable_type(
        &self,
        project: &Project,
        use_at: Address,
        offset: i64,
        size: usize,
    ) -> Option<Term<Type>> {
        self.0
            .resolve_stack_variable_type(project, use_at, offset, size)
    }

    fn resolve_register_type(
        &self,
        project: &Project,
        use_at: Address,
        register: Var,
    ) -> Option<Term<Type>> {
        self.0.resolve_register_type(project, use_at, register)
    }

    fn resolve_temporary_type(
        &self,
        project: &Project,
        use_at: Address,
        temporary: Var,
    ) -> Option<Term<Type>> {
        self.0.resolve_temporary_type(project, use_at, temporary)
    }
}
