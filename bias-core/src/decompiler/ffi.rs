use cxx::CxxString;

use crate::decompiler::annotation::DecompilerAnnotationDB;
use crate::decompiler::project::DecompilerProjectRef;

#[cxx::bridge]
mod ffi {
    struct StructField<'a> {
        name: &'a str,
        offset: usize,
        type_: *mut Datatype,
    }

    struct UnionVariant<'a> {
        name: &'a str,
        type_: *mut Datatype,
    }

    struct EnumVariant {
        name: String,
        value: usize,
    }

    struct FunctionInput {
        name: String,
        type_: *mut Datatype,
    }

    struct FunctionType {
        inputs: Vec<FunctionInput>,
        output_type: *mut Datatype,
        is_no_return: bool,
        is_variadic: bool,
        has_this_pointer: bool,
    }

    struct DataTypeField {
        name: String,
        offset: usize,
        type_: *mut Datatype,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum OverrideKind {
        None = 0,
        Branch = 1,
        Call = 2,
        CallReturn = 3,
        Return = 4,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum SpaceKind {
        Global,
        Register,
        Stack,
        Unique,
    }

    #[derive(Debug, Clone)]
    enum DataMetaType {
        Void = 14,
        Spacebase = 13,
        Unknown = 12,
        Int = 11,
        UnsignedInt = 10,
        Bool = 9,
        Code = 8,
        Float = 7,
        Pointer = 6,
        PointerRel = 5,
        Array = 4,
        Struct = 3,
        Union = 2,
        PartialStruct = 1,
        PartialUnion = 0,
    }

    #[derive(Debug, Clone)]
    enum DataSubMetaType {
        Void = 22,
        Spacebase = 21,
        Unknown = 20,
        PartialStruct = 19,
        Char = 18,
        UnsignedChar = 17,
        Int = 16,
        UnsignedInt = 15,
        Enum = 14,
        UnsignedEnum = 13,
        Unicode = 12,
        UnsignedUnicode = 11,
        Bool = 10,
        Code = 9,
        Float = 8,
        PointerRelUnknown = 7,
        Pointer = 6,
        PointerRel = 5,
        PointerStruct = 4,
        Array = 3,
        Struct = 2,
        Union = 1,
        PartialUnion = 0,
    }

    struct HighVarWithType {
        name: String,
        addr: u64,
        space: SpaceKind,
        offset: u64,
        size: u32,
        type_: *mut Datatype,
    }

    #[derive(Debug, Clone)]
    struct VarInfo {
        space: SpaceKind,
        offset: u64,
        size: u32,
    }

    #[derive(Debug, Clone)]
    struct LoadTableInfo {
        addr: u64,
        size: usize,
        count: usize,
    }

    #[derive(Debug, Clone)]
    struct JumpTableInfo {
        branch: u64,
        targets: Vec<u64>,
        tables: Vec<LoadTableInfo>,
    }

    #[derive(Debug, Clone, Copy)]
    struct AddressRange {
        addr: u64,
        size: usize,
    }

    #[derive(Debug, Clone, Default, PartialOrd, Ord, PartialEq, Eq, Hash)]
    struct FunctionSignature {
        features: Vec<u32>,
        callees: Vec<u64>,
        has_bad_data: bool,
        has_unimplemented: bool,
        overall_hash: u64,
    }

    extern "Rust" {
        type DecompilerProjectRef<'a>;

        #[allow(unused_unsafe)]
        unsafe fn read_bytes(&self, address: u64, size: usize, into: *mut u8) -> Result<()>;
        fn read_only_regions(&self) -> Vec<AddressRange>;
        fn code_regions(&self) -> Vec<AddressRange>;
        #[allow(unused_unsafe)]
        unsafe fn type_at<'a>(
            &'a self,
            decompiler: *mut GhidraDecompiler<'a>,
            at: u64,
            var: VarInfo,
        ) -> Result<*mut Datatype>;
        #[allow(unused_unsafe)]
        unsafe fn update_name<'a>(
            &'a self,
            decompiler: *mut GhidraDecompiler<'a>,
            var: VarInfo,
            name: &CxxString,
            uses: &[u64],
            dtype: *mut Datatype,
        ) -> Result<String>;
    }

    extern "Rust" {
        type DecompilerAnnotationDB;

        fn open_scope(&mut self, start: usize);
        fn close_scope(&mut self, end: usize);

        fn annotate_offset(&mut self, offset: u64);
        fn annotate_function_call(&mut self, value: u64);

        fn annotate_constant(&mut self, name: String, value: u64);
        fn annotate_function_name(&mut self, name: String, value: u64);
        fn annotate_global_variable(&mut self, name: String, value: u64);

        fn annotate_local_variable(&mut self, name: String);
        fn annotate_function_parameter(&mut self, name: String);

        fn annotate_source(&mut self, code: String);
    }

    unsafe extern "C++" {
        include!("decompiler.hh");

        type GhidraDecompiler<'a>;
        type Datatype;

        unsafe fn decompile(
            self: Pin<&mut GhidraDecompiler>,
            address: u64,
            timeout: u64,
        ) -> Result<String>;

        unsafe fn decompile_xml(
            self: Pin<&mut GhidraDecompiler>,
            address: u64,
            timeout: u64,
        ) -> Result<String>;

        unsafe fn decompile_ast(
            self: Pin<&mut GhidraDecompiler>,
            address: u64,
            timeout: u64,
            annotations: &mut DecompilerAnnotationDB,
            tables: &mut Vec<JumpTableInfo>,
            params: &mut Vec<String>,
            vars: &mut Vec<HighVarWithType>,
        ) -> Result<()>;

        unsafe fn function_signature(
            self: Pin<&mut GhidraDecompiler>,
            address: u64,
            timeout: u64,
            settings: u32,
            max_dfg_iters: i32,
            max_block_iters: i32,
            max_varnodes: i32,
            signature: &mut FunctionSignature,
        ) -> Result<()>;

        unsafe fn address_bits<'a>(self: &'a GhidraDecompiler) -> Result<u32>;

        fn get_type<'a>(self: &'a GhidraDecompiler, name: &CxxString) -> Result<*mut Datatype>;

        unsafe fn set_function_variable_type_at<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            func_addr: u64,
            var_name: &CxxString,
            dtype: *mut Datatype,
        ) -> Result<()>;

        unsafe fn set_range_read_only<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            addr: u64,
            size: usize,
        ) -> Result<()>;

        unsafe fn set_range_writable<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            addr: u64,
            size: usize,
        ) -> Result<()>;

        unsafe fn set_non_returning_function<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            addr: u64,
        ) -> Result<()>;

        unsafe fn begin_struct_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
        ) -> Result<*mut Datatype>;

        unsafe fn end_struct_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            type_: *mut Datatype,
            fields: &[StructField<'a>],
        ) -> Result<*mut Datatype>;

        unsafe fn begin_union_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
        ) -> Result<*mut Datatype>;

        unsafe fn end_union_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            type_: *mut Datatype,
            variants: &[UnionVariant<'a>],
        ) -> Result<*mut Datatype>;

        unsafe fn build_function_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            output: *mut Datatype,
            input_names: &[&str],
            input_types: &[*mut Datatype],
            variadic: bool,
        ) -> Result<*mut Datatype>;

        unsafe fn build_pointer_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            t: *mut Datatype,
        ) -> Result<*mut Datatype>;

        unsafe fn build_array_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            t: *mut Datatype,
            n: usize,
        ) -> Result<*mut Datatype>;

        unsafe fn build_typedef<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            t: *mut Datatype,
        ) -> Result<*mut Datatype>;

        unsafe fn build_typedef_with<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            t: *mut Datatype,
            rebuild: bool,
        ) -> Result<*mut Datatype>;

        unsafe fn remove_type<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            dt: *mut Datatype,
        ) -> Result<()>;

        unsafe fn add_extern<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
        ) -> Result<()>;

        unsafe fn add_function_symbol<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            force: bool,
        ) -> Result<()>;

        unsafe fn add_function_symbol_with<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            rtype: *mut Datatype,
            params: &[&str],
            param_types: &[*mut Datatype],
            variadic: bool,
            force: bool,
        ) -> Result<()>;

        unsafe fn add_global<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            t: *mut Datatype,
        ) -> Result<()>;

        unsafe fn add_global_with<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            t: *mut Datatype,
            read_only: bool,
        ) -> Result<()>;

        unsafe fn add_global_ascii_char<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
        ) -> Result<()>;

        unsafe fn add_global_ascii_string<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            n: usize,
        ) -> Result<()>;

        unsafe fn add_global_ascii_pointer<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            n: usize,
        ) -> Result<()>;

        unsafe fn add_global_utf16_char<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
        ) -> Result<()>;

        unsafe fn add_global_utf16_string<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            n: usize,
        ) -> Result<()>;

        unsafe fn add_global_utf16_pointer<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            addr: u64,
            n: usize,
        ) -> Result<()>;

        unsafe fn add_comment<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            comment: &str,
            faddr: u64,
            addr: u64,
        ) -> Result<()>;

        unsafe fn remove_comments<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            faddr: u64,
            addr: u64,
        ) -> Result<()>;

        unsafe fn ghidra_decompiler_new<'a>(
            spec: &CxxString,
            project: Box<DecompilerProjectRef<'a>>,
        ) -> Result<UniquePtr<GhidraDecompiler<'a>>>;

        unsafe fn project_ref(self: Pin<&mut GhidraDecompiler>) -> &mut DecompilerProjectRef;

        unsafe fn ghidra_decompiler_init() -> Result<()>;
        unsafe fn ghidra_decompiler_scan_for_sleigh_directories(root: &CxxString) -> Result<()>;
        unsafe fn ghidra_decompiler_push_sleigh_path(root: &CxxString) -> Result<()>;

        unsafe fn ghidra_decompiler_get_type_name<'a>(type_: *mut Datatype) -> Result<String>;

        unsafe fn ghidra_decompiler_get_type_metatype(type_: *mut Datatype)
            -> Result<DataMetaType>;

        unsafe fn ghidra_decompiler_get_type_submetatype(
            type_: *mut Datatype,
        ) -> Result<DataSubMetaType>;

        unsafe fn ghidra_decompiler_get_type_typedef(type_: *mut Datatype)
            -> Result<*mut Datatype>;

        unsafe fn ghidra_decompiler_get_type_pointee(type_: *mut Datatype)
            -> Result<*mut Datatype>;

        unsafe fn ghidra_decompiler_get_type_field(
            type_: *mut Datatype,
            index: i32,
        ) -> Result<DataTypeField>;

        unsafe fn ghidra_decompiler_get_type_num_fields(type_: *mut Datatype) -> Result<i32>;
        unsafe fn ghidra_decompiler_get_type_size(type_: *mut Datatype) -> Result<i32>;
        unsafe fn ghidra_decompiler_get_type_align_size(type_: *mut Datatype) -> Result<i32>;
        unsafe fn ghidra_decompiler_get_type_alignment(type_: *mut Datatype) -> Result<i32>;
        unsafe fn ghidra_decompiler_get_type_flags(type_: *mut Datatype) -> Result<u32>;

        unsafe fn ghidra_decompiler_get_type_array_base(
            type_: *mut Datatype,
        ) -> Result<*mut Datatype>;
        unsafe fn ghidra_decompiler_get_type_array_num_elements(
            type_: *mut Datatype,
        ) -> Result<i32>;

        unsafe fn ghidra_decompiler_get_type_enum_variants(
            type_: *mut Datatype,
            variants: &mut Vec<EnumVariant>,
        ) -> Result<()>;

        unsafe fn ghidra_decompiler_get_type_function(
            type_: *mut Datatype,
            proto: &mut FunctionType,
        ) -> Result<()>;

        unsafe fn override_flow<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            faddr: u64,
            branch_addr: u64,
            override_kind: OverrideKind,
        ) -> Result<()>;

        unsafe fn override_jump_table<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            faddr: u64,
            switch_addr: u64,
            addr_table: Vec<u64>,
        ) -> Result<()>;

        unsafe fn register_call_fixup<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            snippet: &CxxString,
        ) -> Result<()>;

        unsafe fn apply_call_fixup<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            ea: u64,
        ) -> Result<()>;

        fn get_variable<'a>(self: &'a GhidraDecompiler, name: &CxxString, ea: u64) -> Result<u32>;

        unsafe fn set_variable<'a>(
            self: Pin<&'a mut GhidraDecompiler>,
            name: &CxxString,
            ea: u64,
            val: u32,
        ) -> Result<()>;

        unsafe fn clear_call_fixup<'a>(self: Pin<&'a mut GhidraDecompiler>, ea: u64) -> Result<()>;

        unsafe fn clear_all<'a>(self: Pin<&'a mut GhidraDecompiler>) -> Result<()>;
    }
}

unsafe impl Send for ffi::GhidraDecompiler<'_> {}
unsafe impl Sync for ffi::GhidraDecompiler<'_> {}

pub use ffi::{Datatype as DataType, OverrideKind as FlowOverride, *};

pub type VariableNameRef<'a> = &'a CxxString;

impl Default for FunctionType {
    fn default() -> Self {
        Self {
            inputs: Vec::default(),
            output_type: std::ptr::null_mut(),
            is_variadic: false,
            is_no_return: false,
            has_this_pointer: false,
        }
    }
}
