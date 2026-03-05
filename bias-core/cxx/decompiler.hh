#pragma once

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>

#include "rust.hh"

// From Rust
struct DecompilerAnnotationDB;
struct DecompilerProjectRef;

enum class SpaceKind : ::std::uint8_t;
enum class DataMetaType : ::std::uint8_t;
enum class DataSubMetaType : ::std::uint8_t;
enum class OverrideKind : ::std::uint8_t;

struct DataTypeField;
struct EnumVariant;
struct FunctionInput;
struct FunctionSignature;
struct FunctionType;
struct HighVarWithType;
struct JumpTableInfo;
struct StructField;
struct UnionVariant;
struct VarInfo;

class DecompilerArch;

// From Ghidra
namespace ghidra {
class Datatype;

class TypeCode;
class TypePointer;
class TypeStruct;
class TypeUnion;
}; // namespace ghidra

using Datatype = ghidra::Datatype;
using TypeCode = ghidra::TypeCode;
using TypePointer = ghidra::TypePointer;
using TypeStruct = ghidra::TypeStruct;
using TypeUnion = ghidra::TypeUnion;

struct GhidraDecompiler {
  GhidraDecompiler(const std::string &spec,
                   rust::Box<DecompilerProjectRef> project);
  ~GhidraDecompiler();

  rust::String decompile(uint64_t start_ea, uint64_t timeout);
  rust::String decompile_xml(uint64_t start_ea, uint64_t timeout);
  void decompile_ast(uint64_t start_ea, uint64_t timeout,
                     DecompilerAnnotationDB &mapper,
                     rust::Vec<JumpTableInfo> &tables,
                     rust::Vec<rust::String> &params,
                     rust::Vec<HighVarWithType> &vars);

  void function_signature(uint64_t start_ea, uint64_t timeout,
                          uint32_t settings, int32_t max_dfg_iters,
                          int32_t max_block_iters, int32_t max_varnodes,
                          FunctionSignature &sig);

  Datatype *get_type(const std::string &name) const;
  void set_function_variable_type_at(uint64_t func_addr, const std::string &nm, Datatype *t);
  std::uint32_t address_bits() const;

  Datatype *build_pointer_type(Datatype *t);
  Datatype *build_array_type(Datatype *t, size_t n);
  Datatype *build_typedef(const std::string &name, Datatype *t);
  Datatype *build_typedef_with(const std::string &name, Datatype *t, bool rebuild);
  Datatype *build_function_type(Datatype *output,
                                const rust::Slice<rust::Str const> input_names,
                                const rust::Slice<Datatype *const> input_types,
                                bool variadic);
  Datatype *begin_struct_type(const std::string &name);
  Datatype *end_struct_type(Datatype *dt,
                            const rust::Slice<const StructField> fields);

  Datatype *begin_union_type(const std::string &name);
  Datatype *end_union_type(Datatype *dt,
                           const rust::Slice<const UnionVariant> variants);

  void remove_type(Datatype *t);

  void add_extern(const std::string &name, uint64_t ea);
  void add_function_symbol(const std::string &name, uint64_t ea, bool force);
  void add_function_symbol_with(const std::string &name, uint64_t ea,
                                Datatype *output_type,
                                const rust::Slice<rust::Str const> input_names,
                                const rust::Slice<Datatype *const> input_types,
                                bool variadic, bool force);

  void add_global(const std::string &name, uint64_t ea, Datatype *t);
  void add_global_with(const std::string &name, uint64_t ea, Datatype *t,
                       bool read_only);

  void add_global_ascii_char(const std::string &name, uint64_t ea);
  void add_global_ascii_string(const std::string &name, uint64_t ea, size_t n);
  void add_global_ascii_pointer(const std::string &name, uint64_t ea, size_t n);

  void add_global_utf16_char(const std::string &name, uint64_t ea);
  void add_global_utf16_string(const std::string &name, uint64_t ea, size_t n);
  void add_global_utf16_pointer(const std::string &name, uint64_t ea, size_t n);
  void add_comment(rust::Str comment, uint64_t faddr, uint64_t addr);
  void remove_comments(uint64_t faddr, uint64_t addr);

  void set_range_read_only(uint64_t ea, size_t n);
  void set_range_writable(uint64_t ea, size_t n);

  void set_non_returning_function(uint64_t ea);

  void override_flow(uint64_t ea, uint64_t branch_ea,
                     OverrideKind override_kind);
  void override_jump_table(uint64_t ea, uint64_t switch_ea,
                           rust::Vec<uint64_t> addr_table);

  void apply_call_fixup(const std::string& name, uint64_t ea);
  void clear_call_fixup(uint64_t ea);

  void register_call_fixup(const std::string& name, const std::string& snippet);
  void clear_all();

  uint32_t get_variable(const std::string& name, uint64_t ea) const;
  void set_variable(const std::string& name, uint64_t ea, uint32_t val);

  DecompilerProjectRef &project_ref();

  std::string name;
  std::string spec;

  DecompilerArch *arch;
  std::stringstream *err_stream;
};

std::unique_ptr<GhidraDecompiler>
ghidra_decompiler_new(const std::string &spec,
                      rust::Box<DecompilerProjectRef> project);

void ghidra_decompiler_init();
void ghidra_decompiler_scan_for_sleigh_directories(const std::string &root);
void ghidra_decompiler_push_sleigh_path(const std::string &root);

rust::String ghidra_decompiler_get_type_name(Datatype *t);
DataMetaType ghidra_decompiler_get_type_metatype(Datatype *t);
DataSubMetaType ghidra_decompiler_get_type_submetatype(Datatype *t);
Datatype *ghidra_decompiler_get_type_typedef(Datatype *t);
Datatype *ghidra_decompiler_get_type_pointee(Datatype *t);
DataTypeField ghidra_decompiler_get_type_field(Datatype *t, int32_t i);
int32_t ghidra_decompiler_get_type_num_fields(Datatype *t);
int32_t ghidra_decompiler_get_type_size(Datatype *t);
int32_t ghidra_decompiler_get_type_align_size(Datatype *t);
int32_t ghidra_decompiler_get_type_alignment(Datatype *t);
Datatype *ghidra_decompiler_get_type_array_base(Datatype *t);
int32_t ghidra_decompiler_get_type_array_num_elements(Datatype *t);
void ghidra_decompiler_get_type_enum_variants(Datatype *t, rust::Vec<EnumVariant>& variants);
uint32_t ghidra_decompiler_get_type_flags(Datatype *t);
void ghidra_decompiler_get_type_function(Datatype *t, FunctionType& fp);
