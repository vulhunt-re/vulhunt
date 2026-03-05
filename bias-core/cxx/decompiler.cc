#include "decompiler.hh"
#include "bridge.hh"

#include "decompiler_annot.hh"
#include "decompiler_arch.hh"
#include "decompiler_scope.hh"
#include "inject_sleigh.hh"
#include "libdecomp.hh"
#include "rust.hh"
#include "signature.hh"

#include <chrono>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

using Address = ghidra::Address;
using ArchitectureCapability = ghidra::ArchitectureCapability;
using AttributeId = ghidra::AttributeId;
using CapabilityPoint = ghidra::CapabilityPoint;
using Comment = ghidra::Comment;
using Database = ghidra::Database;
using Datatype = ghidra::Datatype;
using DocumentStorage = ghidra::DocumentStorage;
using ElementId = ghidra::ElementId;
using Funcdata = ghidra::Funcdata;
using FuncCallSpecs = ghidra::FuncCallSpecs;
using PrototypePieces = ghidra::PrototypePieces;
using Range = ghidra::Range;
using Scope = ghidra::Scope;
using ScopeInternal = ghidra::ScopeInternal;
using GraphSigManager = ghidra::GraphSigManager;
using SleighArchitecture = ghidra::SleighArchitecture;
using SymbolEntry = ghidra::SymbolEntry;
using TypeArray = ghidra::TypeArray;
using TypeCode = ghidra::TypeCode;
using TypeEnum = ghidra::TypeEnum;
using TypeField = ghidra::TypeField;
using TypePointer = ghidra::TypePointer;
using TypeStruct = ghidra::TypeStruct;
using TypeUnion = ghidra::TypeUnion;
using Varnode = ghidra::Varnode;

using DecoderError = ghidra::DecoderError;
using LowlevelError = ghidra::LowlevelError;

using int4 = ghidra::int4;

GhidraDecompiler::GhidraDecompiler(const std::string &spec,
                                   rust::Box<DecompilerProjectRef> project) {
  try {
    err_stream = new std::stringstream();
    arch = new DecompilerArch(spec, std::move(project), this, err_stream);
    DocumentStorage store;
    arch->init(store);
    arch->setPrintLanguage("brly-c-language");
    arch->analyze_for_loops = true;
    arch->readonlypropagate = true;
  } catch (DecoderError &err) {
    throw std::runtime_error(err.explain);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

GhidraDecompiler::~GhidraDecompiler() {
  delete arch;
  delete err_stream;
}

std::unique_ptr<GhidraDecompiler>
ghidra_decompiler_new(const std::string &spec,
                      rust::Box<DecompilerProjectRef> project) {
  try {
    return std::unique_ptr<GhidraDecompiler>(
        new GhidraDecompiler(spec, std::move(project)));
  } catch (DecoderError &err) {
    throw std::runtime_error(err.explain);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

std::uint32_t GhidraDecompiler::address_bits() const {
  try {
    return arch->getDefaultSize() * 8;
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::get_type(const std::string &name) const {
  try {
    return arch->types->findByName(name);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

rust::String ghidra_decompiler_get_type_name(Datatype *t) {
  try {
    return rust::String(t->getName());
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

DataMetaType ghidra_decompiler_get_type_metatype(Datatype *t) {
  try {
    switch (t->getMetatype()) {
    case ghidra::TYPE_VOID:
      return DataMetaType::Void;
    case ghidra::TYPE_PTR:
      return DataMetaType::Pointer;
    case ghidra::TYPE_PTRREL:
      return DataMetaType::PointerRel;
    case ghidra::TYPE_ARRAY:
      return DataMetaType::Array;
    case ghidra::TYPE_PARTIALSTRUCT:
      return DataMetaType::PartialStruct;
    case ghidra::TYPE_PARTIALUNION:
      return DataMetaType::PartialUnion;
    case ghidra::TYPE_STRUCT:
      return DataMetaType::Struct;
    case ghidra::TYPE_UNION:
      return DataMetaType::Union;
    case ghidra::TYPE_SPACEBASE:
      return DataMetaType::Spacebase;
    case ghidra::TYPE_UINT:
      return DataMetaType::UnsignedInt;
    case ghidra::TYPE_INT:
      return DataMetaType::Int;
    case ghidra::TYPE_BOOL:
      return DataMetaType::Bool;
    case ghidra::TYPE_CODE:
      return DataMetaType::Code;
    case ghidra::TYPE_FLOAT:
      return DataMetaType::Float;
    case ghidra::TYPE_UNKNOWN:
    default:
      return DataMetaType::Unknown;
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

DataSubMetaType ghidra_decompiler_get_type_submetatype(Datatype *t) {
  try {
    switch (t->getSubMeta()) {
    case ghidra::SUB_VOID:
      return DataSubMetaType::Void;
    case ghidra::SUB_SPACEBASE:
      return DataSubMetaType::Spacebase;
    case ghidra::SUB_PARTIALSTRUCT:
      return DataSubMetaType::PartialStruct;
    case ghidra::SUB_PARTIALUNION:
      return DataSubMetaType::PartialUnion;
    case ghidra::SUB_STRUCT:
      return DataSubMetaType::Struct;
    case ghidra::SUB_UNION:
      return DataSubMetaType::Union;
    case ghidra::SUB_INT_CHAR:
      return DataSubMetaType::Char;
    case ghidra::SUB_UINT_CHAR:
      return DataSubMetaType::UnsignedChar;
    case ghidra::SUB_INT_PLAIN:
      return DataSubMetaType::Int;
    case ghidra::SUB_UINT_PLAIN:
      return DataSubMetaType::UnsignedInt;
    case ghidra::SUB_INT_ENUM:
      return DataSubMetaType::Enum;
    case ghidra::SUB_UINT_ENUM:
      return DataSubMetaType::UnsignedEnum;
    case ghidra::SUB_INT_UNICODE:
      return DataSubMetaType::Unicode;
    case ghidra::SUB_UINT_UNICODE:
      return DataSubMetaType::UnsignedUnicode;
    case ghidra::SUB_BOOL:
      return DataSubMetaType::Bool;
    case ghidra::SUB_CODE:
      return DataSubMetaType::Code;
    case ghidra::SUB_FLOAT:
      return DataSubMetaType::Float;
    case ghidra::SUB_PTRREL_UNK:
      return DataSubMetaType::PointerRelUnknown;
    case ghidra::SUB_PTRREL:
      return DataSubMetaType::PointerRel;
    case ghidra::SUB_PTR:
      return DataSubMetaType::Pointer;
    case ghidra::SUB_PTR_STRUCT:
      return DataSubMetaType::PointerStruct;
    case ghidra::SUB_ARRAY:
      return DataSubMetaType::Array;
    case ghidra::SUB_UNKNOWN:
    default:
      return DataSubMetaType::Unknown;
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *ghidra_decompiler_get_type_typedef(Datatype *t) {
  try {
    return t->getTypedef();
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *ghidra_decompiler_get_type_pointee(Datatype *t) {
  try {
    if (auto p = dynamic_cast<TypePointer *>(t); p != nullptr) {
      return p->getPtrTo();
    } else {
      return nullptr;
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void ghidra_decompiler_get_type_function(Datatype *t, FunctionType &fp) {
  try {
    auto p = dynamic_cast<TypeCode *>(t);
    if (p == nullptr) {
      throw std::runtime_error("not a function");
    }

    auto proto = p->getPrototype();
    if (proto == nullptr) {
      throw std::runtime_error("function has no prototype");
    }

    fp.is_variadic = proto->isDotdotdot();
    fp.has_this_pointer = proto->hasThisPointer();
    fp.is_no_return = proto->isNoReturn();

    PrototypePieces pieces;
    proto->getPieces(pieces);

    fp.output_type = pieces.outtype;

    for (auto i = 0; i < proto->numParams(); ++i) {
      fp.inputs.push_back(FunctionInput{
          .name = rust::String(pieces.innames[i]),
          .type_ = pieces.intypes[i],
      });
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

DataTypeField ghidra_decompiler_get_type_field(Datatype *t, int32_t i) {
  try {
    if (auto p = dynamic_cast<TypeStruct *>(t); p != nullptr) {
      auto field = p->getField(i);
      return DataTypeField{
          .name = rust::String(field->name),
          .offset = static_cast<std::size_t>(field->offset),
          .type_ = field->type,
      };
    } else if (auto p = dynamic_cast<TypeUnion *>(t); p != nullptr) {
      auto field = p->getField(i);
      return DataTypeField{
          .name = rust::String(field->name),
          .offset = 0,
          .type_ = field->type,
      };
    } else {
      throw std::runtime_error("not a struct or union type");
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

int32_t ghidra_decompiler_get_type_num_fields(Datatype *t) {
  try {
    if (auto p = dynamic_cast<TypeStruct *>(t); p != nullptr) {
      return p->numDepend();
    } else if (auto p = dynamic_cast<TypeUnion *>(t); p != nullptr) {
      return p->numDepend();
    } else {
      throw std::runtime_error("not a struct or union type");
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

int32_t ghidra_decompiler_get_type_enum_variants(Datatype *t) {
  try {
    if (auto p = dynamic_cast<TypeEnum *>(t); p != nullptr) {
      return p->numDepend();
    } else {
      throw std::runtime_error("not an enum type");
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

int32_t ghidra_decompiler_get_type_size(Datatype *t) { return t->getSize(); }

int32_t ghidra_decompiler_get_type_align_size(Datatype *t) {
  return t->getAlignSize();
}

int32_t ghidra_decompiler_get_type_alignment(Datatype *t) {
  return t->getAlignment();
}

uint32_t ghidra_decompiler_get_type_flags(Datatype *t) { return t->getFlags(); }

Datatype *ghidra_decompiler_get_type_array_base(Datatype *t) {
  try {
    if (auto p = dynamic_cast<TypeArray *>(t); p != nullptr) {
      return p->getBase();
    } else {
      return nullptr;
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

int32_t ghidra_decompiler_get_type_array_num_elements(Datatype *t) {
  try {
    if (auto p = dynamic_cast<TypeArray *>(t); p != nullptr) {
      return p->numElements();
    } else {
      throw std::runtime_error("not an array type");
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void ghidra_decompiler_get_type_enum_variants(
    Datatype *t, rust::Vec<EnumVariant> &variants) {
  try {
    if (auto p = dynamic_cast<TypeEnum *>(t); p != nullptr) {
      for (auto it = p->beginEnum(); it != p->endEnum(); ++it) {
        auto [val, nm] = *it;
        variants.push_back(EnumVariant{
            .name = rust::String(nm),
            .value = val, // usize
        });
      }
    } else {
      throw std::runtime_error("not an enum type");
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::build_pointer_type(Datatype *t) {
  try {
    auto spc = arch->getDefaultCodeSpace();
    return arch->types->getTypePointer(spc->getAddrSize(), t,
                                       spc->getWordSize());
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::build_array_type(Datatype *t, size_t n) {
  try {
    return arch->types->getTypeArray(n, t);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::build_typedef(const std::string &name,
                                          Datatype *t) {
  try {
    return arch->types->getTypedef(t, name, 0, 0);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::build_typedef_with(const std::string &name,
                                               Datatype *t, bool rebuild) {
  try {
    return arch->types->getTypedef(t, name, 0, 0, rebuild);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::begin_struct_type(const std::string &name) {
  try {
    return arch->types->getTypeStruct(name);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *
GhidraDecompiler::end_struct_type(Datatype *t,
                                  const rust::Slice<const StructField> fields) {
  try {
    auto dt = reinterpret_cast<TypeStruct *>(t);
    auto tf = std::vector<TypeField>();
    auto fid = 0;

    for (auto tt : fields) {
      tf.push_back(TypeField(fid++, tt.offset, std::string(tt.name), tt.type_));
    }

    arch->types->setFields(tf, dt, -1, -1, 0);

    return t;
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::begin_union_type(const std::string &name) {
  try {
    return arch->types->getTypeUnion(name);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::end_union_type(
    Datatype *t, const rust::Slice<const UnionVariant> variants) {
  try {
    auto dt = reinterpret_cast<TypeUnion *>(t);
    auto tf = std::vector<TypeField>();
    auto fid = 0;

    for (auto tt : variants) {
      tf.push_back(TypeField(fid++, 0, std::string(tt.name), tt.type_));
    }

    arch->types->setFields(tf, dt, -1, -1, 0);

    return t;
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

Datatype *GhidraDecompiler::build_function_type(
    Datatype *output, const rust::Slice<rust::Str const> input_names,
    const rust::Slice<Datatype *const> input_types, bool variadic) {
  try {
    auto model = arch->defaultfp;
    auto names = std::vector<std::string>();
    auto types = std::vector<Datatype *>();

    for (const auto &input : input_names) {
      names.push_back(std::string(input));
    }

    for (auto input : input_types) {
      types.push_back(const_cast<Datatype *>(input));
    }

    return arch->types->getTypeCode(PrototypePieces{
        .model = model,
        .outtype = output,
        .intypes = types,
        .innames = names,
        .firstVarArgSlot = variadic ? static_cast<int4>(std::size(types)) : -1,
    });
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::remove_type(Datatype *t) {
  try {
    if (t == nullptr || t->isCoreType()) {
      return;
    }
    arch->types->destroyType(t);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_extern(const std::string &name, uint64_t ea) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto addr_ref = Address(arch->getDefaultCodeSpace(), 0);

    if (global->queryExternalRefFunction(addr)) {
      return;
    }

    global->addExternalRef(addr, addr_ref, name);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_function_symbol(const std::string &name, uint64_t ea,
                                           bool force) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      if (force) {
        global->removeSymbol(overlap->getSymbol());
      } else {
        return;
      }
    }

    global->addFunction(addr, name);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_function_symbol_with(
    const std::string &name, uint64_t ea, Datatype *output_type,
    const rust::Slice<rust::Str const> input_names,
    const rust::Slice<Datatype *const> input_types, bool variadic, bool force) {
  try {
    auto model = arch->defaultfp;
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      if (force) {
        global->removeSymbol(overlap->getSymbol());
      } else {
        return;
      }
    }

    auto names = std::vector<std::string>();
    for (const auto &name : input_names) {
      names.push_back(std::string(name));
    }

    auto types = std::vector<Datatype *>();
    for (const auto type : input_types) {
      types.push_back(type);
    }

    auto f = global->addFunction(addr, name);

    auto &p = f->getFunction()->getFuncProto();

    p.setInputLock(false);
    p.setOutputLock(false);

    p.updateAllTypes(PrototypePieces{
        .model = model,
        .name = name,
        .outtype = output_type,
        .intypes = std::vector<Datatype *>(std::begin(input_types),
                                           std::end(input_types)),
        .innames = std::vector<std::string>(std::begin(input_names),
                                            std::end(input_names)),
        .firstVarArgSlot =
            variadic ? static_cast<int4>(std::size(input_types)) : -1,
    });

    p.setInputLock(true);
    p.setOutputLock(true);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global(const std::string &name, uint64_t ea,
                                  Datatype *t) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock;

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, t, addr, Address());

    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_with(const std::string &name, uint64_t ea,
                                       Datatype *t, bool read_only) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock;

    if (read_only) {
      attr |= Varnode::readonly;
    }

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, t, addr, Address());

    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::set_range_read_only(uint64_t ea, size_t n) {
  if (n == 0) {
    return;
  }

  try {
    Range range(arch->getDefaultCodeSpace(), ea, ea + n - 1);
    arch->symboltab->setPropertyRange(Varnode::readonly, range);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::set_range_writable(uint64_t ea, size_t n) {
  if (n == 0) {
    return;
  }

  try {
    Range range(arch->getDefaultCodeSpace(), ea, ea + n - 1);
    arch->symboltab->clearPropertyRange(Varnode::readonly, range);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::set_non_returning_function(uint64_t ea) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);

    Funcdata *f = global->findFunction(addr);

    if (f == nullptr) {
      throw std::runtime_error(
          "cannot set function as non returning (no function "
          "identified at given address)");
    }

    f->getFuncProto().setNoReturn(true);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_ascii_char(const std::string &name,
                                             uint64_t ea) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock | Varnode::readonly;

    auto spc = arch->getDefaultDataSpace();
    auto t = arch->types->findByName("char");

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, t, addr, Address());
    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_ascii_string(const std::string &name,
                                               uint64_t ea, size_t n) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock | Varnode::readonly;

    auto spc = arch->getDefaultDataSpace();
    auto t = arch->types->findByName("char");
    auto tt = arch->types->getTypeArray(n, t);

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, tt, addr, Address());
    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_ascii_pointer(const std::string &name,
                                                uint64_t ea, size_t n) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock | Varnode::readonly;

    auto spc = arch->getDefaultDataSpace();
    auto t = arch->types->findByName("char");
    auto tt =
        arch->types->getTypePointer(spc->getAddrSize(), t, spc->getWordSize());

    while (n-- > 0) {
      tt = arch->types->getTypePointer(spc->getAddrSize(), tt,
                                       spc->getWordSize());
    }

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, tt, addr, Address());

    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_utf16_char(const std::string &name,
                                             uint64_t ea) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock | Varnode::readonly;

    auto spc = arch->getDefaultDataSpace();
    auto t = arch->types->findByName("char16_t");

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, t, addr, Address());

    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_utf16_string(const std::string &name,
                                               uint64_t ea, size_t n) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock | Varnode::readonly;

    auto spc = arch->getDefaultDataSpace();
    auto t = arch->types->findByName("char16_t");
    auto tt = arch->types->getTypeArray(n, t);

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, tt, addr, Address());
    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_global_utf16_pointer(const std::string &name,
                                                uint64_t ea, size_t n) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto addr = Address(arch->getDefaultCodeSpace(), ea);
    auto attr = Varnode::namelock | Varnode::typelock | Varnode::readonly;

    auto spc = arch->getDefaultDataSpace();
    auto t = arch->types->findByName("char16_t");
    auto tt =
        arch->types->getTypePointer(spc->getAddrSize(), t, spc->getWordSize());

    while (n-- > 0) {
      tt = arch->types->getTypePointer(spc->getAddrSize(), tt,
                                       spc->getWordSize());
    }

    SymbolEntry *overlap = global->queryContainer(addr, 1, Address());
    if (overlap != nullptr) {
      global->removeSymbol(overlap->getSymbol());
    }

    SymbolEntry *entry = global->addSymbol(name, tt, addr, Address());

    auto symbol = entry->getSymbol();
    global->setAttribute(symbol, attr);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::add_comment(rust::Str comment, uint64_t faddr,
                                   uint64_t addr) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address func_addr(arch->getDefaultCodeSpace(), faddr);
    Address comm_addr(arch->getDefaultCodeSpace(), addr);
    Funcdata *fd = global->findFunction(func_addr);
    if (!fd) {
      throw std::runtime_error("cannot add comment to function (no function "
                               "identified at given address)");
    }
    auto type = arch->print->getInstructionComment();
    arch->commentdb->addCommentNoDuplicate(type, func_addr, comm_addr,
                                           std::string(comment));
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::remove_comments(uint64_t faddr, uint64_t addr) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address func_addr(arch->getDefaultCodeSpace(), faddr);
    Address comm_addr(arch->getDefaultCodeSpace(), addr);
    Funcdata *fd = global->findFunction(func_addr);
    if (!fd) {
      throw std::runtime_error(
          "cannot remove comments in function (no function "
          "identified at given address)");
    }
    std::vector<Comment *> comments;
    for (auto iter = arch->commentdb->beginComment(func_addr);
         iter != arch->commentdb->endComment(func_addr); ++iter) {
      if ((*iter)->getAddr() == comm_addr) {
        comments.push_back(*iter);
      }
    }
    for (auto c : comments) {
      arch->commentdb->deleteComment(c);
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

rust::String GhidraDecompiler::decompile(uint64_t start_ea, uint64_t timeout) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), start_ea);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot decompile function (no function "
                               "identified at given address)");
    }

    int4 res = -1;
    std::string func_name = fd->getName();

    // NOTE: ensures fresh decompilation
    fd->clear();

    arch->allacts.getCurrent()->reset(*fd);
    arch->allacts.getCurrent()->resetTimeout(
        timeout == 0 ? std::nullopt
                     : std::make_optional(std::chrono::milliseconds(timeout)));
    res = arch->allacts.getCurrent()->perform(*fd);

    if (res < 0) {
      std::ostringstream os;

      arch->allacts.getCurrent()->printState(os);

      throw std::runtime_error(os.str());
    } else {
      std::stringstream ss;

      arch->print->setMarkup(false);
      arch->print->setIndentIncrement(2);
      arch->print->setOutputStream(&ss);

      arch->print->docFunction(fd);

      return rust::String(ss.str());
    }
  } catch (DecoderError &err) {
    throw std::runtime_error(err.explain);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::decompile_ast(uint64_t start_ea, uint64_t timeout,
                                     DecompilerAnnotationDB &mapper,
                                     rust::Vec<JumpTableInfo> &tables,
                                     rust::Vec<rust::String> &params,
                                     rust::Vec<HighVarWithType> &vars) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), start_ea);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot decompile function (no function "
                               "identified at given address)");
    }

    int4 res = -1;
    std::string func_name = fd->getName();

    // NOTE: ensures fresh decompilation
    fd->clear();

    arch->allacts.getCurrent()->reset(*fd);
    arch->allacts.getCurrent()->resetTimeout(
        timeout == 0 ? std::nullopt
                     : std::make_optional(std::chrono::milliseconds(timeout)));
    res = arch->allacts.getCurrent()->perform(*fd);

    /*
    if (fd->isProcComplete()) {
      res = 0;
    } else {
      arch->allacts.getCurrent()->reset(*fd);
      res = arch->allacts.getCurrent()->perform(*fd);
    }
    */

    if (res < 0) {
      std::ostringstream os;

      arch->allacts.getCurrent()->printState(os);

      throw std::runtime_error(os.str());
    } else {
      for (int4 i = 0; i < fd->numJumpTables(); ++i) {
        auto jt = fd->getJumpTable(i);
        auto branch = jt->getOpAddress().getOffset();
        auto entries = rust::Vec<uint64_t>();
        auto loads = rust::Vec<LoadTableInfo>();
        for (int4 j = 0; j < jt->numEntries(); ++j) {
          auto entry = jt->getAddressByIndex(j).getOffset();
          entries.push_back(entry);
        }
        for (int4 l = 0; l < jt->numLoadTables(); ++l) {
          auto load = jt->getLoadTableByIndex(l);
          loads.push_back(LoadTableInfo{
              .addr = static_cast<uint64_t>(load.getAddress().getOffset()),
              .size = static_cast<size_t>(load.getEntrySize()),
              .count = static_cast<size_t>(load.getNumEntries()),
          });
        }
        tables.push_back(JumpTableInfo{
            .branch = branch,
            .targets = std::move(entries),
            .tables = std::move(loads),
        });
      }

      auto proto = &fd->getFuncProto();
      auto num_params = proto->numParams();

      // Get parameter names
      for (auto i = 0; i < num_params; ++i) {
        auto param = proto->getParam(i);
        auto symbol = param->getSymbol();

        if (symbol) {
          // We have name and type--nothing more...
          auto name = symbol->getName();
          // auto dtype = symbol->getType(); // we can get size?
          params.push_back(rust::String(name));
        }
      }

      for (auto it = fd->beginLoc(); it != fd->endLoc(); ++it) {
        auto vnd = *it;
        if (!vnd->isAnnotation()) {
          auto high = vnd->getHigh();
          if (high->isMark()) {
            continue;
          }

          auto high_sym = high->getSymbol();
          if (high_sym) {
            auto usep = vnd->getUsePoint(*fd);

            // NOTE: we apply a mark to avoid duplicates
            high->setMark();

            // NOTE: this fixes Ghidra's use-point assignment for variables
            // that are used before they are written.
            if (!vnd->isWritten()) {
              usep = fd->getAddress();
            }

            auto space = vnd->getSpace();
            auto space_kind = SpaceKind::Register;

            if (space == arch->getUniqueSpace()) {
              space_kind = SpaceKind::Unique;
            } else if (space == arch->getStackSpace()) {
              space_kind = SpaceKind::Stack;
            }

            vars.push_back(HighVarWithType{
                .name = rust::String(high_sym->getName()),
                .addr = usep.getOffset(),
                .space = space_kind,
                .offset = static_cast<uint64_t>(vnd->getOffset()),
                .size = static_cast<uint32_t>(vnd->getSize()),
                .type_ = high->getType(),
            });
          }
        }
      }

      // clear marked variables
      for (auto it = fd->beginLoc(); it != fd->endLoc(); ++it) {
        auto vnd = *it;
        if (!vnd->isAnnotation()) {
          auto high = vnd->getHigh();
          if (high->getSymbol()) {
            high->clearMark();
          }
        }
      }

      std::stringstream ss;

      arch->print->setMarkup(true);
      arch->print->setIndentIncrement(2);
      arch->print->setOutputStream(&ss);

      arch->print->docFunction(fd);

      ParseCodeXML(fd, mapper, ss.str().c_str());
    }
  } catch (DecoderError &err) {
    throw std::runtime_error(err.explain);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::set_function_variable_type_at(
    uint64_t func_addr, const std::string &var_name, Datatype *ct) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), func_addr);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot update type for function (no function "
                               "identified at given address)");
    }

    Symbol *sym = nullptr;

    // first, try to find as a high variable
    auto high_var = fd->findHigh(var_name);
    if (high_var) {
      if (high_var->getType()->getSize() != ct->getSize()) {
        throw std::runtime_error(
            "cannot update type with new type of different size");
      }
      sym = high_var->getSymbol();
    }

    // if not found as high variable, check function parameters
    if (!sym) {
      auto proto = &fd->getFuncProto();
      auto num_params = proto->numParams();

      for (auto i = 0; i < num_params; ++i) {
        auto param = proto->getParam(i);
        if (param->getName() == var_name) {
          sym = param->getSymbol();
          break;
        }
      }
    }

    if (!sym) {
      throw std::runtime_error("no symbol found with name: " + var_name);
    }

    // retype (based on IfcRetype::execute)
    if (sym->getScope()->isGlobal()) {
      throw std::runtime_error("not overwriting type for global variable");
    }

    sym->getScope()->clearAttribute(sym, Varnode::typelock);

    if (sym->getCategory() == Symbol::function_parameter) {
      fd->getFuncProto().setInputLock(true);
    }

    sym->getScope()->retypeSymbol(sym, ct);
    sym->getScope()->setAttribute(sym, Varnode::typelock);

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

rust::String GhidraDecompiler::decompile_xml(uint64_t start_ea,
                                             uint64_t timeout) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), start_ea);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot decompile function (no function "
                               "identified at given address)");
    }

    int4 res = -1;
    std::string func_name = fd->getName();

    // NOTE: ensures fresh decompilation
    fd->clear();

    arch->allacts.getCurrent()->reset(*fd);
    arch->allacts.getCurrent()->resetTimeout(
        timeout == 0 ? std::nullopt
                     : std::make_optional(std::chrono::milliseconds(timeout)));
    res = arch->allacts.getCurrent()->perform(*fd);

    if (res < 0) {
      std::ostringstream os;

      arch->allacts.getCurrent()->printState(os);

      throw std::runtime_error(os.str());
    } else {
      std::stringstream ss;

      arch->print->setMarkup(true);
      arch->print->setIndentIncrement(2);
      arch->print->setOutputStream(&ss);

      arch->print->docFunction(fd);

      return rust::String(FormatXML(ss.str().c_str()));
    }
  } catch (DecoderError &err) {
    throw std::runtime_error(err.explain);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::function_signature(uint64_t start_ea, uint64_t timeout,
                                          uint32_t settings,
                                          int32_t max_dfg_iters,
                                          int32_t max_block_iters,
                                          int32_t max_varnodes,
                                          FunctionSignature &sig) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), start_ea);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot decompile function (no function "
                               "identified at given address)");
    }

    int4 res = -1;

    if (fd->isProcComplete()) {
      res = 0;
    } else {
      fd->clear();
      arch->allacts.getCurrent()->reset(*fd);
      arch->allacts.getCurrent()->resetTimeout(
          timeout == 0
              ? std::nullopt
              : std::make_optional(std::chrono::milliseconds(timeout)));
      res = arch->allacts.getCurrent()->perform(*fd);
    }

    if (res < 0) {
      std::ostringstream os;

      arch->allacts.getCurrent()->printState(os);

      throw std::runtime_error(os.str());
    } else {
      GraphSigManager gsm(settings);

      gsm.setMaxIteration(max_dfg_iters);
      gsm.setMaxBlockIteration(max_block_iters);
      gsm.setMaxVarnode(max_varnodes);

      gsm.setCurrentFunction(fd);
      gsm.generate();
      gsm.sortByHash();

      sig.overall_hash = 0x12349876abacab;
      sig.callees.reserve(gsm.numSignatures());

      for (const auto s : gsm) {
        auto feature_hash = s->getHash();
        sig.overall_hash = ghidra::hash_mixin(sig.overall_hash, feature_hash);
        sig.features.emplace_back(feature_hash);
      }

      auto numcalls = fd->numCalls();
      for (auto i = 0; i < numcalls; ++i) {
        FuncCallSpecs *fc = fd->getCallSpecs(i);
        const Address &addr(fc->getEntryAddress());
        if (!addr.isInvalid()) {
          sig.callees.emplace_back(addr.getOffset());
        }
      }

      sig.has_bad_data = fd->hasBadData();
      sig.has_unimplemented = fd->hasUnimplemented();
    }
  } catch (DecoderError &err) {
    throw std::runtime_error(err.explain);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::override_flow(uint64_t ea, uint64_t branch_ea,
                                     OverrideKind override_kind) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto space = arch->getDefaultCodeSpace();
    auto addr = Address(space, ea);

    Funcdata *f = global->findFunction(addr);

    if (f == nullptr) {
      throw std::runtime_error("cannot override function flow (no function "
                               "identified at given address)");
    }

    auto branch_addr = Address(space, branch_ea);

    f->getOverride().insertFlowOverride(branch_addr,
                                        static_cast<uint64_t>(override_kind));
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::override_jump_table(uint64_t ea, uint64_t switch_ea,
                                           rust::Vec<uint64_t> addr_table) {
  try {
    auto global = arch->symboltab->getGlobalScope();
    auto space = arch->getDefaultCodeSpace();
    auto addr = Address(space, ea);

    Funcdata *f = global->findFunction(addr);

    if (f == nullptr) {
      throw std::runtime_error("cannot override jump table (no function "
                               "identified at given address)");
    }

    auto switch_addr = Address(space, switch_ea);
    auto *jt = f->installJumpTable(switch_addr);

    if (jt == nullptr) {
      throw std::runtime_error("cannot override jump table (no jump table "
                               "identified at given address)");
    }

    std::vector<Address> adtable;
    adtable.reserve(addr_table.size());

    for (int4 i = 0; i < addr_table.size(); ++i) {
      adtable.push_back(Address(space, addr_table[i]));
    }

    jt->setOverride(adtable, switch_addr, 0, 0);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::clear_all() {
  try {
    arch->reinitialise();
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::register_call_fixup(const std::string &name,
                                           const std::string &snippet) {
  try {
    auto inject = reinterpret_cast<ghidra::PcodeInjectLibrarySleigh *>(
        arch->pcodeinjectlib);
    auto id = inject->manualCallFixup(name, snippet);

    if (id < 0) {
      throw std::runtime_error("cannot register fixup (invalid)");
    }
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::apply_call_fixup(const std::string &name, uint64_t ea) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), ea);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot apply fixup to function (no "
                               "function at given address)");
    }

    auto inject = reinterpret_cast<ghidra::PcodeInjectLibrarySleigh *>(
        arch->pcodeinjectlib);
    auto id = inject->getPayloadId(ghidra::InjectPayload::CALLFIXUP_TYPE, name);

    if (id < 0) {
      throw std::runtime_error("cannot apply fixup to function (no "
                               "fixup called " +
                               name + ")");
    }

    auto &p = fd->getFuncProto();
    p.setInjectId(id);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::clear_call_fixup(uint64_t ea) {
  try {
    Scope *global = arch->symboltab->getGlobalScope();
    Address addr(arch->getDefaultCodeSpace(), ea);
    Funcdata *fd = global->findFunction(addr);

    if (!fd) {
      throw std::runtime_error("cannot clear function fixup (no "
                               "function at given address)");
    }

    auto &p = fd->getFuncProto();
    p.cancelInjectId();
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

uint32_t GhidraDecompiler::get_variable(const std::string &nm,
                                        uint64_t ea) const {
  try {
    Address addr(arch->getDefaultCodeSpace(), ea);
    return arch->getSleigh().getContextVariable(nm, addr);
  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

void GhidraDecompiler::set_variable(const std::string &nm, uint64_t ea,
                                    uint32_t val) {
  try {
    Address addr(arch->getDefaultCodeSpace(), ea);

    arch->getSleigh().setContextVariable(nm, addr, val);
    arch->getSleigh().clearCaches();

  } catch (LowlevelError &err) {
    throw std::runtime_error(err.explain);
  }
}

DecompilerProjectRef &GhidraDecompiler::project_ref() {
  return arch->project_ref();
}

// ONCE
void ghidra_decompiler_init() {
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
}

// NOTE: requires mutex
void ghidra_decompiler_scan_for_sleigh_directories(const std::string &root) {
  SleighArchitecture::scanForSleighDirectories(root.c_str());
}

// NOTE: requires mutex
void ghidra_decompiler_push_sleigh_path(const std::string &path) {
  SleighArchitecture::specpaths.addDir2Path(path);
}
