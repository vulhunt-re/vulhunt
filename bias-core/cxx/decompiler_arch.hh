#pragma once

#include <memory>
#include <set>
#include <sstream>

#include "bridge.hh"

#include "architecture.hh"
#include "decompiler.hh"
#include "loadimage.hh"
#include "sleigh_arch.hh"
#include "type.hh"

using Address = ghidra::Address;
using Datatype = ghidra::Datatype;
using DocumentStorage = ghidra::DocumentStorage;
using Funcdata = ghidra::Funcdata;
using Range = ghidra::Range;
using RangeList = ghidra::RangeList;
using Scope = ghidra::Scope;
using SleighArchitecture = ghidra::SleighArchitecture;
using Symbol = ghidra::Symbol;
using Varnode = ghidra::Varnode;

using DataUnavailError = ghidra::DataUnavailError;
using LowlevelError = ghidra::LowlevelError;

using int4 = ghidra::int4;
using uint1 = ghidra::uint1;
using uintb = ghidra::uintb;

class DecompilerArch : public SleighArchitecture {
public:
  DecompilerArch(const std::string &targ, rust::Box<DecompilerProjectRef> project,
                 GhidraDecompiler *d, std::ostream *estream)
      : SleighArchitecture("", targ, estream), project(std::move(project)),
        decompiler(d){};

  void read_bytes(uint1 *ptr, int4 size, const Address &inaddr) {
    try {
      return project->read_bytes(inaddr.getOffset(), size, ptr);
    } catch (rust::Error &ex) {
      throw DataUnavailError(ex.what());
    }
  }

  void read_only_regions(RangeList &list) {
    try {
      auto ranges = project->read_only_regions();
      insert_ranges(list, ranges);
    } catch (rust::Error &ex) {
      throw LowlevelError(ex.what());
    }
  }

  rust::String update_name(VarInfo var_info, std::string const &name,
                           rust::Slice<const uint64_t> uses, Datatype *dtype) const {
    try {
      return project->update_name(decompiler, var_info, name, uses, dtype);
    } catch (rust::Error &ex) {
      throw LowlevelError(ex.what());
    }
  }

  Datatype *type_at(const Address &addr, const Varnode *vnd) const {
    auto space = vnd->getSpace();
    auto space_kind = SpaceKind::Register;

    if (space == getConstantSpace()) {
      return nullptr;
    }

    if (space == getUniqueSpace()) {
      space_kind = SpaceKind::Unique;
    } else if (space == getStackSpace()) {
      space_kind = SpaceKind::Stack;
    } else if (space == getDefaultDataSpace()) {
      space_kind = SpaceKind::Global;
    }

    auto var = VarInfo{
        .space = space_kind,
        .offset = static_cast<uint64_t>(vnd->getOffset()),
        .size = static_cast<uint32_t>(vnd->getSize()),
    };

    try {
      return project->type_at(decompiler, addr.getOffset(), var);
    } catch (rust::Error &ex) {
      throw LowlevelError(ex.what());
    }
  }

  bool inside_code_region(const Address &addr) const {
    if (addr.isInvalid()) {
      return false;
    }

    if (code.empty()) {
      return true;
    }

    uintb offset = addr.getOffset();
    std::set<Range>::iterator iter = code.upper_bound(Range(addr.getSpace(), offset, offset));

    if (iter == code.begin()) {
      return false;
    }

    // equal to end() or another value not begin so this is not UB
    --iter;
    return iter->contains(addr);
  }

  DecompilerProjectRef &project_ref() {
    return *project;
  }

  void reinitialise();

protected:
  /// \brief Build the LoadImage object and load the executable image
  ///
  /// \param store may hold configuration information
  virtual void buildLoader(DocumentStorage &store);

  // Factory routines for building this architecture
  virtual Scope *buildDatabase(
      DocumentStorage &store); ///< Build the global scope for this executable
  virtual void buildTypegrp(DocumentStorage &store);
  virtual void buildCoreTypes(DocumentStorage &store);
  virtual void buildAction(DocumentStorage &store);

  virtual void
  postSpecFile(void); ///< Let components initialize after Translate is built

  Symbol *getSymbol(const Address &addr);

private:
  rust::Box<DecompilerProjectRef> project;
  GhidraDecompiler *decompiler;
  std::set<Range> code;

  void init_code_regions() {
    try {
      RangeList list;

      auto ranges = project->code_regions();
      insert_ranges(list, ranges);

      for (auto range : list) {
        code.insert(range);
      }
    } catch (rust::Error &ex) {
      throw LowlevelError(ex.what());
    }
  }

  void insert_ranges(RangeList &list, rust::Vec<AddressRange> ranges) {
    auto spc = getDefaultCodeSpace();
    if (spc == nullptr) {
      return;
    }

    for (auto range : ranges) {
      if (range.size != 0) {
        list.insertRange(spc, range.addr, range.addr + range.size - 1);
      }
    }
  }
};
