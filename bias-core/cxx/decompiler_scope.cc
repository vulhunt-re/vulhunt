#include <algorithm>
#include <set>

#include "bridge.hh"
#include "decompiler_scope.hh"

#include "funcdata.hh"

using Address = ghidra::Address;
using AddrSpace = ghidra::AddrSpace;
using Datatype = ghidra::Datatype;
using ExternRefSymbol = ghidra::ExternRefSymbol;
using Funcdata = ghidra::Funcdata;
using FunctionSymbol = ghidra::FunctionSymbol;
using HighVariable = ghidra::HighVariable;
using LabSymbol = ghidra::LabSymbol;
using ScopeInternal = ghidra::ScopeInternal;
using Symbol = ghidra::Symbol;
using SymbolEntry = ghidra::SymbolEntry;
using Varnode = ghidra::Varnode;

using int4 = ghidra::int4;
using uint4 = ghidra::uint4;

/// \param id is the globally unique id associated with the scope
/// \param g is the Architecture and decompiler interface
DecompilerScope::DecompilerScope(uint64_t id, DecompilerArch *g)
    : ScopeInternal(id, "", g), decompiler_arch(g) { }

DecompilerScope::~DecompilerScope(void) {}

// Determine if a symbol is associated with the given address
Symbol *DecompilerScope::decompiler_query(const Address &addr) const {
  Symbol *sym = NULL;
  uint64_t ea = addr.getOffset();
  std::stringstream sn;
  sn << "sub_" << std::hex << ea;

  DecompilerScope *scope =
      dynamic_cast<DecompilerScope *>(glb->symboltab->getGlobalScope());
  sym = new FunctionSymbol(scope, sn.str(), glb->min_funcsymbol_size);
  if (sym) {
    scope->addSymbolInternal(sym);
    scope->addMapPoint(sym, addr, Address());
  }
  return sym;
}

SymbolEntry *DecompilerScope::findAddr(const Address &addr,
                                       const Address &usepoint) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findAddr" << std::endl;
#endif
  return ScopeInternal::findAddr(addr, usepoint);
}

SymbolEntry *DecompilerScope::findContainer(const Address &addr, int4 size,
                                            const Address &usepoint) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findContainer" << std::endl;
#endif
  return ScopeInternal::findContainer(addr, size, usepoint);
}

ExternRefSymbol *DecompilerScope::findExternalRef(const Address &addr) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findExternalRef " << addr << std::endl;
#endif
  return ScopeInternal::findExternalRef(addr);
}

Funcdata *DecompilerScope::findFunction(const Address &addr) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findFunction" << std::endl;
#endif
  if (!decompiler_arch->inside_code_region(addr)) {
    return NULL;
  }

  Funcdata *fd = ScopeInternal::findFunction(addr);
  if (fd == NULL) {
    FunctionSymbol *sym;
    sym = dynamic_cast<FunctionSymbol *>(decompiler_query(addr));
    if (sym != NULL) {
      fd = sym->getFunction();
    }
  }
  return fd;
}

LabSymbol *DecompilerScope::findCodeLabel(const Address &addr) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findCodeLabel" << std::endl;
#endif
  return ScopeInternal::findCodeLabel(addr);
}

Funcdata *
DecompilerScope::resolveExternalRefFunction(ExternRefSymbol *sym) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::resolveExternalRefFunction" << std::endl;
#endif
  return ScopeInternal::resolveExternalRefFunction(sym);
}

SymbolEntry *DecompilerScope::addSymbol(const std::string &name, Datatype *ct,
                                        const Address &addr,
                                        const Address &usepoint) {
#ifdef DEBUG
  std::cout << "DecompilerScope::addSymbol" << std::endl;
#endif
  return ScopeInternal::addSymbol(name, ct, addr, usepoint);
}

std::string DecompilerScope::buildVariableName(const Address &addr,
                                               const Address &pc, Datatype *ct,
                                               int4 &index, uint4 flags) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::buildVariableName" << std::endl;
#endif
  return ScopeInternal::buildVariableName(addr, pc, ct, index, flags);
}

std::string DecompilerScope::buildUndefinedName(void) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::buildUndefinedName" << std::endl;
#endif
  return ScopeInternal::buildUndefinedName();
}

void DecompilerScope::findByName(const std::string &name,
                                 std::vector<Symbol *> &res) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findByName" << std::endl;
#endif
  return ScopeInternal::findByName(name, res);
}

Datatype *DecompilerScope::findDataType(const Address &addr,
                                        const Varnode *vnd) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findDataType" << std::endl;
#endif
  Datatype *t = decompiler_arch->type_at(addr, vnd);
  return t == nullptr ? ScopeInternal::findDataType(addr, vnd) : t;
}

void DecompilerScope::applyNamesViaCallback(Funcdata &data) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::applyNamesViaCallback" << std::endl;
#endif
  std::vector<uint64_t> uses;
  std::set<std::string> symbols;

  /*
  ostringstream s;
  data.getScopeLocal()->printEntries(s);

  std::cout << s.str() << std::endl;
  */

  auto scope = data.getScopeLocal();

  for (auto iter = scope->begin(); iter != scope->end(); ++iter) {
    SymbolEntry *en = const_cast<SymbolEntry *>(*iter);
    Varnode *vn = data.findLinkedVarnode(en);

    if (vn != (Varnode *)0) {
      continue;
    }

    auto addr = en->getAddr();
    auto space = addr.getSpace();

    if (space == (AddrSpace *)0 || space->getType() == ghidra::IPTR_CONSTANT) {
      continue;
    }

    auto sym = en->getSymbol();
    auto name = sym->getName();
    auto type_ = sym->getType();
    auto size = en->getSize();
    auto space_kind = SpaceKind::Register;

    if (space == decompiler_arch->getUniqueSpace()) {
      space_kind = SpaceKind::Unique;
    } else if (space == decompiler_arch->getStackSpace()) {
      space_kind = SpaceKind::Stack;
    } else if (space == decompiler_arch->getDefaultDataSpace()) {
      space_kind = SpaceKind::Global;
    }

    auto var_info = VarInfo{
        .space = space_kind,
        .offset = static_cast<uint64_t>(addr.getOffset()),
        .size = static_cast<uint32_t>(size),
    };

    auto rename = decompiler_arch->update_name(
        var_info, name,
        rust::Slice(static_cast<const uint64_t *>(uses.data()), uses.size()),
        type_);

    if (!rename.empty()) {
      std::string renamed = std::string(scope->makeNameUnique(std::string(rename)));
      sym->getScope()->renameSymbol(sym, renamed);
      symbols.insert(renamed);
    } else {
      symbols.insert(name);
    }
  }

  for (int4 i = 0; i < decompiler_arch->numSpaces(); ++i) {
    auto spc = decompiler_arch->getSpace(i);
    if (spc == (AddrSpace *)0 || spc->getType() == ghidra::IPTR_CONSTANT) {
      continue;
    }
    auto enditer = data.endLoc(spc);
    for (auto iter = data.beginLoc(spc); iter != enditer; ++iter) {
      Varnode *curvn = *iter;
      if (curvn->isAnnotation()) {
        continue;
      }

      Varnode *vnd = curvn->getHigh()->getNameRepresentative();
      if (vnd != curvn) {
        continue; // Hit each high only once
      }

      HighVariable *high = vnd->getHigh();
      if (!high->hasName()) {
        continue;
      }

      Symbol *sym = data.linkSymbol(vnd);
      if (sym != (Symbol *)0) {
        if (symbols.find(sym->getName()) != std::end(symbols)) {
          continue;
        }

        if (sym->isSizeTypeLocked()) {
          if (vnd->getSize() == sym->getType()->getSize())
            sym->getScope()->overrideSizeLockType(sym, high->getType());
        }

        auto space = vnd->getSpace();
        auto space_kind = SpaceKind::Register;
        auto type_ = sym->getType();

        auto name = sym->getName();
        auto offset = vnd->getOffset();
        auto size = vnd->getSize();

        if (space == decompiler_arch->getUniqueSpace()) {
          space_kind = SpaceKind::Unique;
        } else if (space == decompiler_arch->getStackSpace()) {
          space_kind = SpaceKind::Stack;
        } else if (space == decompiler_arch->getDefaultDataSpace()) {
          space_kind = SpaceKind::Global;
        }

        auto var_info = VarInfo{
            .space = space_kind,
            .offset = static_cast<uint64_t>(vnd->getOffset()),
            .size = static_cast<uint32_t>(vnd->getSize()),
        };

        uses.clear();

        std::sort(uses.begin(), uses.end());
        std::unique(uses.begin(), uses.end());

        for (auto vi = 0; vi < high->numInstances(); ++vi) {
          auto vn = high->getInstance(vi);
          auto usep = vn->getUsePoint(data);

          if (!vn->isWritten()) {
            usep = data.getAddress();
          }

          uses.push_back(static_cast<uint64_t>(usep.getOffset()));
        }

        auto rename = decompiler_arch->update_name(
            var_info, name,
            rust::Slice(static_cast<const uint64_t *>(uses.data()),
                        uses.size()),
            type_);

        if (!rename.empty()) {
          std::string renamed = std::string(scope->makeNameUnique(std::string(rename)));
          sym->getScope()->renameSymbol(sym, renamed);
          symbols.insert(renamed);
        } else {
          symbols.insert(name);
        }
      }
    }
  }
}
