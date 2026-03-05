#include "decompiler_scope.hh"

/// \param id is the globally unique id associated with the scope
/// \param g is the Architecture and decompiler interface
DecompilerScope::DecompilerScope(uint64_t id, DecompilerArch *g)
    : ScopeInternal(id, "", g), decompiler_arch(g) {}

DecompilerScope::~DecompilerScope(void) {}

// Determine if a symbol is associated with the given address
Symbol *DecompilerScope::decompiler_query(const Address &addr) const {
  Symbol *sym = NULL;
  uint64_t ea = addr.getOffset();
  std::stringstream sn;
  sn << "sym_" << std::hex << ea;

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
  std::cout << "DecompilerScope::findExternalRef" << std::endl;
#endif
  return ScopeInternal::findExternalRef(addr);
}

Funcdata *DecompilerScope::findFunction(const Address &addr) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findFunction" << std::endl;
#endif
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

Funcdata *DecompilerScope::resolveExternalRefFunction(
    ExternRefSymbol *sym) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::resolveExternalRefFunction" << std::endl;
#endif
  return ScopeInternal::resolveExternalRefFunction(sym);
}

SymbolEntry *DecompilerScope::addSymbol(const string &name, Datatype *ct,
                                        const Address &addr,
                                        const Address &usepoint) {
#ifdef DEBUG
  std::cout << "DecompilerScope::addSymbol" << std::endl;
#endif
  return ScopeInternal::addSymbol(name, ct, addr, usepoint);
}

string DecompilerScope::buildVariableName(const Address &addr,
                                          const Address &pc, Datatype *ct,
                                          int4 &index, uint4 flags) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::buildVariableName" << std::endl;
#endif
  return ScopeInternal::buildVariableName(addr, pc, ct, index, flags);
}

string DecompilerScope::buildUndefinedName(void) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::buildUndefinedName" << std::endl;
#endif
  return ScopeInternal::buildUndefinedName();
}

void DecompilerScope::findByName(const string &name,
                                 vector<Symbol *> &res) const {
#ifdef DEBUG
  std::cout << "DecompilerScope::findByName" << std::endl;
#endif
  return ScopeInternal::findByName(name, res);
}
