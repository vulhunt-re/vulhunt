#pragma once

#include "decompiler_loadimage.hh"

using Address = ghidra::Address;
using Datatype = ghidra::Datatype;
using ExternRefSymbol = ghidra::ExternRefSymbol;
using Funcdata = ghidra::Funcdata;
using LabSymbol = ghidra::LabSymbol;
using RangeList = ghidra::RangeList;
using ScopeInternal = ghidra::ScopeInternal;
using Symbol = ghidra::Symbol;
using SymbolEntry = ghidra::SymbolEntry;
using Varnode = ghidra::Varnode;

using int4 = ghidra::int4;
using uint4 = ghidra::uint4;

/// \brief An implementation of the Scope interface by querying a decompier for
/// Symbol information
///
/// This object is generally instantiated once for an executable and
/// acts as the \e global \e scope for the decompiler.
/// This object fields queries for all scopes above functions.
/// Responses may be for Symbol objects that are not global but belong to
/// sub-scopes, like \e namespace and function Scopes.  This object will build
/// any new Scope or Funcdata, object as necessary and stick the Symbol in,
/// returning as if the new Scope had caught the query in the first place.
class DecompilerScope : public ScopeInternal {
  DecompilerArch *decompiler_arch; ///< Architecture and connection to the

  Symbol *decompiler_query(
      const Address &addr) const; ///< Process a query that missed the cache
public:
  DecompilerScope(uint64_t id, DecompilerArch *g); ///< Constructor

  virtual ~DecompilerScope(void);
  SymbolEntry *addSymbol(const std::string &name, Datatype *ct,
                         const Address &addr, const Address &usepoint) override;
  std::string buildVariableName(const Address &addr, const Address &pc,
                                Datatype *ct, int4 &index,
                                uint4 flags) const override;
  std::string buildUndefinedName(void) const override;

  SymbolEntry *findAddr(const Address &addr,
                        const Address &usepoint) const override;
  SymbolEntry *findContainer(const Address &addr, int4 size,
                             const Address &usepoint) const override;
  Funcdata *findFunction(const Address &addr) const override;
  ExternRefSymbol *findExternalRef(const Address &addr) const override;
  LabSymbol *findCodeLabel(const Address &addr) const override;
  Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const override;
  Datatype *findDataType(const Address &addr,
                         const Varnode *vnd) const override;
  void applyNamesViaCallback(Funcdata &data) const override;

  void findByName(const std::string &name,
                  std::vector<Symbol *> &res) const override;

  const RangeList &getRanges() const { return getRangeTree(); };
};
