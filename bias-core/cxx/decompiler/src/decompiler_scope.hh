#pragma once
#include "decompiler_loadimage.hh"

using namespace ghidra;

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
  DecompilerArch *decompiler_arch;  ///< Architecture and connection to the
                                    ///< decompiler client
  Symbol *decompiler_query(
      const Address &addr) const;  ///< Process a query that missed the cache
 public:
  DecompilerScope(uint64_t id, DecompilerArch *g);  ///< Constructor

  virtual ~DecompilerScope(void);
  virtual SymbolEntry *addSymbol(const string &name, Datatype *ct,
                                 const Address &addr, const Address &usepoint);
  virtual string buildVariableName(const Address &addr, const Address &pc,
                                   Datatype *ct, int4 &index,
                                   uint4 flags) const;
  virtual string buildUndefinedName(void) const;

  virtual SymbolEntry *findAddr(const Address &addr,
                                const Address &usepoint) const;
  virtual SymbolEntry *findContainer(const Address &addr, int4 size,
                                     const Address &usepoint) const;
  virtual Funcdata *findFunction(const Address &addr) const;
  virtual ExternRefSymbol *findExternalRef(const Address &addr) const;
  virtual LabSymbol *findCodeLabel(const Address &addr) const;
  virtual Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const;

  virtual void findByName(const string &name, vector<Symbol *> &res) const;
};
