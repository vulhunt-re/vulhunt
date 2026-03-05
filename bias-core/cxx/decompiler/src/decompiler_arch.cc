#include "decompiler_arch.hh"

#include "decompiler_loadimage.hh"
#include "decompiler_scope.hh"

/// \brief Build the LoadImage object and load the executable image
///
/// \param store may hold configuration information
void DecompilerArch::buildLoader(DocumentStorage &store) {
  collectSpecFiles(*errorstream);
  loader = new DecompilerLoadImage(this);
}

void DecompilerArch::postSpecFile(void) {}

Scope *DecompilerArch::buildDatabase(DocumentStorage &store) {
  symboltab = new Database(this, true);
  Scope *globscope = new DecompilerScope(0, this);
  symboltab->attachScope(globscope, NULL);
  return globscope;
}

Symbol *DecompilerArch::getSymbol(const Address &addr) { return NULL; }
