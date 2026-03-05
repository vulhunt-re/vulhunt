#include "decompiler_arch.hh"

#include "decompiler_loadimage.hh"
#include "decompiler_scope.hh"

using Address = ghidra::Address;
using Architecture = ghidra::Architecture;
using Database = ghidra::Database;
using DocumentStorage = ghidra::DocumentStorage;
using Scope = ghidra::Scope;
using Symbol = ghidra::Symbol;
using TypeFactory = ghidra::TypeFactory;

/// \brief Build the LoadImage object and load the executable image
///
/// \param store may hold configuration information
void DecompilerArch::buildLoader(DocumentStorage &store) {
  collectSpecFiles(*errorstream);
  loader = new DecompilerLoadImage(this);
}

void DecompilerArch::postSpecFile(void) {
  Architecture::postSpecFile();
  init_code_regions();
}

Scope *DecompilerArch::buildDatabase(DocumentStorage &store) {
  symboltab = new Database(this, true);
  Scope *globscope = new DecompilerScope(0, this);
  symboltab->attachScope(globscope, nullptr);
  return globscope;
}

void DecompilerArch::buildTypegrp(DocumentStorage &store) {
  types = new TypeFactory(this);
}

void DecompilerArch::buildCoreTypes(DocumentStorage &store) {
  types->setCoreType("void", 1, ghidra::TYPE_VOID, false);
  types->setCoreType("bool", 1, ghidra::TYPE_BOOL, false);
  types->setCoreType("uint8_t", 1, ghidra::TYPE_UINT, false);
  types->setCoreType("uint16_t", 2, ghidra::TYPE_UINT, false);
  types->setCoreType("uint32_t", 4, ghidra::TYPE_UINT, false);
  types->setCoreType("uint64_t", 8, ghidra::TYPE_UINT, false);
  types->setCoreType("int8_t", 1, ghidra::TYPE_INT, false);
  types->setCoreType("int16_t", 2, ghidra::TYPE_INT, false);
  types->setCoreType("int32_t", 4, ghidra::TYPE_INT, false);
  types->setCoreType("int64_t", 8, ghidra::TYPE_INT, false);
  types->setCoreType("float", 4, ghidra::TYPE_FLOAT, false);
  types->setCoreType("double", 8, ghidra::TYPE_FLOAT, false);
  types->setCoreType("__float80", 10, ghidra::TYPE_FLOAT, false);
  types->setCoreType("long double", 16, ghidra::TYPE_FLOAT, false);
  types->setCoreType("bits8_t", 1, ghidra::TYPE_UNKNOWN, false);
  types->setCoreType("bits16_t", 2, ghidra::TYPE_UNKNOWN, false);
  types->setCoreType("bits32_t", 4, ghidra::TYPE_UNKNOWN, false);
  types->setCoreType("bits64_t", 8, ghidra::TYPE_UNKNOWN, false);
  types->setCoreType("funcptr_t", 1, ghidra::TYPE_CODE, false);
  types->setCoreType("char", 1, ghidra::TYPE_INT, true);
  types->setCoreType("unsigned char", 1, ghidra::TYPE_UINT, true);
  types->setCoreType("char16_t", 2, ghidra::TYPE_INT, true);
  types->setCoreType("char32_t", 4, ghidra::TYPE_INT, true);

  types->cacheCoreTypes();
}

void DecompilerArch::buildAction(DocumentStorage &store) {
  parseExtraRules(store);
  allacts.universalAction(this);
  allacts.resetDefaults();

  allacts.cloneGroup("decompile", "decompile-deuglified");
  allacts.removeFromGroup(
      "decompile-deuglified",
      "fixateglobals"); // NOTE: from Rizin: this action (ActionMapGlobals) will
                        // create these ugly uRam0x12345s
  allacts.setCurrent("decompile-deuglified");
}

Symbol *DecompilerArch::getSymbol(const Address &addr) { return nullptr; }

void DecompilerArch::reinitialise() {
  Database *old_symboltab = symboltab;

  symboltab = new Database(this, true);
  Scope *globscope = new DecompilerScope(0, this);
  symboltab->attachScope(globscope, nullptr);
  symboltab->setRange(globscope, reinterpret_cast<DecompilerScope *>(
                                     old_symboltab->getGlobalScope())
                                     ->getRanges());
  symboltab->setProperties(old_symboltab->getProperties());
  symboltab->adjustCaches();

  // FIXME: we should restore the context database
  // getSleigh().reset(arch->loader, arch->context);
  getSleigh().clearCaches();
  types->clearNoncore();

  /*
  postSpecFile();
  fillinReadOnlyFromLoader();
  */

  delete old_symboltab;
}
