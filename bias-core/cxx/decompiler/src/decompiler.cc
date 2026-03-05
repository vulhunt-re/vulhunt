#include "decompiler.hh"

#include "marshal.hh"

using namespace ghidra;

bool Decompiler::ghidra_init(const char *sleighhomepath) {
  std::vector<std::string> extrapaths;
  startDecompilerLibrary(sleighhomepath, extrapaths);
  err_stream = new std::stringstream();
  arch = new DecompilerArch(filename, sleigh_id, err_stream);
  DocumentStorage store;
  std::string errmsg;
  bool iserror = false;
  try {
    arch->init(store);
  } catch (DecoderError &err) {
    errmsg = err.explain;
    iserror = true;
  } catch (LowlevelError &err) {
    errmsg = err.explain;
    iserror = true;
  }
  if (iserror) {
    std::cout << errmsg << std::endl;
    std::cout << "Could not create architecture" << std::endl;
    delete arch;
    arch = NULL;
    return false;
  }
  std::cout << "Ghidra architecture successfully created" << std::endl;

  return true;
}

void Decompiler::check_err_stream() {
  if (err_stream->tellp()) {
    std::cout << err_stream->str() << std::endl;
    err_stream->str("");
  }
}

bool Decompiler::decompile_at(uint64_t start_ea, DecompileMode mode,
                              std::string &out) {
  Scope *global = arch->symboltab->getGlobalScope();
  Address addr(arch->getDefaultCodeSpace(), start_ea);
  Funcdata *fd = global->findFunction(addr);
  if (!fd) {
    std::cout << "Can not find function" << std::endl;
    return false;
  }
  int4 res = -1;
  std::string func_name = fd->getName();

  arch->clearAnalysis(fd);
  arch->allacts.getCurrent()->reset(*fd);
  res = arch->allacts.getCurrent()->perform(*fd);
  if (res < 0) {
    std::ostringstream os;
    arch->allacts.getCurrent()->printState(os);
    std::cout << "Break at " << os.str() << std::endl;
  } else {
    std::cout << "Decompilation complete" << std::endl;

    std::stringstream ss;
    arch->print->setIndentIncrement(2);
    arch->print->setOutputStream(&ss);

    switch (mode) {
      case (DecompileMode::DEFAULT):
        // print as C
        arch->print->docFunction(fd);
        break;
      case (DecompileMode::XML):
        // print as XML
        XmlEncode enc(ss);
        fd->encode(enc, 0, true);
        break;
    }
    out = ss.str();
    ss.str("");
  }

  check_err_stream();

  return true;
}
