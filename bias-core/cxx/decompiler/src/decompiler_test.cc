#include "decompiler.hh"

#include <iostream>
#include <sstream>

int main() {
  const char *sleighhomepath = getenv("GHIDRA_DIR");
  std::string fname = "spectre.out";
  std::ifstream file(fname);
  if (!file) {
    std::cout << "Could not find input file" << std::endl;
    return -1;
  }
  std::string targ = "x86:LE:64:default:gcc";

  // init decompiler
  Decompiler *decompiler = new Decompiler(fname, targ);

  // init ghidra
  if (!decompiler->ghidra_init(sleighhomepath)) {
    delete decompiler;
    return -1;
  }

  std::string out;

  // try to decompile
  uint64_t start_ea = 0x1716;
  decompiler->decompile_at(start_ea, DecompileMode::DEFAULT, out);
  // decompiler->decompile_at(start_ea, DecompileMode::XML, out);
  std::cout << out << std::endl;

  start_ea = 0x12CD;
  decompiler->decompile_at(start_ea, DecompileMode::DEFAULT, out);
  // decompiler->decompile_at(start_ea, DecompileMode::XML, out);
  std::cout << out << std::endl;

  delete decompiler;

  return 0;
}
