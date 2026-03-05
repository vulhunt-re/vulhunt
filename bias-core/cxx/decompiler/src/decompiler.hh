#pragma once
#include <sstream>

#include "decompiler_arch.hh"
#include "libdecomp.hh"

using namespace ghidra;

enum class DecompileMode { DEFAULT, XML };

class Decompiler {
 public:
  std::stringstream *err_stream;
  DecompilerArch *arch = nullptr;
  Decompiler(std::string fname, std::string target) {
    filename = fname;
    sleigh_id = target;
  }
  ~Decompiler() {}
  bool ghidra_init(const char *sleighhomepath);
  void check_err_stream();
  bool decompile_at(uint64_t start_ea, DecompileMode mode, std::string &out);

  std::string get_filename() { return filename; }
  std::string get_target() { return sleigh_id; }

 private:
  std::string filename;
  std::string sleigh_id;
};
