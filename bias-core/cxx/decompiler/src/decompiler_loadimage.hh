#pragma once
#include <cstring>
#include <fstream>
#include <iostream>

#include "decompiler_arch.hh"
#include "loadimage.hh"

using namespace ghidra;

class DecompilerLoadImage : public LoadImage {
  DecompilerArch
      *arch;  ///< The owning Architecture and connection to the client
 public:
  DecompilerLoadImage(DecompilerArch *a);  ///< Constructor
  void loadFill(uint1 *ptr, int4 size, const Address &addr);
  std::string getArchType(void) const;
  void adjustVma(long adjust);

 private:
  char *file_buffer = nullptr;
  void load_image() {
    std::ifstream file(arch->getFilename(), std::ios::binary);
    if (file) {
      file.seekg(0, std::ios::end);
      std::streampos fsize = file.tellg();
      file.seekg(0, std::ios::beg);
      file_buffer = new char[fsize];
      file.read(file_buffer, fsize);
    } else {
      std::cout << "Could not open input file" << std::endl;
    }
    file.close();
  }

  void read_bytes(uint1 *ptr, int4 size, const Address &inaddr) {
    if (file_buffer) {
      std::memcpy(ptr, file_buffer + inaddr.getOffset(), size);
    }
  }
};
