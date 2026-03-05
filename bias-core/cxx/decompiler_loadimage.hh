#pragma once

#include <memory>

#include "decompiler_arch.hh"
#include "loadimage.hh"

using Address = ghidra::Address;
using LoadImage = ghidra::LoadImage;
using RangeList = ghidra::RangeList;

using uint1 = ghidra::uint1;
using int4 = ghidra::int4;

class DecompilerLoadImage : public LoadImage {
  DecompilerArch
      *arch; ///< The owning Architecture and connection to the client

public:
  DecompilerLoadImage(DecompilerArch *a)
      : LoadImage("program"), arch(a){}; ///< Constructor
  void loadFill(uint1 *ptr, int4 size, const Address &addr);
  void getReadonly(RangeList &list) const;
  std::string getArchType(void) const;
  void adjustVma(long adjust);

private:
  void read_bytes(uint1 *ptr, int4 size, const Address &inaddr) {
    arch->read_bytes(ptr, size, inaddr);
  }

  void read_only_regions(RangeList &list) const {
    arch->read_only_regions(list);
  }
};
