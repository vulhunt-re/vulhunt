#include "decompiler_loadimage.hh"

using Address = ghidra::Address;
using LoadImage = ghidra::LoadImage;
using RangeList = ghidra::RangeList;

using LowlevelError = ghidra::LowlevelError;

using uint1 = ghidra::uint1;
using int4 = ghidra::int4;

void DecompilerLoadImage::loadFill(uint1 *ptr, int4 size,
                                   const Address &inaddr) {
#ifdef DEBUG
  std::cout << "DecompilerLoadImage::loadFill" << std::endl;
  std::cout << "size: " << std::hex << size << std::endl;
  std::cout << "offset: " << std::hex << inaddr.getOffset() << std::endl;
#endif
  read_bytes(ptr, size, inaddr);
}

void DecompilerLoadImage::getReadonly(RangeList& list) const {
#ifdef DEBUG
  std::cout << "DecompilerLoadImage::getReadonly" << std::endl;
#endif
  read_only_regions(list);
}

std::string DecompilerLoadImage::getArchType(void) const {
#ifdef DEBUG
  std::cout << "DecompilerLoadImage::getArchType" << std::endl;
#endif
  return "decompiler";
}

void DecompilerLoadImage::adjustVma(long adjust) {
#ifdef DEBUG
  std::cout << "DecompilerLoadImage::adjustVma" << std::endl;
#endif
  throw LowlevelError("Cannot adjust Decompiler virtual memory");
}
