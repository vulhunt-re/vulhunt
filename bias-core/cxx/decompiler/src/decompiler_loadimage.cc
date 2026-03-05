#include "decompiler_loadimage.hh"

DecompilerLoadImage::DecompilerLoadImage(DecompilerArch *a)
    : LoadImage("program") {
  arch = a;
  load_image();
}

void DecompilerLoadImage::loadFill(uint1 *ptr, int4 size,
                                   const Address &inaddr) {
#ifdef DEBUG
  std::cout << "DecompilerLoadImage::loadFill" << std::endl;
  std::cout << "size: " << std::hex << size << std::endl;
  std::cout << "offset: " << std::hex << inaddr.getOffset() << std::endl;
#endif
  read_bytes(ptr, size, inaddr);
}

string DecompilerLoadImage::getArchType(void) const {
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
