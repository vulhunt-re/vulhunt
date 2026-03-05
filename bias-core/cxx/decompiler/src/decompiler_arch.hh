#pragma once
#include "architecture.hh"
#include "sleigh_arch.hh"

using namespace ghidra;

class DecompilerArch : public SleighArchitecture {
 public:
  DecompilerArch(const std::string &fname, const std::string &targ, std::ostream *estream)
      : SleighArchitecture(fname, targ, estream){};

 protected:
  /// \brief Build the LoadImage object and load the executable image
  ///
  /// \param store may hold configuration information
  virtual void buildLoader(DocumentStorage &store);

  // Factory routines for building this architecture
  virtual Scope *buildDatabase(
      DocumentStorage &store);  ///< Build the global scope for this executable

  virtual void postSpecFile(
      void);  ///< Let components initialize after Translate is built

  Symbol *getSymbol(const Address &addr);
};
