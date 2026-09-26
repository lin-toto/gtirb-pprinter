//===- CapstoneCompat.hpp ---------------------------------------*- C++ -*-===//
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//===----------------------------------------------------------------------===//
//
// Capstone 6 helpers shared by gtirb-pprinter and ddisasm.
//
// Both tools were written against Capstone 5.0.1. This header holds what both
// need to keep their Capstone 5 behaviour on Capstone 6; ddisasm includes it
// as <gtirb_pprinter/CapstoneCompat.hpp>.
//
//===----------------------------------------------------------------------===//
#ifndef GTIRB_PP_CAPSTONE_COMPAT_H
#define GTIRB_PP_CAPSTONE_COMPAT_H

#include <capstone/capstone.h>

#if CS_API_MAJOR < 6
#error "CapstoneCompat.hpp requires Capstone 6 (6.0.0-Alpha11)"
#endif

#include <string>

namespace capstone_compat {

// True if the Capstone library loaded at run time is the version these
// headers describe. A stale LD_LIBRARY_PATH can load another Capstone 6 build
// whose structures differ.
inline bool loadedCapstoneMatchesHeaders(int* Major = nullptr,
                                         int* Minor = nullptr) {
  int LoadedMajor = 0, LoadedMinor = 0;
  cs_version(&LoadedMajor, &LoadedMinor);
  if (Major) {
    *Major = LoadedMajor;
  }
  if (Minor) {
    *Minor = LoadedMinor;
  }
  return LoadedMajor == CS_API_MAJOR && LoadedMinor == CS_API_MINOR;
}

//===----------------------------------------------------------------------===//
// AArch64
//===----------------------------------------------------------------------===//

// Register name as Capstone 5.0.1 spelled it (lower case): X29 and X30 are
// "fp" and "lr" (Capstone 6 says "x29"/"x30" unless CS_OPT_SYNTAX_CS_REG_ALIAS
// is set), and a vector operand is "v<n>" (Capstone 6 reports the Q/D/S/H/B
// register with is_vreg set). Returns "" for AARCH64_REG_INVALID.
inline std::string aarch64RegName(csh Handle, unsigned int Reg, bool IsVreg) {
  if (Reg == AARCH64_REG_INVALID) {
    return "";
  }
  if (Reg == AARCH64_REG_FP) {
    return "fp";
  }
  if (Reg == AARCH64_REG_LR) {
    return "lr";
  }
  if (IsVreg) {
    const unsigned int Banks[] = {AARCH64_REG_B0, AARCH64_REG_H0,
                                  AARCH64_REG_S0, AARCH64_REG_D0,
                                  AARCH64_REG_Q0};
    for (unsigned int Base : Banks) {
      if (Reg >= Base && Reg <= Base + 31) {
        return "v" + std::to_string(Reg - Base);
      }
    }
  }
  const char* Name = cs_reg_name(Handle, Reg);
  return Name ? Name : "";
}

} // namespace capstone_compat

#endif // GTIRB_PP_CAPSTONE_COMPAT_H
