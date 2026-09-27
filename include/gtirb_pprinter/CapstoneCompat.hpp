//===- CapstoneCompat.hpp ---------------------------------------*- C++ -*-===//
//
// This code is licensed under the MIT license. See LICENSE for details.
//
// Shared Capstone version/configuration helpers. Decoded instructions retain
// their native Capstone 6 operands, spellings, accesses and groups.
//
//===----------------------------------------------------------------------===//
#ifndef GTIRB_PP_CAPSTONE_COMPAT_H
#define GTIRB_PP_CAPSTONE_COMPAT_H

#include <capstone/capstone.h>

#if CS_API_MAJOR < 6
#error "CapstoneCompat.hpp requires Capstone 6 (6.0.0-Alpha11)"
#endif

namespace capstone_compat {

// Check the loaded library before accessing version-specific detail structs.
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

// RV32GC/RV64GC, with explicit registers rather than alias-only operands.
// Extension decoding beyond GC follows the pinned Capstone implementation;
// this helper does not reject valid instructions merely absent in Capstone 5.
inline cs_err openRiscv(bool Rv64, bool BigEndian, csh* Handle) {
  unsigned int Mode = Rv64 ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
  Mode |= CS_MODE_RISCV_C | CS_MODE_RISCV_FD | CS_MODE_RISCV_A;
  Mode |= BigEndian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
  cs_err Err = cs_open(CS_ARCH_RISCV, static_cast<cs_mode>(Mode), Handle);
  if (Err != CS_ERR_OK) {
    return Err;
  }
  cs_option(*Handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_REAL);
  cs_option(*Handle, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL);
  return CS_ERR_OK;
}

} // namespace capstone_compat

#endif // GTIRB_PP_CAPSTONE_COMPAT_H
