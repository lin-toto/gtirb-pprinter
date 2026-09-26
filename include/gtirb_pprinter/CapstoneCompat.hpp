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

#include <cctype>
#include <cstring>
#include <initializer_list>
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

// Upper-case register name as ddisasm's facts spell it ("NONE" for no
// register).
inline std::string aarch64RegisterName(csh Handle, unsigned int Reg,
                                       bool IsVreg) {
  std::string Name = aarch64RegName(Handle, Reg, IsVreg);
  if (Name.empty()) {
    return "NONE";
  }
  for (char& C : Name) {
    C = static_cast<char>(std::toupper(static_cast<unsigned char>(C)));
  }
  return Name;
}

// How Capstone 5.0.1 reported a Capstone 6 system operand: as a system
// register (REG_MRS/REG_MSR/SYS, spelled from op_str), a PSTATE field, or a
// barrier option (the raw CRm value, which both versions share).
enum class Aarch64SystemOperand { None, Register, Pstate, Barrier };

inline Aarch64SystemOperand aarch64SystemOperandKind(const cs_aarch64_op& Op) {
  if (Op.type == AARCH64_OP_SYSREG) {
    // MRS/MSR system registers, TLBI and IC operations.
    return Aarch64SystemOperand::Register;
  }
  if (Op.type == AARCH64_OP_SYSALIAS) {
    switch (Op.sysop.sub_type) {
    case AARCH64_OP_DC:
    case AARCH64_OP_AT:
      return Aarch64SystemOperand::Register;
    case AARCH64_OP_PSTATEIMM0_15:
    case AARCH64_OP_PSTATEIMM0_1:
      return Aarch64SystemOperand::Pstate;
    case AARCH64_OP_DB:
      return Aarch64SystemOperand::Barrier;
    default:
      break;
    }
  }
  return Aarch64SystemOperand::None;
}

namespace aarch64_detail {

inline void removeOperand(cs_aarch64& A, unsigned int Index) {
  for (unsigned int I = Index; I + 1 < A.op_count; ++I) {
    A.operands[I] = A.operands[I + 1];
  }
  --A.op_count;
}

inline cs_aarch64_op makeOperand(aarch64_op_type Type, cs_ac_type Access) {
  cs_aarch64_op Op;
  std::memset(&Op, 0, sizeof(Op));
  Op.type = Type;
  Op.vector_index = -1;
  Op.access = Access;
  return Op;
}

inline bool isAlias(const cs_insn& Insn, aarch64_insn Alias) {
  return Insn.is_alias && Insn.alias_id == Alias;
}

// Capstone 5.0.1's generic groups for the instructions whose groups changed:
// BL and BLR (including the pointer-authenticating forms) were JUMP, CALL and
// BRANCH_RELATIVE; RET was only RET; BC.cond had none; SVC was INT; HVC and
// SMC had none.
inline void setGenericGroups(cs_insn& Insn) {
  cs_detail& D = *Insn.detail;
  auto Set = [&](std::initializer_list<uint8_t> Generic) {
    uint8_t Kept[sizeof(D.groups)];
    uint8_t N = 0;
    for (uint8_t I = 0; I < D.groups_count; ++I) {
      if (D.groups[I] > AARCH64_GRP_BRANCH_RELATIVE) {
        Kept[N++] = D.groups[I];
      }
    }
    for (uint8_t G : Generic) {
      if (N < sizeof(Kept)) {
        Kept[N++] = G;
      }
    }
    std::memcpy(D.groups, Kept, N);
    D.groups_count = N;
  };
  switch (Insn.id) {
  case AARCH64_INS_BL:
  case AARCH64_INS_BLR:
  case AARCH64_INS_BLRAA:
  case AARCH64_INS_BLRAAZ:
  case AARCH64_INS_BLRAB:
  case AARCH64_INS_BLRABZ:
    Set({AARCH64_GRP_JUMP, AARCH64_GRP_CALL, AARCH64_GRP_BRANCH_RELATIVE});
    break;
  case AARCH64_INS_RET:
  case AARCH64_INS_RETAA:
  case AARCH64_INS_RETAB:
    Set({AARCH64_GRP_RET});
    break;
  case AARCH64_INS_BC:
  case AARCH64_INS_HVC:
  case AARCH64_INS_SMC:
    Set({});
    break;
  case AARCH64_INS_SVC:
    Set({AARCH64_GRP_INT});
    break;
  default:
    break;
  }
}

inline double exactFpImmValue(int Value) {
  switch (Value) {
  case AARCH64_EXACTFPIMM_HALF:
    return 0.5;
  case AARCH64_EXACTFPIMM_ONE:
    return 1.0;
  case AARCH64_EXACTFPIMM_TWO:
    return 2.0;
  default:
    return 0.0;
  }
}

} // namespace aarch64_detail

// Rewrite a Capstone 6 AArch64 instruction (default alias syntax and details)
// into the operand shape Capstone 5.0.1 reported, as far as ddisasm and
// gtirb-pprinter read it:
//  - writeback only for base-register writeback (pre- or post-indexed);
//    Capstone 6 also sets it for tied operands (movk, bfi, fmla, cas, ...);
//  - post-indexed immediates as an IMM operand after a MEM with disp 0
//    (Capstone 6 folds them into mem.disp);
//  - PC-relative literals (ldr, ldrsw, prfm) as an IMM operand holding the
//    target, not a MEM operand without base or index;
//  - no prefetch-operation operand on PRFM/PRFUM (and SVE PRF*), and no BTI
//    operand, which Capstone 5.0.1 did not report;
//  - lsl/lsr/asr/ror aliases as REG, REG, IMM (or REG, REG, REG for a shift
//    by register), not REG, REG with a shift;
//  - no extender on the source of sxtb/sxth/sxtw/uxtb/uxth, and no LSL #0
//    on register and immediate operands;
//  - "#0.0" of fcmp/fcmpe and exact FP immediates as FP operands;
//  - SVE predicates as plain registers;
//  - system registers and PSTATE fields in lower case in op_str;
//  - Capstone 5.0.1's generic groups for the calls, returns and exceptions
//    whose groups changed.
// Instruction ids are left as Capstone 6 reports them (the real instruction;
// alias_id names the alias). Returns true: Capstone 6 decodes every encoding
// Capstone 5.0.1 decoded.
inline bool adaptAArch64(csh, cs_insn& Insn) {
  using namespace aarch64_detail;
  cs_detail& Detail = *Insn.detail;
  cs_aarch64& A = Detail.aarch64;

  int MemIndex = -1;
  for (unsigned int I = 0; I < A.op_count; ++I) {
    if (A.operands[I].type == AARCH64_OP_MEM) {
      MemIndex = static_cast<int>(I);
    }
  }
  const bool MemIsLast = MemIndex >= 0 && MemIndex + 1 == A.op_count;
  const bool PreIndex = std::strstr(Insn.op_str, "]!") != nullptr;
  Detail.writeback = Detail.writeback && MemIndex >= 0 &&
                     (A.post_index || PreIndex || !MemIsLast);

  if (A.post_index && MemIsLast && A.op_count < NUM_AARCH64_OPS) {
    cs_aarch64_op Imm = makeOperand(AARCH64_OP_IMM, CS_AC_READ);
    Imm.imm = A.operands[MemIndex].mem.disp;
    A.operands[MemIndex].mem.disp = 0;
    A.operands[A.op_count++] = Imm;
  }

  for (unsigned int I = 0; I < A.op_count; ++I) {
    cs_aarch64_op& Op = A.operands[I];
    if (Op.type == AARCH64_OP_MEM && Op.mem.base == AARCH64_REG_INVALID &&
        Op.mem.index == AARCH64_REG_INVALID) {
      const int64_t Target = Op.mem.disp;
      const cs_ac_type Access = Op.access;
      Op = makeOperand(AARCH64_OP_IMM, Access);
      Op.imm = Target;
    }
  }

  switch (Insn.id) {
  case AARCH64_INS_PRFM:
  case AARCH64_INS_PRFUM:
    if (A.op_count >= 2 &&
        (A.operands[0].type == AARCH64_OP_IMM ||
         (A.operands[0].type == AARCH64_OP_SYSALIAS &&
          A.operands[0].sysop.sub_type == AARCH64_OP_PRFM))) {
      removeOperand(A, 0);
    }
    break;
  default:
    if (A.op_count >= 1 && A.operands[0].type == AARCH64_OP_SYSALIAS &&
        A.operands[0].sysop.sub_type == AARCH64_OP_SVEPRFM) {
      removeOperand(A, 0);
    }
    break;
  }
  if (isAlias(Insn, AARCH64_INS_ALIAS_BTI)) {
    for (unsigned int I = A.op_count; I-- > 0;) {
      if (A.operands[I].type == AARCH64_OP_SYSALIAS) {
        removeOperand(A, I);
      }
    }
  }

  if (A.op_count == 2 && A.operands[1].type == AARCH64_OP_REG &&
      A.op_count < NUM_AARCH64_OPS) {
    cs_aarch64_op& Src = A.operands[1];
    const bool ImmediateShiftAlias = (isAlias(Insn, AARCH64_INS_ALIAS_LSL) ||
                                      isAlias(Insn, AARCH64_INS_ALIAS_LSR) ||
                                      isAlias(Insn, AARCH64_INS_ALIAS_ASR) ||
                                      isAlias(Insn, AARCH64_INS_ALIAS_ROR)) &&
                                     Src.shift.type >= AARCH64_SFT_LSL &&
                                     Src.shift.type <= AARCH64_SFT_ROR;
    const bool RegisterShift = Src.shift.type >= AARCH64_SFT_LSL_REG &&
                               Src.shift.type <= AARCH64_SFT_ROR_REG;
    if (ImmediateShiftAlias || RegisterShift) {
      cs_aarch64_op Amount = makeOperand(
          RegisterShift ? AARCH64_OP_REG : AARCH64_OP_IMM, CS_AC_READ);
      if (RegisterShift) {
        Amount.reg = static_cast<aarch64_reg>(Src.shift.value);
      } else {
        Amount.imm = Src.shift.value;
      }
      Src.shift.type = AARCH64_SFT_INVALID;
      Src.shift.value = 0;
      A.operands[A.op_count++] = Amount;
    }
  }

  const bool ExtendAlias = isAlias(Insn, AARCH64_INS_ALIAS_SXTB) ||
                           isAlias(Insn, AARCH64_INS_ALIAS_SXTH) ||
                           isAlias(Insn, AARCH64_INS_ALIAS_SXTW) ||
                           isAlias(Insn, AARCH64_INS_ALIAS_UXTB) ||
                           isAlias(Insn, AARCH64_INS_ALIAS_UXTH);
  for (unsigned int I = 0; I < A.op_count; ++I) {
    cs_aarch64_op& Op = A.operands[I];
    if (ExtendAlias && Op.type == AARCH64_OP_REG) {
      Op.ext = AARCH64_EXT_INVALID;
    }
    // Capstone 6 adds LSL #0 next to extenders and to unshifted immediates;
    // Capstone 5.0.1 reported LSL #0 only for the explicit "lsl #0" of a
    // byte access's index register, which Capstone 6 reports the same way.
    if ((Op.type == AARCH64_OP_REG || Op.type == AARCH64_OP_IMM) &&
        Op.shift.type == AARCH64_SFT_LSL && Op.shift.value == 0) {
      Op.shift.type = AARCH64_SFT_INVALID;
    }
    if (Op.type == AARCH64_OP_SYSIMM &&
        Op.sysop.sub_type == AARCH64_OP_EXACTFPIMM) {
      const double Value = exactFpImmValue(Op.sysop.imm.exactfpimm);
      const cs_ac_type Access = Op.access;
      Op = makeOperand(AARCH64_OP_FP, Access);
      Op.fp = Value;
    } else if (Op.type == AARCH64_OP_PRED) {
      const aarch64_reg Reg = Op.pred.reg;
      const cs_ac_type Access = Op.access;
      Op = makeOperand(AARCH64_OP_REG, Access);
      Op.reg = Reg;
    }
  }
  if ((Insn.id == AARCH64_INS_FCMP || Insn.id == AARCH64_INS_FCMPE) &&
      A.op_count == 2 && A.operands[1].type == AARCH64_OP_REG &&
      (A.operands[1].reg == AARCH64_REG_XZR ||
       A.operands[1].reg == AARCH64_REG_WZR)) {
    const cs_ac_type Access = A.operands[1].access;
    A.operands[1] = makeOperand(AARCH64_OP_FP, Access);
    A.operands[1].fp = 0.0;
  }

  // Capstone 6 spells system registers and PSTATE fields in upper or mixed
  // case ("TPIDR_EL0", "DAIFSet"); Capstone 5.0.1 printed them in lower case.
  bool SystemRegister = false;
  for (unsigned int I = 0; I < A.op_count; ++I) {
    const Aarch64SystemOperand Kind = aarch64SystemOperandKind(A.operands[I]);
    SystemRegister |= Kind == Aarch64SystemOperand::Register ||
                      Kind == Aarch64SystemOperand::Pstate;
  }
  if (SystemRegister) {
    for (char* P = Insn.op_str; *P != '\0'; ++P) {
      *P = static_cast<char>(std::tolower(static_cast<unsigned char>(*P)));
    }
  }

  setGenericGroups(Insn);
  return true;
}

} // namespace capstone_compat

#endif // GTIRB_PP_CAPSTONE_COMPAT_H
