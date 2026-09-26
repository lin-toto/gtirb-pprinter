//===- CapstoneCompat.hpp ---------------------------------------*- C++ -*-===//
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//===----------------------------------------------------------------------===//
//
// Capstone 6 adapter shared by gtirb-pprinter and ddisasm.
//
// Both tools were written against Capstone 5.0.1. Capstone 6 decodes the same
// instructions but reports many of them in a different shape (absolute RISC-V
// branch targets, memory operands for compressed and atomic RISC-V accesses,
// no Capstone 5 alias spellings, AArch64 post-index immediates folded into the
// memory operand, ...). Right after each cs_disasm call the tools pass every
// instruction through the adapter for its ISA, which rewrites the cs_insn in
// place into the shape Capstone 5.0.1 produced, so the printers' logic and
// ddisasm's Datalog facts stay unchanged. The adapter must run before anything
// else reads the instruction, including cs_regs_access, which reads the
// operand array. ddisasm includes this header as
// <gtirb_pprinter/CapstoneCompat.hpp>.
//
// The Capstone 5.0.1 behaviour reproduced here was measured, not assumed: a
// differential harness decodes every 16-bit RISC-V word, millions of random
// 32-bit words and whole .text sections with both libraries and compares the
// fields the two tools read. RISC-V encodings that Capstone 6 accepts but
// 5.0.1 rejected (newer extensions, RVC hints, legacy rounding modes) are
// reported as invalid, so both tools see the instruction set they saw before.
//
//===----------------------------------------------------------------------===//
#ifndef GTIRB_PP_CAPSTONE_COMPAT_H
#define GTIRB_PP_CAPSTONE_COMPAT_H

#include <capstone/capstone.h>

#if CS_API_MAJOR < 6
#error "CapstoneCompat.hpp requires Capstone 6 (6.0.0-Alpha11)"
#endif

#include <cctype>
#include <cinttypes>
#include <cstdio>
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
// RISC-V
//===----------------------------------------------------------------------===//

// Feature-test macro for the RISC-V adapter below.
#define CAPSTONE_COMPAT_RISCV 1

// Open a RISC-V handle in the configuration the adapter expects: RV32GC or
// RV64GC (the C, F/D and A extensions are all off by default in Capstone 6),
// real (non-alias) syntax and details. Zb* and every other extension stay off:
// Capstone 5.0.1 did not decode them either.
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

namespace riscv_detail {

// Instructions Capstone 5.0.1 decoded (its riscv.h, minus URET, which Capstone
// 6 no longer decodes). Anything else Capstone 6 reports is a newer extension.
inline bool isCapstone5Instruction(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_ADD:
  case RISCV_INS_ADDI:
  case RISCV_INS_ADDIW:
  case RISCV_INS_ADDW:
  case RISCV_INS_AMOADD_D:
  case RISCV_INS_AMOADD_D_AQ:
  case RISCV_INS_AMOADD_D_AQRL:
  case RISCV_INS_AMOADD_D_RL:
  case RISCV_INS_AMOADD_W:
  case RISCV_INS_AMOADD_W_AQ:
  case RISCV_INS_AMOADD_W_AQRL:
  case RISCV_INS_AMOADD_W_RL:
  case RISCV_INS_AMOAND_D:
  case RISCV_INS_AMOAND_D_AQ:
  case RISCV_INS_AMOAND_D_AQRL:
  case RISCV_INS_AMOAND_D_RL:
  case RISCV_INS_AMOAND_W:
  case RISCV_INS_AMOAND_W_AQ:
  case RISCV_INS_AMOAND_W_AQRL:
  case RISCV_INS_AMOAND_W_RL:
  case RISCV_INS_AMOMAX_D:
  case RISCV_INS_AMOMAX_D_AQ:
  case RISCV_INS_AMOMAX_D_AQRL:
  case RISCV_INS_AMOMAX_D_RL:
  case RISCV_INS_AMOMAXU_D:
  case RISCV_INS_AMOMAXU_D_AQ:
  case RISCV_INS_AMOMAXU_D_AQRL:
  case RISCV_INS_AMOMAXU_D_RL:
  case RISCV_INS_AMOMAXU_W:
  case RISCV_INS_AMOMAXU_W_AQ:
  case RISCV_INS_AMOMAXU_W_AQRL:
  case RISCV_INS_AMOMAXU_W_RL:
  case RISCV_INS_AMOMAX_W:
  case RISCV_INS_AMOMAX_W_AQ:
  case RISCV_INS_AMOMAX_W_AQRL:
  case RISCV_INS_AMOMAX_W_RL:
  case RISCV_INS_AMOMIN_D:
  case RISCV_INS_AMOMIN_D_AQ:
  case RISCV_INS_AMOMIN_D_AQRL:
  case RISCV_INS_AMOMIN_D_RL:
  case RISCV_INS_AMOMINU_D:
  case RISCV_INS_AMOMINU_D_AQ:
  case RISCV_INS_AMOMINU_D_AQRL:
  case RISCV_INS_AMOMINU_D_RL:
  case RISCV_INS_AMOMINU_W:
  case RISCV_INS_AMOMINU_W_AQ:
  case RISCV_INS_AMOMINU_W_AQRL:
  case RISCV_INS_AMOMINU_W_RL:
  case RISCV_INS_AMOMIN_W:
  case RISCV_INS_AMOMIN_W_AQ:
  case RISCV_INS_AMOMIN_W_AQRL:
  case RISCV_INS_AMOMIN_W_RL:
  case RISCV_INS_AMOOR_D:
  case RISCV_INS_AMOOR_D_AQ:
  case RISCV_INS_AMOOR_D_AQRL:
  case RISCV_INS_AMOOR_D_RL:
  case RISCV_INS_AMOOR_W:
  case RISCV_INS_AMOOR_W_AQ:
  case RISCV_INS_AMOOR_W_AQRL:
  case RISCV_INS_AMOOR_W_RL:
  case RISCV_INS_AMOSWAP_D:
  case RISCV_INS_AMOSWAP_D_AQ:
  case RISCV_INS_AMOSWAP_D_AQRL:
  case RISCV_INS_AMOSWAP_D_RL:
  case RISCV_INS_AMOSWAP_W:
  case RISCV_INS_AMOSWAP_W_AQ:
  case RISCV_INS_AMOSWAP_W_AQRL:
  case RISCV_INS_AMOSWAP_W_RL:
  case RISCV_INS_AMOXOR_D:
  case RISCV_INS_AMOXOR_D_AQ:
  case RISCV_INS_AMOXOR_D_AQRL:
  case RISCV_INS_AMOXOR_D_RL:
  case RISCV_INS_AMOXOR_W:
  case RISCV_INS_AMOXOR_W_AQ:
  case RISCV_INS_AMOXOR_W_AQRL:
  case RISCV_INS_AMOXOR_W_RL:
  case RISCV_INS_AND:
  case RISCV_INS_ANDI:
  case RISCV_INS_AUIPC:
  case RISCV_INS_BEQ:
  case RISCV_INS_BGE:
  case RISCV_INS_BGEU:
  case RISCV_INS_BLT:
  case RISCV_INS_BLTU:
  case RISCV_INS_BNE:
  case RISCV_INS_C_ADD:
  case RISCV_INS_C_ADDI:
  case RISCV_INS_C_ADDI16SP:
  case RISCV_INS_C_ADDI4SPN:
  case RISCV_INS_C_ADDIW:
  case RISCV_INS_C_ADDW:
  case RISCV_INS_C_AND:
  case RISCV_INS_C_ANDI:
  case RISCV_INS_C_BEQZ:
  case RISCV_INS_C_BNEZ:
  case RISCV_INS_C_EBREAK:
  case RISCV_INS_C_FLD:
  case RISCV_INS_C_FLDSP:
  case RISCV_INS_C_FLW:
  case RISCV_INS_C_FLWSP:
  case RISCV_INS_C_FSD:
  case RISCV_INS_C_FSDSP:
  case RISCV_INS_C_FSW:
  case RISCV_INS_C_FSWSP:
  case RISCV_INS_C_J:
  case RISCV_INS_C_JAL:
  case RISCV_INS_C_JALR:
  case RISCV_INS_C_JR:
  case RISCV_INS_C_LD:
  case RISCV_INS_C_LDSP:
  case RISCV_INS_C_LI:
  case RISCV_INS_C_LUI:
  case RISCV_INS_C_LW:
  case RISCV_INS_C_LWSP:
  case RISCV_INS_C_MV:
  case RISCV_INS_C_NOP:
  case RISCV_INS_C_OR:
  case RISCV_INS_C_SD:
  case RISCV_INS_C_SDSP:
  case RISCV_INS_C_SLLI:
  case RISCV_INS_C_SRAI:
  case RISCV_INS_C_SRLI:
  case RISCV_INS_CSRRC:
  case RISCV_INS_CSRRCI:
  case RISCV_INS_CSRRS:
  case RISCV_INS_CSRRSI:
  case RISCV_INS_CSRRW:
  case RISCV_INS_CSRRWI:
  case RISCV_INS_C_SUB:
  case RISCV_INS_C_SUBW:
  case RISCV_INS_C_SW:
  case RISCV_INS_C_SWSP:
  case RISCV_INS_C_UNIMP:
  case RISCV_INS_C_XOR:
  case RISCV_INS_DIV:
  case RISCV_INS_DIVU:
  case RISCV_INS_DIVUW:
  case RISCV_INS_DIVW:
  case RISCV_INS_EBREAK:
  case RISCV_INS_ECALL:
  case RISCV_INS_FADD_D:
  case RISCV_INS_FADD_S:
  case RISCV_INS_FCLASS_D:
  case RISCV_INS_FCLASS_S:
  case RISCV_INS_FCVT_D_L:
  case RISCV_INS_FCVT_D_LU:
  case RISCV_INS_FCVT_D_S:
  case RISCV_INS_FCVT_D_W:
  case RISCV_INS_FCVT_D_WU:
  case RISCV_INS_FCVT_L_D:
  case RISCV_INS_FCVT_L_S:
  case RISCV_INS_FCVT_LU_D:
  case RISCV_INS_FCVT_LU_S:
  case RISCV_INS_FCVT_S_D:
  case RISCV_INS_FCVT_S_L:
  case RISCV_INS_FCVT_S_LU:
  case RISCV_INS_FCVT_S_W:
  case RISCV_INS_FCVT_S_WU:
  case RISCV_INS_FCVT_W_D:
  case RISCV_INS_FCVT_W_S:
  case RISCV_INS_FCVT_WU_D:
  case RISCV_INS_FCVT_WU_S:
  case RISCV_INS_FDIV_D:
  case RISCV_INS_FDIV_S:
  case RISCV_INS_FENCE:
  case RISCV_INS_FENCE_I:
  case RISCV_INS_FENCE_TSO:
  case RISCV_INS_FEQ_D:
  case RISCV_INS_FEQ_S:
  case RISCV_INS_FLD:
  case RISCV_INS_FLE_D:
  case RISCV_INS_FLE_S:
  case RISCV_INS_FLT_D:
  case RISCV_INS_FLT_S:
  case RISCV_INS_FLW:
  case RISCV_INS_FMADD_D:
  case RISCV_INS_FMADD_S:
  case RISCV_INS_FMAX_D:
  case RISCV_INS_FMAX_S:
  case RISCV_INS_FMIN_D:
  case RISCV_INS_FMIN_S:
  case RISCV_INS_FMSUB_D:
  case RISCV_INS_FMSUB_S:
  case RISCV_INS_FMUL_D:
  case RISCV_INS_FMUL_S:
  case RISCV_INS_FMV_D_X:
  case RISCV_INS_FMV_W_X:
  case RISCV_INS_FMV_X_D:
  case RISCV_INS_FMV_X_W:
  case RISCV_INS_FNMADD_D:
  case RISCV_INS_FNMADD_S:
  case RISCV_INS_FNMSUB_D:
  case RISCV_INS_FNMSUB_S:
  case RISCV_INS_FSD:
  case RISCV_INS_FSGNJ_D:
  case RISCV_INS_FSGNJN_D:
  case RISCV_INS_FSGNJN_S:
  case RISCV_INS_FSGNJ_S:
  case RISCV_INS_FSGNJX_D:
  case RISCV_INS_FSGNJX_S:
  case RISCV_INS_FSQRT_D:
  case RISCV_INS_FSQRT_S:
  case RISCV_INS_FSUB_D:
  case RISCV_INS_FSUB_S:
  case RISCV_INS_FSW:
  case RISCV_INS_JAL:
  case RISCV_INS_JALR:
  case RISCV_INS_LB:
  case RISCV_INS_LBU:
  case RISCV_INS_LD:
  case RISCV_INS_LH:
  case RISCV_INS_LHU:
  case RISCV_INS_LR_D:
  case RISCV_INS_LR_D_AQ:
  case RISCV_INS_LR_D_AQRL:
  case RISCV_INS_LR_D_RL:
  case RISCV_INS_LR_W:
  case RISCV_INS_LR_W_AQ:
  case RISCV_INS_LR_W_AQRL:
  case RISCV_INS_LR_W_RL:
  case RISCV_INS_LUI:
  case RISCV_INS_LW:
  case RISCV_INS_LWU:
  case RISCV_INS_MRET:
  case RISCV_INS_MUL:
  case RISCV_INS_MULH:
  case RISCV_INS_MULHSU:
  case RISCV_INS_MULHU:
  case RISCV_INS_MULW:
  case RISCV_INS_OR:
  case RISCV_INS_ORI:
  case RISCV_INS_REM:
  case RISCV_INS_REMU:
  case RISCV_INS_REMUW:
  case RISCV_INS_REMW:
  case RISCV_INS_SB:
  case RISCV_INS_SC_D:
  case RISCV_INS_SC_D_AQ:
  case RISCV_INS_SC_D_AQRL:
  case RISCV_INS_SC_D_RL:
  case RISCV_INS_SC_W:
  case RISCV_INS_SC_W_AQ:
  case RISCV_INS_SC_W_AQRL:
  case RISCV_INS_SC_W_RL:
  case RISCV_INS_SD:
  case RISCV_INS_SFENCE_VMA:
  case RISCV_INS_SH:
  case RISCV_INS_SLL:
  case RISCV_INS_SLLI:
  case RISCV_INS_SLLIW:
  case RISCV_INS_SLLW:
  case RISCV_INS_SLT:
  case RISCV_INS_SLTI:
  case RISCV_INS_SLTIU:
  case RISCV_INS_SLTU:
  case RISCV_INS_SRA:
  case RISCV_INS_SRAI:
  case RISCV_INS_SRAIW:
  case RISCV_INS_SRAW:
  case RISCV_INS_SRET:
  case RISCV_INS_SRL:
  case RISCV_INS_SRLI:
  case RISCV_INS_SRLIW:
  case RISCV_INS_SRLW:
  case RISCV_INS_SUB:
  case RISCV_INS_SUBW:
  case RISCV_INS_SW:
  case RISCV_INS_UNIMP:
  case RISCV_INS_WFI:
  case RISCV_INS_XOR:
  case RISCV_INS_XORI:
    return true;
  default:
    return false;
  }
}

// Capstone 5.0.1's CSR names (RISCVInstPrinter.c getCSRSystemRegisterName),
// copied verbatim, including its swapped pmpaddr13/pmpaddr14 entries.
inline const char* csrName(unsigned int Csr) {
  switch (Csr) {
  case 0x0000:
    return "ustatus";
  case 0x0004:
    return "uie";
  case 0x0005:
    return "utvec";
  case 0x0040:
    return "uscratch";
  case 0x0041:
    return "uepc";
  case 0x0042:
    return "ucause";
  case 0x0043:
    return "utval";
  case 0x0044:
    return "uip";
  case 0x0001:
    return "fflags";
  case 0x0002:
    return "frm";
  case 0x0003:
    return "fcsr";
  case 0x0c00:
    return "cycle";
  case 0x0c01:
    return "time";
  case 0x0c02:
    return "instret";
  case 0x0c03:
    return "hpmcounter3";
  case 0x0c04:
    return "hpmcounter4";
  case 0x0c05:
    return "hpmcounter5";
  case 0x0c06:
    return "hpmcounter6";
  case 0x0c07:
    return "hpmcounter7";
  case 0x0c08:
    return "hpmcounter8";
  case 0x0c09:
    return "hpmcounter9";
  case 0x0c0a:
    return "hpmcounter10";
  case 0x0c0b:
    return "hpmcounter11";
  case 0x0c0c:
    return "hpmcounter12";
  case 0x0c0d:
    return "hpmcounter13";
  case 0x0c0e:
    return "hpmcounter14";
  case 0x0c0f:
    return "hpmcounter15";
  case 0x0c10:
    return "hpmcounter16";
  case 0x0c11:
    return "hpmcounter17";
  case 0x0c12:
    return "hpmcounter18";
  case 0x0c13:
    return "hpmcounter19";
  case 0x0c14:
    return "hpmcounter20";
  case 0x0c15:
    return "hpmcounter21";
  case 0x0c16:
    return "hpmcounter22";
  case 0x0c17:
    return "hpmcounter23";
  case 0x0c18:
    return "hpmcounter24";
  case 0x0c19:
    return "hpmcounter25";
  case 0x0c1a:
    return "hpmcounter26";
  case 0x0c1b:
    return "hpmcounter27";
  case 0x0c1c:
    return "hpmcounter28";
  case 0x0c1d:
    return "hpmcounter29";
  case 0x0c1e:
    return "hpmcounter30";
  case 0x0c1f:
    return "hpmcounter31";
  case 0x0c80:
    return "cycleh";
  case 0x0c81:
    return "timeh";
  case 0x0c82:
    return "instreth";
  case 0x0c83:
    return "hpmcounter3h";
  case 0x0c84:
    return "hpmcounter4h";
  case 0x0c85:
    return "hpmcounter5h";
  case 0x0c86:
    return "hpmcounter6h";
  case 0x0c87:
    return "hpmcounter7h";
  case 0x0c88:
    return "hpmcounter8h";
  case 0x0c89:
    return "hpmcounter9h";
  case 0x0c8a:
    return "hpmcounter10h";
  case 0x0c8b:
    return "hpmcounter11h";
  case 0x0c8c:
    return "hpmcounter12h";
  case 0x0c8d:
    return "hpmcounter13h";
  case 0x0c8e:
    return "hpmcounter14h";
  case 0x0c8f:
    return "hpmcounter15h";
  case 0x0c90:
    return "hpmcounter16h";
  case 0x0c91:
    return "hpmcounter17h";
  case 0x0c92:
    return "hpmcounter18h";
  case 0x0c93:
    return "hpmcounter19h";
  case 0x0c94:
    return "hpmcounter20h";
  case 0x0c95:
    return "hpmcounter21h";
  case 0x0c96:
    return "hpmcounter22h";
  case 0x0c97:
    return "hpmcounter23h";
  case 0x0c98:
    return "hpmcounter24h";
  case 0x0c99:
    return "hpmcounter25h";
  case 0x0c9a:
    return "hpmcounter26h";
  case 0x0c9b:
    return "hpmcounter27h";
  case 0x0c9c:
    return "hpmcounter28h";
  case 0x0c9d:
    return "hpmcounter29h";
  case 0x0c9e:
    return "hpmcounter30h";
  case 0x0c9f:
    return "hpmcounter31h";
  case 0x0100:
    return "sstatus";
  case 0x0102:
    return "sedeleg";
  case 0x0103:
    return "sideleg";
  case 0x0104:
    return "sie";
  case 0x0105:
    return "stvec";
  case 0x0106:
    return "scounteren";
  case 0x0140:
    return "sscratch";
  case 0x0141:
    return "sepc";
  case 0x0142:
    return "scause";
  case 0x0143:
    return "stval";
  case 0x0144:
    return "sip";
  case 0x0180:
    return "satp";
  case 0x0f11:
    return "mvendorid";
  case 0x0f12:
    return "marchid";
  case 0x0f13:
    return "mimpid";
  case 0x0f14:
    return "mhartid";
  case 0x0300:
    return "mstatus";
  case 0x0301:
    return "misa";
  case 0x0302:
    return "medeleg";
  case 0x0303:
    return "mideleg";
  case 0x0304:
    return "mie";
  case 0x0305:
    return "mtvec";
  case 0x0306:
    return "mcounteren";
  case 0x0340:
    return "mscratch";
  case 0x0341:
    return "mepc";
  case 0x0342:
    return "mcause";
  case 0x0343:
    return "mtval";
  case 0x0344:
    return "mip";
  case 0x03a0:
    return "pmpcfg0";
  case 0x03a1:
    return "pmpcfg1";
  case 0x03a2:
    return "pmpcfg2";
  case 0x03a3:
    return "pmpcfg3";
  case 0x03b0:
    return "pmpaddr0";
  case 0x03b1:
    return "pmpaddr1";
  case 0x03b2:
    return "pmpaddr2";
  case 0x03b3:
    return "pmpaddr3";
  case 0x03b4:
    return "pmpaddr4";
  case 0x03b5:
    return "pmpaddr5";
  case 0x03b6:
    return "pmpaddr6";
  case 0x03b7:
    return "pmpaddr7";
  case 0x03b8:
    return "pmpaddr8";
  case 0x03b9:
    return "pmpaddr9";
  case 0x03ba:
    return "pmpaddr10";
  case 0x03bb:
    return "pmpaddr11";
  case 0x03bc:
    return "pmpaddr12";
  case 0x03bd:
    return "pmpaddr14";
  case 0x03be:
    return "pmpaddr13";
  case 0x03bf:
    return "pmpaddr15";
  case 0x0b00:
    return "mcycle";
  case 0x0b02:
    return "minstret";
  case 0x0b03:
    return "mhpmcounter3";
  case 0x0b04:
    return "mhpmcounter4";
  case 0x0b05:
    return "mhpmcounter5";
  case 0x0b06:
    return "mhpmcounter6";
  case 0x0b07:
    return "mhpmcounter7";
  case 0x0b08:
    return "mhpmcounter8";
  case 0x0b09:
    return "mhpmcounter9";
  case 0x0b0a:
    return "mhpmcounter10";
  case 0x0b0b:
    return "mhpmcounter11";
  case 0x0b0c:
    return "mhpmcounter12";
  case 0x0b0d:
    return "mhpmcounter13";
  case 0x0b0e:
    return "mhpmcounter14";
  case 0x0b0f:
    return "mhpmcounter15";
  case 0x0b10:
    return "mhpmcounter16";
  case 0x0b11:
    return "mhpmcounter17";
  case 0x0b12:
    return "mhpmcounter18";
  case 0x0b13:
    return "mhpmcounter19";
  case 0x0b14:
    return "mhpmcounter20";
  case 0x0b15:
    return "mhpmcounter21";
  case 0x0b16:
    return "mhpmcounter22";
  case 0x0b17:
    return "mhpmcounter23";
  case 0x0b18:
    return "mhpmcounter24";
  case 0x0b19:
    return "mhpmcounter25";
  case 0x0b1a:
    return "mhpmcounter26";
  case 0x0b1b:
    return "mhpmcounter27";
  case 0x0b1c:
    return "mhpmcounter28";
  case 0x0b1d:
    return "mhpmcounter29";
  case 0x0b1e:
    return "mhpmcounter30";
  case 0x0b1f:
    return "mhpmcounter31";
  case 0x0b80:
    return "mcycleh";
  case 0x0b82:
    return "minstreth";
  case 0x0b83:
    return "mhpmcounter3h";
  case 0x0b84:
    return "mhpmcounter4h";
  case 0x0b85:
    return "mhpmcounter5h";
  case 0x0b86:
    return "mhpmcounter6h";
  case 0x0b87:
    return "mhpmcounter7h";
  case 0x0b88:
    return "mhpmcounter8h";
  case 0x0b89:
    return "mhpmcounter9h";
  case 0x0b8a:
    return "mhpmcounter10h";
  case 0x0b8b:
    return "mhpmcounter11h";
  case 0x0b8c:
    return "mhpmcounter12h";
  case 0x0b8d:
    return "mhpmcounter13h";
  case 0x0b8e:
    return "mhpmcounter14h";
  case 0x0b8f:
    return "mhpmcounter15h";
  case 0x0b90:
    return "mhpmcounter16h";
  case 0x0b91:
    return "mhpmcounter17h";
  case 0x0b92:
    return "mhpmcounter18h";
  case 0x0b93:
    return "mhpmcounter19h";
  case 0x0b94:
    return "mhpmcounter20h";
  case 0x0b95:
    return "mhpmcounter21h";
  case 0x0b96:
    return "mhpmcounter22h";
  case 0x0b97:
    return "mhpmcounter23h";
  case 0x0b98:
    return "mhpmcounter24h";
  case 0x0b99:
    return "mhpmcounter25h";
  case 0x0b9a:
    return "mhpmcounter26h";
  case 0x0b9b:
    return "mhpmcounter27h";
  case 0x0b9c:
    return "mhpmcounter28h";
  case 0x0b9d:
    return "mhpmcounter29h";
  case 0x0b9e:
    return "mhpmcounter30h";
  case 0x0b9f:
    return "mhpmcounter31h";
  case 0x0323:
    return "mhpmevent3";
  case 0x0324:
    return "mhpmevent4";
  case 0x0325:
    return "mhpmevent5";
  case 0x0326:
    return "mhpmevent6";
  case 0x0327:
    return "mhpmevent7";
  case 0x0328:
    return "mhpmevent8";
  case 0x0329:
    return "mhpmevent9";
  case 0x032a:
    return "mhpmevent10";
  case 0x032b:
    return "mhpmevent11";
  case 0x032c:
    return "mhpmevent12";
  case 0x032d:
    return "mhpmevent13";
  case 0x032e:
    return "mhpmevent14";
  case 0x032f:
    return "mhpmevent15";
  case 0x0330:
    return "mhpmevent16";
  case 0x0331:
    return "mhpmevent17";
  case 0x0332:
    return "mhpmevent18";
  case 0x0333:
    return "mhpmevent19";
  case 0x0334:
    return "mhpmevent20";
  case 0x0335:
    return "mhpmevent21";
  case 0x0336:
    return "mhpmevent22";
  case 0x0337:
    return "mhpmevent23";
  case 0x0338:
    return "mhpmevent24";
  case 0x0339:
    return "mhpmevent25";
  case 0x033a:
    return "mhpmevent26";
  case 0x033b:
    return "mhpmevent27";
  case 0x033c:
    return "mhpmevent28";
  case 0x033d:
    return "mhpmevent29";
  case 0x033e:
    return "mhpmevent30";
  case 0x033f:
    return "mhpmevent31";
  case 0x07a0:
    return "tselect";
  case 0x07a1:
    return "tdata1";
  case 0x07a2:
    return "tdata2";
  case 0x07a3:
    return "tdata3";
  case 0x07b0:
    return "dcsr";
  case 0x07b1:
    return "dpc";
  case 0x07b2:
    return "dscratch";
  default:
    return nullptr;
  }
}

// Capstone 5.0.1 printOperand: decimal up to 9, hexadecimal above.
inline std::string formatImm(int64_t Imm) {
  char Buf[32];
  if (Imm >= 0) {
    std::snprintf(Buf, sizeof(Buf), Imm > 9 ? "0x%" PRIx64 : "%" PRIu64,
                  static_cast<uint64_t>(Imm));
  } else {
    uint64_t Magnitude = uint64_t(0) - static_cast<uint64_t>(Imm);
    std::snprintf(Buf, sizeof(Buf), Imm < -9 ? "-0x%" PRIx64 : "-%" PRIu64,
                  Magnitude);
  }
  return Buf;
}

// One operand as Capstone 5.0.1 printed it, in text order.
struct Part {
  enum Kind {
    Reg,           // register; detail REG
    Imm,           // immediate; detail IMM
    Mem,           // "disp(base)"; detail MEM(base, disp)
    CompressedMem, // "disp(base)"; detail IMM(disp), REG(base)
    AtomicBase,    // "(base)"; detail REG(base)
    Csr,           // CSR name or number; text only
    Fence,         // fence predecessor/successor set; text only
    RoundingMode   // ", rtz" etc.; text only
  };
  Kind K;
  unsigned int RegNo;
  int64_t Value;
};

struct Shape {
  Part Parts[8];
  unsigned int Count = 0;
  void add(Part::Kind K, unsigned int Reg, int64_t Value) {
    if (Count < 8) {
      Parts[Count++] = Part{K, Reg, Value};
    }
  }
  bool isReg(unsigned int I, unsigned int R) const {
    return I < Count && Parts[I].K == Part::Reg && Parts[I].RegNo == R;
  }
  bool isImm(unsigned int I, int64_t V) const {
    return I < Count && Parts[I].K == Part::Imm && Parts[I].Value == V;
  }
  bool isCsr(unsigned int I, int64_t V) const {
    return I < Count && Parts[I].K == Part::Csr && Parts[I].Value == V;
  }
};

inline bool isBranchRelative(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_JAL:
  case RISCV_INS_BEQ:
  case RISCV_INS_BNE:
  case RISCV_INS_BLT:
  case RISCV_INS_BGE:
  case RISCV_INS_BLTU:
  case RISCV_INS_BGEU:
  case RISCV_INS_C_J:
  case RISCV_INS_C_JAL:
  case RISCV_INS_C_BEQZ:
  case RISCV_INS_C_BNEZ:
    return true;
  default:
    return false;
  }
}

inline bool isCompressedMemory(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_C_LW:
  case RISCV_INS_C_LD:
  case RISCV_INS_C_SW:
  case RISCV_INS_C_SD:
  case RISCV_INS_C_FLW:
  case RISCV_INS_C_FLD:
  case RISCV_INS_C_FSW:
  case RISCV_INS_C_FSD:
  case RISCV_INS_C_LWSP:
  case RISCV_INS_C_LDSP:
  case RISCV_INS_C_SWSP:
  case RISCV_INS_C_SDSP:
  case RISCV_INS_C_FLWSP:
  case RISCV_INS_C_FLDSP:
  case RISCV_INS_C_FSWSP:
  case RISCV_INS_C_FSDSP:
    return true;
  default:
    return false;
  }
}

inline bool isLoadReserved(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_LR_W:
  case RISCV_INS_LR_W_AQ:
  case RISCV_INS_LR_W_RL:
  case RISCV_INS_LR_W_AQRL:
  case RISCV_INS_LR_D:
  case RISCV_INS_LR_D_AQ:
  case RISCV_INS_LR_D_RL:
  case RISCV_INS_LR_D_AQRL:
    return true;
  default:
    return false;
  }
}

// SC and AMO: Capstone 6 reports REG(rd), MEM(rs1), REG(rs2); Capstone 5.0.1
// reported the registers in text order, "rd, rs2, (rs1)".
inline bool isStoreConditionalOrAmo(unsigned int Id) {
  switch (Id) {
#define CS5_AMO(NAME)                                                          \
  case RISCV_INS_##NAME:                                                       \
  case RISCV_INS_##NAME##_AQ:                                                  \
  case RISCV_INS_##NAME##_RL:                                                  \
  case RISCV_INS_##NAME##_AQRL:
    CS5_AMO(SC_W)
    CS5_AMO(SC_D)
    CS5_AMO(AMOADD_W)
    CS5_AMO(AMOADD_D)
    CS5_AMO(AMOAND_W)
    CS5_AMO(AMOAND_D)
    CS5_AMO(AMOMAX_W)
    CS5_AMO(AMOMAX_D)
    CS5_AMO(AMOMAXU_W)
    CS5_AMO(AMOMAXU_D)
    CS5_AMO(AMOMIN_W)
    CS5_AMO(AMOMIN_D)
    CS5_AMO(AMOMINU_W)
    CS5_AMO(AMOMINU_D)
    CS5_AMO(AMOOR_W)
    CS5_AMO(AMOOR_D)
    CS5_AMO(AMOSWAP_W)
    CS5_AMO(AMOSWAP_D)
    CS5_AMO(AMOXOR_W)
    CS5_AMO(AMOXOR_D)
#undef CS5_AMO
    return true;
  default:
    return false;
  }
}

// Instructions whose Capstone 5.0.1 text included the rounding mode (",
// <rm>"), omitted only when it is DYN (the alias printed then).
inline bool printsRoundingMode(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_FADD_S:
  case RISCV_INS_FADD_D:
  case RISCV_INS_FSUB_S:
  case RISCV_INS_FSUB_D:
  case RISCV_INS_FMUL_S:
  case RISCV_INS_FMUL_D:
  case RISCV_INS_FDIV_S:
  case RISCV_INS_FDIV_D:
  case RISCV_INS_FSQRT_S:
  case RISCV_INS_FSQRT_D:
  case RISCV_INS_FMADD_S:
  case RISCV_INS_FMADD_D:
  case RISCV_INS_FMSUB_S:
  case RISCV_INS_FMSUB_D:
  case RISCV_INS_FNMADD_S:
  case RISCV_INS_FNMADD_D:
  case RISCV_INS_FNMSUB_S:
  case RISCV_INS_FNMSUB_D:
  case RISCV_INS_FCVT_W_S:
  case RISCV_INS_FCVT_WU_S:
  case RISCV_INS_FCVT_L_S:
  case RISCV_INS_FCVT_LU_S:
  case RISCV_INS_FCVT_S_W:
  case RISCV_INS_FCVT_S_WU:
  case RISCV_INS_FCVT_S_L:
  case RISCV_INS_FCVT_S_LU:
  case RISCV_INS_FCVT_W_D:
  case RISCV_INS_FCVT_WU_D:
  case RISCV_INS_FCVT_L_D:
  case RISCV_INS_FCVT_LU_D:
  case RISCV_INS_FCVT_S_D:
  case RISCV_INS_FCVT_D_L:
  case RISCV_INS_FCVT_D_LU:
    return true;
  default:
    return false;
  }
}

inline const char* roundingModeName(riscv_rounding_mode Rm) {
  switch (Rm) {
  case RISCV_RM_RNE:
    return "rne";
  case RISCV_RM_RTZ:
    return "rtz";
  case RISCV_RM_RDN:
    return "rdn";
  case RISCV_RM_RUP:
    return "rup";
  case RISCV_RM_RMM:
    return "rmm";
  case RISCV_RM_DYN:
    return "dyn";
  default:
    return nullptr;
  }
}

inline std::string fenceSet(int64_t Set) {
  std::string S;
  if (Set & 8)
    S += 'i';
  if (Set & 4)
    S += 'o';
  if (Set & 2)
    S += 'r';
  if (Set & 1)
    S += 'w';
  return Set == 0 ? std::string("unknown") : S;
}

// Capstone 5.0.1's generic groups depended only on the instruction.
inline void setGenericGroups(cs_insn& Insn) {
  cs_detail& D = *Insn.detail;
  uint8_t Kept[sizeof(D.groups)];
  uint8_t N = 0;
  for (uint8_t I = 0; I < D.groups_count; ++I) {
    if (D.groups[I] > RISCV_GRP_BRANCH_RELATIVE) {
      Kept[N++] = D.groups[I];
    }
  }
  auto Add = [&](uint8_t G) {
    if (N < sizeof(Kept)) {
      Kept[N++] = G;
    }
  };
  switch (Insn.id) {
  case RISCV_INS_BEQ:
  case RISCV_INS_BNE:
  case RISCV_INS_BLT:
  case RISCV_INS_BGE:
  case RISCV_INS_BLTU:
  case RISCV_INS_BGEU:
  case RISCV_INS_C_BEQZ:
  case RISCV_INS_C_BNEZ:
    Add(RISCV_GRP_JUMP);
    Add(RISCV_GRP_BRANCH_RELATIVE);
    break;
  case RISCV_INS_C_J:
  case RISCV_INS_C_JR:
    Add(RISCV_GRP_JUMP);
    break;
  case RISCV_INS_JAL:
  case RISCV_INS_JALR:
  case RISCV_INS_C_JAL:
  case RISCV_INS_C_JALR:
    Add(RISCV_GRP_CALL);
    break;
  case RISCV_INS_ECALL:
    Add(RISCV_GRP_INT);
    break;
  default:
    break;
  }
  std::memcpy(D.groups, Kept, N);
  D.groups_count = N;
}

// Capstone 5.0.1 alias table (RISCVGenAsmWriter.inc printAliasInstr, in its
// order). On a match, replaces the mnemonic and keeps the listed operands.
inline bool selectAlias(unsigned int Id, Shape& S, std::string& Mnemonic) {
  const unsigned int X0 = RISCV_REG_X0;
  const unsigned int X1 = RISCV_REG_X1;
  auto Keep = [&](const char* Name, std::initializer_list<unsigned int> Idx) {
    Shape New;
    for (unsigned int I : Idx) {
      New.Parts[New.Count++] = S.Parts[I];
    }
    S = New;
    Mnemonic = Name;
    return true;
  };
  auto SameReg = [&](unsigned int A, unsigned int B) {
    return A < S.Count && B < S.Count && S.Parts[A].K == Part::Reg &&
           S.Parts[B].K == Part::Reg && S.Parts[A].RegNo == S.Parts[B].RegNo;
  };
  switch (Id) {
  case RISCV_INS_ADDI:
    if (S.isReg(0, X0) && S.isReg(1, X0) && S.isImm(2, 0))
      return Keep("nop", {});
    if (S.isImm(2, 0))
      return Keep("mv", {0, 1});
    return false;
  case RISCV_INS_ADDIW:
    if (S.isImm(2, 0))
      return Keep("sext.w", {0, 1});
    return false;
  case RISCV_INS_BEQ:
    if (S.isReg(1, X0))
      return Keep("beqz", {0, 2});
    return false;
  case RISCV_INS_BGE:
    if (S.isReg(0, X0))
      return Keep("blez", {1, 2});
    if (S.isReg(1, X0))
      return Keep("bgez", {0, 2});
    return false;
  case RISCV_INS_BLT:
    if (S.isReg(1, X0))
      return Keep("bltz", {0, 2});
    if (S.isReg(0, X0))
      return Keep("bgtz", {1, 2});
    return false;
  case RISCV_INS_BNE:
    if (S.isReg(1, X0))
      return Keep("bnez", {0, 2});
    return false;
  case RISCV_INS_CSRRC:
    if (S.isReg(0, X0))
      return Keep("csrc", {1, 2});
    return false;
  case RISCV_INS_CSRRCI:
    if (S.isReg(0, X0))
      return Keep("csrci", {1, 2});
    return false;
  case RISCV_INS_CSRRS:
    if (S.isReg(2, X0)) {
      if (S.isCsr(1, 3))
        return Keep("frcsr", {0});
      if (S.isCsr(1, 2))
        return Keep("frrm", {0});
      if (S.isCsr(1, 1))
        return Keep("frflags", {0});
      if (S.isCsr(1, 3074))
        return Keep("rdinstret", {0});
      if (S.isCsr(1, 3072))
        return Keep("rdcycle", {0});
      if (S.isCsr(1, 3073))
        return Keep("rdtime", {0});
      if (S.isCsr(1, 3202))
        return Keep("rdinstreth", {0});
      if (S.isCsr(1, 3200))
        return Keep("rdcycleh", {0});
      if (S.isCsr(1, 3201))
        return Keep("rdtimeh", {0});
      return Keep("csrr", {0, 1});
    }
    if (S.isReg(0, X0))
      return Keep("csrs", {1, 2});
    return false;
  case RISCV_INS_CSRRSI:
    if (S.isReg(0, X0))
      return Keep("csrsi", {1, 2});
    return false;
  case RISCV_INS_CSRRW:
    if (S.isReg(0, X0)) {
      if (S.isCsr(1, 3))
        return Keep("fscsr", {2});
      if (S.isCsr(1, 2))
        return Keep("fsrm", {2});
      if (S.isCsr(1, 1))
        return Keep("fsflags", {2});
      return Keep("csrw", {1, 2});
    }
    if (S.isCsr(1, 3))
      return Keep("fscsr", {0, 2});
    if (S.isCsr(1, 2))
      return Keep("fsrm", {0, 2});
    if (S.isCsr(1, 1))
      return Keep("fsflags", {0, 2});
    return false;
  case RISCV_INS_CSRRWI:
    if (S.isReg(0, X0)) {
      if (S.isCsr(1, 2))
        return Keep("fsrmi", {2});
      if (S.isCsr(1, 1))
        return Keep("fsflagsi", {2});
      return Keep("csrwi", {1, 2});
    }
    if (S.isCsr(1, 2))
      return Keep("fsrmi", {0, 2});
    if (S.isCsr(1, 1))
      return Keep("fsflagsi", {0, 2});
    return false;
  case RISCV_INS_FENCE:
    if (S.Count == 2 && S.Parts[0].Value == 15 && S.Parts[1].Value == 15)
      return Keep("fence", {});
    return false;
  case RISCV_INS_FSGNJN_D:
    if (SameReg(1, 2))
      return Keep("fneg.d", {0, 1});
    return false;
  case RISCV_INS_FSGNJN_S:
    if (SameReg(1, 2))
      return Keep("fneg.s", {0, 1});
    return false;
  case RISCV_INS_FSGNJX_D:
    if (SameReg(1, 2))
      return Keep("fabs.d", {0, 1});
    return false;
  case RISCV_INS_FSGNJX_S:
    if (SameReg(1, 2))
      return Keep("fabs.s", {0, 1});
    return false;
  case RISCV_INS_FSGNJ_D:
    if (SameReg(1, 2))
      return Keep("fmv.d", {0, 1});
    return false;
  case RISCV_INS_FSGNJ_S:
    if (SameReg(1, 2))
      return Keep("fmv.s", {0, 1});
    return false;
  case RISCV_INS_JAL:
    if (S.isReg(0, X0))
      return Keep("j", {1});
    if (S.isReg(0, X1))
      return Keep("jal", {1});
    return false;
  case RISCV_INS_JALR:
    if (S.isReg(0, X0) && S.isReg(1, X1) && S.isImm(2, 0))
      return Keep("ret", {});
    if (S.isReg(0, X0) && S.isImm(2, 0))
      return Keep("jr", {1});
    if (S.isReg(0, X1) && S.isImm(2, 0))
      return Keep("jalr", {1});
    return false;
  case RISCV_INS_SFENCE_VMA:
    if (S.isReg(0, X0) && S.isReg(1, X0))
      return Keep("sfence.vma", {});
    if (S.isReg(1, X0))
      return Keep("sfence.vma", {0});
    return false;
  case RISCV_INS_SLT:
    if (S.isReg(2, X0))
      return Keep("sltz", {0, 1});
    if (S.isReg(1, X0))
      return Keep("sgtz", {0, 2});
    return false;
  case RISCV_INS_SLTIU:
    if (S.isImm(2, 1))
      return Keep("seqz", {0, 1});
    return false;
  case RISCV_INS_SLTU:
    if (S.isReg(1, X0))
      return Keep("snez", {0, 2});
    return false;
  case RISCV_INS_SUB:
    if (S.isReg(1, X0))
      return Keep("neg", {0, 2});
    return false;
  case RISCV_INS_SUBW:
    if (S.isReg(1, X0))
      return Keep("negw", {0, 2});
    return false;
  case RISCV_INS_XORI:
    if (S.isImm(2, -1))
      return Keep("not", {0, 1});
    return false;
  default:
    // The FP aliases only drop a DYN rounding mode; see adaptRiscv.
    return false;
  }
}

} // namespace riscv_detail

// Rewrite a Capstone 6 RISC-V instruction (decoded with a handle from
// openRiscv) into the shape Capstone 5.0.1 produced: its mnemonic and op_str
// spelling (including its aliases), its operand list (the printed registers
// and immediates in text order, relative branch offsets), and its generic
// groups. Returns false for instructions Capstone 5.0.1 did not decode; callers
// treat those exactly as a failed decode.
inline bool adaptRiscv(csh Handle, cs_insn& Insn) {
  using namespace riscv_detail;
  cs_riscv& D = Insn.detail->riscv;
  unsigned int Id = Insn.id;
  std::string Mnemonic = Insn.mnemonic;
  Shape S;

  // Encodings Capstone 6 assigns to newer extensions but Capstone 5.0.1
  // decoded as base instructions.
  switch (Id) {
  case RISCV_INS_PREFETCH_I:
  case RISCV_INS_PREFETCH_R:
  case RISCV_INS_PREFETCH_W: {
    // Zicbop: "ori zero, rs1, imm" with imm[4:0] = 0, 1 or 3.
    if (D.op_count != 1 || D.operands[0].type != RISCV_OP_MEM) {
      return false;
    }
    int64_t Low = Id == RISCV_INS_PREFETCH_I   ? 0
                  : Id == RISCV_INS_PREFETCH_R ? 1
                                               : 3;
    Id = RISCV_INS_ORI;
    Mnemonic = "ori";
    S.add(Part::Reg, RISCV_REG_X0, 0);
    S.add(Part::Reg, D.operands[0].mem.base, 0);
    S.add(Part::Imm, 0, D.operands[0].mem.disp + Low);
    break;
  }
  case RISCV_INS_CMOP_1:
  case RISCV_INS_CMOP_3:
  case RISCV_INS_CMOP_5:
  case RISCV_INS_CMOP_7:
  case RISCV_INS_CMOP_9:
  case RISCV_INS_CMOP_11:
  case RISCV_INS_CMOP_13:
  case RISCV_INS_CMOP_15: {
    // Zcmop: the reserved "c.lui xN, 0" encodings.
    unsigned int N = ((Insn.bytes[1] & 0x0f) << 1) | (Insn.bytes[0] >> 7);
    Id = RISCV_INS_C_LUI;
    Mnemonic = "c.lui";
    S.add(Part::Reg, RISCV_REG_X0 + N, 0);
    S.add(Part::Imm, 0, 0);
    break;
  }
  case RISCV_INS_C_SLLI64:
  case RISCV_INS_C_SRLI64:
  case RISCV_INS_C_SRAI64:
    // Shift by zero: Capstone 5.0.1 printed "c.slli rd, 0" (and rejected the
    // rd = zero hint).
    if (D.op_count != 1 || D.operands[0].type != RISCV_OP_REG ||
        D.operands[0].reg == RISCV_REG_X0) {
      return false;
    }
    Mnemonic = Id == RISCV_INS_C_SLLI64   ? "c.slli"
               : Id == RISCV_INS_C_SRLI64 ? "c.srli"
                                          : "c.srai";
    Id = Id == RISCV_INS_C_SLLI64   ? RISCV_INS_C_SLLI
         : Id == RISCV_INS_C_SRLI64 ? RISCV_INS_C_SRLI
                                    : RISCV_INS_C_SRAI;
    S.add(Part::Reg, D.operands[0].reg, 0);
    S.add(Part::Imm, 0, 0);
    break;
  default:
    if (!isCapstone5Instruction(Id)) {
      return false;
    }
    for (unsigned int I = 0; I < D.op_count; ++I) {
      const cs_riscv_op& Op = D.operands[I];
      switch (Op.type) {
      case RISCV_OP_REG:
        S.add(Part::Reg, Op.reg, 0);
        break;
      case RISCV_OP_IMM:
        S.add(Part::Imm, 0, Op.imm);
        break;
      case RISCV_OP_MEM:
        S.add(Part::Mem, Op.mem.base, Op.mem.disp);
        break;
      case RISCV_OP_CSR:
        S.add(Part::Csr, 0, Op.csr);
        break;
      default:
        return false;
      }
    }
    break;
  }

  // RVC hints and reserved encodings that Capstone 5.0.1 rejected.
  switch (Id) {
  case RISCV_INS_C_LI:
  case RISCV_INS_C_LUI:
  case RISCV_INS_C_SLLI:
  case RISCV_INS_C_MV:
  case RISCV_INS_C_ADD:
    if (S.isReg(0, RISCV_REG_X0)) {
      return false;
    }
    break;
  case RISCV_INS_C_NOP:
    // "c.nop imm": 5.0.1 accepted a positive immediate (and did not report
    // it), and rejected a negative one.
    if (S.Count == 1 && S.Parts[0].K == Part::Imm) {
      if (S.Parts[0].Value < 0) {
        return false;
      }
      S.Count = 0;
    }
    break;
  case RISCV_INS_FCVT_D_S:
  case RISCV_INS_FCVT_D_W:
  case RISCV_INS_FCVT_D_WU:
    // Exact conversions: 5.0.1 decoded them only with rm = RNE (000).
    if (D.rounding_mode != RISCV_RM_RNE &&
        D.rounding_mode != RISCV_RM_INVALID) {
      return false;
    }
    break;
  default:
    break;
  }

  // Operand shapes that differ from Capstone 5.0.1.
  if (isBranchRelative(Id)) {
    // Capstone 6 reports the absolute target; 5.0.1 reported the offset.
    for (unsigned int I = 0; I < S.Count; ++I) {
      if (S.Parts[I].K == Part::Imm) {
        S.Parts[I].Value = static_cast<int64_t>(
            static_cast<uint64_t>(S.Parts[I].Value) - Insn.address);
      }
    }
  } else if (isCompressedMemory(Id)) {
    for (unsigned int I = 0; I < S.Count; ++I) {
      if (S.Parts[I].K == Part::Mem) {
        S.Parts[I].K = Part::CompressedMem;
      }
    }
  } else if (isLoadReserved(Id)) {
    if (S.Count == 2 && S.Parts[1].K == Part::Mem) {
      S.Parts[1].K = Part::AtomicBase;
    }
  } else if (isStoreConditionalOrAmo(Id)) {
    if (S.Count == 3 && S.Parts[1].K == Part::Mem &&
        S.Parts[2].K == Part::Reg) {
      Part Base = S.Parts[1];
      Base.K = Part::AtomicBase;
      S.Parts[1] = S.Parts[2];
      S.Parts[2] = Base;
    }
  } else if (Id == RISCV_INS_FENCE) {
    for (unsigned int I = 0; I < S.Count; ++I) {
      S.Parts[I].K = Part::Fence;
    }
  }

  // Aliases, then the rounding mode Capstone 5.0.1 appended.
  bool Aliased = selectAlias(Id, S, Mnemonic);
  if (!Aliased && printsRoundingMode(Id) && D.rounding_mode != RISCV_RM_DYN &&
      roundingModeName(D.rounding_mode)) {
    S.add(Part::RoundingMode, 0, D.rounding_mode);
  }

  // Write the Capstone 5.0.1 shape back.
  std::string Text;
  cs_riscv_op Ops[NUM_RISCV_OPS];
  unsigned int OpCount = 0;
  auto AddOp = [&](riscv_op_type T, unsigned int Reg, int64_t Value) {
    if (OpCount < NUM_RISCV_OPS) {
      cs_riscv_op& Op = Ops[OpCount++];
      std::memset(&Op, 0, sizeof(Op));
      Op.type = T;
      if (T == RISCV_OP_REG) {
        Op.reg = Reg;
      } else if (T == RISCV_OP_IMM) {
        Op.imm = Value;
      } else {
        Op.mem.base = Reg;
        Op.mem.disp = Value;
      }
      Op.access = CS_AC_INVALID;
    }
  };
  auto RegName = [&](unsigned int Reg) {
    const char* Name = cs_reg_name(Handle, Reg);
    return std::string(Name ? Name : "");
  };
  for (unsigned int I = 0; I < S.Count; ++I) {
    const Part& P = S.Parts[I];
    if (!Text.empty()) {
      Text += ", ";
    }
    switch (P.K) {
    case Part::Reg:
      Text += RegName(P.RegNo);
      AddOp(RISCV_OP_REG, P.RegNo, 0);
      break;
    case Part::Imm:
      Text += formatImm(P.Value);
      AddOp(RISCV_OP_IMM, 0, P.Value);
      break;
    case Part::Mem:
      Text += formatImm(P.Value) + "(" + RegName(P.RegNo) + ")";
      AddOp(RISCV_OP_MEM, P.RegNo, P.Value);
      break;
    case Part::CompressedMem:
      Text += formatImm(P.Value) + "(" + RegName(P.RegNo) + ")";
      AddOp(RISCV_OP_IMM, 0, P.Value);
      AddOp(RISCV_OP_REG, P.RegNo, 0);
      break;
    case Part::AtomicBase:
      Text += "(" + RegName(P.RegNo) + ")";
      AddOp(RISCV_OP_REG, P.RegNo, 0);
      break;
    case Part::Csr:
      if (const char* Name = csrName(static_cast<unsigned int>(P.Value))) {
        Text += Name;
      } else {
        Text += std::to_string(static_cast<unsigned int>(P.Value));
      }
      break;
    case Part::Fence:
      Text += fenceSet(P.Value);
      break;
    case Part::RoundingMode:
      Text += roundingModeName(static_cast<riscv_rounding_mode>(P.Value));
      break;
    }
  }

  Insn.id = Id;
  std::snprintf(Insn.mnemonic, sizeof(Insn.mnemonic), "%s", Mnemonic.c_str());
  std::snprintf(Insn.op_str, sizeof(Insn.op_str), "%s", Text.c_str());
  std::memcpy(D.operands, Ops, sizeof(cs_riscv_op) * OpCount);
  D.op_count = static_cast<uint8_t>(OpCount);
  setGenericGroups(Insn);
  return true;
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
