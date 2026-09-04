//===- RiscvPrettyPrinter.cpp -----------------------------------*- C++ -*-===//
//
//  Copyright (C) 2026 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//===----------------------------------------------------------------------===//

#include "RiscvPrettyPrinter.hpp"
#include "StringUtils.hpp"

#include <algorithm>
#include <cassert>
#include <capstone/capstone.h>
#include <capstone/riscv.h>
#include <functional>
#include <iostream>
#include <sstream>
#include <string_view>
#include <vector>

namespace gtirb_pprint {

// Replace special characters rejected by assembler with '.' character.
static std::string replaceSpecialChars(const std::string& S) {
  std::string Name(S);
  for (size_t I = 0; I < Name.size(); I++) {
    switch (Name[I]) {
    case '?':
    case '(':
    case ')':
    case '{':
    case '}':
    case ' ':
    case ':':
      Name[I] = '.';
      continue;
    default:
      continue;
    }
  }
  return Name;
}

// RISC-V mapping symbols describe whether following bytes are instructions or
// data; they are assembler metadata, not source-level labels.  In particular,
// `$x<isa>` embeds an ISA string.  Renaming duplicate mapping symbols with the
// generic `_disambig_...` suffix makes GAS parse that suffix as bogus ISA
// extensions and produces a malformed .riscv.attributes section.  The
// disassembler has already used these symbols to classify the input, and GAS
// regenerates the appropriate mapping symbols for the emitted instructions,
// so omit their definitions and never select them as branch labels.
static bool isRiscvMappingSymbol(const gtirb::Symbol& Symbol) {
  const std::string& Name = Symbol.getName();
  return Name == "$x" || Name == "$d" || Name.compare(0, 3, "$x.") == 0 ||
         Name.compare(0, 3, "$d.") == 0 ||
         Name.compare(0, 4, "$xrv") == 0;
}

static bool isCompressedLoadStore(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_C_FLD:
  case RISCV_INS_C_FLDSP:
  case RISCV_INS_C_FLW:
  case RISCV_INS_C_FLWSP:
  case RISCV_INS_C_FSD:
  case RISCV_INS_C_FSDSP:
  case RISCV_INS_C_FSW:
  case RISCV_INS_C_FSWSP:
  case RISCV_INS_C_LD:
  case RISCV_INS_C_LDSP:
  case RISCV_INS_C_LW:
  case RISCV_INS_C_LWSP:
  case RISCV_INS_C_SD:
  case RISCV_INS_C_SDSP:
  case RISCV_INS_C_SW:
  case RISCV_INS_C_SWSP:
    return true;
  default:
    return false;
  }
}

static bool isLoadReserved(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_LR_D:
  case RISCV_INS_LR_D_AQ:
  case RISCV_INS_LR_D_AQ_RL:
  case RISCV_INS_LR_D_RL:
  case RISCV_INS_LR_W:
  case RISCV_INS_LR_W_AQ:
  case RISCV_INS_LR_W_AQ_RL:
  case RISCV_INS_LR_W_RL:
    return true;
  default:
    return false;
  }
}

static bool isStoreConditionalOrAtomic(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_AMOADD_D:
  case RISCV_INS_AMOADD_D_AQ:
  case RISCV_INS_AMOADD_D_AQ_RL:
  case RISCV_INS_AMOADD_D_RL:
  case RISCV_INS_AMOADD_W:
  case RISCV_INS_AMOADD_W_AQ:
  case RISCV_INS_AMOADD_W_AQ_RL:
  case RISCV_INS_AMOADD_W_RL:
  case RISCV_INS_AMOAND_D:
  case RISCV_INS_AMOAND_D_AQ:
  case RISCV_INS_AMOAND_D_AQ_RL:
  case RISCV_INS_AMOAND_D_RL:
  case RISCV_INS_AMOAND_W:
  case RISCV_INS_AMOAND_W_AQ:
  case RISCV_INS_AMOAND_W_AQ_RL:
  case RISCV_INS_AMOAND_W_RL:
  case RISCV_INS_AMOMAX_D:
  case RISCV_INS_AMOMAX_D_AQ:
  case RISCV_INS_AMOMAX_D_AQ_RL:
  case RISCV_INS_AMOMAX_D_RL:
  case RISCV_INS_AMOMAX_W:
  case RISCV_INS_AMOMAX_W_AQ:
  case RISCV_INS_AMOMAX_W_AQ_RL:
  case RISCV_INS_AMOMAX_W_RL:
  case RISCV_INS_AMOMAXU_D:
  case RISCV_INS_AMOMAXU_D_AQ:
  case RISCV_INS_AMOMAXU_D_AQ_RL:
  case RISCV_INS_AMOMAXU_D_RL:
  case RISCV_INS_AMOMAXU_W:
  case RISCV_INS_AMOMAXU_W_AQ:
  case RISCV_INS_AMOMAXU_W_AQ_RL:
  case RISCV_INS_AMOMAXU_W_RL:
  case RISCV_INS_AMOMIN_D:
  case RISCV_INS_AMOMIN_D_AQ:
  case RISCV_INS_AMOMIN_D_AQ_RL:
  case RISCV_INS_AMOMIN_D_RL:
  case RISCV_INS_AMOMIN_W:
  case RISCV_INS_AMOMIN_W_AQ:
  case RISCV_INS_AMOMIN_W_AQ_RL:
  case RISCV_INS_AMOMIN_W_RL:
  case RISCV_INS_AMOMINU_D:
  case RISCV_INS_AMOMINU_D_AQ:
  case RISCV_INS_AMOMINU_D_AQ_RL:
  case RISCV_INS_AMOMINU_D_RL:
  case RISCV_INS_AMOMINU_W:
  case RISCV_INS_AMOMINU_W_AQ:
  case RISCV_INS_AMOMINU_W_AQ_RL:
  case RISCV_INS_AMOMINU_W_RL:
  case RISCV_INS_AMOOR_D:
  case RISCV_INS_AMOOR_D_AQ:
  case RISCV_INS_AMOOR_D_AQ_RL:
  case RISCV_INS_AMOOR_D_RL:
  case RISCV_INS_AMOOR_W:
  case RISCV_INS_AMOOR_W_AQ:
  case RISCV_INS_AMOOR_W_AQ_RL:
  case RISCV_INS_AMOOR_W_RL:
  case RISCV_INS_AMOSWAP_D:
  case RISCV_INS_AMOSWAP_D_AQ:
  case RISCV_INS_AMOSWAP_D_AQ_RL:
  case RISCV_INS_AMOSWAP_D_RL:
  case RISCV_INS_AMOSWAP_W:
  case RISCV_INS_AMOSWAP_W_AQ:
  case RISCV_INS_AMOSWAP_W_AQ_RL:
  case RISCV_INS_AMOSWAP_W_RL:
  case RISCV_INS_AMOXOR_D:
  case RISCV_INS_AMOXOR_D_AQ:
  case RISCV_INS_AMOXOR_D_AQ_RL:
  case RISCV_INS_AMOXOR_D_RL:
  case RISCV_INS_AMOXOR_W:
  case RISCV_INS_AMOXOR_W_AQ:
  case RISCV_INS_AMOXOR_W_AQ_RL:
  case RISCV_INS_AMOXOR_W_RL:
  case RISCV_INS_SC_D:
  case RISCV_INS_SC_D_AQ:
  case RISCV_INS_SC_D_AQ_RL:
  case RISCV_INS_SC_D_RL:
  case RISCV_INS_SC_W:
  case RISCV_INS_SC_W_AQ:
  case RISCV_INS_SC_W_AQ_RL:
  case RISCV_INS_SC_W_RL:
    return true;
  default:
    return false;
  }
}

static bool isCsrInstruction(const cs_insn& Inst) {
  return ascii_str_tolower(Inst.mnemonic).rfind("csr", 0) == 0;
}

// Capstone renders the floating-point rounding mode in op_str, but the
// RISC-V detailed operand array used below omits that operand.  Reprinting only
// the detailed operands therefore changes an explicitly encoded mode such as
// RTZ into the assembler default (DYN).  Recover the trailing architectural
// token from Capstone's own text and keep it separate from symbolizable
// immediates.
static std::optional<std::string_view>
getTrailingRoundingMode(const cs_insn& Inst) {
  std::string_view Operands(Inst.op_str);
  const size_t Comma = Operands.rfind(',');
  if (Comma == std::string_view::npos) {
    return std::nullopt;
  }

  std::string_view Token = Operands.substr(Comma + 1);
  const size_t Begin = Token.find_first_not_of(" \t");
  if (Begin == std::string_view::npos) {
    return std::nullopt;
  }
  Token.remove_prefix(Begin);
  const size_t End = Token.find_last_not_of(" \t");
  Token = Token.substr(0, End + 1);

  if (Token == "rne" || Token == "rtz" || Token == "rdn" ||
      Token == "rup" || Token == "rmm" || Token == "dyn") {
    return Token;
  }
  return std::nullopt;
}

static bool isGpRegister(unsigned int Reg) {
  return Reg == RISCV_REG_GP;
}

static bool isGpRelative(const gtirb::SymAddrAddr* SymExpr) {
  return SymExpr && SymExpr->Sym2 &&
         SymExpr->Sym2->getName() == "__global_pointer$" &&
         SymExpr->Scale == 1 && SymExpr->Offset == 0;
}

static const gtirb::Symbol*
getGpRelativeTargetSymbol(const gtirb::SymAddrAddr* SymExpr) {
  return isGpRelative(SymExpr) ? SymExpr->Sym1 : nullptr;
}

static bool isIntegerLoad(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_LB:
  case RISCV_INS_LBU:
  case RISCV_INS_LD:
  case RISCV_INS_LH:
  case RISCV_INS_LHU:
  case RISCV_INS_LW:
  case RISCV_INS_LWU:
    return true;
  default:
    return false;
  }
}

static bool isCompressedIntegerLoad(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_C_LD:
  case RISCV_INS_C_LDSP:
  case RISCV_INS_C_LW:
  case RISCV_INS_C_LWSP:
    return true;
  default:
    return false;
  }
}

static gtirb::SymAttributeSet makeAttributeSet(gtirb::SymAttribute Attr) {
  gtirb::SymAttributeSet Attrs;
  Attrs.insert(Attr);
  return Attrs;
}

static const gtirb::SymbolicExpression*
getInstructionSymbolicExpression(const gtirb::CodeBlock& Block,
                                 const cs_insn& Inst) {
  auto* ByteInterval = Block.getByteInterval();
  if (!ByteInterval || !ByteInterval->getAddress()) {
    return nullptr;
  }

  gtirb::Addr Ea(Inst.address);
  return ByteInterval->getSymbolicExpression(Ea - *ByteInterval->getAddress());
}

static bool isValidCompressedLuiImmediate(int64_t Imm) {
  return (Imm >= 1 && Imm <= 31) || (Imm >= -32 && Imm <= -1) ||
         (Imm >= 0xfffe0 && Imm <= 0xfffff);
}

static const char* getUncompressedMemoryOpcode(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_C_FLD:
  case RISCV_INS_C_FLDSP:
    return "fld";
  case RISCV_INS_C_FLW:
  case RISCV_INS_C_FLWSP:
    return "flw";
  case RISCV_INS_C_FSD:
  case RISCV_INS_C_FSDSP:
    return "fsd";
  case RISCV_INS_C_FSW:
  case RISCV_INS_C_FSWSP:
    return "fsw";
  case RISCV_INS_C_LD:
  case RISCV_INS_C_LDSP:
    return "ld";
  case RISCV_INS_C_LW:
  case RISCV_INS_C_LWSP:
    return "lw";
  case RISCV_INS_C_SD:
  case RISCV_INS_C_SDSP:
    return "sd";
  case RISCV_INS_C_SW:
  case RISCV_INS_C_SWSP:
    return "sw";
  default:
    return nullptr;
  }
}

static bool hasCompressedMemoryOperand(const cs_insn& Inst) {
  const cs_riscv& Detail = Inst.detail->riscv;
  return isCompressedLoadStore(Inst.id) && Detail.op_count == 3 &&
         Detail.operands[1].type == RISCV_OP_IMM &&
         Detail.operands[2].type == RISCV_OP_REG;
}

static bool isPcRelativeImmediate(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_BEQ:
  case RISCV_INS_BGE:
  case RISCV_INS_BGEU:
  case RISCV_INS_BLT:
  case RISCV_INS_BLTU:
  case RISCV_INS_BNE:
  case RISCV_INS_C_BEQZ:
  case RISCV_INS_C_BNEZ:
  case RISCV_INS_C_J:
  case RISCV_INS_C_JAL:
  case RISCV_INS_JAL:
    return true;
  default:
    return false;
  }
}

static bool isConditionalBranch(unsigned int Id) {
  switch (Id) {
  case RISCV_INS_BEQ:
  case RISCV_INS_BGE:
  case RISCV_INS_BGEU:
  case RISCV_INS_BLT:
  case RISCV_INS_BLTU:
  case RISCV_INS_BNE:
  case RISCV_INS_C_BEQZ:
  case RISCV_INS_C_BNEZ:
    return true;
  default:
    return false;
  }
}

static bool isPltSectionName(const std::string& Name) {
  return Name == ".plt" || Name == ".plt.sec" || Name == ".plt.got";
}

static const char* getInvertedBranchOpcode(const cs_insn& Inst) {
  std::string Mnemonic = ascii_str_tolower(Inst.mnemonic);
  if (Mnemonic.rfind("c.", 0) == 0) {
    Mnemonic = Mnemonic.substr(2);
  }

  const cs_riscv& Detail = Inst.detail->riscv;
  if (Detail.op_count == 2) {
    if (Mnemonic == "beqz") {
      return "bnez";
    }
    if (Mnemonic == "bnez") {
      return "beqz";
    }
    if (Mnemonic == "bltz") {
      return "bgez";
    }
    if (Mnemonic == "bgez") {
      return "bltz";
    }
    if (Mnemonic == "blez") {
      return "bgtz";
    }
    if (Mnemonic == "bgtz") {
      return "blez";
    }
    if (Inst.id == RISCV_INS_BEQ) {
      return "bnez";
    }
    if (Inst.id == RISCV_INS_BNE) {
      return "beqz";
    }
    if (Inst.id == RISCV_INS_BLT) {
      return "bgez";
    }
    if (Inst.id == RISCV_INS_BGE) {
      return "bltz";
    }
  }

  switch (Inst.id) {
  case RISCV_INS_BEQ:
    return "bne";
  case RISCV_INS_BGE:
    return "blt";
  case RISCV_INS_BGEU:
    return "bltu";
  case RISCV_INS_BLT:
    return "bge";
  case RISCV_INS_BLTU:
    return "bgeu";
  case RISCV_INS_BNE:
    return "beq";
  case RISCV_INS_C_BEQZ:
    return "bnez";
  case RISCV_INS_C_BNEZ:
    return "beqz";
  default:
    return nullptr;
  }
}

std::string RiscvSyntax::formatSectionName(const std::string& S) const {
  return replaceSpecialChars(S);
}

std::string RiscvSyntax::formatFunctionName(const std::string& S) const {
  return replaceSpecialChars(S);
}

std::string RiscvSyntax::formatSymbolName(const std::string& S) const {
  return replaceSpecialChars(S);
}

RiscvPrettyPrinter::RiscvPrettyPrinter(gtirb::Context& context_,
                                       const gtirb::Module& module_,
                                       const ElfSyntax& syntax_,
                                       const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {
  unsigned int mode =
      getModuleISA(module_) == "riscv64" ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
  mode |= CS_MODE_RISCVC;

  if (module_.getByteOrder() == gtirb::ByteOrder::Big) {
    mode |= CS_MODE_BIG_ENDIAN;
  } else if (module_.getByteOrder() == gtirb::ByteOrder::Little) {
    mode |= CS_MODE_LITTLE_ENDIAN;
  } else {
    mode |= CS_MODE_LITTLE_ENDIAN;
  }

  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_RISCV, static_cast<cs_mode>(mode), &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  collectRelocatedPcrelAnchors();
  collectTargetLabels();
  collectLocalBranchLabels();
  collectInteriorCodeSymbols();
}

std::string RiscvPrettyPrinter::getRegisterName(unsigned int reg) const {
  return reg == RISCV_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg);
}

bool RiscvPrettyPrinter::hasSymbolicAddiAlias(
    const gtirb::CodeBlock& block, const cs_insn& inst) {
  const cs_riscv& Detail = inst.detail->riscv;
  std::string Mnemonic = ascii_str_tolower(inst.mnemonic);

  if ((inst.id != RISCV_INS_ADDI && Mnemonic != "mv") ||
      Detail.op_count != 2 || Detail.operands[0].type != RISCV_OP_REG ||
      Detail.operands[1].type != RISCV_OP_REG) {
    return false;
  }

  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  return Symex != nullptr && std::get_if<gtirb::SymAddrConst>(Symex) != nullptr;
}

bool RiscvPrettyPrinter::hasSymbolicJalrAlias(
    const gtirb::CodeBlock& block, const cs_insn& inst) {
  const cs_riscv& Detail = inst.detail->riscv;
  std::string Mnemonic = ascii_str_tolower(inst.mnemonic);

  if ((inst.id != RISCV_INS_JALR && Mnemonic != "jalr") ||
      Detail.op_count != 1 || Detail.operands[0].type != RISCV_OP_REG) {
    return false;
  }

  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  const auto* Symaddr = std::get_if<gtirb::SymAddrConst>(Symex);
  return Symaddr != nullptr &&
         Symaddr->Attributes.count(gtirb::SymAttribute::LO) != 0;
}

bool RiscvPrettyPrinter::hasSymbolicCompressedAddi(
    const gtirb::CodeBlock& block, const cs_insn& inst) {
  const cs_riscv& Detail = inst.detail->riscv;

  if (inst.id != RISCV_INS_C_ADDI || Detail.op_count != 2 ||
      Detail.operands[0].type != RISCV_OP_REG ||
      Detail.operands[1].type != RISCV_OP_IMM) {
    return false;
  }

  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  return Symex != nullptr && std::get_if<gtirb::SymAddrConst>(Symex) != nullptr;
}

bool RiscvPrettyPrinter::hasSymbolicCompressedAddiw(
    const gtirb::CodeBlock& block, const cs_insn& inst) {
  const cs_riscv& Detail = inst.detail->riscv;

  if (inst.id != RISCV_INS_C_ADDIW || Detail.op_count != 2 ||
      Detail.operands[0].type != RISCV_OP_REG ||
      Detail.operands[1].type != RISCV_OP_IMM) {
    return false;
  }

  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  return Symex != nullptr && std::get_if<gtirb::SymAddrConst>(Symex) != nullptr;
}

bool RiscvPrettyPrinter::shouldPrintCompressedLuiAsLui(
    const gtirb::CodeBlock& block, const cs_insn& inst) {
  const cs_riscv& Detail = inst.detail->riscv;

  if (inst.id != RISCV_INS_C_LUI || Detail.op_count != 2 ||
      Detail.operands[0].type != RISCV_OP_REG ||
      Detail.operands[1].type != RISCV_OP_IMM) {
    return false;
  }

  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  return Symex != nullptr ||
         !isValidCompressedLuiImmediate(Detail.operands[1].imm);
}

void RiscvPrettyPrinter::collectTargetLabels() {
  std::map<uint64_t, std::set<const gtirb::Symbol*, CmpSymPtr>>
      SymbolsByAddress;
  for (const auto& Symbol : module.symbols()) {
    auto Addr = Symbol.getAddress();
    if (Addr && !RelocatedPcrelAnchors.count(&Symbol) &&
        !isRiscvMappingSymbol(Symbol) &&
        !shouldSkip(policy, Symbol)) {
      SymbolsByAddress[static_cast<uint64_t>(*Addr)].insert(&Symbol);
    }
  }

  for (const auto& [Address, Symbols] : SymbolsByAddress) {
    TargetLabels[Address] = getSymbolName(*getBestSymbol(Symbols));
  }
}

void RiscvPrettyPrinter::collectRelocatedPcrelAnchors() {
  struct HighRelocation {
    const gtirb::ByteInterval* Interval;
    uint64_t Offset;
    uint64_t Address;
    unsigned int Register;
  };
  struct LowRelocation {
    const gtirb::ByteInterval* Interval;
    uint64_t Offset;
    uint64_t Address;
    unsigned int Register;
    const gtirb::Symbol* Anchor;
  };

  std::map<const gtirb::ByteInterval*, std::vector<HighRelocation>> Highs;
  std::vector<LowRelocation> Lows;

  auto ReadWord = [&](const gtirb::ByteInterval& Interval,
                      uint64_t Offset) -> std::optional<uint32_t> {
    if (Offset > Interval.getInitializedSize() ||
        Interval.getInitializedSize() - Offset < 4) {
      return std::nullopt;
    }
    const uint8_t* Bytes = Interval.rawBytes<uint8_t>();
    uint32_t Word = 0;
    if (module.getByteOrder() == gtirb::ByteOrder::Big) {
      for (unsigned int I = 0; I < 4; ++I) {
        Word = (Word << 8) | Bytes[Offset + I];
      }
    } else {
      for (unsigned int I = 0; I < 4; ++I) {
        Word |= static_cast<uint32_t>(Bytes[Offset + I]) << (8 * I);
      }
    }
    return Word;
  };

  // A RISC-V %pcrel_lo relocation names a label on its paired AUIPC, not
  // merely the beginning of the surrounding function.  A rewrite can insert
  // bytes at that function boundary while leaving an integral/marker symbol
  // at the old location.  Recover the architectural pair from the relocation
  // attributes and the shared register, then emit the anchor at the AUIPC.
  for (auto SEE : module.symbolic_expressions()) {
    const auto* SAC =
        std::get_if<gtirb::SymAddrConst>(&SEE.getSymbolicExpression());
    if (!SAC || !SAC->Attributes.count(gtirb::SymAttribute::PCREL)) {
      continue;
    }
    const auto* Interval = SEE.getByteInterval();
    if (!Interval || !Interval->getAddress()) {
      continue;
    }
    const uint64_t Offset = SEE.getOffset();
    const auto Word = ReadWord(*Interval, Offset);
    if (!Word || (*Word & 0x3) != 0x3) {
      continue;
    }
    const uint64_t Address =
        static_cast<uint64_t>(*Interval->getAddress()) + Offset;
    if (SAC->Attributes.count(gtirb::SymAttribute::HI) &&
        (*Word & 0x7f) == 0x17) {
      Highs[Interval].push_back(
          {Interval, Offset, Address, (*Word >> 7) & 0x1f});
    } else if (SAC->Attributes.count(gtirb::SymAttribute::LO) && SAC->Sym) {
      Lows.push_back(
          {Interval, Offset, Address, (*Word >> 15) & 0x1f, SAC->Sym});
    }
  }

  for (auto& [Interval, Candidates] : Highs) {
    std::sort(Candidates.begin(), Candidates.end(),
              [](const HighRelocation& A, const HighRelocation& B) {
                return A.Offset < B.Offset;
              });
  }

  std::map<const gtirb::Symbol*, uint64_t> ProposedAddresses;
  std::set<const gtirb::Symbol*> AmbiguousAnchors;
  for (const LowRelocation& Low : Lows) {
    const auto AnchorAddress = Low.Anchor->getAddress();
    if (!AnchorAddress ||
        static_cast<uint64_t>(*AnchorAddress) > Low.Address) {
      continue;
    }
    const auto It = Highs.find(Low.Interval);
    if (It == Highs.end()) {
      continue;
    }

    const HighRelocation* Match = nullptr;
    for (auto Candidate = It->second.rbegin();
         Candidate != It->second.rend(); ++Candidate) {
      if (Candidate->Offset > Low.Offset) {
        continue;
      }
      if (Candidate->Address < static_cast<uint64_t>(*AnchorAddress)) {
        break;
      }
      if (Candidate->Register == Low.Register) {
        Match = &*Candidate;
        break;
      }
    }
    if (!Match || Match->Address == static_cast<uint64_t>(*AnchorAddress)) {
      continue;
    }

    auto [Proposal, Inserted] =
        ProposedAddresses.emplace(Low.Anchor, Match->Address);
    if (!Inserted && Proposal->second != Match->Address) {
      AmbiguousAnchors.insert(Low.Anchor);
    }
  }

  for (const auto& [Anchor, Address] : ProposedAddresses) {
    if (AmbiguousAnchors.count(Anchor) || isRiscvMappingSymbol(*Anchor) ||
        shouldSkip(policy, *Anchor)) {
      continue;
    }
    RelocatedPcrelAnchors.insert(Anchor);
    RelocatedPcrelAnchorsByAddress[Address].insert(Anchor);
  }
}

void RiscvPrettyPrinter::collectLocalBranchLabels() {
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);

  std::set<uint64_t> InstructionAddresses;
  std::set<uint64_t> BranchTargets;

  for (const auto& Block : module.code_blocks()) {
    if (!Block.getAddress()) {
      continue;
    }

    cs_insn* Insn;
    size_t Count = cs_disasm(this->csHandle, Block.rawBytes<uint8_t>(),
                             Block.getSize(),
                             static_cast<uint64_t>(*Block.getAddress()), 0,
                             &Insn);
    std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> FreeInsn(
        Insn, [Count](cs_insn* I) { cs_free(I, Count); });

    for (size_t I = 0; I < Count; I++) {
      InstructionAddresses.insert(Insn[I].address);
      if (!isPcRelativeImmediate(Insn[I].id)) {
        continue;
      }

      const cs_riscv& Detail = Insn[I].detail->riscv;
      for (int J = 0; J < Detail.op_count; J++) {
        const cs_riscv_op& Op = Detail.operands[J];
        if (Op.type != RISCV_OP_IMM) {
          continue;
        }

        gtirb::Addr Ea(Insn[I].address);
        gtirb::Addr Target =
            Op.imm >= 0 ? Ea + static_cast<uint64_t>(Op.imm)
                        : Ea - static_cast<uint64_t>(-Op.imm);
        BranchTargets.insert(static_cast<uint64_t>(Target));
      }
    }
  }

  // A relocation-free branch can still be made layout-safe when its decoded
  // destination is an instruction that this printer will emit: define and
  // reference a synthetic local label there.  Do not create a label for an
  // interior/non-instruction byte, because no definition would be printed;
  // printOpImmediate will retain that unusual fixed displacement as `.+N`.
  for (uint64_t Target : BranchTargets) {
    if (!getTargetLabel(gtirb::Addr(Target)) &&
        InstructionAddresses.count(Target)) {
      LocalBranchLabels.insert(Target);
    }
  }
}

void RiscvPrettyPrinter::collectInteriorCodeSymbols() {
  for (const auto& Symbol : module.symbols()) {
    auto* Block = Symbol.getReferent<gtirb::CodeBlock>();
    auto Address = Symbol.getAddress();
    if (!Block || Block->getSize() != 0 || Symbol.getAtEnd() || !Address ||
        RelocatedPcrelAnchors.count(&Symbol) ||
        isRiscvMappingSymbol(Symbol) || shouldSkip(policy, Symbol)) {
      continue;
    }

    InteriorCodeSymbols[static_cast<uint64_t>(*Address)].insert(&Symbol);
  }
}

std::string RiscvPrettyPrinter::getLocalBranchLabel(gtirb::Addr Target) const {
  std::stringstream Label;
  Label << ".Lgtirb_riscv_" << std::hex << static_cast<uint64_t>(Target);
  return Label.str();
}

std::string RiscvPrettyPrinter::getLongBranchSkipLabel(
    gtirb::Addr Address) const {
  std::stringstream Label;
  Label << ".Lgtirb_riscv_long_branch_" << std::hex
        << static_cast<uint64_t>(Address);
  return Label.str();
}

void RiscvPrettyPrinter::printInstruction(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst,
                                          const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  printComments(os, offset, inst.size);
  printPrototype(os, block, offset);
  printCFIDirectives(os, offset);
  if (auto It =
          RelocatedPcrelAnchorsByAddress.find(static_cast<uint64_t>(ea));
      It != RelocatedPcrelAnchorsByAddress.end()) {
    for (const gtirb::Symbol* Symbol : It->second) {
      ElfPrettyPrinter::printSymbolDefinition(os, *Symbol);
    }
  }
  if (auto It = InteriorCodeSymbols.find(static_cast<uint64_t>(ea));
      It != InteriorCodeSymbols.end()) {
    for (const gtirb::Symbol* Symbol : It->second) {
      printSymbolDefinition(os, *Symbol);
    }
  }
  if (LocalBranchLabels.count(static_cast<uint64_t>(ea))) {
    os << getLocalBranchLabel(ea) << ":\n";
  }

  if (SuppressedInstructionAddresses.erase(static_cast<uint64_t>(ea))) {
    return;
  }

  if (printLongConditionalBranch(os, block, inst, ea)) {
    return;
  }

  if (printPltCall(os, block, inst, ea)) {
    return;
  }

  if (printDirectCallRelocation(os, block, inst, ea)) {
    return;
  }

  if (printPltCallRelocation(os, block, inst, ea)) {
    return;
  }

  if (printGpRelativeCopyRelocation(os, block, inst, ea)) {
    return;
  }

  std::stringstream InstructLine;
  printEA(InstructLine, ea);

  std::string opcode = ascii_str_tolower(inst.mnemonic);
  if (hasSymbolicAddiAlias(block, inst)) {
    opcode = "addi";
  } else if (hasSymbolicJalrAlias(block, inst)) {
    opcode = "jalr";
  } else if (hasSymbolicCompressedAddi(block, inst)) {
    opcode = "addi";
  } else if (hasSymbolicCompressedAddiw(block, inst)) {
    opcode = "addiw";
  } else if (shouldPrintCompressedLuiAsLui(block, inst)) {
    opcode = "lui";
  } else {
    const char* UncompressedMemoryOpcode =
        getUncompressedMemoryOpcode(inst.id);
    if (UncompressedMemoryOpcode != nullptr &&
        getInstructionSymbolicExpression(block, inst) != nullptr) {
      opcode = UncompressedMemoryOpcode;
    }
  }
  InstructLine << "  " << opcode;
  if (inst.detail->riscv.op_count != 0) {
    InstructLine << ' ';
    m_accum_comment.clear();
    printOperandList(InstructLine, block, inst);
    if (!m_accum_comment.empty()) {
      InstructLine << " " << syntax.comment() << " " << m_accum_comment;
      m_accum_comment.clear();
    }
  }
  printCommentableLine(InstructLine, os, ea);
  os << '\n';
}

void RiscvPrettyPrinter::printSymbolDefinition(
    std::ostream& os, const gtirb::Symbol& Symbol) {
  if (isRiscvMappingSymbol(Symbol) ||
      RelocatedPcrelAnchors.count(&Symbol)) {
    return;
  }
  const auto* Block = Symbol.getReferent<gtirb::CodeBlock>();
  if (Block && Block->getSize() == 0 && !Symbol.getAtEnd() &&
      !PrintedInteriorCodeSymbols.insert(&Symbol).second) {
    return;
  }
  ElfPrettyPrinter::printSymbolDefinition(os, Symbol);
}

void RiscvPrettyPrinter::printSymbolDefinitionRelativeToPC(
    std::ostream& os, const gtirb::Symbol& Symbol, gtirb::Addr PC) {
  if (isRiscvMappingSymbol(Symbol) ||
      RelocatedPcrelAnchors.count(&Symbol)) {
    return;
  }
  const auto* Block = Symbol.getReferent<gtirb::CodeBlock>();
  if (Block && Block->getSize() == 0 && !Symbol.getAtEnd() &&
      !PrintedInteriorCodeSymbols.insert(&Symbol).second) {
    return;
  }
  ElfPrettyPrinter::printSymbolDefinitionRelativeToPC(os, Symbol, PC);
}

void RiscvPrettyPrinter::printSymbolicData(
    std::ostream& os,
    const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE,
    uint64_t Size, std::optional<std::string> Type) {
  if ((Type && (*Type == "uleb128" || *Type == "sleb128")) &&
      std::get_if<gtirb::SymAddrAddr>(&SEE.getSymbolicExpression())) {
    auto Bytes = SEE.getByteInterval()->rawBytes<uint8_t>();
    auto Offset = SEE.getOffset();

    os << syntax.byteData() << ' ';
    std::ios_base::fmtflags Flags = os.flags();
    for (uint64_t I = 0; I < Size; I++) {
      if (I != 0) {
        os << ", ";
      }
      os << "0x" << std::hex << static_cast<uint32_t>(Bytes[Offset + I]);
    }
    os.flags(Flags);
    return;
  }

  PrettyPrinterBase::printSymbolicData(os, SEE, Size, Type);
}

const gtirb::Symbol* RiscvPrettyPrinter::getGpRelativeCopyRelocationSymbol(
    const gtirb::SymbolicExpression* Symbolic) const {
  const auto* SAA = std::get_if<gtirb::SymAddrAddr>(Symbolic);
  const gtirb::Symbol* Symbol = getGpRelativeTargetSymbol(SAA);
  if (!Symbol) {
    return nullptr;
  }

  if (Symbol->getReferent<gtirb::ProxyBlock>()) {
    return Symbol;
  }

  gtirb::Symbol* Forwarded = getForwardedSymbol(Symbol);
  if (!Forwarded || !Forwarded->getReferent<gtirb::ProxyBlock>()) {
    return nullptr;
  }

  return Symbol;
}

void RiscvPrettyPrinter::printRelocationSymbol(
    std::ostream& os, const gtirb::Symbol* Symbol,
    const gtirb::SymAttributeSet& Attrs) {
  printSymExprPrefix(os, Attrs, true);
  printSymbolReference(os, Symbol);
  printSymExprSuffix(os, Attrs, true);
}

bool RiscvPrettyPrinter::printGpRelativeCopyRelocation(
    std::ostream& os, const gtirb::CodeBlock& block, const cs_insn& inst,
    gtirb::Addr Address) {
  const gtirb::SymbolicExpression* Symbolic =
      getInstructionSymbolicExpression(block, inst);
  const gtirb::Symbol* Symbol = getGpRelativeCopyRelocationSymbol(Symbolic);
  if (!Symbol) {
    return false;
  }

  const cs_riscv& Detail = inst.detail->riscv;
  std::string Opcode = ascii_str_tolower(inst.mnemonic);

  auto PrintLui = [&](std::ostream& Out, unsigned int Reg) {
    std::stringstream Line;
    printEA(Line, Address);
    Line << "  lui " << getRegisterName(Reg) << ',';
    m_accum_comment.clear();
    printRelocationSymbol(Line, Symbol,
                          makeAttributeSet(gtirb::SymAttribute::HI));
    if (!m_accum_comment.empty()) {
      Line << " " << syntax.comment() << " " << m_accum_comment;
      m_accum_comment.clear();
    }
    printCommentableLine(Line, Out, Address);
    Out << '\n';
  };

  auto PrintLoRegInstruction = [&](std::ostream& Out, const char* Mnemonic,
                                   unsigned int Reg) {
    std::stringstream Line;
    printEA(Line, Address);
    Line << "  " << Mnemonic << ' ' << getRegisterName(Reg) << ','
         << getRegisterName(Reg) << ',';
    m_accum_comment.clear();
    printRelocationSymbol(Line, Symbol,
                          makeAttributeSet(gtirb::SymAttribute::LO));
    if (!m_accum_comment.empty()) {
      Line << " " << syntax.comment() << " " << m_accum_comment;
      m_accum_comment.clear();
    }
    printCommentableLine(Line, Out, Address);
    Out << '\n';
  };

  auto PrintLoMemInstruction = [&](std::ostream& Out, const char* Mnemonic,
                                   unsigned int Reg) {
    std::stringstream Line;
    printEA(Line, Address);
    Line << "  " << Mnemonic << ' ' << getRegisterName(Reg) << ',';
    m_accum_comment.clear();
    printRelocationSymbol(Line, Symbol,
                          makeAttributeSet(gtirb::SymAttribute::LO));
    Line << '(' << getRegisterName(Reg) << ')';
    if (!m_accum_comment.empty()) {
      Line << " " << syntax.comment() << " " << m_accum_comment;
      m_accum_comment.clear();
    }
    printCommentableLine(Line, Out, Address);
    Out << '\n';
  };

  if ((inst.id == RISCV_INS_ADDI || Opcode == "addi") &&
      Detail.op_count == 3 && Detail.operands[0].type == RISCV_OP_REG &&
      Detail.operands[1].type == RISCV_OP_REG &&
      Detail.operands[2].type == RISCV_OP_IMM &&
      isGpRegister(Detail.operands[1].reg) &&
      Detail.operands[0].reg != RISCV_REG_ZERO) {
    unsigned int Reg = Detail.operands[0].reg;
    PrintLui(os, Reg);
    PrintLoRegInstruction(os, "addi", Reg);
    return true;
  }

  if (isIntegerLoad(inst.id) && Detail.op_count == 2 &&
      Detail.operands[0].type == RISCV_OP_REG &&
      Detail.operands[1].type == RISCV_OP_MEM &&
      isGpRegister(Detail.operands[1].mem.base) &&
      Detail.operands[0].reg != RISCV_REG_ZERO) {
    unsigned int Reg = Detail.operands[0].reg;
    PrintLui(os, Reg);
    PrintLoMemInstruction(os, Opcode.c_str(), Reg);
    return true;
  }

  if (isCompressedIntegerLoad(inst.id) && hasCompressedMemoryOperand(inst) &&
      Detail.operands[0].type == RISCV_OP_REG &&
      isGpRegister(Detail.operands[2].reg) &&
      Detail.operands[0].reg != RISCV_REG_ZERO) {
    unsigned int Reg = Detail.operands[0].reg;
    PrintLui(os, Reg);
    PrintLoMemInstruction(os, getUncompressedMemoryOpcode(inst.id), Reg);
    return true;
  }

  return false;
}

bool RiscvPrettyPrinter::printLongConditionalBranch(
    std::ostream& os, const gtirb::CodeBlock& block, const cs_insn& inst,
    gtirb::Addr Address) {
  if (!isConditionalBranch(inst.id)) {
    return false;
  }

  const char* Opcode = getInvertedBranchOpcode(inst);
  if (Opcode == nullptr) {
    return false;
  }

  const cs_riscv& Detail = inst.detail->riscv;
  if (Detail.op_count < 2 ||
      Detail.operands[Detail.op_count - 1].type != RISCV_OP_IMM) {
    return false;
  }

  const std::string SkipLabel = getLongBranchSkipLabel(Address);

  std::stringstream BranchLine;
  printEA(BranchLine, Address);
  BranchLine << "  " << Opcode << ' ';
  m_accum_comment.clear();
  for (int I = 0; I < Detail.op_count - 1; I++) {
    if (I != 0) {
      BranchLine << ',';
    }
    printOperand(BranchLine, block, inst, I);
  }
  BranchLine << ',' << SkipLabel;
  if (!m_accum_comment.empty()) {
    BranchLine << " " << syntax.comment() << " " << m_accum_comment;
    m_accum_comment.clear();
  }
  printCommentableLine(BranchLine, os, Address);
  os << '\n';

  std::stringstream JumpLine;
  printEA(JumpLine, Address);
  JumpLine << "  j ";
  m_accum_comment.clear();
  printOperand(JumpLine, block, inst, Detail.op_count - 1);
  if (!m_accum_comment.empty()) {
    JumpLine << " " << syntax.comment() << " " << m_accum_comment;
    m_accum_comment.clear();
  }
  printCommentableLine(JumpLine, os, Address);
  os << '\n';
  os << SkipLabel << ":\n\n";
  return true;
}

bool RiscvPrettyPrinter::isPltCall(const cs_insn& inst) const {
  std::string Mnemonic = ascii_str_tolower(inst.mnemonic);
  const cs_riscv& Detail = inst.detail->riscv;

  if (inst.id == RISCV_INS_C_JAL || Mnemonic == "c.jal") {
    return true;
  }

  if (inst.id != RISCV_INS_JAL && Mnemonic != "jal") {
    return false;
  }

  if (Detail.op_count == 1) {
    return Mnemonic == "jal";
  }
  return Detail.op_count >= 2 && Detail.operands[0].type == RISCV_OP_REG &&
         Detail.operands[0].reg == RISCV_REG_RA;
}

bool RiscvPrettyPrinter::isPltTailCall(const cs_insn& inst) const {
  std::string Mnemonic = ascii_str_tolower(inst.mnemonic);
  const cs_riscv& Detail = inst.detail->riscv;

  if (Mnemonic == "j" || Mnemonic == "c.j") {
    return true;
  }

  return inst.id == RISCV_INS_JAL && Detail.op_count >= 2 &&
         Detail.operands[0].type == RISCV_OP_REG &&
         Detail.operands[0].reg == RISCV_REG_ZERO;
}

std::optional<std::string>
RiscvPrettyPrinter::getPltTargetName(const gtirb::CodeBlock& block,
                                     const cs_insn& inst) const {
  gtirb::Addr Ea(inst.address);
  const gtirb::SymbolicExpression* Symex =
      block.getByteInterval()->getSymbolicExpression(
          Ea - *block.getByteInterval()->getAddress());
  const auto* SymAddr = std::get_if<gtirb::SymAddrConst>(Symex);
  if (!SymAddr || !SymAddr->Sym) {
    return std::nullopt;
  }

  const auto* Block = SymAddr->Sym->getReferent<gtirb::CodeBlock>();
  if (!Block || !Block->getByteInterval() ||
      !Block->getByteInterval()->getSection()) {
    return std::nullopt;
  }

  if (!isPltSectionName(Block->getByteInterval()->getSection()->getName())) {
    return std::nullopt;
  }

  if (auto* Target = getForwardedSymbol(SymAddr->Sym)) {
    return getSymbolName(*Target);
  }

  return std::nullopt;
}

std::optional<std::string> RiscvPrettyPrinter::getDirectRelocationTargetName(
    const gtirb::CodeBlock& block, const cs_insn& inst) const {
  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  const auto* SymAddr = std::get_if<gtirb::SymAddrConst>(Symex);
  if (!SymAddr || !SymAddr->Sym) {
    return std::nullopt;
  }

  if (SymAddr->Sym->getReferent<gtirb::ProxyBlock>()) {
    return getSymbolName(*SymAddr->Sym) + "@plt";
  }

  if (const auto* Block = SymAddr->Sym->getReferent<gtirb::CodeBlock>()) {
    if (Block->getByteInterval() && Block->getByteInterval()->getSection() &&
        isPltSectionName(Block->getByteInterval()->getSection()->getName())) {
      if (auto* Target = getForwardedSymbol(SymAddr->Sym)) {
        return getSymbolName(*Target) + "@plt";
      }
      return getSymbolName(*SymAddr->Sym) + "@plt";
    }
  }

  std::stringstream Target;
  Target << getSymbolName(*SymAddr->Sym);
  if (SymAddr->Attributes.count(gtirb::SymAttribute::PLT)) {
    Target << "@plt";
  }
  return Target.str();
}

std::optional<std::string> RiscvPrettyPrinter::getPltRelocationTargetName(
    const gtirb::CodeBlock& block, const cs_insn& inst) const {
  const gtirb::SymbolicExpression* Symex =
      getInstructionSymbolicExpression(block, inst);
  const auto* SymAddr = std::get_if<gtirb::SymAddrConst>(Symex);
  if (!SymAddr || !SymAddr->Sym ||
      !SymAddr->Attributes.count(gtirb::SymAttribute::PLT)) {
    return std::nullopt;
  }

  return getSymbolName(*SymAddr->Sym);
}

bool RiscvPrettyPrinter::printPltCall(std::ostream& os,
                                      const gtirb::CodeBlock& block,
                                      const cs_insn& inst,
                                      gtirb::Addr Address) {
  auto Target = getPltTargetName(block, inst);
  if (!Target) {
    return false;
  }

  const char* Opcode = nullptr;
  if (isPltCall(inst)) {
    Opcode = "call";
  } else if (isPltTailCall(inst)) {
    Opcode = "tail";
  } else {
    return false;
  }

  std::stringstream Line;
  printEA(Line, Address);
  Line << "  " << Opcode << ' ' << *Target << "@plt";
  printCommentableLine(Line, os, Address);
  os << '\n';
  return true;
}

bool RiscvPrettyPrinter::printDirectCallRelocation(
    std::ostream& os, const gtirb::CodeBlock& block, const cs_insn& inst,
    gtirb::Addr Address) {
  if (inst.id != RISCV_INS_JAL) {
    return false;
  }

  bool IsCall = isPltCall(inst);
  bool IsTailCall = isPltTailCall(inst);
  if (!IsCall && !IsTailCall) {
    return false;
  }

  auto Target = getDirectRelocationTargetName(block, inst);
  if (!Target) {
    return false;
  }
  if (IsTailCall && Target->find("@plt") == std::string::npos &&
      Target->rfind(".L", 0) == 0) {
    return false;
  }

  std::stringstream Line;
  printEA(Line, Address);
  Line << "  " << (IsCall ? "call " : "tail ") << *Target;
  printCommentableLine(Line, os, Address);
  os << '\n';
  return true;
}

bool RiscvPrettyPrinter::printPltCallRelocation(
    std::ostream& os, const gtirb::CodeBlock& block, const cs_insn& inst,
    gtirb::Addr Address) {
  if (inst.id != RISCV_INS_AUIPC) {
    return false;
  }

  const cs_riscv& Detail = inst.detail->riscv;
  if (Detail.op_count < 2 || Detail.operands[0].type != RISCV_OP_REG ||
      Detail.operands[0].reg != RISCV_REG_RA) {
    return false;
  }

  auto Target = getPltRelocationTargetName(block, inst);
  if (!Target) {
    return false;
  }

  std::stringstream Line;
  printEA(Line, Address);
  Line << "  call " << *Target << "@plt";
  printCommentableLine(Line, os, Address);
  os << '\n';

  SuppressedInstructionAddresses.insert(static_cast<uint64_t>(Address) + 4);
  return true;
}

void RiscvPrettyPrinter::printOperandList(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst) {
  const cs_riscv& detail = inst.detail->riscv;

  if (isCsrInstruction(inst)) {
    os << inst.op_str;
    return;
  }

  if (hasSymbolicJalrAlias(block, inst)) {
    // Capstone contracts `jalr ra,reg,0` to `jalr reg` and
    // `jalr zero,reg,0` to `jr reg`.  A symbolic low immediate cannot be
    // printed in either alias, so restore the expanded spelling while
    // preserving whether the original instruction calls or tail-jumps.
    const std::string Mnemonic = ascii_str_tolower(inst.mnemonic);
    const unsigned int Destination =
        Mnemonic == "jr" ? RISCV_REG_ZERO : RISCV_REG_RA;
    os << getRegisterName(Destination) << ',';
    printOperand(os, block, inst, 0);
    os << ',';

    const gtirb::SymbolicExpression* Symex =
        getInstructionSymbolicExpression(block, inst);
    const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
    this->printSymbolicExpression(os, Symaddr, true);
    return;
  }

  if (hasSymbolicAddiAlias(block, inst)) {
    printOperand(os, block, inst, 0);
    os << ',';
    printOperand(os, block, inst, 1);
    os << ',';

    const gtirb::SymbolicExpression* Symex =
        getInstructionSymbolicExpression(block, inst);
    const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
    this->printSymbolicExpression(os, Symaddr, true);
    return;
  }

  if (hasSymbolicCompressedAddi(block, inst)) {
    printOperand(os, block, inst, 0);
    os << ',';
    printOperand(os, block, inst, 0);
    os << ',';

    const gtirb::SymbolicExpression* Symex =
        getInstructionSymbolicExpression(block, inst);
    const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
    this->printSymbolicExpression(os, Symaddr, true);
    return;
  }

  if (hasSymbolicCompressedAddiw(block, inst)) {
    printOperand(os, block, inst, 0);
    os << ',';
    printOperand(os, block, inst, 0);
    os << ',';

    const gtirb::SymbolicExpression* Symex =
        getInstructionSymbolicExpression(block, inst);
    const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
    this->printSymbolicExpression(os, Symaddr, true);
    return;
  }

  if (hasCompressedMemoryOperand(inst)) {
    printOperand(os, block, inst, 0);
    os << ',';
    const gtirb::SymbolicExpression* Symex =
        getInstructionSymbolicExpression(block, inst);
    printOpImmediate(os, Symex, inst, 1);
    os << '(';
    printOpRegdirect(os, inst, 2);
    os << ')';
    return;
  }

  if (isLoadReserved(inst.id) && detail.op_count == 2 &&
      detail.operands[0].type == RISCV_OP_REG &&
      detail.operands[1].type == RISCV_OP_REG) {
    printOperand(os, block, inst, 0);
    os << ",(";
    printOperand(os, block, inst, 1);
    os << ')';
    return;
  }

  if (isStoreConditionalOrAtomic(inst.id) && detail.op_count == 3 &&
      detail.operands[0].type == RISCV_OP_REG &&
      detail.operands[1].type == RISCV_OP_REG &&
      detail.operands[2].type == RISCV_OP_REG) {
    printOperand(os, block, inst, 0);
    os << ',';
    printOperand(os, block, inst, 1);
    os << ",(";
    printOperand(os, block, inst, 2);
    os << ')';
    return;
  }

  const auto RoundingMode = getTrailingRoundingMode(inst);
  int OperandCount = detail.op_count;
  if (RoundingMode) {
    const std::string_view RawOperands(inst.op_str);
    const size_t RawOperandCount =
        1 + std::count(RawOperands.begin(), RawOperands.end(), ',');
    // Current Capstone omits the mode from detail.  If a future version adds
    // it as an immediate, omit that numeric rendering and still print the
    // assembler token below.
    if (RawOperandCount == static_cast<size_t>(OperandCount)) {
      --OperandCount;
    }
  }

  for (int i = 0; i < OperandCount; i++) {
    if (i != 0) {
      os << ',';
    }
    printOperand(os, block, inst, i);
  }
  if (RoundingMode) {
    if (OperandCount != 0) {
      os << ',';
    }
    os << *RoundingMode;
  }
}

void RiscvPrettyPrinter::printOperand(std::ostream& os,
                                      const gtirb::CodeBlock& block,
                                      const cs_insn& inst, uint64_t index) {
  gtirb::Addr ea(inst.address);
  const cs_riscv_op& op = inst.detail->riscv.operands[index];
  const gtirb::SymbolicExpression* symbolic = nullptr;
  bool finalOp = (index + 1 == inst.detail->riscv.op_count);

  switch (op.type) {
  case RISCV_OP_REG:
    printOpRegdirect(os, inst, index);
    return;
  case RISCV_OP_IMM:
    if (finalOp) {
      uint64_t Offset = ea - *block.getByteInterval()->getAddress();
      symbolic = block.getByteInterval()->getSymbolicExpression(Offset);
    }
    printOpImmediate(os, symbolic, inst, index);
    return;
  case RISCV_OP_MEM:
    if (finalOp) {
      uint64_t Offset = ea - *block.getByteInterval()->getAddress();
      symbolic = block.getByteInterval()->getSymbolicExpression(Offset);
    }
    printOpIndirect(os, symbolic, inst, index);
    return;
  case RISCV_OP_INVALID:
  default:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void RiscvPrettyPrinter::printOpRegdirect(std::ostream& os,
                                          const cs_insn& inst,
                                          uint64_t index) {
  const cs_riscv_op& op = inst.detail->riscv.operands[index];
  assert(op.type == RISCV_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);
}

void RiscvPrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_riscv_op& op = inst.detail->riscv.operands[index];
  assert(op.type == RISCV_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  if (const auto* SAC = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    bool IsBranch =
        cs_insn_group(this->csHandle, &inst, RISCV_GRP_BRANCH_RELATIVE) ||
        cs_insn_group(this->csHandle, &inst, RISCV_GRP_JUMP) ||
        cs_insn_group(this->csHandle, &inst, RISCV_GRP_CALL);
    this->printSymbolicExpression(os, SAC, !IsBranch);
  } else if (const auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    if (isGpRelative(SAA)) {
      os << op.imm;
      return;
    }
    bool IsBranch =
        cs_insn_group(this->csHandle, &inst, RISCV_GRP_BRANCH_RELATIVE) ||
        cs_insn_group(this->csHandle, &inst, RISCV_GRP_JUMP) ||
        cs_insn_group(this->csHandle, &inst, RISCV_GRP_CALL);
    this->printSymbolicExpression(os, SAA, !IsBranch);
  } else if (isPcRelativeImmediate(inst.id)) {
    gtirb::Addr Ea(inst.address);
    gtirb::Addr Target =
        op.imm >= 0 ? Ea + static_cast<uint64_t>(op.imm)
                    : Ea - static_cast<uint64_t>(-op.imm);
    if (auto Name = getTargetLabel(Target)) {
      os << *Name;
    } else if (LocalBranchLabels.count(static_cast<uint64_t>(Target))) {
      os << getLocalBranchLabel(Target);
    } else {
      os << ".";
      if (op.imm >= 0) {
        os << '+';
      }
      os << op.imm;
    }
  } else {
    os << op.imm;
  }
}

void RiscvPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_riscv_op& op = inst.detail->riscv.operands[index];
  assert(op.type == RISCV_OP_MEM &&
         "printOpIndirect called without a memory operand");

  if (const auto* SAC = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    printSymbolicExpression(os, SAC, false);
  } else if (const auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    if (isGpRelative(SAA)) {
      os << op.mem.disp;
    } else {
      printSymbolicExpression(os, SAA, false);
    }
  } else {
    os << op.mem.disp;
  }
  os << '(' << getRegisterName(op.mem.base) << ')';
}

std::optional<std::string>
RiscvPrettyPrinter::getTargetLabel(gtirb::Addr Target) const {
  auto It = TargetLabels.find(static_cast<uint64_t>(Target));
  if (It == TargetLabels.end()) {
    return std::nullopt;
  }

  return It->second;
}

void RiscvPrettyPrinter::printSymExprPrefix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
    bool /* IsNotBranch */) {
  if (Attrs.count(gtirb::SymAttribute::GOT)) {
    OS << "%got_pcrel_hi(";
  } else if (Attrs.count(gtirb::SymAttribute::TLSGD)) {
    OS << "%tls_gd_pcrel_hi(";
  } else if (Attrs.count(gtirb::SymAttribute::HI)) {
    if (Attrs.count(gtirb::SymAttribute::PCREL)) {
      OS << "%pcrel_hi(";
    } else if (Attrs.count(gtirb::SymAttribute::TPREL)) {
      OS << "%tprel_hi(";
    } else {
      OS << "%hi(";
    }
  } else if (Attrs.count(gtirb::SymAttribute::LO)) {
    if (Attrs.count(gtirb::SymAttribute::PCREL)) {
      OS << "%pcrel_lo(";
    } else if (Attrs.count(gtirb::SymAttribute::TPREL)) {
      OS << "%tprel_lo(";
    } else {
      OS << "%lo(";
    }
  }
}

void RiscvPrettyPrinter::printSymExprSuffix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
    bool /* IsNotBranch */) {
  if (Attrs.count(gtirb::SymAttribute::GOT) ||
      Attrs.count(gtirb::SymAttribute::TLSGD) ||
      Attrs.count(gtirb::SymAttribute::HI) ||
      Attrs.count(gtirb::SymAttribute::LO)) {
    OS << ")";
  }
  if (Attrs.count(gtirb::SymAttribute::PLT)) {
    OS << "@plt";
  }
}

std::unique_ptr<PrettyPrinterBase>
RiscvPrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                  const gtirb::Module& module,
                                  const PrintingPolicy& policy) {
  static const RiscvSyntax syntax{};
  return std::make_unique<RiscvPrettyPrinter>(gtirb_context, module, syntax,
                                              policy);
}

} // namespace gtirb_pprint
