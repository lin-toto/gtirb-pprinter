//===- Arm64PrettyPrinter.cpp -----------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020-2022 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include <cstring>
#include <iostream>
#include <sstream>
#include <string_view>

#include "Arm64PrettyPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "StringUtils.hpp"
#include "driver/Logger.h"

#include <capstone/capstone.h>

namespace gtirb_pprint {

namespace {

bool hasArchFeature(const gtirb::Module& Module, const std::string& Feature) {
  const auto* ArchInfo = Module.getAuxData<gtirb::schema::ArchInfo>();
  if (!ArchInfo) {
    return false;
  }

  const auto It = ArchInfo->find("features");
  if (It == ArchInfo->end()) {
    return false;
  }

  std::string Features = ascii_str_tolower(It->second);
  for (char& C : Features) {
    if (C == ',' || C == ';') {
      C = ' ';
    }
  }

  std::istringstream Tokens(Features);
  std::string Token;
  while (Tokens >> Token) {
    if (Token == Feature) {
      return true;
    }
  }
  return false;
}

bool hasSymbolicExpression(const gtirb::CodeBlock& Block,
                           const cs_insn& Inst) {
  const auto* ByteInterval = Block.getByteInterval();
  assert(ByteInterval && ByteInterval->getAddress());
  const uint64_t Offset =
      gtirb::Addr(Inst.address) - *ByteInterval->getAddress();
  for (uint64_t I = 0; I < Inst.size; ++I) {
    if (ByteInterval->getSymbolicExpression(Offset + I)) {
      return true;
    }
  }
  return false;
}

// Capstone 6 encodes a vector arrangement as (lanes << 8) | element bits,
// with zero lanes for a single indexed element (AArch64Layout_VectorLayout).
const char* vectorElementSuffix(AArch64Layout_VectorLayout Vas) {
  switch (Vas & 0xff) {
  case 8:
    return "b";
  case 16:
    return "h";
  case 32:
    return "s";
  case 64:
    return "d";
  case 128:
    return "q";
  default:
    return "";
  }
}

// Share upstream's lane-width recovery with the exact-encoding fallback.
// Recoverable operands should reach the mnemonic printer; unknown forms must
// still retain their original bytes rather than guess an element width.
const char* inferredVectorLaneSuffix(const cs_insn& Inst, uint64_t Index) {
  const auto& Detail = Inst.detail->aarch64;
  const auto& Op = Detail.operands[Index];
  if (Detail.op_count != 2 || !Op.is_vreg) {
    return "";
  }
  const auto& Other = Detail.operands[Index ^ 1];
  if (Other.type != AARCH64_OP_REG) {
    return "";
  }
  if (!Other.is_vreg &&
      ((Other.reg >= AARCH64_REG_X0 && Other.reg <= AARCH64_REG_X28) ||
       Other.reg == AARCH64_REG_X29 || Other.reg == AARCH64_REG_X30 ||
       Other.reg == AARCH64_REG_XZR)) {
    return "d";
  }
  if (!Other.is_vreg &&
      ((Other.reg >= AARCH64_REG_W0 && Other.reg <= AARCH64_REG_W30) ||
       Other.reg == AARCH64_REG_WZR)) {
    return "s";
  }
  // The element size of a known arrangement; a quadword (.1q) arrangement
  // has no lane form to infer.
  const char* Suffix = vectorElementSuffix(Other.vas);
  return Suffix[0] == 'q' ? "" : Suffix;
}

bool hasIncompleteVectorLane(const cs_insn& Inst) {
  const auto& Detail = Inst.detail->aarch64;
  for (uint8_t I = 0; I < Detail.op_count; ++I) {
    const auto& Op = Detail.operands[I];
    if (Op.type == AARCH64_OP_REG && Op.vector_index >= 0 &&
        Op.vas == AARCH64LAYOUT_INVALID &&
        inferredVectorLaneSuffix(Inst, I)[0] == '\0') {
      return true;
    }
  }
  return false;
}

bool hasOmittedPostIndex(const cs_insn& Inst) {
  const auto& Detail = Inst.detail->aarch64;
  return Inst.detail->writeback && Detail.op_count > 0 &&
         Detail.operands[Detail.op_count - 1].type == AARCH64_OP_MEM &&
         std::strstr(Inst.op_str, "],") != nullptr;
}

bool hasDuplicatedCompareZero(const cs_insn& Inst) {
  // Capstone 5 can append the implicit zero twice for scalar integer SIMD
  // compares. These forms have two register operands and one zero immediate;
  // the duplicate detailed operand is not an architectural fourth operand.
  switch (Inst.id) {
  case AARCH64_INS_CMEQ:
  case AARCH64_INS_CMGE:
  case AARCH64_INS_CMGT:
  case AARCH64_INS_CMLE:
  case AARCH64_INS_CMLT:
    break;
  default:
    return false;
  }
  const auto& Detail = Inst.detail->aarch64;
  return Detail.op_count == 4 && Detail.operands[0].type == AARCH64_OP_REG &&
         Detail.operands[1].type == AARCH64_OP_REG &&
         Detail.operands[2].type == AARCH64_OP_IMM &&
         Detail.operands[2].imm == 0 &&
         Detail.operands[3].type == AARCH64_OP_IMM &&
         Detail.operands[3].imm == 0;
}

bool hasMnemonicPrefix(const cs_insn& Inst, std::string_view Prefix) {
  const std::string_view Mnemonic(Inst.mnemonic);
  return Mnemonic.size() >= Prefix.size() &&
         Mnemonic.substr(0, Prefix.size()) == Prefix;
}

bool isOptionalArchitectureInstruction(csh Handle, const cs_insn& Inst) {
  // Capstone annotates optional AArch64 extensions with the LLVM feature the
  // instruction requires. Printing their exact encoding keeps reconstruction
  // independent of the assembler's selected architecture level. These are the
  // Capstone 6 features that correspond to the Capstone 5 groups used before
  // (CRYPTO is covered by AES and SHA2; PAC by PAUTH). Baseline instructions
  // now also carry HasNEON or HasFPARMv8, which are not optional here.
  static const aarch64_insn_group OptionalGroups[] = {
      AARCH64_FEATURE_HASAES,        AARCH64_FEATURE_HASCRC,
      AARCH64_FEATURE_HASDOTPROD,    AARCH64_FEATURE_HASFULLFP16,
      AARCH64_FEATURE_HASLSE,        AARCH64_FEATURE_HASRCPC,
      AARCH64_FEATURE_HASRDM,        AARCH64_FEATURE_HASSHA2,
      AARCH64_FEATURE_HASSHA3,       AARCH64_FEATURE_HASSM4,
      AARCH64_FEATURE_HASSVE,        AARCH64_FEATURE_HASSVE2,
      AARCH64_FEATURE_HASSVE2AES,    AARCH64_FEATURE_HASSVE2BITPERM,
      AARCH64_FEATURE_HASSVE2SHA3,   AARCH64_FEATURE_HASSVE2SM4,
      AARCH64_FEATURE_HASSME,        AARCH64_FEATURE_HASSMEF64F64,
      AARCH64_FEATURE_HASSMEI16I64,  AARCH64_FEATURE_HASMATMULFP32,
      AARCH64_FEATURE_HASMATMULFP64, AARCH64_FEATURE_HASMATMULINT8,
      AARCH64_FEATURE_HASV8_1A,      AARCH64_FEATURE_HASV8_3A,
      AARCH64_FEATURE_HASV8_4A,
  };
  for (const aarch64_insn_group Group : OptionalGroups) {
    if (cs_insn_group(Handle, &Inst, Group)) {
      return true;
    }
  }
  if (cs_insn_group(Handle, &Inst, AARCH64_FEATURE_HASPAUTH)) {
    return true;
  }

  // Capstone does not consistently attach the LSE or an MTE feature group.
  // Cover the corresponding mnemonic families without enumerating aliases.
  static const std::string_view OptionalPrefixes[] = {
      "cas",    "ldadd", "ldclr", "ldeor", "ldset", "ldsmax",
      "ldsmin", "ldumax", "ldumin", "stadd", "stclr", "steor",
      "stset",  "stsmax", "stsmin", "stumax", "stumin", "swp",
      "addg",   "gmi",    "irg",   "ldg",   "st2g",  "stg",
      "stgm",   "stz2g",  "stzg",  "subg",  "subp",  "subps",
      "bti",    "pac",    "aut",   "xpac",   "sha512", "eor3",
      "rax1",
      "xar",    "bcax",
  };
  for (const std::string_view Prefix : OptionalPrefixes) {
    if (hasMnemonicPrefix(Inst, Prefix)) {
      return true;
    }
  }
  return false;
}

} // namespace

Arm64PrettyPrinter::Arm64PrettyPrinter(gtirb::Context& context_,
                                       const gtirb::Module& module_,
                                       const ElfSyntax& syntax_,

                                       const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  buildSymGotRefTable();
}

void Arm64PrettyPrinter::buildSymGotRefTable(void) {
  for (auto It : module.symbolic_expressions()) {
    auto SymExpr = It.getSymbolicExpression();
    if (const auto* SymAddr = std::get_if<gtirb::SymAddrConst>(&SymExpr)) {
      if (SymAddr->Attributes.count(gtirb::SymAttribute::GOT)) {
        if (auto Found = aux_data::getForwardedSymbol(SymAddr->Sym)) {
          // the SymExpr will reference the got entry itself, so we need to
          // look up the forwarded symbol.
          auto ForwardedSymbol = gtirb::dyn_cast_or_null<gtirb::Symbol>(
              gtirb::Node::getByUUID(context, *Found));
          if (ForwardedSymbol) {
            LocalGotSyms.insert(ForwardedSymbol->getUUID());
          }
        }
      }
    }
  }
}

void Arm64PrettyPrinter::printHeader(std::ostream& os) {
  this->printBar(os);
  if (hasArchFeature(module, "mte")) {
    os << ".arch armv8.5-a+memtag\n";
  } else {
    os << ".arch armv8-a\n";
  }
  this->printBar(os);
  os << '\n';
  ElfPrettyPrinter::printHeader(os);
}

std::string Arm64PrettyPrinter::getRegisterName(unsigned int reg) const {
  // Capstone 5 spellings: fp/lr for x29/x30.
  return capstone_compat::aarch64RegName(this->csHandle, reg, false);
}

std::string Arm64PrettyPrinter::getRegisterName(const cs_aarch64_op& op) const {
  // A vector operand is reported as its Q/D/S/H/B register with is_vreg set;
  // print it as v<n>.
  return capstone_compat::aarch64RegName(this->csHandle, op.reg, op.is_vreg);
}

void Arm64PrettyPrinter::fixupInstruction(const gtirb::CodeBlock& block,
                                          cs_insn& inst) {
  PrettyPrinterBase::fixupInstruction(block, inst);

  switch (inst.id) {
  case AARCH64_INS_MOVZ: {
    // Capstone aliases MOVZ as "mov", but the GNU assembler requires "movz"
    // when :abs_gN: relocation modifiers are used. If the instruction has a
    // symbolic operand with abs_g attributes, rename the mnemonic to "movz".
    gtirb::Addr ea(inst.address);
    const gtirb::SymbolicExpression* Symex =
        block.getByteInterval()->getSymbolicExpression(
            ea - *block.getByteInterval()->getAddress());
    if (Symex == nullptr) {
      break;
    }

    const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
    if (Symaddr != nullptr &&
        (Symaddr->Attributes.count(gtirb::SymAttribute::G0) ||
         Symaddr->Attributes.count(gtirb::SymAttribute::G1) ||
         Symaddr->Attributes.count(gtirb::SymAttribute::G2) ||
         Symaddr->Attributes.count(gtirb::SymAttribute::G3))) {
      std::snprintf(inst.mnemonic, sizeof(inst.mnemonic), "MOVZ");
    }
    break;
  }
  }
}

void Arm64PrettyPrinter::printInstruction(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst,
                                          const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  std::stringstream InstructLine;
  printComments(InstructLine, offset, inst.size);
  printCFIDirectives(InstructLine, offset);
  printEA(InstructLine, ea);

  ////////////////////////////////////////////////////////////////////
  // special cases
  std::string opcode = std::string();

  if (inst.is_alias && inst.alias_id == AARCH64_INS_ALIAS_NOP) {
    InstructLine << "  " << syntax.nop();
    printCommentableLine(InstructLine, os, ea);
    os << '\n';
    return;
  }

  // Some optional-extension instructions are rejected under the baseline
  // `.arch armv8-a` directive, and Capstone occasionally omits vector-lane or
  // post-index operands or duplicates a scalar compare's zero operand in its
  // detailed representation. When no relocation
  // is attached, preserve those instructions exactly with `.inst` instead of
  // emitting a mnemonic that is unsupported or semantically incomplete.
  if (!hasSymbolicExpression(block, inst) && inst.size == 4 &&
      (isOptionalArchitectureInstruction(this->csHandle, inst) ||
       hasIncompleteVectorLane(inst) || hasOmittedPostIndex(inst) ||
       hasDuplicatedCompareZero(inst))) {
    uint32_t Word = 0;
    if (module.getByteOrder() == gtirb::ByteOrder::Big) {
      for (uint8_t I = 0; I < inst.size; ++I) {
        Word = (Word << 8) | static_cast<uint32_t>(inst.bytes[I]);
      }
    } else {
      for (uint8_t I = 0; I < inst.size; ++I) {
        Word |= static_cast<uint32_t>(inst.bytes[I]) << (8 * I);
      }
    }
    InstructLine << "  .inst 0x" << std::hex << std::setw(8)
                 << std::setfill('0') << Word;
    printCommentableLine(InstructLine, os, ea);
    os << '\n';
    return;
  }

  if (inst.id == AARCH64_INS_ADR) {
    // The assembler does not allow :got: on adr instructions, but sometimes
    // it substitutes an adrp x0, :got:symbol for an adr instruction. In order
    // to print something that can be reassembled, reverse this substitution
    // and print an adrp.

    const gtirb::SymbolicExpression* Symex =
        block.getByteInterval()->getSymbolicExpression(
            ea - *block.getByteInterval()->getAddress());
    if (Symex != nullptr) {
      const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
      if (Symaddr != nullptr &&
          Symaddr->Attributes.count(gtirb::SymAttribute::GOT)) {
        opcode = "adrp";

        // Print a comment indicating the substitution

        os << syntax.comment()
           << " Instruction substituted from adr to adrp to support :got: "
              "reference.\n";
      }
    }
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  if (opcode.empty()) {
    opcode = ascii_str_tolower(inst.mnemonic);
  }

  InstructLine << "  " << opcode << ' ';

  // Make sure the initial m_accum_comment is empty.
  m_accum_comment.clear();
  printOperandList(InstructLine, block, inst);
  if (!m_accum_comment.empty()) {
    printCommentableLine(InstructLine, os, ea);
    InstructLine.str(std::string()); // Clear
    os << '\n';
    InstructLine << syntax.comment() << " ";
    printEA(InstructLine, ea);
    InstructLine << ": " << m_accum_comment;
    m_accum_comment.clear();
  }
  printCommentableLine(InstructLine, os, ea);
  os << '\n';
}

void Arm64PrettyPrinter::printOperandList(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst) {
  cs_aarch64& detail = inst.detail->aarch64;
  int opCount = detail.op_count;

  // Capstone may keep PRFM's operation only in op_str and omit it from the
  // detailed operand array. Recover the architectural PRFOP field from the
  // instruction word so the emitted instruction remains assembleable.
  bool InjectedPrefetch = false;
  bool HasPrefetch = false;
  for (int I = 0; I < opCount; ++I) {
    HasPrefetch |= detail.operands[I].type == AARCH64_OP_SYSALIAS &&
                   detail.operands[I].sysop.sub_type == AARCH64_OP_PRFM;
  }
  if (inst.id == AARCH64_INS_PRFM && !HasPrefetch) {
    assert(inst.size == 4 && "unexpected AArch64 PRFM size");
    const uint32_t Word = static_cast<uint32_t>(inst.bytes[0]) |
                          (static_cast<uint32_t>(inst.bytes[1]) << 8) |
                          (static_cast<uint32_t>(inst.bytes[2]) << 16) |
                          (static_cast<uint32_t>(inst.bytes[3]) << 24);
    printOpPrefetch(os, Word & 0x1fU);
    InjectedPrefetch = true;
  }

  const static std::map<aarch64_insn, uint8_t> Groupings = {
      {AARCH64_INS_LD1, 0},     {AARCH64_INS_LD1B, 0},
      {AARCH64_INS_LD1D, 0},    {AARCH64_INS_LD1H, 0},
      {AARCH64_INS_LD1R, 0},    {AARCH64_INS_LD1RB, 0},
      {AARCH64_INS_LD1RD, 0},   {AARCH64_INS_LD1RH, 0},
      {AARCH64_INS_LD1RQB, 0},  {AARCH64_INS_LD1RQD, 0},
      {AARCH64_INS_LD1RQH, 0},  {AARCH64_INS_LD1RQW, 0},
      {AARCH64_INS_LD1RSB, 0},  {AARCH64_INS_LD1RSH, 0},
      {AARCH64_INS_LD1RSW, 0},  {AARCH64_INS_LD1RW, 0},
      {AARCH64_INS_LD1SB, 0},   {AARCH64_INS_LD1SH, 0},
      {AARCH64_INS_LD1SW, 0},   {AARCH64_INS_LD1W, 0},
      {AARCH64_INS_LD2, 0},     {AARCH64_INS_LD2B, 0},
      {AARCH64_INS_LD2D, 0},    {AARCH64_INS_LD2H, 0},
      {AARCH64_INS_LD2R, 0},    {AARCH64_INS_LD2W, 0},
      {AARCH64_INS_LD3, 0},     {AARCH64_INS_LD3B, 0},
      {AARCH64_INS_LD3D, 0},    {AARCH64_INS_LD3H, 0},
      {AARCH64_INS_LD3R, 0},    {AARCH64_INS_LD3W, 0},
      {AARCH64_INS_LD4, 0},     {AARCH64_INS_LD4B, 0},
      {AARCH64_INS_LD4D, 0},    {AARCH64_INS_LD4H, 0},
      {AARCH64_INS_LD4R, 0},    {AARCH64_INS_LD4W, 0},
      {AARCH64_INS_LDFF1B, 0},  {AARCH64_INS_LDFF1D, 0},
      {AARCH64_INS_LDFF1H, 0},  {AARCH64_INS_LDFF1SB, 0},
      {AARCH64_INS_LDFF1SH, 0}, {AARCH64_INS_LDFF1SW, 0},
      {AARCH64_INS_LDFF1W, 0},  {AARCH64_INS_LDNF1B, 0},
      {AARCH64_INS_LDNF1D, 0},  {AARCH64_INS_LDNF1H, 0},
      {AARCH64_INS_LDNF1SB, 0}, {AARCH64_INS_LDNF1SH, 0},
      {AARCH64_INS_LDNF1SW, 0}, {AARCH64_INS_LDNF1W, 0},
      {AARCH64_INS_LDNT1B, 0},  {AARCH64_INS_LDNT1D, 0},
      {AARCH64_INS_LDNT1H, 0},  {AARCH64_INS_LDNT1W, 0},
      {AARCH64_INS_ST1, 0},     {AARCH64_INS_ST2, 0},
      {AARCH64_INS_ST3, 0},     {AARCH64_INS_ST4, 0},
      {AARCH64_INS_ST1B, 0},    {AARCH64_INS_ST1D, 0},
      {AARCH64_INS_ST1H, 0},    {AARCH64_INS_ST1W, 0},
      {AARCH64_INS_ST2B, 0},    {AARCH64_INS_ST2D, 0},
      {AARCH64_INS_ST2H, 0},    {AARCH64_INS_ST2W, 0},
      {AARCH64_INS_ST3B, 0},    {AARCH64_INS_ST3D, 0},
      {AARCH64_INS_ST3H, 0},    {AARCH64_INS_ST3W, 0},
      {AARCH64_INS_ST4B, 0},    {AARCH64_INS_ST4D, 0},
      {AARCH64_INS_ST4H, 0},    {AARCH64_INS_ST4W, 0},
      {AARCH64_INS_STNT1B, 0},  {AARCH64_INS_STNT1D, 0},
      {AARCH64_INS_STNT1H, 0},  {AARCH64_INS_STNT1W, 0},
      {AARCH64_INS_TBL, 1}};

  std::optional<uint8_t> GroupingStart;
  if (auto It = Groupings.find(static_cast<aarch64_insn>(inst.id));
      It != Groupings.end()) {
    GroupingStart = It->second;
  }

  for (uint8_t i = 0; i < opCount; i++) {
    if (i != 0 || InjectedPrefetch) {
      os << ',';
    }

    if (GroupingStart && *GroupingStart == i) {
      os << "{";
      IsPrintingGroupedOperands = true;
    }

    printOperand(os, block, inst, i);

    if (IsPrintingGroupedOperands) {
      uint8_t offset = 0;

      if (static_cast<aarch64_insn>(inst.id) == AARCH64_INS_TBL) {
        // Special case: TBL instructions have a trailing ungrouped operand.
        offset = 1;
      }

      // Expect grouped operands to all be registers with a VAS specifier.
      // Close the grouping when we find an operand that does not match this,
      // or if there are no more operands.
      if (i + 1 + offset < opCount) {
        cs_aarch64_op& nextOp = inst.detail->aarch64.operands[i + 1];
        if (nextOp.type != AARCH64_OP_REG ||
            nextOp.vas == AARCH64LAYOUT_INVALID) {
          IsPrintingGroupedOperands = false;
        }
      } else {
        IsPrintingGroupedOperands = false;
      }

      if (!IsPrintingGroupedOperands) {
        os << "}";
        cs_aarch64_op& op = inst.detail->aarch64.operands[i];
        if (op.vector_index != -1) {
          os << "[" << op.vector_index << "]";
        }
      }
    }
  }

  auto arm64Cc2String = [](AArch64CC_CondCode cc) {
    switch (cc) {
    case AArch64CC_EQ:
      return "eq";
    case AArch64CC_NE:
      return "ne";
    case AArch64CC_HS:
      return "hs";
    case AArch64CC_LO:
      return "lo";
    case AArch64CC_MI:
      return "mi";
    case AArch64CC_PL:
      return "pl";
    case AArch64CC_VS:
      return "vs";
    case AArch64CC_VC:
      return "vc";
    case AArch64CC_HI:
      return "hi";
    case AArch64CC_LS:
      return "ls";
    case AArch64CC_GE:
      return "ge";
    case AArch64CC_LT:
      return "lt";
    case AArch64CC_GT:
      return "gt";
    case AArch64CC_LE:
      return "le";
    case AArch64CC_AL:
      return "al";
    default:
      assert(!"Invalid AArch64CC_CondCode");
      return "Invalid AArch64CC_CondCode";
    }
  };

  // This set of special cases is required to handle conditional operands,
  // which capstone does not represent as an explicit operand. See the capstone
  // issue: https://github.com/capstone-engine/capstone/issues/1889
  // Capstone 6 reports the real instruction id: CINC, CSET (CSINC), CINV,
  // CSETM (CSINV) and CNEG (CSNEG) are aliases whose alias details carry the
  // alias's own condition, which is the one printed.
  auto isCondInstr = [](const aarch64_insn opcode) {
    static std::vector<aarch64_insn> cond_instrs{
        AARCH64_INS_CCMN,  AARCH64_INS_CCMP,   AARCH64_INS_CSEL,
        AARCH64_INS_CSINC, AARCH64_INS_CSINV,  AARCH64_INS_CSNEG,
        AARCH64_INS_FCCMP, AARCH64_INS_FCCMPE, AARCH64_INS_FCSEL,
    };

    return (std::find(std::begin(cond_instrs), std::end(cond_instrs), opcode) !=
            std::end(cond_instrs));
  };

  if (inst.detail->aarch64.cc != AArch64CC_Invalid &&
      isCondInstr(static_cast<aarch64_insn>(inst.id))) {
    std::string cc = arm64Cc2String(inst.detail->aarch64.cc);
    os << ',' << cc;
  }
}

void Arm64PrettyPrinter::printOperand(std::ostream& os,
                                      const gtirb::CodeBlock& block,
                                      const cs_insn& inst, uint64_t index) {
  gtirb::Addr ea(inst.address);
  const cs_aarch64_op& op = inst.detail->aarch64.operands[index];
  const gtirb::SymbolicExpression* symbolic = nullptr;
  bool finalOp = (index + 1 == inst.detail->aarch64.op_count);

  switch (op.type) {
  case AARCH64_OP_REG:
    printOpRegdirect(os, inst, index);
    return;
  case AARCH64_OP_IMM:
    if (finalOp) {
      uint64_t Offset = ea - *block.getByteInterval()->getAddress();
      symbolic = block.getByteInterval()->getSymbolicExpression(Offset);
    }
    printOpImmediate(os, symbolic, inst, index);
    return;
  case AARCH64_OP_MEM:
    if (finalOp) {
      uint64_t Offset = ea - *block.getByteInterval()->getAddress();
      symbolic = block.getByteInterval()->getSymbolicExpression(Offset);
    }
    printOpIndirect(os, symbolic, inst, index);
    return;
  case AARCH64_OP_FP:
    os << "#" << std::scientific << std::setprecision(18) << op.fp;
    return;
  case AARCH64_OP_SYSALIAS:
    // Capstone 6 reports barriers and prefetch operations as system aliases
    // holding the raw architectural field.
    if (op.sysop.sub_type == AARCH64_OP_DB) {
      printOpBarrier(os, op.sysop.alias.db);
      return;
    }
    if (op.sysop.sub_type == AARCH64_OP_PRFM) {
      printOpPrefetch(os, op.sysop.alias.prfm);
      return;
    }
    printOpRawValue(os, inst, index);
    return;
  case AARCH64_OP_CIMM:
  case AARCH64_OP_REG_MRS:
  case AARCH64_OP_REG_MSR:
  case AARCH64_OP_SYSREG:
  case AARCH64_OP_SYSIMM:
  case AARCH64_OP_PRED:
  case AARCH64_OP_SME:
  case AARCH64_OP_IMM_RANGE:
    // Print the operand directly (system registers, PSTATE fields, cache and
    // TLB operations, and SVE/SME operands, which are printed as .inst unless
    // they carry a relocation).
    printOpRawValue(os, inst, index);
    return;
  case AARCH64_OP_INVALID:
  default:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void Arm64PrettyPrinter::printSymExprPrefix(std::ostream& OS,
                                            const gtirb::SymAttributeSet& Attrs,
                                            bool /* IsNotBranch */) {
  if (Attrs.count(gtirb::SymAttribute::GOT)) {
    if (Attrs.count(gtirb::SymAttribute::LO12)) {
      OS << ":got_lo12:";
    } else {
      OS << ":got:";
    }
  } else if (Attrs.count(gtirb::SymAttribute::LO12)) {
    OS << ":lo12:";
  }
}

void Arm64PrettyPrinter::printSymExprSuffix(
    std::ostream& /* OS */, const gtirb::SymAttributeSet& /* Attrs */,
    bool /* IsNotBranch */) {}

void Arm64PrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                          uint64_t index) {
  assert(index < inst.detail->aarch64.op_count &&
         "printOpRegdirect called with invalid register index");
  const cs_aarch64_op& op = inst.detail->aarch64.operands[index];
  assert(op.type == AARCH64_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op);

  // Capstone does not always populate `vas` for instructions that reference
  // a single vector element (a "lane"), even though it always populates
  // `vector_index` for them. This shows up, for example, with:
  //   fmov v0.d[1], x3         (and the reverse: fmov x3, v0.d[1])
  //   mov x0, v1.d[0]          (UMOV alias; only the lane-0 forms are hit)
  //   mov w0, v1.s[0]          (UMOV alias; only the lane-0 forms are hit)
  //   dup v0.2d, v1.d[1]       (DUP's source lane operand, any index)
  //
  // In all of these cases the operand is still a V register with a valid
  // lane index, so GAS requires an explicit element-width suffix
  // (e.g. `.d[1]`) even though Capstone hasn't told us what that width is.
  // We recover it from a sibling operand:
  //   - if the sibling is a GPR, its width implies the element size
  //     (X -> .d, W -> .s), as with fmov/umov above; or
  //   - if the sibling is itself a vector register with a known
  //     arrangement (e.g. DUP's destination), that arrangement's element
  //     size gives us the width.
  if (op.vas == AARCH64LAYOUT_INVALID && op.vector_index != -1 && op.is_vreg) {
    const char* suffix = inferredVectorLaneSuffix(inst, index);
    if (suffix[0] == '\0') {
      LOG_ERROR << "printOpRegdirect: could not infer lane width for "
                << getRegisterName(op) << "[" << op.vector_index
                << "]; no usable sibling width/arrangement\n";
    }

    if (suffix[0] != '\0') {
      os << "." << suffix;
    }
    if (!IsPrintingGroupedOperands) {
      // Grouped operands print the index following the group.
      os << "[" << op.vector_index << "]";
    }
  } else if (op.vas != AARCH64LAYOUT_INVALID &&
             op.vas != AARCH64LAYOUT_VL_COMPLETE) {
    // Arrangement (lanes, element size); a single indexed element has zero
    // lanes and prints only its element size (".d[1]").
    auto arm64Vas2String = [](AArch64Layout_VectorLayout vas) {
      const unsigned int Lanes = static_cast<unsigned int>(vas) >> 8;
      std::string Element = vectorElementSuffix(vas);
      return Lanes == 0 ? Element : std::to_string(Lanes) + Element;
    };

    os << "." << arm64Vas2String(op.vas);
    if (!IsPrintingGroupedOperands) {
      // Grouped operands print the index following the group.
      if (op.vector_index != -1) {
        os << "[" << op.vector_index << "]";
      }
    }
  }

  auto arm64Shifter2String = [](aarch64_shifter sft) {
    switch (sft) {
    case AARCH64_SFT_INVALID:
      return "";
    case AARCH64_SFT_ASR:
    case AARCH64_SFT_ASR_REG:
      return "asr";
    case AARCH64_SFT_LSL:
    case AARCH64_SFT_LSL_REG:
      return "lsl";
    case AARCH64_SFT_LSR:
    case AARCH64_SFT_LSR_REG:
      return "lsr";
    case AARCH64_SFT_MSL:
    case AARCH64_SFT_MSL_REG:
      return "msl";
    case AARCH64_SFT_ROR:
    case AARCH64_SFT_ROR_REG:
      return "ror";
    default:
      return "";
    }
  };

  // Add extender if needed.
  if (op.ext != AARCH64_EXT_INVALID) {
    os << ", ";
    printExtender(os, op.ext, op.shift.type, op.shift.value);
  } else {
    std::string opcode = ascii_str_tolower(inst.mnemonic);
    opcode = opcode.substr(0, 3);
    if (op.shift.type != AARCH64_SFT_INVALID && op.shift.value != 0) {
      os << ", ";
      // In case where opcode is the same as one of arm64_shifters (e.g., lsl),
      // do not print it again here.
      std::string shift_type = arm64Shifter2String(op.shift.type);
      if (shift_type != opcode)
        os << shift_type << " ";
      // A shift by a register (Capstone 6 *_REG types) holds the register.
      if (op.shift.type >= AARCH64_SFT_LSL_REG)
        os << getRegisterName(op.shift.value);
      else
        os << "#" << op.shift.value;
    }
  }
}

void Arm64PrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_aarch64_op& op = inst.detail->aarch64.operands[index];
  assert(op.type == AARCH64_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    // Handle MOVZ/MOVK with absolute address group attributes (G0-G3).
    // The #:abs_gN: prefix tells the assembler which 16-bit group of the
    // symbol address to extract. GTIRB records the group but not whether the
    // original relocation was checked. Use the no-check spelling for G0-G2
    // so known binary addresses remain reconstructible even when rewriting
    // separates the instructions that materialize successive groups.
    bool hasAbsGroup = s->Attributes.count(gtirb::SymAttribute::G0) ||
                       s->Attributes.count(gtirb::SymAttribute::G1) ||
                       s->Attributes.count(gtirb::SymAttribute::G2) ||
                       s->Attributes.count(gtirb::SymAttribute::G3);

    if (hasAbsGroup) {
      if (s->Attributes.count(gtirb::SymAttribute::G0))
        os << "#:abs_g0_nc:";
      else if (s->Attributes.count(gtirb::SymAttribute::G1))
        os << "#:abs_g1_nc:";
      else if (s->Attributes.count(gtirb::SymAttribute::G2))
        os << "#:abs_g2_nc:";
      else // G3 is always the highest group, no _nc needed.
        os << "#:abs_g3:";
      this->printSymbolicExpression(os, s, true);
    } else {
      bool is_jump = cs_insn_group(this->csHandle, &inst, AARCH64_GRP_JUMP);
      if (!is_jump) {
        os << ' ';
      }
      this->printSymbolicExpression(os, s, !is_jump);
    }
  } else if (const auto* sa = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    printSymbolicExpression(os, sa, true);
  } else {
    os << "#" << op.imm;
    if (op.shift.type != AARCH64_SFT_INVALID && op.shift.value != 0) {
      os << ",";
      printShift(os, op.shift.type, op.shift.value);
    }
  }
}

void Arm64PrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_aarch64& detail = inst.detail->aarch64;
  const cs_aarch64_op& op = detail.operands[index];
  assert(op.type == AARCH64_OP_MEM &&
         "printOpIndirect called without a memory operand");

  bool first = true;

  os << "[";

  // Base register
  if (op.mem.base != AARCH64_REG_INVALID) {
    first = false;
    os << getRegisterName(op.mem.base);
  }

  // Displacement (constant)
  // Must always be printed if symbolic, even if disp is zero.
  const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic);
  const auto* sa = std::get_if<gtirb::SymAddrAddr>(symbolic);
  if (op.mem.disp != 0 || s || sa) {
    if (!first) {
      os << ",";
    }
    if (s) {
      printSymbolicExpression(os, s, false);
    } else if (sa) {
      printSymbolicExpression(os, sa, false);
    } else {
      os << "#" << op.mem.disp;
    }
    first = false;
  }

  // Index register
  if (op.mem.index != AARCH64_REG_INVALID) {
    if (!first) {
      os << ",";
    }
    first = false;
    os << getRegisterName(op.mem.index);
  }

  // Add extend / shift
  if (op.ext != AARCH64_EXT_INVALID) {
    os << ",";
    printExtender(os, op.ext, op.shift.type, op.shift.value);
  } else if (op.shift.type != AARCH64_SFT_INVALID && op.shift.value != 0) {
    os << ",";
    assert(!first && "unexpected shift operator");
    printShift(os, op.shift.type, op.shift.value);
  }

  os << "]";

  if (inst.detail->writeback && index + 1 == detail.op_count) {
    os << "!";
  }
}

void Arm64PrettyPrinter::printOpRawValue(std::ostream& os, const cs_insn& inst,
                                         uint64_t index) {
  // Grab the full operand string.
  const char* opStr = inst.op_str;

  // Flick through to the start of the operand.
  unsigned int currOperand = 0;
  bool inBlock = false;
  const char* pos;
  for (pos = opStr; *pos != '\0' && currOperand != index; pos++) {
    char cur = *pos;
    if (cur == '[') {
      // Entering an indirect memory access.
      assert(!inBlock && "nested blocks should not be possible");
      inBlock = true;
    } else if (cur == ']') {
      // Exiting an indirect memory access.
      assert(inBlock && "Closing unopened memory access");
      inBlock = false;
    } else if (!inBlock && cur == ',') {
      // Hit a new operand.
      currOperand++;
    }
  }
  assert(currOperand == index && "unexpected end of operands");
  const char* operandStart = pos;

  // Find the end of the operand.
  while (*pos != '\0') {
    char cur = *pos;
    if (cur == '[') {
      inBlock = true;
    } else if (cur == ']') {
      inBlock = false;
    } else if (!inBlock && cur == ',') {
      // Found end of operand.
      break;
    }
    pos++;
  }
  const char* operandEnd = pos;

  // Skip leading whitespace.
  while (isspace(*operandStart))
    operandStart++;

  // Print every character in the operand.
  for (const char* cur = operandStart; cur < operandEnd; cur++) {
    os << *cur;
  }
}

void Arm64PrettyPrinter::printOpBarrier(std::ostream& os,
                                        unsigned int barrier) {
  // Raw CRm field (AARCH64_DB_*, the values Capstone 5 used as well).
  switch (barrier) {
  case AARCH64_DB_OSHLD:
    os << "oshld";
    return;
  case AARCH64_DB_OSHST:
    os << "oshst";
    return;
  case AARCH64_DB_OSH:
    os << "osh";
    return;
  case AARCH64_DB_NSHLD:
    os << "nshld";
    return;
  case AARCH64_DB_NSHST:
    os << "nshst";
    return;
  case AARCH64_DB_NSH:
    os << "nsh";
    return;
  case AARCH64_DB_ISHLD:
    os << "ishld";
    return;
  case AARCH64_DB_ISHST:
    os << "ishst";
    return;
  case AARCH64_DB_ISH:
    os << "ish";
    return;
  case AARCH64_DB_LD:
    os << "ld";
    return;
  case AARCH64_DB_ST:
    os << "st";
    return;
  case AARCH64_DB_SY:
    os << "sy";
    return;
  default:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void Arm64PrettyPrinter::printOpPrefetch(std::ostream& os,
                                         unsigned int prefetch) {
  // Raw five-bit PRFOP field (Capstone 6 AARCH64_PRFM_* are 0-based; Capstone
  // 5's ARM64_PRFM_* were the same values plus one).
  switch (prefetch) {
  case AARCH64_PRFM_PLDL1KEEP:
    os << "pldl1keep";
    return;
  case AARCH64_PRFM_PLDL1STRM:
    os << "pldl1strm";
    return;
  case AARCH64_PRFM_PLDL2KEEP:
    os << "pldl2keep";
    return;
  case AARCH64_PRFM_PLDL2STRM:
    os << "pldl2strm";
    return;
  case AARCH64_PRFM_PLDL3KEEP:
    os << "pldl3keep";
    return;
  case AARCH64_PRFM_PLDL3STRM:
    os << "pldl3strm";
    return;
  case AARCH64_PRFM_PLIL1KEEP:
    os << "plil1keep";
    return;
  case AARCH64_PRFM_PLIL1STRM:
    os << "plil1strm";
    return;
  case AARCH64_PRFM_PLIL2KEEP:
    os << "plil2keep";
    return;
  case AARCH64_PRFM_PLIL2STRM:
    os << "plil2strm";
    return;
  case AARCH64_PRFM_PLIL3KEEP:
    os << "plil3keep";
    return;
  case AARCH64_PRFM_PLIL3STRM:
    os << "plil3strm";
    return;
  case AARCH64_PRFM_PSTL1KEEP:
    os << "pstl1keep";
    return;
  case AARCH64_PRFM_PSTL1STRM:
    os << "pstl1strm";
    return;
  case AARCH64_PRFM_PSTL2KEEP:
    os << "pstl2keep";
    return;
  case AARCH64_PRFM_PSTL2STRM:
    os << "pstl2strm";
    return;
  case AARCH64_PRFM_PSTL3KEEP:
    os << "pstl3keep";
    return;
  case AARCH64_PRFM_PSTL3STRM:
    os << "pstl3strm";
    return;
  default:
    // The names above are the operations Capstone 5 named; the instruction
    // field itself permits the full five-bit range, and GNU as accepts the
    // remaining values as an immediate operand.
    if (prefetch <= 0x1f) {
      os << "#" << prefetch;
      return;
    }
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void Arm64PrettyPrinter::printShift(std::ostream& os,
                                    const aarch64_shifter type,
                                    unsigned int value) {
  switch (type) {
  case AARCH64_SFT_LSL:
    os << "lsl";
    break;
  case AARCH64_SFT_MSL:
    os << "msl";
    break;
  case AARCH64_SFT_LSR:
    os << "lsr";
    break;
  case AARCH64_SFT_ASR:
    os << "asr";
    break;
  case AARCH64_SFT_ROR:
    os << "ror";
    break;
  default:
    assert(false && "unexpected case");
  }
  os << " #" << value;
}

void Arm64PrettyPrinter::printExtender(std::ostream& os,
                                       const aarch64_extender& ext,
                                       const aarch64_shifter shiftType,
                                       uint64_t shiftValue) {
  switch (ext) {
  case AARCH64_EXT_UXTB:
    os << "uxtb";
    break;
  case AARCH64_EXT_UXTH:
    os << "uxth";
    break;
  case AARCH64_EXT_UXTW:
    os << "uxtw";
    break;
  case AARCH64_EXT_UXTX:
    os << "uxtx";
    break;
  case AARCH64_EXT_SXTB:
    os << "sxtb";
    break;
  case AARCH64_EXT_SXTH:
    os << "sxth";
    break;
  case AARCH64_EXT_SXTW:
    os << "sxtw";
    break;
  case AARCH64_EXT_SXTX:
    os << "sxtx";
    break;
  default:
    assert(false && "unexpected case");
  }
  if (shiftType != AARCH64_SFT_INVALID) {
    assert(shiftType == AARCH64_SFT_LSL && "unexpected shift type in extender");
    os << " #" << shiftValue;
  }
}

void Arm64PrettyPrinter::printSymbolHeader(std::ostream& os,
                                           const gtirb::Symbol& sym) {
  if (LocalGotSyms.find(sym.getUUID()) != LocalGotSyms.end()) {
    if (auto SymbolInfo = aux_data::getElfSymbolInfo(sym)) {
      if (SymbolInfo->Binding == "LOCAL" &&
          SymbolInfo->Visibility == "DEFAULT") {
        // If there is a :got: reference to this symbol, we need it to be a
        // global symbol. Otherwise, the linker fails to generate .got entries
        // properly. Using ld from binutils 2.34, I observed where it would
        // generate a single entry in the .got for *all* symbols defined in the
        // binary referenced via :got:, so they all resolved to the same
        // (usually incorrect) symbol. We also apply hidden, so when linked into
        // a shared object or executable, the symbol is converted back to a
        // local symbol. These attributes match how the symbol would have
        // originally appeared in the assembly in an individual object file; to
        // be referenced via the got, the reference would be across compilation
        // units, so it would have to be global in the original object.
        auto Name = getSymbolName(sym);
        printBar(os, false);
        os << syntax.global() << ' ' << Name << '\n';
        os << elfSyntax.hidden() << ' ' << Name << '\n';

        printSymbolType(os, Name, *SymbolInfo);
        printBar(os, false);
        return;
      }
    }
  }

  // With no got references, print it normally.
  ElfPrettyPrinter::printSymbolHeader(os, sym);
}

std::unique_ptr<PrettyPrinterBase>
Arm64PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                  const gtirb::Module& module,
                                  const PrintingPolicy& policy) {
  static const Arm64Syntax syntax{};
  return std::make_unique<Arm64PrettyPrinter>(gtirb_context, module, syntax,
                                              policy);
}

} // namespace gtirb_pprint
