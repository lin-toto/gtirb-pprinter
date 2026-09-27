//===- RiscvPrettyPrinter.hpp -----------------------------------*- C++ -*-===//
//
//  Copyright (C) 2026 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//===----------------------------------------------------------------------===//

#ifndef GTIRB_PP_RISCV_ASM_PRINTER_H
#define GTIRB_PP_RISCV_ASM_PRINTER_H

#include "ElfPrettyPrinter.hpp"

#include <map>
#include <set>

namespace gtirb_pprint {

class RiscvSyntax : public ElfSyntax {
public:
  std::string formatSectionName(const std::string& x) const override;
  std::string formatFunctionName(const std::string& x) const override;
  std::string formatSymbolName(const std::string& x) const override;

  SyntaxAlignmentStyle alignmentStyle() const override {
    return SyntaxAlignmentZeros;
  };

  const std::string& wordData() const override { return WordDirective; }

private:
  // ".word" on RISC-V is 4 bytes, so use ".half" for 2-byte data.
  const std::string WordDirective{".half"};
};

class RiscvPrettyPrinter : public ElfPrettyPrinter {
public:
  RiscvPrettyPrinter(gtirb::Context& context, const gtirb::Module& module,
                     const ElfSyntax& syntax, const PrintingPolicy& policy);

protected:
  std::string getRegisterName(unsigned int reg) const override;

  bool hasSymbolicCompressedJalr(const gtirb::CodeBlock& block,
                                 const cs_insn& inst);
  bool hasSymbolicCompressedAddi(const gtirb::CodeBlock& block,
                                 const cs_insn& inst);
  bool hasSymbolicCompressedAddiw(const gtirb::CodeBlock& block,
                                  const cs_insn& inst);
  bool shouldPrintCompressedLuiAsLui(const gtirb::CodeBlock& block,
                                     const cs_insn& inst);
  void collectTargetLabels();
  void collectLocalBranchLabels();
  void validatePcrelAnchors() const;
  void collectInteriorCodeSymbols();
  std::string getLocalBranchLabel(gtirb::Addr Target) const;
  std::string getLongBranchSkipLabel(gtirb::Addr Address) const;

  void printInstruction(std::ostream& os, const gtirb::CodeBlock& block,
                        const cs_insn& inst,
                        const gtirb::Offset& offset) override;
  void printSymbolDefinition(std::ostream& os,
                             const gtirb::Symbol& symbol) override;
  void printSymbolDefinitionRelativeToPC(std::ostream& os,
                                         const gtirb::Symbol& symbol,
                                         gtirb::Addr pc) override;
  bool printGpRelativeCopyRelocation(std::ostream& os,
                                     const gtirb::CodeBlock& block,
                                     const cs_insn& inst, gtirb::Addr Address);
  const gtirb::Symbol* getGpRelativeCopyRelocationSymbol(
      const gtirb::SymbolicExpression* Symbolic) const;
  void printRelocationSymbol(std::ostream& os, const gtirb::Symbol* Symbol,
                             const gtirb::SymAttributeSet& Attrs);
  bool printLongConditionalBranch(std::ostream& os,
                                  const gtirb::CodeBlock& block,
                                  const cs_insn& inst, gtirb::Addr Address);
  bool printPltCall(std::ostream& os, const gtirb::CodeBlock& block,
                    const cs_insn& inst, gtirb::Addr Address);
  bool printDirectCallRelocation(std::ostream& os,
                                 const gtirb::CodeBlock& block,
                                 const cs_insn& inst, gtirb::Addr Address);
  bool printPltCallRelocation(std::ostream& os, const gtirb::CodeBlock& block,
                              const cs_insn& inst, gtirb::Addr Address);
  std::optional<std::string>
  getPltTargetName(const gtirb::CodeBlock& block, const cs_insn& inst);
  std::optional<std::string> getDirectRelocationTargetName(
      const gtirb::CodeBlock& block, const cs_insn& inst);
  std::optional<std::string> getPltRelocationTargetName(
      const gtirb::CodeBlock& block, const cs_insn& inst);
  bool isPltCall(const cs_insn& inst) const;
  bool isPltTailCall(const cs_insn& inst) const;
  void printOperandList(std::ostream& os, const gtirb::CodeBlock& block,
                        const cs_insn& inst) override;
  void printOperand(std::ostream& os, const gtirb::CodeBlock& block,
                    const cs_insn& inst, uint64_t index) override;
  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        uint64_t index) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

  std::optional<std::string> getTargetLabel(gtirb::Addr Target) const;

  void printSymExprPrefix(std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
                          bool IsNotBranch) override;
  void printSymExprSuffix(std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
                          bool IsNotBranch) override;

  std::set<uint64_t> LocalBranchLabels;
  std::map<uint64_t, std::string> TargetLabels;
  std::map<uint64_t, std::set<const gtirb::Symbol*, CmpSymPtr>>
      InteriorCodeSymbols;
  std::set<const gtirb::Symbol*> PrintedInteriorCodeSymbols;
  std::set<uint64_t> SuppressedInstructionAddresses;
};

class RiscvPrettyPrinterFactory : public ElfPrettyPrinterFactory {
public:
  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, const gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_RISCV_ASM_PRINTER_H */
