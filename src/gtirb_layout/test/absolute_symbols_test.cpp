#include "gtirb_layout/gtirb_layout.hpp"
#include "gtirb_pprinter/AuxDataSchema.hpp"

#include <gtest/gtest.h>

using namespace gtirb;
using namespace gtirb_layout;

TEST(Unit_Layout, absoluteSymbolsSurviveRepeatedLayout) {
  Context C;
  Module* M = Module::Create(C, "absolute-symbols");
  M->setFileFormat(FileFormat::ELF);
  Section* S = M->addSection(C, ".text");
  ByteInterval* BI = S->addByteInterval(C, Addr(0x1000), 16);
  CodeBlock* Block = BI->addBlock<CodeBlock>(C, 0, 4);
  Symbol* Zero = M->addSymbol(C, Addr(0), "zero");
  Symbol* Constant = M->addSymbol(C, Addr(0x1000), "constant");
  Symbol* Movable = M->addSymbol(C, Addr(0x1000), "movable");
  Symbol* SectionRelative = M->addSymbol(C, Addr(0x3000), "section_relative");
  AuxDataContainer::registerAuxDataType<schema::ElfSymbolInfo>();
  schema::ElfSymbolInfo::Type Info;
  Info[Constant->getUUID()] = {0, "NOTYPE", "LOCAL", "DEFAULT", 0xfff1};
  Info[SectionRelative->getUUID()] = {0, "NOTYPE", "GLOBAL", "DEFAULT", 1};
  M->addAuxData<schema::ElfSymbolInfo>(std::move(Info));

  for (int I = 0; I < 3; ++I) {
    layoutModule(C, *M);
    EXPECT_EQ(Zero->getAddress(), Addr(0));
    EXPECT_FALSE(Zero->hasReferent());
    EXPECT_EQ(Constant->getAddress(), Addr(0x1000));
    EXPECT_FALSE(Constant->hasReferent());
    EXPECT_EQ(Movable->getReferent<CodeBlock>(), Block);
  }
  const auto* Result = M->getAuxData<schema::ElfSymbolInfo>();
  ASSERT_TRUE(Result->count(Zero->getUUID()));
  EXPECT_EQ(std::get<4>(Result->at(Zero->getUUID())), 0xfff1);
  EXPECT_EQ(std::get<4>(Result->at(SectionRelative->getUUID())), 1);
}
