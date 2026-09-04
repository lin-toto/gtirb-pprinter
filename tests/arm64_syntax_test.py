import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm64InstructionsTest(PPrinterTest):
    def test_unpack_instructions(self):
        """
        Test printing various instructions
        """
        instructions = [
            (b"\x00\x08\x80\xD2", "mov x0,#64"),
            (b"\xE8\x0E\x04\x0E", "dup v8.2s,w23"),
            (b"\xC7\x04\x02\x4E", "dup v7.8h,v6.h[0]"),
            (b"\x00\x00\x01\x4E", "tbl v0.16b,{v0.16b},v1.16b"),
            (b"\x47\x90\x00\x0D", "st1 {v7.s}[1],[x2]"),
            (b"\x9D\x0E\x9E\x0D", "st1 {v29.b}[3],[x20],lr"),
            (b"\x40\x1E\xB2\x4E", "mov v0.16b,v18.16b"),
            (b"\x00\xBC\x21\x1E", "fcsel s0,s0,s1,lt"),
            (b"\x40\x00\x80\xF9", "prfm pldl1keep,[x2]"),
            (b"\x13\xA0\x20\x0D", "st4 {v19.s,v20.s,v21.s,v22.s}[0],[x0]"),
            # TODO: capstone bug, see
            # https://github.com/capstone-engine/capstone/issues/1842
            # (b"\xDD\x9F\x2D\x05", "splice z29.b,p7,{z30.b,z31.b}"),
            # (b"\xFD\x9F\x2C\x05", "splice z29.b,p7,z30.b,z31.b"),
        ]

        for insn_bytes, insn_str in instructions:
            with self.subTest(instruction=insn_str):
                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ARM64,
                )
                s, bi = add_text_section(m)

                add_code_block(bi, insn_bytes)

                asm = run_asm_pprinter(ir)
                self.assertIn(insn_str, asm)

    def test_exact_instruction_fallbacks(self):
        """Preserve encodings Capstone cannot print as baseline ARMv8-A."""
        instructions = [
            (b"\x00\x48\x28\x4E", ".inst 0x4e284800"),  # AESE
            (b"\x00\xE0\xE0\x0E", ".inst 0x0ee0e000"),  # PMULL
            (b"\xCA\x00\xAE\x9E", ".inst 0x9eae00ca"),  # FMOV lane
            (b"\xDF\x04\x18\x5E", ".inst 0x5e1804df"),  # MOV lane
            (b"\x10\x06\x08\x4E", ".inst 0x4e080610"),  # DUP lane
            (b"\x14\x7C\x9F\x4C", ".inst 0x4c9f7c14"),  # ST1 post-index
            (b"\x01\x00\x21\xB8", ".inst 0xb8210001"),  # LDADD
            (b"\x1F\x24\x03\xD5", ".inst 0xd503241f"),  # BTI
            (b"\x99\x2A\x0F\xCE", ".inst 0xce0f2a99"),  # SHA3 EOR3
            (b"\xA3\x80\x66\xCE", ".inst 0xce6680a3"),  # SHA512H
        ]

        for insn_bytes, expected in instructions:
            with self.subTest(expected=expected):
                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ARM64,
                )
                _, bi = add_text_section(m)
                add_code_block(bi, insn_bytes)

                asm = run_asm_pprinter(ir)
                self.assertIn(expected, asm)

    def test_fixed_width_nop_is_printed_once(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ARM64,
        )
        _, bi = add_text_section(m)
        add_code_block(bi, b"\x1f\x20\x03\xd5")

        asm = run_asm_pprinter(ir)
        self.assertEqual(
            1,
            sum(line.strip() == "nop" for line in asm.splitlines()),
        )

    def test_print_abs_group_symbolic_operands(self):
        cases = [
            (
                b"\x00\x08\x80\xD2",
                gtirb.symbolicexpression.SymbolicExpression.Attribute.G0,
                "movz x0,#:abs_g0_nc:my_sym",
            ),
            (
                b"\x00\x00\xC0\xD2",
                gtirb.symbolicexpression.SymbolicExpression.Attribute.G2,
                "movz x0,#:abs_g2_nc:my_sym",
            ),
            (
                b"\x00\x00\x80\xF2",
                gtirb.symbolicexpression.SymbolicExpression.Attribute.G1,
                "movk x0,#:abs_g1_nc:my_sym",
            ),
            (
                b"\x00\x00\x80\xF2",
                gtirb.symbolicexpression.SymbolicExpression.Attribute.G3,
                "movk x0,#:abs_g3:my_sym",
            ),
        ]

        for insn_bytes, attr, expected in cases:
            with self.subTest(expected=expected):
                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ARM64,
                )
                _, bi = add_text_section(m)

                code = add_code_block(bi, insn_bytes)
                sym = gtirb.symbol.Symbol("my_sym", payload=code, module=m)
                sym_expr = gtirb.symbolicexpression.SymAddrConst(
                    0,
                    sym,
                    attributes=[attr],
                )
                bi.symbolic_expressions[0] = sym_expr

                asm = run_asm_pprinter(ir)
                self.assertIn(expected, asm)

    def test_movz_low_group_in_separated_chain_is_no_check(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ARM64,
        )
        _, bi = add_text_section(m)

        code = add_code_block(
            bi,
            b"\x00\x00\x80\xD2\x1F\x20\x03\xD5\x00\x00\xA0\xF2",
        )
        sym = gtirb.symbol.Symbol("my_sym", payload=code, module=m)
        bi.symbolic_expressions[0] = gtirb.symbolicexpression.SymAddrConst(
            0,
            sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.G0
            ],
        )
        bi.symbolic_expressions[8] = gtirb.symbolicexpression.SymAddrConst(
            0,
            sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.G1
            ],
        )

        asm = run_asm_pprinter(ir)
        self.assertIn("movz x0,#:abs_g0_nc:my_sym", asm)
        self.assertIn("movk x0,#:abs_g1_nc:my_sym", asm)
