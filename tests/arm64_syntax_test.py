import gtirb
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm64InstructionsTest(PPrinterTest):
    @unittest.skipUnless(shutil.which("aarch64-linux-gnu-as") and
                         shutil.which("aarch64-linux-gnu-objcopy"),
                         "requires AArch64 binutils")
    def test_scalar_compare_zero_roundtrip_exact_bytes(self):
        """Capstone's duplicate zero operand must not corrupt scalar compares."""
        instructions = [
            f"{mnemonic} {destination},{source},#0"
            for mnemonic in ("cmge", "cmgt", "cmeq", "cmle", "cmlt")
            for destination, source in (("d0", "d1"), ("d31", "d31"), ("d0", "d31"))
        ]
        # Correct three-operand vector, floating-point and register-source
        # comparisons must retain their encodings as well.
        instructions += [
            f"{mnemonic} v0.16b,v1.16b,#0"
            for mnemonic in ("cmge", "cmgt", "cmeq", "cmle", "cmlt")
        ] + [
            f"{mnemonic} d0,d1,#0.0"
            for mnemonic in ("fcmge", "fcmgt", "fcmeq", "fcmle", "fcmlt")
        ] + [
            f"{mnemonic} d0,d1,d2" for mnemonic in ("cmge", "cmgt", "cmeq")
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def assemble(text):
                result = subprocess.run([
                    "aarch64-linux-gnu-as", "-o", str(root / "code.o"),
                ], input=text + "\n", text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                subprocess.run([
                    "aarch64-linux-gnu-objcopy", "-O", "binary", "-j", ".text",
                    str(root / "code.o"), str(root / "code.bin"),
                ], check=True, capture_output=True)
                return (root / "code.bin").read_bytes()

            for instruction in instructions:
                with self.subTest(instruction=instruction):
                    original = assemble(instruction)
                    ir, module = create_test_module(
                        file_format=gtirb.Module.FileFormat.ELF,
                        isa=gtirb.Module.ISA.ARM64,
                    )
                    _, interval = add_text_section(module)
                    add_code_block(interval, original)
                    self.assertEqual(assemble(run_asm_pprinter(ir)), original)

    def test_unpack_instructions(self):
        """
        Test printing various instructions
        """
        instructions = [
            (b"\x60\x00\xaf\x9e", "fmov v0.d[1],x3"),
            (b"\x03\x00\xae\x9e", "fmov x3,v0.d[1]"),
            (b"\x20\x3c\x08\x4e", "mov x0,v1.d[0]"),
            (b"\x20\x3c\x04\x0e", "mov w0,v1.s[0]"),
            (b"\x20\x04\x18\x4e", "dup v0.2d,v1.d[1]"),
            (b"\x20\x04\x08\x4e", "dup v0.2d,v1.d[0]"),
            (b"\xCA\x00\xAE\x9E", "fmov x10,v6.d[1]"),
            (b"\x10\x06\x08\x4E", "dup v16.2d,v16.d[0]"),
            (b"\x10\x04\x01\x4e", "dup v16.16b,v0.b[0]"),
            (b"\x20\x04\x04\x4e", "dup v0.4s,v1.s[0]"),
            (b"\x20\x3c\x02\x0e", "umov w0,v1.h[0]"),
            (b"\x20\x3c\x01\x0e", "umov w0,v1.b[0]"),
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

    @unittest.skipUnless(shutil.which("aarch64-linux-gnu-as") and
                         shutil.which("aarch64-linux-gnu-objcopy"),
                         "requires AArch64 binutils")
    def test_recovered_lanes_roundtrip_exact_bytes(self):
        """Mnemonic recovery and the unknown-lane fallback retain all bits."""
        instructions = [
            "fmov v0.d[1], x3", "fmov x3, v0.d[1]",
            "fmov v0.d[1], x29", "fmov x30, v0.d[1]",
            "fmov v0.d[1], xzr", "fmov xzr, v0.d[1]",
            "mov x0, v1.d[0]", "mov w0, v1.s[0]",
            "mov wzr, v1.s[0]", "dup v0.2d, v1.d[1]",
            "dup v16.2d, v16.d[0]", "mov d31, v6.d[1]",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def assemble(text):
                result = subprocess.run([
                    "aarch64-linux-gnu-as", "-o", str(root / "code.o"),
                ], input=text + "\n", text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                subprocess.run([
                    "aarch64-linux-gnu-objcopy", "-O", "binary", "-j", ".text",
                    str(root / "code.o"), str(root / "code.bin"),
                ], check=True, capture_output=True)
                return (root / "code.bin").read_bytes()

            for instruction in instructions:
                with self.subTest(instruction=instruction):
                    original = assemble(instruction)
                    ir, module = create_test_module(
                        file_format=gtirb.Module.FileFormat.ELF,
                        isa=gtirb.Module.ISA.ARM64,
                    )
                    _, interval = add_text_section(module)
                    add_code_block(interval, original)
                    self.assertEqual(assemble(run_asm_pprinter(ir)), original)

    @unittest.skipUnless(
        shutil.which("aarch64-linux-gnu-as")
        and shutil.which("aarch64-linux-gnu-objcopy"),
        "requires AArch64 binutils",
    )
    def test_complete_details_print_exact_mnemonics(self):
        """
        Capstone 5 left out the lane arrangement of a scalar DUP and the
        post-index immediate of a single-register ST1, so these printed as
        .inst. Capstone 6 reports both; the mnemonics must round-trip.
        """
        instructions = [
            (b"\xDF\x04\x18\x5E", "mov d31,v6.d[1]"),
            (b"\x14\x7C\x9F\x4C", "st1 {v20.2d},[x0],#16"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
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
                    subprocess.run(
                        ["aarch64-linux-gnu-as", "-o", str(root / "code.o")],
                        input=asm,
                        text=True,
                        check=True,
                        capture_output=True,
                    )
                    subprocess.run(
                        [
                            "aarch64-linux-gnu-objcopy", "-O", "binary",
                            "-j", ".text", str(root / "code.o"),
                            str(root / "code.bin"),
                        ],
                        check=True,
                        capture_output=True,
                    )
                    self.assertEqual(
                        (root / "code.bin").read_bytes(), insn_bytes
                    )

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
