"""Multi-byte x86 NOPs must remain one instruction after a round trip."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import PPrinterTest, run_asm_pprinter


class X86NopEncodingTest(PPrinterTest):
    def test_masm_uses_native_byte_directives(self):
        """The shared printer path must not emit ELF directives for PE."""
        for isa in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64):
            with self.subTest(isa=isa):
                ir, module = create_test_module(
                    file_format=gtirb.Module.FileFormat.PE, isa=isa,
                    binary_type=["EXEC", "EXE", "WINDOWS_CUI"])
                _, interval = add_text_section(module)
                add_code_block(interval, bytes.fromhex("0f1f4000c3"))
                assembly = run_asm_pprinter(ir)
                for value in ("BYTE 00fH", "BYTE 01fH", "BYTE 040H", "BYTE 000H"):
                    self.assertIn(value, assembly)
                self.assertNotIn(".byte", assembly)

    @unittest.skipUnless(shutil.which("as") and shutil.which("objcopy"),
                         "requires GNU x86 assembler and objcopy")
    def test_multi_byte_nops_reassemble_to_original_instructions(self):
        encodings = [
            "90", "6690", "0f1f00", "0f1f4000", "0f1f440000",
            "660f1f440000", "0f1f8000000000", "0f1f840000000000",
            "660f1f840000000000", "662e0f1f840000000000",
        ]
        for bits, isa in ((32, gtirb.Module.ISA.IA32),
                          (64, gtirb.Module.ISA.X64)):
            for syntax in ("att", "intel"):
                for encoding in encodings:
                    with self.subTest(bits=bits, syntax=syntax, encoding=encoding):
                        # A real following instruction also pins the next
                        # boundary, rather than checking assembly spelling.
                        code = bytes.fromhex(encoding + "31c0c3")
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF, isa=isa)
                        _, interval = add_text_section(module)
                        add_code_block(interval, code)
                        assembly = run_asm_pprinter(ir, ["--syntax=" + syntax])
                        with tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            result = subprocess.run(
                                ["as", "--" + str(bits), "-o", str(root / "code.o")],
                                input=assembly, text=True, capture_output=True)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            subprocess.run([
                                "objcopy", "-O", "binary", "-j", ".text",
                                str(root / "code.o"), str(root / "code.bin"),
                            ], check=True, capture_output=True)
                            self.assertEqual((root / "code.bin").read_bytes(), code)

    def test_single_byte_nop_remains_readable(self):
        for syntax in ("att", "intel"):
            with self.subTest(syntax=syntax):
                ir, module = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.X64)
                _, interval = add_text_section(module)
                add_code_block(interval, b"\x90\xc3")
                assembly = run_asm_pprinter(ir, ["--syntax=" + syntax])
                self.assertEqual(sum(line.strip() == "nop"
                                     for line in assembly.splitlines()), 1)
