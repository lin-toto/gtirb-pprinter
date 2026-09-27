"""Environment/state widths and their relocatable operands survive printing."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb

from gtirb_helpers import (
    add_code_block, add_data_block, add_data_section, add_elf_symbol_info, add_symbol,
    add_text_section, create_test_module,
)
from pprinter_helpers import PPrinterTest, run_asm_pprinter


@unittest.skipUnless(shutil.which("as") and shutil.which("objcopy"),
                     "requires GNU assembler and objcopy")
class X87StateTests(PPrinterTest):
    def test_environment_state_widths_roundtrip(self):
        # With 66 these are 14/94-byte accesses, without it 28/108 bytes.
        # Include FWAIT (waiting FSTENV/FSAVE) as well as the FN forms.
        encodings = (b"\xd9\x27", b"\xd9\x37", b"\xdd\x27", b"\xdd\x37")
        code = b"".join(wait + prefix + insn
                        for insn in encodings
                        for prefix in (b"", b"\x66")
                        for wait in (b"", b"\x9b"))
        for bits, isa in ((32, gtirb.Module.ISA.IA32), (64, gtirb.Module.ISA.X64)):
            ir, m = create_test_module(gtirb.Module.FileFormat.ELF, isa)
            _, bi = add_text_section(m)
            add_code_block(bi, code)
            for syntax in ("att", "intel"):
                with self.subTest(bits=bits, syntax=syntax):
                    self.assertEqual(self.assemble(ir, syntax, bits), code)

    def test_prefixed_state_operands_remain_relocatable(self):
        # A prefix-only fix must not emit the entire instruction as bytes:
        # these four RIP-relative data references still need relocations.
        for syntax in ("att", "intel"):
            with self.subTest(syntax=syntax):
                ir, m = create_test_module(gtirb.Module.FileFormat.ELF,
                                           gtirb.Module.ISA.X64)
                _, bi = add_text_section(m)
                _, data = add_data_section(m)
                target = add_symbol(m, "state_buffer", add_data_block(data, bytes(108)))
                add_elf_symbol_info(m, target, 108, "OBJECT")
                for opcode, modrm in ((0xd9, 0x25), (0xd9, 0x35),
                                      (0xdd, 0x25), (0xdd, 0x35)):
                    block = add_code_block(bi, bytes((0x66, opcode, modrm)) + bytes(4))
                    bi.symbolic_expressions[block.offset + 3] = gtirb.SymAddrConst(0, target)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.assemble(ir, syntax, 64, root)
                    relocations = subprocess.check_output(
                        ["readelf", "-rW", str(root / "printed.o")], text=True)
                    self.assertEqual(relocations.count("R_X86_64_PC32"), 4)
                    # Every relocation points at the state buffer, with the
                    # usual displacement addend; only the size prefix is raw.
                    self.assertEqual(relocations.count("state_buffer - 4"), 4)

    def assemble(self, ir, syntax, bits, root=None):
        if root is None:
            with tempfile.TemporaryDirectory() as directory:
                return self.assemble(ir, syntax, bits, Path(directory))
        (root / "printed.S").write_text(run_asm_pprinter(ir, ["--syntax=" + syntax]))
        assembled = subprocess.run(["as", "--" + str(bits), str(root / "printed.S"),
                                    "-o", str(root / "printed.o")], capture_output=True)
        self.assertEqual(assembled.returncode, 0, assembled.stderr.decode())
        subprocess.run(["objcopy", "-O", "binary", "-j", ".text",
                        str(root / "printed.o"), str(root / "printed.bin")],
                       check=True, capture_output=True)
        return (root / "printed.bin").read_bytes()
