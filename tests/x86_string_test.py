from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import PPrinterTest, run_asm_pprinter


@unittest.skipUnless(shutil.which("as") and shutil.which("objcopy"),
                     "requires GNU assembler and objcopy")
class X86StringTests(PPrinterTest):
    def test_string_prefixes_survive_reassembly(self):
        for bits, isa in ((32, gtirb.Module.ISA.IA32), (64, gtirb.Module.ISA.X64)):
            code = bytearray()
            for opcode in (0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf):
                for repeat in (b"", b"\xf2", b"\xf3"):
                    for address in (b"", b"\x67"):
                        for segment in (b"", b"\x64", b"\x65"):
                            for operand in ((b"", b"\x66", b"\x48") if bits == 64 else (b"", b"\x66")):
                                code.extend(segment + address + (operand if operand == b"\x66" else b"") +
                                            repeat + (operand if operand == b"\x48" else b"") + bytes([opcode]))
            ir, module = create_test_module(file_format=gtirb.Module.FileFormat.ELF, isa=isa)
            _, interval = add_text_section(module)
            add_code_block(interval, bytes(code))
            for syntax in ("intel", "att"):
                with self.subTest(bits=bits, syntax=syntax), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    assembly = run_asm_pprinter(ir, ["--syntax=" + syntax])
                    (root / "printed.S").write_text(assembly)
                    subprocess.run(["as", "--" + str(bits), str(root / "printed.S"),
                                    "-o", str(root / "printed.o")], check=True, capture_output=True)
                    subprocess.run(["objcopy", "-O", "binary", "-j", ".text",
                                    str(root / "printed.o"), str(root / "printed.bin")],
                                   check=True, capture_output=True)
                    self.assertEqual((root / "printed.bin").read_bytes(), bytes(code))


if __name__ == "__main__":
    unittest.main()
