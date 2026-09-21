from pathlib import Path
import shutil
import subprocess
import tempfile

import gtirb

from gtirb_helpers import (
    add_code_block,
    add_data_block,
    add_section,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import PPrinterTest, run_asm_pprinter


class RiscvLeb128Test(PPrinterTest):
    def _assembly(self, bits, encoding, negative):
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            {"ISA": f"RISCV{bits}"}, "mapping<string,string>"
        )
        _, text = add_text_section(module, address=0x1000)
        first = add_code_block(text, bytes.fromhex("13000000 ef000000"))
        last = add_code_block(text, bytes.fromhex("13000000"))
        start = gtirb.Symbol("region_start", payload=first, module=module)
        end = gtirb.Symbol("region_end", payload=last, module=module)
        text.symbolic_expressions[first.offset + 4] = gtirb.SymAddrConst(
            0, start
        )

        _, data = add_section(module, ".rodata", address=0x2000)
        # The table length must grow when the region length needs more bytes.
        length = add_data_block(data, b"\x01")
        field = add_data_block(data, b"\x7b" if negative else b"\x0b")
        sentinel = add_data_block(data, b"\x5a")
        table = gtirb.Symbol("table_start", payload=field, module=module)
        table_end = gtirb.Symbol(
            "table_end", payload=sentinel, module=module
        )
        expressions = (
            (length, "uleb128", gtirb.SymAddrAddr(1, 0, table_end, table)),
            (field, encoding, gtirb.SymAddrAddr(
                1, 3, start if negative else end, end if negative else start
            )),
        )
        for block, kind, expression in expressions:
            module.aux_data["encodings"].data[block] = kind
            module.aux_data["symbolicExpressionSizes"].data[
                gtirb.Offset(data, block.offset)
            ] = 1
            data.symbolic_expressions[block.offset] = expression
        return run_asm_pprinter(ir)

    @staticmethod
    def _decode(data, signed):
        value = 0
        for index, byte in enumerate(data):
            value |= (byte & 0x7f) << (7 * index)
            if not byte & 0x80:
                if signed and byte & 0x40:
                    value -= 1 << (7 * (index + 1))
                return value, index + 1
        raise AssertionError("unterminated LEB128")

    def _check_relayout(self, bits, encoding, negative, compiler, relax):
        for tool in (compiler, "riscv64-linux-gnu-ld",
                     "riscv64-linux-gnu-objcopy", "riscv64-linux-gnu-nm"):
            if not shutil.which(tool):
                self.skipTest(f"requires {tool}")
        asm = self._assembly(bits, encoding, negative)
        self.assertRegex(asm, rf"\.{encoding}\s+.*region_")
        self.assertRegex(asm, r"\.uleb128\s+.*table_end")
        # Exercise both encoding-width growth and linker call relaxation.
        for nops in (0, 63, 8192):
            with self.subTest(nops=nops):
                moved = asm.replace(
                    "region_end:",
                    f".rept {nops}\n nop\n.endr\nregion_end:",
                )
                self.assertNotEqual(moved, asm)
                if not relax:
                    moved = ".option norelax\n" + moved
                with tempfile.TemporaryDirectory() as directory:
                    obj = str(Path(directory) / "test.o")
                    binary = str(Path(directory) / "test")
                    raw = Path(directory) / "data"
                    if compiler == "riscv64-linux-gnu-as":
                        cmd = [compiler, f"-march=rv{bits}gc", "-o", obj]
                    else:
                        cmd = [compiler, f"--target=riscv{bits}-linux-gnu",
                               "-x", "assembler", "-c", "-o", obj, "-"]
                    assembled = subprocess.run(
                        cmd, input=moved, text=True, capture_output=True,
                        timeout=30,
                    )
                    self.assertEqual(assembled.returncode, 0, assembled.stderr)
                    linked = subprocess.run(
                        ["riscv64-linux-gnu-ld", f"-melf{bits}lriscv",
                         "--relax" if relax else "--no-relax",
                         "-e", "0", "-o", binary, obj],
                        text=True, capture_output=True, timeout=30,
                    )
                    self.assertEqual(linked.returncode, 0, linked.stderr)
                    subprocess.run(
                        ["riscv64-linux-gnu-objcopy", "-O", "binary",
                         "-j", ".rodata", binary, str(raw)],
                        check=True, capture_output=True, timeout=30,
                    )
                    names = subprocess.check_output(
                        ["riscv64-linux-gnu-nm", "-P", binary],
                        text=True, timeout=30,
                    )
                    addresses = {}
                    for line in names.splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            addresses[parts[0]] = int(parts[2], 16)
                    distance = (
                        addresses["region_end"] - addresses["region_start"]
                    )
                    data = raw.read_bytes()
                    length, header_size = self._decode(data, False)
                    value, field_size = self._decode(
                        data[header_size:], encoding == "sleb128"
                    )
                    self.assertEqual(
                        value, (-distance if negative else distance) + 3
                    )
                    self.assertEqual(length, field_size)
                    if nops == 8192:
                        self.assertGreaterEqual(field_size, 3)
                    self.assertEqual(data[header_size + field_size:], b"\x5a")

    def test_unsigned_relayout(self):
        for bits in (32, 64):
            for compiler in ("riscv64-linux-gnu-as", "clang-19"):
                for relax in (False, True):
                    with self.subTest(
                        bits=bits, compiler=compiler, relax=relax
                    ):
                        self._check_relayout(
                            bits, "uleb128", False, compiler, relax
                        )

    def test_signed_relayout(self):
        # Signed differences have no RISC-V relaxation relocation; LLVM can
        # resolve them when instruction sizes are fixed at assembly time.
        for bits in (32, 64):
            for negative in (False, True):
                with self.subTest(bits=bits, negative=negative):
                    self._check_relayout(
                        bits, "sleb128", negative, "clang-19", False
                    )

    def test_signed_relaxation_is_not_silently_frozen(self):
        if not shutil.which("clang-19"):
            self.skipTest("requires clang-19")
        for bits in (32, 64):
            with self.subTest(bits=bits):
                asm = self._assembly(bits, "sleb128", False)
                with tempfile.TemporaryDirectory() as directory:
                    result = subprocess.run(
                        ["clang-19", f"--target=riscv{bits}-linux-gnu",
                         "-x", "assembler", "-c", "-o",
                         str(Path(directory) / "test.o"), "-"],
                        input=asm, text=True, capture_output=True, timeout=30,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(".sleb128", result.stderr)
