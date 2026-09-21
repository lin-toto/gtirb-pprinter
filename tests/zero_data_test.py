from pathlib import Path
import shutil
import subprocess
import tempfile

import gtirb

from gtirb_helpers import (
    add_data_block,
    add_data_section,
    create_test_module,
)
from pprinter_helpers import PPrinterTest, run_asm_pprinter


class ZeroDataTest(PPrinterTest):
    def test_interior_expression_is_not_replaced_with_zeroes(self):
        if not shutil.which("cc") or not shutil.which("objcopy"):
            self.skipTest("requires the host assembler and objcopy")
        for size in (1, 2, 4, 8):
            for difference in (False, True):
                with self.subTest(size=size, difference=difference):
                    ir, module = create_test_module(
                        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
                    )
                    _, interval = add_data_section(module, address=0x2000)
                    add_data_block(interval, b"\x00" * 16)
                    first = gtirb.Symbol("first", payload=0x42, module=module)
                    second = gtirb.Symbol("second", payload=0x40, module=module)
                    expression = (
                        gtirb.SymAddrAddr(1, 0, first, second) if difference
                        else gtirb.SymAddrConst(0, first)
                    )
                    offset = 16 - size
                    interval.symbolic_expressions[offset] = expression
                    module.aux_data["symbolicExpressionSizes"].data[
                        gtirb.Offset(interval, offset)
                    ] = size
                    asm = run_asm_pprinter(ir)
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        assembled = subprocess.run(
                            ["cc", "-c", "-x", "assembler", "-", "-o",
                             str(root / "test.o")],
                            input=asm, text=True, capture_output=True,
                            timeout=30,
                        )
                        self.assertEqual(
                            assembled.returncode, 0, assembled.stderr
                        )
                        extracted = subprocess.run(
                            ["objcopy", "--dump-section",
                             f".data={root / 'data.bin'}", str(root / "test.o")],
                            text=True, capture_output=True, timeout=10,
                        )
                        self.assertEqual(
                            extracted.returncode, 0, extracted.stderr
                        )
                        expected = 2 if difference else 0x42
                        self.assertEqual(
                            (root / "data.bin").read_bytes(),
                            b"\x00" * offset + expected.to_bytes(size, "little"),
                        )

    def test_expression_in_next_block_keeps_zero_block_compact(self):
        ir, module = create_test_module(
            gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
        )
        _, interval = add_data_section(module, address=0x2000)
        add_data_block(interval, b"\x00" * 16)
        target = gtirb.Symbol("target", payload=0x42, module=module)
        add_data_block(interval, b"\x00" * 8,
                       {0: gtirb.SymAddrConst(0, target)})
        asm = run_asm_pprinter(ir)
        self.assertRegex(asm, r"(?m)^\s*\.zero 16\s*$")
        self.assertRegex(asm, r"(?m)^\s*\.quad target\s*$")
