import subprocess
import unittest

import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter_with_output, PPrinterTest


class IncompleteDecodeTest(PPrinterTest):
    def test_undecodable_block_tail_is_an_error(self):
        """
        A code block whose bytes Capstone cannot decode completely must not
        print silently truncated: a lone REX prefix after a NOP ends the block.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        s, bi = add_text_section(m)
        add_code_block(bi, b"\x90\x48")

        with self.assertRaises(subprocess.CalledProcessError) as error:
            run_asm_pprinter_with_output(ir)
        self.assertEqual(error.exception.returncode, 1)
        self.assertIn(
            b"Capstone could not decode the instruction at 0x",
            error.exception.output,
        )

    def test_complete_block_prints(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        s, bi = add_text_section(m)
        add_code_block(bi, b"\x90\xc3")

        asm, _ = run_asm_pprinter_with_output(ir)
        self.assertIn("ret", asm)


if __name__ == "__main__":
    unittest.main()
