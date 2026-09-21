"""The CLI must propagate printer and output-stream failures without origins."""
from pathlib import Path
import subprocess
import unittest

import gtirb

from gtirb_helpers import create_test_module, add_text_section, add_code_block
from pprinter_helpers import PPrinterTest, pprinter_binary, temp_directory


class PrintingErrorTest(PPrinterTest):
    def fixture(self):
        ir, module = create_test_module(gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64)
        _, interval = add_text_section(module, address=0x1000)
        add_code_block(interval, b"\xc3")
        return ir, module

    def test_invalid_aux_data_fails_for_file_and_stdout(self):
        for output in ("file", "stdout"):
            with self.subTest(output=output), temp_directory(prefix="print-error-") as directory:
                root = Path(directory)
                ir, module = self.fixture()
                del module.aux_data["functionEntries"]
                ir.save_protobuf(root / "input.gtirb")
                command = [pprinter_binary(), "--ir", str(root / "input.gtirb")]
                if output == "file":
                    command += ["--asm", str(root / "output.S")]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, output + ": " + result.stderr)
                self.assertIn("Missing FunctionEntries", result.stderr)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires Linux /dev/full")
    def test_failed_output_flush_returns_failure(self):
        with temp_directory(prefix="print-flush-") as directory:
            root = Path(directory)
            ir, _ = self.fixture()
            ir.save_protobuf(root / "input.gtirb")
            result = subprocess.run([pprinter_binary(), "--ir", str(root / "input.gtirb"),
                                     "--asm", "/dev/full"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
