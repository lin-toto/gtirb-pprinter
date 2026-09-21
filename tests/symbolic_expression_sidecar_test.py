import gzip
from pathlib import Path
import struct
import subprocess
import tempfile

import gtirb

from gtirb_helpers import (
    add_code_block,
    add_data_block,
    add_data_section,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import PPrinterTest, pprinter_binary


class SymbolicExpressionSidecarTest(PPrinterTest):
    def _restore(self, size, *, offset=0, has_size=True, block_size=16,
                 cached_size=None, encoding=None, kind=0, code=False,
                 initialized_size=None, valid=True):
        ir, module = create_test_module(
            gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
        )
        if code:
            _, interval = add_text_section(module, address=0x1000)
            block = add_code_block(
                interval, bytes.fromhex("48b8 0000000000000000 c3")
            )
        else:
            _, interval = add_data_section(module, address=0x2000)
            block = add_data_block(interval, b"\x00" * block_size)
            interval.contents += b"\x00" * (16 - block_size)
            interval.size = len(interval.contents)
        if initialized_size is not None:
            interval.contents = interval.contents[:initialized_size]
        if encoding is not None:
            module.aux_data["encodings"].data[block] = encoding
        if cached_size is not None:
            module.aux_data["symbolicExpressionSizes"].data[
                gtirb.Offset(interval, offset)
            ] = cached_size
        first = gtirb.Symbol("target", payload=0x42, module=module)
        second = gtirb.Symbol("other", payload=0x40, module=module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(root / "input.gtirb")
            with gzip.open(root / "expressions.gz", "wb") as stream:
                stream.write(b"GTIRBSE1" + struct.pack("<QQ", 1, 1))
                stream.write(interval.uuid.bytes + struct.pack("<Q", 1))
                stream.write(struct.pack(
                    "<QBBHQq", offset, kind, int(has_size), 0, size, 0
                ))
                if kind:
                    stream.write(struct.pack("<q", 1))
                stream.write(first.uuid.bytes)
                if kind:
                    stream.write(second.uuid.bytes)
            command = [
                pprinter_binary(), "--ir", str(root / "input.gtirb"),
                "--symbolic-expression-sidecar", str(root / "expressions.gz"),
                "--asm", str(root / "output.S"),
            ]
            if not valid:
                # Exercise loader rejection without reaching a printer loop
                # or assertion in an unfixed build.
                command.extend(("--skip-section", ".data"))
            result = subprocess.run(
                command, text=True, capture_output=True, timeout=10
            )
            if valid:
                self.assertEqual(result.returncode, 0, result.stderr)
                return (root / "output.S").read_text()
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("sidecar", result.stderr)
            self.assertFalse((root / "output.S").exists())

    def test_scalar_sizes_and_interval_end(self):
        directives = {1: "byte", 2: "(?:word|short)", 4: "long", 8: "quad"}
        for size in (1, 2, 4, 8):
            for offset in (0, 16 - size):
                for kind in (0, 1):
                    with self.subTest(size=size, offset=offset, kind=kind):
                        asm = self._restore(size, offset=offset, kind=kind)
                        self.assertRegex(
                            asm, rf"(?m)^\s*\.{directives[size]}\s+target"
                        )

    def test_invalid_sizes_are_rejected_before_printing(self):
        for size, offset, block_size in (
            (0, 0, 16), (3, 0, 16), (16, 0, 16), (17, 0, 16),
            ((1 << 64) - 1, 1, 16), (8, 12, 16), (8, 4, 8),
            (4, 16, 16), (4, (1 << 64) - 1, 16),
        ):
            for kind in (0, 1):
                with self.subTest(size=size, offset=offset, kind=kind):
                    self._restore(size, offset=offset, block_size=block_size,
                                  kind=kind, valid=False)

    def test_leb128_sizes(self):
        for encoding in ("uleb128", "sleb128"):
            for size in (1, 3, 5):
                with self.subTest(encoding=encoding, size=size):
                    asm = self._restore(size, encoding=encoding, kind=1)
                    self.assertIn("." + encoding, asm)
            self._restore(17, encoding=encoding, valid=False)

    def test_inferred_and_existing_sizes(self):
        self._restore(0, has_size=False, block_size=4)
        self._restore(0, has_size=False, cached_size=4)
        self._restore(0, has_size=False, block_size=16, valid=False)
        for size in (0, 3, 17):
            with self.subTest(cached_size=size):
                self._restore(0, has_size=False, cached_size=size, valid=False)
        self._restore(4, cached_size=4, valid=False)

    def test_code_expression_without_size(self):
        self._restore(0, has_size=False, code=True, offset=2)
        self._restore(8, code=True, offset=2)

    def test_uninitialized_extent(self):
        self._restore(8, offset=4, initialized_size=8, valid=False)
        self._restore(8, offset=8, initialized_size=8, valid=False)
        self._restore(0, has_size=False, code=True, offset=2,
                      initialized_size=2, valid=False)
