"""Native Capstone operands must survive assembly and a changed code layout."""

from pathlib import Path
import shutil
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
from pprinter_helpers import PPrinterTest, run_asm_pprinter


class NativeOperandShapesTest(PPrinterTest):
    def _assemble(self, source, prefix, directory, flags=()):
        obj = directory / "code.o"
        binary = directory / "code.bin"
        result = subprocess.run(
            [prefix + "as", *flags, "-o", str(obj)],
            input=source + "\n", text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + "\n" + source)
        subprocess.run(
            [prefix + "objcopy", "-O", "binary", "-j", ".text",
             str(obj), str(binary)], check=True, capture_output=True,
        )
        return binary.read_bytes()

    def test_native_nonaddress_operands_after_nop_insertion(self):
        variants = [
            ("aarch64-linux-gnu-", gtirb.Module.ISA.ARM64, None,
             bytes.fromhex("1f2003d5"), (), [
                 "ldr x0,[x1],#8", "ldr x0,[x1,#8]!",
                 "stp x0,x1,[sp],#16", "st1 {v0.2d},[x0],#16",
                 "st1 {v0.b}[0],[x0],x1", "prfm #31,[x0]",
                 "lsl x0,x1,#0", "lsl x0,x1,#4", "lsr x0,x1,x2",
                 "sxtb x0,w1", "sxth w0,w1", "add x0,x1,w2,sxtw #2",
                 "fcmp d0,#0.0", "fcmpe d0,#0.0", "fmov d0,#1.0",
                 "mrs x0,TPIDR_EL0", "msr DAIFSet,#2", "dc cvau,x0",
                 "dmb ish", "mov v0.16b,v1.16b",
             ]),
            ("riscv64-linux-gnu-", gtirb.Module.ISA.ValidButUnsupported,
             "RISCV64", bytes.fromhex("0100"),
             ("-march=rv64gc", "-mabi=lp64d"), [
                 "c.ld a0,8(a1)", "c.sd a0,8(a1)", "c.lw a0,4(a1)",
                 "c.fld fa0,8(a1)", "c.fsd fa0,8(a1)",
                 "lr.d.aq a0,(a1)", "sc.d.rl a0,a2,(a1)",
                 "amoadd.d.aqrl a0,a2,(a1)", "amoswap.w a0,a2,(a1)",
                 "csrrs a0,0xc01,zero", "csrrw zero,0x003,a0",
                 "fence iorw,iorw", ".4byte 0x0000000f", "fence ir,ow",
                 "fadd.d fa0,fa1,fa2,rtz", "fadd.s fa0,fa1,fa2,dyn",
                 "fcvt.d.w fa0,a0", "addi a0,a1,0",
             ]),
        ]
        for prefix, isa, arch, nop, flags, instructions in variants:
            if not shutil.which(prefix + "as"):
                self.skipTest("requires AArch64 and RISC-V binutils")
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for instruction in instructions:
                    with self.subTest(isa=isa, instruction=instruction):
                        encoded = self._assemble(instruction, prefix, root, flags)
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF, isa=isa,
                        )
                        if arch:
                            module.aux_data["archInfo"] = gtirb.AuxData(
                                {"ISA": arch}, "mapping<string,string>",
                            )
                        _, interval = add_text_section(module, address=0x1000)
                        # Move every original instruction behind a new block.
                        add_code_block(interval, nop)
                        add_code_block(interval, encoded)
                        assembly = run_asm_pprinter(ir)
                        if arch:
                            assembly = ".option norelax\n" + assembly
                        actual = self._assemble(assembly, prefix, root, flags)
                        # RISC-V GAS pads .text to its declared alignment.
                        # Build the expected bytes with the same alignment,
                        # but from the original instruction plus the new NOP.
                        if arch:
                            expected = self._assemble(
                                ".option norelax\n.align 4\nc.nop\n" + instruction,
                                prefix, root, flags,
                            )
                        else:
                            expected = nop + encoded
                        self.assertEqual(actual, expected, assembly)

    def test_aarch64_literal_target_after_nop_insertion(self):
        """A native MEM literal must stay symbolic after the code moves."""
        prefix = "aarch64-linux-gnu-"
        if not all(shutil.which(tool) for tool in
                   (prefix + "as", prefix + "ld", "qemu-aarch64")):
            self.skipTest("requires AArch64 binutils and QEMU")
        for nop_count in (1, 9, 64):
            with self.subTest(nops=nop_count), tempfile.TemporaryDirectory() as directory:
                ir, module = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ARM64,
                )
                _, text = add_text_section(module, address=0x1000)
                entry = add_code_block(
                    text, bytes.fromhex("1f2003d5") * nop_count,
                )
                code = add_code_block(
                    text, bytes.fromhex("00000058 a80b80d2 010000d4"),
                )  # ldr x0,literal; mov x8,#93; svc #0
                module.entry_point = entry
                gtirb.Symbol("_start", payload=entry, module=module)
                _, data = add_data_section(module, address=0x2000)
                value = add_data_block(data, (37).to_bytes(8, "little"))
                target = gtirb.Symbol("answer", payload=value, module=module)
                text.symbolic_expressions[code.offset] = gtirb.SymAddrConst(0, target)
                assembly = run_asm_pprinter(ir)
                self.assertIn("ldr x0,answer", assembly)
                root = Path(directory)
                self._assemble(assembly, prefix, root)
                subprocess.run([prefix + "ld", "-e", "_start", str(root / "code.o"),
                                "-o", str(root / "run")], check=True, capture_output=True)
                result = subprocess.run(["qemu-aarch64", str(root / "run")],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 37, result.stderr)
