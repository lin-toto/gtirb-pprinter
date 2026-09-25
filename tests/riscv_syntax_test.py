from pathlib import Path
import re
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


class RiscvInstructionsTest(PPrinterTest):
    def _run_static_assembly(self, asm, bits):
        tools = ("riscv64-linux-gnu-as", "riscv64-linux-gnu-ld",
                 f"qemu-riscv{bits}")
        if not all(shutil.which(tool) for tool in tools):
            self.skipTest("requires RISC-V binutils and QEMU")
        with tempfile.TemporaryDirectory() as directory:
            obj = str(Path(directory) / "test.o")
            binary = str(Path(directory) / "test")
            abi = "ilp32d" if bits == 32 else "lp64d"
            assembled = subprocess.run(
                [tools[0], f"-march=rv{bits}gc", f"-mabi={abi}", "-o", obj],
                input=asm, text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(assembled.returncode, 0, assembled.stderr)
            linked = subprocess.run(
                [tools[1], f"-melf{bits}lriscv", "--no-relax", "-e", "_start",
                 obj, "-o", binary],
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(linked.returncode, 0, linked.stderr)
            result = subprocess.run(
                [tools[2], binary],
                text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(result.stdout + result.stderr, "")
            return result.returncode

    def test_local_jump_preserves_t1(self):
        """Naming an intraprocedural target must not create a call clobber."""
        for bits in (32, 64):
            for name in (".Llocal_target", "named_target"):
                for nop_count in (0, 1, 9, 64):
                    with self.subTest(bits=bits, name=name, nops=nop_count):
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF,
                            isa=gtirb.Module.ISA.ValidButUnsupported,
                        )
                        module.aux_data["archInfo"] = gtirb.AuxData(
                            type_name="mapping<string,string>",
                            data={"ISA": f"RISCV{bits}"},
                        )
                        _, interval = add_text_section(module, address=0x1000)
                        # li t1,37; j target
                        entry = add_code_block(
                            interval, bytes.fromhex("13035002 6f000000")
                        )
                        gtirb.Symbol("_start", payload=entry, module=module)
                        module.entry_point = entry
                        if nop_count:
                            add_code_block(
                                interval, bytes.fromhex("13000000") * nop_count
                            )
                        # Exit with t1 to observe an unexpected tail clobber.
                        target = add_code_block(
                            interval,
                            bytes.fromhex("13050300 9308d005 73000000"),
                        )
                        symbol = gtirb.Symbol(
                            name, payload=target, module=module
                        )
                        interval.symbolic_expressions[entry.offset + 4] = (
                            gtirb.SymAddrConst(0, symbol)
                        )
                        asm = ".option norvc\n" + run_asm_pprinter(ir)
                        self.assertEqual(
                            self._run_static_assembly(asm, bits), 37
                        )

    def test_call_addend_after_nop_insertion(self):
        """A moved target plus an addend still calls the intended entry."""
        for bits in (32, 64):
            for nop_count in (0, 1, 9, 64):
                for addend, expected in ((8, 7), (-8, 1)):
                    with self.subTest(
                        bits=bits, nops=nop_count, addend=addend
                    ):
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF,
                            isa=gtirb.Module.ISA.ValidButUnsupported,
                        )
                        module.aux_data["archInfo"] = gtirb.AuxData(
                            type_name="mapping<string,string>",
                            data={"ISA": f"RISCV{bits}"},
                        )
                        _, interval = add_text_section(module, address=0x1000)
                        # Call, then exit with the callee's return value.
                        entry = add_code_block(
                            interval,
                            bytes.fromhex("ef000000 9308d005 73000000"),
                        )
                        module.entry_point = entry
                        gtirb.Symbol("_start", payload=entry, module=module)
                        if nop_count:
                            add_code_block(
                                interval, bytes.fromhex("13000000") * nop_count
                            )
                        first = add_code_block(
                            interval, bytes.fromhex("13051000 67800000")
                        )
                        second = add_code_block(
                            interval, bytes.fromhex("13057000 67800000")
                        )
                        symbol = gtirb.Symbol(
                            "target", payload=first if addend > 0 else second,
                            module=module,
                        )
                        interval.symbolic_expressions[entry.offset] = (
                            gtirb.SymAddrConst(addend, symbol)
                        )
                        # Keep the eight-byte entry spacing used by the addend.
                        asm = ".option norvc\n" + run_asm_pprinter(ir)
                        self.assertEqual(
                            self._run_static_assembly(asm, bits), expected
                        )

    def test_direct_transfer_addends(self):
        """Call expansion and PLT forwarding retain the expression addend."""
        cases = (
            ("ef000000", "call", "local"),
            ("6f000000", "j", "local"),
            ("01a0", "c.j", "local"),
            ("6300b500", "beq", "local"),
            ("ef000000", "call", "proxy"),
            ("6f000000", "tail", "proxy"),
            ("ef000000", "call", "plt"),
            ("97000000 e7800000", "call", "plt_attribute"),
        )
        for isa in ("RISCV32", "RISCV64"):
            for encoded, opcode, kind in cases:
                for addend in (-4, 0, 4):
                    with self.subTest(
                        isa=isa, code=encoded, kind=kind, addend=addend
                    ):
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF,
                            isa=gtirb.Module.ISA.ValidButUnsupported,
                        )
                        module.aux_data["archInfo"] = gtirb.AuxData(
                            type_name="mapping<string,string>",
                            data={"ISA": isa},
                        )
                        _, interval = add_text_section(module, address=0x1000)
                        branch = add_code_block(
                            interval, bytes.fromhex(encoded)
                        )
                        target = add_code_block(
                            interval, bytes.fromhex("13000000") * 3
                        )
                        symbol = gtirb.Symbol(
                            "target", payload=target, module=module
                        )
                        attributes = set()
                        if kind in ("proxy", "plt", "plt_attribute"):
                            proxy = gtirb.ProxyBlock(module=module)
                            external = gtirb.Symbol(
                                "external", payload=proxy, module=module
                            )
                            symbol = external
                            if kind == "plt":
                                _, plt = add_section(
                                    module, ".plt", address=0x2000
                                )
                                entry = add_code_block(
                                    plt, bytes.fromhex("13000000") * 4
                                )
                                symbol = gtirb.Symbol(
                                    "plt_entry", payload=entry, module=module
                                )
                                module.aux_data["symbolForwarding"].data[
                                    symbol
                                ] = external
                            if kind == "plt_attribute":
                                attributes.add(
                                    gtirb.SymbolicExpression.Attribute.PLT
                                )
                        interval.symbolic_expressions[branch.offset] = (
                            gtirb.SymAddrConst(
                                addend, symbol, attributes=attributes
                            )
                        )

                        asm = run_asm_pprinter(ir)

                        name = "target" if kind == "local" else "external"
                        offset = f"{addend:+d}" if addend else ""
                        suffix = "" if kind == "local" else "@plt"
                        registers = "a0,a1," if opcode == "beq" else ""
                        self.assertRegex(
                            asm, rf"(?m)^\s*{re.escape(opcode)}\s+"
                            + re.escape(registers)
                            + re.escape(name + offset + suffix) + r"\s*$"
                        )
                        if shutil.which("riscv64-linux-gnu-as"):
                            with tempfile.TemporaryDirectory() as directory:
                                bits = isa[-2:]
                                abi = "ilp32d" if bits == "32" else "lp64d"
                                result = subprocess.run(
                                    [
                                        "riscv64-linux-gnu-as",
                                        f"-march=rv{bits}gc", f"-mabi={abi}",
                                        "-o", str(Path(directory) / "test.o"),
                                    ],
                                    input=asm, text=True, capture_output=True,
                                    timeout=30,
                                )
                                self.assertEqual(
                                    result.returncode, 0, result.stderr
                                )

    def test_floating_rounding_modes_are_preserved(self):
        """Floating conversion instructions retain their encoded FRM."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module, address=0x1000)

        # fcvt.lu.d a5,fa5 with each valid rm field.  Capstone includes the
        # trailing token in op_str but not in its detailed operand array.
        add_code_block(
            interval,
            bytes.fromhex(
                "d38737c2 "  # rne
                "d39737c2 "  # rtz
                "d3a737c2 "  # rdn
                "d3b737c2 "  # rup
                "d3c737c2 "  # rmm
                "d3f737c2"  # dyn
            ),
        )

        asm = run_asm_pprinter(ir)

        for mode in ("rne", "rtz", "rdn", "rup", "rmm"):
            self.assertIn(f"fcvt.lu.d a5,fa5,{mode}", asm)
        # DYN is the assembler default, and Capstone intentionally omits it.
        self.assertRegex(asm, r"(?m)^\s*fcvt\.lu\.d a5,fa5\s*$")

    def test_unsymbolized_direct_branch_uses_defined_local_label(self):
        """A resolved branch to an instruction remains safe under relayout."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module, address=0x1000)

        # jal zero,+8 followed by two four-byte nops.  There is deliberately
        # no symbolic expression: the displacement is already resolved.
        add_code_block(
            interval,
            bytes.fromhex("6f008000 13000000 13000000"),
        )

        asm = run_asm_pprinter(ir)

        self.assertIn("j .Lgtirb_riscv_1008", asm)
        self.assertIn(".Lgtirb_riscv_1008:", asm)

    def test_unsymbolized_branch_to_interior_byte_has_no_undefined_label(self):
        """A non-instruction target stays numeric instead of becoming undefined."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module, address=0x1000)

        # jal zero,+6 targets the middle of the following four-byte nop.
        add_code_block(interval, bytes.fromhex("6f006000 13000000"))

        asm = run_asm_pprinter(ir)

        self.assertNotIn(".Lgtirb_riscv_1006", asm)
        self.assertRegex(asm, r"j\s+\.\+6")

    def test_symbolic_zero_low_jalr_uses_expanded_spelling(self):
        """A zero PCREL_LO immediate must survive Capstone's jalr alias."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            # The GTIRB C++ library used by this pprinter release predates
            # the dedicated RISC-V enum values.  Ddisasm therefore records
            # RISC-V through ValidButUnsupported plus archInfo.
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module)

        # jalr ra,ra,0. Capstone contracts this to the one-operand
        # spelling `jalr ra`, which otherwise has nowhere to print the low
        # relocation operand.
        target = add_code_block(interval, bytes.fromhex("97000000"))
        call = add_code_block(interval, b"\xe7\x80\x00\x00")
        anchor = gtirb.Symbol("pcrel_anchor", payload=target, module=module)
        callee = gtirb.Symbol("callee", payload=gtirb.ProxyBlock(module=module), module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        interval.symbolic_expressions[target.offset] = gtirb.SymAddrConst(
            0, callee, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[call.offset] = (
            gtirb.symbolicexpression.SymAddrConst(
                0,
                anchor,
                attributes=[
                    gtirb.symbolicexpression.SymbolicExpression.Attribute.PCREL,
                    gtirb.symbolicexpression.SymbolicExpression.Attribute.LO,
                ],
            )
        )

        asm = run_asm_pprinter(ir)

        self.assertIn("jalr ra,ra,%pcrel_lo(pcrel_anchor)", asm)

    def test_symbolic_zero_low_jr_preserves_zero_destination(self):
        """Expanding a symbolic jr must not turn its tail jump into a call."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module)

        # jalr zero,t0,0. Capstone contracts this to `jr t0`.
        target = add_code_block(interval, bytes.fromhex("97020000"))
        jump = add_code_block(interval, b"\x67\x80\x02\x00")
        anchor = gtirb.Symbol("jump_anchor", payload=target, module=module)
        destination = gtirb.Symbol("destination", payload=gtirb.ProxyBlock(module=module), module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        interval.symbolic_expressions[target.offset] = gtirb.SymAddrConst(
            0, destination, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[jump.offset] = (
            gtirb.symbolicexpression.SymAddrConst(
                0,
                anchor,
                attributes=[
                    gtirb.symbolicexpression.SymbolicExpression.Attribute.PCREL,
                    gtirb.symbolicexpression.SymbolicExpression.Attribute.LO,
                ],
            )
        )

        asm = run_asm_pprinter(ir)

        self.assertIn("jalr zero,t0,%pcrel_lo(jump_anchor)", asm)
        self.assertNotIn("jalr ra,t0,%pcrel_lo(jump_anchor)", asm)

    def test_symbolic_compressed_indirect_transfers_expand(self):
        """C.JR/C.JALR acquire a low relocation without changing link semantics."""
        for encoding, destination in (("0293", "ra"), ("0283", "zero")):
            with self.subTest(destination=destination):
                ir, module = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ValidButUnsupported,
                )
                module.aux_data["archInfo"] = gtirb.AuxData(
                    type_name="mapping<string,string>", data={"ISA": "RISCV64"})
                _, interval = add_text_section(module)
                high = add_code_block(interval, bytes.fromhex("17030000"))  # AUIPC t1
                low = add_code_block(interval, bytes.fromhex(encoding))
                anchor = gtirb.Symbol("transfer_anchor", payload=high, module=module)
                target = gtirb.Symbol("target", payload=gtirb.ProxyBlock(module=module), module=module)
                attrs = gtirb.SymbolicExpression.Attribute
                interval.symbolic_expressions[high.offset] = gtirb.SymAddrConst(
                    0, target, {attrs.PCREL, attrs.HI})
                interval.symbolic_expressions[low.offset] = gtirb.SymAddrConst(
                    0, anchor, {attrs.PCREL, attrs.LO})
                assembly = run_asm_pprinter(ir)
                self.assertIn("jalr %s,t1,%%pcrel_lo(transfer_anchor)" % destination, assembly)
                self.assertNotRegex(assembly, r"c\.j(?:al)?r\s")

    def test_same_section_conditional_branches_stay_native(self):
        """Symbolic short branches must not gain a printer-inserted jump."""
        cases = (
            ("6300b500", "beq"), ("6310b500", "bne"),
            ("6340b500", "blt"), ("6350b500", "bge"),
            ("6360b500", "bltu"), ("6370b500", "bgeu"),
            ("01c0", "c.beqz"), ("01e0", "c.bnez"),
        )
        for bits in (32, 64):
            for encoded, opcode in cases:
                for cross_section in (False, True):
                    with self.subTest(bits=bits, opcode=opcode,
                                      cross_section=cross_section):
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF,
                            isa=gtirb.Module.ISA.ValidButUnsupported,
                        )
                        module.aux_data["archInfo"] = gtirb.AuxData(
                            type_name="mapping<string,string>",
                            data={"ISA": f"RISCV{bits}"},
                        )
                        section, interval = add_text_section(module, address=0x1000)
                        branch = add_code_block(interval, bytes.fromhex(encoded))
                        if cross_section:
                            _, target_interval = add_section(
                                module, ".other", address=0x2000,
                                flags=section.flags,
                            )
                        else:
                            target_interval = interval
                        target = add_code_block(
                            target_interval, bytes.fromhex("13000000")
                        )
                        symbol = gtirb.Symbol("target", payload=target,
                                              module=module)
                        interval.symbolic_expressions[branch.offset] = (
                            gtirb.SymAddrConst(0, symbol)
                        )
                        asm = run_asm_pprinter(ir)
                        if cross_section:
                            self.assertIn(".Lgtirb_riscv_long_branch_", asm)
                            self.assertRegex(asm, r"(?m)^\s*j\s+target\s*$")
                        else:
                            self.assertNotIn(".Lgtirb_riscv_long_branch_", asm)
                            self.assertRegex(
                                asm, rf"(?m)^\s*{re.escape(opcode)}\s+"
                                r"[^\n]*,target\s*$",
                            )

    def test_same_section_conditional_assembler_relaxation(self):
        """GAS, not stale IR distance estimates, handles local branch growth."""
        cases = (("6300b500", True), ("6310b500", False),
                 ("01c0", True), ("01e0", False))
        for bits in (32, 64):
            for encoded, branch_if_equal in cases:
                for padding in (4, 75, 4096):
                    for backward in (False, True):
                        for equal in (False, True):
                            with self.subTest(bits=bits, code=encoded,
                                              padding=padding, backward=backward,
                                              equal=equal):
                                ir, module = create_test_module(
                                    file_format=gtirb.Module.FileFormat.ELF,
                                    isa=gtirb.Module.ISA.ValidButUnsupported,
                                )
                                module.aux_data["archInfo"] = gtirb.AuxData(
                                    type_name="mapping<string,string>",
                                    data={"ISA": f"RISCV{bits}"},
                                )
                                _, interval = add_text_section(module, address=0x1000)
                                init = bytes.fromhex(
                                    "13050000 93050000 13040000" if equal else
                                    "13050000 93051000 13041000"
                                )
                                entry = add_code_block(interval, init)
                                gtirb.Symbol("_start", payload=entry, module=module)
                                module.entry_point = entry
                                exit3 = bytes.fromhex("13053000 9308d005 73000000")
                                exit7 = bytes.fromhex("13057000 9308d005 73000000")
                                if backward:
                                    jump = add_code_block(
                                        interval, bytes.fromhex("6f000000")
                                    )
                                    target = add_code_block(interval, exit7)
                                    add_code_block(interval, bytes.fromhex("13000000") * padding)
                                    branch = add_code_block(interval, bytes.fromhex(encoded))
                                    add_code_block(interval, exit3)
                                    symbol = gtirb.Symbol("branch", payload=branch,
                                                          module=module)
                                    interval.symbolic_expressions[jump.offset] = (
                                        gtirb.SymAddrConst(0, symbol)
                                    )
                                else:
                                    branch = add_code_block(interval, bytes.fromhex(encoded))
                                    add_code_block(interval, exit3)
                                    add_code_block(interval, bytes.fromhex("13000000") * padding)
                                    target = add_code_block(interval, exit7)
                                symbol = gtirb.Symbol("target", payload=target,
                                                      module=module)
                                interval.symbolic_expressions[branch.offset] = (
                                    gtirb.SymAddrConst(0, symbol)
                                )
                                asm = ".option norelax\n" + run_asm_pprinter(ir)
                                self.assertNotIn(".Lgtirb_riscv_long_branch_", asm)
                                self.assertEqual(
                                    self._run_static_assembly(asm, bits),
                                    7 if equal == branch_if_equal else 3,
                                )

    def test_interior_symbol_stays_at_instruction_after_branch_expansion(self):
        """A relocated interior target must not use a stale byte delta."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module, address=0x1000)

        # This is a real RV64 block shape: the interior target is the second
        # lw (offset 12), while a later conditional branch expands into an
        # inverted branch plus a long jump.  Defining the target afterwards
        # as `. - original_delta` would therefore move it by the expansion.
        code = add_code_block(
            interval,
            bytes.fromhex(
                "832784f2 93e70702 2324f4f2 832784f2 "
                "93e70704 2324f4f2 8327c4f2 1b870700 "
                "9547 6301f712"
            ),
        )
        marker = gtirb.CodeBlock(
            offset=code.offset + 12,
            size=0,
            byte_interval=interval,
        )
        gtirb.Symbol("interior_target", payload=marker, module=module)

        asm = run_asm_pprinter(ir)

        self.assertIn(".Lgtirb_riscv_long_branch_1022", asm)
        self.assertIn("interior_target:", asm)
        self.assertNotIn(".set interior_target", asm)
        self.assertLess(
            asm.index("interior_target:"),
            asm.index("lw a5,-216(s0)", asm.index("interior_target:")),
        )

    def test_zero_sized_symbol_at_block_start_is_printed_once(self):
        """A marker sharing the first instruction address is not duplicated."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module, address=0x1000)

        code = add_code_block(interval, b"\x13\x00\x00\x00")
        marker = gtirb.CodeBlock(
            offset=code.offset,
            size=0,
            byte_interval=interval,
        )
        gtirb.Symbol("section_start_marker", payload=marker, module=module)

        asm = run_asm_pprinter(ir)

        self.assertEqual(asm.count("section_start_marker:"), 1)

    def test_valid_pcrel_anchor_is_not_replaced_by_bypassed_auipc(self):
        """A lexical AUIPC predecessor need not execute before the low part."""
        attrs = gtirb.SymbolicExpression.Attribute
        for bits in (32, 64):
            for split_interval in (False, True):
                for integral in (False, True):
                    for got in (False, True):
                        with self.subTest(
                            bits=bits, split_interval=split_interval,
                            integral=integral, got=got,
                        ):
                            ir, module = create_test_module(
                                file_format=gtirb.Module.FileFormat.ELF,
                                isa=gtirb.Module.ISA.ValidButUnsupported,
                            )
                            module.aux_data["archInfo"] = gtirb.AuxData(
                                {"ISA": f"RISCV{bits}"}, "mapping<string,string>"
                            )
                            section, interval = add_text_section(
                                module, address=0x1000
                            )
                            # auipc t0,hi; j low. The second AUIPC is bypassed.
                            entry = add_code_block(
                                interval, bytes.fromhex("97020000 6f000000")
                            )
                            gtirb.Symbol("_start", payload=entry, module=module)
                            module.entry_point = entry
                            anchor = gtirb.Symbol(
                                "original_anchor",
                                payload=0x1000 if integral else entry,
                                module=module,
                            )
                            following = (
                                gtirb.ByteInterval(
                                    address=0x1100, contents=b"", section=section
                                ) if split_interval else interval
                            )
                            decoy = add_code_block(
                                following, bytes.fromhex("97020000")
                            )
                            gtirb.Symbol(
                                "bypassed_anchor", payload=decoy, module=module
                            )
                            # addi t0,t0,lo or load t0 from its GOT slot.
                            low_word = (
                                "83b20200" if bits == 64 else "83a20200"
                            ) if got else "93820200"
                            low = add_code_block(
                                following, bytes.fromhex(
                                    low_word + " 03c50200 9308d005 73000000"
                                )
                            )
                            low_symbol = gtirb.Symbol(
                                "low", payload=low, module=module
                            )
                            _, data = add_section(
                                module, ".rodata", address=0x3000
                            )
                            first = add_data_block(data, b"\x25" + b"\xcc" * 63)
                            second = add_data_block(data, b"\x63" + b"\xcc" * 63)
                            target = gtirb.Symbol(
                                "target", payload=first, module=module
                            )
                            other = gtirb.Symbol(
                                "other", payload=second, module=module
                            )
                            high_attrs = {attrs.GOT} if got else {
                                attrs.PCREL, attrs.HI
                            }
                            interval.symbolic_expressions[entry.offset] = (
                                gtirb.SymAddrConst(0, target, high_attrs)
                            )
                            interval.symbolic_expressions[entry.offset + 4] = (
                                gtirb.SymAddrConst(0, low_symbol)
                            )
                            following.symbolic_expressions[decoy.offset] = (
                                gtirb.SymAddrConst(
                                    0, other, {attrs.PCREL, attrs.HI}
                                )
                            )
                            following.symbolic_expressions[low.offset] = (
                                gtirb.SymAddrConst(
                                    0, anchor, {attrs.PCREL, attrs.LO}
                                )
                            )
                            asm = run_asm_pprinter(ir)
                            for nops in (0, 9):
                                with self.subTest(nops=nops):
                                    moved = asm.replace(
                                        "bypassed_anchor:",
                                        f".rept {nops}\n nop\n.endr\n"
                                        "bypassed_anchor:",
                                    )
                                    self.assertNotEqual(moved, asm)
                                    self.assertEqual(
                                        self._run_static_assembly(moved, bits), 37
                                    )

    def test_pcrel_marker_at_aligned_block_start(self):
        """Alignment must precede both the AUIPC and its zero-sized anchor."""
        attrs = gtirb.SymbolicExpression.Attribute
        for bits in (32, 64):
            for alignment in (4, 16, 64):
                with self.subTest(bits=bits, alignment=alignment):
                    ir, module = create_test_module(
                        file_format=gtirb.Module.FileFormat.ELF,
                        isa=gtirb.Module.ISA.ValidButUnsupported,
                    )
                    module.aux_data["archInfo"] = gtirb.AuxData(
                        {"ISA": f"RISCV{bits}"}, "mapping<string,string>"
                    )
                    _, interval = add_text_section(module, address=0x1000)
                    # A compressed prefix makes the next block need padding.
                    add_code_block(interval, bytes.fromhex("0100"))
                    code = add_code_block(interval, bytes.fromhex(
                        "97020000 93820200 03c50200 9308d005 73000000"
                    ))
                    marker = gtirb.CodeBlock(
                        offset=code.offset, size=0, byte_interval=interval
                    )
                    anchor = gtirb.Symbol(
                        "instruction_anchor", payload=marker, module=module
                    )
                    gtirb.Symbol("_start", payload=code, module=module)
                    module.entry_point = code
                    module.aux_data["alignment"].data[code] = alignment
                    _, data = add_section(module, ".rodata", address=0x3000)
                    target = gtirb.Symbol(
                        "target", payload=add_data_block(data, b"\x25"),
                        module=module,
                    )
                    interval.symbolic_expressions[code.offset] = (
                        gtirb.SymAddrConst(0, target, {attrs.PCREL, attrs.HI})
                    )
                    interval.symbolic_expressions[code.offset + 4] = (
                        gtirb.SymAddrConst(0, anchor, {attrs.PCREL, attrs.LO})
                    )
                    asm = run_asm_pprinter(ir)
                    self.assertEqual(asm.count("instruction_anchor:"), 1)
                    self.assertNotIn(
                        ".align", asm[asm.index("instruction_anchor:"):
                                      asm.index("auipc t0,")]
                    )
                    self.assertEqual(self._run_static_assembly(asm, bits), 37)

    def test_stale_pcrel_anchor_requires_producer_repair(self):
        """Do not infer a pair from a stale entry label and nearby AUIPC."""
        for nop_count in (1, 9, 64):
            with self.subTest(nop_count=nop_count):
                ir, module = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ValidButUnsupported,
                )
                module.aux_data["archInfo"] = gtirb.AuxData(
                    type_name="mapping<string,string>",
                    data={"ISA": "RISCV64"},
                )
                _, interval = add_text_section(module, address=0x1000)

                inserted = gtirb.CodeBlock(
                    offset=0,
                    size=nop_count * 4,
                    byte_interval=interval,
                )
                pair = gtirb.CodeBlock(
                    offset=nop_count * 4,
                    size=8,
                    byte_interval=interval,
                )
                target = gtirb.CodeBlock(
                    offset=nop_count * 4 + 8,
                    size=4,
                    byte_interval=interval,
                )
                interval.contents = (
                    bytes.fromhex("13000000") * nop_count
                    + bytes.fromhex("17030000 67000300 13000000")
                )
                interval.size = len(interval.contents)

                anchor = gtirb.Symbol(
                    "pcrel_anchor",
                    payload=inserted,
                    module=module,
                )
                destination = gtirb.Symbol(
                    "register_tm_clones",
                    payload=target,
                    module=module,
                )
                hi_offset = pair.offset
                interval.symbolic_expressions[hi_offset] = (
                    gtirb.symbolicexpression.SymAddrConst(
                        0,
                        destination,
                        attributes=[
                            gtirb.symbolicexpression.SymbolicExpression.Attribute.PCREL,
                            gtirb.symbolicexpression.SymbolicExpression.Attribute.HI,
                        ],
                    )
                )
                interval.symbolic_expressions[hi_offset + 4] = (
                    gtirb.symbolicexpression.SymAddrConst(
                        0,
                        anchor,
                        attributes=[
                            gtirb.symbolicexpression.SymbolicExpression.Attribute.PCREL,
                            gtirb.symbolicexpression.SymbolicExpression.Attribute.LO,
                        ],
                    )
                )

                with self.assertRaises(subprocess.CalledProcessError) as error:
                    run_asm_pprinter(ir)
                self.assertIn(b"stale AUIPC anchor", error.exception.output)
                self.assertEqual(error.exception.returncode, 1)

                # With an exact instruction referent, emit a real label there.
                anchor.referent = pair
                asm = run_asm_pprinter(ir)
                anchor_text = "pcrel_anchor:"
                hi_text = "auipc t1,%pcrel_hi(register_tm_clones)"
                lo_text = "jalr zero,t1,%pcrel_lo(pcrel_anchor)"
                self.assertEqual(asm.count(anchor_text), 1)
                self.assertIn(hi_text, asm)
                self.assertIn(lo_text, asm)
                anchor_index = asm.index(anchor_text)
                hi_index = asm.index(hi_text)
                self.assertLess(anchor_index, hi_index)
                self.assertNotIn("nop", asm[anchor_index:hi_index])
                self.assertGreater(asm.rfind("nop", 0, anchor_index), -1)

    def test_pcrel_low_base_must_match_high_destination(self):
        # Include a store whose value is the producer's register: the base,
        # not an arbitrary register operand, must match the AUIPC destination.
        cases = (
            (5, 0x00028513, 4),  # mv a0,t0 (ADDI)
            (5, 0x0002c503, 4),  # lbu a0,0(t0)
            (5, 0x00628023, 4),  # sb t1,0(t0)
            (5, 0x000280e7, 4),  # jalr t0
            (5, 0x0285, 2),      # c.addi t0,1
            (8, 0x4008, 2),      # c.lw a0,0(s0)
            (8, 0xc004, 2),      # c.sw s1,0(s0)
        )
        for bits in (32, 64):
            for base, instruction, size in cases:
                for matching in (False, True):
                    with self.subTest(bits=bits, instruction=instruction, matching=matching):
                        ir, module = create_test_module(
                            file_format=gtirb.Module.FileFormat.ELF,
                            isa=gtirb.Module.ISA.ValidButUnsupported,
                        )
                        module.aux_data["archInfo"] = gtirb.AuxData(
                            {"ISA": f"RISCV{bits}"}, "mapping<string,string>"
                        )
                        _, interval = add_text_section(module, address=0x1000)
                        producer = base if matching else base + 1
                        block = add_code_block(interval, ((producer << 7) | 0x17).to_bytes(4, "little")
                                               + instruction.to_bytes(size, "little"))
                        anchor = gtirb.Symbol("producer", payload=block, module=module)
                        target = gtirb.Symbol("target", payload=gtirb.ProxyBlock(module=module), module=module)
                        attrs = gtirb.SymbolicExpression.Attribute
                        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target, {attrs.HI, attrs.PCREL})
                        interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, anchor, {attrs.LO, attrs.PCREL})
                        if matching:
                            self.assertIn("%pcrel_lo(producer)", run_asm_pprinter(ir))
                        else:
                            with self.assertRaises(subprocess.CalledProcessError) as error:
                                run_asm_pprinter(ir)
                            self.assertEqual(error.exception.returncode, 1)
                            self.assertIn(b"source register does not match AUIPC", error.exception.output)

    def test_mapping_symbols_are_regenerated_instead_of_disambiguated(self):
        """Repeated `$x<isa>` metadata must not become bogus ISA names."""
        ir, module = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ValidButUnsupported,
        )
        module.aux_data["archInfo"] = gtirb.AuxData(
            type_name="mapping<string,string>",
            data={"ISA": "RISCV64"},
        )
        _, interval = add_text_section(module, address=0x1000)

        first = add_code_block(interval, b"\x13\x00\x00\x00")
        second = add_code_block(interval, b"\x13\x00\x00\x00")
        normal = gtirb.Symbol("ordinary_label", payload=first, module=module)
        mapping_name = "$xrv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0"
        gtirb.Symbol(mapping_name, payload=first, module=module)
        gtirb.Symbol(mapping_name, payload=second, module=module)
        gtirb.Symbol("$x", payload=first, module=module)
        gtirb.Symbol("$d.1", payload=second, module=module)

        asm = run_asm_pprinter(ir)

        self.assertIn(f"{normal.name}:", asm)
        self.assertNotIn("$x", asm)
        self.assertNotIn("$d.1", asm)
        self.assertNotIn("_disambig_", asm)
