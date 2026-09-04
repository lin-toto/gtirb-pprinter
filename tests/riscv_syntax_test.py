import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import PPrinterTest, run_asm_pprinter


class RiscvInstructionsTest(PPrinterTest):
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
        call = add_code_block(interval, b"\xe7\x80\x00\x00")
        target = add_code_block(interval, b"\x13\x00\x00\x00")
        anchor = gtirb.Symbol("pcrel_anchor", payload=target, module=module)
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
        jump = add_code_block(interval, b"\x67\x80\x02\x00")
        target = add_code_block(interval, b"\x13\x00\x00\x00")
        anchor = gtirb.Symbol("jump_anchor", payload=target, module=module)
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

    def test_pcrel_low_anchor_follows_auipc_across_nop_insertions(self):
        """A stale function-entry anchor is emitted on its paired AUIPC."""
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
