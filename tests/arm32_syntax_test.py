import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm32InstructionsTest(PPrinterTest):
    def test_unpack_instructions(self):
        """
        Test printing various instructions
        """
        Arm = gtirb.CodeBlock.DecodeMode.Default
        Thumb = gtirb.CodeBlock.DecodeMode.Thumb

        instructions = [
            (Thumb, b"\x60\xf9\xef\x0a", "vld1.64 { d16, d17 }, [r0 :128]"),
            (Thumb, b"\x61\xf9\x8f\x6a", "vld1.32 { d22, d23 }, [r1]"),
            (Thumb, b"\x62\xf9\x9f\x07", "vld1.32 { d16 }, [r2 :64]"),
            (Thumb, b"\x62\xf9\x00\x0a", "vld1.8 { d16, d17 }, [r2], r0"),
            (Thumb, b"\x41\xf9\xcf\x0a", "vst1.64 { d16, d17 }, [r1]"),
            (Thumb, b"\x41\xf9\x00\x2a", "vst1.8 { d18, d19 }, [r1], r0"),
            (Thumb, b"\x00\xf9\x0d\x8a", "vst1.8 { d8, d9 }, [r0]!"),
            (Thumb, b"\xfe\xde", "udf #254"),
            (Arm, b"\x01\x00\x9f\xe7", "ldr r0, [pc, r1]"),
            (Thumb, b"\x12\xee\x10\x0b", "vmov.32 r0, d2[0]"),
        ]

        for insn_mode, insn_bytes, insn_str in instructions:
            with self.subTest(instruction=insn_str):
                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ARM,
                )
                s, bi = add_text_section(m)

                code_block = add_code_block(bi, insn_bytes)
                code_block.decode_mode = insn_mode

                asm = run_asm_pprinter(ir)
                self.assertIn(insn_str, asm)

    def test_arm_block_after_thumb_block(self):
        """
        Blocks of both decode modes in one module print in their own mode.
        Capstone 6 ORs CS_OPT_MODE into an ARM handle, so switching one handle
        from Thumb back to ARM mode left it decoding Thumb.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ARM,
        )
        s, bi = add_text_section(m)
        thumb_block = add_code_block(bi, b"\x01\x20\x02\x21")
        thumb_block.decode_mode = gtirb.CodeBlock.DecodeMode.Thumb
        arm_block = add_code_block(bi, b"\x01\x00\x9f\xe7")
        arm_block.decode_mode = gtirb.CodeBlock.DecodeMode.Default

        asm = run_asm_pprinter(ir)
        self.assertIn("movs r0, #1", asm)
        self.assertIn("movs r1, #2", asm)
        # Capstone 6 spells pc as r15 unless CS_OPT_SYNTAX_CS_REG_ALIAS is set.
        self.assertRegex(asm, r"ldr r0, \[(pc|r15), r1\]")
