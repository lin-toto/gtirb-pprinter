import gtirb

from gtirb_helpers import (
    add_code_block,
    add_symbol,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class ATTInstructionsTest(PPrinterTest):
    def _assert_att_insn(self, insn_bytes, insn_str):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        s, bi = add_text_section(m)
        add_code_block(bi, insn_bytes)
        asm = run_asm_pprinter(ir, ["--syntax=att"])
        self.assertIn(insn_str, asm)

    def test_avx512_att(self):
        """
        This test ensures that we print avx512 instructions correctly.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        instructions = [
            (b"\x62\xF1\xE5\xC9\xD4\xCA", "vpaddq %zmm2,%zmm3,%zmm1{%k1}{z}"),
            (b"\x62\xF3\x7D\x20\x1F\x07\x00", "vpcmpeqd (%rdi),%ymm16,%k0"),
            (b"\x62\xB2\x75\x20\x26\xC9", "vptestmb %ymm17,%ymm17,%k1"),
            (
                b"\x62\xB3\x2D\x21\x3F\xC0\x00",
                "vpcmpeqb %ymm16,%ymm26,%k0{%k1}",
            ),
            (b"\x62\xF3\x45\x28\x1F\xC2\x01", "vpcmpltd %ymm2,%ymm7,%k0"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x02", "vpcmpled %ymm2,%ymm7,%k0"),
            (b"\x62\xF1\x45\x28\x76\xC2", "vpcmpeqd %ymm2,%ymm7,%k0"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x04", "vpcmpneqd %ymm2,%ymm7,%k0"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x05", "vpcmpnltd %ymm2,%ymm7,%k0"),
            (b"\x62\xf3\x6d\x28\x1f\xc7\x06", "vpcmpnled %ymm7,%ymm2,%k0"),
        ]

        for insn_bytes, insn_str in instructions:
            self._assert_att_insn(insn_bytes, insn_str)

    def test_shift_att(self):
        """
        Prevent regression on the following:

        https://git.grammatech.com/rewriting/ddisasm/-/issues/415
        https://git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/466#note_180416
        """

        # capstone drops %cl operand from shl instructions
        instructions = [
            (b"\xD3\x65\xF8", "shll %cl,-8(%rbp)"),
            (b"\x48\xD3\x24\x24", "shlq %cl,(%rsp)"),
            (b"\x48\xD3\x6D\xB8", "shrq %cl,-72(%rbp)"),
            (b"\x48\xD3\xBD\x78\xFF\xFF\xFF", "sarq %cl,-136(%rbp)"),
        ]

        for insn_bytes, insn_str in instructions:
            self._assert_att_insn(insn_bytes, insn_str)

    def test_rotate_att(self):
        """Variable-count rotates must retain Capstone's implicit %cl."""
        instructions = [
            (b"\xD3\x45\xEC", "roll %cl,-20(%rbp)"),
            (b"\xD3\x4D\xEC", "rorl %cl,-20(%rbp)"),
            (b"\xD3\x55\xEC", "rcll %cl,-20(%rbp)"),
            (b"\xD3\x5D\xEC", "rcrl %cl,-20(%rbp)"),
        ]

        for insn_bytes, insn_str in instructions:
            self._assert_att_insn(insn_bytes, insn_str)

    def test_xabort_att(self):
        """
        Ensure xabort's 1-byte immediate operand is printed as unsigned int
        rather than a signed integer for newer assembler compatibility.
        """
        self._assert_att_insn(b"\xC6\xF8\xFF", "xabort $255")

    def test_fsgsbase_att(self):
        """GNU as rejects the nonstandard rdfsbaseq/rdgsbaseq spellings."""
        self._assert_att_insn(b"\xF3\x48\x0F\xAE\xC0", "rdfsbase %rax")
        self._assert_att_insn(b"\xF3\x48\x0F\xAE\xC8", "rdgsbase %rax")

    def test_fixed_width_interrupts_att(self):
        """The one-byte INT1/INT3 opcodes must keep their native encodings."""
        self._assert_att_insn(b"\xF1", ".byte 0xf1")
        self._assert_att_insn(b"\xCC", ".byte 0xcc")

    def test_sha1msg2_is_not_arm64_nop_att(self):
        """Architecture-local Capstone IDs must not collide across ISAs."""
        self._assert_att_insn(
            b"\x0F\x38\xCA\xDE", "sha1msg2 %xmm6,%xmm3"
        )

    def test_bnd_branch_without_symbol_att(self):
        """An unsymbolized MPX branch retains every original byte."""
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        _, bi = add_text_section(m)
        add_code_block(bi, b"\xF2\x73\x00\xC3")
        asm = run_asm_pprinter(ir, ["--syntax=att"])
        self.assertIn(".byte 0xf2", asm)
        self.assertIn(".byte 0x73", asm)
        self.assertNotIn("bnd jae", asm)

    def test_bnd_branch_with_symbol_att(self):
        """A symbolic MPX branch keeps a relocatable underlying Jcc."""
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        _, bi = add_text_section(m)
        branch = add_code_block(bi, b"\xF2\x73\x00")
        target = add_code_block(bi, b"\xC3")
        target_symbol = add_symbol(m, "target", target)
        bi.symbolic_expressions[branch.offset + 2] = gtirb.SymAddrConst(
            0, target_symbol
        )
        asm = run_asm_pprinter(ir, ["--syntax=att"])
        self.assertIn(".byte 0xf2", asm)
        self.assertIn("jae target", asm)
        self.assertNotIn("bnd jae", asm)

    def test_symbolic_loop_uses_near_jump_trampoline_att(self):
        """A rel8-only LOOP remains relocatable after section growth."""
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        _, bi = add_text_section(m, address=0x1000)
        branch = add_code_block(bi, b"\xE2\x00")
        target = add_code_block(bi, b"\xC3")
        target_symbol = add_symbol(m, "loop_target", target)
        bi.symbolic_expressions[branch.offset + 1] = gtirb.SymAddrConst(
            0, target_symbol
        )

        asm = run_asm_pprinter(ir, ["--syntax=att"])

        self.assertIn("loop .Lgtirb_x86_loop_taken_1000", asm)
        self.assertIn("jmp .Lgtirb_x86_loop_done_1000", asm)
        self.assertIn("jmp loop_target", asm)
