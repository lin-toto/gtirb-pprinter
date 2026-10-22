import gtirb
from gtirb_helpers import (
    create_test_module,
    add_code_block,
    add_data_block,
    add_data_section,
    add_text_section,
    add_section,
    add_function,
    add_elf_symbol_info,
    add_symbol,
)
from pprinter_helpers import run_asm_pprinter, PPrinterTest, asm_lines


class PrintingPolicyTests(PPrinterTest):
    def test_skipped_eh_frame_begin_anchor(self):
        """References to GCC's skipped unwind anchor remain relocatable."""
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC"],
        )
        _, eh_interval = add_section(m, ".eh_frame", address=0x5000)
        eh_block = add_data_block(eh_interval, b"\x00" * 8)
        anchor = add_symbol(m, "__EH_FRAME_BEGIN__", eh_block)
        add_elf_symbol_info(
            m, anchor, 0, "OBJECT", binding="LOCAL", visibility="DEFAULT"
        )

        _, data_interval = add_data_section(m, address=0x6000)
        add_data_block(
            data_interval,
            b"\x00" * 8,
            {0: gtirb.SymAddrConst(0, anchor)},
        )

        for syntax in ("att", "intel"):
            with self.subTest(syntax=syntax):
                asm = run_asm_pprinter(
                    ir, ["--syntax", syntax, "--policy", "static"]
                )
                lines = asm_lines(asm)
                self.assertContains(
                    lines,
                    [
                        '.pushsection .eh_frame,"a",@progbits',
                        ".subsection 0",
                        ".type __EH_FRAME_BEGIN__, @object",
                        "__EH_FRAME_BEGIN__:",
                        ".popsection",
                    ],
                )
                self.assertIn(".quad __EH_FRAME_BEGIN__", lines)
                self.assertContains(
                    lines,
                    [
                        '.pushsection .eh_frame,"a",@progbits',
                        ".subsection 1",
                        ".long 0",
                        ".popsection",
                    ],
                )

    def test_keep_function(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        add_function(m, "_start", add_code_block(bi, b"\xC3"))

        asm = run_asm_pprinter(
            ir, ["--syntax", "intel", "--policy", "dynamic"]
        )
        self.assertNotContains(
            asm_lines(asm), ["_start:", "ret", ".size _start, . - _start"]
        )
        asm = run_asm_pprinter(
            ir, ["--keep-function", "_start", "--syntax", "intel"]
        )
        self.assertContains(
            asm_lines(asm), ["_start:", "ret", ".size _start, . - _start"]
        )

    def test_skip_interp(self):
        """
        Check that the dynamic and complete policies skip .interp: the linker
        writes its own, so printing the original stores the path twice.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_section(m, ".interp")
        add_data_block(bi, b"/lib64/ld-linux-x86-64.so.2\x00")
        _, bi = add_text_section(m)
        add_function(m, "main", add_code_block(bi, b"\xC3"))

        for policy in ("dynamic", "complete"):
            asm = run_asm_pprinter(ir, ["--policy", policy])
            self.assertNotIn(".interp", asm)
        asm = run_asm_pprinter(
            ir, ["--policy", "complete", "--keep-section", ".interp"]
        )
        self.assertIn(".interp", asm)

    def test_skip_function_alias(self):
        """
        Check that skip function works with
        function aliases too.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        code = add_code_block(bi, b"\xC3")
        add_function(m, "foo", code)

        alias_sym = add_symbol(m, "foo_alias", code)
        add_elf_symbol_info(m, alias_sym, 0, "FUNC")

        function_lines = [
            "retq",
            ".size foo, . - foo",
            ".size foo_alias, . - foo_alias",
        ]
        asm = run_asm_pprinter(ir)
        self.assertContains(asm_lines(asm), function_lines)
        asm = run_asm_pprinter(ir, ["--skip-function", "foo_alias"])
        self.assertNotContains(asm_lines(asm), function_lines)
