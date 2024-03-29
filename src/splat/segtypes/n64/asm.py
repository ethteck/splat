from ...util import options

from ..common.asm import CommonSegAsm


class N64SegAsm(CommonSegAsm):
    def get_file_header(self):
        ret = []

        ret.append('.include "macro.inc"')
        ret.append("")
        ret.append("/* assembler directives */")
        ret.append(".set noat      /* allow manual use of $at */")
        ret.append(".set noreorder /* don't insert nops after branches */")
        if options.opts.add_set_gp_64:
            ret.append(
                ".set gp=64     /* allow use of 64-bit general purpose registers */"
            )
        ret.append("")
        preamble = options.opts.generated_s_preamble
        if preamble:
            ret.append(preamble)
            ret.append("")

        ret.append(self.get_section_asm_line())
        ret.append("")

        return ret
