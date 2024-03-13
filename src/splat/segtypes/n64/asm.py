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

        line = f".section {self.get_linker_section_linksection()}"
        section_flags = self.get_section_flags()
        if section_flags:
            line += f', "{section_flags}"'
        ret.append(line)
        ret.append("")

        return ret
