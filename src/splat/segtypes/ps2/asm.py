from ...util import options

from ..common.asm import CommonSegAsm


class Ps2SegAsm(CommonSegAsm):
    def get_file_header(self):
        ret = []

        ret.append('.include "macro.inc"')
        ret.append("")
        ret.append(".set noat")
        ret.append(".set noreorder")
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
