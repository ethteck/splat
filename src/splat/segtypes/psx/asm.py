from ...util import options

from ..common.asm import CommonSegAsm


class PsxSegAsm(CommonSegAsm):
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

        ret.append(self.get_section_asm_line())
        ret.append("")

        return ret
