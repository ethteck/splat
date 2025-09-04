.include "macro.inc"

.section .bss, "wa"

nonmatching D_80000540, 0x80

dlabel D_80000540
    /* 80000540 */ .space 0x80
