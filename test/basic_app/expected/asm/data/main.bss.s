.include "macro.inc"

.section .bss, "wa"

dlabel D_80000540
nonmatching D_80000540, 0x80
    /* 80000540 */ .space 0x80
