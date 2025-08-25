.include "macro.inc"

.section .data, "wa"

dlabel D_80000500
nonmatching D_80000500
    /* 1100 80000500 00000001 */ .word 0x00000001
enddlabel D_80000500

dlabel D_80000504
nonmatching D_80000504
    /* 1104 80000504 00000000 */ .word 0x00000000
    /* 1108 80000508 00000000 */ .word 0x00000000
    /* 110C 8000050C 00000000 */ .word 0x00000000
enddlabel D_80000504
