.include "macro.inc"

.section .rodata

glabel D_80000510
/* 1110 80000510 00010203 */ .word 0x00010203
/* 1114 80000514 04050607 */ .word 0x04050607
.size D_80000510, . - D_80000510
