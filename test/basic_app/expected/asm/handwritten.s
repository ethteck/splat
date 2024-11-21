.include "macro.inc"

.set noat
.set noreorder
.set gp=64

.section .text, "ax"

/* Handwritten function */
glabel func_800004F0
    /* 10F0 800004F0 00851020 */  add        $v0, $a0, $a1 /* handwritten instruction */
    /* 10F4 800004F4 03E00008 */  jr         $ra
    /* 10F8 800004F8 00000000 */   nop
    /* 10FC 800004FC 00000000 */  nop
.size func_800004F0, . - func_800004F0
