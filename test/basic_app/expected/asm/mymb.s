.include "macro.inc"

/* assembler directives */
.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */
.set gp=64     /* allow use of 64-bit general purpose registers */

.section .text, "ax"

glabel func_0040028C
/* 28C 0040028C 27BDFFF8 */  addiu      $sp, $sp, -0x8
/* 290 00400290 AFBE0004 */  sw         $fp, 0x4($sp)
/* 294 00400294 03A0F025 */  or         $fp, $sp, $zero
/* 298 00400298 0000000F */  sync
/* 29C 0040029C 00000000 */  nop
/* 2A0 004002A0 03C0E825 */  or         $sp, $fp, $zero
/* 2A4 004002A4 8FBE0004 */  lw         $fp, 0x4($sp)
/* 2A8 004002A8 27BD0008 */  addiu      $sp, $sp, 0x8
/* 2AC 004002AC 03E00008 */  jr         $ra
/* 2B0 004002B0 00000000 */   nop
