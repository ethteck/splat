.include "macro.inc"

/* assembler directives */
.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */
.set gp=64     /* allow use of 64-bit general purpose registers */

.section .text, "ax"

glabel func_004001DC
/* 1DC 004001DC 27BDFFF8 */  addiu      $sp, $sp, -0x8
/* 1E0 004001E0 AFBE0004 */  sw         $fp, 0x4($sp)
/* 1E4 004001E4 03A0F025 */  or         $fp, $sp, $zero
/* 1E8 004001E8 0000000F */  sync
/* 1EC 004001EC 00000000 */  nop
/* 1F0 004001F0 03C0E825 */  or         $sp, $fp, $zero
/* 1F4 004001F4 8FBE0004 */  lw         $fp, 0x4($sp)
/* 1F8 004001F8 27BD0008 */  addiu      $sp, $sp, 0x8
/* 1FC 004001FC 03E00008 */  jr         $ra
/* 200 00400200 00000000 */   nop
