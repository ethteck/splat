glabel func_004002B4
/* 2B4 004002B4 27BDFFE8 */  addiu      $sp, $sp, -0x18
/* 2B8 004002B8 AFBF0014 */  sw         $ra, 0x14($sp)
/* 2BC 004002BC AFBE0010 */  sw         $fp, 0x10($sp)
/* 2C0 004002C0 03A0F025 */  or         $fp, $sp, $zero
/* 2C4 004002C4 0C100077 */  jal        func_004001DC
/* 2C8 004002C8 00000000 */   nop
/* 2CC 004002CC 0C1000A3 */  jal        func_0040028C
/* 2D0 004002D0 00000000 */   nop
.L004002D4:
/* 2D4 004002D4 8F828008 */  lw         $v0, -0x7FF8($gp)
/* 2D8 004002D8 24420001 */  addiu      $v0, $v0, 0x1
/* 2DC 004002DC AF828008 */  sw         $v0, -0x7FF8($gp)
/* 2E0 004002E0 1000FFFC */  b          .L004002D4
/* 2E4 004002E4 00000000 */   nop
