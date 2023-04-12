glabel func_004001DC
/* 1DC 004001DC 27BDFFF8 */  addiu      $sp, $sp, -0x8
/* 1E0 004001E0 AFBE0004 */  sw         $fp, 0x4($sp)
/* 1E4 004001E4 03A0F025 */  or         $fp, $sp, $zero
.L004001E8:
/* 1E8 004001E8 8F82800C */  lw         $v0, -0x7FF4($gp)
/* 1EC 004001EC 24420001 */  addiu      $v0, $v0, 0x1
/* 1F0 004001F0 AF82800C */  sw         $v0, -0x7FF4($gp)
/* 1F4 004001F4 1000FFFC */  b          .L004001E8
/* 1F8 004001F8 00000000 */   nop
