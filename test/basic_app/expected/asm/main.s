.include "macro.inc"

.set noat
.set noreorder
.set gp=64

.section .text, "ax"

glabel func_80000400
    /* 1000 80000400 27BDFFF8 */  addiu      $sp, $sp, -0x8
    /* 1004 80000404 AFBE0000 */  sw         $fp, 0x0($sp)
    /* 1008 80000408 03A0F021 */  addu       $fp, $sp, $zero
    /* 100C 8000040C 3C028000 */  lui        $v0, %hi(D_80000504)
    /* 1010 80000410 8C420504 */  lw         $v0, %lo(D_80000504)($v0)
    /* 1014 80000414 2C430008 */  sltiu      $v1, $v0, 0x8
    /* 1018 80000418 1060001B */  beqz       $v1, .L80000488
    /* 101C 8000041C 00000000 */   nop
    /* 1020 80000420 3C028000 */  lui        $v0, %hi(D_80000504)
    /* 1024 80000424 8C420504 */  lw         $v0, %lo(D_80000504)($v0)
    /* 1028 80000428 00401821 */  addu       $v1, $v0, $zero
    /* 102C 8000042C 00031080 */  sll        $v0, $v1, 2
    /* 1030 80000430 3C038000 */  lui        $v1, %hi(jtbl_80000518)
    /* 1034 80000434 24630518 */  addiu      $v1, $v1, %lo(jtbl_80000518)
    /* 1038 80000438 00431021 */  addu       $v0, $v0, $v1
    /* 103C 8000043C 8C430000 */  lw         $v1, 0x0($v0)
    /* 1040 80000440 00600008 */  jr         $v1
    /* 1044 80000444 00000000 */   nop
  glabel .L80000448
    /* 1048 80000448 08000124 */  j          .L80000490
    /* 104C 8000044C 24020007 */   addiu     $v0, $zero, 0x7
  glabel .L80000450
    /* 1050 80000450 08000124 */  j          .L80000490
    /* 1054 80000454 24020006 */   addiu     $v0, $zero, 0x6
  glabel .L80000458
    /* 1058 80000458 08000124 */  j          .L80000490
    /* 105C 8000045C 24020005 */   addiu     $v0, $zero, 0x5
  glabel .L80000460
    /* 1060 80000460 08000124 */  j          .L80000490
    /* 1064 80000464 24020004 */   addiu     $v0, $zero, 0x4
  glabel .L80000468
    /* 1068 80000468 08000124 */  j          .L80000490
    /* 106C 8000046C 24020003 */   addiu     $v0, $zero, 0x3
  glabel .L80000470
    /* 1070 80000470 08000124 */  j          .L80000490
    /* 1074 80000474 24020002 */   addiu     $v0, $zero, 0x2
  glabel .L80000478
    /* 1078 80000478 08000124 */  j          .L80000490
    /* 107C 8000047C 24020001 */   addiu     $v0, $zero, 0x1
  glabel .L80000480
    /* 1080 80000480 08000124 */  j          .L80000490
    /* 1084 80000484 00001021 */   addu      $v0, $zero, $zero
  .L80000488:
    /* 1088 80000488 08000124 */  j          .L80000490
    /* 108C 8000048C 00001021 */   addu      $v0, $zero, $zero
  .L80000490:
    /* 1090 80000490 03C0E821 */  addu       $sp, $fp, $zero
    /* 1094 80000494 8FBE0000 */  lw         $fp, 0x0($sp)
    /* 1098 80000498 03E00008 */  jr         $ra
    /* 109C 8000049C 27BD0008 */   addiu     $sp, $sp, 0x8
.size func_80000400, . - func_80000400

glabel func_800004A0
    /* 10A0 800004A0 27BDFFE8 */  addiu      $sp, $sp, -0x18
    /* 10A4 800004A4 AFBF0014 */  sw         $ra, 0x14($sp)
    /* 10A8 800004A8 AFBE0010 */  sw         $fp, 0x10($sp)
    /* 10AC 800004AC 0C000100 */  jal        func_80000400
    /* 10B0 800004B0 03A0F021 */   addu      $fp, $sp, $zero
  .L800004B4:
    /* 10B4 800004B4 3C028000 */  lui        $v0, %hi(D_80000500)
    /* 10B8 800004B8 8C420500 */  lw         $v0, %lo(D_80000500)($v0)
    /* 10BC 800004BC 24430001 */  addiu      $v1, $v0, 0x1
    /* 10C0 800004C0 3C018000 */  lui        $at, %hi(D_80000500)
    /* 10C4 800004C4 AC230500 */  sw         $v1, %lo(D_80000500)($at)
    /* 10C8 800004C8 3C028000 */  lui        $v0, %hi(D_80000500)
    /* 10CC 800004CC 8C420500 */  lw         $v0, %lo(D_80000500)($v0)
    /* 10D0 800004D0 0800012D */  j          .L800004B4
    /* 10D4 800004D4 00000000 */   nop
    /* 10D8 800004D8 03C0E821 */  addu       $sp, $fp, $zero
    /* 10DC 800004DC 8FBF0014 */  lw         $ra, 0x14($sp)
    /* 10E0 800004E0 8FBE0010 */  lw         $fp, 0x10($sp)
    /* 10E4 800004E4 03E00008 */  jr         $ra
    /* 10E8 800004E8 27BD0018 */   addiu     $sp, $sp, 0x18
.size func_800004A0, . - func_800004A0
    /* 10EC 800004EC 00000000 */  nop
