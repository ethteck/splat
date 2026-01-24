#!/usr/bin/env python3
"""Tests for N64EntrypointInfo.parse_rom_bytes().

Covers all 35 entrypoint signature types found in N64 dumps.
Each test constructs a MIPS instruction sequence matching a real
entrypoint pattern and verifies that the parser correctly identifies:
- traditional_entrypoint flag
- main_address (jr/jal target)
- stack_top ($sp value)
- bss_start_address (BSS clear target)
- bss_size / bss_end_address
"""

import unittest

from src.splat.util.n64.rominfo import N64EntrypointInfo

# === MIPS Instruction Encoding Helpers ===

# Register numbers
ZERO, AT, V0, V1 = 0, 1, 2, 3
A0, A1, A2, A3 = 4, 5, 6, 7
T0, T1, T2, T3, T4, T5, T6, T7 = 8, 9, 10, 11, 12, 13, 14, 15
S0, S1, S2, S3, S4, S5, S6, S7 = 16, 17, 18, 19, 20, 21, 22, 23
T8, T9 = 24, 25
GP, SP, FP, RA = 28, 29, 30, 31


def _w(val: int) -> str:
    """Format a 32-bit value as 8-char hex string."""
    return f"{val & 0xFFFFFFFF:08X}"


def lui(rt, imm16):
    return _w(0x3C000000 | (rt << 16) | (imm16 & 0xFFFF))


def addiu(rt, rs, imm16):
    return _w(0x24000000 | (rs << 21) | (rt << 16) | (imm16 & 0xFFFF))


def ori(rt, rs, imm16):
    return _w(0x34000000 | (rs << 21) | (rt << 16) | (imm16 & 0xFFFF))


def addi(rt, rs, imm16):
    return _w(0x20000000 | (rs << 21) | (rt << 16) | (imm16 & 0xFFFF))


def sw(rt, offset, base):
    return _w(0xAC000000 | (base << 21) | (rt << 16) | (offset & 0xFFFF))


def bnez(rs, offset):
    return _w(0x14000000 | (rs << 21) | (offset & 0xFFFF))


def beq(rs, rt, offset):
    return _w(0x10000000 | (rs << 21) | (rt << 16) | (offset & 0xFFFF))


def bgtz(rs, offset):
    return _w(0x1C000000 | (rs << 21) | (offset & 0xFFFF))


def jr(rs):
    return _w(0x00000008 | (rs << 21))


def jal(target):
    return _w(0x0C000000 | ((target >> 2) & 0x03FFFFFF))


def j(target):
    return _w(0x08000000 | ((target >> 2) & 0x03FFFFFF))


def sltu(rd, rs, rt):
    return _w(0x00000000 | (rs << 21) | (rt << 16) | (rd << 11) | 0x2B)


def nop():
    return "00000000"


def mtc0(rt, rd):
    """MTC0 rt, rd (move to coprocessor 0)."""
    return _w(0x40800000 | (rt << 16) | (rd << 11))


def mfc0(rt, rd):
    """MFC0 rt, rd (move from coprocessor 0)."""
    return _w(0x40000000 | (rt << 16) | (rd << 11))


def tlbwi():
    return "42000002"


def cache(op, offset, base):
    return _w(0xBC000000 | (base << 21) | (op << 16) | (offset & 0xFFFF))


def break_():
    return "0001008D"


def sync():
    return "0000000F"


def addu(rd, rs, rt):
    return _w(0x00000000 | (rs << 21) | (rt << 16) | (rd << 11) | 0x21)


def lw(rt, offset, base):
    return _w(0x8C000000 | (base << 21) | (rt << 16) | (offset & 0xFFFF))


# === Test Helpers ===

VRAM = 0x80000400
OFFSET = 0x1000
SIZE = 0x100


def build_rom_bytes(hex_words: list, offset=OFFSET) -> bytes:
    """Build minimal ROM bytes from hex instruction words at given offset."""
    data = bytearray(offset)
    for word in hex_words:
        data.extend(bytes.fromhex(word))
    # Sentinel to trigger nop-gap break (non-nop after trailing nops)
    data.extend(b"\xff\xff\xff\xff")
    # Pad to ensure size window is available
    while len(data) < offset + SIZE + 4:
        data.extend(b"\x00" * 4)
    return bytes(data)


def parse(hex_words: list, vram=VRAM, offset=OFFSET, size=SIZE) -> N64EntrypointInfo:
    """Parse instruction words and return entrypoint info."""
    rom_bytes = build_rom_bytes(hex_words, offset)
    return N64EntrypointInfo.parse_rom_bytes(rom_bytes, vram, offset, size)


# === Test Cases ===


class TestTraditionalEntrypoints(unittest.TestCase):
    """Traditional entrypoints: BSS clear loop + jr $t2 to main."""

    def test_traditional_a(self):
        """SM64-style: lui/lui/addiu/ori + decrement-first BSS loop.
        Games: Super Mario 64, Mario Kart 64, GoldenEye 007, Star Fox 64
        """
        words = [
            lui(T0, 0x8034),
            lui(T1, 0x0002),
            addiu(T0, T0, 0xA580),
            ori(T1, T1, 0xCEE0),
            addi(T1, T1, 0xFFF8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, 0xFFFC),
            addi(T0, T0, 8),
            lui(T2, 0x8024),
            lui(SP, 0x8020),
            addiu(T2, T2, 0x6DF8),
            jr(T2),
            addiu(SP, SP, 0x0600),
        ]
        info = parse(words, vram=0x80246000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80246DF8)
        self.assertEqual(info.stack_top.value, 0x80200600)
        self.assertEqual(info.bss_start_address.value, 0x8033A580)
        self.assertEqual(info.bss_size.value, 0x0002CEE0)
        self.assertIsNone(info.bss_end_address)

    def test_traditional_a_li(self):
        """Zelda OoT-style: bss_size loaded via li (addiu $t1,$zero,imm).
        Games: Zelda: Ocarina of Time, Donkey Kong 64, Banjo-Kazooie
        """
        words = [
            lui(T0, 0x8000),
            addiu(T0, T0, 0x6830),
            addiu(T1, ZERO, 0x4910),
            addi(T1, T1, 0xFFF8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, 0xFFFC),
            addi(T0, T0, 8),
            lui(T2, 0x8000),
            lui(SP, 0x8000),
            addiu(T2, T2, 0x0498),
            jr(T2),
            addiu(SP, SP, 0x7220),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80000498)
        self.assertEqual(info.stack_top.value, 0x80007220)
        self.assertEqual(info.bss_start_address.value, 0x80006830)
        self.assertIsNone(info.bss_size)

    def test_traditional_a_li_ori(self):
        """Bomberman-style: bss_size loaded via ori $t1,$zero,imm.
        Games: Zelda: Majora's Mask (EU Beta), Bomberman 64, Bomberman Hero
        """
        words = [
            lui(T0, 0x8002),
            addiu(T0, T0, 0xBFC0),
            ori(T1, ZERO, 0xC4A0),
            addi(T1, T1, 0xFFF8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, 0xFFFC),
            addi(T0, T0, 8),
            lui(T2, 0x8000),
            lui(SP, 0x8002),
            addiu(T2, T2, 0x19A0),
            jr(T2),
            addiu(SP, SP, 0x44B0),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x800019A0)
        self.assertEqual(info.stack_top.value, 0x800244B0)
        self.assertEqual(info.bss_start_address.value, 0x8001BFC0)
        self.assertIsNone(info.bss_size)

    def test_traditional_b(self):
        """Mario Party-style: lui/addiu/lui/addiu + sw/sw/addi/addi/bnez/nop.
        Games: Mario Party 1/2/3, Mario Golf, WCW/nWo Revenge, WWF No Mercy
        """
        words = [
            lui(T0, 0x800D),
            addiu(T0, T0, 0xCE50),
            lui(T1, 0x0003),
            addiu(T1, T1, 0x9790),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, 0x8000),
            addiu(T2, T2, 0x0460),
            lui(SP, 0x800F),
            jr(T2),
            addiu(SP, SP, 0x2A70),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80000460)
        self.assertEqual(info.stack_top.value, 0x800F2A70)
        self.assertEqual(info.bss_start_address.value, 0x800CCE50)
        self.assertEqual(info.bss_size.value, 0x00029790)

    def test_traditional_b_nop(self):
        """Ridge Racer 64: traditional_b with nop as jr delay slot.
        Games: Ridge Racer 64
        """
        words = [
            lui(T0, 0x8003),
            addiu(T0, T0, 0x4A70),
            lui(T1, 0x0009),
            addiu(T1, T1, 0xEF90),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, 0x8000),
            addiu(T2, T2, 0x1F54),
            lui(SP, 0x8003),
            addiu(SP, SP, 0x51F0),
            jr(T2),
            nop(),
        ]
        info = parse(words, vram=0x80000450)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80001F54)
        self.assertEqual(info.stack_top.value, 0x800351F0)
        self.assertEqual(info.bss_start_address.value, 0x80034A70)
        self.assertEqual(info.bss_size.value, 0x0008EF90)

    def test_traditional_b_ori_sp(self):
        """Mario Tennis: traditional_b with ori for $sp lo half.
        Games: Mario Tennis
        """
        words = [
            lui(T0, 0x8031),
            addiu(T0, T0, 0x06C0),
            lui(T1, 0x0000),
            addiu(T1, T1, 0x0010),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, 0x8030),
            addiu(T2, T2, 0x0050),
            lui(SP, 0x803F),
            jr(T2),
            ori(SP, SP, 0xF000),
        ]
        info = parse(words, vram=0x80300000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80300050)
        self.assertEqual(info.stack_top.value, 0x803FF000)
        self.assertEqual(info.bss_start_address.value, 0x803106C0)
        self.assertEqual(info.bss_size.value, 0x00000010)

    def test_traditional_c(self):
        """Batman Beyond style: lui order swapped (lui/lui/addiu/addiu).
        Games: Batman Beyond, Daikatana
        """
        words = [
            lui(T0, 0x801B),
            lui(T1, 0x0008),
            addiu(T0, T0, 0x9BC0),
            addiu(T1, T1, 0x30F0),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, 0x801A),
            lui(SP, 0x8023),
            addiu(T2, T2, 0xC940),
            addiu(SP, SP, 0xCCA0),
            jr(T2),
            nop(),
        ]
        info = parse(words, vram=0x80180000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x8019C940)
        self.assertEqual(info.stack_top.value, 0x8022CCA0)
        self.assertEqual(info.bss_start_address.value, 0x801A9BC0)
        self.assertEqual(info.bss_size.value, 0x000830F0)

    def test_traditional_d(self):
        """Paper Mario style: $sp set before BSS loop.
        Games: Paper Mario
        """
        words = [
            lui(T0, 0x800A),
            addiu(T0, T0, 0xA5B0),
            lui(T1, 0x0004),
            addiu(T1, T1, 0x1F50),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(SP, 0x800B),
            addiu(SP, SP, 0x6590),
            lui(T2, 0x8006),
            addiu(T2, T2, 0xE8B0),
            jr(T2),
            nop(),
        ]
        info = parse(words, vram=0x80125C00)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x8005E8B0)
        self.assertEqual(info.stack_top.value, 0x800B6590)
        self.assertEqual(info.bss_start_address.value, 0x8009A5B0)
        self.assertEqual(info.bss_size.value, 0x00041F50)

    def test_traditional_d_ori(self):
        """Superman: bss_size uses ori for lo half (lui+ori pair).
        Games: Superman
        """
        words = [
            lui(T0, 0x800E),
            addiu(T0, T0, 0x09F0),
            lui(T1, 0x0006),
            ori(T1, T1, 0x7520),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(SP, 0x800F),
            addiu(SP, SP, 0xC0E0),
            lui(T2, 0x8000),
            addiu(T2, T2, 0x4820),
            jr(T2),
            nop(),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80004820)
        self.assertEqual(info.stack_top.value, 0x800EC0E0)
        self.assertEqual(info.bss_start_address.value, 0x800E09F0)
        self.assertEqual(info.bss_size.value, 0x00067520)

    def test_traditional_d_bgtz(self):
        """Tsumi to Batsu: uses bgtz instead of bnez for BSS loop.
        Games: Tsumi to Batsu
        """
        words = [
            lui(T0, 0x8006),
            addiu(T0, T0, 0x3450),
            lui(T1, 0x0004),
            addiu(T1, T1, 0x3C20),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bgtz(T1, 0xFFFB),
            nop(),
            lui(T2, 0x8002),
            addiu(T2, T2, 0x5C40),
            lui(SP, 0x8006),
            addiu(SP, SP, 0x77B8),
            jr(T2),
            nop(),
            addiu(SP, SP, 0xFFE0),
            sw(RA, 0x18, SP),
            jal(0x8004BAE8),
            nop(),
        ]
        info = parse(words, vram=0x80025C00)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x8004BAE8)
        self.assertEqual(info.stack_top.value, 0x800677B8)
        self.assertEqual(info.bss_start_address.value, 0x80063450)
        self.assertIsNone(info.bss_size)

    def test_direct_jump(self):
        """Direct jr to main (no BSS clear).
        Games: Star Wars: Shadows of the Empire, SW Episode I: Racer, Turok
        """
        words = [
            lui(T2, 0x8000),
            lui(SP, 0x8011),
            addiu(T2, T2, 0x1184),
            jr(T2),
            addiu(SP, SP, 0x2A80),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80001184)
        self.assertEqual(info.stack_top.value, 0x80112A80)
        self.assertIsNone(info.bss_start_address)
        self.assertIsNone(info.bss_size)


class TestSltuClearEntrypoints(unittest.TestCase):
    """Non-traditional entrypoints using sltu-based BSS clearing."""

    def test_sltu_clear(self):
        """Basic sltu pattern: beq + sltu loop + jal + break.
        Games: Glover, Command & Conquer
        """
        words = [
            lui(SP, 0x8026),
            addiu(SP, SP, 0xF158),
            lui(T0, 0x801F),
            addiu(T0, T0, 0x5680),
            lui(T1, 0x802B),
            addiu(T1, T1, 0x0D10),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x80139DE8),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100000)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, 0x801F5680)
        self.assertEqual(info.bss_end_address.value, 0x802B0D10)
        self.assertIsNone(info.bss_size)
        self.assertEqual(info.main_address.value, 0x80139DE8)
        self.assertEqual(info.stack_top.value, 0x8025F158)
        self.assertEqual(info.entry_size, 60)

    def test_sltu_clear_ori_sp(self):
        """sltu pattern with ori for $sp lo half.
        Games: Kobe Bryant NBA Courtside, Toy Story 2
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFEF0),
            lui(T0, 0x800E),
            addiu(T0, T0, 0xEDC0),
            lui(T1, 0x8014),
            addiu(T1, T1, 0x74C0),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x80000440),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.stack_top.value, 0x803FFEF0)
        self.assertEqual(info.bss_start_address.value, 0x800DEDC0)
        self.assertEqual(info.bss_end_address.value, 0x801474C0)
        self.assertEqual(info.main_address.value, 0x80000440)
        self.assertEqual(info.entry_size, 60)

    def test_sltu_clear_ori_sp_double(self):
        """sltu with ori $sp and double BSS clear loop.
        Games: Extreme-G
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            lui(T0, 0x8000),
            addiu(T0, T0, 0x0400),
            lui(T1, 0x8000),
            addiu(T1, T1, 0x0400),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, 0x8000),
            addiu(T0, T0, 0x1000),
            lui(T1, 0x8000),
            addiu(T1, T1, 0x1000),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x8004B498),
            nop(),
        ]
        info = parse(words, vram=0x8004B400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, 0x80000400)
        self.assertEqual(info.bss_end_address.value, 0x80000400)
        self.assertEqual(info.main_address.value, 0x8004B498)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)

    def test_sltu_clear_ori_sp_double_gp(self):
        """sltu with ori $sp, double BSS clear, and $gp setup.
        Games: Tony Hawk's Pro Skater, Namco Museum 64, South Park Rally
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            lui(T0, 0x8001),
            addiu(T0, T0, 0x2F10),
            lui(T1, 0x8001),
            addiu(T1, T1, 0x6AC0),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, 0x8001),
            addiu(T0, T0, 0x2F10),
            lui(T1, 0x8001),
            addiu(T1, T1, 0x2F10),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(GP, 0x0000),
            addiu(GP, GP, 0x0000),
            jal(0x80000870),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, 0x80012F10)
        self.assertEqual(info.bss_end_address.value, 0x80016AC0)
        self.assertEqual(info.main_address.value, 0x80000870)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)

    def test_sltu_clear_ori_sp_t2(self):
        """sltu with ori $sp, TLB setup after loop (no jal).
        Games: South Park
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFC0),
            lui(T0, 0x800C),
            addiu(T0, T0, 0x2000),
            lui(T1, 0x800F),
            addiu(T1, T1, 0x3730),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(T2, T0, T1),
            bnez(T2, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            addiu(A0, ZERO, 0x001E),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, 0x8000),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, 0x803FFFC0)
        self.assertEqual(info.bss_start_address.value, 0x800C2000)
        self.assertEqual(info.bss_end_address.value, 0x800F3730)

    def test_sltu_clear_double(self):
        """sltu with double BSS clear, addiu $sp.
        Games: LEGO Racers
        """
        words = [
            lui(SP, 0x8002),
            addiu(SP, SP, 0x7248),
            lui(T0, 0x8003),
            addiu(T0, T0, 0x2410),
            lui(T1, 0x8004),
            addiu(T1, T1, 0xBCE0),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, 0x8003),
            addiu(T0, T0, 0x2410),
            lui(T1, 0x8003),
            addiu(T1, T1, 0x2410),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x8000258C),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, 0x80032410)
        self.assertEqual(info.bss_end_address.value, 0x8003BCE0)
        self.assertEqual(info.stack_top.value, 0x80027248)
        self.assertEqual(info.main_address.value, 0x8000258C)

    def test_sltu_clear_double_gp(self):
        """sltu with double BSS clear and $gp.
        Games: NFL Blitz 2001
        """
        words = [
            lui(SP, 0x8005),
            addiu(SP, SP, 0x74E0),
            lui(T0, 0x8005),
            addiu(T0, T0, 0x9B80),
            lui(T1, 0x8008),
            addiu(T1, T1, 0x18B0),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, 0x8005),
            addiu(T0, T0, 0x9B80),
            lui(T1, 0x8005),
            addiu(T1, T1, 0x9B80),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(GP, 0x0000),
            addiu(GP, GP, 0x0000),
            jal(0x8000A404),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, 0x80049B80)
        self.assertEqual(info.bss_end_address.value, 0x800818B0)
        self.assertEqual(info.stack_top.value, 0x800574E0)
        self.assertEqual(info.main_address.value, 0x8000A404)

    def test_sltu_clear_jal(self):
        """sltu without beq guard, jal + break.
        Games: FIFA 99
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            lui(T0, 0x8001),
            addiu(T0, T0, 0x4EB8),
            lui(T1, 0x8004),
            addiu(T1, T1, 0xF0B8),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x80000438),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80000438)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)
        self.assertEqual(info.bss_start_address.value, 0x80014EB8)
        self.assertEqual(info.bss_end_address.value, 0x8003F0B8)
        self.assertEqual(info.entry_size, 52)

    def test_sltu_clear_size(self):
        """sltu where bss_end is computed via addu (bss_start + size).
        Games: NHL Breakaway
        """
        words = [
            lui(SP, 0x800D),
            addiu(SP, SP, 0x5D70),
            lui(T0, 0x8006),
            addiu(T0, T0, 0x4040),
            lui(T1, 0x0008),
            addiu(T1, T1, 0x8000),
            addu(T1, T0, T1),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x80003B00),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80003B00)
        self.assertEqual(info.stack_top.value, 0x800D5D70)
        self.assertEqual(info.bss_start_address.value, 0x80064040)
        self.assertEqual(info.bss_end_address.value, 0x00078000)
        self.assertEqual(info.entry_size, 64)

    def test_sltu_clear_tlb(self):
        """sltu with TLB setup after BSS clear, no jal.
        Games: Shadow Man
        """
        words = [
            lui(SP, 0x8005),
            addiu(SP, SP, 0xDA38),
            lui(T0, 0x8005),
            addiu(T0, T0, 0xA440),
            lui(T1, 0x8005),
            addiu(T1, T1, 0x2760),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            addiu(A0, ZERO, 0x001E),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, 0x8000),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, 0x8004DA38)
        self.assertEqual(info.bss_start_address.value, 0x8004A440)
        self.assertEqual(info.bss_end_address.value, 0x80052760)

    def test_sltu_clear_magic(self):
        """sltu with magic constant (FACEFACE) store after BSS clear.
        Games: Forsaken 64
        """
        words = [
            lui(SP, 0x8004),
            addiu(SP, SP, 0x9D00),
            lui(T0, 0x8003),
            addiu(T0, T0, 0x9D10),
            lui(T1, 0x800C),
            addiu(T1, T1, 0x82B0),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, 0x8003),
            addiu(T0, T0, 0x9D10),
            lui(AT, 0xFACE),
            ori(AT, AT, 0xFACE),
            addu(T1, ZERO, AT),
            sw(T1, 0, T0),
            jal(0x80001BC0),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80001BC0)
        self.assertEqual(info.stack_top.value, 0x80039D00)
        self.assertEqual(info.bss_start_address.value, 0x80029D10)
        self.assertEqual(info.bss_end_address.value, 0x800B82B0)
        self.assertEqual(info.entry_size, 84)


class TestSn64Entrypoints(unittest.TestCase):
    """SN64 SDK entrypoints (jal to main, often with TLB setup)."""

    def test_sn64_jal(self):
        """SN64 jal to main with ori $sp.
        Games: Madden 64/99/2000/2001/2002
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            jal(0x802004B8),
            nop(),
        ]
        info = parse(words, vram=0x80200400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x802004B8)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)
        self.assertIsNone(info.bss_start_address)

    def test_sn64_jal_addiu(self):
        """SN64 jal with addiu for $sp instead of ori.
        Games: Bust-A-Move '99
        """
        words = [
            lui(SP, 0x8010),
            addiu(SP, SP, 0xB768),
            jal(0x80089EA0),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80089EA0)
        self.assertEqual(info.stack_top.value, 0x800FB768)
        self.assertIsNone(info.bss_start_address)
        self.assertEqual(info.entry_size, 20)

    def test_sn64_tlb(self):
        """SN64 TLB setup, parser breaks at nop gap.
        Games: Turok 2: Seeds of Evil
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFC0),
            addiu(A0, ZERO, 0x001E),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, 0x8000),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, 0x803FFFC0)

    def test_sn64_tlb_li(self):
        """SN64 TLB with li for loop counter.
        Games: South Park: Chef's Luv Shack
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            addiu(A0, ZERO, 0x001E),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, 0x8000),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words, vram=0x80300000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)


class TestSpecialEntrypoints(unittest.TestCase):
    """Unusual entrypoint patterns (Factor 5, Acclaim, etc.)."""

    def test_excitebike(self):
        """Excitebike 64: magic constant + sltu BSS clear + jal + break.
        Games: Excitebike 64
        """
        words = [
            lui(T0, 0xBEEF),
            ori(T0, T0, 0xDEAD),
            lui(SP, 0x803F),
            ori(SP, SP, 0xFEF0),
            lui(T0, 0x8001),
            addiu(T0, T0, 0x1D80),
            lui(T1, 0x8002),
            addiu(T1, T1, 0xBD90),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(0x80000450),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80000450)
        self.assertEqual(info.stack_top.value, 0x803FFEF0)
        self.assertEqual(info.bss_start_address.value, 0x80011D80)
        self.assertEqual(info.bss_end_address.value, 0x8001BD90)
        self.assertEqual(info.entry_size, 68)

    def test_factor5_jump(self):
        """Factor 5: j instruction (not tracked by parser).
        Games: Star Wars: Rogue Squadron
        """
        words = [
            lui(SP, 0x803F),
            j(0x80001E90),
            ori(SP, SP, 0xFFF0),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)

    def test_factor5_cache(self):
        """Factor 5: multiple jals, last one overrides main_address.
        Games: SW Episode I: Battle for Naboo, Indiana Jones
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            addiu(T0, ZERO, 0x0001),
            mtc0(T0, 6),
            mtc0(ZERO, 4),
            jal(0x80000880),
            nop(),
            mtc0(ZERO, 0),
            lui(A0, 0x007F),
            ori(A0, A0, 0xE000),
            lui(A1, 0x4000),
            lui(A2, 0x0000),
            lui(A3, 0x0040),
            jal(0x80000F08),
            nop(),
            lui(T0, 0x4000),
            ori(T0, T0, 0x044C),
            jr(T0),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80000F08)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)

    def test_vigilante8(self):
        """Vigilante 8: sltu loop + j instruction (not tracked as main).
        Games: Vigilante 8
        """
        words = [
            lui(SP, 0x803F),
            ori(SP, SP, 0xFFF0),
            lui(V0, 0x8019),
            addiu(V0, V0, 0x9B60),
            lui(V1, 0x801E),
            addiu(V1, V1, 0x9B20),
            sw(ZERO, 0, V0),
            sltu(AT, V0, V1),
            bnez(AT, 0xFFFD),
            addiu(V0, V0, 4),
            j(0x8012D260),
            nop(),
        ]
        info = parse(words, vram=0x80125800)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, 0x803FFFF0)
        self.assertEqual(info.bss_start_address.value, 0x80189B60)
        self.assertEqual(info.bss_end_address.value, 0x801D9B20)

    def test_acclaim_jump(self):
        """Acclaim: bare j instruction (not recognized by parser).
        Games: WWF War Zone, WWF Attitude
        """
        words = [
            j(0x80000430),
            nop(),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertIsNone(info.stack_top)

    def test_army_men(self):
        """Army Men: complex boot with multiple jal calls.
        Games: Army Men: Sarge's Heroes
        """
        words = [
            lui(A1, 0x800C),
            addiu(A1, A1, 0x97D8),
            addu(SP, A1, ZERO),
            addu(FP, A1, ZERO),
            addiu(GP, ZERO, 0xFFFF),
            lui(A0, 0x800B),
            addiu(A0, A0, 0x3210),
            lui(A0, 0x800B),
            addiu(A0, A0, 0x57F0),
            lui(A1, 0x800C),
            addiu(A1, A1, 0x97F0),
            lui(A2, 0x5555),
            ori(A2, A2, 0x5555),
            jal(0x800004A0),
            nop(),
            lui(A0, 0x800C),
            addiu(A0, A0, 0x97F0),
            lui(A1, 0x8017),
            addiu(A1, A1, 0xE670),
            jal(0x800004A0),
            addu(A2, ZERO, ZERO),
            lui(A0, 0x800C),
            addiu(A0, A0, 0x97F0),
            lui(A1, 0x800C),
            addiu(A1, A1, 0x97F0),
            jal(0x800004A0),
            addu(A2, ZERO, ZERO),
            lui(A0, 0x8000),
            addiu(A0, A0, 0x0318),
            lui(S7, 0x8008),
            addiu(S7, S7, 0xCAB0),
            lw(T0, 0, A0),
            nop(),
            lui(AT, 0x8000),
            addu(T0, T0, AT),
            sw(T0, 0x002C, S7),
            jal(0x80050810),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x80050810)
        self.assertIsNone(info.stack_top)

    def test_empty_entry(self):
        """All nops (no meaningful code at entrypoint).
        Games: GameShark/Action Replay
        """
        words = [nop()] * 16
        info = parse(words, vram=0x80190000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertIsNone(info.stack_top)
        self.assertIsNone(info.bss_start_address)
        self.assertIsNone(info.bss_size)

    def test_cheat_device(self):
        """Cheat device: DMA copy loop + cache flush + j + jal.
        Games: GameBooster 64
        """
        words = [
            lui(V1, 0xB0C0),
            ori(V1, V1, 0x1000),
            lui(V0, 0x8020),
            ori(V0, V0, 0x0400),
            lui(T0, 0x0003),
            ori(T0, T0, 0xF000),
            lw(AT, 0, V1),
            sync(),
            sw(AT, 0, V0),
            addiu(V1, V1, 4),
            addiu(V0, V0, 4),
            addiu(T0, T0, 0xFFFC),
            bgtz(T0, 0xFFF9),
            nop(),
            lui(T0, 0x8000),
            addiu(T1, T0, 0x3000),
            addiu(T1, T1, 0xFFF0),
            cache(1, 0, T0),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            addiu(T0, T0, 0x0010),
            lui(T0, 0x8000),
            addiu(T1, T0, 0x6000),
            addiu(T1, T1, 0xFFE0),
            cache(0, 0, T0),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            addiu(T0, T0, 0x0020),
            lui(SP, 0x803F),
            ori(SP, SP, 0xFF00),
            j(0x80200480),
            nop(),
            addiu(SP, SP, 0xFFE8),
            sw(RA, 0x0010, SP),
            jal(0x802029F8),
            nop(),
        ]
        info = parse(words, vram=0x80280000)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, 0x802029F8)
        self.assertEqual(info.stack_top.value, 0x803FFF00)

    def test_cheat_device_bal(self):
        """Cheat device variant: bgezal (BAL) + DMA loop.
        Games: GameShark Pro v2.0
        """
        bal = _w(0x04110000)  # bgezal $zero, 0
        words = [
            bal,
            addu(A0, RA, ZERO),
            lui(V1, 0xB0C0),
            lui(V0, 0x8040),
            lui(T0, 0x0004),
            lw(AT, 0, V1),
            nop(),
            sync(),
            nop(),
            sw(AT, 0, V0),
            addiu(V1, V1, 4),
            addiu(V0, V0, 4),
            addiu(T0, T0, 0xFFFC),
            bgtz(T0, 0xFFF7),
            nop(),
        ]
        info = parse(words, vram=0x80401000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertIsNone(info.stack_top)


if __name__ == "__main__":
    unittest.main()
