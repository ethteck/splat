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


def HI(val: int) -> int:
    return (val + 0x8000) >> 16


def LO(val: int) -> int:
    return val & 0xFFFF


def UHI(val: int) -> int:
    return (val >> 16) & 0xFFFF


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
        BSS_START = 0x80334C20
        BSS_SIZE = 0x00024A20
        MAIN_ADDR = 0x80246B40
        STACK_TOP = 0x80205A00

        words = [
            lui(T0, HI(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T0, T0, LO(BSS_START)),
            ori(T1, T1, LO(BSS_SIZE)),
            addi(T1, T1, 0xFFF8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, 0xFFFC),
            addi(T0, T0, 8),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words, vram=0x80246000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertIsNone(info.bss_end_address)

    def test_traditional_a_li(self):
        """Zelda OoT-style: bss_size loaded via li (addiu $t1,$zero,imm).
        Games: Zelda: Ocarina of Time, Donkey Kong 64, Banjo-Kazooie
        """
        BSS_START = 0x80006210
        MAIN_ADDR = 0x80000640
        STACK_TOP = 0x80007050

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            addiu(T1, ZERO, 0x4910),
            addi(T1, T1, 0xFFF8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, 0xFFFC),
            addi(T0, T0, 8),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertIsNone(info.bss_size)

    def test_traditional_a_li_ori(self):
        """Bomberman-style: bss_size loaded via ori $t1,$zero,imm.
        Games: Zelda: Majora's Mask (EU Beta), Bomberman 64, Bomberman Hero
        """
        BSS_START = 0x80014E60
        BSS_SIZE = 0x0001C4A0  # TODO: parse bss_size from li/ori pattern
        MAIN_ADDR = 0x80001B20
        STACK_TOP = 0x800233A0

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            ori(T1, ZERO, LO(BSS_SIZE)),
            addi(T1, T1, 0xFFF8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, 0xFFFC),
            addi(T0, T0, 8),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertIsNone(info.bss_size)

    def test_traditional_b(self):
        """Mario Party-style: lui/addiu/lui/addiu + sw/sw/addi/addi/bnez/nop.
        Games: Mario Party 1/2/3, Mario Golf, WCW/nWo Revenge, WWF No Mercy
        """
        BSS_START = 0x800C5B10
        BSS_SIZE = 0x00024B60
        MAIN_ADDR = 0x800006A0
        STACK_TOP = 0x800F1E40

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)

    def test_traditional_b_nop(self):
        """Ridge Racer 64: traditional_b with nop as jr delay slot.
        Games: Ridge Racer 64
        """
        BSS_START = 0x80033620
        BSS_SIZE = 0x00086B40
        MAIN_ADDR = 0x80001D80
        STACK_TOP = 0x800345C0

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            jr(T2),
            nop(),
        ]
        info = parse(words, vram=0x80000450)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)

    def test_traditional_b_ori_sp(self):
        """Mario Tennis: traditional_b with ori for $sp lo half.
        Games: Mario Tennis
        """
        BSS_START = 0x80311240
        BSS_SIZE = 0x00000020
        MAIN_ADDR = 0x80300210
        STACK_TOP = 0x803F6C00

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, 0x0000),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            jr(T2),
            ori(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words, vram=0x80300000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)

    def test_traditional_c(self):
        """Batman Beyond style: lui order swapped (lui/lui/addiu/addiu).
        Games: Batman Beyond, Daikatana
        """
        BSS_START = 0x801A7840
        BSS_SIZE = 0x00081220
        MAIN_ADDR = 0x8019B5A0
        STACK_TOP = 0x80224D80

        words = [
            lui(T0, HI(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T0, T0, LO(BSS_START)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            addiu(SP, SP, LO(STACK_TOP)),
            jr(T2),
            nop(),
        ]
        info = parse(words, vram=0x80180000)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)

    def test_traditional_d(self):
        """Paper Mario style: $sp set before BSS loop.
        Games: Paper Mario
        """
        BSS_START = 0x80097A30
        BSS_SIZE = 0x00043840
        MAIN_ADDR = 0x8005D220
        STACK_TOP = 0x800B4C60

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            nop(),
        ]
        info = parse(words, vram=0x80125C00)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)

    def test_traditional_d_ori(self):
        """Superman: bss_size uses ori for lo half (lui+ori pair).
        Games: Superman
        """
        BSS_START = 0x800E2A10
        BSS_SIZE = 0x00064C80
        MAIN_ADDR = 0x80005C10
        STACK_TOP = 0x800E6B40

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            ori(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bnez(T1, 0xFFFB),
            nop(),
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            nop(),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_size.value, BSS_SIZE)

    def test_traditional_d_bgtz(self):
        """Tsumi to Batsu: uses bgtz instead of bnez for BSS loop.
        Games: Tsumi to Batsu
        """
        BSS_START = 0x80064A20
        MAIN_ADDR = 0x8004D360
        STACK_TOP = 0x80066B90

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, 0x0004),
            addiu(T1, T1, 0x3C20),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, 0xFFF8),
            bgtz(T1, 0xFFFB),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            jr(T2),
            nop(),
            addiu(SP, SP, 0xFFE0),
            sw(RA, 0x18, SP),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80025C00)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertIsNone(info.bss_size)

    def test_direct_jump(self):
        """Direct jr to main (no BSS clear).
        Games: Star Wars: Shadows of the Empire, SW Episode I: Racer, Turok
        """
        MAIN_ADDR = 0x80001520
        STACK_TOP = 0x80110C40

        words = [
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertIsNone(info.bss_start_address)
        self.assertIsNone(info.bss_size)


class TestSltuClearEntrypoints(unittest.TestCase):
    """Non-traditional entrypoints using sltu-based BSS clearing."""

    def test_sltu_clear(self):
        """Basic sltu pattern: beq + sltu loop + jal + break.
        Games: Glover, Command & Conquer
        """
        BSS_START = 0x801F3000
        BSS_END = 0x802B5400
        MAIN_ADDR = 0x80136D40
        STACK_TOP = 0x80256C20

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100000)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertIsNone(info.bss_size)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.entry_size, 60)

    def test_sltu_clear_ori_sp(self):
        """sltu pattern with ori for $sp lo half.
        Games: Kobe Bryant NBA Courtside, Toy Story 2
        """
        BSS_START = 0x800D5A40
        BSS_END = 0x80146210
        MAIN_ADDR = 0x80000680
        STACK_TOP = 0x803F4A20

        words = [
            lui(SP, HI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.entry_size, 60)

    def test_sltu_clear_ori_sp_double(self):
        """sltu with ori $sp and double BSS clear loop.
        Games: Extreme-G
        """
        BSS_START = 0x80002000
        BSS_END = 0x80002000
        MAIN_ADDR = 0x80047A80
        STACK_TOP = 0x803F6A10

        words = [
            lui(SP, HI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
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
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x8004B400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)

    def test_sltu_clear_ori_sp_double_gp(self):
        """sltu with ori $sp, double BSS clear, and $gp setup.
        Games: Tony Hawk's Pro Skater, Namco Museum 64, South Park Rally
        """
        BSS_START = 0x80013420
        BSS_END = 0x80017B60
        MAIN_ADDR = 0x80000920
        STACK_TOP = 0x803F5C80

        words = [
            lui(SP, HI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_START)),
            addiu(T1, T1, LO(BSS_START)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(GP, 0x0000),
            addiu(GP, GP, 0x0000),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)

    def test_sltu_clear_ori_sp_t2(self):
        """sltu with ori $sp, TLB setup after loop (no jal).
        Games: South Park
        """
        BSS_START = 0x800C2C40
        BSS_END = 0x800F4A10
        STACK_TOP = 0x803F5B60

        words = [
            lui(SP, HI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
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
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)

    def test_sltu_clear_double(self):
        """sltu with double BSS clear, addiu $sp.
        Games: LEGO Racers
        """
        BSS_START = 0x80033280
        BSS_END = 0x8003C560
        MAIN_ADDR = 0x80002740
        STACK_TOP = 0x80026A40

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_START)),
            addiu(T1, T1, LO(BSS_START)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.main_address.value, MAIN_ADDR)

    def test_sltu_clear_double_gp(self):
        """sltu with double BSS clear and $gp.
        Games: NFL Blitz 2001
        """
        BSS_START = 0x80054B40
        BSS_END = 0x80081610
        MAIN_ADDR = 0x8000A720
        STACK_TOP = 0x80056A20

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_START)),
            addiu(T1, T1, LO(BSS_START)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(GP, 0x0000),
            addiu(GP, GP, 0x0000),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.main_address.value, MAIN_ADDR)

    def test_sltu_clear_jal(self):
        """sltu without beq guard, jal + break.
        Games: FIFA 99
        """
        BSS_START = 0x80015C20
        BSS_END = 0x8003D480
        MAIN_ADDR = 0x800006C0
        STACK_TOP = 0x803F5E20

        words = [
            lui(SP, HI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.entry_size, 52)

    def test_sltu_clear_size(self):
        """sltu where bss_end is computed via addu (bss_start + size).
        Games: NHL Breakaway
        """
        BSS_START = 0x80064C20
        BSS_SIZE = 0x00024000
        BSS_END = BSS_SIZE  # TODO: fix bss_end detection for addu(size) case
        MAIN_ADDR = 0x80003D40
        STACK_TOP = 0x800D4F20

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            addu(T1, T0, T1),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.entry_size, 64)

    def test_sltu_clear_tlb(self):
        """sltu with TLB setup after BSS clear, no jal.
        Games: Shadow Man
        """
        BSS_START = 0x8004B040
        BSS_END = 0x80052D60
        STACK_TOP = 0x8004C220

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
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
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)

    def test_sltu_clear_magic(self):
        """sltu with magic constant (FACEFACE) store after BSS clear.
        Games: Forsaken 64
        """
        BSS_START = 0x80029A40
        BSS_END = 0x800B5C60
        MAIN_ADDR = 0x80001D20
        STACK_TOP = 0x8003A120

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(AT, 0xFACE),
            ori(AT, AT, 0xFACE),
            addu(T1, ZERO, AT),
            sw(T1, 0, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.entry_size, 84)


class TestSn64Entrypoints(unittest.TestCase):
    """SN64 SDK entrypoints (jal to main, often with TLB setup)."""

    def test_sn64_jal(self):
        """SN64 jal to main with ori $sp.
        Games: Madden 64/99/2000/2001/2002
        """
        MAIN_ADDR = 0x802004B8
        STACK_TOP = 0x803FFFF0

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80200400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertIsNone(info.bss_start_address)

    def test_sn64_jal_addiu(self):
        """SN64 jal with addiu for $sp instead of ori.
        Games: Bust-A-Move '99
        """
        MAIN_ADDR = 0x80089EA0
        STACK_TOP = 0x800FB768

        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertIsNone(info.bss_start_address)
        self.assertEqual(info.entry_size, 20)

    def test_sn64_tlb(self):
        """SN64 TLB setup, parser breaks at nop gap.
        Games: Turok 2: Seeds of Evil
        """
        STACK_TOP = 0x803FFFC0

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
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
        self.assertEqual(info.stack_top.value, STACK_TOP)

    def test_sn64_tlb_li(self):
        """SN64 TLB with li for loop counter.
        Games: South Park: Chef's Luv Shack
        """
        STACK_TOP = 0x803FFFF0

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
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
        self.assertEqual(info.stack_top.value, STACK_TOP)


class TestSpecialEntrypoints(unittest.TestCase):
    """Unusual entrypoint patterns (Factor 5, Acclaim, etc.)."""

    def test_excitebike(self):
        """Excitebike 64: magic constant + sltu BSS clear + jal + break.
        Games: Excitebike 64
        """
        BSS_START = 0x80011D80
        BSS_END = 0x8001BD90
        MAIN_ADDR = 0x80000450
        STACK_TOP = 0x803FFEF0

        words = [
            lui(T0, 0xBEEF),
            ori(T0, T0, 0xDEAD),
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, 0xFFFD),
            sw(ZERO, 0xFFFC, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100400)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertEqual(info.entry_size, 68)

    def test_factor5_jump(self):
        """Factor 5: j instruction (not tracked by parser).
        Games: Star Wars: Rogue Squadron
        """
        MAIN_ADDR = 0x80001E90  # TODO: track j target as main_address
        STACK_TOP = 0x803FFFF0

        words = [
            lui(SP, UHI(STACK_TOP)),
            j(MAIN_ADDR),
            ori(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, STACK_TOP)

    def test_factor5_cache(self):
        """Factor 5: multiple jals, last one overrides main_address.
        Games: SW Episode I: Battle for Naboo, Indiana Jones
        """
        FN1_ADDR = 0x80000880
        MAIN_ADDR = 0x80000F08
        STACK_TOP = 0x803FFFF0

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            addiu(T0, ZERO, 0x0001),
            mtc0(T0, 6),
            mtc0(ZERO, 4),
            jal(FN1_ADDR),
            nop(),
            mtc0(ZERO, 0),
            lui(A0, 0x007F),
            ori(A0, A0, 0xE000),
            lui(A1, 0x4000),
            lui(A2, 0x0000),
            lui(A3, 0x0040),
            jal(MAIN_ADDR),
            nop(),
            lui(T0, 0x4000),
            ori(T0, T0, 0x044C),
            jr(T0),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)

    def test_vigilante8(self):
        """Vigilante 8: sltu loop + j instruction (not tracked as main).
        Games: Vigilante 8
        """
        BSS_START = 0x80189B60
        BSS_END = 0x801D9B20
        MAIN_ADDR = 0x8012D260  # TODO: track j target as main_address
        STACK_TOP = 0x803FFFF0

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(V0, HI(BSS_START)),
            addiu(V0, V0, LO(BSS_START)),
            lui(V1, HI(BSS_END)),
            addiu(V1, V1, LO(BSS_END)),
            sw(ZERO, 0, V0),
            sltu(AT, V0, V1),
            bnez(AT, 0xFFFD),
            addiu(V0, V0, 4),
            j(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80125800)
        self.assertTrue(info.traditional_entrypoint)
        self.assertIsNone(info.main_address)
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertEqual(info.bss_end_address.value, BSS_END)

    def test_acclaim_jump(self):
        """Acclaim: bare j instruction (not recognized by parser).
        Games: WWF War Zone, WWF Attitude
        """
        MAIN_ADDR = 0x80000430  # TODO: track j target as main_address
        words = [
            j(MAIN_ADDR),
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
        STACK_BASE = 0x800C97D8
        RANGE1_START = 0x800B3210
        RANGE1_END = 0x800B57F0
        RANGE2_START = 0x800C97F0
        RANGE2_END = 0x8017E670
        RANGE3_START = 0x800C97F0
        RANGE3_END = 0x800C97F0
        PTR_ADDR = 0x80000318
        DEST_BASE = 0x8008CAB0
        KSEG0_BASE = 0x80000000
        MAGIC = 0x55555555
        FN1_ADDR = 0x800004A0
        MAIN_ADDR = 0x80050810

        words = [
            lui(A1, HI(STACK_BASE)),
            addiu(A1, A1, LO(STACK_BASE)),
            addu(SP, A1, ZERO),
            addu(FP, A1, ZERO),
            addiu(GP, ZERO, 0xFFFF),
            lui(A0, HI(RANGE1_START)),
            addiu(A0, A0, LO(RANGE1_START)),
            lui(A0, HI(RANGE1_END)),
            addiu(A0, A0, LO(RANGE1_END)),
            lui(A1, HI(RANGE2_START)),
            addiu(A1, A1, LO(RANGE2_START)),
            lui(A2, UHI(MAGIC)),
            ori(A2, A2, LO(MAGIC)),
            jal(FN1_ADDR),
            nop(),
            lui(A0, HI(RANGE2_START)),
            addiu(A0, A0, LO(RANGE2_START)),
            lui(A1, HI(RANGE2_END)),
            addiu(A1, A1, LO(RANGE2_END)),
            jal(FN1_ADDR),
            addu(A2, ZERO, ZERO),
            lui(A0, HI(RANGE3_START)),
            addiu(A0, A0, LO(RANGE3_START)),
            lui(A1, HI(RANGE3_END)),
            addiu(A1, A1, LO(RANGE3_END)),
            jal(FN1_ADDR),
            addu(A2, ZERO, ZERO),
            lui(A0, HI(PTR_ADDR)),
            addiu(A0, A0, LO(PTR_ADDR)),
            lui(S7, HI(DEST_BASE)),
            addiu(S7, S7, LO(DEST_BASE)),
            lw(T0, 0, A0),
            nop(),
            lui(AT, HI(KSEG0_BASE)),
            addu(T0, T0, AT),
            sw(T0, 0x002C, S7),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
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
        JUMP_ADDR = 0x80200480
        MAIN_ADDR = 0x802029F8
        STACK_TOP = 0x803FFF00

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
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            j(JUMP_ADDR),
            nop(),
            addiu(SP, SP, 0xFFE8),
            sw(RA, 0x0010, SP),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80280000)
        self.assertFalse(info.traditional_entrypoint)
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertEqual(info.stack_top.value, STACK_TOP)

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
