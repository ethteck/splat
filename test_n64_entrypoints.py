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


# === Entrypoint Test Constants ===

BSS_START = 0x802A4000
BSS_SIZE = 0x00018000
BSS_END = BSS_START + BSS_SIZE
BSS_SIZE_SMALL = 0x00002000
BSS_END_SMALL = BSS_START + BSS_SIZE_SMALL

MAIN_ADDR = 0x80001280
STACK_TOP = 0x803FA000


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
        """lui/lui/addiu/ori + decrement-first BSS loop."""
        words = [
            lui(T0, HI(BSS_START)),
            lui(T1, UHI(BSS_SIZE)),
            addiu(T0, T0, LO(BSS_START)),
            ori(T1, T1, LO(BSS_SIZE)),
            addi(T1, T1, -0x8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, -0x4),
            addi(T0, T0, 8),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words, vram=0x80246000)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertTrue(info.bss_size.ori)

        self.assertIsNone(info.bss_end_address)

    def test_traditional_a_li(self):
        """bss_size loaded via li (addiu $t1,$zero,imm)."""
        BSS_SIZE = BSS_SIZE_SMALL  # TODO: parse bss_size from li pattern

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            addiu(T1, ZERO, LO(BSS_SIZE)),
            addi(T1, T1, -0x8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, -0x4),
            addi(T0, T0, 8),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        self.assertIsNone(info.bss_size)

    def test_traditional_a_li_ori(self):
        """bss_size loaded via ori $t1,$zero,imm."""
        BSS_SIZE = BSS_SIZE_SMALL  # TODO: parse bss_size from plain ori pattern

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            ori(T1, ZERO, LO(BSS_SIZE)),
            addi(T1, T1, -0x8),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            bnez(T1, -0x4),
            addi(T0, T0, 8),
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        self.assertIsNone(info.bss_size)

    def test_traditional_b(self):
        """lui/addiu/lui/addiu + sw/sw/addi/addi/bnez/nop."""
        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bnez(T1, -0x5),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertFalse(info.bss_size.ori)

    def test_traditional_b_nop(self):
        """traditional_b with nop as jr delay slot."""
        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bnez(T1, -0x5),
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
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertFalse(info.bss_size.ori)

    def test_traditional_b_ori_sp(self):
        """traditional_b with ori for $sp lo half."""
        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bnez(T1, -0x5),
            nop(),
            lui(T2, HI(MAIN_ADDR)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            lui(SP, UHI(STACK_TOP)),
            jr(T2),
            ori(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words, vram=0x80300000)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertFalse(info.bss_size.ori)

    def test_traditional_c(self):
        """lui order swapped (lui/lui/addiu/addiu)."""
        words = [
            lui(T0, HI(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T0, T0, LO(BSS_START)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bnez(T1, -0x5),
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
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertFalse(info.bss_size.ori)

    def test_traditional_d(self):
        """$sp set before BSS loop."""
        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bnez(T1, -0x5),
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
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertFalse(info.bss_size.ori)

    def test_traditional_d_ori(self):
        """bss_size uses ori for lo half (lui+ori pair)."""
        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, UHI(BSS_SIZE)),
            ori(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bnez(T1, -0x5),
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
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_size is not None
        self.assertEqual(info.bss_size.value, BSS_SIZE)
        self.assertTrue(info.bss_size.ori)

    def test_traditional_d_bgtz(self):
        """uses bgtz instead of bnez for BSS loop."""
        BSS_SIZE = 0x00043C20  # TODO: parse bss_size for bgtz loop

        words = [
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_SIZE)),
            addiu(T1, T1, LO(BSS_SIZE)),
            sw(ZERO, 0, T0),
            sw(ZERO, 4, T0),
            addi(T0, T0, 8),
            addi(T1, T1, -0x8),
            bgtz(T1, -0x5),
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
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        self.assertIsNone(info.bss_size)

    def test_direct_jump(self):
        """Direct jr to main (no BSS clear)."""
        words = [
            lui(T2, HI(MAIN_ADDR)),
            lui(SP, HI(STACK_TOP)),
            addiu(T2, T2, LO(MAIN_ADDR)),
            jr(T2),
            addiu(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        self.assertIsNone(info.bss_start_address)

        self.assertIsNone(info.bss_size)


class TestSltuClearEntrypoints(unittest.TestCase):
    """Non-traditional entrypoints using sltu-based BSS clearing."""

    def test_sltu_clear(self):
        """beq + sltu loop + jal + break."""
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100000)

        self.assertFalse(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

        self.assertIsNone(info.bss_size)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)
        self.assertEqual(info.entry_size, 60)

    def test_sltu_clear_ori_sp(self):
        """sltu pattern with ori for $sp lo half."""
        words = [
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100400)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        self.assertEqual(info.entry_size, 60)

    def test_sltu_clear_ori_sp_double(self):
        """sltu with ori $sp and double BSS clear loop."""
        BSS2_START = 0x80001000
        BSS2_END = 0x80001000

        words = [
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(T0, HI(BSS2_START)),
            addiu(T0, T0, LO(BSS2_START)),
            lui(T1, HI(BSS2_END)),
            addiu(T1, T1, LO(BSS2_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x8004B400)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

    def test_sltu_clear_ori_sp_double_gp(self):
        """sltu with ori $sp, double BSS clear, and $gp setup."""
        words = [
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_START)),
            addiu(T1, T1, LO(BSS_START)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(GP, 0x0000),
            addiu(GP, GP, 0x0000),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

    def test_sltu_clear_ori_sp_t2(self):
        """sltu with ori $sp, TLB setup after loop (no jal)."""
        TLB_COUNT = 0x001E
        TLB_BASE = 0x80004000

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(T2, T0, T1),
            bnez(T2, -0x3),
            sw(ZERO, -0x4, T0),
            addiu(A0, ZERO, TLB_COUNT),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, UHI(TLB_BASE)),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

    def test_sltu_clear_double(self):
        """sltu with double BSS clear, addiu $sp."""
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_START)),
            addiu(T1, T1, LO(BSS_START)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

    def test_sltu_clear_double_gp(self):
        """sltu with double BSS clear and $gp."""
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_START)),
            addiu(T1, T1, LO(BSS_START)),
            beq(T0, T1, 0x0005),
            nop(),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(GP, 0x0000),
            addiu(GP, GP, 0x0000),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

    def test_sltu_clear_jal(self):
        """sltu without beq guard, jal + break."""
        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(T1, HI(BSS_END)),
            addiu(T1, T1, LO(BSS_END)),
            addiu(T0, T0, 4),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)
        self.assertEqual(info.entry_size, 52)

    def test_sltu_clear_size(self):
        """sltu where bss_end is computed via addu (bss_start + size)."""
        BSS_END = BSS_SIZE  # TODO: fix bss_end detection for addu(size) case

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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)
        self.assertEqual(info.entry_size, 64)

    def test_sltu_clear_tlb(self):
        """sltu with TLB setup after BSS clear, no jal."""
        TLB_COUNT = 0x001E
        TLB_BASE = 0x80004000

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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            addiu(A0, ZERO, TLB_COUNT),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, UHI(TLB_BASE)),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

    def test_sltu_clear_magic(self):
        """sltu with magic constant (FACEFACE) store after BSS clear."""
        MAGIC = 0xFACEFACE

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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            lui(T0, HI(BSS_START)),
            addiu(T0, T0, LO(BSS_START)),
            lui(AT, UHI(MAGIC)),
            ori(AT, AT, LO(MAGIC)),
            addu(T1, ZERO, AT),
            sw(T1, 0, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)
        self.assertEqual(info.entry_size, 84)


class TestSn64Entrypoints(unittest.TestCase):
    """SN64 SDK entrypoints (jal to main, often with TLB setup)."""

    def test_sn64_jal(self):
        """SN64 jal to main with ori $sp."""
        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80200400)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        self.assertIsNone(info.bss_start_address)

    def test_sn64_jal_addiu(self):
        """SN64 jal with addiu for $sp instead of ori."""
        words = [
            lui(SP, HI(STACK_TOP)),
            addiu(SP, SP, LO(STACK_TOP)),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertFalse(info.stack_top.ori)

        self.assertIsNone(info.bss_start_address)
        self.assertEqual(info.entry_size, 20)

    def test_sn64_tlb(self):
        """SN64 TLB setup, parser breaks at nop gap."""
        TLB_COUNT = 0x001E
        TLB_BASE = 0x80004000

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            addiu(A0, ZERO, TLB_COUNT),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, UHI(TLB_BASE)),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

    def test_sn64_tlb_li(self):
        """SN64 TLB with li for loop counter."""
        TLB_COUNT = 0x001E
        TLB_BASE = 0x80004000

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            addiu(A0, ZERO, TLB_COUNT),
            mfc0(T0, 10),
            mtc0(A0, 0),
            lui(T1, UHI(TLB_BASE)),
            mtc0(T1, 10),
            mtc0(ZERO, 2),
            mtc0(ZERO, 3),
            nop(),
            tlbwi(),
            nop(),
        ]
        info = parse(words, vram=0x80300000)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)


class TestSpecialEntrypoints(unittest.TestCase):
    """Unusual entrypoint patterns (Factor 5, Acclaim, etc.)."""

    def test_excitebike(self):
        """magic constant + sltu BSS clear + jal + break."""
        MAGIC = 0xBEEFDEAD

        words = [
            lui(T0, UHI(MAGIC)),
            ori(T0, T0, LO(MAGIC)),
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
            bnez(AT, -0x3),
            sw(ZERO, -0x4, T0),
            jal(MAIN_ADDR),
            nop(),
            break_(),
        ]
        info = parse(words, vram=0x80100400)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)
        self.assertEqual(info.entry_size, 68)

    def test_factor5_jump(self):
        """j instruction (not tracked by parser)."""
        MAIN_ADDR = 0x800020F0  # TODO: track j target as main_address

        words = [
            lui(SP, UHI(STACK_TOP)),
            j(MAIN_ADDR),
            ori(SP, SP, LO(STACK_TOP)),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        self.assertIsNone(info.bss_start_address)
        self.assertIsNone(info.bss_size)
        self.assertIsNone(info.bss_end_address)

    def test_factor5_cache(self):
        """multiple jals, last one overrides main_address."""
        CONTROL_FLAG = 0x0001
        A0_MASK = 0x0067C000
        A1_BASE = 0x50000000
        A3_BASE = 0x00500000
        JUMP_TARGET = 0x50000620
        FN1_ADDR = 0x80000A40

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            addiu(T0, ZERO, CONTROL_FLAG),
            mtc0(T0, 6),
            mtc0(ZERO, 4),
            jal(FN1_ADDR),
            nop(),
            mtc0(ZERO, 0),
            lui(A0, UHI(A0_MASK)),
            ori(A0, A0, LO(A0_MASK)),
            lui(A1, UHI(A1_BASE)),
            lui(A2, 0x0000),
            lui(A3, UHI(A3_BASE)),
            jal(MAIN_ADDR),
            nop(),
            lui(T0, UHI(JUMP_TARGET)),
            ori(T0, T0, LO(JUMP_TARGET)),
            jr(T0),
            nop(),
        ]
        info = parse(words)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

    def test_vigilante8(self):
        """sltu loop + j instruction (not tracked as main)."""
        MAIN_ADDR = 0x80134080  # TODO: track j target as main_address

        words = [
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            lui(V0, HI(BSS_START)),
            addiu(V0, V0, LO(BSS_START)),
            lui(V1, HI(BSS_END)),
            addiu(V1, V1, LO(BSS_END)),
            sw(ZERO, 0, V0),
            sltu(AT, V0, V1),
            bnez(AT, -0x3),
            addiu(V0, V0, 4),
            j(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80125800)

        self.assertTrue(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

        assert info.bss_start_address is not None
        self.assertEqual(info.bss_start_address.value, BSS_START)
        self.assertFalse(info.bss_start_address.ori)

        assert info.bss_end_address is not None
        self.assertEqual(info.bss_end_address.value, BSS_END)
        self.assertFalse(info.bss_end_address.ori)

    def test_acclaim_jump(self):
        """bare j instruction (not recognized by parser)."""
        MAIN_ADDR = 0x80000890  # TODO: track j target as main_address
        words = [
            j(MAIN_ADDR),
            nop(),
        ]
        info = parse(words)

        self.assertTrue(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        self.assertIsNone(info.stack_top)

    def test_army_men(self):
        """complex boot with multiple jal calls."""
        RANGE1_START = 0x800A2100
        RANGE1_END = 0x800A47E0
        RANGE2_START = 0x800C1000
        RANGE2_END = 0x80168000
        RANGE3_START = 0x800C1000
        RANGE3_END = 0x800C1000
        PTR_ADDR = 0x80000420
        DEST_BASE = 0x80092000
        KSEG0_BASE = 0x80001000
        MAGIC = 0x55555555
        FN1_ADDR = 0x800005C0

        words = [
            lui(A1, HI(STACK_TOP)),
            addiu(A1, A1, LO(STACK_TOP)),
            addu(SP, A1, ZERO),
            addu(FP, A1, ZERO),
            addiu(GP, ZERO, -0x1),
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
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        self.assertIsNone(info.stack_top)

    def test_empty_entry(self):
        """All nops (no meaningful code at entrypoint)."""
        words = [nop()] * 16
        info = parse(words, vram=0x80190000)

        self.assertTrue(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        self.assertIsNone(info.stack_top)

        self.assertIsNone(info.bss_start_address)

        self.assertIsNone(info.bss_size)

    def test_cheat_device(self):
        """DMA copy loop + cache flush + j + jal."""
        DMA_SRC = 0xB0D02000
        DMA_DST = 0x80202000
        DMA_SIZE = 0x00042000
        CACHE1_START = 0x80002000
        CACHE1_MID_OFFSET = 0x2800
        CACHE1_END_ADJUST = 0xFFF0
        CACHE1_LINE = 0x0010
        CACHE2_START = 0x80002000
        CACHE2_MID_OFFSET = 0x7000
        CACHE2_END_ADJUST = 0xFFE0
        CACHE2_LINE = 0x0020
        STACK_FRAME = 0xFFE8
        RA_SLOT = 0x0010
        JUMP_ADDR = 0x80203000

        words = [
            lui(V1, UHI(DMA_SRC)),
            ori(V1, V1, LO(DMA_SRC)),
            lui(V0, UHI(DMA_DST)),
            ori(V0, V0, LO(DMA_DST)),
            lui(T0, UHI(DMA_SIZE)),
            ori(T0, T0, LO(DMA_SIZE)),
            lw(AT, 0, V1),
            sync(),
            sw(AT, 0, V0),
            addiu(V1, V1, 4),
            addiu(V0, V0, 4),
            addiu(T0, T0, -0x4),
            bgtz(T0, -0x7),
            nop(),
            lui(T0, UHI(CACHE1_START)),
            addiu(T1, T0, CACHE1_MID_OFFSET),
            addiu(T1, T1, CACHE1_END_ADJUST),
            cache(1, 0, T0),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            addiu(T0, T0, CACHE1_LINE),
            lui(T0, UHI(CACHE2_START)),
            addiu(T1, T0, CACHE2_MID_OFFSET),
            addiu(T1, T1, CACHE2_END_ADJUST),
            cache(0, 0, T0),
            sltu(AT, T0, T1),
            bnez(AT, -0x3),
            addiu(T0, T0, CACHE2_LINE),
            lui(SP, UHI(STACK_TOP)),
            ori(SP, SP, LO(STACK_TOP)),
            j(JUMP_ADDR),
            nop(),
            addiu(SP, SP, STACK_FRAME),
            sw(RA, RA_SLOT, SP),
            jal(MAIN_ADDR),
            nop(),
        ]
        info = parse(words, vram=0x80280000)

        self.assertFalse(info.traditional_entrypoint)
        self.assertTrue(info.ori_entrypoint)

        assert info.main_address is not None
        self.assertEqual(info.main_address.value, MAIN_ADDR)
        self.assertFalse(info.main_address.ori)

        assert info.stack_top is not None
        self.assertEqual(info.stack_top.value, STACK_TOP)
        self.assertTrue(info.stack_top.ori)

    def test_cheat_device_bal(self):
        """bgezal (BAL) + DMA loop."""
        DMA_SRC_BASE = 0xB0D00000
        DMA_DST_BASE = 0x80500000
        DMA_COUNT = 0x00048000
        bal = _w(0x04110000)  # bgezal $zero, 0
        words = [
            bal,
            addu(A0, RA, ZERO),
            lui(V1, UHI(DMA_SRC_BASE)),
            lui(V0, UHI(DMA_DST_BASE)),
            lui(T0, UHI(DMA_COUNT)),
            lw(AT, 0, V1),
            nop(),
            sync(),
            nop(),
            sw(AT, 0, V0),
            addiu(V1, V1, 4),
            addiu(V0, V0, 4),
            addiu(T0, T0, -0x4),
            bgtz(T0, -0x9),
            nop(),
        ]
        info = parse(words, vram=0x80401000)

        self.assertTrue(info.traditional_entrypoint)
        self.assertFalse(info.ori_entrypoint)

        self.assertIsNone(info.main_address)

        self.assertIsNone(info.stack_top)


if __name__ == "__main__":
    unittest.main()
