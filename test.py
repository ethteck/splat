from split import *
import unittest
import io
import filecmp
import pprint
from util import symbols, options
import spimdisasm


class Testing(unittest.TestCase):
    def compare_files(self, test_path, ref_path):
        with io.open(test_path) as test_f, io.open(ref_path) as ref_f:
            self.assertListEqual(list(test_f), list(ref_f))

    def get_same_files(self, dcmp, out):
        for name in dcmp.same_files:
            out.append((name, dcmp.left, dcmp.right))

        for sub_dcmp in dcmp.subdirs.values():
            self.get_same_files(sub_dcmp, out)

    def get_diff_files(self, dcmp, out):
        for name in dcmp.diff_files:
            out.append((name, dcmp.left, dcmp.right))

        for sub_dcmp in dcmp.subdirs.values():
            self.get_diff_files(sub_dcmp, out)

    def test_basic_app(self):
        main(["test/basic_app/splat.yaml"], None, None)

        comparison = filecmp.dircmp("test/basic_app/split", "test/basic_app/expected")

        diff_files: List[Tuple[str, str, str]] = []
        self.get_diff_files(comparison, diff_files)

        same_files: List[Tuple[str, str, str]] = []
        self.get_same_files(comparison, same_files)

        print("same_files", same_files)
        print("diff_files", diff_files)

        assert len(diff_files) == 0


class Symbols(unittest.TestCase):
    def test_check_valid_type(self):
        # first char is uppercase
        assert symbols.check_valid_type("Symbol") == True

        splat_sym_types = {"func", "jtbl", "jtbl_label", "label"}

        for type in splat_sym_types:
            assert symbols.check_valid_type(type) == True

        spim_types = [
            "char*",
            "u32",
            "Vec3f",
            "u8",
            "char",
            "u16",
            "f32",
            "u64",
            "asciz",
            "s8",
            "s64",
            "f64",
            "s16",
            "s32",
        ]

        for type in spim_types:
            assert symbols.check_valid_type(type) == True

    def test_add_symbol_to_spim_segment(self):
        context = None
        vromStart = 0x0
        vromEnd = 0x10
        vramStart = 0x40000000 + 0x0
        vramEnd = 0x40000000 + 0x10
        segment = spimdisasm.common.SymbolsSegment(
            context=context,
            vromStart=vromStart,
            vromEnd=vromEnd,
            vramStart=vramStart,
            vramEnd=vramEnd,
        )
        sym = symbols.Symbol(0x40000000)
        sym.user_declared = False
        sym.defined = True
        sym.rom = 0x0
        sym.type = "func"
        result = symbols.add_symbol_to_spim_segment(segment, sym)
        assert result.type == spimdisasm.common.SymbolSpecialType.function
        assert sym.user_declared == result.isUserDeclared
        assert sym.defined == result.isDefined

    def test_add_symbol_to_spim_section(self):
        context = spimdisasm.common.Context()
        section = spimdisasm.mips.sections.SectionBase(
            context=context,
            vromStart=0x100,
            vromEnd=None,
            vram=None,
            filename=None,
            words=None,
            sectionType=None,
            segmentVromStart=None,
            overlayCategory=None,
        )
        sym = symbols.Symbol(0x100)
        sym.type = "func"
        sym.user_declared = False
        sym.defined = True
        result = symbols.add_symbol_to_spim_section(section, sym)
        assert result.type == spimdisasm.common.SymbolSpecialType.function
        assert sym.user_declared == result.isUserDeclared
        assert sym.defined == result.isDefined

    def test_create_symbol_from_spim_symbol(self):
        rom_start = 0x0
        rom_end = 0x100
        type = "func"
        name = "MyFunc"
        vram_start = 0x40000000
        args = None
        yaml = None

        # need to init otherwise options.opts isn't defined.
        # used in initializing a Segment
        options_dict = {
            "options": {
                "platform": "n64",
                "basename": "basic_app",
                "base_path": ".",
                "build_path": "build",
                "target_path": "build/main.bin",
                "asm_path": "split/asm",
                "src_path": "split/src",
                "ld_script_path": "split/basic_app.ld",
                "cache_path": "split/.splache",
                "symbol_addrs_path": "split/generated.symbols.txt",
                "undefined_funcs_auto_path": "split/undefined_funcs_auto.txt",
                "undefined_syms_auto_path": "split/undefined_syms_auto.txt",
            },
            "segments": [
                {
                    "name": "basic_app",
                    "type": "code",
                    "start": 0,
                    "vram": 4194304,
                    "subalign": 4,
                    "subsegments": [[0, "data"], [476, "c", "main"], [508, "data"]],
                },
                [4752],
            ],
        }
        options.initialize(options_dict, ["./test/basic_app/splat.yaml"], [], False)
        segment = Segment(
            rom_start=rom_start,
            rom_end=rom_end,
            type=type,
            name=name,
            vram_start=vram_start,
            args=[],
            yaml=yaml,
        )
        context_sym = spimdisasm.common.ContextSymbol(address=0)
        result = symbols.create_symbol_from_spim_symbol(segment, context_sym)
        assert result.referenced == True
        assert result.extract == True
        assert result.name == "D_0"


if __name__ == "__main__":
    unittest.main()
