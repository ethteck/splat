from segtypes.n64.segment import N64Segment
from util import options
from util.color import unpack_color
from util.iter import iter_in_groups
from util import log

class N64SegPalette(N64Segment):
    require_unique_name = False

    def __init__(self, segment, rom_start, rom_end):
        super().__init__(segment, rom_start, rom_end)

        # palette segments must be named as one of the following:
        #  1) same as the relevant ci4/ci8 segment name (max. 1 palette)
        #  2) relevant ci4/ci8 segment name + "." + unique palette name
        #  3) unique, referencing the relevant ci4/ci8 segment using `image_name`
        self.image_name = segment.get("image_name", self.name.split(
            ".")[0]) if type(segment) is dict else self.name.split(".")[0]

        if self.max_length():
            expected_len = int(self.max_length())
            actual_len = self.rom_end - self.rom_start
            if actual_len > expected_len and actual_len - expected_len > self.subalign:
                log.error(f"Error: {self.name} should end at 0x{self.rom_start + expected_len:X}, but it ends at 0x{self.rom_end:X}\n(hint: add a 'bin' segment after it)")

    def should_split(self):
        return super().should_split() or (
            options.mode_active("img") or
            options.mode_active("ci4") or
            options.mode_active("ci8") or
            options.mode_active("i4") or
            options.mode_active("i8") or
            options.mode_active("ia4") or
            options.mode_active("ia8") or
            options.mode_active("ia16")
        )

    def split(self, rom_bytes):
        self.path = options.get_asset_path() / self.dir / (self.name + ".png")

        data = rom_bytes[self.rom_start: self.rom_end]

        self.palette = N64SegPalette.parse_palette(data)

    @staticmethod
    def parse_palette(data):
        palette = []

        for a, b in iter_in_groups(data, 2):
            palette.append(unpack_color([a, b]))

        return palette

    def max_length(self):
        return 256 * 2

    def get_linker_entries(self):
        from segtypes.linker_entry import LinkerEntry

        return [LinkerEntry(
            self,
            [options.get_asset_path() / self.dir / f"{self.name}.png"],
            options.get_asset_path() / self.dir / f"{self.name}.pal",
            ".data"
        )]
