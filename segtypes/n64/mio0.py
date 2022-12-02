from util import log, options
from util.n64.Mio0decompress import Mio0Decompressor

from segtypes.n64.segment import N64Segment


class N64SegMio0(N64Segment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # allow extensions to override this
        self.decompressor = Mio0Decompressor()

    def split(self, rom_bytes):
        out_dir = options.opts.asset_path / self.dir
        out_dir.mkdir(parents=True, exist_ok=True)

        if self.rom_end == "auto":
            log.error(
                f"segment {self.name} needs to know where it ends; add a position marker [0xDEADBEEF] after it"
            )

        out_path = out_dir / f"{self.name}.bin"
        with open(out_path, "wb") as f:
            assert isinstance(self.rom_start, int)
            assert isinstance(self.rom_end, int)

            self.log(f"Decompressing {self.name}")
            compressed_bytes = rom_bytes[self.rom_start : self.rom_end]
            decompressed_bytes = self.decompressor.decompress(compressed_bytes)
            f.write(decompressed_bytes)
        self.log(f"Wrote {self.name} to {out_path}")

    def get_linker_entries(self):
        from segtypes.linker_entry import LinkerEntry

        return [
            LinkerEntry(
                self,
                [options.opts.asset_path / self.dir / f"{self.name}.bin"],
                options.opts.asset_path / self.dir / f"{self.name}.Mio0",
                self.get_linker_section(),
            )
        ]
