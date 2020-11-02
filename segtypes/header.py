import os
from segtypes.segment import N64Segment
from pathlib import Path

class N64SegHeader(N64Segment):
    def should_run(self):
        return N64Segment.should_run(self) or "asm" in self.options["modes"]

    def split(self, rom_bytes, base_path):
        out_dir = self.create_split_dir(base_path, "asm")

        header_lines = []
        header_lines.append(f".section .{self.name}, \"a\"\n")

        pi_bsd = rom_bytes[0x00:0x04].hex().upper()
        clock_rate = rom_bytes[0x04:0x08].hex().upper()
        entry_point = rom_bytes[0x08:0x0C].hex().upper()
        release = rom_bytes[0x0C:0x10].hex().upper()
        crc1 = rom_bytes[0x10:0x14].hex().upper()
        crc2 = rom_bytes[0x14:0x18].hex().upper()
        unk1 = rom_bytes[0x18:0x1C].hex().upper()
        unk2 = rom_bytes[0x1C:0x20].hex().upper()
        name = rom_bytes[0x20:0x34].decode("ASCII").strip()
        unk3 = rom_bytes[0x34:0x38].hex().upper()
        cartridge = rom_bytes[0x38:0x3C].hex().upper()
        cartridge_id = rom_bytes[0x3C:0x3E].decode("ASCII").strip()
        country_code = rom_bytes[0x3E:0x3F].decode("ASCII").strip()
        version = rom_bytes[0x3F:0x40].hex().upper()

        header_lines.append(".word 0x" + pi_bsd + " /* PI PSD Domain 1 register */")
        header_lines.append(".word 0x" + clock_rate + " /* Clockrate setting */")
        header_lines.append(".word 0x" + entry_point + " /* Entrypoint address */")
        header_lines.append(".word 0x" + release + " /* Revision */")
        header_lines.append(".word 0x" + crc1 + " /* Checksum 1 */")
        header_lines.append(".word 0x" + crc2 + " /* Checksum 2 */")
        header_lines.append(".word 0x" + unk1 + " /* Unknown 1 */")
        header_lines.append(".word 0x" + unk2 + " /* Unknown 2 */")
        header_lines.append(".ascii \"" + name.ljust(20) + "\" /* Internal ROM name */")
        header_lines.append(".word 0x" + unk3 + " /* Unknown 3 */")
        header_lines.append(".word 0x" + cartridge + " /* Cartridge */")
        header_lines.append(".ascii \"" + cartridge_id + "\" /* Cartridge ID */")
        header_lines.append(".ascii \"" +  country_code + "\" /* Country code */")
        header_lines.append(".byte " +  version + " /* Version */")
        header_lines.append("")

        s_path = os.path.join(out_dir, self.name + ".s")
        Path(s_path).parent.mkdir(parents=True, exist_ok=True)
        with open(s_path, "w", newline="\n") as f:
            f.write("\n".join(header_lines))
        self.log(f"Wrote {self.name} to {s_path}")


    def get_ld_section_name(self):
        return self.name


    def get_ld_files(self):
        return [("asm", f"{self.name}.s", ".data")]


    @staticmethod
    def get_default_name(addr):
        return "header"
