from util import options

def write_ldscript(sections):
    with open(options.get_ld_script_path(), "w", newline="\n") as f:
        f.write(
            "#ifndef SPLAT_BEGIN_SEG\n"
                "#ifndef SHIFT\n"
                    "#define SPLAT_BEGIN_SEG(name, start, vram, subalign) \\\n"
                    "    . = start;\\\n"
                    "    name##_ROM_START = .;\\\n"
                    "    name##_VRAM = ADDR(.name);\\\n"
                    "    .name vram : AT(name##_ROM_START) subalign {\n"
                "#else\n"
                    "#define SPLAT_BEGIN_SEG(name, start, vram, subalign) \\\n"
                    "    name##_ROM_START = .;\\\n"
                    "    name##_VRAM = ADDR(.name);\\\n"
                    "    .name vram : AT(name##_ROM_START) subalign {\n"
                "#endif\n"
            "#endif\n"
            "\n"
            "#ifndef SPLAT_END_SEG\n"
                "#ifndef SHIFT\n"
                    "#define SPLAT_END_SEG(name, end) \\\n"
                    "    } \\\n"
                    "    . = end;\\\n"
                    "    name##_ROM_END = .;\n"
                "#else\n"
                    "#define SPLAT_END_SEG(name, end) \\\n"
                    "    } \\\n"
                    "    name##_ROM_END = .;\n"
                "#endif\n"
            "#endif\n"
            "\n"
        )

        if options.get("ld_bare", False):
            f.write("\n".join(sections))
        else:
            f.write(
                "SECTIONS\n"
                "{\n"
                "    "
            )
            f.write("\n    ".join(s.replace("\n", "\n    ") for s in sections)[:-4])
            f.write(

                "    /DISCARD/ :\n"
                "    {\n"
                "        *(*);\n"
                "    }\n"
                "}\n"
            )
