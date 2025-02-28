SECTIONS
{
    __romPos = 0;
    header_ROM_START = __romPos;
    header_VRAM = ADDR(.header);
    .header : AT(header_ROM_START) SUBALIGN(16)
    {
        FILL(0x00000000);
        header_DATA_START = .;
        build/asm/header.o(.data);
        header_DATA_END = .;
        header_DATA_SIZE = ABSOLUTE(header_DATA_END - header_DATA_START);
    }
    __romPos += SIZEOF(.header);
    header_ROM_END = __romPos;
    header_VRAM_END = .;

    dummy_ipl3_ROM_START = __romPos;
    dummy_ipl3_VRAM = ADDR(.dummy_ipl3);
    .dummy_ipl3 0xA4000040 : AT(dummy_ipl3_ROM_START) SUBALIGN(16)
    {
        FILL(0x00000000);
        dummy_ipl3_DATA_START = .;
        build/assets/dummy_ipl3.o(.data);
        . = ALIGN(., 16);
        dummy_ipl3_DATA_END = .;
        dummy_ipl3_DATA_SIZE = ABSOLUTE(dummy_ipl3_DATA_END - dummy_ipl3_DATA_START);
    }
    __romPos += SIZEOF(.dummy_ipl3);
    __romPos = ALIGN(__romPos, 16);
    . = ALIGN(., 16);
    dummy_ipl3_ROM_END = __romPos;
    dummy_ipl3_VRAM_END = .;

    boot_ROM_START = __romPos;
    boot_VRAM = ADDR(.boot);
    .boot 0x80000400 : AT(boot_ROM_START) SUBALIGN(16)
    {
        FILL(0x00000000);
        boot_TEXT_START = .;
        build/src/main.o(.text);
        build/asm/handwritten.o(.text);
        . = ALIGN(., 16);
        boot_TEXT_END = .;
        boot_TEXT_SIZE = ABSOLUTE(boot_TEXT_END - boot_TEXT_START);
        boot_DATA_START = .;
        build/asm/data/main.data.o(.data);
        build/asm/handwritten.o(.data);
        . = ALIGN(., 16);
        boot_DATA_END = .;
        boot_DATA_SIZE = ABSOLUTE(boot_DATA_END - boot_DATA_START);
        boot_RODATA_START = .;
        build/src/main.o(.rodata);
        build/asm/handwritten.o(.rodata);
        . = ALIGN(., 16);
        boot_RODATA_END = .;
        boot_RODATA_SIZE = ABSOLUTE(boot_RODATA_END - boot_RODATA_START);
    }
    boot_bss_VRAM = ADDR(.boot_bss);
    .boot_bss (NOLOAD) : SUBALIGN(16)
    {
        FILL(0x00000000);
        boot_BSS_START = .;
        build/asm/data/main.bss.o(.bss);
        build/asm/handwritten.o(.bss);
        . = ALIGN(., 16);
        boot_BSS_END = .;
        boot_BSS_SIZE = ABSOLUTE(boot_BSS_END - boot_BSS_START);
    }
    __romPos += SIZEOF(.boot);
    __romPos = ALIGN(__romPos, 16);
    . = ALIGN(., 16);
    boot_ROM_END = __romPos;
    boot_VRAM_END = .;

    /DISCARD/ :
    {
        *(*);
    }
}
