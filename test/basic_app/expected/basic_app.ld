SECTIONS
{
    __romPos = 0;
    _gp = 0x0;
    basic_app_ROM_START = __romPos;
    basic_app_VRAM = ADDR(.basic_app);
    .basic_app 0x400000 : AT(basic_app_ROM_START) SUBALIGN(4)
    {
        basic_app_DATA_START = .;
        _MIPS_abiflags_abiflags__data__s = .;
        build/split/asm/data/.MIPS.abiflags.data.s.o(.data);
        basic_app_TEXT_START = .;
        build/split/src/do_switch.c.o(.text);
        build/split/asm/mymb.s.o(.text);
        build/split/src/main.c.o(.text);
        _2E8_data__s = .;
        build/split/asm/data/2E8.data.s.o(.data);
        basic_app_RODATA_START = .;
        build/split/asm/data/370.rodata.s.o(.rodata);
        basic_app_RODATA_END = .;
        basic_app_RODATA_SIZE = ABSOLUTE(basic_app_RODATA_END - basic_app_RODATA_START);
        build/split/asm/390.s.o(.text);
        basic_app_TEXT_END = .;
        basic_app_TEXT_SIZE = ABSOLUTE(basic_app_TEXT_END - basic_app_TEXT_START);
        bin_data_bin = .;
        build/split/assets/bin_data.bin.o(.data);
        basic_app_DATA_END = .;
        basic_app_DATA_SIZE = ABSOLUTE(basic_app_DATA_END - basic_app_DATA_START);
    }
    basic_app_bss_VRAM = ADDR(.basic_app_bss);
    .basic_app_bss (NOLOAD) : SUBALIGN(4)
    {
        basic_app_BSS_START = .;
        build/split/asm/data/completed.3751.bss.s.o(.bss);
        build/split/asm/data/dtor_idx.3753.bss.s.o(.bss);
        build/split/asm/data/object.3763.bss.s.o(.bss);
        basic_app_BSS_END = .;
        basic_app_BSS_SIZE = ABSOLUTE(basic_app_BSS_END - basic_app_BSS_START);
    }
    __romPos += SIZEOF(.basic_app);
    __romPos = ALIGN(__romPos, 16);
    basic_app_ROM_END = __romPos;
    basic_app_VRAM_END = .;

    /DISCARD/ :
    {
        *(*);
    }
}
