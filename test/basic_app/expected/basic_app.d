build/basic_app_target.elf: \
    build/asm/header.o \
    build/assets/dummy_ipl3.o \
    build/src/main.o \
    build/asm/handwritten.o \
    build/asm/data/main.data.o \
    build/asm/data/main.bss.o
build/asm/header.o:
build/assets/dummy_ipl3.o:
build/src/main.o:
build/asm/handwritten.o:
build/asm/data/main.data.o:
build/asm/data/main.bss.o:
-include build/asm/header.d build/assets/dummy_ipl3.d build/src/main.d build/asm/handwritten.d build/asm/data/main.data.d build/asm/data/main.bss.d
