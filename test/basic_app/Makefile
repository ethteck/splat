BUILD_FOLDER    := build
KMC_FOLDER      := gcc-2.7.2
CROSS           := mips-linux-gnu-


ROM             := $(BUILD_FOLDER)/basic_app.bin

## Programs

CC              := COMPILER_PATH=$(KMC_FOLDER) $(KMC_FOLDER)/gcc
LD              := $(CROSS)ld
OBJCOPY         := $(CROSS)objcopy


## Programs' flags

CFLAGS          := -G0 -mgp32 -mfp32 -mips3


# Targets

all: $(ROM)

download_kmc: $(KMC_FOLDER)/gcc

clean:
	$(RM) -rf $(BUILD_FOLDER)
	$(RM) -rf split

.PHONY: all download_kmc clean
.DEFAULT_GOAL := all
# Prevent removing intermediate files
.SECONDARY:


## Files

O_FILES         := $(BUILD_FOLDER)/main.o $(BUILD_FOLDER)/header.o $(BUILD_FOLDER)/handwritten.o $(BUILD_FOLDER)/dummy_ipl3.o

o_files: $(O_FILES)
.PHONY: o_files

## Rules

%.bin: %.elf
	$(OBJCOPY) $< -O binary $@ --pad-to=0x1140 --gap-fill=0x00

$(BUILD_FOLDER)/%.elf: $(O_FILES) %.ld | $(BUILD_FOLDER)
	$(LD) -Map $(@:.elf=.map) -T $*.ld -o $@ $(O_FILES)

$(BUILD_FOLDER)/%.o: %.s | $(BUILD_FOLDER)
	$(CC) -EB -c $(CFLAGS) -o $@ $<

$(BUILD_FOLDER)/%.o: %.c | $(BUILD_FOLDER)
	$(CC) -EB -c $(CFLAGS) -o $@ $<


$(KMC_FOLDER)/gcc:
	$(RM) -rf $(KMC_FOLDER)
	wget https://github.com/decompals/mips-binutils-2.6/releases/latest/download/binutils-2.6-linux.tar.gz
	wget https://github.com/decompals/mips-gcc-2.7.2/releases/latest/download/gcc-2.7.2-linux.tar.gz
	mkdir -p $(KMC_FOLDER)
	tar -xvf binutils-2.6-linux.tar.gz -C $(KMC_FOLDER)
	tar -xvf gcc-2.7.2-linux.tar.gz -C $(KMC_FOLDER)
	$(RM) -rf binutils-2.6-linux.tar.gz
	$(RM) -rf gcc-2.7.2-linux.tar.gz


## Folders to create

$(BUILD_FOLDER):
	mkdir -p $(BUILD_FOLDER)


# Print target for debugging
print-% : ; $(info $* is a $(flavor $*) variable set to [$($*)]) @true
