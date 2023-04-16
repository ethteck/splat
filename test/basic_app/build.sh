mkdir -p build
echo "Building..."
/usr/local/bin/mips-elf-gcc main.c -o build/main.o
echo "Dumping bin..."
/usr/local/bin/mips-elf-objcopy build/main.o -O binary build/main.bin
