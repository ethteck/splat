echo "Building..."
/usr/local/bin/mips-elf-gcc main.c -o main.o
echo "Dumping bin..."
/usr/local/bin/mips-elf-objcopy main.o -O binary main.bin
