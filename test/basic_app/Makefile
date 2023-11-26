KMC_FOLDER := gcc-2.7.2

download_kmc:
	$(RM) -rf $(KMC_FOLDER)
	wget https://github.com/decompals/mips-binutils-2.6/releases/latest/download/binutils-2.6-linux.tar.gz
	wget https://github.com/decompals/mips-gcc-2.7.2/releases/latest/download/gcc-2.7.2-linux.tar.gz
	mkdir -p $(KMC_FOLDER)
	tar -xvf binutils-2.6-linux.tar.gz -C $(KMC_FOLDER)
	tar -xvf gcc-2.7.2-linux.tar.gz -C $(KMC_FOLDER)
	$(RM) -rf binutils-2.6-linux.tar.gz
	$(RM) -rf gcc-2.7.2-linux.tar.gz

clean:
	$(RM) -rf ./build
	$(RM) -rf ./split

.PHONY: download_kmc clean
