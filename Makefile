UTIL_DIR := util

default: all

all: Yay0Decompress

Yay0Decompress:
	gcc $(UTIL_DIR)/Yay0Decompress.c -fPIC -shared -O3 -o $(UTIL_DIR)/Yay0Decompress

clean:
	rm -f $(UTIL_DIR)/Yay0Decompress
