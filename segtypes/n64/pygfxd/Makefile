LIBGFXD := libgfxd
CC := gcc
CPPFLAGS := -fPIC

export

all:
	$(MAKE) -C $(LIBGFXD)
	gcc -shared -o $(LIBGFXD).so -Wl,--whole-archive $(LIBGFXD)/$(LIBGFXD).a -Wl,--no-whole-archive

clean:
	$(RM) $(LIBGFXD).so
	$(MAKE) -C $(LIBGFXD) clean
