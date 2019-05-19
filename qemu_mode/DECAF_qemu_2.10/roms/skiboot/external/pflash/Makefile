include rules.mk
GET_ARCH := ../../external/common/get_arch.sh
include ../../external/common/rules.mk

all: links arch_links $(EXE)

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(PFLASH_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

install: all $(INSTALLDEPS)
	install -D pflash $(DESTDIR)$(sbindir)/pflash

.PHONY: dist
#File is named $(PFLASH_VERSION).tar because the expectation is that pflash-
#is always at the start of the verion. This remains consistent with skiboot
#version strings
dist: links .version
	find -L ../pflash/ -iname '*.[ch]' -print0 | xargs -0 tar -rhf $(PFLASH_VERSION).tar
	tar --transform 's/Makefile.dist/Makefile/' -rhf $(PFLASH_VERSION).tar \
		../pflash/Makefile.dist ../pflash/rules.mk \
		../pflash/.version ../pflash/make_version.sh \
		../pflash/common/*

.PHONY: clean
clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d
.PHONY: distclean
distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan version.c .version .version.tmp
	rm -f common io.h
