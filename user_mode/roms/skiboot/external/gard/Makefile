# This tool is a linux userland tool and should be completely stand alone
include rules.mk
GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

all: links arch_links $(EXE)

#Rebuild version.o so that the the version always matches
#what the test suite will get from ./make_version.sh
check: version.o all
	@ln -sf ../../test/test.sh test/test.sh
	@test/test-gard

links += make_version.sh

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(GARD_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

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

clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d .version .version.tmp

distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan common io.h make_version.sh

