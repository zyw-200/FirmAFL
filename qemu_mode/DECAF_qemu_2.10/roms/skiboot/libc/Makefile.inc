LIBCDIR = libc

SUBDIRS += $(LIBCDIR)
LIBC = $(LIBCDIR)/built-in.o $(LIBCDIR)/time.o

include $(SRC)/$(LIBCDIR)/string/Makefile.inc
include $(SRC)/$(LIBCDIR)/ctype/Makefile.inc
include $(SRC)/$(LIBCDIR)/stdlib/Makefile.inc
include $(SRC)/$(LIBCDIR)/stdio/Makefile.inc

$(LIBC): $(STRING) $(CTYPE) $(STDLIB) $(STDIO)
