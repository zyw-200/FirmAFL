SUBDIRS += $(PLATDIR)/mambo

MAMBO_OBJS = mambo.o
MAMBO = $(PLATDIR)/mambo/built-in.o
$(MAMBO): $(MAMBO_OBJS:%=$(PLATDIR)/mambo/%)

