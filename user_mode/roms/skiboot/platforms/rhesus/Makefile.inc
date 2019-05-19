SUBDIRS += $(PLATDIR)/rhesus

RHESUS_OBJS = rhesus.o
RHESUS = $(PLATDIR)/rhesus/built-in.o
$(RHESUS): $(RHESUS_OBJS:%=$(PLATDIR)/rhesus/%)

