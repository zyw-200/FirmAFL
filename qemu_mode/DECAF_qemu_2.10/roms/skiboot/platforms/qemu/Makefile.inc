SUBDIRS += $(PLATDIR)/qemu

QEMU_OBJS = qemu.o
QEMU = $(PLATDIR)/qemu/built-in.o
$(QEMU): $(QEMU_OBJS:%=$(PLATDIR)/qemu/%)

