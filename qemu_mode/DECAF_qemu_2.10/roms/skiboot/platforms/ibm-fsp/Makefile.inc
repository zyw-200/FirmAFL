SUBDIRS += $(PLATDIR)/ibm-fsp

IBM_FSP_OBJS = common.o lxvpd.o apollo.o apollo-pci.o \
	       firenze.o firenze-pci.o
IBM_FSP = $(PLATDIR)/ibm-fsp/built-in.o
$(IBM_FSP): $(IBM_FSP_OBJS:%=$(PLATDIR)/ibm-fsp/%)

