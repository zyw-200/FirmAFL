SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = palmetto.o habanero.o firestone.o garrison.o barreleye.o pnor.o common.o slots.o
ASTBMC = $(PLATDIR)/astbmc/built-in.o
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)

