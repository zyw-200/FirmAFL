# -*-Makefile-*-

SUBDIRS += ccan ccan/list ccan/str
CCAN_OBJS = list/list.o str/str.o
CCAN=ccan/built-in.o

$(CCAN): $(CCAN_OBJS:%=ccan/%)

