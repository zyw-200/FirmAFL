HOSTEND=$(shell uname -m | sed -e 's/^i.*86$$/LITTLE/' -e 's/^x86.*/LITTLE/' -e 's/^ppc.*/BIG/')
CFLAGS=-g -Wall -DHAVE_$(HOSTEND)_ENDIAN -I../../include

dump_trace: dump_trace.c

clean:
	rm -f dump_trace *.o
