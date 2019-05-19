LIBFLASH_SRCS = libflash.c libffs.c ecc.c blocklevel.c
LIBFLASH_OBJS = $(LIBFLASH_SRCS:%.c=%.o)

SUBDIRS += libflash
LIBFLASH = libflash/built-in.o

$(LIBFLASH): $(LIBFLASH_OBJS:%=libflash/%)
