ifeq ($(PORE),1)
LIBPORE_SRCS = p8_pore_table_gen_api_fixed.C
LIBPORE_SRCS += p8_pore_table_static_data.c sbe_xip_image.c pore_inline_assembler.c
LIBPORE_OBJS_1 = $(LIBPORE_SRCS:%.c=%.o)
LIBPORE_OBJS = $(LIBPORE_OBJS_1:%.C=%.o)
endif
SUBDIRS += libpore
LIBPORE = libpore/built-in.o

CFLAGS_SKIP_libpore/pore_inline_assembler.o=-Wsuggest-attribute=const

$(LIBPORE): $(LIBPORE_OBJS:%=libpore/%)

