# -*-Makefile-*-
# Sapphire EC makefile

SUBDIRS += hw/ec
EC_OBJS = gpio.o
EC=hw/ec/built-in.o

$(EC): $(EC_OBJS:%=hw/ec/%)
