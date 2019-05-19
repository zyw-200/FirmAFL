# If you want to build in another directory copy this file there and
# fill in the following values

#
# Prefix of cross toolchain, if anything
# Example: CROSS= powerpc64-unknown-linux-gnu-
#
ARCH = $(shell uname -m)
ifdef CROSS_COMPILE
	CROSS ?= $(CROSS_COMPILE)
endif
ifeq ("$(ARCH)", "ppc64")
	CROSS ?=
else
	CROSS ?= powerpc64-linux-
endif

#
# Set to enable SLW bits
#
PORE ?= 1

#
# Optional location of embedded linux kernel file
# This can be a raw vmlinux, stripped vmlinux or
# zImage.epapr
#
KERNEL ?=

#
# Optional build with advanced stack checking
#
STACK_CHECK ?= 0

#
# Where is the source directory, must be a full path (no ~)
# Example: SRC= /home/me/skiboot
#
SRC=$(CURDIR)

#
# Where to get information about this machine (subdir name)
#
DEVSRC=hdata

#
# default config file, see include config_*.h for more specifics
#
CONFIG := config.h

include $(SRC)/Makefile.main

