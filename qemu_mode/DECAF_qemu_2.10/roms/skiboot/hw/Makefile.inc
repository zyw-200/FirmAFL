# -*-Makefile-*-
SUBDIRS += hw
HW_OBJS  = xscom.o chiptod.o gx.o cec.o lpc.o lpc-uart.o psi.o
HW_OBJS += homer.o slw.o occ.o fsi-master.o centaur.o
HW_OBJS += nx.o nx-rng.o nx-crypto.o nx-842.o
HW_OBJS += p7ioc.o p7ioc-inits.o p7ioc-phb.o
HW_OBJS += phb3.o sfc-ctrl.o fake-rtc.o bt.o p8-i2c.o prd.o
HW_OBJS += dts.o lpc-rtc.o npu.o npu-hw-procedures.o xive.o phb4.o
HW=hw/built-in.o

# FIXME hack this for now
CFLAGS_hw/phb4.o = -Wno-unused-value -Wno-unused-parameter

include $(SRC)/hw/fsp/Makefile.inc
include $(SRC)/hw/ec/Makefile.inc
include $(SRC)/hw/ast-bmc/Makefile.inc
include $(SRC)/hw/ipmi/Makefile.inc

$(HW): $(HW_OBJS:%=hw/%) $(FSP) $(EC) $(AST_BMC) $(IPMI)
