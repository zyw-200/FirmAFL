SUBDIRS += hw/ipmi

IPMI_OBJS  = ipmi-rtc.o ipmi-power.o ipmi-fru.o ipmi-sel.o
IPMI_OBJS += ipmi-watchdog.o ipmi-sensor.o ipmi-attn.o

IPMI = hw/ipmi/built-in.o
$(IPMI): $(IPMI_OBJS:%=hw/ipmi/%)
