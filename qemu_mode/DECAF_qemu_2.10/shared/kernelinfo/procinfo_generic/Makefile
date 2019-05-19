obj-m	:= procinfo.o
#KDIR	:= /lib/modules/$(shell uname -r)/build
#KDIR	:= /lib/modules/3.2.1/build
KDIR	:= /lib/modules/2.6.32.70/build
#KDIR	:= /lib/modules/4.1.17+/build
PWD	:= $(shell pwd)



default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -rf Module.markers modules.order Module.symvers

#make ARCH=mips CROSS_COMPILE=/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-
#make ARCH=arm CROSS_COMPILE=/opt/cross/arm-linux-musleabihf/bin/arm-linux-musleabihf-


