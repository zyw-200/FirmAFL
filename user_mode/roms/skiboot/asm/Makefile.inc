# -*-Makefile-*-

SUBDIRS += asm 
ASM_OBJS = head.o lock.o misc.o kernel-wrapper.o
ASM=asm/built-in.o

# Add extra dependency to the kernel wrapper
kernel_wrapper.o : $(KERNEL)

$(ASM): $(ASM_OBJS:%=asm/%)

