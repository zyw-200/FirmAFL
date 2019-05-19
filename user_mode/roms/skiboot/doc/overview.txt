skiboot overview
================

skiboot is firmware, loaded by the FSP. Along with loading the bootloader,
it provides some runtime services to the OS (typically Linux).

Source layout
-------------
asm/	  small amount, mainly entry points
ccan/	  bits from CCAN
core/	  common code among machines.
doc/	  not enough here
external/ tools to run external of sapphire.
hdata/	  all stuff going to/from FSP
hw/ 	  drivers for things & fsp things.
include/  headers!
libc/ 	  tiny libc, from SLOF
libfdt/   straight device tree lib
libpore/  to manipulate PORE engine.

We have a spinlock implementation in asm/lock.S
Entry points are detailed in asm/head.S
The main C entry point is in core/init.c: main_cpu_entry()

Binaries
--------
The following binaries are built:

skiboot.lid: is the actual lid. objdump out
skiboot.elf: is the elf binary of it, lid comes from this
skiboot.map: plain map of symbols

Booting
-------

On boot, every thread of execution jumps to a single entry point in skiboot
so we need to do some magic to ensure we init things properly and don't stomp
on each other. We choose a master thread, putting everybody else into a
spinloop.

Essentially, we do this by doing an atomic fetch and inc and whoever gets 0
gets to be the master.

When we enter skiboot we also get a memory location in a register which
is the location of a device tree for the system. We fatten out the device
tree, turning offsets into real pointers and manipulating it where needed.
We re-flatten the device tree before booting the OS (Linux).

The main entry point is main_cpu_entry() in core/init.c, this is a carefully
ordered init of things. The sequence is relatively well documented there.

OS interface
------------

Skiboot maintains its own stack for each CPU. We do not have an ABI like
"may use X stack on OS stack", we entirely keep to our own stack space.
The OS (Linux) calling skiboot will never use any OS stack space and the OS
does not need to call skiboot with a valid stack.

We define an array of stacks, one for each CPU. On entry to skiboot,
we can find out stack by multiplying our CPU number by the stack size and
adding that to the address of the stack area.

At the bottom of each stack area is a per CPU data structure, which we
can get to by chopping off the LSBs of the stack pointer.

The OPAL interface is a generic message queue. The Linux side of things
can be found in linux/arch/powerpc/platform/powernv/opal-*.c

Interrupts
----------

We don't handle interrupts in skiboot.

In the future we may have to change to process machine check interrupts
during boot.

We do not have timer interrupts.


Memory
------

We initially occupy a chunk of memory, "heap". We pass to the OS (Linux)
a reservation of what we occupy (including stacks).

In the source file include/config.h we include a memory map. This is
manually generated, not automatically generated.

We use CCAN for a bunch of helper code, turning on things like DEBUG_LOCKS
and DEBUG_MALLOC as these are not a performance issue for us, and we like
to be careful.

In include/config.h there are defines for turning on extra tracing.
OPAL is what we name the interface from skiboot to OS (Linux).

Each CPU gets a 16k stack, which is probably more than enough. Stack
should be used sparingly though.

Important memory locations:

SKIBOOT_BASE - where we sit

HEAP_BASE,
HEAP_SIZE - the location and size for heap. We reserve 4MB for
	    initial allocations.

There is also SKIBOOT_SIZE (manually calculated) and DEVICE_TREE_MAX_SIZE,
which is largely historical.

Skiboot log
-----------

There is a circular log buffer that skiboot maintains. This can be
accessed either from the FSP or through /dev/mem or through a debugfs
patch that's currently floating around.
