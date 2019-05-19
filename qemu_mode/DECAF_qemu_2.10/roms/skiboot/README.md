# skiboot

Firmware for OpenPower systems.

Source: https://github.com/open-power/skiboot

Mailing list: skiboot@lists.ozlabs.org

Info/subscribe: https://lists.ozlabs.org/listinfo/skiboot

Archives: https://lists.ozlabs.org/pipermail/skiboot/

Patchwork: http://patchwork.ozlabs.org/project/skiboot/list/

## Overview
OPAL firmware (OpenPower Abstraction Layer) comes in several parts.

A simplified flow of what happens when the power button is pressed is:

1. The baseboard management controller (BMC) powers the system on.
2. The BMC selects the master chip and releases the self-boot engines (SBEs)
   on the POWER8 chips, master last.
3. The BMC relinquishes control of the flexible service interface (FSI)
   SCAN/SCOM engines.
4. The hostboot firmware IPLs the system. It initiates a secondary power-on
   sequence through a digital power systems sweep (DPSS).
5. The hostboot firmware loads the OPAL image and moves all processors to
   their execution starting points.

Here, the OPAL image is three parts:

1. skiboot (includes OPAL runtime services)
2. skiroot - the bootloader environment
   * kernel
   * initramfs (containing petitboot bootloader)

They may be all part of one payload or three separate images (depending on
platform).

The bootloader will kexec a host kernel (probably linux). The host OS can
make OPAL calls. The OPAL API is documented in doc/opal-api/ (there are
missing parts, patches are welcome!)

See doc/overview.txt for a more in depth overview of skiboot.

## Building
You can build on a linux host. Modern Debian and Ubuntu are well known
to be suitable. Build and testing on x86 is fine. You do not need a POWER
host to build and test skiboot.

You will need a C compiler for big endian ppc64. If your distro does
not provide one, crosstool built compilers work well:
https://www.kernel.org/pub/tools/crosstool/

You should then be able to just (where 4=nr cpu cores of your machine)

```
make -j4
make -j4 check
```

If using crosstool compilers, add /opt/cross/gcc-4.8.0-nolibc/powerpc64-linux/bin/
to your PATH.

If using packaged cross compilers on Ubuntu, you may need to set the
following environment variable:
CROSS=powerpc-linux-gnu-

## Testing
To test in a simulator, install the IBM POWER8 Functional Simulator from:
http://www-304.ibm.com/support/customercare/sas/f/pwrfs/home.html
Also see external/mambo/README.md

Qemu (as of 2.2.0) is not suitable as it does not (yet) implement
the HyperVisor mode of the POWER8 processor.
See https://www.flamingspork.com/blog/2015/08/28/running-opal-in-qemu-the-powernv-platform/ for instructions on how to use a work-in-progress patchset
to qemu that may be suitable for some work.

To run a boot-to-bootloader test, you'll need a zImage.papr built using
the mambo_defconfig config for op-build. See
https://github.com/open-power/op-build/ on howto build. Drop zImage.epapr
in the skiboot directory and the skiboot test suite will automatically pick
it up.

See opal-ci/README for further testing instructions.

To test on real hardware, you will need to understand how to flash new
skiboot onto your system. This will vary from platform to platform.

You may want to start with external/boot-tests/boot_test.sh as it can
(provided the correct usernames/passwords) automatically flash a new
skiboot onto ASTBMC based OpenPower machines.

## Hacking

All patches should be sent to the mailing list with linux-kernel style
'Signed-Off-By'. The following git commands are your friends:
```
git commit -s
git format-patch
```

You probably want to read the linux Documentation/SubmittingPatches as
much of it applies to skiboot.

## License

See LICENSE