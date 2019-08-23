# FIRM-AFL

FIRM-AFL is the first high-throughput greybox fuzzer for IoT firmware. FIRM-AFL addresses two fundamental problems in IoT fuzzing. First, it addresses compatibility issues by enabling fuzzing for POSIX-compatible firmware that can be emulated in a system emulator. Second, it addresses the performance bottleneck caused by system-mode emulation with a novel technique called "augmented process emulation". By combining system-mode emulation and user-mode emulation in a novel way, augmented process emulation provides high compatibility as system-mode emulation and high throughput as user-mode emulation. 

## Publication

Yaowen Zheng, Ali Davanian, Heng Yin, Chengyu Song, Hongsong Zhu, Limin Sun, “FIRM-AFL: High-throughput greybox fuzzing of IoT firmware via augmented process emulation,” in USENIX Security Symposium, 2019.

## Introduction

FIRM-AFL is the first high-throughput greybox fuzzer for IoT firmware. FIRM-AFL addresses two fundamental problems in IoT fuzzing. First, it addresses compatibility issues by enabling fuzzing for POSIX-compatible firmware that can be emulated in a system emulator. Second, it addresses the performance bottleneck caused by system-mode emulation with a novel technique called "augmented process emulation". By combining system-mode emulation and user-mode emulation in a novel way, augmented process emulation provides high compatibility as system-mode emulation and high throughput as user-mode emulation. The overview is show in Figure 1.

<div align=center><img src="https://github.com/zyw-200/FirmAFL/raw/master/image/augmented_process_emulation.png" width=70% height=70% /></div>

<div align=center>Figure 1. Overview of Augmented Process Emulation</div>

&nbsp;

We design and implement FIRM-AFL, an enhancement of AFL for fuzzing IoT firmware. We keep the workflow of AFL intact and replace the user-mode QEMU with augmented process emulation, and the rest of the components remain unchanged. The new workflow is illustrated in Figure 2.

<div align=center><img src="https://github.com/zyw-200/FirmAFL/raw/master/image/overview_of_FirmAFL.png" width=70% height=70% /></div>

<div align=center>Figure 2. Overview of FIRM-AFL</div>


## Setup

Our system has two parts: system mode and user mode. We compile them separately for now.

### User mode 
	cd user_mode/
	./configure --target-list=mipsel-linux-user,mips-linux-user,arm-linux-user --static --disable-werror
	make

### System mode
	cd qemu_mode/DECAF_qemu_2.10/
	./configure --target-list=mipsel-softmmu,mips-softmmu,arm-softmmu --disable-werror
	make

## Usage

1.  Setup the firmadyne including importing its datasheet https://cmu.app.boxcn.net/s/hnpvf1n72uccnhyfe307rc2nb9rfxmjp into database.

2.  Replace the scripts/makeImage.sh with modified one in firmadyne_modify directory.

3.  follow the guidance from firmadyne to generate the system running scripts. 
>Take DIR-815 router firmware as a example,

	./sources/extractor/extractor.py -b dlink -sql 127.0.0.1 -np -nk "../firmware/DIR-815_FIRMWARE_1.01.ZIP" images
	./scripts/getArch.sh ./images/9050.tar.gz
	./scripts/makeImage.sh 9050
	./scripts/inferNetwork.sh 9050
	python FirmAFL_setup.py 9050 mipsel

4. modify the run.sh manually as following,  in order to emulate firmware with our modified QEMU and kernel, and running on the RAM file.
>For mipsel,

	ARCH=mipsel
	QEMU="./qemu-system-${ARCH}"
	KERNEL="./vmlinux.${ARCH}_3.2.1" 
	IMAGE="./image.raw"
	MEM_FILE="./mem_file"
	${QEMU} -m 256 -mem-prealloc -mem-path ${MEM_FILE} -M ${QEMU_MACHINE} -kernel ${KERNEL} \ 
>For mipseb,

	ARCH=mips
	QEMU="./qemu-system-${ARCH}"
	KERNEL="./vmlinux.${ARCH}_3.2.1" 
	IMAGE="./image.raw"
	MEM_FILE="./mem_file"
	${QEMU} -m 256 -mem-prealloc -mem-path ${MEM_FILE} -M ${QEMU_MACHINE} -kernel ${KERNEL} \

5. run the fuzzing process
>after running the start.py script, FirmAFL will start the firmware emulation, and after the system initialization(120s), the fuzzing process will start.

	cd image_9050
	python start.py 9050



## Related Work

Our system is built on top of TriforceAFL, DECAF, AFL, and Firmadyne.

**TriforceAFL:** AFL/QEMU fuzzing with full-system emulation, https://github.com/nccgroup/TriforceAFL.

**DECAF:** "Make it work, make it right, make it fast: building a platform-neutral whole-system dynamic binary analysis platform", Andrew Henderson, Aravind Prakash, Lok Kwong Yan, Xunchao Hu, Xujiewen Wang, Rundong Zhou, and Heng Yin, to appear in the International Symposium on Software Testing and Analysis (ISSTA'14), San Jose, CA, July 2014. https://github.com/sycurelab/DECAF.

**AFL:** american fuzzy lop (2.52b), http://lcamtuf.coredump.cx/afl/.

**Firmadyne:** Daming D. Chen, Maverick Woo, David Brumley, and Manuel Egele. “Towards automated dynamic analysis for Linux-based embedded firmware,” in Network and Distributed System Security Symposium (NDSS’16), 2016. https://github.com/firmadyne.