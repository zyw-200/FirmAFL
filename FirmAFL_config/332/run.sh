#!/bin/bash

set -u

ARCHEND=armel
IID=332

if [ -e ./firmadyne.config ]; then
    source ./firmadyne.config
elif [ -e ../firmadyne.config ]; then
    source ../firmadyne.config
elif [ -e ../../firmadyne.config ]; then
    source ../../firmadyne.config
else
    echo "Error: Could not find 'firmadyne.config'!"
    exit 1
fi

IMAGE=`get_fs ${IID}`
KERNEL=`get_kernel ${ARCHEND}`
QEMU=`get_qemu ${ARCHEND}`
QEMU_MACHINE=`get_qemu_machine ${ARCHEND}`
QEMU_ROOTFS=`get_qemu_disk ${ARCHEND}`
WORK_DIR=`get_scratch ${IID}`


TAPDEV_0=tap${IID}_0
HOSTNETDEV_0=${TAPDEV_0}
echo "Creating TAP device ${TAPDEV_0}..."
sudo tunctl -t ${TAPDEV_0} -u ${USER}


echo "Initializing VLAN..."
HOSTNETDEV_0=${TAPDEV_0}.1
sudo ip link add link ${TAPDEV_0} name ${HOSTNETDEV_0} type vlan id 1
sudo ip link set ${TAPDEV_0} up


echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_0} up
sudo ip addr add 192.168.1.2/24 dev ${HOSTNETDEV_0}

echo "Adding route to 192.168.1.1..."
sudo ip route add 192.168.1.1 via 192.168.1.1 dev ${HOSTNETDEV_0}


function cleanup {
    pkill -P $$
    
echo "Deleting route..."
sudo ip route flush dev ${HOSTNETDEV_0}

echo "Bringing down TAP device..."
sudo ip link set ${TAPDEV_0} down


echo "Removing VLAN..."
sudo ip link delete ${HOSTNETDEV_0}


echo "Deleting TAP device ${TAPDEV_0}..."
sudo tunctl -d ${TAPDEV_0}

}

trap cleanup EXIT

echo "Starting firmware emulation... use Ctrl-a + x to exit"
sleep 1s

ARCH=arm
QEMU="./qemu-system-${ARCH}"
KERNEL="./zImage.armel" 
IMAGE="./image.raw"
MEM_FILE="./mem_file"

QEMU_AUDIO_DRV=none ${QEMU} -m 256 -mem-prealloc -mem-path ${MEM_FILE} -M ${QEMU_MACHINE} -kernel ${KERNEL} \
    -drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs -append "root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 user_debug=31 firmadyne.syscall=0" \
    -nographic \
    -device virtio-net-device,netdev=net0 -netdev tap,id=net0,ifname=${TAPDEV_0},script=no -device virtio-net-device,netdev=net1 -netdev socket,id=net1,listen=:2001 -device virtio-net-device,netdev=net2 -netdev socket,id=net2,listen=:2002 -device virtio-net-device,netdev=net3 -netdev socket,id=net3,listen=:2003 | tee ${WORK_DIR}/qemu.final.serial.log
