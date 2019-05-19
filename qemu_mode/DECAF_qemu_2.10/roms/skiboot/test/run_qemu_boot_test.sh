#!/bin/bash


if [ -z "$QEMU_PATH" ]; then
    QEMU_PATH=`pwd`/opal-ci/qemu/ppc64-softmmu/
fi

if [ -z "$QEMU_BINARY" ]; then
    QEMU_BINARY="qemu-system-ppc64"
fi

if [ ! -x "$QEMU_PATH/$QEMU_BINARY" ]; then
    echo 'Could not find executable QEMU_BINARY. Skipping hello_world test';
    exit 0;
fi

if [ -n "$KERNEL" ]; then
    echo 'Please rebuild skiboot without KERNEL set. Skipping hello_world test';
    exit 0;
fi

if [ ! `command -v expect` ]; then
    echo 'Could not find expect binary. Skipping hello_world test';
    exit 0;
fi

if [ -z "$SKIBOOT_ZIMAGE" ]; then
    export SKIBOOT_ZIMAGE=`pwd`/zImage.epapr
fi

if [ ! -f "$SKIBOOT_ZIMAGE" ]; then
    echo "No $SKIBOOT_ZIMAGE, skipping boot test";
    exit 0;
fi

T=`mktemp  --tmpdir skiboot_qemu_boot_test.XXXXXXXXXX`

( cat <<EOF | expect
set timeout 600
spawn $QEMU_PATH/$QEMU_BINARY -m 1G -M powernv -kernel $SKIBOOT_ZIMAGE -nographic
expect {
timeout { send_user "\nTimeout waiting for petitboot\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n;" exit 1 }
"Welcome to Petitboot"
}
close
wait
exit 0
EOF
) 2>&1 > $T
E=$?

if [ $E -eq 0 ]; then
    rm $T
else
    echo "Boot Test FAILED. Results in $T";
fi

echo
exit $E;
