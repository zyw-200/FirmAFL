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


export SKIBOOT_ZIMAGE=`pwd`/test/hello_world/hello_kernel/hello_kernel

t=$(mktemp) || exit 1

trap "rm -f -- '$t'" EXIT

(
cat <<EOF | expect
set timeout 30
spawn $QEMU_PATH/$QEMU_BINARY -m 1G -M powernv -kernel $SKIBOOT_ZIMAGE -nographic
expect {
timeout { send_user "\nTimeout waiting for hello world\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n;" exit 1 }
"Hello World!"
}
close
wait
exit 0
EOF
) 2>&1 > $t

r=$?
if [ $r != 0 ]; then
    cat $t
    exit $r
fi

rm -f -- "$t"
trap - EXIT

exit 0;
