id=${1}
ARCH=${2}

cp ../FirmAFL_config/afl-fuzz .
cp ../FirmAFL_config/afl-fuzz-detail .
cp ../FirmAFL_config/afl-fuzz-nodetail .
cp afl-fuzz-nodetail afl-fuzz
cp ../FirmAFL_config/afl-fuzz-full . #full -QQ
cp ../FirmAFL_config/procinfo.ini .
mkdir inputs
rm -r outputs
####
cp ../FirmAFL_config/${id}/test_${id}.py .
cp ../FirmAFL_config/${id}/keywords_${id} .
cp ../FirmAFL_config/${id}/seed inputs/
cp ../FirmAFL_config/${id}/seed_random inputs/
cp ../FirmAFL_config/${id}/user.sh .
cp ../FirmAFL_config/${id}/run.sh .
cp ../FirmAFL_config/${id}/run_full.sh .
cp ../FirmAFL_config/start.py .
cp ../FirmAFL_config/start_full.py .
cp ../FirmAFL_config/sleep_and_test.py .
cp ../FirmAFL_config/${id}/FirmAFL_config_${id} .
cp ../FirmAFL_config/${id}/FirmAFL_config_${id} FirmAFL_config
cp ../FirmAFL_config/qemu-${ARCH}  afl-qemu-trace 
cp ../FirmAFL_config/qemu-system-${ARCH} .
cp ../FirmAFL_config/qemu-system-${ARCH}-full .

cp ../firmadyne/binaries/vmlinux.${ARCH}_3.2.1 .
cp ../firmadyne/firmadyne.config .
cp ../qemu_mode/DECAF_qemu_2.10/pc-bios/efi-pcnet.rom .
cp ../qemu_mode/DECAF_qemu_2.10/pc-bios/vgabios-cirrus.bin .
cp ../firmadyne/scratch/${id}/image.raw .