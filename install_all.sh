#!/usr/bin/bash

## Installing some deps

sudo apt install busybox-static fakeroot git dmsetup kpartx netcat-openbsd nmap python-psycopg2 python3-psycopg2 snmp uml-utilities util-linux vlan libsdl1.2-dev zlib1g-dev libglib2.0-dev binutils-dev build-essential binutils qemu libboost-dev git lib tool autoconf xorg-dev binwalk

## Building user-mode

pushd user_mode
./configure --target-list=mipsel-linux-user,mips-linux-user,arm-linux-user --static --disable-werror
make $(nproc)
popd

## Building user-mode

pushd qemu_mode/DECAF_qemu_2.10/
./configure --target-list=mipsel-softmmu,mips-softmmu,arm-softmmu --disable-werror
make $(nproc)
popd

## Installing Firmadyne
git clone --recursive https://github.com/firmadyne/firmadyne.git

# Install additional deps
sudo pip3 install git+https://github.com/ahupp/python-magic
sudo pip install git+https://github.com/sviehb/jefferson

# Set up database
sudo service postgresql start
sudo -u postgres createuser firmadyne
sudo -u postgres createdb -O firmadyne firmware
sudo -u postgres psql -d firmware < ./firmadyne/database/schema
echo "ALTER USER firmadyne PASSWORD 'firmadyne'" | sudo -u postgres psql

# Set up firmadyne
pushd firmadyne
./download.sh

git clone https://github.com/devttys0/sasquatch.git
pushd sasquatch
./build.sh
popd 
popd

# Set FIRMWARE_DIR in firmadyne.config
mv firmadyne.config firmadyne.config.orig
echo -e '#!/bin/sh' "\nFIRMWARE_DIR=$(pwd)/" > firmadyne.config
cat firmadyne.config.orig >> firmadyne.config

cp firmadyne_modify/makeImage.sh firmadyne/scripts/
