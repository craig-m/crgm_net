#!/bin/bash

apt-get update && apt-get upgrade

apt-get install -y \
  build-essential libncurses5-dev gcc flex libfl-dev \
  libssl-dev grub2 bc gpgv2 dirmngr bison libelf-dev

mkdir -pv ~/Downloads/
cd ~/Downloads/

wget https://git.kernel.org/pub/scm/linux/kernel/git/mricon/korg-helpers.git/plain/get-verified-tarball
chmod +x get-verified-tarball

./get-verified-tarball 4.20

xz -d linux-4.20.tar.xz
tar -xf linux-4.20.tar
cd linux-4.20

# -- get current running kern config: --
# zcat /proc/config.gz > .config

# -- to change kernel options: --
# make oldconfig
# make menuconfig

rm -rfv -- /boot/*

make
make install

update-grub

# -- change the kernel type to 'grub2' in linode server config & reboot the linode --
