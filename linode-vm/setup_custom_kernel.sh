#!/bin/bash

# build a custom kernel for Linode Linux VPS
# tested on Debian GNU/Linux 9.6 (stretch) + Linux V 4.20

sudo apt-get update
sudo apt-get upgrade -y

sudo apt-get install -y \
  build-essential libncurses5-dev gcc flex bison bc \
  grub2 gpgv2 dirmngr libssl-dev libfl-dev libelf-dev;

mkdir -pv ~/Downloads/
cd ~/Downloads/

wget https://git.kernel.org/pub/scm/linux/kernel/git/mricon/korg-helpers.git/plain/get-verified-tarball
chmod +x get-verified-tarball
gpg --list-keys
./get-verified-tarball 4.20.1
gpg --list-keys

xz -d -- linux-4.20.1.tar.xz
tar -xf linux-4.20.1.tar
cd linux-4.20.1

# -- get current running kern config: --
# zcat /proc/config.gz > .config

# wget https://raw.githubusercontent.com/craig-m/crgm_net/master/linode-vm/kern.config
# mv kern.config .config

# -- to change kernel options: --
# make oldconfig
# make menuconfig

make

sudo rm -rfv -- /boot/*
sudo mkdir -pv /boot/grub/

sudo make install

sudo update-grub

# -- change the kernel type to 'grub2' in linode server config & reboot the linode --
