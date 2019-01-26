#!/bin/bash

kernver="4.20.4";

if [ ! -f /etc/stackscript ]; then
  echo "error: stackscript did not run on linode";
  exit 1;
fi

export DEBIAN_FRONTEND=noninteractive;
sudo apt-get update
sudo apt-get upgrade -y

sudo apt-get install -y \
  build-essential libncurses5-dev gcc flex bison bc \
  grub2 gpgv2 dirmngr libssl-dev libfl-dev libelf-dev gcc-6-plugin-dev;

mkdir -pv ~/Downloads/
cd ~/Downloads/

if [ ! -f get-verified-tarball ]; then
  wget https://git.kernel.org/pub/scm/linux/kernel/git/mricon/korg-helpers.git/plain/get-verified-tarball
  chmod 755 get-verified-tarball
  gpg --list-keys
fi

./get-verified-tarball ${kernver}
gpg --list-keys

xz -d -- linux-${kernver}.tar.xz
tar -xf linux-${kernver}.tar
cd linux-${kernver}

# -- get current running kern config: --
#zcat /proc/config.gz > .config

# wget https://raw.githubusercontent.com/craig-m/crgm_net/master/linode-vm/kern.config
# mv kern.config .config

# -- to change kernel options: --
# make oldconfig
# make menuconfig

make

sudo rm -rfv -- /boot/*
sudo mkdir -pv /boot/grub/
sudo chmod 750 /boot/

sudo make install

sudo update-grub

# -- change the kernel type to 'grub2' in linode server config & reboot the linode --
