#!/bin/bash

echo "Starting Vagrantfile.sh as root";

# update
export DEBIAN_FRONTEND=noninteractive
apt-get update

# install tools
apt-get install --assume-yes --quiet \
  build-essential git uuid pass attr \
  rsync wget curl nmap \
  screen tmux vim \
  ruby-full

# install linode-cli
bash -c 'echo "deb http://apt.linode.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/linode.list'
wget -O- https://apt.linode.com/linode.gpg | sudo apt-key add -
apt-get update
apt-get install linode-cli --assume-yes
mkdir -pv /home/vagrant/.linodecli/ && touch -f /home/vagrant/.linodecli/config && chmod 640 /home/vagrant/.linodecli/config
chown vagrant:vagrant -R /home/vagrant/.linodecli/

# motd
echo -e "\nLinode dev/admin Vagrant VM\n" > /etc/motd

# EOF
