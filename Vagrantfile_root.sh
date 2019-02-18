#!/bin/bash

echo "Starting Vagrantfile_root.sh";
if [ ! -d /root/.setup/ ]; then
	mkdir -v /root/.setup/;
else
	echo "ERROR: Vagrantfile_root.sh has already run";
	exit 1;
fi

# update
export DEBIAN_FRONTEND=noninteractive
apt-get update

# install tools
apt-get install --assume-yes --quiet \
  build-essential git uuid pass attr \
  rsync wget curl nmap \
  screen tmux vim jq expect \
  ruby-full

# install linode-cli
# https://www.linode.com/docs/platform/api/linode-cli/
bash -c 'echo "deb http://apt.linode.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/linode.list'
wget -O- https://apt.linode.com/linode.gpg | sudo apt-key add -
apt-get update
apt-get install linode-cli --assume-yes
mkdir -pv /home/vagrant/.linodecli/ && touch -f /home/vagrant/.linodecli/config && chmod 640 /home/vagrant/.linodecli/config
chown vagrant:vagrant -R /home/vagrant/.linodecli/

# install puppet bolt
# https://puppet.com/docs/bolt/1.x/bolt_installing.html#task-7569
echo "installing puppet bolt"
wget https://apt.puppet.com/puppet6-release-stretch.deb
dpkg -i puppet6-release-stretch.deb
apt-get update
apt-get install -y puppet-bolt
bolt --version
# install puppet development kit
apt-get install -y pdk


# motd
echo -e "\nLinode dev/admin Vagrant VM\n" > /etc/motd

# EOF
