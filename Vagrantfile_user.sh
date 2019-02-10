#!/bin/bash

echo "Starting Vagrantfile_user.sh as vagrant user";
if [ ! -d /home/vagrant/.setup/ ]; then
	mkdir -vp /home/vagrant/.setup/;
else
	echo "ERROR: Vagrantfile_user.sh has already run";
	exit 1;
fi

chmod +x -v -- /vagrant/create_linode.sh
chmod -x -v -- /vagrant/Vagrantfile_user.sh
chmod -x -v -- /vagrant/Vagrantfile_root.sh


# puppet bolt env
mkdir -pv ~/.puppetlabs/bolt/modules/
echo "disabled: true" > ~/.puppetlabs/bolt/analytics.yaml
touch ~/.puppetlabs/bolt/bolt.yaml


# install Jekyll ---------------------------------------------------------------
# https://jekyllrb.com/docs/installation/other-linux/

echo '# Install Ruby Gems to ~/gems' >> $HOME/.bashrc
echo 'export GEM_HOME="$HOME/gems"' >> $HOME/.bashrc
echo 'export PATH="$HOME/gems/bin:$PATH"' >> $HOME/.bashrc

export GEM_HOME="$HOME/gems"
export PATH="$HOME/gems/bin:$PATH"

gem install jekyll bundler minima
cd /vagrant/jekyll-blog;

jekyll -v || echo "ERROR: failed to install jekyll"


# create ssh key ---------------------------------------------------------------

if [ ! -f /home/vagrant/.ssh/id_rsa_node ]; then
  ssh-keygen -b 4096 -m PEM -P "" -C "vb" -o -f /home/vagrant/.ssh/id_rsa_node -t rsa
fi

# EOF
