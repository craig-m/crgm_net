# Vagrantfile for crgm.net Debian 9 dev/admin VM.
# src: https://github.com/craig-m/crgm_net
# Doc: https://www.vagrantup.com/docs/vagrantfile/

VAGRANT_API_VER = "2"

Vagrant.configure(VAGRANT_API_VER) do |config|

  # VM settings
  config.vm.box = "debian/stretch64"
  config.vm.box_check_update = false
  config.vm.boot_timeout = 360
  config.vm.hostname = 'stretch.local'

  # VirtualBox settings
  config.vm.provider :virtualbox do |vb|
    vb.name = "stretch_node_admin"
    vb.memory = 2048
    vb.cpus = 2
  end

  # forward desktop SSH agent into VM
  config.ssh.forward_agent = true

  # Port forwarding
  config.vm.network :forwarded_port, guest: 22, host: 2929, id: 'ssh'
  config.vm.network :forwarded_port, guest: 4000, host: 4949, id: 'jekyll'

  # provisioning script (as root user)
  config.vm.provision :shell, :path => "Vagrantfile_root.sh", :privileged => true
  # provisioning script (as vagrant user)
  config.vm.provision :shell, :path => "Vagrantfile_user.sh", :privileged => false

  config.vm.post_up_message = "----[ Linode Admin VM up! ]----"
end

# EOF
