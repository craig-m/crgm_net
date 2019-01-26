# Linode2019

The hosting for https://crgm.net

Nothing new or flashy, not particularly exciting - pretty boring really.

I needed some simple hosting that was stable and cheap (in cost, and in time/maintenance). Also something that was [very] fast for me to create.

When I have more time available I will build something better and replace this solution, like the *many* others that come before it.


# Stack

### infrastructure
* VPS: https://www.linode.com
* DNS: https://www.gandi.net/
* TLS: https://letsencrypt.org/

### web stack
* OS: https://www.debian.org/ (current stable is Stretch/9)
* Kernel: https://www.kernel.org/ (current stable + custom config)
* Web server: https://www.nginx.com/
* Web site: https://jekyllrb.com

### local environment
* dev/management VM: https://www.vagrantup.com
* Linode api + tools: https://github.com/linode/linode-cli


# Documentation

On your Mac/Linux/Win desktop install Vagrant + a provider.

Clone this repo, then in this dir:


## setup Linode-cli

```
vagrant up
vagrant ssh
linode configure
```

* skip 'distribution' question (Debian 9 is used).
* pick a datacenter.
* I use a the `1 - Nanode 1GB` ($5 monthly) - Option 1.
* Skip `Path to an SSH public` option.

Config will be saved at `/home/vagrant/.linodecli/config`


## set environment vars

All config is set in environment variables. Change and paste into shell:

```
export vm_name="crgmnetsrv_001"
export vm_root_pw="a_good_root_password"
export vm_username="someuser"
export vm_user_pw="a_good_nonroot_password"
export stackscriptname="crgm_debian9_base"
export vm_ip_whitelist="x.x.x.x"
```


## setup virtual machine

To deploy a new linode (using the details above):

```
vagrant@stretch:/vagrant$ ./create_linode.sh create
```


To rebuild the existing linode:

```
vagrant@stretch:/vagrant$ ./create_linode.sh recreate
```
