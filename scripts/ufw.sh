#!/bin/bash

# get whitelisted IP (put here by stackscript)
ipw=$(getfattr -n user.crgmnet_ipw /etc/stackscript | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

# install
export DEBIAN_FRONTEND=noninteractive;
apt-get install -y ufw;

# default
ufw default deny outgoing
ufw default deny incoming

# inbound
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from ${ipw} to any port 22 proto tcp

# outbound ports
ufw allow out 80,443/tcp # http/s
ufw allow out 53,123/tcp # dns, ntp
ufw allow out 53,123/udp # dns, ntp
ufw allow out 67,68/udp # dhcp
ufw allow out 11371/tcp # OpenPGP HTTP Keyserver

# enable
systemctl enable ufw
ufw enable
ufw logging on
ufw status
