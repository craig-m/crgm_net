#!/bin/bash

[[ ! -z "$vm_ip_whitelist" ]] || exit 1

# install
apt-get install -y ufw;

# default
ufw default deny outgoing
ufw default deny incoming

# inbound
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from ${vm_ip_whitelist} to any port 22 proto tcp

# outbound ports
ufw allow out 80,443/tcp # http/s
ufw allow out 53,123/tcp # dns, ntp
ufw allow out 53,123/udp # dns, ntp
ufw allow out 67,68/udp # dhcp

# enable
ufw enable
ufw logging on
ufw status
