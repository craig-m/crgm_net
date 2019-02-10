#!/bin/bash

# ------------------------------------------------------------------------------
# crgm.net Linode StackScript for Debian 9 - base hosting setup.
# https://github.com/craig-m/crgm_net
#
# update stackscript:
#
# linode-stackscript -a update --label="$stackscriptname" \
# 	--revnote="update v9" --codefile="/vagrant/stackscript.sh";
# ------------------------------------------------------------------------------

# These "UDF tags" below are processed by the Linode deployment process.
# Doc: https://www.linode.com/docs/platform/stackscripts/#variables-and-udfs

# <UDF name="deployuser" Label="non-root admin user for vm" example="deployer" />
# <UDF name="deployeruserpassword" Label="admin user password" example="a_secret_sudo_pw" />
# <UDF name="sshipwhitelist" Label="whitelist ipv4 on temp fw" example="1.2.3.4" />
# <UDF name="vm_name" Label="vm_name" example="vm_name" />


# Init #########################################################################

# start
set -o verbose
echo "Starting Stackscript" | logger

# save deployment info here
if [ ! -d /root/setup/ ]; then
	mkdir -v /root/setup/;
	# unique token in this capture the flag file ;)
	cat /proc/sys/kernel/random/uuid > /root/setup/ctf.txt
else
	echo "ERROR: stackscript has already run";
	exit 1;
fi

# log all output from this script to:
exec > >(tee /root/setup/stackscript.log)
exec 2>&1

# Stop SSHD !!
# until we harden + update + setup users etc
echo "Stopping sshd"
systemctl stop sshd

# host info
uname -a;
uptime;
lsb_release -a;
thedate=$(date)
# fetch info about this image:
curl https://api.linode.com/v4/images/linode/debian9

# Remount /proc with hidepid option to hide processes from other users
mount -o remount,rw,hidepid=2 /proc

# Remount /dev/shm noexec
mount -o remount,noexec,nosuid,nodev /dev/shm

sysctl -w kernel.modules_disabled=1

# increase ulimit
ulimit -n 8192

# reduce swappiness to 0 for setup - default is 60
echo "0" > /proc/sys/vm/swappiness


# Firewall (ip whitelist) ######################################################

echo "[*] Firewall off host for setup";

#---------------------- Firewall ----------------------
# simple IPv4 whitelisted FW.
# these rules will not persist after rebooting this Linode,
# they are here to protect the host while it gets setup.

# iptables commands
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables

# ------ defaults - ipv4 ------
$IPTABLES -F
$IPTABLES -X
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

# ------ defaults - ipv6 ------
$IP6TABLES -F
$IP6TABLES -X
$IP6TABLES -P INPUT DROP
$IP6TABLES -P OUTPUT DROP
$IP6TABLES -P FORWARD DROP

# ------ loopback interface - ipv4 ------
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# ------ loopback interface - ipv6 ------
$IP6TABLES -A INPUT -i lo -j ACCEPT
$IP6TABLES -A OUTPUT -o lo -j ACCEPT

# ------ estasblished - ipv4 ------
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ------ estasblished - ipv6 ------
$IP6TABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IP6TABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ------ ipv4 - Ping requests in ------
$IPTABLES -A INPUT -i eth0 -p icmp --icmp-type echo-request -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "ping request"

# ------ ipv4 - Disable TCP timestamps to stop fingerprinting ------
$IPTABLES -A INPUT -i eth0 -p icmp --icmp-type timestamp-request -j DROP
$IPTABLES -A OUTPUT -p icmp --icmp-type timestamp-reply -j DROP

# ------ icmpv6 Allow Link-Local addresses ------
$IP6TABLES -A INPUT -s fe80::/10 -p icmpv6 -j ACCEPT
$IP6TABLES -A OUTPUT -s fe80::/10 -p icmpv6 -j ACCEPT

# ------ icmpv6 protocol ------
$IP6TABLES -I INPUT -i eth0 -p icmpv6 -j ACCEPT
$IP6TABLES -I OUTPUT -p icmpv6 -j ACCEPT
$IP6TABLES -I FORWARD -p icmpv6 -j ACCEPT

# ------ all outgoing - ipv4 + ipv6 ------
$IPTABLES -A OUTPUT -j ACCEPT
$IP6TABLES -A OUTPUT -j ACCEPT

# ------ incoming allowed (ipv4 only) ------
$IPTABLES -A INPUT -i eth0 -p tcp -m tcp --dport 22 -s $SSHIPWHITELIST -m comment --comment "Linode stackscript ssh" -j ACCEPT
$IPTABLES -A INPUT -i eth0 -p tcp -m tcp --dport 80 -s $SSHIPWHITELIST -m comment --comment "Linode stackscript http" -j ACCEPT
$IPTABLES -A INPUT -i eth0 -p tcp -m tcp --dport 443 -s $SSHIPWHITELIST -m comment --comment "Linode stackscript https" -j ACCEPT
$IPTABLES -A INPUT -i eth0 -p tcp -m tcp --dport 8080 -s $SSHIPWHITELIST -m comment --comment "Linode stackscript http alt" -j ACCEPT

# ------ Drop and Log all other incoming ------
$IPTABLES -N REJECTLOG
$IP6TABLES -N REJECTLOG

# log level debug
$IPTABLES -A REJECTLOG -j LOG --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options \
-m comment --comment "Linode FWDROP" -m limit --limit 10/m --limit-burst 10 --log-prefix "TEMP_FW_DROP "

$IP6TABLES -A REJECTLOG -j LOG --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options \
-m comment --comment "Linode FWDROP" -m limit --limit 10/m --limit-burst 10 --log-prefix "TEMP_FW_DROP "

# drop
$IPTABLES -A REJECTLOG -j DROP
$IP6TABLES -A REJECTLOG -j DROP

# Reject all other incoming traffic:
$IPTABLES -A INPUT -j REJECTLOG
$IP6TABLES -A INPUT -j REJECTLOG

# save temp fw for later
# can be restored with: iptables-restore /root/setup/iptables_stackscript
iptables-save > /root/setup/iptables_stackscript


# SSHD #########################################################################

echo "[*] SSHD hardening";

# Basic temp hardening
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config
sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
sed -i 's/#StrictModes yes/StrictModes yes/' /etc/ssh/sshd_config
sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#MaxSessions 10/MaxSessions 10/' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#UsePrivilegeSeparation sandbox/UsePrivilegeSeparation sandbox/' /etc/ssh/sshd_config

# public key auth
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config

# no password auth
sed -i 's/#PasswordAuthentication yes/#PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication no/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/AcceptEnv/#AcceptEnv/' /etc/ssh/sshd_config

# group for ssh users
groupadd sshusers
echo "# only the users in sshusers group have access:" >> /etc/ssh/sshd_config
echo "AllowGroups sshusers" >> /etc/ssh/sshd_config


# add non-root user ############################################################

echo "[*] create a non-root user that has [passworded] sudo";

# create /etc/skel files
cat >> /etc/skel/.screenrc << EOF
# ~/.screenrc
caption always "%{= bb}%{+b w}%h %u@%H %= %c %{=b rw} %l %{= db}%{= dg}"
hardstatus alwayslastline "%-Lw%{= BW}%50>%n%f* %t%{-}%+Lw%<"
startup_message off
chdir
autodetach on
defscrollback 10000
vbell on
vbell_msg "bell on %t (%n)"
activity "Activity in %t(%n)"
shelltitle "shell"
shell -$SHELL
EOF

touch /etc/skel/.bash_aliasess

# make the user + password it
adduser $DEPLOYUSER --force-badname --disabled-password --gecos ""
echo "$DEPLOYUSER:$DEPLOYERUSERPASSWORD" | chpasswd

# add to groups
usermod -aG sudo $DEPLOYUSER
usermod -aG sshusers $DEPLOYUSER

# pub ssh key for user
mkdir -p --mode=700 /home/${DEPLOYUSER}/.ssh
touch /home/${DEPLOYUSER}/.ssh/authorized_keys
touch /home/${DEPLOYUSER}/.ssh/config

# copy root's authorized_keys (added by linode stackscript) to this users (these are removed later)
cat /root/.ssh/authorized_keys >> /home/${DEPLOYUSER}/.ssh/authorized_keys

# user homedir folders
mkdir -pv --mode=700 /home/${DEPLOYUSER}/Downloads

# ssh dir perms
chmod 700 /home/${DEPLOYUSER}/
chmod 600 /home/${DEPLOYUSER}/.ssh/authorized_keys
chown -R ${DEPLOYUSER}:${DEPLOYUSER} /home/${DEPLOYUSER}/.ssh

# add pub keys from github
sudo -u ${DEPLOYUSER} /usr/bin/curl https://github.com/${github_user}.keys >> /home/${DEPLOYUSER}/.ssh/authorized_keys

# create a 5MB tmpfs
if [ ! -f /mnt/ramstore/data/test.txt ]; then
  mkdir -pv /mnt/ramstore;
  mount -t tmpfs -o size=5m tmpfs /mnt/ramstore;
	# these files exist in Volatile memory!
  mkdir --mode=770 /mnt/ramstore/data;
	chown ${DEPLOYUSER}:root /mnt/ramstore/data
  touch /mnt/ramstore/data/test.txt
fi

# setup ruby env
echo '# Install Ruby Gems to ~/gems' >> /home/${DEPLOYUSER}/.bashrc
echo 'export GEM_HOME="$HOME/gems"' >> /home/${DEPLOYUSER}/.bashrc
echo 'export PATH="$HOME/gems/bin:$PATH"' >> /home/${DEPLOYUSER}/.bashrc


# install/upgrade programs #####################################################

echo "[*] OS Update + Package install";

export DEBIAN_FRONTEND=noninteractive;

# update OS
apt-get update || echo "CRITICAL aptget update failed"
apt-get upgrade --assume-yes --quiet || echo "CRITICAL aptget upgrade failed"

# Install packages
apt-get install --assume-yes apt-transport-https ca-certificates
apt-get install --assume-yes \
	sudo \
	net-tools \
	build-essential \
	libncurses5-dev libfl-dev libelf-dev \
	bison gcc gcc-6-plugin-dev flex \
	libssl-dev libcurl4-openssl-dev \
	git \
	rsync \
	bc \
	attr \
	autoconf automake \
	python-dev:any ruby-full \
	libffi-dev \
	vim nano \
	screen tmux \
	htop \
	dtach \
	tcpdump \
	unzip \
	exiftool steghide \
	uuid \
	pass \
	expect inotify-tools \
  monitoring-plugins-common monitoring-plugins-basic \
	debsums \
	bats \
  apparmor apparmor-utils \
	grub2 gpgv2 dirmngr;


# install haveged, an unpredictable random number generator
apt-get install -y haveged
systemctl start haveged.service
systemctl enable haveged.service
/usr/lib/nagios/plugins/check_procs -C haveged 1:3

# install fail2ban
apt-get install -y fail2ban
systemctl start fail2ban
systemctl enable fail2ban
/usr/lib/nagios/plugins/check_procs -C fail2ban-server 1:3

# track uptimes
apt-get install -y uptimed
systemctl start uptimed.service
systemctl enable uptimed.service
/usr/lib/nagios/plugins/check_procs -C uptimed 1:3


# ssh keys #####################################################################

echo "[*] deal with ssh keys";

# remove sshd host keys
rm -v /etc/ssh/ssh_host_rsa_key
rm -v /etc/ssh/ssh_host_ecdsa_key

# regenerate sshd host keys
echo "entropy_avail before keygen:"
cat /proc/sys/kernel/random/entropy_avail
ssh-keygen -t rsa -N "" -f /etc/ssh/ssh_host_rsa_key
ssh-keygen -t ecdsa -N "" -f /etc/ssh/ssh_host_ecdsa_key
echo "entropy_avail after keygen:"
cat /proc/sys/kernel/random/entropy_avail

# remove root authorized_keys
echo "" > /root/.ssh/authorized_keys
chattr +i /root/.ssh/authorized_keys


# auditd #######################################################################

echo "[*] setup auditd";

apt-get install auditd -y
systemctl enable auditd
/usr/lib/nagios/plugins/check_procs -C auditd 1:3

# auditd rules to monitor the server
cat >> /etc/audit/rules.d/audit.rules << EOF
## etc file changes
-w /etc/ssh/sshd_config -p wa -k etcfiles
-w /etc/sysctl.conf -p wa -k etcfiles
-w /etc/hosts -p wa -k etcfiles
-w /etc/ld.so.conf -p wa -k etcfiles
-w /etc/ld.so.conf.d/libc.conf -p wa -k etcfiles
-w /etc/ld.so.conf.d/x86_64-linux-gnu.conf -p wa -k etcfiles
-w /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf -p wa -k etcfiles

# cron
-w /var/spool/cron/crontabs/ -p wa -k crontab
-w /etc/crontab -p wa -k crontab
-w /etc/cron.allow -p wa -k crontab
-w /etc/cron.deny -p wa -k crontab
-w /etc/cron.daily/ -p wa -k crontab
-w /etc/cron.hourly/ -p wa -k crontab
-w /etc/cron.weekly/ -p wa -k crontab
-w /etc/cron.monthly/ -p wa -k crontab

## Kernel module loading and unloading
-w /etc/modprobe.conf -p wa -k etcfiles
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules

## Special files
# -a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles

## Mount operations (only attributable)
-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount

# Change swap (only attributable)
-a always,exit -F arch=b64 -S swapon -S swapoff -F auid!=-1 -k swap

## User, group, password databases
-w /etc/group -p wa -k etcfiles
-w /etc/passwd -p wa -k etcfiles
-w /etc/sudoers -p wa -k etcfiles
-w /etc/gshadow -k etcfiles
-w /etc/shadow -k etcfiles
-w /etc/security/opasswd -k etcfiles

# sudo
-w /bin/su -p x -k sudo
-w /usr/bin/sudo -p x -k sudo
-w /etc/sudoers -p rw -k sudo

## Suspicious activity
-w /usr/bin/passwd -p x -k susp_exec
-w /usr/bin/base64 -p x -k susp_exec
-w /usr/bin/od -p x -k susp_exec
-w /usr/sbin/tcpdump -p x -k susp_exec
-w /bin/busybox -p x -k susp_exec

## network clients
-w /usr/bin/wget -p x -k netcli_exec
-w /usr/bin/curl -p x -k netcli_exec
-w /bin/nc -p x -k netcli_exec
-w /bin/netcat -p x -k netcli_exec
-w /usr/bin/ncat -p x -k netcli_exec
-w /usr/bin/ssh -p x -k netcli_exec
-w /usr/bin/socat -p x -k netcli_exec
-w /usr/bin/telnet -p x -k netcli_exec
-w /usr/bin/whois -p x -k netcli_exec

# ctf
-w /root/setup/ctf.txt -p war -k ctfwin
EOF

service auditd restart
/usr/lib/nagios/plugins/check_procs -C auditd 1:3
auditctl -l | wc -l


# misc hardening ###############################################################

# apparmor enabled on boot
if [ ! -f /root/setup/.apparmor ]; then
	echo "[*] enable apparmor on boot ";
	perl -pi -e 's,GRUB_CMDLINE_LINUX="(.*)"$,GRUB_CMDLINE_LINUX=" $1 apparmor=1 security=apparmor",' /etc/default/grub
	/usr/sbin/update-grub
	touch -f /root/setup/.apparmor
fi

# hide procs perm
echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab

# no exec on shared mem
echo "tmpfs /dev/shm tmpfs rw,nodev,nosuid,noexec,mode=1777 0 0" >> /etc/fstab

# boot dir perms
chmod 700 /boot/

# no kernel modules
echo 'kernel.modules_disabled=1' >> /etc/sysctl.d/99-custom.conf

# remove setuid bit on:
chmod u-s /bin/ping
chmod u-s /usr/bin/mtr
chmod u-s /bin/mount
chmod u-s /bin/umount

# sysctl.conf
sed -i 's/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.default.rp_filter=1/' /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=1/' /etc/sysctl.conf
sed -i 's/#net.ipv4.tcp_syncookies=1/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=0/' /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/' /etc/sysctl.conf
sed -i 's/#kernel.sysrq=1/kernel.sysrq=0/' /etc/sysctl.conf
sed -i 's/#fs.protected_hardlinks=0/fs.protected_hardlinks=1/' /etc/sysctl.conf
sed -i 's/#fs.protected_symlinks=0/fs.protected_symlinks=1/' /etc/sysctl.conf

echo -e "\n# added tuning options:" >> /etc/sysctl.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.conf
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
echo "kernel.kptr_restrict = 1" >> /etc/sysctl.conf
echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
echo "kernel.perf_event_paranoid = 2" >> /etc/sysctl.conf
echo "user.max_user_namespaces = 0" >> /etc/sysctl.conf
echo "fs.file-max = 65535" >> /etc/sysctl.conf
echo "kernel.pid_max = 65536" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_port_range = 2000 65000" >> /etc/sysctl.conf

# set immutable
chattr +i /etc/sysctl.conf

# reload sysctl config:
sysctl -p /etc/sysctl.conf


# Gather server info ###########################################################

echo "[*] VM Info";

serverdeets="/home/${DEPLOYUSER}/welcome.txt"
touch -f $serverdeets

IPADDR=$(/sbin/ifconfig eth0 | awk '/inet / { print $2 }' | sed 's/addr://')
echo "My IP $IPADDR" >> $serverdeets

# get ssh keys
ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key >> $serverdeets
ssh-keygen -l -f /etc/ssh/ssh_host_ecdsa_key >> $serverdeets
echo " " >> $serverdeets

last -a -F >> $serverdeets
uptime >> $serverdeets

echo " " >> $serverdeets
echo "StackScript started $thedate" >> $serverdeets

# list installed packages and versions
apt list --installed > /root/setup/packages


# done #########################################################################


# Message Of The Day
cat > /etc/motd << EOF

'||'''|.        '||                           .|'''|,    '||                              ||'
 ||   ||         ||      ''                   ||   ||     ||      ''                      ||
 ||   || .|''|,  ||''|,  ||   '''|.  '||''|,  '|...||     ||      ||  '||''|,  .|''|, .|''||  .|''|,
 ||   || ||..||  ||  ||  ||  .|''||   ||  ||       ''     ||      ||   ||  ||  ||  || ||  ||  ||..||
.||...|' '|...  .||..|' .||. '|..||. .||  ||.     ''     .||...| .||. .||  ||. '|..|' '|..||. '|...
                                                 ''
EOF


# free pagecache, dentries and inodes.
sync;
echo 3 > /proc/sys/vm/drop_caches;
sync;


# --- start sshd ! ---
echo "Starting sshd (iptables whitelisted)"
systemctl start sshd || echo "CRITICAL could not restart sshd"
/usr/lib/nagios/plugins/check_ssh -p 22 localhost


# -- script finished !! --
SSFIN=$(date)
echo "StackScript finished $SSFIN" >> $serverdeets
touch -f /etc/stackscript
# save info in extended file attributes
setfattr -n user.crgmnet_vmname -v "${vm_name}" /etc/stackscript
setfattr -n user.crgmnet_user -v "${DEPLOYUSER}" /etc/stackscript
setfattr -n user.crgmnet_ipw -v "${sshipwhitelist}" /etc/stackscript
setfattr -n user.crgmnet_stackscript -v "setup finished" /etc/stackscript
echo "[*] StackScript Finished" | logger;
chattr +i /etc/stackscript


# EOF
