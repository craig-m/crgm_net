#!/bin/bash

# setup nginx (with apparmor profile) + certbot

echo "setup webserver";
export DEBIAN_FRONTEND=noninteractive;

webdomain="crgm"
webtld="net"

echo "# stretch backports" >> /etc/apt/sources.list
echo "deb http://deb.debian.org/debian stretch-backports main contrib non-free" >> /etc/apt/sources.list
echo "deb-src http://deb.debian.org/debian stretch-backports main contrib non-free" >> /etc/apt/sources.list

apt-get update
apt-get upgrade
apt-get install -y python-certbot-nginx -t stretch-backports

systemctl stop nginx

rm -rfv /etc/nginx/sites-enabled/default

mkdir -pv /var/www/${webdomain}/htdocs

cat > /etc/nginx/sites-enabled/crgm << EOF
server {
  server_name ${webdomain}.${webtld} www.${webdomain}.${webtld};
  root /var/www/${webdomain}/htdocs;
  index index.html;
  autoindex off;
}
EOF

systemctl restart nginx
systemctl enable nginx

certbot --nginx -d ${webdomain}.${webtld} -d www.${webdomain}.${webtld}

# certbot renew --dry-run

cat > /etc/apparmor.d/usr.sbin.nginx << EOF
# Last Modified: Sat Jan 26 22:02:01 2019
#include <tunables/global>

/usr/sbin/nginx {
  #include <abstractions/base>

  capability dac_override,
  capability net_bind_service,
  capability setgid,
  capability setuid,

  /etc/group r,
  /etc/letsencrypt/archive/${webdomain}.${webtld}/fullchain1.pem r,
  /etc/letsencrypt/archive/${webdomain}.${webtld}/privkey1.pem r,
  /etc/letsencrypt/options-ssl-nginx.conf r,
  /etc/letsencrypt/ssl-dhparams.pem r,
  /etc/nginx/conf.d/ r,
  /etc/nginx/mime.types r,
  /etc/nginx/modules-enabled/ r,
  /etc/nginx/nginx.conf r,
  /etc/nginx/sites-enabled/ r,
  /etc/nginx/sites-enabled/* r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/ssl/openssl.cnf r,
  /lib/x86_64-linux-gnu/ld-*.so mr,
  /run/nginx.pid rw,
  /usr/lib/nginx/modules/* mr,
  /usr/sbin/nginx mr,
  /usr/share/nginx/modules-available/* r,
  /var/log/nginx/access.log w,
  /var/log/nginx/error.log w,
  /var/www/${webdomain}/htdocs/** r,

}
EOF

systemctl reload apparmor

echo "done"
