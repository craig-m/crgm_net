#!/bin/bash

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
