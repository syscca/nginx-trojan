#!/bin/bash
set -euo pipefail

function prompt() {
    while true; do
        read -p "$1 [y/N] " yn
        case $yn in
            [Yy] ) return 0;;
            [Nn]|"" ) return 1;;
        esac
    done
}

if [[ $(id -u) != 0 ]]; then
    echo Please run this script as root.
    exit 1
fi

if [[ $(uname -m 2> /dev/null) != x86_64 ]]; then
    echo Please run this script on x86_64 machine.
    exit 1
fi

echo 刷新源...
apt update

echo 安装软件 socat qrencode curl xz build-essential...
apt install socat qrencode curl xz-utils build-essential -y

echo "输入域名不要带www: "
read newname
echo "输入阿里云 dns api Ali_Key : "
read alykey
echo "输入阿里云 dns api Ali_Secret : "
read alysecret
echo "设置 trojan 密码password: "
read TJ_PASS
echo "输入防火墙 SSH 要开放的端口: "
read ssh_prot

SYSTEMDPREFIX="/lib/systemd/system"
SUFFIX=.tar.gz
NG_NAME=nginx
NG_VERSION=1.16.1
NG_TARBALL="${NG_NAME}-${NG_VERSION}${SUFFIX}"
NG_DOWNLOADURL="https://nginx.org/download/${NG_TARBALL}"
NG_CONFIG_URL="https://raw.githubusercontent.com/vinyo/nginx-trojan/master/nginx.conf"
NG_CONFIG="/etc/nginx/nginx.conf"
NG_SYSTEMDPATH="${SYSTEMDPREFIX}/${NG_NAME}.service"
# http://nginx.org/download/nginx-1.16.1.tar.gz

PCRE_NAME=pcre
PCRE_VERSION=8.44
PCRE_TARBALL="${PCRE_NAME}-${PCRE_VERSION}${SUFFIX}"
PCRE_DOWNLOADURL="https://ftp.pcre.org/pub/pcre/${PCRE_TARBALL}"
# https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz

ZLIB_NAME=zlib
ZLIB_VERSION=1.2.11
ZLIB_TARBALL="${ZLIB_NAME}-${ZLIB_VERSION}${SUFFIX}"
ZLIB_DOWNLOADURL="http://zlib.net/${ZLIB_TARBALL}"
# http://zlib.net/zlib-1.2.11.tar.gz

SSL_NAME=openssl
SSL_VERSION=1.1.1f
SSL_TARBALL="${SSL_NAME}-${SSL_VERSION}${SUFFIX}"
SSL_DOWNLOADURL="https://www.openssl.org/source/${SSL_TARBALL}"
# https://www.openssl.org/source/openssl-1.1.1d.tar.gz

SSLCER="/etc/nginx/ssl/${newname}/fullchain.cer"
SSLKEY="/etc/nginx/ssl/${newname}/${newname}.key"
SSLFILE="/etc/nginx/ssl"

TJ_NAME=trojan
TJ_VERSION=$(curl -fsSL https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name | sed -E 's/.*"v(.*)".*/\1/')
TJ_TARBALL="${TJ_NAME}-${TJ_VERSION}-linux-amd64.tar.xz"
TJ_DOWNLOADURL="https://github.com/trojan-gfw/${TJ_NAME}/releases/download/v${TJ_VERSION}/${TJ_TARBALL}"
TJ_INSTALLPREFIX=/usr/local

TJ_BINARYPATH="${TJ_INSTALLPREFIX}/bin/${TJ_NAME}"
TJ_CONFIGPATH="${TJ_INSTALLPREFIX}/etc/${TJ_NAME}/config.json"
TJ_SYSTEMDPATH="${SYSTEMDPREFIX}/${TJ_NAME}.service"
# https://github.com/trojan-gfw/trojan/releases/download/v1.14.1/trojan-1.14.1-linux-amd64.tar.xz

ymname="/etc/nginx/conf.d/${newname}.conf"
wwip=$(curl -s myip.ipip.net |grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}")

TMPDIR="$(mktemp -d)"

echo 进入临时文件夹 ${TMPDIR}...
cd "${TMPDIR}"

off_log(){
if systemctl is-active --quiet rsyslog; then
    echo 停止和禁止 syslog...
    service rsyslog stop
    systemctl disable rsyslog
else
    echo "syslog没有运行"
fi
}

fw_save(){
if [ `command -v iptables-save` ];then
    echo "iptables 已经安装"
else
echo "安装 iptables..."
apt install iptables -y
fi

echo 安装iptables-persistent...
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt -y install iptables-persistent

echo 清空防火墙...
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -F
ip6tables -X

echo 添加防火墙规则...
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW --dport ${ssh_prot} -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -j REJECT

echo 保存iptables 防火墙规则...
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
}

setup_bbr(){
# 开启BBR
LSBBR=$(sysctl net.ipv4.tcp_congestion_control)
if [[ ${LSBBR} =~ "bbr" ]]; then
echo "已开启BBR"
else
echo "正在开启BBR"
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
fi
}

set_user(){
NG_USER=$(awk -F: '$0~/nginx/' /etc/passwd|wc -l)
if [[ ${NG_USER} -ne 0 ]]; then
echo nginx 组和用户已存在...
else
echo 正在创建 nginx 组和用户...
groupadd nginx
useradd -M -g nginx -s /sbin/nologin nginx
fi
}

setup_nginx(){
echo Downloading ${NG_NAME} $NG_VERSION...
curl -LO --progress-bar "${NG_DOWNLOADURL}" || wget -q --show-progress "${NG_DOWNLOADURL}"

echo Downloading ${PCRE_NAME} ${PCRE_VERSION}...
curl -LO --progress-bar "${PCRE_DOWNLOADURL}" || wget -q --show-progress "${PCRE_DOWNLOADURL}"

echo Downloading ${ZLIB_NAME} ${ZLIB_VERSION}...
curl -LO --progress-bar "${ZLIB_DOWNLOADURL}" || wget -q --show-progress "${ZLIB_DOWNLOADURL}"

echo Downloading ${SSL_NAME} ${SSL_VERSION}...
curl -LO --progress-bar "${SSL_DOWNLOADURL}" || wget -q --show-progress "${SSL_DOWNLOADURL}"

echo Unpacking ${NG_NAME} ${NG_VERSION}...
tar -zxf "${NG_TARBALL}"

echo Unpacking ${PCRE_NAME} ${PCRE_VERSION}...
tar -zxf "${PCRE_TARBALL}"

echo Unpacking ${ZLIB_NAME} ${ZLIB_VERSION}...
tar -zxf "${ZLIB_TARBALL}"

echo Unpacking ${SSL_NAME} ${SSL_VERSION}...
tar -zxf "${SSL_TARBALL}"

echo 安装acme.sh...
curl  https://get.acme.sh | sh

echo 设置阿里云DNS API KEY...
export Ali_Key="${alykey}"
export Ali_Secret="${alysecret}"

echo 生成${newname} SSL 证书...
/root/.acme.sh/acme.sh --issue --dns dns_ali -d "${newname}" -d "*.${newname}" --force

echo configure ${NG_NAME}...
cd ${NG_NAME}-${NG_VERSION}
./configure \
 --prefix=/etc/nginx \
 --sbin-path=/usr/sbin/nginx \
 --modules-path=/usr/lib/nginx/modules \
 --conf-path=/etc/nginx/nginx.conf \
 --error-log-path=/var/log/nginx/error.log \
 --http-log-path=/var/log/nginx/access.log \
 --pid-path=/var/run/nginx.pid \
 --lock-path=/var/run/nginx.lock \
 --http-client-body-temp-path=/var/cache/nginx/client_temp \
 --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
 --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
 --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
 --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
 --user=nginx \
 --group=nginx \
 --with-compat \
 --with-file-aio \
 --with-threads \
 --with-http_addition_module \
 --with-http_auth_request_module \
 --with-http_dav_module \
 --with-http_flv_module \
 --with-http_gunzip_module \
 --with-http_gzip_static_module \
 --with-http_mp4_module \
 --with-http_random_index_module \
 --with-http_realip_module \
 --with-http_secure_link_module \
 --with-http_slice_module \
 --with-http_ssl_module \
 --with-http_stub_status_module \
 --with-http_sub_module \
 --with-http_v2_module \
 --with-mail \
 --with-mail_ssl_module \
 --with-stream \
 --with-stream_realip_module \
 --with-stream_ssl_module \
 --with-stream_ssl_preread_module \
 --with-pcre=../pcre-8.44 \
 --with-zlib=../zlib-1.2.11 \
 --with-openssl=../openssl-1.1.1f \
 --with-cc-opt='-g -O2 -fdebug-prefix-map=./nginx-1.16.1=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
 --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'

echo make ${NG_NAME} ${NG_VERSION}...
make

echo install ${NG_NAME} ${NG_VERSION}...
make install

if [[ ! -d "/etc/nginx/conf.d" ]]; then
echo 新建/etc/nginx/conf.d文件夹...
mkdir -p /etc/nginx/conf.d
else
echo /etc/nginx/conf.d文件夹已创建...
fi

if [[ ! -d "/var/www/${newname}" ]]; then
echo 新建/var/www/${newname}文件夹...
mkdir -p "/var/www/${newname}"
else
echo /var/www/${newname}文件夹已创建...
fi

if [[ ! -d "${SSLFILE}/${newname}" ]]; then
echo 新建${SSLFILE}/${newname}文件夹...
mkdir -p "${SSLFILE}/${newname}"
else
echo ${SSLFILE}/${newname}文件夹已创建...
fi

if [[ ! -d "/var/cache/nginx/client_temp" ]]; then
echo 新建/var/cache/nginx/client_temp文件夹...
mkdir -p /var/cache/nginx/client_temp
else
echo /var/cache/nginx/client_temp文件夹已创建...
fi

echo Downloading ${NG_NAME} ${NG_VERSION} CONFIG File...
curl -LO --progress-bar "${NG_CONFIG_URL}" || wget -q --show-progress "${NG_CONFIG_URL}"

echo copy ${NG_NAME}.conf to ${NG_CONFIG}...
cp -rf "./${NG_NAME}.conf" "${NG_CONFIG}"

if [ -f "/var/www/${newname}/index.html" ];then
echo "/var/www/${newname}/index.html文件已存在"
else
echo 正在创建 "/var/www/${newname}/index.html"...
cat > /var/www/${newname}/index.html << EOF
<html>

<head>
<title>我的第一个 HTML 页面</title>
</head>

<body>
<p>body 元素的内容会显示在浏览器中。</p>
<p>title 元素的内容会显示在浏览器的标题栏中。</p>
</body>

</html>
EOF
fi

echo 添加 /var/www/${newname} 权限...
chown -R nginx:nginx "/var/www/${newname}"

if [ -f "${ymname}" ];then
  echo "${ymname}文件已存在"
  else
echo 正在创建 "${ymname}"...
cat > ${ymname} << EOF
server {

  listen 127.0.0.1:80 default_server;
  server_name ${newname};
  index index.html;
  root /var/www/${newname};
}
server {

  listen 127.0.0.1:80;
  server_name ${wwip};
  return 301 https://${newname}\$request_uri;
}

server {
  listen 0.0.0.0:80;
  listen [::]:80;
  server_name _;
  return 301 https://\$host\$request_uri;
}
EOF
fi

if [ -f "${NG_SYSTEMDPATH}" ];then
  echo "文件存在"
  else
echo 正在创建 ${NG_NAME} systemd service to ${NG_SYSTEMDPATH}...
cat > "${NG_SYSTEMDPATH}" <<EOF
[Unit]
Description=nginx - high performance web server
Documentation=http://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID

[Install]
WantedBy=multi-user.target
EOF
fi

echo Reloading systemd daemon...
systemctl daemon-reload

if systemctl is-active --quiet nginx; then
    echo 强制停止和禁止 nginx...
	killall -9 nginx
    systemctl disable nginx
else
    echo "systemctl nginx没有运行"
fi

echo Installing ${NG_NAME} SSL证书...
/root/.acme.sh/acme.sh --installcert -d ${newname} --key-file /etc/nginx/ssl/${newname}/${newname}.key --fullchain-file /etc/nginx/ssl/${newname}/fullchain.cer --reloadcmd "systemctl restart nginx"

echo enable nginx...
systemctl enable nginx
}

setup_trojan(){
echo Downloading ${TJ_NAME} ${TJ_VERSION}...
curl -LO --progress-bar "${TJ_DOWNLOADURL}" || wget -q --show-progress "${TJ_DOWNLOADURL}"

echo Unpacking ${TJ_NAME} ${TJ_VERSION}...
tar -xf "${TJ_TARBALL}"

echo Installing ${TJ_NAME} ${TJ_VERSION} to ${TJ_BINARYPATH}...
install -Dm755 "./${TJ_NAME}/${TJ_NAME}" "${TJ_BINARYPATH}"

echo Installing ${TJ_NAME} server config to ${TJ_CONFIGPATH}...
install -Dm644 "./${TJ_NAME}/examples/server.json-example" "${TJ_CONFIGPATH}"

echo configure "${TJ_CONFIGPATH}"...
cat > "${TJ_CONFIGPATH}" << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "${TJ_PASS}"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "${SSLCER}",
        "key": "${SSLKEY}",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF

if [ -f "${TJ_SYSTEMDPATH}" ];then
  echo "文件已存在"
  else
echo Installing ${TJ_NAME} systemd service to ${TJ_SYSTEMDPATH}...
cat > "${TJ_SYSTEMDPATH}" << EOF
[Unit]
Description=${TJ_NAME}
Documentation=https://trojan-gfw.github.io/${TJ_NAME}/config https://trojan-gfw.github.io/${TJ_NAME}/
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service

[Service]
Type=simple
StandardError=journal
ExecStart="${TJ_BINARYPATH}" "${TJ_CONFIGPATH}"
ExecReload=/bin/kill -HUP \${MAINPID}
LimitNOFILE=51200
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
fi

echo Reloading systemd daemon...
systemctl daemon-reload

if systemctl is-active --quiet trojan; then
    echo 强制停止和禁止 trojan...
	killall -9 trojan
    systemctl disable trojan
else
    echo "systemctl trojan没有运行"
fi

echo start trojan...
systemctl start trojan

echo enable trojan
systemctl enable trojan

echo Deleting temp directory ${TMPDIR}...
rm -rf "${TMPDIR}"

echo Done!
}

off_log
fw_save
setup_bbr
set_user
setup_nginx
setup_trojan
