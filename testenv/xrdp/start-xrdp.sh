#!/bin/sh
set -eu

install -d -m 755 /run/xrdp
install -m 644 /certs/server.pem /etc/xrdp/test-cert.pem
install -o xrdp -g xrdp -m 600 /certs/server-key.pem /etc/xrdp/test-key.pem
sed -i \
    -e 's/^security_layer=.*/security_layer=tls/' \
    -e 's/^ssl_protocols=.*/ssl_protocols=TLSv1.2, TLSv1.3/' \
    -e 's|^certificate=.*|certificate=/etc/xrdp/test-cert.pem|' \
    -e 's|^key_file=.*|key_file=/etc/xrdp/test-key.pem|' \
    -e 's/^EnableSyslog=.*/EnableSyslog=false/' \
    -e 's/^#\{0,1\}EnableConsole=.*/EnableConsole=true/' \
    /etc/xrdp/xrdp.ini

if [ -s /account/password ]; then
    user=$(head -n1 /account/user)
    case "$user" in
    [a-z_][a-z0-9_-]*) ;;
    *) echo 'invalid test user name' >&2; exit 1 ;;
    esac
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/sh "$user"
    printf '%s:%s\n' "$user" "$(head -n1 /account/password)" | chpasswd
    echo "test account $user configured (password not logged)"
fi

/usr/sbin/xrdp-sesman
exec /usr/sbin/xrdp --nodaemon
