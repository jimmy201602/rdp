#!/bin/sh
set -eu
umask 077

if [ "$(uname -s)" != Linux ]; then
    echo 'Run this test environment on the Linux VM, not the local workstation.' >&2
    exit 1
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
name=${XRDP_CONTAINER_NAME:-rdp-go-kernel-xrdp}
port=${XRDP_PORT:-33890}
case "$port" in ''|*[!0-9]*) echo 'Invalid XRDP_PORT' >&2; exit 1;; esac
if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
    echo 'XRDP_PORT must be between 1024 and 65535' >&2
    exit 1
fi
command -v docker >/dev/null
command -v openssl >/dev/null

owned_container() {
    label=$(docker inspect --format '{{index .Config.Labels "rdp-kernel.test"}}' "$name" 2>/dev/null) || return 1
    if [ "$label" != true ]; then
        echo "Refusing to manage an unrelated container named $name" >&2
        exit 1
    fi
}

case "${1:-}" in
start)
    if owned_container; then
        docker start "$name" >/dev/null
        echo "Existing test server started: 127.0.0.1:$port (verify its published port with docker port)."
        exit 0
    fi
    certs="$root/.testenv/certs"
    mkdir -p "$certs"
    if [ ! -e "$certs/ca.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
            -subj '/CN=Go RDP kernel test CA' \
            -addext 'basicConstraints=critical,CA:TRUE' \
            -addext 'keyUsage=critical,keyCertSign,cRLSign' \
            -keyout "$certs/ca-key.pem" -out "$certs/ca.pem" >/dev/null 2>&1
        openssl req -new -newkey rsa:2048 -nodes \
            -subj '/CN=localhost' \
            -keyout "$certs/server-key.pem" -out "$certs/server.csr" >/dev/null 2>&1
        cat > "$certs/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT
        openssl x509 -req -in "$certs/server.csr" \
            -CA "$certs/ca.pem" -CAkey "$certs/ca-key.pem" -CAcreateserial \
            -days 2 -sha256 -extfile "$certs/server.ext" \
            -out "$certs/server.pem" >/dev/null 2>&1
    fi
    openssl x509 -checkend 0 -noout -in "$certs/ca.pem" >/dev/null
    openssl x509 -checkend 0 -noout -in "$certs/server.pem" >/dev/null
    # Test account for the INFO_AUTOLOGON path. The random password lives only
    # in .testenv/account (mode 0600, git-ignored) and inside the container.
    account="$root/.testenv/account"
    mkdir -p "$account"
    if [ ! -e "$account/password" ]; then
        printf '%s\n' "${XRDP_TEST_USER:-rdptest}" > "$account/user"
        openssl rand -base64 24 | tr -d '\n' > "$account/password"
        echo >> "$account/password"
    fi
    docker build -t rdp-go-kernel-xrdp:test "$root/testenv/xrdp"
    docker run -d --name "$name" --label rdp-kernel.test=true \
        --memory=1g --cpus=2 --pids-limit=256 \
        --publish "127.0.0.1:$port:3389" \
        --mount "type=bind,src=$certs,dst=/certs,readonly" \
        --mount "type=bind,src=$account,dst=/account,readonly" \
        rdp-go-kernel-xrdp:test >/dev/null
    echo "Test server starting on 127.0.0.1:$port; verify readiness with rdpprobe."
    echo "Trust file: $certs/ca.pem"
    echo "Test account: user in $account/user, password in $account/password (export it, e.g. RDP_TEST_PASSWORD=\$(cat $account/password), and pass -password-env RDP_TEST_PASSWORD)."
    ;;
stop)
    if owned_container; then
        docker rm -f "$name" >/dev/null
    fi
    ;;
*)
    echo 'Usage: sh scripts/xrdp-env.sh start|stop' >&2
    exit 2
    ;;
esac
