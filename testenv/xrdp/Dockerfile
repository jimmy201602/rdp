FROM mirror.gcr.io/library/ubuntu@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c

ARG DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        xrdp xorgxrdp xfce4-session xfwm4 xfce4-panel xterm dbus-x11 \
        openssl ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

COPY start-xrdp.sh /usr/local/bin/start-xrdp
RUN chmod 755 /usr/local/bin/start-xrdp
EXPOSE 3389
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/start-xrdp"]
