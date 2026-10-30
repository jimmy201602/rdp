> [中文文档](../VALIDATION.md)

# Validation Environment and Results (G1 negotiation + TLS, G2 part 1 MCS/GCC + Channel Join, G2 part 2 Client Info → Font Map, G2 part 3 observation after Font Map, G2 part 4 bitmap decoding, G2 part 5 Fast-Path output + pointer rendering, G3-1 server role + real xfreerdp client, G3-3 gateway xfreerdp → rdpgw → xrdp, G3-4 static virtual channel passthrough + back-end NLA: xfreerdp → rdpgw → Windows 7 / Server 2016, G3-5 front-end NLA: xfreerdp /sec:nla → rdpgw CredSSP server → Windows 7 / Server 2016, G3-6 logon form: xfreerdp → rdpgw -login-form (target entered in the form) → Windows 7 / Server 2016)

This document records how the isolated xrdp interop environment was set up, the commands run, and the actual results. The conclusions cover TPKT/X.224/RDP security negotiation, TLS server authentication, MCS Connect-Initial/Response and the GCC Basic Settings Exchange (including reconfirmation of the negotiation result), Erect Domain / Attach User / Channel Join (user channel + I/O channel), Client Info, MS-RDPELE licensing, the Demand/Confirm Active capability exchange, and the Synchronize/Control/Font List/Font Map connection finalization. G2 part 3 keeps reading server output after Font Map (Slow-Path Update / Pointer / Save Session Info category counts); G2 part 4 decodes Bitmap Updates (Interleaved RLE) into a framebuffer and exports PNG, yielding the complete login screen and xfce desktop on xrdp (see 5.5); G2 part 5 advertises FASTPATH_OUTPUT_SUPPORTED, handles both TPKT and fast-path PDUs in the read loop, and decodes pointer updates into RGBA cursors (see 5.6). G3-1 implements the reverse, server-side role (`server` package / `rdpserve`), validated with a Go client loopback e2e and a real xfreerdp 2.6.1 + Xvfb on the VM, covering negotiation, TLS, Client Info policy, licensing, capability exchange, finalization, and bitmap/cursor output (see 5.7). Orders, input, and virtual channels are not implemented; with a test account the xrdp-side log records a successful login and a started Xorg session, but xrdp never sends Save Session Info, so there is no logon notification at the protocol layer (see 5.4).

## 1. Topology

```
Local macOS (write code, run unit/fuzz tests, cross-compile the Linux probe)
        │  copy the go-kernel source tarball (from G2 part 2 onward, compile directly with Go on the VM; copying an 8 MB binary over the Devin host channel drops the connection)
        ▼
Linux VM (Ubuntu 22.04.5, Docker 29.7.2, Go 1.25.3 linux/amd64 used only to compile the probe)
        │  docker run --publish 127.0.0.1:33890:3389
        ▼
Container rdp-go-kernel-xrdp (Ubuntu 24.04 + xrdp 0.9.24, security_layer=tls)
```

xrdp is only a standalone interop test server; it is not linked into the kernel and is not a product dependency. The port is published only on the VM loopback and is not exposed to the public internet (xrdp inside the container still listens on 0.0.0.0:3389 and is reachable from other containers on the same Docker bridge; this is a known and accepted scope).

## 2. Components and Versions

| Component | Version / identifier | Source |
|---|---|---|
| Local Go | go1.27.1 darwin/amd64 | local workstation |
| VM OS / kernel | Ubuntu 22.04.5 LTS / 6.8.0-1061-aws x86_64 | VM |
| VM Docker | 29.7.2 | VM |
| VM OpenSSL (generate test certificates) | 3.0.2 | VM |
| Container base image | `mirror.gcr.io/library/ubuntu@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c` (ubuntu:24.04) | Docker Hub pull hit 429, switched to the GCR mirror |
| xrdp / xorgxrdp | 0.9.24-4ubuntu0.1 / 1:0.9.19-1 | Ubuntu 24.04 apt |
| openssl / tini / xfce4-session in container | 3.0.13-0ubuntu3.16 / 0.19.0-1 / 4.18.3-1build2 | Ubuntu 24.04 apt |

The Dockerfile pins the base image by digest; apt package versions are not pinned. On rebuild, record the actual `dpkg -l` output and write it back into this table.

## 3. Files

| Path | Purpose |
|---|---|
| `testenv/xrdp/Dockerfile` | Installs xrdp/xorgxrdp/xfce/tini; entrypoint is `start-xrdp` |
| `testenv/xrdp/start-xrdp.sh` | Installs the test certificates from `/certs` into `/etc/xrdp`, edits `xrdp.ini`: `security_layer=tls`, `ssl_protocols=TLSv1.2, TLSv1.3`, `certificate`/`key_file` point at the test certificates, syslog off, console logging on; if `/account` is mounted, creates a one-shot test account with `useradd`/`chpasswd` (password never printed); starts `xrdp-sesman` and `xrdp --nodaemon` |
| `scripts/xrdp-env.sh start|stop` | Linux only: generates a one-shot test CA and `localhost`/`127.0.0.1` server certificate (CA 7 days, server certificate 2 days, in `.testenv/certs/`, umask 077), generates the test account name `rdptest` (override with `XRDP_TEST_USER`) and a 24-byte random password into `.testenv/account/`, builds the image, and starts the container with `--publish 127.0.0.1:$XRDP_PORT:3389` (default 33890), memory/CPU/PID limits, read-only mounts of the certificate and account directories, and the `rdp-kernel.test=true` label; `stop` removes only containers carrying that label |
| `cmd/rdpprobe` | Probe CLI; `-ca` sets the trusted PEM root, `-server-name` sets the SNI/verification name, `-stage tls\|channel-join\|client-info\|license\|capabilities\|activated` (default channel-join) controls where to stop, `-client-name` sets the client name in Client Core Data, `-user`/`-domain`/`-password-env` fill in Client Info (the password is read only from an environment variable and never appears on the command line, in the report, or in logs; INFO_AUTOLOGON is set only when a password is given), `-observe <duration>` (only with `-stage activated`, otherwise rejected) keeps reading server output after Font Map and counts it (update types, bitmap rects/compression/bytes, orders count, pointer types, Save Session Info, Set Error Info, Deactivate All reactivation count) and decodes Bitmap Updates into a framebuffer of the desktop size used by `-stage` (1024x768) (the `framebuffer:` report line / JSON `observation.frame`: rect count, RLE count, clipped count, pixels written, coverage, color depth, dirty region, decode errors, pixel SHA-256), `-png <file>` (requires `-observe`) writes the framebuffer as PNG (compositing the cursor when its position is known and visible), `-cursor-png <file>` writes the current cursor shape; the report also has a `fast-path:` line (fast-path PDU count, per-updateCode counts, fragment reassembly count) and a `pointer:` line (decoded cursor count, cache hits/misses, visibility, position, current cursor size/hotspot/color depth/SHA-256, errors), with JSON fields `observation.fastpath_pdus/fastpath_updates/fragments/pointer`; `-timeout` is automatically extended by the observation duration, `-json` prints the report |
| `server` package / `cmd/rdpserve` | G3-1 server role and validation CLI: `rdpserve -listen 127.0.0.1:33891 -user demo -password-env RDP_DEMO_PASSWORD [-cert/-key] [-once] [-json]`; without a certificate it generates a temporary self-signed one (testing only); `-json` prints one line per completed session (remote/user/domain/client/stage/authorized/duration_ms/error, no password) |
| `bitmap` package | Interleaved RLE decompression, RGBA framebuffer, pointer XOR/AND mask decoding and caching, cursor compositing (unit tests + fuzz), depends only on the standard library and `wire` |
| `transport.Session` / `server.Handler`+`server.Conn` | G3-3 foundation: `transport.Dial` runs through TLS → MCS → Client Info → licensing and keeps the connection; `ReadPDU` (slow-path I/O channel payload or a whole fast-path frame) / `WriteIO` / `WriteFastPath` / `Disconnect`; `server.Config.Handler` hands the connection to the caller after licensing completes (`Conn.Peer/Credentials/ReadPDU/WriteIO/WriteFastPath/Deny/Disconnect`); `Credentials` is valid only until Handler returns and is zeroed afterwards; without a Handler the G3-1 demo server behavior is kept |
| `gateway` package / `cmd/rdpgw` | G3-3 gateway: `Route(ctx, Peer) (Target, error)` policy selects the target (deny → Set Error Info DENIED + DPU); credentials are passed through to the target exactly once (Client Info, never into logs/Summary); Demand Active / Confirm Active are filtered by the `AllowCapability` whitelist (Surface Commands, Bitmap Codecs, Frame Ack, RAIL/Window/NineGrid/GDI+/CompDesk dropped by default); other Share Control PDUs have pduSource rewritten to the user channel assigned by the target; fast-path frames are forwarded whole in both directions; slow-path/fast-path input is decoded and counted (categories only, no scancodes/coordinates); when either side ends, a DPU is sent to the other side and everything is cleaned up; `rdpgw -listen … -cert/-key -target host:port -target-ca ca.pem -target-name name [-allow-user u]... [-allow-domain d]... [-target-timeout] [-handshake-timeout] [-max-sessions] [-once] [-json]`; `-json` prints a session line and a relay line per session (PDU/fast-path counts, bytes, input category counts, dropped capability types, reactivation count, ending party client-closed/target-closed/canceled/error) |

`.testenv/` (certificates, test account) and `.build/` are in `.gitignore` and are not committed.

## 4. Procedure

### 4.1 Local (macOS)

```sh
cd go-kernel
gofmt -l . && go vet ./...
CGO_ENABLED=0 go test -count=1 -timeout 120s ./...
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzReadTPKT -fuzztime=10s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecodeConnectionConfirm -fuzztime=10s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecodeConnectResponse -fuzztime=8s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDomainPDUs -fuzztime=5s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecodeSendDataIndication -fuzztime=5s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecodeDemandActive -fuzztime=5s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecodeDataPDU -fuzztime=5s ./wire
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzHandle -fuzztime=5s ./licensing
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecompress -fuzztime=20s ./bitmap
CGO_ENABLED=0 go test -run='^$' -fuzz=FuzzDecodeFastPathPDU -fuzztime=10s ./wire
tar --exclude=.build --exclude=.testenv -czf .build/go-kernel-src.tar.gz -C .. go-kernel
```

Copy `.build/go-kernel-src.tar.gz` to `~/rdp-kernel-validation/` on the VM (the probe is compiled on the VM, see 4.2; copying an 8 MB binary over the host channel drops the connection).

### 4.2 VM (Linux)

```sh
cd ~/rdp-kernel-validation
tar -xzf go-kernel-src.tar.gz
(cd go-kernel && CGO_ENABLED=0 go build -trimpath -o ../rdpprobe-linux-amd64 ./cmd/rdpprobe)   # Go 1.25.3 on the VM
cd go-kernel && sh scripts/xrdp-env.sh start        # first build takes about 1–2 minutes
docker ps --filter name=rdp-go-kernel-xrdp           # should show 127.0.0.1:33890->3389/tcp
cd ..
CA=go-kernel/.testenv/certs/ca.pem
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA"              # default runs to channel-join
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -json
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage tls   # TLS only
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage activated   # Client Info → Font Map, no credentials
RDP_TEST_PASSWORD=$(head -n1 go-kernel/.testenv/account/password) ./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 \
    -server-name localhost -ca "$CA" -stage activated -user "$(head -n1 go-kernel/.testenv/account/user)" -password-env RDP_TEST_PASSWORD
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage activated -observe 8s   # read server output for 8 s after Font Map
RDP_TEST_PASSWORD=$(head -n1 go-kernel/.testenv/account/password) ./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 \
    -server-name localhost -ca "$CA" -stage activated -observe 15s -user "$(head -n1 go-kernel/.testenv/account/user)" -password-env RDP_TEST_PASSWORD
docker exec rdp-go-kernel-xrdp tail -n 30 /var/log/xrdp-sesman.log   # login result only appears in server-side logs
# G3-3 gateway: front end uses the same test certificates (xfreerdp verifies the name localhost), back end trusts the test CA
(cd go-kernel && CGO_ENABLED=0 go build -o ../rdpgw ./cmd/rdpgw)
C=go-kernel/.testenv/certs
./rdpgw -listen 127.0.0.1:33892 -cert $C/server.pem -key $C/server-key.pem -target 127.0.0.1:33890 -target-ca $C/ca.pem -target-name localhost -allow-user rdptest -json &
export DISPLAY=:99; export RDP_PW=$(head -n1 go-kernel/.testenv/account/password)   # export is required for expansion inside sh -c
sh -c 'xfreerdp /v:127.0.0.1:33892 /u:rdptest /p:"$RDP_PW" /cert:ignore /sec:tls /size:1024x768 /bpp:24 -clipboard /log-level:INFO' &
sleep 8; import -window root gw-desktop.png; xdotool mousemove 50 12 click 1   # open the xfce menu through the gateway
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage activated -observe 8s -png login.png   # decode bitmaps and export the picture (xrdp login screen)
RDP_TEST_PASSWORD=$(head -n1 go-kernel/.testenv/account/password) ./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 \
    -server-name localhost -ca "$CA" -stage activated -observe 15s -user "$(head -n1 go-kernel/.testenv/account/user)" -password-env RDP_TEST_PASSWORD -png desktop.png -cursor-png cursor.png   # xfce desktop + current cursor
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost                 # expected failure: system roots do not trust the test CA
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name wrong.example.test -ca "$CA"  # expected failure: hostname mismatch
```

Logs: `docker logs rdp-go-kernel-xrdp`, or `/var/log/xrdp.log` and `/var/log/xrdp-sesman.log` inside the container.

Cleanup: `cd go-kernel && sh scripts/xrdp-env.sh stop`; to also remove the image and certificates: `docker rmi rdp-go-kernel-xrdp:test && rm -rf .testenv`.

## 5. Actual Results

### 5.1 G1 (2026-10-29, negotiation + TLS)

Local: `gofmt`/`go vet` pass; `wire` and `transport` unit tests pass (TPKT boundary/truncation/short write, X.224 Microsoft sample vectors, malformed CC, negotiation failure, non-TLS selection rejection, unknown CA rejection, hostname mismatch rejection, timeouts); `FuzzReadTPKT` ~2.03M and `FuzzDecodeConnectionConfirm` ~1.80M executions with no crashes; linux/amd64 cross-compiled artifact SHA-256 `e8134b77f0e76f738350145df07390bda1c88b014d1ec6563ac441abe6822f9b`.

| Case | Result |
|---|---|
| Trust test CA, `-server-name localhost` | `negotiation: ok (PROTOCOL_SSL, flags=0x01)`; `tls: ok (TLS1.3, TLS_AES_128_GCM_SHA256, peer=CN=localhost)`; exit code 0 |
| Without `-server-name` (verified against IP SAN 127.0.0.1) | Same as above, pass |
| System roots | Negotiation ok; TLS fails with `x509: certificate signed by unknown authority`; exit code 1 |
| `-server-name wrong.example.test` | Negotiation ok; TLS fails with `certificate is valid for localhost, not wrong.example.test`; exit code 1 |
| Port 33891 closed | `dial ... connection refused`; exit code 1 |

xrdp-side log: `Security protocol: configured [SSL], requested [SSL|RDP], selected [SSL]` (xrdp displays requestedProtocols=0x01 as SSL|RDP; PROTOCOL_RDP=0 is implicit). In the verification-failure cases xrdp logs `sslv3 alert bad certificate`, i.e. the client aborted. `flags=0x01` is `EXTENDED_CLIENT_DATA_SUPPORTED`, recorded only and currently unused.

### 5.2 G2 part 1 (2026-10-29, MCS/GCC + Channel Join)

Local: `gofmt`/`go vet` pass; all new tests pass — `EncodeConnectInitial` reproduces the 416-byte MS-RDPBCGR 4.1.3 sample byte for byte; `DecodeConnectResponse`/GCC/SC_CORE/SC_NET/SC_SEC1 parse the 4.1.4 sample; Attach User Confirm and Channel Join Confirm use the 4.1.7/4.1.8 samples; malformed BER/PER/user-data blocks, non-success MCS results, and DisconnectProviderUltimatum all have rejection cases; `transport` uses a built-in fake server to cover SC_CORE echoed protocol mismatch, server demanding Standard RDP Security encryption, server assigning unrequested static channels, missing SC_SECURITY/SC_NET, Attach User failure, and Join Confirm channel mismatch. `FuzzDecodeConnectResponse` 8 s and `FuzzDomainPDUs` 5 s with no crashes. linux/amd64 cross-compiled artifact SHA-256 `33947427a3497d27cefbf770b4a489247c164bdcbc73f637f70b61600985a2ef`.

| Case | Result |
|---|---|
| Default `-stage channel-join`, trust test CA | `mcs connect: ok (server version 0x00080004, protocol reconfirmed=true, encryption method/level=0/0, io channel=1003)`; `channel connection: ok (user channel 1004, joined [1004 1003])`; `reached stage: channel-join`; exit code 0, 6 ms |
| `-stage tls` | Negotiation and TLS ok; MCS/channel stages shown as `skipped` |
| System roots | TLS fails; MCS/channel `not attempted`; `reached stage: negotiation`; exit code 1 |

xrdp-side log: `Connected client computer name: rdpkernel`, `xrdp_load_keyboard_layout: ... keyboard_type:[0x04] ... keylayout:[0x00000409]`, `TLS connection established ... TLSv1.3 with cipher TLS_AES_128_GCM_SHA256`, showing that the Client Core Data in Connect-Initial was parsed correctly by xrdp; the probe then closes on its own after Channel Join completes, and xrdp logs `libxrdp_force_read: header read error` and sends DisconnectProviderUltimatum — expected, since the next step, the Client Info PDU, is not implemented yet.

Negotiation result reconfirmation: xrdp echoes `PROTOCOL_SSL` in SC_CORE's `clientRequestedProtocols`, matching the client's request; SC_SECURITY is `ENCRYPTION_METHOD_NONE`/`ENCRYPTION_LEVEL_NONE`, consistent with Enhanced RDP Security. Any mismatch would drop the connection at the MCS stage (see the `transport` tests).

### 5.3 G2 part 2 (2026-10-29, Client Info → licensing → capability exchange → Font Map)

Local: `gofmt`/`go vet` pass; all `licensing`, `transport`, and `wire` tests pass. `licensing` is validated with the public MS-RDPELE 4.1/4.4/4.5 samples (Server License Request including the X.509 chain and 8+4n bytes of trailing padding, Platform Challenge, Platform Challenge Response) and a fake server holding its own RSA key (decrypts the premaster, derives the same set of keys, sends Platform Challenge and New License, and verifies every MAC); `transport` uses a built-in fake server that runs all the way from TLS to Font Map (MS-RDPBCGR 4.1.12 Demand Active sample), and covers not sending a password / not setting INFO_AUTOLOGON without credentials, correct encoding when credentials are given, licensing ERR_INVALID_CLIENT, Set Error Info, Deactivate All, and illegal stop stages. New fuzz targets `FuzzDecodeSendDataIndication`, `FuzzDecodeDemandActive`, `FuzzDecodeDataPDU` (wire) and `FuzzHandle` (licensing) each ran 5 s with no crashes; the older targets were re-run 5 s each with no crashes. Probe compiled on the VM: SHA-256 `23ba3a43dfb7936810313dd1e5cee714f17c0e64202820ad687ca0d50f2133c7` (pre-fix version; the two xrdp compatibility fixes below came later — final code is the local workspace).

| Case | Result |
|---|---|
| `-stage activated`, no credentials | `client info: ok (autologon=false)`; `license: ok (valid-client, product "236")`; `capabilities: ok (share 0x000103ea, server channel 1004, source "RDP", 13 server capability sets)`; `activation: ok (received synchronize control-cooperate control-granted font-map)`; `reached stage: activated`; exit code 0 |
| `-stage activated`, `-user rdptest -password-env RDP_TEST_PASSWORD` | Same as above, `client info: ok (autologon=true)`; the report's `not verified` states "logon outcome ... not observed" |
| `-stage capabilities` / `-stage license` | Reaches the respective stage ok, later stages `skipped` |

Two xrdp compatibility issues found and fixed during interop (both got regression tests):

1. xrdp's built-in proprietary certificate declares a 512-bit RSA key, but the modulus is actually only 511 bits; the original implementation treated `modulus.BitLen() < 512` as a degenerate key. It now rejects only when the modulus is more than 8 bits shorter than the declared length or the exponent is < 3 (keylen/bitlen themselves are still validated per spec).
2. xrdp replies to a New License Request with a Licensing Error Message carrying STATUS_VALID_CLIENT, whose zero-length blob has `wBlobType` 0x1428; per MS-RDPBCGR 2.2.1.12.1.3, when `wBlobLen` is 0, `wBlobType` is ignored. The original implementation enforced BB_ERROR_BLOB; the type is now checked only for non-empty blobs.

xrdp-side log: `xrdp_caps_process_pointer: client supports new(color) cursor`, `xrdp_process_offscreen_bmpcache: support level 0 ...` show the Confirm Active capability sets were parsed by xrdp; after receiving Font Map the probe closes on its own, and xrdp then logs many `xrdp_rdp_send_data: xrdp_sec_send failed` (it was trying to send the login screen bitmap) and sends DisconnectProviderUltimatum — expected. xrdp's licensing path does not go through Platform Challenge / New License; those branches are validated only against the local fake server and the public samples. In the credential case, xrdp initiates the login via sesman only after Font Map, by which time the probe has already disconnected, so the logs contain no login success/failure record — `autologon=true` must not be interpreted as the account having been authenticated.

### 5.4 G2 part 3 (2026-10-29, observation after Font Map: Update / Pointer / Save Session Info)

Local: `gofmt`/`go vet` pass; `wire` gains decode tests for Save Session Info (TS_LOGON_INFO / VERSION_2 / PLAIN_NOTIFY / EXTENDED including logon errors), Slow-Path Update (Bitmap rects and compression flags, Orders count, Palette, Synchronize), Pointer, and the Fast-Path output header; `transport` gains `observe` read-loop tests (mixed bitmap / pointer / save session info / unknown pduType2, window timeout while the server is silent, Deactivate All → reactivation). Probe compiled on the VM with Go 1.25.3: SHA-256 `1bfa9c58706a8c35e6d7cc190e0e126dae7353d686f8be0493a21e15195579aa` (this section's code; the switch of JSON fields to snake_case and the `-observe` argument validation were added afterwards — final code is the local workspace).

| Case | Result |
|---|---|
| `-stage activated -observe 8s`, no credentials | Reaches `activated` as in 5.3; `observed: 45 PDUs in 8.04s, end=timeout, updates=map[bitmap:42 synchronize:1] (bitmap rects 190, 190 compressed, 74298 bytes; 0 orders), pointers=map[new:2], other=map[], reactivations=0`; no logon notification; exit code 0 |
| `-stage activated -observe 15s`, `-user rdptest -password-env RDP_TEST_PASSWORD` | `client info: ok (autologon=true)`; `observed: 23 PDUs in 15.053s, end=timeout, updates=map[bitmap:17 synchronize:1] (bitmap rects 666, 666 compressed, 32304 bytes; 0 orders), pointers=map[cached:2 new:3], other=map[], reactivations=0`; no logon notification, no Set Error Info; exit code 0 |
| `-stage activated -observe 3s -json` | Report contains an `observation` object (counts as above; `logon` omitted when empty) |
| `-stage capabilities -observe 2s` | Probe refuses before connecting: `-observe requires -stage activated` |

xrdp-side logs (with credentials): `xrdp.log` records `sending login info to session manager`, `login successful for user rdptest on display 10`, `lib_mod_connect: connecting via UNIX socket` / `connected ok`; `xrdp-sesman.log` records `++ created session (access granted): username rdptest`, `Starting session: ... display :10.0, width 1024, height 768, bpp 24`, `Session started successfully for user rdptest on display 10` (there is also a `sesman_data_in: scp_process_msg failed`; the session still started normally and this was not investigated further). That is, the credentials in INFO_AUTOLOGON were used by xrdp for PAM authentication and an Xorg/xfce session was started; however, xrdp 0.9.24 never sends a Save Session Info PDU, there is no logon notification at the protocol layer, and login success can only be confirmed from server-side logs — the probe report still lists the logon outcome as not verified. Without credentials xrdp does not contact sesman, and the received bitmap is its built-in login screen; with credentials there are more bitmap rects (666 small rects, incremental refresh of the xfce desktop). In both cases there was no Deactivate All, Set Error Info, or orders/palette updates; all bitmap rects carry the compression flag (xrdp's Interleaved RLE) and were only counted, not decoded, in this round; there was no fast-path output (not declared in Confirm Active). After the probe closes at the timeout, xrdp logs `xrdp_iso_send: trans_write_copy_s failed` / `Sending [ITU T.125] DisconnectProviderUltimatum failed` — expected.

### 5.5 G2 part 4 (2026-10-29, Bitmap Update decoding: Interleaved RLE → framebuffer → PNG)

Local: `gofmt`/`go vet` pass; new `bitmap` package (`Decompress` covers all RLE orders, extended lengths, first-line/non-first-line XOR, BG_RUN foreground pixel insertion, 8/15/16/24/32bpp, truncation/overflow/underfill/unknown-order rejection; `Framebuffer.Draw` covers bottom-up flipping, clipping to the destination rect and the screen, 8bpp before/after a Palette, RGB555/565/BGR24/BGRX32 conversion, rejected rects leaving the picture unchanged); `FuzzDecompress` 20 s with no crashes; the `transport` observe test adds `Options.Render` checking `Observation.Frame`. Probe compiled on the VM with Go 1.25.3: SHA-256 `d8c89cc5e175275cc021b64d64861ec62ceb9640e52e832e7f17a1309db46141`.

| Case | Result |
|---|---|
| `-stage activated -observe 8s -png login.png`, no credentials | `observed: 45 PDUs ... bitmap rects 190, 190 compressed`; `framebuffer: 1024x768, 190 rects (190 rle, 112 clipped), 850977 pixels written, 786432/786432 covered (100.0%), depths=map[24:190], dirty (0,0)-(1024,768), 0 decode errors`; the PNG is the complete xrdp built-in login window (teal background, xrdp logo, Session/username/password/OK/Cancel), text and icons sharp, no misalignment, no color shift; exit code 0 |
| `-stage activated -observe 15s -user rdptest -password-env RDP_TEST_PASSWORD -png desktop.png` | `bitmap rects 669, 669 compressed`; `framebuffer: 669 rects (669 rle, 9 clipped), 3357513 pixels written, 786432/786432 covered (100.0%), depths=map[24:669], 0 decode errors`; the PNG is the xfce desktop: top panel (Applications, clock, username rdptest), bottom dock icons; the desktop background is pure black because Client Info's performanceFlags carry PERF_DISABLE_WALLPAPER — expected; exit code 0 |
| `-stage activated -observe 3s -json` | `observation.frame` object fields `width/height/rects/decompressed/clipped/pixels/covered/depths/dirty/sha256`; the pixel SHA-256 of the same login screen matches the 8 s case (`7a92b17a...`), i.e. the full-frame repaint is deterministic |
| `-stage activated -png x.png` (no `-observe`) | Refused before connecting: `-png requires -observe` |

Notes: all of xrdp's bitmaps are 24bpp Interleaved RLE; rect widths are aligned to 4 pixels and often larger than destRight-destLeft+1, so the clip counts (112 / 9) are normal; decode correctness was judged by visual comparison of the PNGs, with no pixel-by-pixel comparison against another client; 100% coverage shows xrdp repaints the whole desktop after connecting. Neither run produced a Palette Update; the 8bpp path is covered only by unit tests.

### 5.6 G2 part 5 (2026-10-29, Fast-Path output + pointer rendering)

Local: `gofmt`/`go vet` pass; `wire` gains fast-path framing decode tests (short/long lengths, multiple updates, fragmentation and compression flags, ReadFastPathPDU consuming exactly one PDU, encryption flag/length/truncation rejection, fast-path pointer conversion, numberOrders) and `FuzzDecodeFastPathPDU` 10 s; `bitmap` gains cursor decode tests (24bpp XOR/AND combinations: transparent, inverted approximated as black, opaque; 1bpp, 8bpp palette, 16bpp, 32bpp with/without alpha; size/mask-length rejection), a pointer state machine (New → cache → Null hide → Cached hit/miss/out-of-range → Default → unknown type) and compositing; `transport` gains `TestActivateObserveFastPath`: a fake server writes 5 fast-path PDUs verbatim after a slow-path Update (bitmap + synchronize + position merged into one packet, a Color pointer split into FIRST/NEXT/LAST fragments, orders, cached, surfcmds), verifying that Confirm Active's extraFlags include FASTPATH_OUTPUT_SUPPORTED, that counts from both paths merge, fragment reassembly, and cursor compositing at the hotspot into the framebuffer. Probe compiled on the VM: SHA-256 `72a2caf2191d5d79c88966186956cc07055851381d8b0a01a7d21d0700b6136b`.

| Case | Result |
|---|---|
| `-stage activated -observe 8s -png login-fp.png -cursor-png cursor-login.png`, no credentials | `observed: 45 PDUs ... pointers=map[new:2]`; `fast-path: 3 of 45 PDUs, updates=map[ptr-new:2 synchronize:1], 0 reassembled`; `pointer: 2 cursors decoded, cache hits 0, misses 0, visible=true, position unknown, current 32x32 hotspot (0,0) xorBpp 24 cache 0, 0 errors`; `framebuffer: ... 0 decode errors`, PNG still the complete login screen; the cursor PNG is the standard black arrow with a white edge; exit code 0 |
| `-stage activated -observe 15s -user rdptest -password-env RDP_TEST_PASSWORD -png desktop-fp.png -cursor-png cursor-desktop.png` | `pointers=map[cached:2 new:3]`; `fast-path: 6 of 24 PDUs, updates=map[ptr-cached:2 ptr-new:3 synchronize:1]`; `pointer: 3 cursors decoded, cache hits 2, misses 0, visible=true, position unknown, current 32x32 hotspot (3,1) xorBpp 32 cache 2, 0 errors`; the cursor PNG is the xfce theme's black arrow (32bpp with alpha, anti-aliased translucent edges); framebuffer as in 5.5; exit code 0 |
| `-stage activated -observe 3s -json` | `observation` gains `fastpath_pdus`, `fastpath_updates`, `fragments`, `pointer` (including `current`'s size/hotspot/color depth/cache slot/SHA-256) |
| `-stage activated -cursor-png x.png` (no `-observe`) | Refused before connecting: `-png/-cursor-png require -observe` |

Notes: after FASTPATH_OUTPUT_SUPPORTED is declared, xrdp 0.9.24 moves Synchronize and all pointer updates to fast-path, while bitmap updates stay on slow-path Share Data (hence `fast-path:` only 3/45 and 6/24); there was no fragmentation (updates are small), no compression flags, and no Surface Commands; xrdp never sends Pointer Position, so the cursor position is unknown, `-png` does not composite the cursor, and the cursor is exported separately via `-cursor-png`. Both cursor images were verified by eye (shape, hotspot, transparent edges).

### 5.7 G3-1 (2026-10-29, server role: Go client loopback + real xfreerdp client)

Local/VM: `gofmt`/`go vet` pass; `wire` gains `server_test.go` (Connection Request decoding with cookie / without RDP_NEG_REQ / malformed rejection, Connection Confirm and NEG_FAILURE encode round-trips, MS-RDPBCGR 4.1.3 Connect-Initial decoded into CS_CORE/CS_SECURITY/CS_NET fields, 4.1.4 Connect-Response re-encoded byte-identical after decoding, self-written SC_* → ConferenceCreateResponse → Connect-Response round-trips, Erect Domain / Attach User / Channel Join request decoding and Confirm/failure/DPU encoding, Client Info Unicode with extended section and minimal ANSI round-trips, licensing header rejection, truncation rejection, Demand Active self-written round-trip and 4.1.12 sample re-encoded identically, Deactivate All / Font Map / Set Error Info / Font List, Bitmap Update and the 5 Pointer types encoded and round-tripped through the existing decoders); `licensing` gains `EncodeValidClientAlert` which the client state machine accepts as `valid-client`; `server` gains `TestLoopbackActivationAndGraphics` (`transport.Activate` + `Observe/Render` against `server.Serve`: PROTOCOL_SSL, ENCRYPTION_NONE, SC_CORE reconfirmation, valid-client, the 4 finalization PDUs, `Peer` fields, Bitmap Update and 1 Color pointer, the rendered framebuffer matching the server's `TestPattern` pixel-for-pixel at 5 sample points, no password in logs, `Serve` returning after context cancellation with `Summary.Authorized`), `TestPolicyDenied` (client gets `ERRINFO_SERVER_DENIED_CONNECTION`, server `Summary.Err` is `ErrDenied`), `TestRefusesNonTLSClient` (PROTOCOL_RDP only → RDP_NEG_FAILURE SSL_REQUIRED_BY_SERVER), `TestHandshakeTimeoutAndGarbage` (HTTP request → `ErrProtocol`, no reply), `TestNewRejectsBadConfig`; `go test -race ./server ./transport` passes. Incidental `transport` fix: when a Share Data PDU (Set Error Info) arrives where Demand Active is expected, report the ERRINFO instead of a pduType mismatch.

Real client on the VM: Ubuntu 22.04 `apt install freerdp2-x11` (xfreerdp 2.6.1) + `Xvfb :99 -screen 0 1024x768x24`, `rdpserve -listen 127.0.0.1:33891 -user demo -password-env RDP_DEMO_PASSWORD -json` (temporary self-signed certificate).

| Case | Result |
|---|---|
| `xfreerdp /v:127.0.0.1:33891 /u:demo /p:… /cert:ignore /size:640x480 /sec:tls /bpp:32` | Server log `x224 ok → tls ok → mcs-connect ok → mcs-join ok → client-info ok → license ok → capabilities ok → finalize ok → output ok`; xfreerdp window 640x480, `import -window root` screenshot samples (5,5)=white, (100,50)=yellow, (200,50)=cyan, (320,400)=grey (200,200,200), (636,476)=(32,32,96), matching `TestPattern` (server converts and pushes at the client's preferred 32bpp); no xfreerdp errors; after Ctrl-C the server prints `{"authorized":true,"client":"devin-box","stage":"output","user":"demo",...}` |
| Same with `/size:400x300 /bpp:16`, without `/sec:` (client requests NLA\|TLS by default) | Server selects PROTOCOL_SSL, xfreerdp accepts; 16bpp push screenshot samples white/yellow/cyan/green/(32,32,96)/black match the pattern |
| `/p:wrong` (policy denial) | Server `policy denied user "demo" … : bad password`, `stage":"mcs-join","authorized":false`; xfreerdp logs `ERRINFO_SERVER_DENIED_CONNECTION (0x00000007):The server denied the connection.` and exits |
| `/sec:rdp` (Standard RDP Security only) | Server `negotiation failed: client offered protocols 0x00000000 without PROTOCOL_SSL`; xfreerdp `Error: SSL_REQUIRED_BY_SERVER` / `Protocol Security Negotiation Failure` |

Notes: xfreerdp 2.6.1 requests static channels cliprdr/rdpdr/rdpsnd/drdynvc in CS_NET; the server assigns channel numbers starting at 1004 in request order and accepts the joins, and channel data is discarded; fast-path input (mouse moves) sent by the client after activation is discarded by length, unparsed. In the screenshots the cursor is composited by Xvfb/xfreerdp and the screenshot tool excludes cursors, so for color pointers one can only confirm xfreerdp receives them without error (the Go client loopback already round-trips every field). mstsc / Windows clients were not tested.

### 5.8 G3-3 (2026-10-29, gateway: xfreerdp → rdpgw → xrdp)

Local/VM: `gofmt`/`go vet`/`golangci-lint`/`CGO_ENABLED=0 go test ./...` pass; `go test -race -count=3 ./gateway ./server ./transport` passes. `gateway` unit tests: `TestRelayEndToEnd` (Go client `transport.Activate` → gateway → `server.Serve` demo server: the target receives the passed-through username/password, the client activates and receives the pattern, Summary is client-closed), `TestRouteDenied` (`ERRINFO_SERVER_DENIED_CONNECTION`), `TestTargetUnreachable`, `TestTargetRejectsPassedThroughCredentials` (target policy denial → client DENIED, `ErrBackend`), `TestCapabilityFilter`; `wire` gains `input_test.go` (slow-path/fast-path input decoding). Fixed a relay-end classification race: the context is cancelled and the other side closed only after the first ending party is determined; otherwise the `AfterFunc` close would record client-closed as target-closed.

Real chain on the VM: Ubuntu 22.04 + Xvfb :99, xfreerdp 2.6.1 → `rdpgw 127.0.0.1:33892` (front end uses `.testenv/certs/server.pem`, back end `-target-ca ca.pem -target-name localhost`) → Docker xrdp 0.9.24 `127.0.0.1:33890`, input injected with xdotool 3.20211022.1.

| Case | Result |
|---|---|
| `xfreerdp /v:127.0.0.1:33892 /u:rdptest /p:… /cert:ignore /sec:tls /size:1024x768 /bpp:24` | Gateway `x224 ok → … → license ok → target 127.0.0.1:33890 licensed (user channel 1004), relaying`; xrdp log `Connected client computer name: devin-box`, `login successful for user rdptest on display 10`, `connected ok` (sesman `++ reconnected session`/`created session`); screenshot after 6 s is the full xfce desktop (top bar Applications/clock/`rdptest`, bottom dock), not the xrdp login window |
| Same, `xdotool` clicks the Applications menu → Esc → clicks the dock terminal → types `echo gateway-ok` + Enter | Screenshot 1: xfce application menu expanded; screenshot 2: uxterm showing `$ echo gateway-ok` / `gateway-ok`. Relay line: `client 5 pdus + 44 fast-path, target 72 pdus + 5 fast-path, input map[mouse:8 scancode:38 sync:2], dropped caps map[6:1 28:1 29:1 30:1], reactivations 0`, server_bytes 268076; all input is forwarded as whole fast-path frames, statistics are category counts only |
| `/u:nobody` (policy allows only rdptest) | Gateway `route denied user "nobody" client "devin-box": user not allowed`, session line `"authorized":false,"stage":"license"`, target never dialed; xfreerdp exits with `ERRINFO_SERVER_DENIED_CONNECTION (0x00000007)` |
| `-target 127.0.0.1:33999` (target unreachable) | Gateway `target 127.0.0.1:33999 failed at handshake: dial: … connection refused`, session line `"authorized":true,"stage":"license","error":"rdp gateway: target connection failed…"`; xfreerdp receives `ERRINFO_SERVER_DENIED_CONNECTION` and exits |
| Client `kill -9 xfreerdp` / Ctrl-C | Relay `ended (client-closed)` (client reads EOF), gateway sends DPU to xrdp, xrdp logs `xrdp_mcs_recv failed` then ends the connection; session line `"stage":"handler","authorized":true` |
| Kill `xrdp --nodaemon` inside the container (target disconnect) | Relay `ended (target-closed)`, gateway sends DPU to the client (provider initiated), xfreerdp exits with `ERRINFO_RPC_INITIATED_DISCONNECT (0x00000001)` |
| `rdpprobe -stage activated -observe` through the gateway | `reached stage: activated`, framebuffer 1024x768 155 rects 100% covered, fast-path `ptr-new:2 synchronize:1`, identical to a direct xrdp connection |

Notes: xrdp dropped the gateway's Demand Active capability types 6 (xrdp-specific / not defined in MS-RDPBCGR), 28 Surface Commands, 29 Bitmap Codecs, 30 Frame Acknowledge, so xfreerdp used only orders + bitmap updates, and the desktop was still complete; xrdp never sent Deactivate All (the reactivation path is unit-test only). Troubleshooting record: one instance of "login window + black screen" was a test-script bug — `sh -c '…$RDP_PW…'` without `export` produced an empty password, and xrdp disables autologin per its rules and shows the login window (`xrdp_sec.c`: cbPassword==0 → rdp_autologin=0); the black screen was Xvfb's bare root window after xfreerdp had exited; `docker start` on a stopped xrdp container fails to start because of a leftover `xrdp-sesman.pid`, and `start-xrdp.sh` now removes stale pid files first.

### 5.9 G3-4 (2026-10-29, static virtual channel passthrough + back-end NLA: local xfreerdp → rdpgw → Windows 7 / Windows Server 2016)

Local macOS: `gofmt`/`go vet`/`golangci-lint`/`CGO_ENABLED=0 go test ./...` pass. New unit tests: `gateway.TestChannelRelay` (client requests rdpdr+cliprdr, policy allows only cliprdr: the target sees only cliprdr, cliprdr blocks are echoed through the gateway unchanged, rdpdr blocks are dropped and counted); `transport`'s `TestMD4Vectors` (RFC 1320's four vectors), `TestNTOWFv2Vector` (MS-NLMP 4.2.4.1.1), `TestCredSSPExchange` (in-process fake CredSSP server verifies the NTLMv2 proof, MIC, MsvAvChannelBindings/SPN, client public-key binding, sends back the server binding, then decrypts TSPasswordCreds to obtain domain/user/password), `TestCredSSPRejectsWrongServerBinding` (server public-key binding mismatch → client rejects), `TestReadTSRequestErrorCode` (errorCode NTSTATUS surfaced).

Real chain: macOS + XQuartz, xfreerdp 3.31.1 (`/sec:tls /cert:ignore /size:1280x800 +clipboard /drive:gwshare,/tmp/rdpdrive`) → local `rdpgw` (temporary self-signed front-end certificate) → LAN Windows hosts. Target certificates are all self-signed; the leaf certificate SHA-256 was read first with `rdpprobe -pin 00` and then pinned with `-target-pin`.

| Case | Result |
|---|---|
| `rdpprobe -addr 192.0.2.10:3389 -stage tls` | Windows 7 SP1 offers only TLS 1.0: the handshake fails at the default MinVersion 1.2; after `-min-tls 1.0`, `tls ok` (TLS1.0, RSA-AES128-SHA) |
| `rdpprobe -addr 192.0.2.20:3389 -stage tls` | Server 2016 replies `RDP_NEG_FAILURE HYBRID_REQUIRED_BY_SERVER`; after `-nla`, `negotiation ok (PROTOCOL_HYBRID, flags=0x1f)` |
| `rdpprobe -addr 192.0.2.20:3389 -nla -pin … -stage activated -user administrator -password-env … -observe 6s` | `nla: true, credssp_version: 6`, TLS1.2 ECDHE-RSA-AES256-GCM, MCS → Client Info → `license valid-client` → 17 server capability sets → Font Map; 6 s of observation received 87 fast-path Bitmap Updates (1108 rects), pointer updates, and Save Session Info `logon info_type 1, session 2, domain WIN-EXAMPLEPC1, user Administrator` — the NLA credentials were accepted and logged in |
| `rdpgw -listen 127.0.0.1:33892 -target 192.0.2.10:3389 -target-min-tls 1.0 -target-pin … -allow-user win7`; xfreerdp `/u:win7` | Gateway `target … licensed (user channel 1008, channels [rdpdr rdpsnd cliprdr drdynvc]), relaying`: the 4 static channels are assigned under the same names and joined on the target side; the FreeRDP window shows the Windows 7 Ultimate desktop (Control Panel "System" window, taskbar, IME status) |
| `rdpgw -listen 127.0.0.1:33893 -target 192.0.2.20:3389 -target-nla -target-pin … -allow-user administrator`; xfreerdp `/u:administrator` | Front-end xfreerdp is still TLS-only; after the gateway completes CredSSP to the target, `licensed (user channel 1009, channels [rdpdr rdpsnd cliprdr drdynvc]), relaying`; the window shows the Server 2016 desktop (icons, start menu bar, tooltips) |
| Manual operations inside the two sessions above (by the user in the FreeRDP window): Mac `pbcopy` text → Ctrl+V on Windows; copy text on Windows → Mac `pbpaste`; open `\\tsclient\gwshare` in Explorer | Pasting, reverse copying (Mac `pbpaste` returns the text selected on Windows), and opening the shared directory to see `gw-test.txt` all work on both machines. Relay lines: Win7 `client 10 pdus + 1807 fast-path, target 14 pdus + 677 fast-path, input map[mouse:1776 scancode:46 sync:15], channels map[cliprdr:33 drdynvc:4 rdpdr:5736], dropped channels map[], reactivations 1` (the 5736 rdpdr blocks are Explorer enumerating/reading the share; Win7 sent one real Deactivate All during the session and the gateway continued after reactivation); Server 2016 `client 5 pdus + 697 fast-path, target 8 pdus + 831 fast-path, input map[mouse:679 scancode:30 sync:12], channels map[cliprdr:31 drdynvc:27 rdpdr:309], dropped channels map[]`. Neither side had dropped channels, and the filtered capabilities (Win7: 22/23/24/25/28/29; 2016: 23/24/28/29/30) did not affect the desktop |
| Wrong `-target-pin` | Gateway `target … failed at handshake: tls handshake: server certificate sha256 4109… does not match pin`, the client receives `ERRINFO_SERVER_DENIED_CONNECTION` and exits; the wrong value appears in the log to make first-time pinning easy |

Notes: XQuartz on macOS has no XTEST extension, so xdotool cannot inject input into the FreeRDP window; the in-desktop clipboard/drive operations were done manually by the user, and the gateway prints per-channel two-way block counts when the relay ends. Channel data is not parsed; counts are MCS block counts, not protocol message counts; rdpsnd has no count because no sound was played during the test. `rdpprobe -png` reports `truncated stream` decoding Server 2016's 32bpp Interleaved RLE bitmaps (a probe rendering limitation; the gateway does not decode bitmaps and is unaffected).

### 5.10 G3-5 (2026-10-29, front-end NLA: local xfreerdp /sec:nla → rdpgw (CredSSP server) → Windows 7 / Windows Server 2016)

Local macOS: `gofmt`/`go vet`/`golangci-lint`/`CGO_ENABLED=0 go test ./...` pass. The CredSSP/NTLM code moved into the `nla` package; the former `transport` unit tests moved with it and became real `nla.Client` ↔ `nla.Server` loopbacks: `TestClientServerExchange` (bare NTLMSSP: NTLMv2 proof, MIC, MsvAvChannelBindings, two-way public-key binding, TSPasswordCreds decrypted to CORP/alice/s3cret, `ChannelBound=true`), `TestServerRejectsWrongPassword` (server `ErrLogonFailure`, client receives `NTSTATUS 0xc000006d`), `TestServerRejectsUnknownUserAndMismatchedBinding` (unknown user, channel-binding mismatch, and client public-key binding mismatch are all rejected before MCS), `TestClientRejectsWrongServerBinding` (hand-written server returns a wrong public-key proof → client rejects), `TestServerRejectsOldVersionWithErrorCode` (CredSSP 4 rejected with an errorCode), `TestServerRejectsForeignDelegatedCredentials` (NTLM identity alice but a delegated password for someone else → reject), `TestSPNEGO` (simulating mstsc: NTLM as the preferred mechanism with an optimistic token / Kerberos preferred → request-mic, both paths with two-way mechListMIC, public-key proof and credentials still unsealable after the RC4 reset), `TestSPNEGORejectsMissingRequiredMIC`, `TestNegTokenRespRoundTrip`; `server.TestNLAFrontEnd` (Go client `Options.NLA` → front end selects PROTOCOL_HYBRID, `Peer.NLA`/username/delegated password reach `Authorize`, the same server still accepts TLS-only clients, a wrong password ends at the `tls` stage with `ErrDenied`, `RequireNLA` replies HYBRID_REQUIRED_BY_SERVER to a TLS-only client, `RequireNLA` without a callback is `ErrConfig`).

Real chain: macOS + XQuartz, xfreerdp 3.31.1 (libwinpr built without Kerberos, so it sends bare NTLMSSP tokens) → local `rdpgw -nla-users /tmp/nla-users.txt` (temporary self-signed front-end certificate) → LAN Windows hosts.

| Case | Result |
|---|---|
| `rdpgw -listen 127.0.0.1:33892 -target 192.0.2.10:3389 -target-pin … -target-min-tls 1.0 -nla-users … -allow-user win7`; xfreerdp `/sec:nla /cert:ignore /u:win7 +clipboard /drive:gwshare,…` | Gateway `credssp v6 user "win7" domain "" spnego=false delegated=true bound=false` → `credssp ok` → MCS → Client Info (username from NLA) → target `licensed (channels [rdpdr rdpsnd cliprdr drdynvc]), relaying`; the FreeRDP window shows the Windows 7 desktop (reconnected to the logged-in session, Explorer `\\tsclient\gwshare` and Notepad still open). Relay: `client 10 pdus + 5 fast-path, target 14 pdus + 214 fast-path, channels map[cliprdr:5 drdynvc:4 rdpdr:2606], dropped map[], reactivations 1, nla true` |
| `rdpgw -listen 127.0.0.1:33893 -target 192.0.2.20:3389 -target-nla -target-pin … -nla-users … -allow-user administrator`; xfreerdp without `/sec` (requests SSL+HYBRID by default) `/u:administrator` | Front end selects HYBRID: `credssp v6 user "administrator" … delegated=true`; the delegated password is then used by the gateway for back-end CredSSP to Server 2016 (two independent NTLMv2 exchanges, front and back), `licensed … relaying`, the window shows the Server 2016 desktop. Relay: `client 5 pdus + 273 fast-path, target 8 pdus + 200 fast-path, input map[mouse:269 scancode:8 sync:4], channels map[cliprdr:5 drdynvc:27 rdpdr:13], nla true` |
| xfreerdp `/auth-only /sec:nla /u:win7 /p:bad` → 33892 | Gateway `CredSSP logon failure` → `closed after tls: … connection denied by policy: CredSSP: NTLM logon failure`, session line `stage tls, nla false, authorized false`; xfreerdp side `CONNECTION_STATE_NLA status STATE_RUN_FAILED`; the target was never touched |

Notes: `bound=false` means xfreerdp 3.31 did not put a non-zero MsvAvChannelBindings in the NTLMv2 response (the server enforces the comparison only when the client provides one; the public-key binding nonce proof is still verified), and `spnego=false` means bare NTLMSSP. The SPNEGO/mechListMIC path (mstsc) is unit-test only, modeled on the FreeRDP 3.31 `negotiate.c` acceptor behavior (request-mic when the preferred mechanism is not NTLM; RC4 stream reset after the MIC exchange, sequence numbers not reset), and was not verified against a real mstsc.

### 5.11 G3-6 (2026-10-29, logon form: local xfreerdp → rdpgw -login-form → user enters the target in the form → Windows Server 2016 / Windows 7)

Local macOS: `gofmt`/`go vet`/`go test ./...`/`go test -race ./server ./gateway ./wire` pass. New unit tests: `form` (field editing/focus/submit/cancel state machine, bitmap-font rendering), `server.TestHandlerActivateInputAndReactivate` (activate → bitmaps/pointers → input → Deactivate All → reactivate), `server.TestServerCapabilitiesKeepRelayFeaturesNegotiable`, `gateway.TestFormRetryThenRelay` (wrong password keeps the form, correct password → Deactivate All → target Demand Active → finalize → relay, stale Enter releases are dropped, password never logged), `TestFormAttemptsExhaustedAndEscape`, `TestFormEmptyPasswordIsNotAnAttempt`, `TestDescribeDialError`, `transport.TestTLS10CredSSPRetriesWithStreamCipher`/`TestTLS10WithoutNLAKeepsBlockCipher`, `nla.TestClientLegacyCredSSP`.

Real chain: macOS + XQuartz, xfreerdp 3.31.1 (`/cert:ignore`, default negotiation) → local `rdpgw -listen 127.0.0.1:33892 -login-form -allow-target 192.0.2.0/24 -target-pin 192.0.2.10=…,192.0.2.20=… -target-min-tls 1.0 -target-nla -target-credssp-legacy -json`, with the user entering the target address / username / password in the form inside the FreeRDP window.

| Case | Result |
|---|---|
| Before the fix: form → 192.0.2.20 (Server 2016, correct credentials) | Target `licensed via logon form … relaying`, but the relay end line shows `target 8 pdus + 0 fast-path` and the client stays on the form screen. Cause: the form's Demand Active did not declare fast-path output / orders etc., so FreeRDP intersected it with Windows' subsequent Demand Active and confirmed to Windows a capability set with no fast-path output and no orders, and Windows stopped producing graphics |
| After the fix: form → 192.0.2.20, correct credentials | User confirms reaching the Server 2016 desktop; relay `client 5 pdus + 1211 fast-path, target 8 pdus + 1075 fast-path, channels map[cliprdr:5 drdynvc:859 rdpdr:13], reactivations 0, form_attempts 1` |
| Form → 192.0.2.10 (Windows 7 SP1, `-target-nla`) | Before the fix, `CredSSP authentication failed: remote error: tls: internal error`; after the form Fail cleared the password, xfreerdp's repeated Enter presses triggered two more `NLA requires a user and password`, exhausting the three attempts immediately → an empty password no longer counts as an attempt. Diagnosis with `rdpprobe -nla -min-tls 1.0 -pin …`: under TLS 1.0 CBC an alert arrives right after the first TSRequest (regardless of password); after retrying with RC4, Win7 replies CHALLENGE but with CredSSP version 2; with `-credssp-legacy` added, `mcs connect ok → client info ok (autologon) → license ok (valid-client)`, `tls: TLS_RSA_WITH_RC4_128_SHA (RC4 retry …)` |
| After the fix: form → 192.0.2.10, correct credentials, gateway with `-target-credssp-legacy` | User confirms reaching the Windows 7 desktop; gateway `target 192.0.2.10:3389 licensed via logon form (user channel 1008, channels [rdpdr rdpsnd cliprdr drdynvc]), relaying`, relay `client 10 pdus + 47 fast-path, target 14 pdus + 85 fast-path, channels map[cliprdr:5 drdynvc:4 rdpdr:13], dropped channels map[], reactivations 1, form_attempts 1` (Win7 as usual sends one real Deactivate All after logon, and gateway reactivation works; filtered capabilities 22/23/24/25/28/29 as in G3-4) |

Notes: the local Homebrew xfreerdp 3.31.1 (OpenSSL 3) cannot complete a handshake with TLS 1.0-only Win7 (`/tls:seclevel:0` and `/tls:enforce:1.0` both fail with `BIO_do_handshake failed`), so the Win7 NLA cross-check could only be done with `rdpprobe`. The RC4 fallback triggers only for NLA when TLS 1.0 CBC has been negotiated; the TLS-only path is unchanged (TPKT is reassembled across multiple records and is unaffected by splitting).

## 6. Not Covered by This Round of Validation

- Protocol-level determination of the user authentication result: no NLA/CredSSP; xrdp-side logs confirm the INFO_AUTOLOGON credentials logged in successfully and an Xorg session started, but no Save Session Info was received within the observation window, so the probe cannot determine the login result on its own; Save Session Info / Set Error Info decoding is verified only by unit tests. The wrong-password case was not run (xrdp failures likewise appear only in server-side logs).
- The licensing Platform Challenge / New License / Upgrade License branches are verified only against the local fake server and the public MS-RDPELE samples; xrdp does not take those branches.
- Graphics: only Slow-Path Bitmap Updates are decoded (on xrdp only 24bpp RLE appeared; 8/15/16/32bpp, uncompressed bitmaps, and Palette are unit-test only; decode correctness relies on visual comparison of PNGs with no pixel-exact reference); orders are not parsed; Surface Commands are only counted; fast-path fragment reassembly, compression-flag rejection, Large Pointer, and Pointer Position compositing are unit-test only (xrdp updates are small and it never sends positions); input; all other Share Data PDUs are counted by pduType2 only.
- Static virtual channels are passthrough only (no parsing of cliprdr/rdpdr/rdpsnd/drdynvc protocols, no channel-level policy such as read-only clipboard); message channels and multi-transport channels; a channel count assigned by the server that differs from the request is rejected.
- Public-internet targets and Standard RDP Security servers (rejected by the probe by design); Windows targets were tested only with one Windows 7 SP1 (TLS 1.0) and one Server 2016 (NLA), both self-signed certificates + `-pin`; domain accounts / Kerberos, HYBRID_EX, CredSSP servers requiring Early User Auth, and hosts with NTLM disabled (Kerberos only) were not tested.
- Gateway: front-end NLA was exercised only against xfreerdp 3.31's bare NTLMSSP tokens; mstsc's SPNEGO wrapping is unit-test only; no Kerberos, HYBRID_EX / Early User Auth, smart-card credentials, or NTLM account lockout/password-expired status codes (all failures are STATUS_LOGON_FAILURE); `-nla-users` is a plaintext password file with no hash storage; the target certificate must be verified via `-target-ca`/system roots or a `-target-pin` leaf fingerprint, with no skip option; the filtered capabilities (codecs/Surface Commands/Frame Ack/RAIL etc.) mean no RemoteFX/GFX or RemoteApp support; input is only forwarded and counted, with no keyboard-layout rewriting or policy interception; reactivation (Deactivate All), client Shutdown Request, multi-session concurrency limits, and handshake timeouts exist only in unit tests / code paths; real Windows targets and mstsc clients were not tested.
- Server role: verified only with xfreerdp 2.6.1 (TLS) and 3.31 (NLA, through the gateway); mstsc/Windows clients, multi-monitor, Auto-Reconnect, the real Shutdown Request path, idle timeouts, and concurrency limits (unit/manual paths only) were not verified against real clients; reactivation was verified on xfreerdp 3.31 only in the form "gateway form → Deactivate All → target Demand Active"; bitmaps are sent as uncompressed rects only — no compressed bitmap encoding, no fast-path output, no orders (declaring them in Demand Active is only to preserve negotiation with later targets).
- Logon form: Chinese prompts only, no IME; the form screen is sent uncompressed; `-allow-target` is address-based policy only, with no per-user/time rules; `-target-credssp-legacy` gives up the CredSSP 5/6 nonce public-key binding (CVE-2018-0886) and is meaningful only together with `-target-pin`, and the RC4 fallback makes the entire Win7 session use RC4 — both are compatibility measures for EOL hosts, not recommended configurations.
- Certificate verification disabled or downgraded paths: no such option exists and none is planned.

## Web client: clipboard, browser folder mapping, reconnection (2026-10-30)

Chain: headless driver `.build/webe2e` (plays the browser: login → `/api/connect` → owner WebSocket; file requests answered from a local temporary directory) → local `rdpgw -login-form -web-users … -target-nla -target-min-tls 1.0 -target-pin …` → 192.0.2.20 Server 2016.

| Item | Result |
| --- | --- |
| Channels | The web session requests `rdpdr`, `rdpsnd`, `cliprdr` (target assigns 1004/1005/1006). When only cliprdr+rdpdr are requested, Windows does not send the rdpdr Server Announce — rdpsnd must also be present; when cliprdr blocks lack `CHANNEL_FLAG_SHOW_PROTOCOL`, Windows does not respond |
| Remote → browser clipboard | Remote `echo remote-clip-ok\| clip` → browser receives `{"t":"clip","text":"remote-clip-ok"}` |
| Browser → remote clipboard | Sending `from-browser-剪贴板` → remote `Get-Clipboard` writes back to the mapped drive, content identical |
| Mapped folder | `\\tsclient\E2E` visible; `dir`, `type` (reading a local file), `mkdir`, redirected file write, `ren`, `del`, `copy explorer.exe` (4,673,928 bytes) all correct |
| Reconnection | After closing the WebSocket for 5 seconds and reconnecting with the same owner key, hello returns `owner=true drive="E2E"` and the session is intact |

Fix: FILE_FS_VOLUME_INFORMATION in RDP does not include the trailing Reserved byte (17 bytes + volume label); with one byte extra, Windows stops sending further I/O requests.

Not tested: the File System Access API and clipboard permission prompts in real Chrome/Edge (only a TypeScript build check was done), Windows 7 targets, and the behavior in browsers of certificates generated by `-monitor-autocert`.

## Web client: audio, graphics, dynamic channels, remote reconnection, rich clipboard, security (2026-10-30)

Same headless driver, targets 192.0.2.20 Server 2016 (NLA) and 192.0.2.10 Windows 7 (TLS 1.0, no NLA).

| Item | 2016 | Win7 |
| --- | --- | --- |
| Audio (rdpsnd, PCM 44.1 kHz stereo 16-bit forwarded to the browser) | PCM received on both the static channel and `AUDIO_PLAYBACK_DVC` | PCM received on the static channel |
| Dynamic channel drdynvc + display control (MS-RDPEDISP) | 1280×800 → 1600×900 → 1366×768 graphics correct | No display control (not supported by the OS; initial resolution kept) |
| Remote reconnect (`RDPGW_DEBUG_DROP_TARGET` artificially drops the target TCP) | Reconnects within 1 second with an auto-reconnect cookie; Notepad can be opened after reconnect | Reconnects within 1 second (server sent no cookie; credentials log back into the original session) |
| Browser → remote: text + HTML + PNG | Remote reads a 30×20 image and `GetText('Html')` contains the fragment | Same |
| Remote → browser: image | Remote `SetImage` 50×40 → browser receives a PNG | Same (Win7 sends a 16-bit BI_BITFIELDS 5-6-5 DIB, now supported) |
| Existing clipboard / mapped drive / WebSocket reconnection regressions | Pass | Pass (Win7 PowerShell 2.0 has no `Get-Clipboard`; that step cannot be checked due to a driver-script limitation) |

Graphics (multiple dirty rects, large-area JPEG + lossless resend after the picture settles, 40 ms frame interval) and security (token exchanged for an HttpOnly Cookie, `?token=` no longer accepted, `-monitor-origins`, HTTPS page notice, HSTS) have unit tests; `go test -race ./...` all pass.

Not tested: Web Audio unlocking, keyboard lock, IME, touch gestures, `navigator.clipboard.read/write` permissions in real browsers (only a TypeScript build check was done); real network jitter (only a dropped target TCP was simulated).
