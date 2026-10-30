> [中文文档](../USAGE.md)

# rdpgw User Guide

`rdpgw` is the RDP gateway provided by this repository (`go-kernel`). On the front end it accepts connections from RDP clients (mstsc, xfreerdp, etc.) or a browser; on the back end it connects to the real Windows remote desktop host over TLS / CredSSP (NLA); in between it provides session auditing, real-time monitoring, collaborative control, and session recording/playback.

> All addresses, usernames, tokens, and certificate fingerprints in this document are placeholders (such as `192.0.2.10`, `<sha256>`, `<token>`); replace them with your own values.

## 1. Feature List

- **RDP clients connecting through the gateway**: mstsc / xfreerdp connect to the gateway, which forwards them to a fixed target (`-target`); front-end TLS and front-end NLA (`-nla-users`) are supported.
- **Login form mode** (`-login-form`): after connecting, the client first sees a login form drawn by the gateway; the user enters the server address, username, and password, and the gateway then connects to the entered target. Use `-allow-target` to restrict the allowed targets; failures can be retried.
- **Web browser RDP client** (`-web-users`): after logging in to the monitor UI, open a remote desktop directly in the browser without installing any client.
- **Real-time monitoring and collaborative control**: watch any session live in the browser; with `-monitor-control` enabled you can join in with keyboard and mouse input, or forcibly disconnect a session.
- **Recording and playback (with audio)**: `-record-dir` saves each session as a `.rdpv` file; playback supports seeking, an operation-event timeline, and audio playback at 1× speed (audio is recorded as IMA ADPCM).
- **Clipboard (including rich formats)**: text, HTML, PNG images, and 16/24/32-bit DIB bitmaps.
- **Drive redirection**: the web client can map a local folder as a remote drive (Chrome / Edge); the monitor can browse the user's mapped drives, and with `-monitor-drive-control` enabled can upload, download, and delete files.
- **Audio**: remote sound is played in the browser via rdpsnd / AUDIO_PLAYBACK_DVC.
- **Dynamic resolution**: servers that support display control (Server 2016 and later) automatically adjust the resolution to the browser window; older systems (such as Windows 7) keep the initial resolution.
- **Automatic reconnection to the target**: when the connection to the remote host drops, the gateway reconnects automatically using the ARC cookie; if the browser disconnects from the gateway, the session is retained for the `-web-reconnect` period and can be reattached.
- **Extended input**: wheel / horizontal wheel, mouse side buttons, input method (IME), keyboard lock in full screen (you can press Win, Alt+Tab directly), touch.
- **Chinese and English UI**: switch the language in the top-right corner; the choice is stored in the browser; the first visit follows the browser's language automatically.

## 2. Installation and Build

Requires Go (see `go.mod` for the version) and Node.js / npm (only needed to build the web UI).

```sh
cd go-kernel

# Build the gateway and the probe tool
go build -o bin/rdpgw ./cmd/rdpgw
go build -o bin/rdpprobe ./cmd/rdpprobe

# Build the web monitor UI; output goes to web/monitor/dist
cd web/monitor
npm install
npm run build
```

At startup, point `-monitor-ui web/monitor/dist` at the built front-end directory.

## 3. Quick Start

### 3.1 Fixed-target mode

All clients are forwarded to the same host:

```sh
./bin/rdpgw -listen 0.0.0.0:33892 \
  -target 192.0.2.10:3389 \
  -target-pin <sha256>
```

When `-cert` / `-key` are not provided, the gateway uses a temporary self-signed certificate, and clients will warn that the certificate is not trusted.

### 3.2 Login form mode

After connecting, the user fills in the target in the form:

```sh
./bin/rdpgw -listen 0.0.0.0:33892 \
  -login-form \
  -allow-target 192.0.2.10,192.0.2.0/24 \
  -target-pin 192.0.2.10=<sha256>,192.0.2.11=<sha256>
```

### 3.3 Full example with the web UI

```sh
export RDPGW_MONITOR_TOKEN='<token>'

./bin/rdpgw \
  -listen 0.0.0.0:33892 \
  -login-form \
  -allow-target 192.0.2.10,192.0.2.11 \
  -target-pin 192.0.2.10=<sha256>,192.0.2.11=<sha256> \
  -monitor 0.0.0.0:8443 \
  -monitor-autocert ./monitor-cert \
  -monitor-ui web/monitor/dist \
  -monitor-control \
  -monitor-drive-control \
  -web-users ./web-users.txt \
  -web-user-targets ./web-user-targets.txt \
  -record-dir ./recordings \
  -json
```

Then open `https://<gateway-address>:8443/` in a browser. The token is passed through the `RDPGW_MONITOR_TOKEN` environment variable so it does not appear in the process list or shell history. For production, provide a trusted certificate with `-monitor-cert` / `-monitor-key`.

## 4. Flag Reference

The values and defaults below follow the output of `go run ./cmd/rdpgw -h`.

### 4.1 Front-end listener and certificates

| Flag | Default | Description |
|---|---|---|
| `-listen` | `127.0.0.1:33892` | Front-end RDP listen address |
| `-cert` | temporary self-signed | Front-end PEM certificate chain |
| `-key` | | Front-end PEM private key |
| `-handshake-timeout` | `30s` | Front-end handshake time limit |
| `-max-sessions` | `16` | Maximum number of concurrent client connections |
| `-nla-users` | | Enable front-end CredSSP/NLA: a file with one `user:password` per line; clients offering PROTOCOL_HYBRID authenticate with NTLMv2 first, and the delegated credentials are then forwarded to the target |
| `-require-nla` | `false` | Reject clients that do not offer PROTOCOL_HYBRID (requires `-nla-users`) |
| `-allow-user` | empty (any) | Usernames allowed by the routing policy, comma-separated |
| `-allow-domain` | empty (any) | Required domain |
| `-once` | `false` | Exit after the first session ends |
| `-json` | `false` | Print one line of JSON per finished forward / session |
| `-trace` | `false` | Log slow-path share PDU types of each forward (for debugging) |

### 4.2 Target, TLS, NLA, and certificate pinning

| Flag | Default | Description |
|---|---|---|
| `-target` | | Target `host:port` (required unless `-login-form` is used) |
| `-target-name` | target hostname | TLS name used when verifying the target certificate |
| `-target-ca` | | Trusted target root certificate (PEM) |
| `-target-pin` | | Hexadecimal SHA-256 of the target leaf certificate, replacing CA/name verification (suitable for self-signed Windows hosts); under `-login-form` it can be a comma-separated `host=sha256` list to pin multiple hosts |
| `-target-min-tls` | `1.2` | Minimum TLS version allowed for the target: `1.0`, `1.1`, `1.2`, `1.3` (Windows 7 only offers 1.0) |
| `-target-nla` | `false` | Require the back end to use CredSSP 5/6 + NTLMv2 (no fallback to TLS-only); the front end remains TLS-only |
| `-target-credssp-legacy` | `false` | With `-target-nla`: also accept CredSSP 2-4 from unpatched Windows 7 / 2008 R2 (CVE-2018-0886); must be used together with `-target-pin` |
| `-target-timeout` | `20s` | Target handshake time limit |

### 4.3 Login form

| Flag | Default | Description |
|---|---|---|
| `-login-form` | `false` | Show each client a login form and connect to the server the user enters, instead of `-target` |
| `-allow-target` | empty (any) | Hosts, IPs, or CIDRs the user may enter, comma-separated; if `-target` is set it is always allowed. Also constrains web connections |
| `-form-attempts` | `5` | Disconnect the client after this many failed attempts |
| `-form-idle` | `5m0s` | Disconnect the client after the form has been idle this long |

### 4.4 Virtual channels

| Flag | Default | Description |
|---|---|---|
| `-allow-channel` | `*` | Static virtual channels to forward to the target, comma-separated (`*` for all, empty for none), e.g. `cliprdr,rdpdr,rdpsnd,drdynvc` |

### 4.5 Monitor and HTTPS

| Flag | Default | Description |
|---|---|---|
| `-monitor` | | Address of the monitor web UI and API, e.g. `127.0.0.1:8090` |
| `-monitor-ui` | | Built front-end directory (`web/monitor/dist`) |
| `-monitor-token` | `$RDPGW_MONITOR_TOKEN` | Bearer token required by the monitor API; empty means no token required |
| `-monitor-cert` | | Monitor HTTPS certificate chain (required when `-monitor` is a non-loopback address) |
| `-monitor-key` | | Private key for `-monitor-cert` |
| `-monitor-autocert` | | Serve HTTPS with a self-signed certificate, stored in this directory (created on first start; browsers warn until it is trusted) |
| `-monitor-hosts` | `-monitor` host and local addresses | With `-monitor-autocert`: DNS names / IPs in the certificate, comma-separated |
| `-monitor-insecure` | `false` | Allow plaintext HTTP on non-loopback addresses (passwords and screen content will be transmitted unencrypted; not recommended) |
| `-monitor-origins` | | Additional accepted browser Origins (`https://host[:port]`), such as the public address of a reverse proxy |
| `-monitor-control` | `false` | Allow the monitor to join a session with keyboard and mouse |
| `-monitor-drive-control` | `false` | Allow browsing, reading, creating, and deleting files on client-mapped drives (requires `-monitor` and `-monitor-token`) |

### 4.6 Web users and session limits

| Flag | Default | Description |
|---|---|---|
| `-web-users` | | Enable browser login and the web RDP client: one `user:password` or `user:<-hash-password output>` per line |
| `-web-user-targets` | | Per-user allowed-targets file (see 5.2) |
| `-web-max-sessions` | `8` | Total number of concurrent browser-initiated RDP sessions |
| `-web-max-per-user` | `2` | Concurrent browser sessions per account (0 for unlimited) |
| `-web-idle` | `30m0s` | Disconnect a browser session after this long without keyboard/mouse input (0 for never) |
| `-web-reconnect` | `2m0s` | How long a session is kept after the browser disconnects so it can be reattached (negative ends it immediately) |
| `-hash-password` | `false` | Read a password from stdin, print the hash for use in `-web-users`, then exit |

### 4.7 Recording

| Flag | Default | Description |
|---|---|---|
| `-record-dir` | | Record each forwarded session into this directory (`.rdpv` files) |

## 5. Account and Target Configuration Files

### 5.1 `-web-users`

One account per line; lines starting with `#` and blank lines are ignored. Storing only hashes is recommended:

```sh
# Read the password from stdin (which can come from a pipe or a password manager) and print the hash
printf '%s' '<password>' | ./bin/rdpgw -hash-password
```

```text
# web-users.txt
alice:<output of -hash-password>
bob:<output of -hash-password>
```

Plaintext `user:password` also works but is not recommended. The file permissions should be restricted so only the account running the gateway can read it (e.g. `chmod 600`). The `-nla-users` file uses the same format, one `user:password` per line.

### 5.2 `-web-user-targets`

```text
# web-user-targets.txt
alice: 192.0.2.10, 192.0.2.0/28
bob: rdp-host.example.com
admin: *
```

- Listed users can only connect to the listed targets, which must still be within `-allow-target`.
- `*` allows every target allowed by `-allow-target`.
- Users not listed fall back to `-allow-target`.

## 6. Obtaining the Target Certificate Fingerprint

Windows Remote Desktop usually uses a self-signed certificate; pinning it with `-target-pin` is recommended:

```sh
./bin/rdpprobe -addr 192.0.2.10:3389 -stage tls -json
```

The `peer_sha256` field in the JSON output is the value for `-target-pin`. Windows 7 requires `-min-tls 1.0`. If you probe with a wrong `-pin`, the failure message also reports the fingerprint actually observed. Obtain and verify fingerprints over a trusted network.

## 7. Notes for Windows 7 and Older Systems

- Windows 7 / 2008 R2 only offer TLS 1.0, requiring `-target-min-tls 1.0`. When connecting to a host that only supports TLS 1.0, NLA retries with RC4 (Go's 1/n-1 CBC splitting breaks CredSSP on Windows 7).
- Windows 7 without the CVE-2018-0886 patch only supports CredSSP 2-4, requiring `-target-credssp-legacy`, and the certificate must also be pinned with `-target-pin`.
- Older systems do not support display control, so web sessions keep the initial resolution and do not adjust to the window.

```sh
./bin/rdpgw -listen 0.0.0.0:33892 -target 192.0.2.20:3389 \
  -target-min-tls 1.0 -target-nla -target-credssp-legacy \
  -target-pin <sha256>
```

## 8. Using the Web UI

### 8.1 Login

The login page offers two methods:

- **User login**: use an account from `-web-users`; after logging in you can connect to remote desktops in the browser, and sessions are recorded under that account.
- **Access token**: enter the token matching `-monitor-token` (leave it empty if none is set); this only allows viewing and collaboration, not initiating connections.

The token is exchanged for an HttpOnly cookie and never appears in the URL. The top navigation includes "Live sessions", "Connect to Remote Desktop", and "Recordings", with a language switcher and "Logout" in the top-right corner.

### 8.2 Connect page

- **Server address**: e.g. `192.0.2.10` or `192.0.2.10:3389`; it must be within the allowed targets.
- **Username / Domain (optional) / Password**.
- **Resolution**: "Fit window" or a fixed resolution (e.g. 1280×800, 1920×1080).
- **Color depth**: 32-bit, 24-bit, 16-bit, 15-bit.
- **More options**:
  - Visual experience: best quality, balanced, smooth (default), low bandwidth. More effects consume more bandwidth.
  - Keyboard layout: Chinese (Simplified/Traditional), English (US/UK), Japanese, Korean, German, French; this affects the remote input method and symbol keys.

Credentials are kept only in the gateway's memory for automatic reconnection after a drop, are cleared when the session ends, and are never written to disk or logs. A warning is shown if the page is not served over HTTPS.

### 8.3 Session toolbar

- **Clipboard**: content copied remotely is automatically written to the local machine; when you switch back to the page, the local clipboard (text, HTML, images) is synchronized automatically; you can also type into the panel and click "Send to remote". Images larger than about 2.9 MB sync text only.
- **Drive redirection**: select a local folder to map into the remote session (requires Chrome / Edge, accessed over HTTPS or localhost); the mapping can be changed or cancelled; after refreshing the page you need to select it again.
- **Send Ctrl+Alt+Del**.
- **Shortcuts** menu: Win, Alt+Tab, Win+R, Win+E, Win+D, Win+L, Ctrl+Shift+Esc, Alt+F4, PrintScreen. In full screen these key combinations can be pressed directly.
- **Mute / Unmute**: when the browser blocks autoplay, click anywhere on the page to start audio playback.
- **Full screen / Exit full screen**, **Disconnect**.

When the connection to the remote host drops, "Reconnecting (attempt n)" is displayed; disconnections from the gateway are also reconnected automatically.

### 8.4 Session list and live monitoring

The "Live sessions" page lists active sessions: user, client, target, resolution, start time, duration, traffic, viewer count, recording status. Click "Monitor" to watch, or "Disconnect" to forcibly end a session.

On the live page you can turn "Control" on and off (requires `-monitor-control`). While co-controlling, your keyboard and mouse act on the desktop together with the original user's. The sidebar shows session information, operation events, and a "User-mapped drives" browser; file upload, download, and delete require `-monitor-drive-control` and the access token (uploads are new files only, up to 64 MiB per file; deletions do not go to the recycle bin).

### 8.5 Recording list and playback

The "Recordings" page lists recordings (requires `-record-dir`), searchable by user, target, and client, with playback, download, and delete. The playback page supports fit-window / original size, full screen, seeking, and an "Operation events" timeline (keyboard, mouse, clipboard, files, redirected devices, etc., which can follow the playback position). Events do not store the typed text or clipboard contents. Audio only plays at 1× speed.

## 9. Connecting with xfreerdp / mstsc

```sh
# Fixed-target mode (when the gateway uses a self-signed certificate)
xfreerdp /v:<gateway-address>:33892 /u:<user> /d:<domain> /cert:ignore

# Front-end NLA (gateway configured with -nla-users)
xfreerdp /v:<gateway-address>:33892 /u:<user> /sec:nla /cert:ignore

# Login form mode: connect without credentials and fill in the gateway form
xfreerdp /v:<gateway-address>:33892 /sec:tls /cert:ignore
```

`/cert:ignore` is for testing only; in production, configure a trusted certificate for the gateway (`-cert` / `-key`).

mstsc: enter `<gateway-address>:33892` in "Computer" and enter credentials when prompted. A certificate warning appears when the gateway uses a self-signed certificate.

## 10. Security Recommendations

- Always use HTTPS for the monitor when its address is not loopback (`-monitor-cert` or `-monitor-autocert`); do not use `-monitor-insecure`.
- When running behind a reverse proxy, declare the public Origin with `-monitor-origins https://rdp.example.com`. The gateway sends HSTS when HTTPS is enabled.
- List only the required hosts in `-allow-target`, narrow them further per user with `-web-user-targets`, and enable only the needed channels in `-allow-channel`.
- Verify target certificates with `-target-pin` or `-target-ca`, and set a strong `-monitor-token` (passed via `RDPGW_MONITOR_TOKEN`).
- Store only `-hash-password` hashes in `-web-users` and restrict the file permissions.
- Credentials never touch disk: the gateway keeps connection credentials only in memory, and neither logs nor recordings contain passwords.
- Enable `-monitor-control` and `-monitor-drive-control` only when needed; also restrict access permissions on the recording directory.

## 11. Troubleshooting

| Symptom | Possible cause and remedy |
|---|---|
| Certificate mismatch / verification failure | The target certificate has changed or the pin is wrong: re-obtain `peer_sha256` with `rdpprobe -json`; for name verification failures check `-target-name` / `-target-ca` |
| TLS handshake failure, protocol version error | The target only supports an older TLS version (e.g. Windows 7): set `-target-min-tls 1.0` |
| NLA / CredSSP failure | Check the username, domain, and password; unpatched Windows 7 requires `-target-credssp-legacy` plus `-target-pin`; do not use `-target-nla` when the target has NLA disabled |
| Startup fails with port in use (address already in use) | Change the `-listen` / `-monitor` port, or stop the process occupying it (`lsof -i :33892`) |
| Monitor fails to start on a non-loopback address | `-monitor-cert` or `-monitor-autocert` is required |
| No picture after connecting in the browser | Check whether the target is reachable and whether `-allow-target` includes it; check the gateway log; try lowering the color depth or visual experience |
| Connect page says "web connections are not enabled on this gateway" | Start with `-web-users` and `-allow-target`, and access over HTTPS |
| Cannot collaborate/control | `-monitor-control` is not enabled |
| Cannot map a folder | Chrome / Edge is required, accessed over HTTPS or localhost |
| No audio | Click the page to lift the browser's autoplay restriction; make sure `-allow-channel` includes `rdpsnd` / `drdynvc` |
| API requests rejected behind a reverse proxy | Add the proxy's public Origin with `-monitor-origins` |
| Recording list is empty | `-record-dir` is not set |
| Clipboard / drive redirection not working | Make sure `-allow-channel` includes `cliprdr` / `rdpdr` |

For more information, use `-json` to output session summaries, and add `-trace` for debugging when necessary.
