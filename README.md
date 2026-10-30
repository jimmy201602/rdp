# RDP

An RDP (Remote Desktop Protocol) kernel and gateway written in pure Go: no CGO, no third-party protocol libraries. The wire protocol is implemented from scratch — TPKT/X.224, MCS, GCC, licensing, capability exchange, bitmap decoding and input forwarding — and ships as ready-to-use command-line tools plus a gateway with a web UI.

用 Go 标准库实现的 RDP 内核与网关：不依赖 CGO 和第三方协议库，从 TPKT/X.224、MCS、许可、能力协商一路实现到画面解码与输入转发，并在此基础上提供命令行工具和带 Web 界面的网关。RDP 客户端或浏览器经网关接入内网 Windows 主机，支持登录表单、NLA、证书指纹固定、剪贴板/磁盘/音频通道、浏览器内远程桌面、实时监控与接管、会话录像回放，界面中英文双语。


## Features

- **RDP gateway `rdpgw`**: RDP clients (mstsc, xfreerdp, …) or a browser reach internal Windows hosts through the gateway
  - Fixed-target mode (`-target`) or logon-form mode (`-login-form`): the client first sees a logon form drawn by the gateway and is connected to the server it enters
  - Backend NLA/CredSSP (NTLMv2), certificate pinning (`-target-pin`), minimum TLS version, per-host/IP/CIDR target allow-list
  - Optional front-end NLA (`-nla-users`, including mstsc's SPNEGO wrapping)
  - Static virtual channel relay: clipboard, drive redirection, audio, drdynvc (configurable with `-allow-channel`)
  - Windows 7 / Server 2008 R2 compatibility: `-target-min-tls 1.0`, automatic RC4 retry for CredSSP over TLS 1.0, `-target-credssp-legacy`
- **Web UI & browser RDP client** (`-monitor` + `-web-users`)
  - Start RDP sessions from the browser: dynamic resolution, audio, rich text/image clipboard, map a local folder as a drive on the target, touch input, shortcuts such as Ctrl+Alt+Del
  - Watch live sessions and take over keyboard/mouse collaboratively; browse user-mapped drives from the monitor
  - Session recordings (`.rdpv`, with audio) and playback
  - Chinese and English UI, follows the browser language
  - Automatic reconnect to the target (ARC cookie); sessions survive a browser drop for a grace period
- **Server role `rdpserve`**: a minimal RDP server (policy-callback authorization, test pattern output) for interop testing
- **Protocol probe `rdpprobe`**: staged probing of a target (TLS / MCS / licensing / capabilities / activation), can export screen and cursor PNGs, supports NLA
- **Monitor API security**: token exchanged for an HttpOnly cookie, origin checks, HTTPS enforced on non-loopback listeners (own or self-signed certificate)

## Quick start

```sh
# Build (pure Go, CGO_ENABLED=0)
go build -o bin/rdpgw ./cmd/rdpgw

# Build the web UI
cd web/monitor && npm ci && npm run build && cd ../..

# Fixed-target mode
./bin/rdpgw -listen 0.0.0.0:33892 -target 192.0.2.20:3389 -target-pin <sha256>

# Logon form + web UI
RDPGW_MONITOR_TOKEN=<token> ./bin/rdpgw -listen 0.0.0.0:33892 -login-form \
  -allow-target 192.0.2.0/24 -target-pin 192.0.2.20=<sha256> \
  -monitor 127.0.0.1:8090 -monitor-ui web/monitor/dist -web-users users.txt
```

Then connect mstsc / xfreerdp to the gateway address, or open `http://127.0.0.1:8090` for the browser client. See the usage guide for all flags.

## Architecture

```
RDP client / browser ──► server (front end: X.224/TLS/NLA, MCS, licensing, capabilities)
                            │  optional logon form
                            ▼
                        gateway (routing policy, channel relay, monitor tap, recording)
                            │
                            ▼
                        transport + nla + licensing (back end: CredSSP/NTLMv2, target TLS verification)
                            │
                            ▼
                        Windows host
```

Directories: `wire` (protocol codecs), `transport` (client connection state machine), `nla` (CredSSP/NTLM client and server), `licensing` (MS-RDPELE), `bitmap` (RLE decode, framebuffer, pointers), `server` (server role), `form` (logon form), `gateway` (gateway and relay), `monitor` (monitor HTTP/WebSocket API, recordings), `web/monitor` (React frontend), `cmd` (rdpgw / rdpserve / rdpprobe).

## Testing

```sh
go vet ./... && go test ./...
cd web/monitor && npx tsc -b --noEmit
```

Interop results against real Windows hosts are recorded in the validation log.

## Documentation

| English | 中文 |
| --- | --- |
| [Usage guide](docs/en/USAGE.md) | [使用文档](docs/USAGE.md) |
| [Developer guide](docs/en/DEVELOPMENT.md) | [开发文档](docs/DEVELOPMENT.md) |
| [Validation log](docs/en/VALIDATION.md) | [验证记录](docs/VALIDATION.md) |
| [Sources and boundaries](docs/en/SOURCES.md) | [来源与边界](docs/SOURCES.md) |
