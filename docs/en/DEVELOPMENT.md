> [中文文档](../DEVELOPMENT.md)

# Developer Guide

This document is for engineers working on `go-kernel`. It covers the architecture, directory responsibilities, how to build and test, the monitor API, the recording format, the front-end structure, and coding conventions. See `docs/SOURCES.md` for protocol sources and implementation boundaries, and `docs/VALIDATION.md` for real-machine validation records.

All addresses, accounts, and fingerprints in this document are placeholders (e.g. `192.0.2.10`, `<sha256>`). Never put real IPs, passwords, or certificate fingerprints into documentation, tests, or logs.

## 1. Project Overview and Architecture

`go-kernel` is a standalone Go module (`module rdp.local/kernel`, `go 1.25`) that depends only on the Go standard library and imports no GPL packages from the parent project. The core deliverable is the RDP gateway `rdpgw`: on the front end it acts as an RDP server; on the back end it acts as an RDP client connecting to Windows; in between it relays PDUs, enforces policy, audits channels, provides live viewing, and records sessions. It can also let a browser start RDP sessions directly through the monitor Web UI.

### Data Flow

```
 mstsc / xfreerdp                       browser (web/monitor)
        |  TCP 3389-like                        |  HTTPS + WebSocket
        v                                       v
 +---------------+                     +------------------+
 | server front  |  X.224/TLS/NLA       | monitor          |
 | end (terminated|  MCS/GCC/ClientInfo  | HTTP API / WS    |
 | by gateway)   |                     | recordings .rdpv |
 +-------+-------+                     +----+--------+----+
         |  (optional) form login page      |        ^
         v                                  | web    | Observer:
 +---------------------------------------+  | session| frames/pointer/
 | gateway relay                         |<-+        | events
 |  - routing policy / channel whitelist |-----------+
 |  - channel tap: cliprdr / rdpdr /     |
 |    rdpsnd / drdynvc (display control, |
 |    audio)                             |
 +-------------------+-------------------+
                     | transport.Dial
                     v
 +---------------------------------------+
 | transport back end: TLS / CredSSP(nla)|
 | / licensing / activation              |
 +-------------------+-------------------+
                     v
             Windows RDP host (e.g. 192.0.2.10:3389)
```

Key points:

- **Front end (server)**: accepts RDP clients and completes X.224 negotiation, TLS, optional front-end NLA (`-nla-users`, PROTOCOL_HYBRID), MCS/GCC, Client Info, and licensing. In `-login-form` mode the gateway activates the session itself, draws a login form with the `form` package, and dials based on user input.
- **Relay (gateway)**: forwards share PDUs, fast-path input/output, and static virtual channels between front end and back end, rewriting pduSource / channel numbers, filtering channels per `-allow-channel`, and handing frames and events to the Observer (monitor).
- **Channel tap**: `gateway/channeltap.go` parses the clipboard (cliprdr), drive redirection (rdpdr), etc. for auditing. For Web sessions the gateway implements the clipboard itself (`webclip.go`), the browser folder as a redirected drive (`webdrive.go`), audio (`websound.go`, rdpsnd / AUDIO_PLAYBACK_DVC), and drdynvc with display control (`webdvc.go`, dynamic resolution).
- **Back end (transport)**: connects to the target, supports a minimum TLS version, CA/name verification or certificate pinning, CredSSP/NTLMv2 (the `nla` package), and automatically retries with RC4 for TLS 1.0 CBC on Windows 7.
- **monitor**: HTTP/WebSocket API, live frame stream (frames as PNG/JPEG rectangles), collaborative control, mapped-drive browsing, `.rdpv` recording write and playback, Web user login, and browser RDP connections.

## 2. Directory and Package Responsibilities

| Path | Responsibility | Key types / entry points |
| --- | --- | --- |
| `wire/` | RDP wire-format codecs: TPKT, X.224, MCS/PER/BER, GCC, security headers, Client Info, capability sets, share PDUs, fast-path input/output, virtual channels, cliprdr, rdpdr, ARC cookie | various `Encode*/Decode*` functions; sample vectors in `wire/testdata/*.hex` |
| `transport/` | Back-end client: probing, connecting, CredSSP, licensing, activation, observing output | `transport.Dial`, `Result` (e.g. `TLS10StreamCipher`) |
| `nla/` | CredSSP / SPNEGO / NTLMv2 (including MD4), both client and server sides | `nla.ClientConfig` (`MinVersion`, etc.) |
| `licensing/` | Licensing-phase state machine | `licensing.Client`, `ErrorAlert` |
| `bitmap/` | Framebuffer, interleaved RLE, planar decoding, pointer cache | `bitmap.Framebuffer`, `bitmap.New`, `PointerState` |
| `server/` | Front-end server connection, activation, capability advertisement, sending bitmaps/pointers, decoding input | `server.Conn` (`Activate/SendBitmap/SendPointer/DecodeInput/DeactivateAll`), `serverCapabilities` |
| `form/` | Gateway login form: dot-matrix font canvas, fields, keyboard mapping, Chinese prompts | `form.Form`, `form.New`, `Values`, `Canvas` |
| `gateway/` | Relay core, login-form routing, channel tap, Web sessions | `gateway.Config`, `gateway.New`, `Gateway`, `Target`, `FormConfig` (`Route`), `Observer`, `ChannelObserver`, `WebRequest`/`WebSession`, `WebFS` |
| `monitor/` | Monitoring HTTP API, WebSocket, recordings, Web login, drive browsing, audio ADPCM encoding | `monitor.Config`, `monitor.New`, `(*Monitor).Handler(token, uiDir)`, `Meta`, `Reader`/`NewReader`, `Accounts` |
| `cmd/rdpgw/` | Gateway executable (`main.go` flags and assembly, `web.go` Web-session wiring) | `flag` definitions are centralized in `main.go` |
| `cmd/rdpprobe/` | Probe a target (protocol, TLS, certificate; `-json` outputs `peer_sha256`) | `main.go` |
| `cmd/rdpserve/` | Standalone RDP server for testing | `main.go` |
| `web/monitor/` | React + antd + Vite + TypeScript front end | see Section 7 |
| `testenv/xrdp`, `scripts/xrdp-env.sh` | Local xrdp interoperability environment | |
| `docs/` | `SOURCES.md` (protocol sources), `VALIDATION.md` (real-machine validation), this document | |

## 3. Building

Back end (static binary, no cgo):

```sh
cd go-kernel
CGO_ENABLED=0 go build ./cmd/rdpgw
CGO_ENABLED=0 go build ./cmd/rdpprobe ./cmd/rdpserve
# cross-compilation example
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/rdpgw ./cmd/rdpgw
```

Front end:

```sh
cd go-kernel/web/monitor
npm ci
npm run build       # = tsc --noEmit && vite build, output in dist/
npm run typecheck   # tsc --noEmit only
npm run dev         # Vite dev server
```

Run examples (placeholder addresses):

```sh
./rdpgw -listen 127.0.0.1:33892 -target 192.0.2.10:3389 -target-pin <sha256> \
  -monitor 127.0.0.1:8090 -monitor-ui web/monitor/dist -record-dir /tmp/rdpv
# browser login + Web RDP
./rdpgw -hash-password < pw.txt          # generate a hash for -web-users
./rdpgw -login-form -allow-target 192.0.2.0/24 -monitor 127.0.0.1:8090 \
  -monitor-ui web/monitor/dist -web-users users.txt
```

A non-loopback `-monitor` requires `-monitor-cert/-monitor-key` or `-monitor-autocert`; otherwise an explicit `-monitor-insecure` is needed. `-monitor-token` defaults to the `RDPGW_MONITOR_TOKEN` environment variable.

## 4. Testing

```sh
go vet ./...
go test ./...
go test -race ./...                 # recommended for concurrency-related changes
go test ./wire -run '^$' -fuzz FuzzReadTPKT -fuzztime 30s
cd web/monitor && npm run typecheck
```

Existing fuzz targets are concentrated in `wire` (e.g. `FuzzReadTPKT`, `FuzzDecodeConnectionConfirm`, `FuzzDecodeConnectResponse`, `FuzzDomainPDUs`, `FuzzDecodeFastPathInput`, `FuzzDecodeFastPathPDU`, `FuzzDecodeDemandActive`, `FuzzDecodeDataPDU`, `FuzzDecodeSendDataIndication`, `FuzzDecodeOutput`), plus `bitmap/rle_test.go` and `licensing/licensing_test.go`. Use `grep -rn "func Fuzz" .` to list them all. `-fuzz` can only specify one target in one package at a time.

The steps and conclusions of real-machine validation (Windows 7 / Server 2016, xfreerdp, mstsc, browser) are recorded in `docs/VALIDATION.md`. After changing handshakes, capability negotiation, NLA, or channel logic, regress against the scenarios there and append results to that document (again, placeholder addresses only).

## 5. monitor API

Routes are defined in `monitor/http.go` (`(*Monitor).Handler`) and `monitor/drives_http.go` (`driveRoutes`). All `/api/` requests first go through:

- **Same-origin check**: when Origin is neither the Host nor listed in `-monitor-origins`, non-GET requests and WebSocket upgrades return 403.
- **Authentication** (`authorized`): any one of:
  1. Web user login session cookie `rdpmon_session` (obtained via `POST /api/login` when `-web-users` is enabled);
  2. `Authorization: Bearer <token>` (`-monitor-token`);
  3. the HttpOnly cookie `rdpmon_token` exchanged from a token (`POST /api/token-session`), so WebSockets and download links do not need `?token=`.
  
  When Web login is enabled but no token is set, only login sessions are accepted. When neither a token nor login is configured, the API is unauthenticated (recommended for loopback addresses only). All cookies are HttpOnly, SameSite=Strict, and Secure under HTTPS; HTTPS responses include HSTS.

| Method | Path | Purpose | Auth |
| --- | --- | --- | --- |
| GET | `/api/info` | Feature switches: control, recording, drive_control, login, current user, web | required |
| POST | `/api/login` | Web user login (user/password), issues a session cookie; failures are rate-limited/locked per IP | none (still same-origin checked) |
| POST | `/api/token-session` | Exchange a Bearer token for an HttpOnly cookie; returns 204 when no token is set | Bearer |
| POST | `/api/logout` | End the token cookie and login session | required |
| POST | `/api/connect` | Browser starts an RDP session (address, credentials, resolution, color depth, keyboard layout, etc.); returns a session ID and owner key | logged-in user; token usable when login is not enabled |
| GET | `/api/sessions` | List of current sessions | required |
| GET | `/api/sessions/{id}/live` | WebSocket live stream; `?control=1` (requires `-monitor-control`) or `?owner=<key>` allows sending input | required |
| POST | `/api/sessions/{id}/disconnect` | Disconnect a session | required |
| GET | `/api/sessions/{id}/devices` | Devices mapped by the client | required |
| GET | `/api/sessions/{id}/drives/{device}/entries` | List a directory | requires `-monitor-drive-control` and a token |
| GET / PUT / DELETE | `/api/sessions/{id}/drives/{device}/file` | Download / upload / delete a file | same as above |
| GET | `/api/recordings` | Recording list (Meta) | required |
| GET | `/api/recordings/{id}` | Read a recording; `?download=1` downloads it as an attachment | required |
| DELETE | `/api/recordings/{id}` | Delete a recording | required |
| GET | `/` (all other paths) | SPA under the `-monitor-ui` directory | none |

Session and recording IDs must match `^[0-9A-Za-z-]{1,64}$`.

## 6. Recording Format `.rdpv`

Defined in `monitor/record.go`. Files and the live WebSocket share one record encoding; integers are little-endian:

```
header: "RDPV" | version u16 (=1) | metaLen u32 | meta (JSON Meta)
record: kind u8 | time u32 (milliseconds since session start) | len u32 | payload
```

| kind | Name | payload |
| --- | --- | --- |
| 1 | Frame | x, y, w, h (u16) + the image of that rectangle |
| 2 | Key | same as Frame, covers the full screen, used as a seek point |
| 3 | Resize | w, h (u16), clears the screen |
| 4 | Pointer | mouse position x, y |
| 5 | End | session ended |
| 6 | Event | JSON `Event`; excludes key codes and clipboard contents |

`Meta` records the ID, source address, user, domain, client name, target, whether it is a login-form / Web session, resolution, and start time; after the session ends, `duration_ms`, `size`, and `end` are filled in and written to a sidecar file. Meta is capped at 64 KiB and a single record at 64 MiB. On the Go side use `monitor.NewReader`; the front-end parser is in `web/monitor/src/rdpv.ts`. Web-session audio is recorded as IMA ADPCM (`monitor/audio.go`). When changing the format, bump `fileVersion` and keep older versions readable.

## 7. Front-End Structure (`web/monitor`)

```
src/
  main.tsx          routing and entry point
  Shell.tsx         layout, navigation, login state
  api.ts            all HTTP calls, types (SessionInfo, RecordingMeta, MonitorInfo, ConnectRequest, WebSession), liveURL/downloadURL
  rdpv.ts           .rdpv record parsing (shared by live stream and playback)
  input.ts touch.ts keyboard/mouse, wheel, IME, keyboard lock, touch
  clipboard.ts      rich clipboard (text / HTML / PNG)
  audio.ts          audio playback
  webfs.ts          browser folder as a redirected drive
  pages/            Connect (start a connection), Live (live view), Login, Player (playback), Recordings, Sessions
  components/       Screen (canvas), Events, DriveBrowser (+ finderState.ts), LanguageSwitch
  i18n/             index.ts, i18next.d.ts, locales/{zh,en}/<namespace>.ts
```

`api.ts` centrally handles token exchange (`tokenSession`) and 401s (`AuthError`); pages must not build their own fetch calls.

### i18n

- Uses i18next + react-i18next + browser language detection; the language choice is stored in `localStorage` under `rdpmon.lang`, and the dayjs locale is synced.
- Namespaces: `api, common, connect, drive, events, live, login, player, recordings, sessions`; each language re-exports them from `locales/<lang>/index.ts`.
- **zh is the source of truth**: `i18next.d.ts` declares `resources: typeof zh`, so every key used in `t('ns:key')` must exist in the Chinese resources; each English namespace is type-constrained by its corresponding Chinese module (`typeof zh`), so missing or extra keys fail `tsc`.

Adding strings:

1. Add the key and Chinese text in `src/i18n/locales/zh/<ns>.ts`;
2. Add the same key and English text in `src/i18n/locales/en/<ns>.ts`;
3. In the component, use `t('key')` after `const { t } = useTranslation('<ns>')`;
4. `npm run typecheck`.

Adding a language (e.g. ja): copy `locales/en` to `locales/ja` and translate (still type-constrained by zh), register it in `i18n/index.ts` under resources and `LANGUAGES`, and import the corresponding dayjs locale.

## 8. Coding Conventions

- **Standard library only**: no third-party modules on the Go side; implement new protocols from public specifications, do not copy code from other RDP projects, and document sources in `docs/SOURCES.md`. Keep front-end dependencies within the existing package.json scope; new additions need a strong justification.
- **No credentials in logs**: passwords, NTLM hashes, tokens, cookies, delegated credentials, clipboard contents, and key codes must never appear in logs, `-json` output, recording events, or error messages. User-visible errors use categorized messages.
- **Defensive parsing**: all decoders check length bounds; malformed input returns an error instead of panicking; new decoders come with fuzz targets.
- **New capabilities need unit tests**: prefer sample vectors from the specification for protocol fields (placed in `wire/testdata`); problems found on real machines must be turned into regression tests (e.g. `TestServerCapabilitiesKeepRelayFeaturesNegotiable`, `TestTLS10CredSSPRetriesWithStreamCipher`).
- Conservative security defaults: minimum TLS 1.2 for the back end, certificates must be verified or pinned, and a non-loopback monitor requires HTTPS. Downgrade options (such as `-target-credssp-legacy`) must be explicitly enabled and state their risks in the help text.
- Before committing, run `gofmt`, `go vet ./...`, `go test ./...`, and the front-end `npm run typecheck`.

## 9. Common Development Tasks

### Adding a CLI Flag

1. Add it in the flag block of `cmd/rdpgw/main.go`, e.g.:
   ```go
   webBanner := flag.String("web-banner", "", "text shown on the monitor login page")
   ```
   Help text is in English and explains the default value and any flags it depends on.
2. Validate combinations in `main` (e.g. exit with an error if it depends on `-monitor`), pass the value into `gateway.Config` or `monitor.Config`, and do not read flags or environment variables inside library packages.
3. Write unit tests for the new option in the corresponding package; if behavior changes, update `README.md` / `docs/VALIDATION.md`.

### Adding a monitor API

1. Register it in `Handler` in `monitor/http.go` using Go 1.22+ routing patterns:
   ```go
   mux.HandleFunc("GET /api/sessions/{id}/stats", func(w http.ResponseWriter, r *http.Request) {
       s := m.Session(r.PathValue("id"))
       if s == nil {
           http.Error(w, "no such session", http.StatusNotFound)
           return
       }
       writeJSON(w, s.Stats())
   })
   ```
   `/api/` routes registered on the mux automatically go through the same-origin check and `authorized`; do not bypass the outer wrapping. Only endpoints that genuinely need to skip authentication are special-cased outside (currently only `POST /api/login`).
2. Decode request bodies with `decodeJSONBody` and set a size limit; validate IDs with `validID`.
3. Cover success, 401, and cross-site 403 cases with `httptest` in `monitor/monitor_test.go` or `web_test.go`.
4. On the front end, add a method and return type to the `api` object in `api.ts`.

### Adding Page Text

1. Add the key in both `locales/zh/<ns>.ts` and `locales/en/<ns>.ts`;
2. Use `t('<ns>:key')` in the page, or `t('key')` after `useTranslation('<ns>')`; interpolation uses `t('key', { name })`;
3. If a new page needs a new namespace, export it in both languages' `index.ts`, then register the route in `main.tsx` and add navigation in `Shell.tsx`;
4. Run `npm run build` after `npm run typecheck` passes.
