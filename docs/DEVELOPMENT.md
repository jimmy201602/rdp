# 开发者指南

本文面向在 `go-kernel` 上做开发的工程师，说明架构、目录职责、构建测试方法、monitor API、录像格式、前端结构和编码约定。协议来源与实现边界见 `docs/SOURCES.md`，真机验证记录见 `docs/VALIDATION.md`。

文中所有地址、账号、指纹均为占位符（如 `192.0.2.10`、`<sha256>`），不要把真实 IP、密码或证书指纹写进文档、测试或日志。

## 1. 项目概述与架构

`go-kernel` 是独立 Go module（`module rdp.local/kernel`，`go 1.25`），只依赖 Go 标准库，不导入父项目的 GPL 包。核心产物是 RDP 网关 `rdpgw`：它在前端扮演 RDP 服务端，在后端扮演 RDP 客户端连接 Windows，中间做 PDU 中继、策略控制、通道审计、实时监看和录像；同时可以通过 monitor 的 Web UI 让浏览器直接发起 RDP 会话。

### 数据流

```
 mstsc / xfreerdp                       浏览器 (web/monitor)
        |  TCP 3389-like                        |  HTTPS + WebSocket
        v                                       v
 +---------------+                     +------------------+
 | server 前端   |  X.224/TLS/NLA       | monitor          |
 | (被网关终结)  |  MCS/GCC/ClientInfo  | HTTP API / WS    |
 +-------+-------+                     | 录像 .rdpv       |
         |  (可选) form 登录表单         +----+--------+----+
         v                                  |        ^
 +---------------------------------------+  | web    | Observer:
 | gateway relay                         |<-+ 会话   | 帧/指针/事件
 |  - 路由策略 / 通道白名单              |-----------+
 |  - channel tap: cliprdr / rdpdr /     |
 |    rdpsnd / drdynvc (显示控制、音频)  |
 +-------------------+-------------------+
                     | transport.Dial
                     v
 +---------------------------------------+
 | transport 后端：TLS / CredSSP(nla) /  |
 | 许可(licensing) / 激活                |
 +-------------------+-------------------+
                     v
             Windows RDP 主机 (例 192.0.2.10:3389)
```

要点：

- **前端（server）**：接受 RDP 客户端，完成 X.224 协商、TLS、可选前端 NLA（`-nla-users`，PROTOCOL_HYBRID）、MCS/GCC、Client Info 和许可。`-login-form` 模式下网关先自己激活会话，用 `form` 包绘制登录表单，再按用户输入拨号。
- **中继（gateway）**：把前端与后端的 share PDU、fast-path 输入输出、静态虚拟通道互相转发，改写 pduSource / 通道号，按 `-allow-channel` 过滤通道，并把画面和事件交给 Observer（monitor）。
- **通道 tap**：`gateway/channeltap.go` 解析剪贴板（cliprdr）、磁盘重定向（rdpdr）等用于审计；Web 会话下 gateway 自己实现剪贴板（`webclip.go`）、浏览器文件夹作为重定向磁盘（`webdrive.go`）、音频（`websound.go`，rdpsnd / AUDIO_PLAYBACK_DVC）、drdynvc 与显示控制（`webdvc.go`，动态分辨率）。
- **后端（transport）**：连接目标，支持 TLS 最低版本、CA/名称校验或证书 pin、CredSSP/NTLMv2（`nla` 包），Windows 7 下 TLS 1.0 CBC 自动改用 RC4 重试。
- **monitor**：HTTP/WebSocket API、实时画面流（帧为 PNG/JPEG 矩形）、协作控制、映射磁盘浏览、`.rdpv` 录像写入与回放、Web 用户登录与浏览器 RDP 连接。

## 2. 目录与包职责

| 路径 | 职责 | 关键类型 / 入口 |
| --- | --- | --- |
| `wire/` | RDP 线格式编解码：TPKT、X.224、MCS/PER/BER、GCC、安全头、Client Info、能力集、share PDU、fast-path 输入输出、虚拟通道、cliprdr、rdpdr、ARC cookie | 各 `Encode*/Decode*` 函数；样例向量在 `wire/testdata/*.hex` |
| `transport/` | 后端客户端：探测、连接、CredSSP、许可、激活、观察输出 | `transport.Dial`、`Result`（如 `TLS10StreamCipher`） |
| `nla/` | CredSSP / SPNEGO / NTLMv2（含 MD4），客户端与服务端两侧 | `nla.ClientConfig`（`MinVersion` 等） |
| `licensing/` | 许可阶段状态机 | `licensing.Client`、`ErrorAlert` |
| `bitmap/` | 帧缓冲、交错 RLE、planar 解码、指针缓存 | `bitmap.Framebuffer`、`bitmap.New`、`PointerState` |
| `server/` | 前端服务端连接、激活、能力声明、发送位图/指针、解码输入 | `server.Conn`（`Activate/SendBitmap/SendPointer/DecodeInput/DeactivateAll`）、`serverCapabilities` |
| `form/` | 网关登录表单：点阵字体画布、字段、键盘映射、中文提示 | `form.Form`、`form.New`、`Values`、`Canvas` |
| `gateway/` | 中继核心、登录表单路由、通道 tap、Web 会话 | `gateway.Config`、`gateway.New`、`Gateway`、`Target`、`FormConfig`（`Route`）、`Observer`、`ChannelObserver`、`WebRequest`/`WebSession`、`WebFS` |
| `monitor/` | 监看 HTTP API、WebSocket、录像、Web 登录、磁盘浏览、音频 ADPCM 编码 | `monitor.Config`、`monitor.New`、`(*Monitor).Handler(token, uiDir)`、`Meta`、`Reader`/`NewReader`、`Accounts` |
| `cmd/rdpgw/` | 网关可执行程序（`main.go` 参数与组装，`web.go` Web 会话接线） | `flag` 定义集中在 `main.go` |
| `cmd/rdpprobe/` | 探测目标（协议、TLS、证书；`-json` 输出 `peer_sha256`） | `main.go` |
| `cmd/rdpserve/` | 独立的测试用 RDP 服务端 | `main.go` |
| `web/monitor/` | React + antd + Vite + TypeScript 前端 | 见第 7 节 |
| `testenv/xrdp`、`scripts/xrdp-env.sh` | 本地 xrdp 互操作环境 | |
| `docs/` | `SOURCES.md`（协议来源）、`VALIDATION.md`（真机验证）、本文 | |

## 3. 构建

后端（静态二进制，无 cgo）：

```sh
cd go-kernel
CGO_ENABLED=0 go build ./cmd/rdpgw
CGO_ENABLED=0 go build ./cmd/rdpprobe ./cmd/rdpserve
# 交叉编译示例
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/rdpgw ./cmd/rdpgw
```

前端：

```sh
cd go-kernel/web/monitor
npm ci
npm run build       # = tsc --noEmit && vite build，产物在 dist/
npm run typecheck   # 只做 tsc --noEmit
npm run dev         # Vite 开发服务器
```

运行示例（占位地址）：

```sh
./rdpgw -listen 127.0.0.1:33892 -target 192.0.2.10:3389 -target-pin <sha256> \
  -monitor 127.0.0.1:8090 -monitor-ui web/monitor/dist -record-dir /tmp/rdpv
# 浏览器登录 + Web RDP
./rdpgw -hash-password < pw.txt          # 生成 -web-users 用的哈希
./rdpgw -login-form -allow-target 192.0.2.0/24 -monitor 127.0.0.1:8090 \
  -monitor-ui web/monitor/dist -web-users users.txt
```

非回环的 `-monitor` 必须配 `-monitor-cert/-monitor-key` 或 `-monitor-autocert`，否则需显式 `-monitor-insecure`。`-monitor-token` 默认取环境变量 `RDPGW_MONITOR_TOKEN`。

## 4. 测试

```sh
go vet ./...
go test ./...
go test -race ./...                 # 并发相关修改建议跑
go test ./wire -run '^$' -fuzz FuzzReadTPKT -fuzztime 30s
cd web/monitor && npm run typecheck
```

现有 fuzz 目标集中在 `wire`（如 `FuzzReadTPKT`、`FuzzDecodeConnectionConfirm`、`FuzzDecodeConnectResponse`、`FuzzDomainPDUs`、`FuzzDecodeFastPathInput`、`FuzzDecodeFastPathPDU`、`FuzzDecodeDemandActive`、`FuzzDecodeDataPDU`、`FuzzDecodeSendDataIndication`、`FuzzDecodeOutput`），以及 `bitmap/rle_test.go`、`licensing/licensing_test.go`。用 `grep -rn "func Fuzz" .` 查看全部。`-fuzz` 每次只能指定一个包内的一个目标。

真机验证（Windows 7 / Server 2016、xfreerdp、mstsc、浏览器）的步骤和结论记录在 `docs/VALIDATION.md`。修改握手、能力协商、NLA 或通道逻辑后，应按其中的场景回归，并在该文档补充结果（同样只写占位地址）。

## 5. monitor API

路由定义在 `monitor/http.go`（`(*Monitor).Handler`）和 `monitor/drives_http.go`（`driveRoutes`）。所有 `/api/` 请求先经过：

- **同源检查**：Origin 既不是 Host 也不在 `-monitor-origins` 中时，非 GET 请求和 WebSocket 升级返回 403。
- **鉴权**（`authorized`）：满足其一即可：
  1. Web 用户登录会话 cookie `rdpmon_session`（启用 `-web-users` 时，通过 `POST /api/login` 获得）；
  2. `Authorization: Bearer <token>`（`-monitor-token`）；
  3. token 交换得到的 HttpOnly cookie `rdpmon_token`（`POST /api/token-session`），WebSocket 与下载链接因此不需要 `?token=`。
  
  启用了 Web 登录但未设置 token 时，只认登录会话。未设置 token 且未启用登录时，API 不鉴权（仅建议回环地址使用）。cookie 均为 HttpOnly、SameSite=Strict，HTTPS 下带 Secure；HTTPS 响应附带 HSTS。

| 方法 | 路径 | 用途 | 鉴权 |
| --- | --- | --- | --- |
| GET | `/api/info` | 功能开关：control、recording、drive_control、login、当前 user、web | 需鉴权 |
| POST | `/api/login` | Web 用户登录（user/password），发放会话 cookie；失败按 IP 限速锁定 | 免鉴权（仍需同源） |
| POST | `/api/token-session` | 用 Bearer token 换 HttpOnly cookie；无 token 时返回 204 | Bearer |
| POST | `/api/logout` | 结束 token cookie 与登录会话 | 需鉴权 |
| POST | `/api/connect` | 浏览器发起 RDP 会话（地址、凭据、分辨率、色深、键盘布局等），返回会话 ID 与 owner key | 登录用户；未启用登录时可用 token |
| GET | `/api/sessions` | 当前会话列表 | 需鉴权 |
| GET | `/api/sessions/{id}/live` | WebSocket 实时流；`?control=1`（需 `-monitor-control`）或 `?owner=<key>` 可发送输入 | 需鉴权 |
| POST | `/api/sessions/{id}/disconnect` | 断开会话 | 需鉴权 |
| GET | `/api/sessions/{id}/devices` | 客户端映射的设备 | 需鉴权 |
| GET | `/api/sessions/{id}/drives/{device}/entries` | 列目录 | 需 `-monitor-drive-control` 且设置 token |
| GET / PUT / DELETE | `/api/sessions/{id}/drives/{device}/file` | 下载 / 上传 / 删除文件 | 同上 |
| GET | `/api/recordings` | 录像列表（Meta） | 需鉴权 |
| GET | `/api/recordings/{id}` | 读取录像，`?download=1` 作为附件下载 | 需鉴权 |
| DELETE | `/api/recordings/{id}` | 删除录像 | 需鉴权 |
| GET | `/`（其余路径） | `-monitor-ui` 目录下的 SPA | 无 |

会话与录像 ID 须匹配 `^[0-9A-Za-z-]{1,64}$`。

## 6. 录像格式 `.rdpv`

定义在 `monitor/record.go`。文件和实时 WebSocket 共用一套记录编码，整数为小端序：

```
header: "RDPV" | version u16 (=1) | metaLen u32 | meta (JSON Meta)
record: kind u8 | time u32 (会话开始后的毫秒) | len u32 | payload
```

| kind | 名称 | payload |
| --- | --- | --- |
| 1 | Frame | x, y, w, h（u16）+ 该矩形的图像 |
| 2 | Key | 同 Frame，覆盖全屏，作为 seek 点 |
| 3 | Resize | w, h（u16），清屏 |
| 4 | Pointer | 鼠标位置 x, y |
| 5 | End | 会话结束 |
| 6 | Event | JSON `Event`；不含按键码和剪贴板正文 |

`Meta` 记录 ID、来源地址、用户、域、客户端名、目标、是否登录表单 / Web 会话、分辨率、开始时间；会话结束后补齐 `duration_ms`、`size`、`end` 写入旁路文件。meta 上限 64 KiB，单条记录上限 64 MiB。Go 侧用 `monitor.NewReader` 读取，前端解析在 `web/monitor/src/rdpv.ts`。Web 会话的音频以 IMA ADPCM 录入（`monitor/audio.go`）。修改格式时要提升 `fileVersion` 并保持旧版本可读。

## 7. 前端结构（`web/monitor`）

```
src/
  main.tsx          路由与入口
  Shell.tsx         布局、导航、登录态
  api.ts            所有 HTTP 调用、类型（SessionInfo、RecordingMeta、MonitorInfo、ConnectRequest、WebSession）、liveURL/downloadURL
  rdpv.ts           .rdpv 记录解析（实时流与回放共用）
  input.ts touch.ts 键鼠、滚轮、IME、键盘锁定、触控
  clipboard.ts      富剪贴板（文本 / HTML / PNG）
  audio.ts          音频播放
  webfs.ts          浏览器文件夹作为重定向磁盘
  pages/            Connect（发起连接）、Live（实时画面）、Login、Player（回放）、Recordings、Sessions
  components/       Screen（画布）、Events、DriveBrowser（+ finderState.ts）、LanguageSwitch
  i18n/             index.ts、i18next.d.ts、locales/{zh,en}/<namespace>.ts
```

`api.ts` 统一处理 token 交换（`tokenSession`）与 401（`AuthError`），页面不要自己拼 fetch。

### i18n

- 使用 i18next + react-i18next + 浏览器语言检测，语言选择存在 `localStorage` 的 `rdpmon.lang`，并同步 dayjs 语言。
- 命名空间：`api, common, connect, drive, events, live, login, player, recordings, sessions`，每个语言在 `locales/<lang>/index.ts` 汇总导出。
- **zh 是基准**：`i18next.d.ts` 声明 `resources: typeof zh`，`t('ns:key')` 的键必须存在于中文资源；英文各命名空间以对应中文模块的类型约束（`typeof zh`），因此缺键或多键都会在 `tsc` 时报错。

新增词条：

1. 在 `src/i18n/locales/zh/<ns>.ts` 加键和中文；
2. 在 `src/i18n/locales/en/<ns>.ts` 加同名键和英文；
3. 组件中 `const { t } = useTranslation('<ns>')` 后使用 `t('key')`；
4. `npm run typecheck`。

新增语言（例如 ja）：复制 `locales/en` 为 `locales/ja` 并翻译（同样以 zh 类型约束），在 `i18n/index.ts` 的 resources 和 `LANGUAGES` 中注册，引入对应 dayjs locale。

## 8. 编码约定

- **只用标准库**：Go 侧不引入第三方 module；新协议实现按公开规范编写，不复制其他 RDP 项目的代码，并在 `docs/SOURCES.md` 补充来源。前端依赖保持在现有 package.json 范围内，新增需有充分理由。
- **凭据不入日志**：密码、NTLM 哈希、token、cookie、委派凭据、剪贴板正文、按键码不得出现在日志、`-json` 输出、录像事件或错误信息中。用户可见错误使用分类后的提示。
- **解析防御**：所有解码函数对长度做上限检查，畸形输入返回错误而不是 panic；新增解码器配 fuzz 目标。
- **新增能力需单测**：协议字段优先用规范中的样例向量（放在 `wire/testdata`）；真机发现的问题要固化成回归测试（例如 `TestServerCapabilitiesKeepRelayFeaturesNegotiable`、`TestTLS10CredSSPRetriesWithStreamCipher`）。
- 安全相关默认值保守：后端最低 TLS 1.2、证书必须校验或 pin、非回环 monitor 必须 HTTPS。降级选项（如 `-target-credssp-legacy`）必须显式开启并在帮助文本中说明风险。
- 提交前跑 `gofmt`、`go vet ./...`、`go test ./...` 和前端 `npm run typecheck`。

## 9. 常见开发任务

### 新增 CLI 参数

1. 在 `cmd/rdpgw/main.go` 的 flag 区块添加，例如：
   ```go
   webBanner := flag.String("web-banner", "", "text shown on the monitor login page")
   ```
   帮助文本用英文，说明默认值和依赖的其他参数。
2. 在 `main` 中校验组合（例如依赖 `-monitor` 时报错退出），把值传入 `gateway.Config` 或 `monitor.Config`，不要在库包里读 flag 或环境变量。
3. 在对应包为新配置项写单测；如影响行为，更新 `README.md` / `docs/VALIDATION.md`。

### 新增 monitor API

1. 在 `monitor/http.go` 的 `Handler` 中用 Go 1.22+ 路由模式注册：
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
   注册在 mux 上的 `/api/` 路由自动经过同源检查和 `authorized`，不要绕过外层包装；只有确实需要免鉴权的入口才在外层特判（目前只有 `POST /api/login`）。
2. 请求体用 `decodeJSONBody` 并设大小上限；ID 用 `validID` 校验。
3. 在 `monitor/monitor_test.go` 或 `web_test.go` 中用 `httptest` 覆盖成功、401、跨站 403 场景。
4. 前端在 `api.ts` 的 `api` 对象加方法和返回类型。

### 新增页面文案

1. 在 `locales/zh/<ns>.ts` 和 `locales/en/<ns>.ts` 同时加键；
2. 页面里 `t('<ns>:key')` 或在 `useTranslation('<ns>')` 后 `t('key')`，插值用 `t('key', { name })`；
3. 新页面需要新命名空间时，在两种语言的 `index.ts` 中都导出，再在 `main.tsx` 注册路由、`Shell.tsx` 加导航；
4. `npm run typecheck` 通过后再 `npm run build`。
