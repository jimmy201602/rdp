# rdpgw 使用指南

`rdpgw` 是本仓库（`go-kernel`）提供的 RDP 网关。它在前端接受 RDP 客户端（mstsc、xfreerdp 等）或浏览器的连接，在后端以 TLS / CredSSP(NLA) 连接真正的 Windows 远程桌面主机，并在中间提供会话审计、实时监控、协同控制和录像回放。

> 本文中的地址、用户名、令牌和证书指纹均为占位符（如 `192.0.2.10`、`<sha256>`、`<token>`），请替换为你自己的值。

## 1. 功能列表

- **RDP 客户端经网关接入**：mstsc / xfreerdp 连接网关，网关转发到固定目标（`-target`），支持前端 TLS 和前端 NLA（`-nla-users`）。
- **登录表单模式**（`-login-form`）：客户端连上后先看到网关绘制的登录表单，输入服务器地址、用户名和密码后，由网关连接所填的目标；可用 `-allow-target` 限制可选目标，失败可重试。
- **Web 浏览器 RDP 客户端**（`-web-users`）：在监控界面登录后，直接在浏览器中打开远程桌面，无需安装客户端。
- **实时监控与协同控制**：在浏览器里实时观看任意会话；开启 `-monitor-control` 后可加入键盘鼠标操作，也可强制断开会话。
- **录像与回放（含音频）**：`-record-dir` 把每个会话保存为 `.rdpv` 文件；回放支持进度跳转、操作事件时间轴，以及 1× 速度下播放声音（音频以 IMA ADPCM 记录）。
- **剪贴板（含富文本）**：文字、HTML 格式、PNG 图片，以及 16/24/32 位 DIB 位图。
- **磁盘映射**：Web 客户端可把本地文件夹映射为远程磁盘（Chrome / Edge）；监控端可浏览用户映射的磁盘，开启 `-monitor-drive-control` 后可上传、下载、删除文件。
- **音频**：远程声音通过 rdpsnd / AUDIO_PLAYBACK_DVC 播放到浏览器。
- **动态分辨率**：支持显示控制的服务器（Server 2016 及以上）会随浏览器窗口自动调整分辨率；旧系统（如 Windows 7）保持初始分辨率。
- **目标断线自动重连**：与远程主机的连接中断时，网关使用 ARC Cookie 自动重连；浏览器与网关断开后，会话在 `-web-reconnect` 时间内保留，可重新接上。
- **扩展输入**：滚轮 / 水平滚轮、鼠标侧键、输入法（IME）、全屏时的键盘锁定（可直接按 Win、Alt+Tab）、触控。
- **中英文界面**：界面右上角可切换语言，选择保存在浏览器中；首次访问按浏览器语言自动选择。

## 2. 安装与构建

需要 Go（版本见 `go.mod`）和 Node.js / npm（仅构建 Web 界面时需要）。

```sh
cd go-kernel

# 构建网关和探测工具
go build -o bin/rdpgw ./cmd/rdpgw
go build -o bin/rdpprobe ./cmd/rdpprobe

# 构建 Web 监控界面，产物在 web/monitor/dist
cd web/monitor
npm install
npm run build
```

启动时用 `-monitor-ui web/monitor/dist` 指向构建好的前端目录。

## 3. 快速开始

### 3.1 固定目标模式

所有客户端都被转发到同一台主机：

```sh
./bin/rdpgw -listen 0.0.0.0:33892 \
  -target 192.0.2.10:3389 \
  -target-pin <sha256>
```

未提供 `-cert` / `-key` 时，网关使用临时自签名证书，客户端会提示证书不受信任。

### 3.2 登录表单模式

客户端连上后由用户在表单中填写目标：

```sh
./bin/rdpgw -listen 0.0.0.0:33892 \
  -login-form \
  -allow-target 192.0.2.10,192.0.2.0/24 \
  -target-pin 192.0.2.10=<sha256>,192.0.2.11=<sha256>
```

### 3.3 启用 Web 界面的完整示例

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

然后在浏览器打开 `https://<网关地址>:8443/`。令牌通过环境变量 `RDPGW_MONITOR_TOKEN` 传入，避免出现在进程列表和 shell 历史中。正式环境建议用 `-monitor-cert` / `-monitor-key` 提供受信任的证书。

## 4. 参数参考

以下取值和默认值以 `go run ./cmd/rdpgw -h` 的输出为准。

### 4.1 前端监听与证书

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-listen` | `127.0.0.1:33892` | 前端 RDP 监听地址 |
| `-cert` | 临时自签名 | 前端 PEM 证书链 |
| `-key` | | 前端 PEM 私钥 |
| `-handshake-timeout` | `30s` | 前端握手时限 |
| `-max-sessions` | `16` | 最大并发客户端连接数 |
| `-nla-users` | | 启用前端 CredSSP/NLA：每行 `user:password` 的文件；提供 PROTOCOL_HYBRID 的客户端先以 NTLMv2 认证，委派的凭据再转给目标 |
| `-require-nla` | `false` | 拒绝不提供 PROTOCOL_HYBRID 的客户端（需要 `-nla-users`） |
| `-allow-user` | 空（任意） | 路由策略允许的用户名，逗号分隔 |
| `-allow-domain` | 空（任意） | 要求的域 |
| `-once` | `false` | 第一个会话结束后退出 |
| `-json` | `false` | 每个结束的转发 / 会话输出一行 JSON |
| `-trace` | `false` | 记录每个转发的慢路径 share PDU 类型（调试用） |

### 4.2 目标、TLS、NLA 与证书固定

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-target` | | 目标 `host:port`（不用 `-login-form` 时必填） |
| `-target-name` | 目标主机名 | 校验目标证书时使用的 TLS 名称 |
| `-target-ca` | | 信任的目标根证书（PEM） |
| `-target-pin` | | 目标叶证书的十六进制 SHA-256，替代 CA/名称校验（适合自签名的 Windows 主机）；在 `-login-form` 下可写成逗号分隔的 `host=sha256` 列表固定多台主机 |
| `-target-min-tls` | `1.2` | 目标允许的最低 TLS 版本：`1.0`、`1.1`、`1.2`、`1.3`（Windows 7 只提供 1.0） |
| `-target-nla` | `false` | 要求后端使用 CredSSP 5/6 + NTLMv2（不回退到仅 TLS）；前端仍为仅 TLS |
| `-target-credssp-legacy` | `false` | 配合 `-target-nla`：也接受未打补丁的 Windows 7 / 2008 R2 的 CredSSP 2-4（CVE-2018-0886），须同时使用 `-target-pin` |
| `-target-timeout` | `20s` | 目标握手时限 |

### 4.3 登录表单

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-login-form` | `false` | 向每个客户端显示登录表单，并连接用户输入的服务器，而非 `-target` |
| `-allow-target` | 空（任意） | 用户可输入的主机、IP 或 CIDR，逗号分隔；设置了 `-target` 时它始终允许。同样约束 Web 连接 |
| `-form-attempts` | `5` | 失败多少次后断开客户端 |
| `-form-idle` | `5m0s` | 表单空闲多久后断开客户端 |

### 4.4 虚拟通道

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-allow-channel` | `*` | 转发到目标的静态虚拟通道，逗号分隔（`*` 全部，空为不转发），如 `cliprdr,rdpdr,rdpsnd,drdynvc` |

### 4.5 监控与 HTTPS

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-monitor` | | 监控 Web 界面与 API 的地址，如 `127.0.0.1:8090` |
| `-monitor-ui` | | 构建好的前端目录（`web/monitor/dist`） |
| `-monitor-token` | `$RDPGW_MONITOR_TOKEN` | 监控 API 要求的 Bearer 令牌；为空表示不需要 |
| `-monitor-cert` | | 监控端 HTTPS 证书链（`-monitor` 非回环地址时必需） |
| `-monitor-key` | | `-monitor-cert` 对应的私钥 |
| `-monitor-autocert` | | 使用自签名证书提供 HTTPS，证书保存在该目录（首次启动创建；浏览器在信任前会警告） |
| `-monitor-hosts` | `-monitor` 主机和本机地址 | 配合 `-monitor-autocert`：证书中的 DNS 名称 / IP，逗号分隔 |
| `-monitor-insecure` | `false` | 允许非回环地址使用明文 HTTP（密码和画面将不加密传输，不建议） |
| `-monitor-origins` | | 额外接受的浏览器 Origin（`https://host[:port]`），如反向代理的公网地址 |
| `-monitor-control` | `false` | 允许监控端以键盘鼠标加入会话 |
| `-monitor-drive-control` | `false` | 允许在客户端映射的磁盘上浏览、读取、新建、删除（需要 `-monitor` 和 `-monitor-token`） |

### 4.6 Web 用户与会话限制

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-web-users` | | 启用浏览器登录和 Web RDP 客户端：每行 `user:password` 或 `user:<-hash-password 输出>` |
| `-web-user-targets` | | 每用户可连接目标文件（见 5.2） |
| `-web-max-sessions` | `8` | 浏览器发起的并发 RDP 会话总数 |
| `-web-max-per-user` | `2` | 每个账号的并发浏览器会话数（0 不限制） |
| `-web-idle` | `30m0s` | 无键盘鼠标输入多久后断开浏览器会话（0 永不） |
| `-web-reconnect` | `2m0s` | 浏览器断开后会话保留多久以便重连（负数为立即结束） |
| `-hash-password` | `false` | 从标准输入读取密码，输出供 `-web-users` 使用的哈希后退出 |

### 4.7 录像

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-record-dir` | | 把每个转发的会话录制到该目录（`.rdpv` 文件） |

## 5. 账号与目标配置文件

### 5.1 `-web-users`

每行一个账号，`#` 开头的行和空行会被忽略。建议只存哈希：

```sh
# 从标准输入读取密码（可来自管道或密码管理器），输出哈希
printf '%s' '<password>' | ./bin/rdpgw -hash-password
```

```text
# web-users.txt
alice:<-hash-password 的输出>
bob:<-hash-password 的输出>
```

也可以写明文 `user:password`，但不建议。文件权限应限制为仅网关运行账号可读（如 `chmod 600`）。`-nla-users` 文件格式相同，为每行 `user:password`。

### 5.2 `-web-user-targets`

```text
# web-user-targets.txt
alice: 192.0.2.10, 192.0.2.0/28
bob: rdp-host.example.com
admin: *
```

- 列出的用户只能连接所列目标，且仍须在 `-allow-target` 范围内。
- `*` 表示允许 `-allow-target` 允许的全部目标。
- 未列出的用户回退到 `-allow-target`。

## 6. 获取目标证书指纹

Windows 远程桌面通常使用自签名证书，推荐用 `-target-pin` 固定证书：

```sh
./bin/rdpprobe -addr 192.0.2.10:3389 -stage tls -json
```

输出 JSON 中的 `peer_sha256` 即为 `-target-pin` 的值。Windows 7 需加 `-min-tls 1.0`。如果用错误的 `-pin` 探测，失败信息也会报告实际观察到的指纹。请通过可信网络获取并核对指纹。

## 7. Windows 7 及旧系统注意事项

- Windows 7 / 2008 R2 只提供 TLS 1.0，需要 `-target-min-tls 1.0`。连接仅支持 TLS 1.0 的主机时，NLA 会改用 RC4 重试（Go 对 CBC 的 1/n-1 分片会破坏 Windows 7 的 CredSSP）。
- 未打 CVE-2018-0886 补丁的 Windows 7 只支持 CredSSP 2-4，需要 `-target-credssp-legacy`，并且必须同时用 `-target-pin` 固定证书。
- 旧系统不支持显示控制，Web 会话保持初始分辨率，不随窗口调整。

```sh
./bin/rdpgw -listen 0.0.0.0:33892 -target 192.0.2.20:3389 \
  -target-min-tls 1.0 -target-nla -target-credssp-legacy \
  -target-pin <sha256>
```

## 8. Web 界面使用说明

### 8.1 登录

登录页有两种方式：

- **用户登录**：使用 `-web-users` 中的账号，登录后可在浏览器中连接远程桌面，会话记在该账号名下。
- **访问令牌**：输入与 `-monitor-token` 一致的令牌（未设置时留空），只能查看与协同，不能发起连接。

令牌会交换为 HttpOnly Cookie，不会出现在 URL 中。顶部导航包括“实时监控”、“连接远程桌面”、“录像回放”，右上角有语言切换和“退出”。

### 8.2 连接页

- **服务器地址**：如 `192.0.2.10` 或 `192.0.2.10:3389`，必须在允许的目标范围内。
- **用户名 / 域（可选）/ 密码**。
- **分辨率**：“适应窗口”或固定分辨率（如 1280×800、1920×1080）。
- **颜色**：32 位、24 位、16 位、15 位。
- **更多选项**：
  - 视觉体验：最佳效果、均衡、流畅（默认）、低带宽。效果越多，占用带宽越大。
  - 键盘布局：中文（简体/繁体）、英语（美国/英国）、日语、韩语、德语、法语，会影响远程输入法与符号键。

凭据只保存在网关内存中，用于断线自动重连，会话结束即清除，不写入磁盘或日志。若页面未使用 HTTPS，会显示警告。

### 8.3 会话工具条

- **剪贴板**：远程复制的内容自动写入本机；切回页面时自动同步本机剪贴板（文字、HTML、图片）；也可在面板中输入后点“发送到远程”。图片超过约 2.9 MB 时只同步文字。
- **磁盘映射**：选择本地文件夹映射到远程（需要 Chrome / Edge，且通过 HTTPS 或 localhost 访问），可更换或取消映射；刷新页面后需重新选择。
- **发送 Ctrl+Alt+Del**。
- **快捷键**菜单：Win、Alt+Tab、Win+R、Win+E、Win+D、Win+L、Ctrl+Shift+Esc、Alt+F4、PrintScreen。全屏时可直接按这些组合键。
- **静音 / 取消静音**：浏览器阻止自动播放时，点击页面任意处即可播放声音。
- **全屏 / 退出全屏**、**断开**。

与远程主机断线时会显示“正在重连（第 n 次）”；与网关断线时也会自动重连。

### 8.4 会话列表与实时监控

“实时监控”页列出活动会话：用户、客户端、目标、分辨率、开始时间、时长、流量、观看人数、录像状态。可点“监控”观看，或点“断开”强制结束会话。

在实时页中可在“旁观”和“协同”之间切换（需要 `-monitor-control`）。协同时你的键盘鼠标会与原用户一起作用于桌面。侧栏显示会话信息、操作事件和“用户映射磁盘”浏览器；文件上传、下载和删除需要 `-monitor-drive-control` 和访问令牌（上传仅新建、单文件不超过 64 MiB；删除不进回收站）。

### 8.5 录像列表与回放

“录像回放”页列出录像（需要 `-record-dir`），可按用户、目标、客户端搜索，支持回放、下载、删除。回放页支持适应窗口 / 原始大小、全屏、进度跳转，以及“操作事件”时间轴（键盘、鼠标、剪贴板、文件、映射设备等，可跟随播放进度）。事件不保存键入原文和剪贴板正文。声音只在 1× 速度下播放。

## 9. 使用 xfreerdp / mstsc 接入

```sh
# 固定目标模式（网关使用自签名证书时）
xfreerdp /v:<网关地址>:33892 /u:<user> /d:<domain> /cert:ignore

# 前端 NLA（网关配置了 -nla-users）
xfreerdp /v:<网关地址>:33892 /u:<user> /sec:nla /cert:ignore

# 登录表单模式：不带凭据连接，在网关表单中填写
xfreerdp /v:<网关地址>:33892 /sec:tls /cert:ignore
```

`/cert:ignore` 仅用于测试；正式环境请为网关配置受信任证书（`-cert` / `-key`）。

mstsc：在“计算机”中填写 `<网关地址>:33892`，按提示输入凭据。网关使用自签名证书时会出现证书警告。

## 10. 安全建议

- 监控地址不是回环地址时必须使用 HTTPS（`-monitor-cert` 或 `-monitor-autocert`），不要使用 `-monitor-insecure`。
- 放在反向代理后面时，用 `-monitor-origins https://rdp.example.com` 声明公网 Origin。网关启用 HTTPS 时会发送 HSTS。
- `-allow-target` 只列出必需的主机，并按用户用 `-web-user-targets` 进一步收窄；`-allow-channel` 只开启需要的通道。
- 用 `-target-pin` 或 `-target-ca` 校验目标证书，并设置较强的 `-monitor-token`（通过 `RDPGW_MONITOR_TOKEN` 传入）。
- `-web-users` 中只存 `-hash-password` 生成的哈希，并限制文件权限。
- 凭据不落盘：网关只在内存中保存连接凭据，日志和录像都不包含密码。
- `-monitor-control` 和 `-monitor-drive-control` 只在需要时开启；录像目录也要限制访问权限。

## 11. 故障排查

| 现象 | 可能原因与处理 |
|---|---|
| 证书不符 / 证书校验失败 | 目标证书已更新或指纹有误：用 `rdpprobe -json` 重新获取 `peer_sha256`；名称校验失败时检查 `-target-name` / `-target-ca` |
| TLS 握手失败、协议版本错误 | 目标只支持旧版本 TLS（如 Windows 7）：设置 `-target-min-tls 1.0` |
| NLA / CredSSP 失败 | 检查用户名、域、密码；未打补丁的 Windows 7 需要 `-target-credssp-legacy` 加 `-target-pin`；目标未启用 NLA 时不要用 `-target-nla` |
| 启动报端口占用（address already in use） | 更换 `-listen` / `-monitor` 端口，或停止占用端口的进程（`lsof -i :33892`） |
| 非回环地址启动监控失败 | 需要 `-monitor-cert` 或 `-monitor-autocert` |
| 浏览器连接后无画面 | 检查目标是否可达、`-allow-target` 是否包含该目标；查看网关日志；尝试降低颜色深度或视觉体验 |
| 连接页提示“网关未开启网页连接” | 启动时加 `-web-users` 和 `-allow-target`，并通过 HTTPS 访问 |
| 无法协同控制 | 未开启 `-monitor-control` |
| 无法映射文件夹 | 需要 Chrome / Edge，并通过 HTTPS 或 localhost 访问 |
| 没有声音 | 点击页面以解除浏览器自动播放限制；确认 `-allow-channel` 包含 `rdpsnd` / `drdynvc` |
| 反代后 API 请求被拒绝 | 用 `-monitor-origins` 添加代理的公网 Origin |
| 录像列表为空 | 未设置 `-record-dir` |
| 剪贴板 / 磁盘无效 | 确认 `-allow-channel` 包含 `cliprdr` / `rdpdr` |

需要更多信息时，用 `-json` 输出会话摘要，必要时加 `-trace` 调试。
