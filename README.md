# RDP

用 Go 标准库实现的 RDP（远程桌面协议）内核与网关：不依赖 CGO 和第三方协议库，从 TPKT/X.224、MCS、GCC、许可、能力协商一路实现到画面解码与输入转发，并在此基础上提供可直接使用的命令行工具和带 Web 界面的网关。

## 功能

- **RDP 网关 `rdpgw`**：RDP 客户端（mstsc、xfreerdp 等）或浏览器经网关接入内网 Windows 主机
  - 固定目标模式（`-target`）或登录表单模式（`-login-form`）：客户端先看到网关绘制的登录表单，填写目标地址和凭据后再连接
  - 目标侧支持 NLA/CredSSP（NTLMv2）、证书指纹固定（`-target-pin`）、TLS 版本下限、按主机/IP/CIDR 的目标白名单
  - 前端可要求客户端先过 NLA（`-nla-users`，含 mstsc 的 SPNEGO 包装）
  - 静态虚拟通道透传：剪贴板、驱动器重定向、声音、drdynvc（`-allow-channel` 可控）
  - 兼容 Windows 7 / Server 2008 R2：`-target-min-tls 1.0`、TLS 1.0 下 CredSSP 自动改用 RC4 套件、`-target-credssp-legacy`
- **Web 界面与浏览器 RDP 客户端**（`-monitor` + `-web-users`）
  - 浏览器直接发起 RDP 会话：动态分辨率、音频、富文本/图片剪贴板、把本地文件夹映射为目标磁盘、触控、Ctrl+Alt+Del 等快捷键
  - 实时监控在途会话画面，可接管键鼠协同操作；监控端可浏览用户映射的磁盘
  - 会话录像（`.rdpv`，含音频）与回放
  - 中英文界面，默认跟随浏览器语言
  - 目标断线自动重连（ARC cookie），浏览器断开后会话保留一段时间可恢复
- **服务端角色 `rdpserve`**：最小 RDP 服务端（策略回调授权、推送测试画面），用于联调
- **协议探针 `rdpprobe`**：分阶段探测目标（TLS / MCS / 许可 / 能力 / 激活），可导出画面和光标 PNG，支持 NLA
- **监控 API 安全**：token 换 HttpOnly Cookie、来源校验、非回环监听强制 HTTPS（自带证书或自签）

## 快速开始

```sh
# 构建（纯 Go，CGO_ENABLED=0）
go build -o bin/rdpgw ./cmd/rdpgw

# 构建 Web 界面
cd web/monitor && npm ci && npm run build && cd ../..

# 固定目标模式
./bin/rdpgw -listen 0.0.0.0:33892 -target 192.0.2.20:3389 -target-pin <sha256>

# 登录表单 + Web 界面
RDPGW_MONITOR_TOKEN=<token> ./bin/rdpgw -listen 0.0.0.0:33892 -login-form \
  -allow-target 192.0.2.0/24 -target-pin 192.0.2.20=<sha256> \
  -monitor 127.0.0.1:8090 -monitor-ui web/monitor/dist -web-users users.txt
```

然后用 mstsc / xfreerdp 连接网关地址，或打开 `http://127.0.0.1:8090` 使用浏览器客户端。完整参数说明见使用文档。

## 架构

```
RDP 客户端 / 浏览器 ──► server（前端：X.224/TLS/NLA、MCS、许可、能力协商）
                            │  可选 form 登录表单
                            ▼
                        gateway（路由策略、通道透传、监控分接、录像）
                            │
                            ▼
                        transport + nla + licensing（后端：CredSSP/NTLMv2、目标证书校验）
                            │
                            ▼
                        Windows 主机
```

目录：`wire`（协议编解码）、`transport`（客户端连接状态机）、`nla`（CredSSP/NTLM 客户端与服务端）、`licensing`（MS-RDPELE）、`bitmap`（RLE 解码、帧缓冲、指针）、`server`（服务端角色）、`form`（登录表单）、`gateway`（网关与 relay）、`monitor`（监控 HTTP/WebSocket API、录像）、`web/monitor`（React 前端）、`cmd`（rdpgw / rdpserve / rdpprobe）。

## 测试

```sh
go vet ./... && go test ./...
cd web/monitor && npx tsc -b --noEmit
```

真机互操作验证记录见验证文档。

## 文档

- [使用文档](docs/USAGE.md)：部署、全部命令行参数、Web 界面使用、安全建议、故障排查
- [开发文档](docs/DEVELOPMENT.md)：架构、包职责、构建测试、监控 API、录像格式、前端与 i18n
- [验证记录](docs/VALIDATION.md)：测试环境、执行步骤与真机实测结果
- [来源与边界](docs/SOURCES.md)：实现参考的公开规范与代码来源说明
