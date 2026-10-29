# 独立 Go RDP 内核

本目录是独立 Go module，不导入父项目的 GPL 包。它是闭源迁移的分阶段实现，不是已经完成的完整 RDP 客户端、服务端或网关。

当前里程碑：TPKT 帧、X.224 安全协议协商、严格验证服务器证书的 TLS，MCS Connect-Initial/Response（BER）与 GCC Basic Settings Exchange（PER，含对协商结果的重确认），Erect Domain / Attach User / Channel Join（用户通道 + I/O 通道），Client Info PDU（Secure Settings Exchange），MS-RDPELE 许可（New License Request / Platform Challenge Response / STATUS_VALID_CLIENT / New·Upgrade License MAC 校验），Demand Active / Confirm Active 能力交换，Synchronize / Control / Font List / Font Map 连接收尾，以及 Font Map 之后的服务端输出观察（Save Session Info 登录通知、Slow-Path Update / Pointer 分类计数、Deactivate All 重激活），Fast-Path 输出（TS_FP_UPDATE_PDU 按首字节与 TPKT 区分、分片重组、各 updateCode 分发到同一套处理），Bitmap Update 解码（Interleaved RLE 解压，8/15/16/24/32bpp 与 Palette Update 转 RGBA 帧缓冲，`rdpprobe -png` 可导出），以及指针渲染（Color/New/Large 指针的 XOR/AND 掩码转 RGBA 光标、按 Pointer Capability 容量缓存、Cached/Position/Null/Default 状态，`rdpprobe -cursor-png` 导出，位置已知时合成到 `-png`；orders 不解析）；单元/fuzz 测试和隔离 xrdp 互操作验证到 Font Map 后解码出的 xrdp 登录界面 / xfce 桌面画面与光标。只请求 TLS；不支持 TLS-only 的目标应明确失败，不回退到 Standard RDP Security 或绕过 NLA。`Probe`/`Connect` 不发送 Client Info；`Activate` 发送 Client Info，只有调用方显式给出密码时才设置 INFO_AUTOLOGON。

内核要求 `CGO_ENABLED=0` 可构建，使用 Go 标准库，不引入协议替身。UI、OCR 和视频导出属于后续独立审核范围。

- 迁移计划：`../docs/development/closed-source-go-kernel-plan.md`
- 来源和边界：`docs/SOURCES.md`
- 测试环境、执行步骤与实际结果：`docs/VALIDATION.md`

目录：`wire`（TPKT、X.224、RDP_NEG_*、BER/PER 工具、MCS Connect/域/Send Data PDU、GCC 与 Client/Server Core/Security/Network Data、Basic Security Header、Client Info、Share Control/Data、Demand/Confirm Active 与能力集、Synchronize/Control/Font List/Font Map、Save Session Info/Slow-Path Update/Pointer、Fast-Path 输出 PDU 与分片）、`bitmap`（Interleaved RLE 解压、RGBA 帧缓冲、指针 XOR/AND 掩码解码与缓存、光标合成）、`licensing`（MS-RDPELE 客户端状态机、许可密钥派生、RC4、许可 MAC、专有证书与 X.509 链中的 RSA 公钥）、`transport`（TLS-only 探测 `Probe`、到 Channel Join 的 `Connect`、到 Font Map 的 `Activate`，`Options.Observe`/`Render` 在 Font Map 后读慢路径 + fast-path 输出并渲染）、`cmd/rdpprobe`（CLI，`-stage tls|channel-join|client-info|license|capabilities|activated`，`-observe`/`-png`/`-cursor-png`，凭据只经 `-user`/`-password-env` 传入）、`testenv/xrdp` 与 `scripts/xrdp-env.sh`（隔离 xrdp 测试服务器与一次性测试账号，仅 Linux VM）。

仅在明确授权的目标上运行。不得把 TLS、Channel Join 或 Font Map 解释为用户已认证、桌面已显示或完整 RDP 会话已通过：Font Map 之后只解码 Bitmap Update 与指针（orders、Surface Commands、编解码器不处理），没有输入和虚拟通道；发送凭据时本工具只报告收到的 Save Session Info / Set Error Info，服务端不发（xrdp 0.9.24 就不发）时登录结果仍不可知。尚未实现：NLA/CredSSP、Standard RDP Security、基础位图/指针之外的图形、输入、虚拟通道。
