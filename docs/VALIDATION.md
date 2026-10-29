# 验证环境与结果（G1 协商 + TLS，G2 第一段 MCS/GCC + Channel Join，G2 第二段 Client Info → Font Map，G2 第三段 Font Map 后观察，G2 第四段位图解码，G2 第五段 Fast-Path 输出 + 指针渲染，G3-1 服务端角色 + xfreerdp 真实客户端，G3-3 网关 xfreerdp → rdpgw → xrdp，G3-4 静态虚拟通道透传 + 后端 NLA：xfreerdp → rdpgw → Windows 7 / Server 2016）

本文记录隔离 xrdp 互操作环境的搭建方式、执行命令和实际结果。结论覆盖 TPKT/X.224/RDP 安全协商、TLS 服务器认证、MCS Connect-Initial/Response 与 GCC Basic Settings Exchange（含协商结果重确认）、Erect Domain / Attach User / Channel Join（用户通道 + I/O 通道）、Client Info、MS-RDPELE 许可、Demand/Confirm Active 能力交换和 Synchronize/Control/Font List/Font Map 连接收尾。G2 第三段在 Font Map 后保持连接读取服务端输出（Slow-Path Update / Pointer / Save Session Info 分类计数）；G2 第四段把 Bitmap Update 解码（Interleaved RLE）到帧缓冲并导出 PNG，在 xrdp 上得到完整的登录界面和 xfce 桌面画面（见 5.5）；G2 第五段声明 FASTPATH_OUTPUT_SUPPORTED，读循环同时处理 TPKT 与 fast-path PDU，并把指针更新解码成 RGBA 光标（见 5.6）。G3-1 反向实现服务端角色（`server` 包 / `rdpserve`），用 Go 客户端回环 e2e 和 VM 上的真实 xfreerdp 2.6.1 + Xvfb 验证了协商、TLS、Client Info 策略、许可、能力交换、收尾和位图/光标输出（见 5.7）。orders、输入、虚拟通道未实现；带测试账号时 xrdp 侧日志记录登录成功并启动了 Xorg 会话，但 xrdp 不发 Save Session Info，协议层没有登录通知（见 5.4）。

## 1. 拓扑

```
本地 macOS（编写代码、运行单元/fuzz 测试、交叉编译 Linux 探测器）
        │  复制 go-kernel 源码包（G2 第二段起在 VM 上用 Go 直接编译，8 MB 二进制经 Devin 本机通道复制会断连）
        ▼
Linux VM（Ubuntu 22.04.5，Docker 29.7.2，Go 1.25.3 linux/amd64 仅用于编译探测器）
        │  docker run --publish 127.0.0.1:33890:3389
        ▼
容器 rdp-go-kernel-xrdp（Ubuntu 24.04 + xrdp 0.9.24，security_layer=tls）
```

xrdp 只是独立的互操作测试服务器，不链接到内核、不进入产品依赖。端口只发布到 VM loopback，不对公网开放（容器内 xrdp 仍监听 0.0.0.0:3389，同一 Docker bridge 上的其他容器可以访问，属已知范围）。

## 2. 组件与版本

| 组件 | 版本 / 标识 | 来源 |
|---|---|---|
| 本地 Go | go1.27.1 darwin/amd64 | 本地工作站 |
| VM OS / 内核 | Ubuntu 22.04.5 LTS / 6.8.0-1061-aws x86_64 | VM |
| VM Docker | 29.7.2 | VM |
| VM OpenSSL（生成测试证书） | 3.0.2 | VM |
| 容器基础镜像 | `mirror.gcr.io/library/ubuntu@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c`（ubuntu:24.04） | Docker Hub 拉取遇 429，改用 GCR 镜像 |
| xrdp / xorgxrdp | 0.9.24-4ubuntu0.1 / 1:0.9.19-1 | Ubuntu 24.04 apt |
| 容器内 openssl / tini / xfce4-session | 3.0.13-0ubuntu3.16 / 0.19.0-1 / 4.18.3-1build2 | Ubuntu 24.04 apt |

Dockerfile 用 digest 固定基础镜像，apt 包未固定版本；重新构建时以 `dpkg -l` 实际输出为准并回写本表。

## 3. 文件

| 路径 | 作用 |
|---|---|
| `testenv/xrdp/Dockerfile` | 安装 xrdp/xorgxrdp/xfce/tini，入口为 `start-xrdp` |
| `testenv/xrdp/start-xrdp.sh` | 把 `/certs` 中的测试证书装入 `/etc/xrdp`，改 `xrdp.ini`：`security_layer=tls`、`ssl_protocols=TLSv1.2, TLSv1.3`、`certificate`/`key_file` 指向测试证书、关闭 syslog、开启控制台日志；若挂载了 `/account`，用 `useradd`/`chpasswd` 创建一次性测试账号（密码不打印）；启动 `xrdp-sesman` 和 `xrdp --nodaemon` |
| `scripts/xrdp-env.sh start|stop` | 仅在 Linux 执行：生成一次性测试 CA 和 `localhost`/`127.0.0.1` 服务器证书（CA 7 天、服务器证书 2 天，位于 `.testenv/certs/`，umask 077），生成测试账号名 `rdptest`（`XRDP_TEST_USER` 可改）与 24 字节随机密码到 `.testenv/account/`，构建镜像，以 `--publish 127.0.0.1:$XRDP_PORT:3389`（默认 33890）、内存/CPU/PID 限制、只读挂载证书和账号目录、`rdp-kernel.test=true` 标签启动容器；`stop` 只删除带该标签的容器 |
| `cmd/rdpprobe` | 探测器 CLI；`-ca` 指定信任的 PEM 根证书，`-server-name` 指定 SNI/校验名，`-stage tls|channel-join|client-info|license|capabilities|activated`（默认 channel-join）控制停止阶段，`-client-name` 设置 Client Core Data 中的客户端名，`-user`/`-domain`/`-password-env` 填 Client Info（密码只从环境变量读取，不出现在命令行、报告或日志；给出密码才设置 INFO_AUTOLOGON），`-observe <时长>`（仅配合 `-stage activated`，否则拒绝）在 Font Map 后继续读取服务端输出并计数（Update 类型、位图矩形/压缩/字节、orders 数、指针类型、Save Session Info、Set Error Info、Deactivate All 重激活次数）并把 Bitmap Update 解码到 `-stage` 所用桌面尺寸（1024x768）的帧缓冲（报告 `framebuffer:` 行 / JSON `observation.frame`：矩形数、RLE 数、裁剪数、写入像素、覆盖率、色深、脏区、解码错误、像素 SHA-256），`-png <文件>`（需 `-observe`）把帧缓冲写成 PNG（指针位置已知且可见时合成光标），`-cursor-png <文件>` 写当前光标形状；报告另有 `fast-path:` 行（fast-path PDU 数、各 updateCode 计数、分片重组数）和 `pointer:` 行（解码光标数、缓存命中/缺失、可见性、位置、当前光标尺寸/热点/色深/SHA-256、错误），JSON 为 `observation.fastpath_pdus/fastpath_updates/fragments/pointer`；`-timeout` 自动加上观察时长，`-json` 输出报告 |
| `server` 包 / `cmd/rdpserve` | G3-1 服务端角色与验证 CLI：`rdpserve -listen 127.0.0.1:33891 -user demo -password-env RDP_DEMO_PASSWORD [-cert/-key] [-once] [-json]`；不给证书时生成临时自签名证书（仅测试）；`-json` 每个会话结束输出一行（remote/user/domain/client/stage/authorized/duration_ms/error，无密码）|
| `bitmap` 包 | Interleaved RLE 解压、RGBA 帧缓冲、指针 XOR/AND 掩码解码与缓存、光标合成（单测 + fuzz），只依赖标准库与 `wire` |
| `transport.Session` / `server.Handler`+`server.Conn` | G3-3 基础：`transport.Dial` 走完 TLS → MCS → Client Info → 许可后保留连接，`ReadPDU`（慢路径 I/O 通道 payload 或整帧 fast-path）/`WriteIO`/`WriteFastPath`/`Disconnect`；`server.Config.Handler` 在许可完成后把连接交给调用方（`Conn.Peer/Credentials/ReadPDU/WriteIO/WriteFastPath/Deny/Disconnect`），`Credentials` 只在 Handler 返回前有效，返回后清零；不设 Handler 时保持 G3-1 演示服务端行为 |
| `gateway` 包 / `cmd/rdpgw` | G3-3 网关：`Route(ctx, Peer) (Target, error)` 策略选目标（拒绝 → Set Error Info DENIED + DPU），凭据只向目标透传一次（Client Info，不进日志/Summary），Demand Active / Confirm Active 按 `AllowCapability` 白名单过滤（默认丢 Surface Commands、Bitmap Codecs、Frame Ack、RAIL/Window/NineGrid/GDI+/CompDesk），其余 Share Control PDU 改写 pduSource 为目标分配的用户通道，fast-path 两向整帧转发，慢路径/fast-path 输入解码计数（只计类别，不记扫描码/坐标），任一侧结束就给另一侧发 DPU 并清理；`rdpgw -listen … -cert/-key -target host:port -target-ca ca.pem -target-name name [-allow-user u]... [-allow-domain d]... [-target-timeout] [-handshake-timeout] [-max-sessions] [-once] [-json]`，`-json` 每会话输出 session 行和 relay 行（PDU/fast-path 计数、字节、输入类别计数、丢弃的能力类型、重激活次数、结束方 client-closed/target-closed/canceled/error） |

`.testenv/`（证书、测试账号）与 `.build/` 已在 `.gitignore` 中，不入库。

## 4. 执行步骤

### 4.1 本地（macOS）

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

把 `.build/go-kernel-src.tar.gz` 复制到 VM 的 `~/rdp-kernel-validation/`（探测器在 VM 上编译，见 4.2；8 MB 二进制经本机通道复制会断连）。

### 4.2 VM（Linux）

```sh
cd ~/rdp-kernel-validation
tar -xzf go-kernel-src.tar.gz
(cd go-kernel && CGO_ENABLED=0 go build -trimpath -o ../rdpprobe-linux-amd64 ./cmd/rdpprobe)   # VM 上 Go 1.25.3
cd go-kernel && sh scripts/xrdp-env.sh start        # 首次构建约 1–2 分钟
docker ps --filter name=rdp-go-kernel-xrdp           # 应显示 127.0.0.1:33890->3389/tcp
cd ..
CA=go-kernel/.testenv/certs/ca.pem
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA"              # 默认跑到 channel-join
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -json
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage tls   # 只到 TLS
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage activated   # Client Info → Font Map，不带凭据
RDP_TEST_PASSWORD=$(head -n1 go-kernel/.testenv/account/password) ./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 \
    -server-name localhost -ca "$CA" -stage activated -user "$(head -n1 go-kernel/.testenv/account/user)" -password-env RDP_TEST_PASSWORD
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage activated -observe 8s   # Font Map 后读 8 s 服务端输出
RDP_TEST_PASSWORD=$(head -n1 go-kernel/.testenv/account/password) ./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 \
    -server-name localhost -ca "$CA" -stage activated -observe 15s -user "$(head -n1 go-kernel/.testenv/account/user)" -password-env RDP_TEST_PASSWORD
docker exec rdp-go-kernel-xrdp tail -n 30 /var/log/xrdp-sesman.log   # 登录结果只在服务端日志里
# G3-3 网关：前端用同一套测试证书（xfreerdp 校验名 localhost），后端信任测试 CA
(cd go-kernel && CGO_ENABLED=0 go build -o ../rdpgw ./cmd/rdpgw)
C=go-kernel/.testenv/certs
./rdpgw -listen 127.0.0.1:33892 -cert $C/server.pem -key $C/server-key.pem -target 127.0.0.1:33890 -target-ca $C/ca.pem -target-name localhost -allow-user rdptest -json &
export DISPLAY=:99; export RDP_PW=$(head -n1 go-kernel/.testenv/account/password)   # 必须 export，sh -c 内才能展开
sh -c 'xfreerdp /v:127.0.0.1:33892 /u:rdptest /p:"$RDP_PW" /cert:ignore /sec:tls /size:1024x768 /bpp:24 -clipboard /log-level:INFO' &
sleep 8; import -window root gw-desktop.png; xdotool mousemove 50 12 click 1   # 经网关点开 xfce 菜单
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost -ca "$CA" -stage activated -observe 8s -png login.png   # 解码位图并导出画面（xrdp 登录界面）
RDP_TEST_PASSWORD=$(head -n1 go-kernel/.testenv/account/password) ./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 \
    -server-name localhost -ca "$CA" -stage activated -observe 15s -user "$(head -n1 go-kernel/.testenv/account/user)" -password-env RDP_TEST_PASSWORD -png desktop.png -cursor-png cursor.png   # xfce 桌面 + 当前光标
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name localhost                 # 预期失败：系统根不信任测试 CA
./rdpprobe-linux-amd64 -addr 127.0.0.1:33890 -server-name wrong.example.test -ca "$CA"  # 预期失败：主机名不匹配
```

日志：`docker logs rdp-go-kernel-xrdp`，或容器内 `/var/log/xrdp.log`、`/var/log/xrdp-sesman.log`。

清理：`cd go-kernel && sh scripts/xrdp-env.sh stop`；如需删除镜像和证书：`docker rmi rdp-go-kernel-xrdp:test && rm -rf .testenv`。

## 5. 实际结果

### 5.1 G1（2026-10-29，协商 + TLS）

本地：`gofmt`/`go vet` 通过；`wire`、`transport` 单元测试通过（TPKT 边界/截断/短写、X.224 微软样例向量、畸形 CC、协商失败、非 TLS 选择拒绝、未知 CA 拒绝、主机名不匹配拒绝、超时）；`FuzzReadTPKT` 约 203 万次、`FuzzDecodeConnectionConfirm` 约 180 万次执行无崩溃；linux/amd64 交叉编译产物 SHA-256 `e8134b77f0e76f738350145df07390bda1c88b014d1ec6563ac441abe6822f9b`。

| 用例 | 结果 |
|---|---|
| 信任测试 CA，`-server-name localhost` | `negotiation: ok (PROTOCOL_SSL, flags=0x01)`；`tls: ok (TLS1.3, TLS_AES_128_GCM_SHA256, peer=CN=localhost)`；退出码 0 |
| 不带 `-server-name`（按 IP SAN 127.0.0.1 校验） | 同上，通过 |
| 系统根证书 | 协商 ok；TLS 失败 `x509: certificate signed by unknown authority`；退出码 1 |
| `-server-name wrong.example.test` | 协商 ok；TLS 失败 `certificate is valid for localhost, not wrong.example.test`；退出码 1 |
| 关闭端口 33891 | `dial ... connection refused`；退出码 1 |

xrdp 侧日志：`Security protocol: configured [SSL], requested [SSL|RDP], selected [SSL]`（xrdp 把 requestedProtocols=0x01 显示为 SSL|RDP，PROTOCOL_RDP=0 为隐含项）。校验失败用例中 xrdp 记录 `sslv3 alert bad certificate`，即客户端主动中止。`flags=0x01` 为 `EXTENDED_CLIENT_DATA_SUPPORTED`，只记录，当前未使用。

### 5.2 G2 第一段（2026-10-29，MCS/GCC + Channel Join）

本地：`gofmt`/`go vet` 通过；新增测试全部通过——`EncodeConnectInitial` 逐字节复现 MS-RDPBCGR 4.1.3 的 416 字节样例，`DecodeConnectResponse`/GCC/SC_CORE/SC_NET/SC_SEC1 解析 4.1.4 样例，Attach User Confirm 与 Channel Join Confirm 使用 4.1.7/4.1.8 样例；畸形 BER/PER/用户数据块、MCS 非成功结果、DisconnectProviderUltimatum 均有拒绝用例；`transport` 用内置假服务器覆盖 SC_CORE 回显协议不一致、服务端要求 Standard RDP Security 加密、服务端分配未请求的静态通道、缺少 SC_SECURITY/SC_NET、Attach User 失败、Join Confirm 通道号不一致。`FuzzDecodeConnectResponse` 8 s、`FuzzDomainPDUs` 5 s 无崩溃。linux/amd64 交叉编译产物 SHA-256 `33947427a3497d27cefbf770b4a489247c164bdcbc73f637f70b61600985a2ef`。

| 用例 | 结果 |
|---|---|
| 默认 `-stage channel-join`，信任测试 CA | `mcs connect: ok (server version 0x00080004, protocol reconfirmed=true, encryption method/level=0/0, io channel=1003)`；`channel connection: ok (user channel 1004, joined [1004 1003])`；`reached stage: channel-join`；退出码 0，耗时 6 ms |
| `-stage tls` | 协商与 TLS ok，MCS/通道阶段显示 `skipped` |
| 系统根证书 | TLS 失败，MCS/通道 `not attempted`，`reached stage: negotiation`，退出码 1 |

xrdp 侧日志：`Connected client computer name: rdpkernel`、`xrdp_load_keyboard_layout: ... keyboard_type:[0x04] ... keylayout:[0x00000409]`、`TLS connection established ... TLSv1.3 with cipher TLS_AES_128_GCM_SHA256`，说明 Connect-Initial 中的 Client Core Data 被 xrdp 正常解析；随后探测器在 Channel Join 完成后主动关闭，xrdp 记录 `libxrdp_force_read: header read error` 并发送 DisconnectProviderUltimatum，这是预期现象：下一步 Client Info PDU 未实现。

协商结果重确认：xrdp 在 SC_CORE 的 `clientRequestedProtocols` 回显 `PROTOCOL_SSL`，与客户端请求一致；SC_SECURITY 为 `ENCRYPTION_METHOD_NONE`/`ENCRYPTION_LEVEL_NONE`，与 Enhanced RDP Security 一致。任何不一致都会在 MCS 阶段直接断开（见 `transport` 测试）。

### 5.3 G2 第二段（2026-10-29，Client Info → 许可 → 能力交换 → Font Map）

本地：`gofmt`/`go vet` 通过；`licensing`、`transport`、`wire` 全部测试通过。`licensing` 用 MS-RDPELE 4.1/4.4/4.5 公开样例（Server License Request 含 X.509 链及 8+4n 字节尾部填充、Platform Challenge、Platform Challenge Response）和一个持有自己 RSA 密钥的假服务器（解密 premaster、派生同一组密钥、下发 Platform Challenge 与 New License 并校验每个 MAC）验证；`transport` 用内置假服务器从 TLS 一路跑到 Font Map（MS-RDPBCGR 4.1.12 Demand Active 样例），并覆盖无凭据时不发密码/不设 INFO_AUTOLOGON、给出凭据时正确编码、许可 ERR_INVALID_CLIENT、Set Error Info、Deactivate All、非法停止阶段。新增 fuzz 目标 `FuzzDecodeSendDataIndication`、`FuzzDecodeDemandActive`、`FuzzDecodeDataPDU`（wire）与 `FuzzHandle`（licensing）各 5 s 无崩溃，旧目标 5 s 复跑无崩溃。VM 上编译的探测器 SHA-256 `23ba3a43dfb7936810313dd1e5cee714f17c0e64202820ad687ca0d50f2133c7`（修复前的版本；两处 xrdp 兼容修复见下，最终代码以本机工作区为准）。

| 用例 | 结果 |
|---|---|
| `-stage activated`，不带凭据 | `client info: ok (autologon=false)`；`license: ok (valid-client, product "236")`；`capabilities: ok (share 0x000103ea, server channel 1004, source "RDP", 13 server capability sets)`；`activation: ok (received synchronize control-cooperate control-granted font-map)`；`reached stage: activated`；退出码 0 |
| `-stage activated`，`-user rdptest -password-env RDP_TEST_PASSWORD` | 同上，`client info: ok (autologon=true)`；报告 `not verified` 中标明“logon outcome ... not observed” |
| `-stage capabilities` / `-stage license` | 到对应阶段 ok，后续阶段 `skipped` |

互操作中发现并修复的两处 xrdp 兼容问题（均补了回归测试）：

1. xrdp 内置专有证书声明 512 位 RSA，但模数实际只有 511 位；原实现按 `modulus.BitLen() < 512` 判为退化密钥。现只在模数比声明位长短 8 位以上或指数 < 3 时拒绝（keylen/bitlen 本身仍按规范校验）。
2. xrdp 对 New License Request 固定回复 STATUS_VALID_CLIENT 的 Licensing Error Message，其零长度 blob 的 `wBlobType` 为 0x1428；按 MS-RDPBCGR 2.2.1.12.1.3，`wBlobLen` 为 0 时忽略 `wBlobType`。原实现强制 BB_ERROR_BLOB，现只对非空 blob 校验类型。

xrdp 侧日志：`xrdp_caps_process_pointer: client supports new(color) cursor`、`xrdp_process_offscreen_bmpcache: support level 0 ...` 说明 Confirm Active 的能力集被 xrdp 解析；探测器收到 Font Map 后主动关闭，xrdp 随后记录大量 `xrdp_rdp_send_data: xrdp_sec_send failed`（它在尝试发送登录界面位图）并发送 DisconnectProviderUltimatum，属预期。xrdp 的许可路径不经过 Platform Challenge / New License，这两条分支只在本地假服务器和公开样例上验证。带凭据的用例里，xrdp 在 Font Map 之后才通过 sesman 发起登录，探测器此时已经断开，因此日志中没有登录成功/失败记录——不能把 `autologon=true` 解释为账号已认证。

### 5.4 G2 第三段（2026-10-29，Font Map 后观察：Update / Pointer / Save Session Info）

本地：`gofmt`/`go vet` 通过；`wire` 新增 Save Session Info（TS_LOGON_INFO / VERSION_2 / PLAIN_NOTIFY / EXTENDED 含 logon errors）、Slow-Path Update（Bitmap 矩形与压缩标志、Orders 计数、Palette、Synchronize）、Pointer、Fast-Path 输出头的解码测试；`transport` 新增 `observe` 读循环测试（混合 bitmap / pointer / save session info / 未知 pduType2、服务端静默时按窗口超时、Deactivate All → 重激活）。VM 上用 Go 1.25.3 编译的探测器 SHA-256 `1bfa9c58706a8c35e6d7cc190e0e126dae7353d686f8be0493a21e15195579aa`（本段代码，JSON 字段改 snake_case 与 `-observe` 参数校验在此之后加入，最终代码以本机工作区为准）。

| 用例 | 结果 |
|---|---|
| `-stage activated -observe 8s`，不带凭据 | 到 `activated` 同 5.3；`observed: 45 PDUs in 8.04s, end=timeout, updates=map[bitmap:42 synchronize:1] (bitmap rects 190, 190 compressed, 74298 bytes; 0 orders), pointers=map[new:2], other=map[], reactivations=0`；没有 logon notification；退出码 0 |
| `-stage activated -observe 15s`，`-user rdptest -password-env RDP_TEST_PASSWORD` | `client info: ok (autologon=true)`；`observed: 23 PDUs in 15.053s, end=timeout, updates=map[bitmap:17 synchronize:1] (bitmap rects 666, 666 compressed, 32304 bytes; 0 orders), pointers=map[cached:2 new:3], other=map[], reactivations=0`；没有 logon notification，没有 Set Error Info；退出码 0 |
| `-stage activated -observe 3s -json` | 报告含 `observation` 对象（计数同上，`logon` 为空时省略） |
| `-stage capabilities -observe 2s` | 探测器在连接前拒绝：`-observe requires -stage activated` |

xrdp 侧日志（带凭据）：`xrdp.log` 记录 `sending login info to session manager`、`login successful for user rdptest on display 10`、`lib_mod_connect: connecting via UNIX socket` / `connected ok`；`xrdp-sesman.log` 记录 `++ created session (access granted): username rdptest`、`Starting session: ... display :10.0, width 1024, height 768, bpp 24`、`Session started successfully for user rdptest on display 10`（另有一条 `sesman_data_in: scp_process_msg failed`，会话仍正常启动，未深究）。即 INFO_AUTOLOGON 中的凭据被 xrdp 用于 PAM 认证并启动了 Xorg/xfce 会话；但 xrdp 0.9.24 全程没有发送 Save Session Info PDU，协议层没有登录通知，登录成功只能从服务端日志确认——探测器报告里仍把 logon outcome 列为 not verified。不带凭据时 xrdp 不连 sesman，收到的位图是其内置登录界面；带凭据时位图矩形更多（666 个小矩形，xfce 桌面增量刷新）。两种情况都没有 Deactivate All、Set Error Info、orders/palette 更新；所有位图矩形都带压缩标志（xrdp 的 Interleaved RLE），本轮只计数不解码；没有 fast-path 输出（Confirm Active 未声明）。探测器到时主动关闭后，xrdp 记录 `xrdp_iso_send: trans_write_copy_s failed` / `Sending [ITU T.125] DisconnectProviderUltimatum failed`，属预期。

### 5.5 G2 第四段（2026-10-29，Bitmap Update 解码：Interleaved RLE → 帧缓冲 → PNG）

本地：`gofmt`/`go vet` 通过；新增 `bitmap` 包（`Decompress` 覆盖全部 RLE 订单、扩展长度、首行/非首行 XOR、BG_RUN 插入前景像素、8/15/16/24/32bpp、截断/溢出/欠填/未知订单拒绝；`Framebuffer.Draw` 覆盖自底向上翻转、裁剪到目标矩形与屏幕、Palette 前后的 8bpp、RGB555/565/BGR24/BGRX32 转换、被拒矩形不改画面），`FuzzDecompress` 20 s 无崩溃；`transport` 的 observe 测试加 `Options.Render` 检查 `Observation.Frame`。VM 上用 Go 1.25.3 编译的探测器 SHA-256 `d8c89cc5e175275cc021b64d64861ec62ceb9640e52e832e7f17a1309db46141`。

| 用例 | 结果 |
|---|---|
| `-stage activated -observe 8s -png login.png`，不带凭据 | `observed: 45 PDUs ... bitmap rects 190, 190 compressed`；`framebuffer: 1024x768, 190 rects (190 rle, 112 clipped), 850977 pixels written, 786432/786432 covered (100.0%), depths=map[24:190], dirty (0,0)-(1024,768), 0 decode errors`；PNG 是完整的 xrdp 内置登录窗口（蓝绿色背景、xrdp logo、Session/username/password/OK/Cancel），文字和图标清晰、无错位、无色偏；退出码 0 |
| `-stage activated -observe 15s -user rdptest -password-env RDP_TEST_PASSWORD -png desktop.png` | `bitmap rects 669, 669 compressed`；`framebuffer: 669 rects (669 rle, 9 clipped), 3357513 pixels written, 786432/786432 covered (100.0%), depths=map[24:669], 0 decode errors`；PNG 是 xfce 桌面：顶部面板（Applications、时钟、用户名 rdptest）、底部 dock 图标；桌面背景为纯黑，因为 Client Info 的 performanceFlags 带 PERF_DISABLE_WALLPAPER，属预期；退出码 0 |
| `-stage activated -observe 3s -json` | `observation.frame` 对象字段 `width/height/rects/decompressed/clipped/pixels/covered/depths/dirty/sha256`，同一登录界面的像素 SHA-256 与 8 s 用例一致（`7a92b17a...`），即全幏重绘是确定的 |
| `-stage activated -png x.png`（无 `-observe`） | 连接前拒绝：`-png requires -observe` |

说明：xrdp 的位图全部是 24bpp Interleaved RLE，矩形宽度按 4 像素对齐、常大于 destRight-destLeft+1，所以裁剪计数（112 / 9）正常；解码结果以肉眼比对 PNG 为准，没有与其他客户端做逐像素比对；覆盖率 100% 说明 xrdp 在连接后重绘了整幅桌面。两次运行都没有 Palette Update，8bpp 路径只经单测。

### 5.6 G2 第五段（2026-10-29，Fast-Path 输出 + 指针渲染）

本地：`gofmt`/`go vet` 通过；`wire` 新增 fast-path 框架解码测试（短/长长度、多更新、分片与压缩标志、ReadFastPathPDU 只消费一个 PDU、加密标志/长度/截断拒绝、fast-path 指针转换、numberOrders）与 `FuzzDecodeFastPathPDU` 10 s；`bitmap` 新增光标解码测试（24bpp XOR/AND 组合：透明、反色近似黑、不透明；1bpp、8bpp 调色板、16bpp、32bpp 带/不带 alpha；尺寸/掩码长度拒绝）、指针状态机（New → 缓存 → Null 隐藏 → Cached 命中/缺失/越界 → Default → 未知类型）与合成；`transport` 新增 `TestActivateObserveFastPath`：假服务器在慢路径 Update 之后原样写入 5 个 fast-path PDU（bitmap + synchronize + position 合并一包、Color 指针拆成 FIRST/NEXT/LAST 三片、orders、cached、surfcmds），校验 Confirm Active 的 extraFlags 含 FASTPATH_OUTPUT_SUPPORTED、两条路径的计数合并、分片重组、光标按热点合成到帧缓冲。VM 上编译的探测器 SHA-256 `72a2caf2191d5d79c88966186956cc07055851381d8b0a01a7d21d0700b6136b`。

| 用例 | 结果 |
|---|---|
| `-stage activated -observe 8s -png login-fp.png -cursor-png cursor-login.png`，不带凭据 | `observed: 45 PDUs ... pointers=map[new:2]`；`fast-path: 3 of 45 PDUs, updates=map[ptr-new:2 synchronize:1], 0 reassembled`；`pointer: 2 cursors decoded, cache hits 0, misses 0, visible=true, position unknown, current 32x32 hotspot (0,0) xorBpp 24 cache 0, 0 errors`；`framebuffer: ... 0 decode errors`，PNG 仍是完整登录界面；光标 PNG 是标准黑色箭头白边；退出码 0 |
| `-stage activated -observe 15s -user rdptest -password-env RDP_TEST_PASSWORD -png desktop-fp.png -cursor-png cursor-desktop.png` | `pointers=map[cached:2 new:3]`；`fast-path: 6 of 24 PDUs, updates=map[ptr-cached:2 ptr-new:3 synchronize:1]`；`pointer: 3 cursors decoded, cache hits 2, misses 0, visible=true, position unknown, current 32x32 hotspot (3,1) xorBpp 32 cache 2, 0 errors`；光标 PNG 是 xfce 主题的黑色箭头（32bpp 带 alpha，边缘有抗锯齿半透明）；帧缓冲同 5.5；退出码 0 |
| `-stage activated -observe 3s -json` | `observation` 新增 `fastpath_pdus`、`fastpath_updates`、`fragments`、`pointer`（含 `current` 的尺寸/热点/色深/缓存位/SHA-256） |
| `-stage activated -cursor-png x.png`（无 `-observe`） | 连接前拒绝：`-png/-cursor-png require -observe` |

说明：声明 FASTPATH_OUTPUT_SUPPORTED 后，xrdp 0.9.24 把 Synchronize 与全部指针更新改走 fast-path，位图更新仍走慢路径 Share Data（所以 `fast-path:` 只占 3/45、6/24）；没有分片（更新都很小）、没有压缩标志、没有 Surface Commands；xrdp 全程不发 Pointer Position，光标位置未知，`-png` 不合成光标，光标只经 `-cursor-png` 单独导出。两张光标图以肉眼核对（形状、热点、透明边）为准。

### 5.7 G3-1（2026-10-29，服务端角色：Go 客户端回环 + xfreerdp 真实客户端）

本地/VM：`gofmt`/`go vet` 通过；`wire` 新增 `server_test.go`（Connection Request 解码含 cookie / 无 RDP_NEG_REQ / 畸形拒绝，Connection Confirm 与 NEG_FAILURE 编码往返，MS-RDPBCGR 4.1.3 Connect-Initial 解码到 CS_CORE/CS_SECURITY/CS_NET 字段，4.1.4 Connect-Response 解码后重编码逐字节一致，自编 SC_* → ConferenceCreateResponse → Connect-Response 往返，Erect Domain / Attach User / Channel Join 请求解码与 Confirm/失败/DPU 编码，Client Info Unicode 带扩展段与 ANSI 最小包往返、许可头拒绝、截断拒绝，Demand Active 自编往返与 4.1.12 样例重编码一致，Deactivate All / Font Map / Set Error Info / Font List，Bitmap Update 与 5 类 Pointer 编码经既有解码器往返）；`licensing` 新增 `EncodeValidClientAlert` 经客户端状态机得到 `valid-client`；`server` 新增 `TestLoopbackActivationAndGraphics`（`transport.Activate` + `Observe/Render` 连到 `server.Serve`：PROTOCOL_SSL、ENCRYPTION_NONE、SC_CORE 重确认、valid-client、4 个收尾 PDU、`Peer` 字段、Bitmap Update 与 1 个 Color 指针、渲染帧缓冲 5 个采样点与服务端 `TestPattern` 逐像素一致、日志中不含密码、取消上下文后 `Serve` 返回且 `Summary.Authorized`）、`TestPolicyDenied`（客户端拿到 `ERRINFO_SERVER_DENIED_CONNECTION`，服务端 `Summary.Err` 为 `ErrDenied`）、`TestRefusesNonTLSClient`（仅 PROTOCOL_RDP → RDP_NEG_FAILURE SSL_REQUIRED_BY_SERVER）、`TestHandshakeTimeoutAndGarbage`（HTTP 请求 → `ErrProtocol`，无回包）、`TestNewRejectsBadConfig`；`go test -race ./server ./transport` 通过。`transport` 顺带修正：Demand Active 位置收到 Share Data（Set Error Info）时报告 ERRINFO 而不是 pduType 不符。

VM 真实客户端：Ubuntu 22.04 `apt install freerdp2-x11`（xfreerdp 2.6.1）+ `Xvfb :99 -screen 0 1024x768x24`，`rdpserve -listen 127.0.0.1:33891 -user demo -password-env RDP_DEMO_PASSWORD -json`（临时自签名证书）。

| 用例 | 结果 |
|---|---|
| `xfreerdp /v:127.0.0.1:33891 /u:demo /p:… /cert:ignore /size:640x480 /sec:tls /bpp:32` | 服务端日志 `x224 ok → tls ok → mcs-connect ok → mcs-join ok → client-info ok → license ok → capabilities ok → finalize ok → output ok`；xfreerdp 窗口 640x480，`import -window root` 截图采样 (5,5)=白、(100,50)=黄、(200,50)=青、(320,400)=灰 (200,200,200)、(636,476)=(32,32,96) 与 `TestPattern` 一致（服务端按客户端首选 32bpp 转换推送）；无 xfreerdp 错误；Ctrl-C 后服务端 `{"authorized":true,"client":"devin-box","stage":"output","user":"demo",...}` |
| 同上 `/size:400x300 /bpp:16`，不带 `/sec:`（客户端默认请求 NLA\|TLS） | 服务端选 PROTOCOL_SSL，xfreerdp 接受；16bpp 推送截图采样白/黄/青/绿/(32,32,96)/黑与图案一致 |
| `/p:wrong`（策略拒绝） | 服务端 `policy denied user "demo" … : bad password`，`stage":"mcs-join","authorized":false`；xfreerdp 日志 `ERRINFO_SERVER_DENIED_CONNECTION (0x00000007):The server denied the connection.`，退出 |
| `/sec:rdp`（仅 Standard RDP Security） | 服务端 `negotiation failed: client offered protocols 0x00000000 without PROTOCOL_SSL`；xfreerdp `Error: SSL_REQUIRED_BY_SERVER` / `Protocol Security Negotiation Failure` |

说明：xfreerdp 2.6.1 在 CS_NET 请求 cliprdr/rdpdr/rdpsnd/drdynvc 等静态通道，服务端按请求顺序分配 1004 起的通道号并接受加入，通道数据被丢弃；客户端激活后发送的 fast-path 输入（鼠标移动）被按长度丢弃，未解析。截图中光标由 Xvfb/xfreerdp 合成，截图工具不含光标，彩色指针只能确认 xfreerdp 无错误接收（Go 客户端回环中已逐字段往返）。mstsc / Windows 客户端未测。

### 5.8 G3-3（2026-10-29，网关：xfreerdp → rdpgw → xrdp）

本地/VM：`gofmt`/`go vet`/`golangci-lint`/`CGO_ENABLED=0 go test ./...` 通过，`go test -race -count=3 ./gateway ./server ./transport` 通过。`gateway` 单测：`TestRelayEndToEnd`（Go 客户端 `transport.Activate` → gateway → `server.Serve` 演示服务端：目标收到透传的用户名/密码、客户端激活并收到图案、Summary 为 client-closed）、`TestRouteDenied`（`ERRINFO_SERVER_DENIED_CONNECTION`）、`TestTargetUnreachable`、`TestTargetRejectsPassedThroughCredentials`（目标策略拒绝 → 客户端 DENIED，`ErrBackend`）、`TestCapabilityFilter`；`wire` 新增 `input_test.go`（慢路径/fast-path 输入解码）。修过一个 relay 结束分类竞态：首个结束方确定后才取消上下文并关闭另一侧，否则 `AfterFunc` 关闭会把 client-closed 记成 target-closed。

VM 真实链路：Ubuntu 22.04 + Xvfb :99，xfreerdp 2.6.1 → `rdpgw 127.0.0.1:33892`（前端用 `.testenv/certs/server.pem`，后端 `-target-ca ca.pem -target-name localhost`）→ Docker xrdp 0.9.24 `127.0.0.1:33890`，xdotool 3.20211022.1 注入输入。

| 用例 | 结果 |
|---|---|
| `xfreerdp /v:127.0.0.1:33892 /u:rdptest /p:… /cert:ignore /sec:tls /size:1024x768 /bpp:24` | 网关 `x224 ok → … → license ok → target 127.0.0.1:33890 licensed (user channel 1004), relaying`；xrdp 日志 `Connected client computer name: devin-box`、`login successful for user rdptest on display 10`、`connected ok`（sesman `++ reconnected session`/`created session`）；6 s 后截图为完整 xfce 桌面（顶栏 Applications/时钟/`rdptest`、底部 dock），非 xrdp 登录窗 |
| 同上，`xdotool` 点 Applications 菜单 → Esc → 点 dock 终端 → 键入 `echo gateway-ok` 回车 | 截图 1：xfce 应用菜单展开；截图 2：uxterm 中显示 `$ echo gateway-ok` / `gateway-ok`。relay 行：`client 5 pdus + 44 fast-path, target 72 pdus + 5 fast-path, input map[mouse:8 scancode:38 sync:2], dropped caps map[6:1 28:1 29:1 30:1], reactivations 0`，server_bytes 268076；输入全部是 fast-path 整帧转发，统计只有类别计数 |
| `/u:nobody`（策略只允许 rdptest） | 网关 `route denied user "nobody" client "devin-box": user not allowed`，session 行 `"authorized":false,"stage":"license"`，未拨号目标；xfreerdp `ERRINFO_SERVER_DENIED_CONNECTION (0x00000007)` 退出 |
| `-target 127.0.0.1:33999`（目标不可达） | 网关 `target 127.0.0.1:33999 failed at handshake: dial: … connection refused`，session 行 `"authorized":true,"stage":"license","error":"rdp gateway: target connection failed…"`；xfreerdp 收到 `ERRINFO_SERVER_DENIED_CONNECTION` 退出 |
| 客户端 `kill -9 xfreerdp` / Ctrl-C | relay `ended (client-closed)`（客户端读到 EOF），网关向 xrdp 发 DPU，xrdp 日志 `xrdp_mcs_recv failed` 后结束该连接；session 行 `"stage":"handler","authorized":true` |
| 杀掉容器内 `xrdp --nodaemon`（目标断开） | relay `ended (target-closed)`，网关向客户端发 DPU（provider initiated），xfreerdp `ERRINFO_RPC_INITIATED_DISCONNECT (0x00000001)` 退出 |
| `rdpprobe -stage activated -observe` 经网关 | `reached stage: activated`，framebuffer 1024x768 155 rects 100% covered，fast-path `ptr-new:2 synchronize:1`，与直连 xrdp 一致 |

说明：xrdp 对网关发的 Demand Active 丢了类型 6（xrdp 自定义 / 未在 MS-RDPBCGR 中定义）、28 Surface Commands、29 Bitmap Codecs、30 Frame Acknowledge，xfreerdp 因而只用 orders + 位图更新，桌面仍完整；xrdp 全程无 Deactivate All（重激活路径只有单测）。排错记录：一次“登录窗 + 黑屏”是测试脚本问题——`sh -c '…$RDP_PW…'` 未 `export` 导致密码为空，xrdp 按规则关掉 autologin 显示登录窗（`xrdp_sec.c`：cbPassword==0 → rdp_autologin=0），黑屏则是 xfreerdp 已退出后 Xvfb 的裸根窗口；`docker start` 已停止的 xrdp 容器会因残留 `xrdp-sesman.pid` 启动失败，`start-xrdp.sh` 现在先删除陈旧 pid 文件。

### 5.9 G3-4（2026-10-29，静态虚拟通道透传 + 后端 NLA：本机 xfreerdp → rdpgw → Windows 7 / Windows Server 2016）

本地 macOS：`gofmt`/`go vet`/`golangci-lint`/`CGO_ENABLED=0 go test ./...` 通过。新增单测：`gateway.TestChannelRelay`（客户端请求 rdpdr+cliprdr，策略只放行 cliprdr：目标只看到 cliprdr，cliprdr 块经网关回显原样、rdpdr 块被丢弃并计数）；`transport` 的 `TestMD4Vectors`（RFC 1320 四组向量）、`TestNTOWFv2Vector`（MS-NLMP 4.2.4.1.1）、`TestCredSSPExchange`（进程内假 CredSSP 服务端校验 NTLMv2 proof、MIC、MsvAvChannelBindings/SPN、客户端公钥绑定，回送服务端绑定后解密 TSPasswordCreds 得到 domain/user/password）、`TestCredSSPRejectsWrongServerBinding`（服务端公钥绑定不符 → 客户端拒绝）、`TestReadTSRequestErrorCode`（errorCode NTSTATUS 透出）。

真实链路：macOS + XQuartz，xfreerdp 3.31.1（`/sec:tls /cert:ignore /size:1280x800 +clipboard /drive:gwshare,/tmp/rdpdrive`）→ 本机 `rdpgw`（临时自签前端证书）→ 局域网 Windows 主机。目标证书均为自签名，用 `rdpprobe -pin 00` 先读出叶证书 SHA-256 再以 `-target-pin` 固定。

| 用例 | 结果 |
|---|---|
| `rdpprobe -addr 192.0.2.10:3389 -stage tls` | Windows 7 SP1 只提供 TLS 1.0：默认 MinVersion 1.2 握手失败，`-min-tls 1.0` 后 `tls ok`（TLS1.0, RSA-AES128-SHA） |
| `rdpprobe -addr 192.0.2.20:3389 -stage tls` | Server 2016 回 `RDP_NEG_FAILURE HYBRID_REQUIRED_BY_SERVER`；`-nla` 后 `negotiation ok (PROTOCOL_HYBRID, flags=0x1f)` |
| `rdpprobe -addr 192.0.2.20:3389 -nla -pin … -stage activated -user administrator -password-env … -observe 6s` | `nla: true, credssp_version: 6`，TLS1.2 ECDHE-RSA-AES256-GCM，MCS → Client Info → `license valid-client` → 17 个服务端能力集 → Font Map；观察 6 s 收到 87 个 fast-path Bitmap Update（1108 矩形）、指针更新，以及 Save Session Info `logon info_type 1, session 2, domain WIN-EXAMPLEPC1, user Administrator`——NLA 凭据被接受并登录 |
| `rdpgw -listen 127.0.0.1:33892 -target 192.0.2.10:3389 -target-min-tls 1.0 -target-pin … -allow-user win7`；xfreerdp `/u:win7` | 网关 `target … licensed (user channel 1008, channels [rdpdr rdpsnd cliprdr drdynvc]), relaying`：4 个静态通道在目标侧同名分配并加入；FreeRDP 窗口显示 Windows 7 旗舰版桌面（控制面板「系统」窗口、任务栏、输入法状态） |
| `rdpgw -listen 127.0.0.1:33893 -target 192.0.2.20:3389 -target-nla -target-pin … -allow-user administrator`；xfreerdp `/u:administrator` | 前端 xfreerdp 仍是 TLS-only；网关对目标完成 CredSSP 后 `licensed (user channel 1009, channels [rdpdr rdpsnd cliprdr drdynvc]), relaying`；窗口显示 Server 2016 桌面（图标、开始菜单栏、工具提示） |
| 上述两个会话内手工操作（用户在 FreeRDP 窗口里）：Mac `pbcopy` 文本 → Windows Ctrl+V；Windows 复制文本 → Mac `pbpaste`；资源管理器打开 `\\tsclient\gwshare` | 两台机器上粘贴、反向复制（Mac 上 `pbpaste` 得到 Windows 里选中的文本）和打开共享目录看到 `gw-test.txt` 均正常。relay 行：Win7 `client 10 pdus + 1807 fast-path, target 14 pdus + 677 fast-path, input map[mouse:1776 scancode:46 sync:15], channels map[cliprdr:33 drdynvc:4 rdpdr:5736], dropped channels map[], reactivations 1`（rdpdr 5736 块为资源管理器枚举/读取共享；会话中 Win7 发了一次真实 Deactivate All，网关重激活后继续）；Server 2016 `client 5 pdus + 697 fast-path, target 8 pdus + 831 fast-path, input map[mouse:679 scancode:30 sync:12], channels map[cliprdr:31 drdynvc:27 rdpdr:309], dropped channels map[]`。两侧均无 dropped channels，且被过滤的能力（Win7：22/23/24/25/28/29；2016：23/24/28/29/30）不影响桌面 |
| 错误的 `-target-pin` | 网关 `target … failed at handshake: tls handshake: server certificate sha256 4109… does not match pin`，客户端收到 `ERRINFO_SERVER_DENIED_CONNECTION` 退出；错误值出现在日志里便于首次固定 |

说明：macOS 上 XQuartz 不带 XTEST 扩展，xdotool 无法向 FreeRDP 窗口注入输入，桌面内的剪贴板/驱动器操作由用户手工完成，网关在 relay 结束时按通道名输出两向块计数。通道数据未解析，计数是 MCS 块数而非协议消息数；rdpsnd 没有计数是因为测试中没有声音播放。`rdpprobe -png` 对 Server 2016 的 32bpp Interleaved RLE 位图解码报 `truncated stream`（探测器渲染限制，网关不解码位图、不受影响）。

## 6. 本轮验证不覆盖

- 用户认证结果的协议层判定：无 NLA/CredSSP；xrdp 侧日志确认 INFO_AUTOLOGON 凭据登录成功并启动了 Xorg 会话，但观察窗口内没有收到任何 Save Session Info，探测器不能自行判定登录结果；Save Session Info / Set Error Info 解码只经单元测试验证。错误密码用例未跑（xrdp 失败时同样只在服务端日志体现）。
- 许可的 Platform Challenge / New License / Upgrade License 分支仅在本地假服务器与 MS-RDPELE 公开样例上验证，xrdp 不走该分支。
- 图形：只解码 Slow-Path Bitmap Update（xrdp 上只出现 24bpp RLE，8/15/16/32bpp、未压缩位图和 Palette 只经单测；解码正确性靠肉眼比对 PNG，没有逐像素参考）；orders 不解析，Surface Commands 只计数；fast-path 分片重组、压缩标志拒绝、Large Pointer、Pointer Position 合成只经单测（xrdp 更新都很小、不发位置）；输入；其余 Share Data PDU 只按 pduType2 计数。
- 静态虚拟通道只做透传（不解析 cliprdr/rdpdr/rdpsnd/drdynvc 协议，不做通道级策略如只读剪贴板）、消息通道、多传输通道；服务端分配的通道数与请求不符会被拒绝。
- 公网目标、Standard RDP Security 服务器（探测器按设计拒绝）；Windows 目标只测了 Windows 7 SP1（TLS 1.0）与 Server 2016（NLA）各一台，均为自签名证书 + `-pin`，未测域账户 / Kerberos、HYBRID_EX、CredSSP 服务端要求 Early User Auth、NTLM 被禁用（只允许 Kerberos）的主机。
- 网关：前端仍 TLS-only（mstsc 默认会先请求 NLA，需要服务器侧接受 TLS 降级或客户端改为 TLS），不做 CredSSP 服务端；目标证书必须经 `-target-ca`/系统根或 `-target-pin` 叶证书指纹验证，没有跳过选项；被过滤的能力（codecs/Surface Commands/Frame Ack/RAIL 等）意味着不支持 RemoteFX/GFX、RemoteApp；输入只透传并计数，不做键盘布局改写或策略拦截；重激活（Deactivate All）、客户端 Shutdown Request、多会话并发上限、握手超时只在单测/代码路径上；真实 Windows 目标与 mstsc 客户端未测。
- 服务端角色：只对 xfreerdp 2.6.1 验证，mstsc/Windows 客户端、NLA 客户端（被按设计降到 TLS 或拒绝）、多显示器、Auto-Reconnect、重激活（Deactivate All → 新 Demand Active）、Shutdown Request 真实路径、空闲超时、并发上限（只有单元/手工路径）未在真实客户端上验证；位图只发未压缩矩形，没有压缩编码、fast-path 输出、orders；输入被丢弃；不连接上游目标。
- 证书验证关闭或降级路径：不存在该选项，也不计划提供。
