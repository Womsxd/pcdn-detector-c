# pcdn-detect

在 OpenWrt / Linux 路由器上运行的 P2P CDN 行为检测工具。按设备 MAC + 本地端口统计
滑动窗口内的不同远端公网 IP 数量，达到阈值后输出告警，并可选地对接防火墙封禁、
全 UDP 端口封禁与 UPnP 拦截。

本仓库是 [Womsxd/pcdn-detector](https://github.com/Womsxd/pcdn-detector)的 **C23 重写实现**：
行为、配置格式、命令行参数、HTTP API 与状态继承格式尽量与原 Go 版本保持一致，
运行时改为 pthread + AF_PACKET，可在 OpenWrt 上静态链接部署。

## 编译

需要支持 C23 的编译器（GCC 13+ / Clang 16+）；依赖（tomlc99 / cJSON / uthash /
picohttpparser）以 **git submodule** 放在 `third_party/`，首次检出后拉取：

```bash
git submodule update --init --recursive   # 或 make deps
make                                      # 本机构建，产出 bin/pcdn-detect
make -j4 && make test                     # 并行构建 + 单元 / HTTP / CLI 测试
make STATIC=1                             # Musl 全静态，拷到任意 Linux 直接运行
make all                                  # 多架构静态产物 bin/pcdn-detect-<arch>
make DEBUG=1                              # 保留完整调试符号
make PIE=0                                # 关闭 PIE（默认开启）
make clean                                # 清理 build/ 与 bin/
```

依赖与 submodule 说明、调试符号拆分、交叉工具链、`build-all-static.sh`、静态构建原理、
构建变量与产物校验见 [构建与交叉编译](docs/build.md)。

## 运行

抓包需要 `CAP_NET_RAW`，请以 **root** 运行：

```bash
# 监听 br-lan，60 秒内同一端口出现 20 个不同对端 IP 即告警
./bin/pcdn-detect -i br-lan -n 20 -t 60s

# 只校验配置
./bin/pcdn-detect -T -c /etc/pcdn-detect.toml

# 在指定目录生成默认配置模板（目录必须已存在，不覆盖已有文件）
./bin/pcdn-detect --init-config /etc/pcdn-detect
```

命令行参数与 Go 版本一致（短/长形式等价，命令行优先于配置文件）：

| 短 / 长 | 默认值 | 说明 |
| --- | --- | --- |
| `-i` / `--interface` | 空（必填） | 监听的网卡，如 `br-lan` |
| `-n` / `--count` | `20` | 窗口内不同远端公网 IP 数阈值，最大 `200000000` |
| `-t` / `--window` | `60s` | 滑动窗口时长 |
| `-a` / `--alert-duration` | `10m` | 持续提示时长（有流量即续期） |
| `-p` / `--promisc` | `true` | 混杂模式 |
| `-s` / `--interval` | `2s` | 扫描间隔 |
| `-z` / `--timezone` | 空 | 日志时区（IANA 名称或 POSIX 串） |
| `-H` / `--hide-address` | `false` | 隐私模式（隐藏设备自身 MAC / IPv6 / 公网 IPv4） |
| `-L` / `--low-memory` | `false` | 告警后清空对端列表且不再记录新对端 |
| `--peer-limit` | `max(1000, 阈值×10)` | 单端口对端上限；`0` 不限制，最大 `200000000` |
| `--max-ports` | `512` | 单设备端口条目上限；`0` 不限制，最大 `200000000` |
| `-P` / `--protocol` | `udp` | `udp` / `tcp` / `all` |
| `-c` / `--config` | 空 | 指定配置文件（只读取该文件，不自动创建） |
| `--init-config <目录>` | — | 生成默认配置并退出 |
| `-T` / `--test-config` | `false` | 只校验配置 |
| `-v` / `--version` | — | 版本号 |
| `-h` / `--help` | — | 帮助 |

配置文件为 TOML，按顺序查找当前目录的 `config.toml`、`pcdn-detect.toml`；都不可用时
自动创建 `pcdn-detect.toml`。完整模板见 `--init-config` 的输出，功能分块与 Go 版本相同
（C 生成的模板可直接被 Go 版本加载，Go 生成的模板也可直接被 C 版本校验通过）：

```toml
[detect]
threshold = 20
window = "60s"
alert_duration = "10m"
interval = "2s"

[capture]
interface = "br-lan"
promisc = true
frame_size = 2048
block_size = 65536
num_blocks = 4
snaplen = 256
protocol = "udp"

[log]
level = "warn"          # debug / info / warn / error
timezone = ""
hide_address = false

[filter]
list_mode = "whitelist"
# [[filter.blacklist]]
# mac = "aa:bb:cc:dd:ee:ff"
# ports = [40000, "40001-40010"]
# upnp = true
# full_ban = true
```

`[http]`、`[firewall]`、`[full_ban]`、`[upnp]` 的字段与语义和 Go 版本一致，详见生成模板
中的注释与下文各专题文档。防火墙支持 `hook` / `iptables` / `nftables` 三种后端；UPnP 拦截与
全 UDP 端口封禁复用同一后端。

配置热重载：

```bash
kill -HUP <pid>                        # 始终可用
curl -XPOST localhost:8080/api/v1/reload   # 启用 [http] 后
```

## 进阶配置

以下为按需查阅的详细说明，初次使用可按上文默认值直接运行：

- [内存占用与低内存优化](docs/memory.md)：内核抓包缓冲与 `snaplen`、`low_memory` /
  `peer_limit` / `max_ports` 等内存控制项；C 版本没有 GC，`memory_limit` / `gc_percent`
  仅兼容保留。
- [黑白名单](docs/filter.md)：`[filter]` 按设备 MAC（可限定端口）过滤检测范围。
- [防火墙对接](docs/firewall.md)：`[firewall]` 自动封禁 / 解封（hook / iptables / nftables），
  含 [全 UDP 端口封禁模式](docs/firewall.md#全-udp-端口封禁模式full_ban)。
- [UPnP 拦截](docs/upnp.md)：`[upnp]` 拦截设备向路由器发起的 UPnP 请求。
- [HTTP API](docs/http.md)：`[http]` 运行时状态读取、手动解封、重载配置（含跨重启继承封禁状态）；
  配置热重载也可通过 `SIGHUP`（procd 的 `reload` 默认发送该信号）触发，HTTP 关闭时仍可用。

HTTP API 默认关闭；开启后默认只监听 `127.0.0.1:8080`，绑定非回环地址必须配置 token。
端点、鉴权、CORS 与传输层限制见 [HTTP API](docs/http.md)。

### 隐私模式（`hide_address`）

开启后（配置文件 `hide_address = true`，或命令行 `-H` / `--hide-address`），日志中会**隐藏设备自身的身份信息**：

- **MAC** 与**设备的 IPv6** 只保留**前两段与最后一段**，中间以 `...` 省略：
  `60:21:01:1b:0a:23` → `60:21:...:23`，`2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3` → `2408:8240:...:b2a3`。
- **设备的公网 IPv4** 只保留**首段与末段**，中间两段以 `*` 替换：`112.245.115.51` → `112.*.*.51`。
- **内网 IPv4**（如 `192.168.1.100`）不属于公网地址，**保持原样**。
- 只隐藏**设备自己**的地址；**设备外连的远端对端 IP**（告警中的「相关IP」）**不受影响**，始终完整展示。

> 该选项仅影响**日志展示**，不影响黑白名单过滤、防火墙封禁与 HTTP API（API 返回原始值）。
> 支持热重载即时生效。

### 日志等级（`level`）

`[log] level` 控制输出多少日志，取值 `debug` / `info` / `warn` / `error`（默认 `warn`）：

| 等级 | 输出内容 |
| --- | --- |
| `warn`（默认） | 只有警告与错误（配置项被忽略、封禁 / 解封失败、端口被丢弃等） |
| `info` | 额外输出启动参数、检测告警（疑似 / 持续产生 PCDN 行为、行为结束）、封禁 / 解封、UPnP 拦截、抓包缓冲等业务事件 |
| `debug` | 额外输出调试信息 |

> 调试或排查封禁问题时把 `level` 设为 `"info"`，即可看到「已封禁 / 已解封 / 持续产生PCDN行为」等记录；
> 该等级支持热重载（`SIGHUP` / `POST /api/v1/reload`）即时生效。

## 目录结构

```
src/
  app.c        CLI 解析、启动装配、reload 编排、信号与退出
  config.c     配置结构、默认值、TOML 映射、校验、模板
  capture.c    AF_PACKET TPACKET_V2 环形缓冲、经典 BPF、报文解析
  detector.c   滑动窗口、对端集合、端口淘汰、告警
  filter.c     MAC + 端口黑白名单
  firewall.c   hook / iptables / nftables 后端
  blocker.c    告警事件队列、封禁协调、全端口封禁、UPnP
  httpapi.c    API 路由、鉴权、CORS、JSON
  http.c       极简 HTTP/1.1 传输层（picohttpparser + pthread）
  state.c      PCST v1 二进制状态文件（与 Go 版本格式一致）
  util.c       日志、时长/字节格式化、MAC/IP、时区、掩码
  main.c       入口
tests/
  test_core.c  配置 / 过滤 / 检测 / 状态文件
  test_http.c  HTTP API 鉴权 / CORS / 路由 / reload / 内存接口
docs/
  build.md     依赖、本机 / 交叉 / 静态构建、产物校验
  memory.md    抓包缓冲 / snaplen / 内存控制项
  filter.md    黑白名单
  firewall.md  防火墙对接与全 UDP 端口封禁
  upnp.md      UPnP 拦截
  http.md      HTTP API、CORS、reload 与状态继承
```

## 与 Go 版本的差异

- **运行时**：C 版本没有 GC。`[memory] memory_limit` / `gc_percent` 会被解析和校验，
  但不会产生运行时效果；启动时会给出提示。`low_memory` / `peer_limit` / `max_ports`
  的语义完整保留。
- **抓包**：使用 `AF_PACKET` + `TPACKET_V2` 环形缓冲和内核经典 BPF（与 Go 版本的
  `afpacket` 方案等价），不依赖 libpcap。`snaplen`、`frame_size`、`block_size`、
  `num_blocks` 语义一致；`/proc` 无权限或缺少 `CAP_NET_RAW` 时会直接报错。
- **重载**：防火墙变更采用「导出状态快照 → 关闭旧 blocker（逐条解封）→ 清理旧后端 →
  构建新后端 → 恢复快照」的原地流程，效果与 Go 版本的 `Migrate` 等价；旧 blocker /
  旧 firewall 对象会保留到进程退出，避免并发 HTTP 请求持有悬空指针。HTTP 监听地址变更
  若发生在 HTTP 请求线程内，会回退到「保存状态 + 自重启」，避免停止并等待自身。
- **状态继承**：`pcdn-detect.state` 使用与 Go 版本相同的 `PCST v1` 二进制布局
  （magic / version / CRC32 / 小端记录），只在兜底重启时写入，权限 0600。
- **HTTP 传输层**：自建极简 HTTP/1.1（keep-alive、Content-Length、413/414/431/501、
  `Date` 头），请求解析使用 picohttpparser；不支持 HTTPS / chunked 请求体，需在前置
  反向代理终结 TLS。
- **iptables / nftables 后端未在真机验证**：命令拼装与 Go 版本逐条对齐，但没有在
  OpenWrt 内核上做端到端测试；部署前请先用 `hook` 后端或测试环境验证规则。

## 测试

```bash
make test
```

测试覆盖：

- 配置解析（类型错误、未知键、数组表、端口表达式、CORS / 令牌校验、模板可解析）；
- 黑白名单匹配；
- 检测器阈值触发、持续告警、结束回收、对端上限、端口上限与淘汰；
- `PCST v1` 状态文件写入 / 读取往返（已与 Go 版本 `internal/state` 做**双向兼容验证**：
  C 写 → Go 读、Go 写 → C 读）；
- blocker 引用计数（`ban_both` 合并 v4/v6）、全 UDP 端口封禁联动、手动解封；
- hook 后端的占位符替换、v4/v6 双发、全端口 / UPnP 参数；
- iptables / nftables 后端的命令拼装（用假命令记录 argv，不触碰真实防火墙）；
- 真实 HTTP 监听下的鉴权、CORS 预检、404/405/503、`/devices` / `/device` / `/peers`、
  `/dev/memory`、`/reload`；
- CLI：版本、`--init-config`、`-T` 校验（缺少网卡应失败）。

## 贡献

欢迎提交 issue 与 PR，请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)（含开发环境、
检查项与 PR 流程）。提交 PR 即表示您同意 [`CLA.md`](CLA.md)，且每个提交都需要
`Signed-off-by` 签署行（`git commit -s`）。

## 许可证与 CLA

本项目以 [GNU General Public License v3.0](LICENSE) 分发，与上游
[pcdn-detector](https://github.com/Womsxd/pcdn-detector) 保持一致。

提交 Pull Request 即表示您同意[贡献者许可协议（CLA）](CLA.md)，该协议适用于您当前及
未来的所有贡献。提交前请阅读[贡献指南](CONTRIBUTING.md)（含 DCO 签署要求）。

第三方库保留各自许可证（见 `third_party` 各仓库的 LICENSE 或源文件头）：
tomlc99 / cJSON / picohttpparser 为 MIT，uthash 为 BSD-1-Clause。
