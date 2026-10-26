# pcdn-detect（C23 重写版）

在 OpenWrt / Linux 路由器上运行的 P2P CDN 行为检测工具。按设备 MAC + 本地端口统计
滑动窗口内的不同远端公网 IP 数量，达到阈值后输出告警，并可选地对接防火墙封禁、
全 UDP 端口封禁与 UPnP 拦截。

本仓库是 [Womsxd/pcdn-detector](https://github.com/Womsxd/pcdn-detector)
（[CNB 镜像](https://cnb.cool/womsxd/pcdn-detector)）的 **C23 重写实现**：
行为、配置格式、命令行参数、HTTP API 与状态继承格式尽量与原 Go 版本保持一致，
运行时改为 pthread + AF_PACKET，可在 OpenWrt 上静态链接部署。

## 依赖（均为成熟第三方库）

依赖以 **git submodule** 方式放在 `third_party/`，不依赖系统开发包，便于交叉编译：

| 库 | 用途 | 许可证 |
| --- | --- | --- |
| [tomlc99](https://github.com/cktan/tomlc99) | TOML 配置解析 | MIT |
| [cJSON](https://github.com/DaveGamble/cJSON) | HTTP API 的 JSON 编解码 | MIT |
| [uthash](https://github.com/troydhanson/uthash) | 检测器 / 封禁状态的哈希表与集合 | BSD-1-Clause |
| [picohttpparser](https://github.com/h2o/picohttpparser) | HTTP/1.1 请求行与请求头解析 | MIT / Perl |

系统库：`pthread`（线程）、Linux `AF_PACKET` + 经典 BPF（抓包，内核 API，无 libpcap 依赖）。

### 为什么用 submodule 而不是包管理器

- 路由器固件普遍要求**可复现的静态构建**：submodule 固定到具体 commit，交叉编译时不需要
  目标平台具备包管理器；
- 四个依赖都很小、无传递依赖，直接 `make` 最省事；
- 如团队已有依赖管理流程，也可以把这些库换成 **Conan / vcpkg / Meson WrapDB** 中的包，
  只需保证头文件与源文件路径可被 Makefile 找到；本项目没有私有构建逻辑，替换成本很低。

首次检出后拉取依赖：

```bash
git submodule update --init --recursive
# 或
make deps
```

## 编译

需要支持 C23 的编译器（GCC 13+ / Clang 16+）：

```bash
make            # 发布构建，产出 bin/pcdn-detect + bin/pcdn-detect.debug
make -j4
make release    # clean 后发布构建（切换构建模式时推荐）
make debug      # clean 后保留完整调试符号，不拆分 .debug 文件
make test       # 构建并运行单元测试 / HTTP 集成测试 / CLI 冒烟测试
```

默认发布构建会：

1. 正常链接带 `-g` 的可执行文件；
2. 用 `objcopy --only-keep-debug` 生成 `bin/pcdn-detect.debug`（完整调试信息）；
3. 用 `strip --strip-unneeded` 精简 `bin/pcdn-detect`；
4. 写入 `.gnu_debuglink`，调试时 `gdb ./bin/pcdn-detect` 会自动加载同目录的
   `pcdn-detect.debug`。

可用变量：

```bash
# 保留符号表，只删调试段
make STRIP_FLAGS=--strip-debug

# 自定义 binutils（交叉编译使用 clang 或非 *-gcc 工具链时）
make CC=aarch64-linux-gnu-clang \
     OBJCOPY=aarch64-linux-gnu-objcopy STRIP=aarch64-linux-gnu-strip

# 不剥离，直接产出带完整调试信息的二进制
make clean && make DEBUG=1
```

交叉编译（示例，`CC` 以 `-gcc` 结尾时会自动推导同前缀的 `objcopy` / `strip`）：

```bash
make CC=mipsel-openwrt-linux-musl-gcc
make CC=aarch64-openwrt-linux-musl-gcc
make LDFLAGS="-static -pthread"     # 静态链接
```

验证调试信息是否已拆分：

```bash
file bin/pcdn-detect bin/pcdn-detect.debug
readelf -S bin/pcdn-detect | grep debug       # 主程序应无 .debug_* 段
readelf -p .gnu_debuglink bin/pcdn-detect     # 应显示 pcdn-detect.debug
```

版本号通过 `-DPCDN_BASE_VERSION` / `-DPCDN_GIT_HASH` 注入，默认取当前 git 短哈希：

```bash
make GIT_HASH=dev
./bin/pcdn-detect --version    # 0.0.1-beta.1+dev
```

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
| `-n` / `--count` | `20` | 窗口内不同远端公网 IP 数阈值 |
| `-t` / `--window` | `60s` | 滑动窗口时长 |
| `-a` / `--alert-duration` | `10m` | 持续提示时长（有流量即续期） |
| `-p` / `--promisc` | `true` | 混杂模式 |
| `-s` / `--interval` | `2s` | 扫描间隔 |
| `-z` / `--timezone` | 空 | 日志时区（IANA 名称或 POSIX 串） |
| `-H` / `--hide-address` | `false` | 隐私模式（隐藏设备自身 MAC / IPv6 / 公网 IPv4） |
| `-L` / `--low-memory` | `false` | 告警后清空对端列表且不再记录新对端 |
| `--peer-limit` | `max(1000, 阈值×10)` | 单端口对端上限；`0` 不限制 |
| `--max-ports` | `512` | 单设备端口条目上限；`0` 不限制 |
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
中的注释。防火墙支持 `hook` / `iptables` / `nftables` 三种后端；UPnP 拦截与全 UDP 端口
封禁复用同一后端。

配置热重载：

```bash
kill -HUP <pid>                        # 始终可用
curl -XPOST localhost:8080/api/v1/reload   # 启用 [http] 后
```

## HTTP API

默认关闭；开启后默认只监听 `127.0.0.1:8080`。绑定非回环地址必须配置 token。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/health` | `{"status":"ok","uptime_seconds":N}` |
| GET | `/api/v1/status` | 设备 / 告警 / 封禁计数 |
| GET | `/api/v1/devices` | 设备级 IPv4 / IPv6 端口统计 |
| GET | `/api/v1/device?mac=...` | 单设备端口明细（`family` / `state` / `limit` / `page`） |
| GET | `/api/v1/peers?mac=&port=` | 单端口对端 IP（`proto` / `v6` / `limit` / `page`） |
| GET | `/api/v1/blocks` | 当前端口级 / 全端口 / UPnP 封禁状态 |
| POST | `/api/v1/unban` | `{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}` |
| POST | `/api/v1/reload` | 重载配置 |
| GET | `/dev/memory` | C 运行时统计（RSS / 线程数 / 设备数等） |

支持 Bearer 鉴权（`Authorization: Bearer <token>`）、CORS 预检与 `token = "allow-no-token"`
显式关闭鉴权；行为与原项目 `docs/http.md` 描述的 Go 版本一致。`/dev/memory` 因运行时不同，
返回 `version` / `uptime_seconds` / `num_cpu` / `threads` / `rss_bytes` / `vm_bytes` 等
C 侧字段，而不是 Go 的 `MemStats`。

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

## 许可证

第三方库保留各自许可证（见 `third_party` 各仓库的 LICENSE
或源文件头）。
