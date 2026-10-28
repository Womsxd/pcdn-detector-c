# 构建与交叉编译

需要支持 C23 的编译器（GCC 13+ / Clang 16+）。依赖以 **git submodule** 方式放在 `third_party/`，
不依赖系统开发包，便于交叉编译。

## 依赖

| 库 | 用途 | 许可证 |
| --- | --- | --- |
| [tomlc99](https://github.com/cktan/tomlc99) | TOML 配置解析 | MIT |
| [cJSON](https://github.com/DaveGamble/cJSON) | HTTP API 的 JSON 编解码 | MIT |
| [uthash](https://github.com/troydhanson/uthash) | 检测器 / 封禁状态的哈希表与集合 | BSD-1-Clause |
| [picohttpparser](https://github.com/h2o/picohttpparser) | HTTP/1.1 请求行与请求头解析 | MIT / Perl |

系统库：`pthread`（线程）、Linux `AF_PACKET` + 经典 BPF（抓包，内核 API，无 libpcap 依赖）。

### 宿主机依赖包

以下按用途分组，装齐「必需」即可完成 `make` / `make test`；其余按需：

| 用途 | 需要的包 | 说明 |
| --- | --- | --- |
| 必需 | C23 编译器（`gcc` 13+ 或 `clang` 16+）、`make`、`git` | `git` 只用于拉 submodule |
| 必需 | `binutils`、`file`、`coreutils` | `objcopy`/`strip` 拆调试符号，`file` 校验产物，`sha256sum` 校验工具链 |
| 必需 | `tar`（配 `xz` / `gzip`） | `script/toolchain.sh` 解压交叉工具链 |
| 下载工具链 / zig | `curl` 或 `wget` | `script/toolchain.sh` 与 zig 安装包 |
| 解压兜底（可选） | `7z` 或 `python3` | 老内核缺 `openat2` 时 GNU tar 会报 `Function not implemented`，脚本自动改用二者之一 |
| 本机静态构建 | musl 工具链（`musl-gcc`） | 只有 `make STATIC=1` 需要；用 `script/gcc-*.sh` 时由它下载的 musl-cross 代替，可跳过 |
| zig 构建 | zig 0.17+ | 用 `./script/zig.sh` 下载官方包（发行版包通常落后，见下文） |
| zig 构建 | LLVM（`llvm-objcopy` / `llvm-strip`） | 交叉架构拆分符号必需，宿主 GNU binutils 只认本机架构 |

各发行版一次性安装：

```bash
# Fedora
sudo dnf install gcc make git tar xz curl binutils file llvm musl-gcc 7zip

# Debian / Ubuntu
sudo apt install gcc make git tar xz-utils curl binutils file llvm musl-tools p7zip-full

# Alpine（cc 本身就是 musl，无需 musl-gcc）
sudo apk add build-base make git tar xz curl binutils file llvm python3 p7zip

# Arch
sudo pacman -S --needed base-devel git tar xz curl binutils file llvm musl p7zip
```

需要注意的点：

- **编译器版本**：Debian 12 / Ubuntu 22.04 自带的 gcc 11/12 不支持 `-std=c23`，需额外装
  `gcc-13`（或 `clang-16`）并用 `make CC=gcc-13`；Ubuntu 24.04 起的 gcc 13 可以直接用。
- **`musl-tools` 只影响 `make STATIC=1`**：它提供 `musl-gcc` 包装脚本，本机静态构建用它；
  跨架构的 `script/gcc-static.sh` 用的是 `.toolchains/` 里的 musl-cross，不需要它。
- **zig 建议用官方 0.17+**：脚本按 0.17 的链接行为编写（`-static-pie` 必须配合 `-fPIE`
  才真的产出 PIE，动态 musl 必须显式 `-dynamic`）。0.16 在脚本下也能用（`-fPIE` 已带上），
  更早的版本若探测不到 PIE 会自动降级为 `PIE=0` 并打印提示。用 `ZIG=/path/to/zig`
  指向官方解压目录里的可执行文件即可。
- 上述包都只是**构建期**依赖：产物本身是静态 ELF，不依赖目标机的 libc 或这些工具。

### 安装 zig（官方包）

发行版仓库通常落后于官方（例如 Fedora 打包的是 0.16），而本仓库的脚本按 0.17 的链接行为适配，
所以建议直接用官方包。脚本可以代下载：

```bash
./script/zig.sh                       # 最新稳定版 → .zig/<版本>/
./script/zig.sh --version 0.17.0      # 指定版本
./script/zig.sh --master              # master（每日构建）
./script/zig.sh --list                # 已下载的版本
./script/zig.sh --path                # 当前会使用的 zig
./script/zig.sh --clean               # 删除 .zig/ 与下载缓存
```

- 下载后按官方 `index.json` 里的 `shasum` 做 SHA256 校验；解压同样是 tar → 7z → python3 兜底。
- 解压到 `.zig/zig-<platform>-<version>/`（已在 `.gitignore` 中）。单个版本约 57 MB 下载、400 MB 解压。
- **解析顺序**：`$ZIG` → `.zig/`（取版本号最大的）→ `PATH` 里的 `zig`。装好之后
  `./script/zig-static.sh`、`./script/zig-dynamic.sh` 会自动使用它，不需要设置任何环境变量。
- 手工从 ziglang.org 下载的包同样适用：把解压目录放进 `.zig/`，或用
  `ZIG=/path/to/zig ./script/zig-static.sh` 显式指定。
- 只有在 `PATH` 里已有合适版本的 zig 时才会用到它；版本太旧时脚本探测不到 PIE 会自动
  退回 `PIE=0` 并提示。

首次检出后拉取依赖：

```bash
git submodule update --init --recursive
# 或
make deps
```

### 为什么用 submodule 而不是包管理器

- 路由器固件普遍要求**可复现的静态构建**：submodule 固定到具体 commit，交叉编译时不需要
  目标平台具备包管理器；
- 四个依赖都很小、无传递依赖，直接 `make` 最省事；
- 如团队已有依赖管理流程，也可以把这些库换成 **Conan / vcpkg / Meson WrapDB** 中的包，
  只需保证头文件与源文件路径可被 Makefile 找到；本项目没有私有构建逻辑，替换成本很低。

## 本机构建

```bash
make / make build   # 本机架构构建，产出 bin/pcdn-detect + bin/pcdn-detect.debug
make -j4
make all            # 多 CPU 架构构建，产物 bin/pcdn-detect-<arch>
make <arch>         # 单个架构：mipsle / mips / armv7 / arm64 / amd64
make test           # 构建并运行单元测试 / HTTP 集成测试 / CLI 冒烟测试
make DEBUG=1        # 保留完整调试符号，不拆分 .debug 文件
make STATIC=1       # Musl libc 全静态构建（见下文，用于跨系统分发）
make STATIC=1 test  # 用 musl 静态工具链重跑全部测试
make PIE=0          # 关闭 PIE（默认开启）
make clean          # 清理 build/ 与 bin/
```

默认开启 PIE（与静态/动态无关）：动态链接产出 `pie executable`，静态链接产出
`static-pie linked`，两者都保留 ASLR。`PIE=0` 显式关闭，产出固定加载地址的可执行文件
（个别老内核或需要固定地址调试的场景才需要）。

默认发布构建（`DEBUG=0`）会：

1. 正常链接带 `-g` 的可执行文件；
2. 用 `objcopy --only-keep-debug` 生成 `bin/pcdn-detect.debug`（完整调试信息）；
3. 用 `strip --strip-unneeded` 精简 `bin/pcdn-detect`；
4. 写入 `.gnu_debuglink`，调试时 `gdb ./bin/pcdn-detect` 会自动加载同目录的
   `pcdn-detect.debug`。

`DEBUG=1` 跳过 2~4 步，调试信息完整保留在可执行文件里。

可用变量：

```bash
# 保留符号表，只删调试段
make STRIP_FLAGS=--strip-debug

# 自定义 binutils（交叉编译使用 clang 或非 *-gcc 工具链时）
make CC=aarch64-linux-gnu-clang \
     OBJCOPY=aarch64-linux-gnu-objcopy STRIP=aarch64-linux-gnu-strip

# 不剥离，直接产出带完整调试信息的二进制
make DEBUG=1
```

`DEBUG` / `STATIC` / `PIE` / `ARCH` 的取值变化时会自动重新链接，不同组合的目标文件也分目录
存放（`build/local`、`build/static`、`build/<arch>`，PIE=0 时加 `-nopie` 后缀），
来回切换不需要 `make clean`。

## 多架构构建

`make all` 按 Go 版本的命名产出各架构二进制。**产物是纯静态 ELF，与部署发行版无关**，
不需要 OpenWrt 的任何东西：用的是通用 musl 交叉工具链，OpenWrt 官方工具链只是同架构的
备选，谁在 `PATH` 里就用谁。缺失的架构会打印提示并跳过，不会中断整体构建：

| 产物 | 典型目标 | 候选工具链（按顺序取第一个存在的） |
| --- | --- | --- |
| `bin/pcdn-detect-mipsle` | ramips / mt7621 (mipsel_24kc) | `mipsel-linux-muslsf-gcc`、`mipsel-linux-musl-gcc`、`mipsel-openwrt-linux-musl-gcc` |
| `bin/pcdn-detect-mips` | ar71xx / ath79 (mips_24kc) | `mips-linux-muslsf-gcc`、`mips-linux-musl-gcc`、`mips-openwrt-linux-musl-gcc` |
| `bin/pcdn-detect-armv7` | arm_cortex-a7 / a9 | `armv7l-linux-musleabihf-gcc`、`arm-linux-musleabihf-gcc`、`arm-openwrt-linux-musl-gcc` |
| `bin/pcdn-detect-arm64` | aarch64_cortex-a53 | `aarch64-linux-musl-gcc`、`aarch64-openwrt-linux-musl-gcc` |
| `bin/pcdn-detect-amd64` | x86-64 | `musl-gcc`、`x86_64-linux-musl-gcc`、`cc`（musl 发行版） |

MIPS 路由器 24Kc 无 FPU，所以 `mips`/`mipsle` 优先选 soft-float 工具链（`muslsf`）。

工具链来源（任选其一，都是普通 Linux 上的 musl 交叉工具链）：

```bash
# musl.cc 预编译 tarball：解压即用，把 bin/ 加进 PATH
wget https://musl.cc/aarch64-linux-musl-cross.tgz && tar xf aarch64-linux-musl-cross.tgz
export PATH=$PWD/aarch64-linux-musl-cross/bin:$PATH

# Alpine 包：aarch64-linux-musl-gcc 等
apk add gcc-aarch64-linux-musl

# OpenWrt SDK：mipsel-openwrt-linux-musl-gcc 等
```

命名不同或不在 `PATH` 时按架构覆盖：

```bash
make all CC_arm64=aarch64-linux-musl-gcc
make arm64 CC_arm64=/opt/musl-cross/bin/aarch64-linux-musl-gcc
```

单架构构建（`make <arch>`）固定为静态链接，等价于：

```bash
make ARCH=arm64 CC=aarch64-linux-musl-gcc STATIC=1
```

架构列表由 `ARCHS` 定义，需要增删（例如补 `mips64`、`riscv64`）时改这一行并补上
对应的 `CC_<arch>` 即可。

> 以上只是「编出某个架构的静态二进制」。若目标就是本机 x86-64（Debian / Ubuntu /
> CentOS / 容器），不需要任何交叉工具链，`make STATIC=1` 就够了。

## 一键多架构构建（script/ 脚本）

`script/` 按「编译器 × 链接方式」拆成四个脚本，产物各自落在 `bin/<变体>/`，互不覆盖，
目标文件也按变体隔离（`build/<变体>/<arch>`），来回切换不需要 `make clean`：

| 脚本 | 产物目录 | 说明 |
| --- | --- | --- |
| `script/gcc-static.sh` | `bin/gcc-static/` | musl-cross GCC，全静态 `static-pie` |
| `script/gcc-dynamic.sh` | `bin/gcc-dynamic/` | musl-cross GCC，动态链接 musl |
| `script/zig-static.sh` | `bin/zig-static/` | 官方 zig，全静态 `static-pie`（musl） |
| `script/zig-dynamic.sh` | `bin/zig-dynamic-<glibc\|musl>/` | 官方 zig，动态链接，`--libc` 选 libc |

```bash
./script/gcc-static.sh                      # 全部架构：下载工具链 + 编译
./script/gcc-static.sh -t "arm64 amd64"     # 只做指定架构
./script/gcc-static.sh -j 8                 # make 并行度
./script/zig.sh                             # 下载官方 zig 到 .zig/（可选，脚本会自动使用）
./script/zig-static.sh                      # zig 全静态
./script/zig-dynamic.sh --libc musl         # zig 动态 + musl
./script/zig-dynamic.sh --libc glibc        # zig 动态 + glibc（默认）
ZIG=/opt/zig/zig ./script/zig-static.sh     # 指定 zig 路径
DEBUG=1 ./script/gcc-static.sh              # 保留完整调试符号
```

GCC 脚本用 `.toolchains/` 里的 musl-cross 工具链，缺失时自动由 `script/toolchain.sh`
下载（[WomsxdTools/musl-libc-toolchains](https://github.com/WomsxdTools/musl-libc-toolchains)，
musl 1.2.6 + GCC 15.1.0）。也可以单独管理工具链：

```bash
./script/toolchain.sh                     # 缺哪个架构装哪个
./script/toolchain.sh -t "arm64 amd64"    # 只装指定架构
./script/toolchain.sh --list              # 列出已就位的工具链
./script/toolchain.sh --clean             # 删除工具链与下载缓存
./script/toolchain.sh --tag <tag>         # 固定 release（默认 latest）
./script/toolchain.sh --base-url <url>    # 换镜像源
```

| 架构 | GCC（musl-cross） | zig musl | zig glibc |
| --- | --- | --- | --- |
| `mipsle` | `mipsel-linux-muslsf`（o32 小端 soft-float） | `mipsel-linux-musleabi` | `mipsel-linux-gnueabi` |
| `mips` | `mips-linux-muslsf`（o32 大端 soft-float） | `mips-linux-musleabi` | `mips-linux-gnueabi` |
| `armv7` | `arm-linux-musleabihf`（VFPv3-D16） | `arm-linux-musleabihf` | `arm-linux-gnueabihf` |
| `arm64` | `aarch64-linux-musl` | `aarch64-linux-musl` | `aarch64-linux-gnu` |
| `amd64` | `x86_64-linux-musl` | `x86_64-linux-musl` | `x86_64-linux-gnu` |

注意：

- 工具链解压到 `.toolchains/<tag>-<arch>/`，tar.gz 缓存在 `.toolchains/downloads/`
  （可复用、可离线；`--clean` 一并删除）。单架构约 100 MB 下载、400 MB 解压。
- 下载后按 release 附带的 `SHA256SUMS` 校验；拿不到时只提示、不中断。
- 解压优先用系统 `tar`；老内核缺 `openat2` 时 GNU tar 会报 `Function not implemented`，
  自动改用 7z / `python3` 兜底。
- 脚本每次都探测 `-static-pie` 是否真的产出 PIE（工具链的 musl 若不是 `-fPIC` 编译，
  链接会退化成非 PIE）：探测失败自动退回 `PIE=0`（仍全静态，只是没有 ASLR）并提示。
- zig 侧：`-static-pie` 只有在 CC 里同时带 `-fPIE` 时才真的产出 PIE；动态 + musl 必须
  显式 `-dynamic`（zig 对 musl 目标默认静态链接）。这些细节脚本都已处理并做产物校验。
- zig 交叉构建需要 `llvm-objcopy` / `llvm-strip`（宿主 GNU binutils 只认本机架构）。

`make all` / `make <arch>` 仍然可用，用的是 PATH 里已有的交叉工具链（Alpine / OpenWrt SDK /
musl.cc 都行），不下载任何东西；候选名单与 `script/` 共用 `script/common.sh` 里的同一份
架构→triple 表：

```bash
PATH="$PWD/.toolchains/musl-cross-1.2.6-gcc15.1.0-20261026-arm64/bin:$PATH" \
    make all CC_arm64=aarch64-linux-musl-gcc
```

## 静态构建（Musl libc）

要产出「拷到任意 Linux 上就能跑」的单文件，在**任意普通 Linux**（Debian / Ubuntu /
CentOS / Fedora / Alpine / 容器）上加 `STATIC=1` 即可，不需要 OpenWrt SDK，也不需要
目标平台的任何 libc：

```bash
make STATIC=1        # 本机自动选 musl 工具链（musl-gcc / x86_64-linux-musl-gcc / cc）
make STATIC=1 test   # 用同一套 musl 静态工具链跑完整测试（含 HTTP 集成测试）
```

静态产物只依赖内核 ABI（`AF_PACKET` + `TPACKET_V2`，Linux 3.2+），所以在 glibc 发行版上
编译、拷到 musl 路由器上运行是完全正常的组合，反之亦然。

本机 musl 工具链按需安装：

```bash
apt install musl-tools     # Debian / Ubuntu，提供 musl-gcc
dnf install musl-gcc       # Fedora
# Alpine / OpenWrt 的 cc 本身就是 musl，无需额外安装
```

**为什么不用 `LDFLAGS=-static` + glibc**：glibc 静态链接时 `getaddrinfo` / NSS 仍要
`dlopen` 加载 NSS 模块，静态产物在运行期会静默失效（域名的监听地址解析、`/etc/hosts`
之外的主机名等），且依然依赖宿主 `/etc` 下的配置。Musl 的静态 libc 是自洽的：DNS 解析、
`/etc/hosts`、时区、pthread 全部编进 libc。因此 `STATIC=1` 会先探测编译器，若发现是
glibc 就直接报错，而不是产出一个「能编译、运行期失灵」的二进制；链接完成后还会校验产物
确实是 `statically linked`。

交叉编译直接见上一节「多架构构建」：`make all` / `make <arch>` 产出的都是静态二进制。

静态构建相关变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `STATIC` | `0` | `1` 全静态链接，并校验编译器不是 glibc |
| `PIE` | `1` | 默认开启：动态链接用 `-pie`、静态链接用 `-static-pie`（配套 `-fPIE`），保留 ASLR；`PIE=0` 显式关闭 |
| `ARCH` | 空（本机架构） | 目标架构，决定产物名 `bin/pcdn-detect-<arch>` 与默认工具链 |
| `ARCHS` | `mipsle mips armv7 arm64 amd64` | `make all` 构建的架构列表 |
| `CC_<arch>` | 按候选列表探测（见「多架构构建」） | 各架构的交叉工具链，可覆盖 |
| `MUSL_CC` | `musl-gcc` → `x86_64-linux-musl-gcc` → `cc` | 本机静态构建（`amd64`）使用的编译器，按上述顺序取第一个存在的 |
| `KERNEL_HEADERS_DIR` | `/usr/include` | 编译器找不到内核头文件时（如 Fedora 的 `musl-gcc`）追加的目录，用 `-idirafter` 追加，musl 自身头文件始终优先 |

## 产物、验证与分发

产物（x86-64，`-O2 -g` 后 strip，默认 PIE）：

```
bin/pcdn-detect         ≈ 434 KiB   static-pie linked，无 PT_INTERP
bin/pcdn-detect.debug   ≈ 1.6 MiB   调试符号（gdb 自动加载）
```

验证与分发：

```bash
file bin/pcdn-detect                       # static-pie linked
readelf -l bin/pcdn-detect | grep INTERP   # 应无输出
scp bin/pcdn-detect root@router:/usr/bin/  # 拷过去直接运行，无需目标机有对应 libc
```

`PIE=0` 时产物是普通 `statically linked` 可执行文件，体积略小（≈ 414 KiB）。

与 libc 无关、但仍属于系统层面的运行时前提：

- 抓包需 root + `CAP_NET_RAW`，并读取 `/proc`；内核需支持 `AF_PACKET` + `TPACKET_V2`（Linux 3.2+）；
- `[log] timezone` 使用 IANA 名称（如 `Asia/Shanghai`）时，目标系统需存在
  `/usr/share/zoneinfo`（Alpine 需装 `tzdata`）；用 POSIX 偏移写法（如 `8:00`、`CST-8`）则无此依赖；
- 选择 `iptables` / `nftables` 后端时需要目标系统有对应命令；`hook` 后端无外部依赖。

验证调试信息是否已拆分：

```bash
file bin/pcdn-detect bin/pcdn-detect.debug
readelf -S bin/pcdn-detect | grep debug       # 主程序应无 .debug_* 段
readelf -p .gnu_debuglink bin/pcdn-detect     # 应显示 pcdn-detect.debug
```

版本号通过 `-DPCDN_BASE_VERSION` / `-DPCDN_GIT_HASH` 注入，默认取当前 git 短哈希：

```bash
make GIT_HASH=dev
./bin/pcdn-detect --version    # 0.0.1-beta.2+dev
```
