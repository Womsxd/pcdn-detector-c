#!/bin/sh
#
# common.sh —— script/ 下各构建脚本的共享逻辑，不单独执行。
#
# 统一约定（四个构建脚本都遵守）：
#   产物    bin/<variant>/pcdn-detect-<arch>（默认另有同目录 .debug）
#   目标文件 build/<variant>/<arch>[-nopie]，各变体互不复用，来回切换不需要 make clean
#   工具链  GCC 用 .toolchains/ 下的 musl-cross（script/toolchain.sh 安装）；
#           zig 用官方包，binutils 用 llvm-objcopy/llvm-strip
#
# 也可以作为命令使用（Makefile 靠它做 PATH 探测，保证架构→triple 表只有一处）：
#   ./script/common.sh --cc-candidates <arch>   输出该架构的交叉编译器候选名，每行一个
#
# 环境变量：
#   ZIG        zig 可执行文件（优先级：$ZIG → .zig/ 下由 script/zig.sh 下载的 → PATH）
#   OBJCOPY    覆盖 objcopy（默认 llvm-objcopy）
#   STRIP      覆盖 strip（默认 llvm-strip）
#   DEBUG=1    保留完整调试符号，不拆分 .debug（Makefile 直接读取该环境变量）
#   TOOLCHAIN_TAG  固定 musl-cross release（透传给 toolchain.sh）

COMMON_LOADED=1
PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
ARCHS_DEFAULT="mipsle mips armv7 arm64 amd64"
ARCHS="$ARCHS_DEFAULT"
JOBS=$(nproc 2>/dev/null || echo 2)
ZIG=${ZIG:-}
OBJCOPY=${OBJCOPY:-}
STRIP=${STRIP:-}

log()  { printf '==> %s\n' "$*"; }
warn() { printf '警告：%s\n' "$*" >&2; }
die()  { printf '错误：%s\n' "$*" >&2; exit 1; }

validate_archs() {
    for _a in $ARCHS; do
        case " $ARCHS_DEFAULT " in
            *" $_a "*) ;;
            *) die "未知架构：$_a（支持：$ARCHS_DEFAULT）" ;;
        esac
    done
}

check_jobs() {
    case "$JOBS" in
        ''|*[!0-9]*) die "-j/--jobs 需要正整数" ;;
    esac
}

# 架构 -> musl-cross 工具链 triple（.toolchains/ 里预编译工具链的命名）
gcc_triple() {
    case "$1" in
        mipsle) echo mipsel-linux-muslsf ;;      # ramips / mt7621，24Kc 无 FPU
        mips)   echo mips-linux-muslsf ;;        # ar71xx / ath79
        armv7)  echo arm-linux-musleabihf ;;     # cortex-a7 / a9
        arm64)  echo aarch64-linux-musl ;;
        amd64)  echo x86_64-linux-musl ;;
        *)      return 1 ;;
    esac
}

# 架构 -> zig 的 musl triple。
# 注意 mips 必须写 musleabi：zig 不认 musl.cc 的 muslsf 命名，写成 muslsf 会退化成
# "找不到目标 libc 头文件"，然后连带把宿主 glibc 头文件混进 32 位编译。
zig_musl_triple() {
    case "$1" in
        mipsle) echo mipsel-linux-musleabi ;;
        mips)   echo mips-linux-musleabi ;;
        armv7)  echo arm-linux-musleabihf ;;
        arm64)  echo aarch64-linux-musl ;;
        amd64)  echo x86_64-linux-musl ;;
        *)      return 1 ;;
    esac
}

# 架构 -> zig 的 glibc triple（mips 的 glibc 只有 o32，zig 里叫 gnueabi）
zig_glibc_triple() {
    case "$1" in
        mipsle) echo mipsel-linux-gnueabi ;;
        mips)   echo mips-linux-gnueabi ;;
        armv7)  echo arm-linux-gnueabihf ;;
        arm64)  echo aarch64-linux-gnu ;;
        amd64)  echo x86_64-linux-gnu ;;
        *)      return 1 ;;
    esac
}

# 某个架构的 GCC 交叉编译器候选名（按优先级，每行一个）。
# 这里是 musl.cc / Alpine / OpenWrt 各种命名的唯一来源：Makefile 的 `make all` /
# `make <arch>` 通过 `common.sh --cc-candidates <arch>` 取这份列表去 PATH 里探测。
cc_candidates() {
    case "$1" in
        mipsle)
            echo mipsel-linux-muslsf-gcc
            echo mipsel-linux-musl-gcc
            echo mipsel-openwrt-linux-musl-gcc
            ;;
        mips)
            echo mips-linux-muslsf-gcc
            echo mips-linux-musl-gcc
            echo mips-openwrt-linux-musl-gcc
            ;;
        armv7)
            echo armv7l-linux-musleabihf-gcc
            echo arm-linux-musleabihf-gcc
            echo arm-openwrt-linux-musl-gcc
            ;;
        arm64)
            echo aarch64-linux-musl-gcc
            echo aarch64-openwrt-linux-musl-gcc
            ;;
        amd64)
            echo musl-gcc
            echo x86_64-linux-musl-gcc
            ;;
        *)
            return 1
            ;;
    esac
}

# musl-cross 工具链目录；未安装时输出空
toolchain_dir() {
    _triple=$(gcc_triple "$1") || return 0
    _found=
    for _d in "$PROJECT_DIR"/.toolchains/musl-cross-*-"$1"; do
        [ -x "$_d/bin/$_triple-gcc" ] && _found=$_d
    done
    [ -n "$_found" ] && echo "$_found"
    return 0
}

# 确保所需架构的 musl-cross 工具链就位；缺失时交给 script/toolchain.sh 安装
ensure_toolchains() {
    _missing=
    for _a in $ARCHS; do
        [ -n "$(toolchain_dir "$_a")" ] || _missing="$_missing $_a"
    done
    [ -n "$_missing" ] || return 0

    . "$PROJECT_DIR/script/toolchain.sh"
    log "缺少工具链：$_missing，开始下载"
    toolchain_ensure_archs "$_missing" || die "工具链准备失败：$_missing"
}

# 解压 tar 包。优先系统 tar；老内核缺 openat2 时 GNU tar 1.35 会报
# "Cannot mkdir/open: Function not implemented"，依次用 7z、python3 兜底。
#   extract_tarball <tarball> <dest-dir> <expected-top-dir>
extract_tarball() {
    case "$1" in
        *.tar.xz|*.txz) _tar=-xJf; _zfmt=-txz ;;
        *.tar.gz|*.tgz) _tar=-xzf; _zfmt=-tgzip ;;
        *)              _tar=-xf;  _zfmt= ;;
    esac
    if tar "$_tar" "$1" -C "$2" 2>/dev/null; then
        return 0
    fi
    rm -rf "$3"

    _7z=
    for _c in 7z 7zz 7za; do
        command -v "$_c" >/dev/null 2>&1 && { _7z=$_c; break; }
    done
    if [ -n "$_7z" ]; then
        log "tar 解压失败，改用 $_7z 重试"
        # shellcheck disable=SC2086
        "$_7z" x -y $_zfmt -so "$1" 2>/dev/null \
            | "$_7z" x -y -si -ttar -o"$2" >/dev/null 2>&1 || :
        if [ -d "$3" ]; then
            return 0
        fi
        rm -rf "$3"
    fi

    if command -v python3 >/dev/null 2>&1; then
        log "改用 python3 tarfile 解压"
        python3 - "$1" "$2" <<'PY' >/dev/null 2>&1 || :
import sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    try:
        t.extractall(sys.argv[2], filter='tar')
    except TypeError:      # Python < 3.12 没有 filter 参数
        t.extractall(sys.argv[2])
PY
        if [ -d "$3" ]; then
            return 0
        fi
    fi

    warn "解压失败：需要 tar / 7z / python3 之一（内核 $(uname -r) 缺 openat2 时 tar 会失败）"
    return 1
}

# .zig/ 下由 script/zig.sh 下载的官方包（取版本号最大的那个）
zig_local() {
    _dir=$(ls -d "$PROJECT_DIR"/.zig/*/ 2>/dev/null | sort -V | tail -n 1)
    [ -n "$_dir" ] && [ -x "$_dir/zig" ] && echo "${_dir%/}/zig"
    return 0
}

# 实际使用的 zig：$ZIG → .zig/ → PATH
zig_bin() {
    if [ -n "$ZIG" ] && [ -x "$ZIG" ]; then
        echo "$ZIG"
        return 0
    fi
    _l=$(zig_local)
    if [ -n "$_l" ]; then
        echo "$_l"
        return 0
    fi
    command -v zig 2>/dev/null || true
}

require_zig() {
    _z=$(zig_bin)
    [ -n "$_z" ] || die "未找到 zig：可用 ./script/zig.sh 下载官方包，或 ZIG=/path/to/zig 指定"
    ZIG=$_z
    log "zig：$("$ZIG" version 2>/dev/null || echo '版本未知')（$ZIG）"
}

# 交叉构建必须用 llvm 的 binutils：宿主 GNU objcopy 只认本机架构
require_llvm_binutils() {
    [ -n "$OBJCOPY" ] || OBJCOPY=$(command -v llvm-objcopy 2>/dev/null || true)
    [ -n "$STRIP" ]   || STRIP=$(command -v llvm-strip 2>/dev/null || true)
    if [ -z "$OBJCOPY" ] || [ -z "$STRIP" ]; then
        die "缺少 llvm-objcopy / llvm-strip（宿主 binutils 只能处理本机架构）：
       dnf install llvm / apt install llvm；或用 OBJCOPY=<路径> STRIP=<路径> 指定"
    fi
    log "binutils：$OBJCOPY / $STRIP"
}

# 探测某个 CC 是否真能产出 PIE：部分工具链（以及 zig 的 -static-pie）会静默退化成非 PIE，
# 只看"命令是否成功"会漏判，必须检查产物 ELF 类型。
#   choose_pie <cc> <1=静态链接|0=动态链接>  -> 输出 1 或 0
choose_pie() {
    _cc=$1
    _static=$2
    _result=0
    _tmp=$(mktemp -d 2>/dev/null) || { echo 0; return 0; }
    printf 'int main(void){return 0;}\n' > "$_tmp/p.c"
    if [ "$_static" = 1 ]; then
        _flags="-fPIE -static-pie"
    else
        _flags="-fPIE -pie"
    fi
    # shellcheck disable=SC2086
    if $_cc $_flags "$_tmp/p.c" -o "$_tmp/p" >/dev/null 2>&1 \
        && readelf -h "$_tmp/p" 2>/dev/null | grep -q 'DYN'; then
        _result=1
    fi
    rm -rf "$_tmp"
    echo "$_result"
}

# build_variant <variant> <arch> <cc> <static> <pie> <objcopy> <strip>
build_variant() {
    _variant=$1
    _arch=$2
    _cc=$3
    _static=$4
    _pie=$5
    _objcopy=$6
    _strip=$7

    log "[$_arch] STATIC=$_static PIE=$_pie CC=$_cc"
    # 产物目录 / 中间文件目录都由 Makefile 的 VARIANT 推导（bin/<variant>/、build/<variant>/），
    # 这里不再覆盖 BIN、OBJDIR、MODE_STAMP，避免脚本复制 Makefile 的命名约定。
    ( cd "$PROJECT_DIR" && \
      make -j"$JOBS" \
        ARCH="$_arch" CC="$_cc" STATIC="$_static" PIE="$_pie" \
        VARIANT="$_variant" \
        OBJCOPY="$_objcopy" STRIP="$_strip" )
}

summary() {
    _dir="$PROJECT_DIR/bin/$1"
    log "产物（bin/$1）："
    for _f in "$_dir"/pcdn-detect-*; do
        case "$_f" in *.debug) continue ;; esac
        [ -f "$_f" ] || continue
        printf '    %-32s %8s  %s\n' \
            "$(basename "$_f")" "$(du -h "$_f" | cut -f1)" "$(file -b "$_f" | cut -d, -f1-4)"
    done
}

# finish <variant> <failed-archs>
finish() {
    summary "$1"
    if [ -n "${2:-}" ]; then
        warn "以下架构失败：$2"
        exit 1
    fi
    log "完成"
}

# 作为命令使用时只做查询（Makefile 的 `make all` / `make <arch>` 依赖 --cc-candidates）
if [ "${0##*/}" = "common.sh" ]; then
    case "${1:-}" in
        --cc-candidates)
            _arch=${2:-}
            [ -n "$_arch" ] || { printf '用法：%s --cc-candidates <arch>\n' "$0" >&2; exit 2; }
            cc_candidates "$_arch"
            exit 0
            ;;
        -h|--help)
            printf '用法：%s --cc-candidates <mipsle|mips|armv7|arm64|amd64>\n' "$0"
            exit 0
            ;;
        *)
            printf '用法：%s --cc-candidates <arch>（其余功能由 script/ 下的构建脚本 source 使用）\n' "$0" >&2
            exit 2
            ;;
    esac
fi
