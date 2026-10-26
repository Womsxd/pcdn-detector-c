#!/bin/sh
#
# build-all-static.sh —— 下载预编译的 musl 交叉工具链，产出全静态多架构二进制。
#
# 工具链来源：https://github.com/WomsxdTools/musl-libc-toolchains
#   默认始终拉取 latest release（musl + 最新 GCC，x86_64 host，解压即用）；
#   每个架构一个 tar.gz（约 100 MB）。
#
# 用法：
#   ./build-all-static.sh                      构建全部架构（mipsle mips armv7 arm64 amd64）
#   ./build-all-static.sh -t "arm64 amd64"     只构建指定架构
#   ./build-all-static.sh --toolchain-only     只下载/解压工具链，不编译项目
#   ./build-all-static.sh --clean              删除已解压的工具链与下载缓存
#   ./build-all-static.sh --tag <tag>          固定 release tag（默认 latest，每次运行重新解析）
#   ./build-all-static.sh -j 8                 指定项目编译并行度（默认 nproc）
#
# 环境变量：
#   TOOLCHAIN_TAG        覆盖 release tag，默认 latest
#   TOOLCHAIN_REPO       GitHub 仓库，默认 WomsxdTools/musl-libc-toolchains
#
# 目录：
#   .toolchains/<tag>-<arch>/   解压好的交叉工具链
#   .toolchains/downloads/      下载的 tar.gz 缓存（可复用、可离线）
#   bin/pcdn-detect-<arch>      项目产物
#
# 说明：
#   * 资产命名与项目架构一一对应：<tag>-{mipsle,mips,armv7,arm64,amd64}.tar.gz
#   * 包内同时有 <triple>-gcc 与 <triple>-musl-gcc；这里用前者（Makefile 会按
#     <triple>-objcopy / <triple>-strip 推导 binutils，`-musl-` 变体会推导错）。
#   * 该工具链的 musl 不是 -fPIC 编译的，static-pie 链接会失败；脚本检测到后
#     自动改为 PIE=0（仍然是全静态 ELF，只是没有 ASLR）。
#   * latest 指向新版本后，旧版本的解压目录与 tar.gz 不会自动删除；需要回收
#     空间时用 --clean（会连同新版本一起删掉）。
#
set -eu

PROJECT_DIR=$(cd "$(dirname "$0")" && pwd)

ARCHS="mipsle mips armv7 arm64 amd64"
JOBS=$(nproc 2>/dev/null || echo 2)
PREFIX="$PROJECT_DIR/.toolchains"
TOOLCHAIN_REPO="${TOOLCHAIN_REPO:-WomsxdTools/musl-libc-toolchains}"
TOOLCHAIN_TAG="${TOOLCHAIN_TAG:-latest}"
TOOLCHAIN_BASE_URL="${TOOLCHAIN_BASE_URL:-https://github.com/$TOOLCHAIN_REPO/releases/download}"
TOOLCHAIN_ONLY=0
DO_CLEAN=0
NO_VERIFY=0

log()  { printf '==> %s\n' "$*"; }
warn() { printf '警告：%s\n' "$*" >&2; }
die()  { printf '错误：%s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,/^set -eu/{/^set -eu/d; s/^# \{0,1\}//; p}' "$0"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--targets)     [ $# -ge 2 ] || die "$1 需要参数"; ARCHS=$2; shift 2 ;;
        -j|--jobs)        [ $# -ge 2 ] || die "$1 需要参数"; JOBS=$2; shift 2 ;;
        -p|--prefix)      [ $# -ge 2 ] || die "$1 需要参数"; PREFIX=$2; shift 2 ;;
        --tag)            [ $# -ge 2 ] || die "$1 需要参数"; TOOLCHAIN_TAG=$2; shift 2 ;;
        --base-url)       [ $# -ge 2 ] || die "$1 需要参数"; TOOLCHAIN_BASE_URL=$2; shift 2 ;;
        --toolchain-only) TOOLCHAIN_ONLY=1; shift ;;
        --no-verify)      NO_VERIFY=1; shift ;;
        --clean)          DO_CLEAN=1; shift ;;
        -h|--help)        usage ;;
        *)                die "未知参数：$1（-h 查看用法）" ;;
    esac
done

case "$JOBS" in
    ''|*[!0-9]*) die "-j/--jobs 需要正整数" ;;
esac

# 项目架构 → 工具链 target triple（与 release 资产内的命名一致）
triple_for() {
    case "$1" in
        mipsle) echo "mipsel-linux-muslsf" ;;     # ramips / mt7621，24Kc 无 FPU
        mips)   echo "mips-linux-muslsf" ;;       # ar71xx / ath79
        armv7)  echo "arm-linux-musleabihf" ;;    # cortex-a7 / a9
        arm64)  echo "aarch64-linux-musl" ;;
        amd64)  echo "x86_64-linux-musl" ;;
        *)      return 1 ;;
    esac
}

for a in $ARCHS; do
    triple_for "$a" >/dev/null || die "未知架构：$a（支持：mipsle mips armv7 arm64 amd64）"
done

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"
}

log "检查依赖"
need_cmd tar
need_cmd sha256sum

if command -v curl >/dev/null 2>&1; then
    DL=curl
elif command -v wget >/dev/null 2>&1; then
    DL=wget
else
    die "缺少下载工具：curl 或 wget"
fi

# 把 latest 解析成真实 tag：优先 GitHub API，失败时跟随 releases/latest 的跳转。
resolve_latest_tag() {
    [ "$TOOLCHAIN_TAG" = latest ] || return 0

    hit=
    if [ "$DL" = curl ]; then
        hit=$(curl -fsSL --retry 2 --connect-timeout 20 \
                  -H 'Accept: application/vnd.github+json' \
                  "https://api.github.com/repos/$TOOLCHAIN_REPO/releases/latest" 2>/dev/null \
              | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
              | head -n 1)
        if [ -z "$hit" ]; then
            hit=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
                      --retry 2 --connect-timeout 20 \
                      "https://github.com/$TOOLCHAIN_REPO/releases/latest" 2>/dev/null) || hit=
            case "$hit" in
                */releases/tag/*) hit=${hit##*/releases/tag/} ;;
                *)                hit= ;;
            esac
        fi
    else
        hit=$(wget -qO- --timeout=20 --tries=2 \
                  --header='Accept: application/vnd.github+json' \
                  "https://api.github.com/repos/$TOOLCHAIN_REPO/releases/latest" 2>/dev/null \
              | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
              | head -n 1)
        if [ -z "$hit" ]; then
            hit=$(wget --spider -S --max-redirect=0 --timeout=20 --tries=1 \
                      "https://github.com/$TOOLCHAIN_REPO/releases/latest" 2>&1 \
                  | sed -n 's/^[[:space:]]*[Ll]ocation:[[:space:]]*//p' \
                  | tr -d '\r' | sed -n 's#.*/releases/tag/##p' | head -n 1) || hit=
        fi
    fi

    case "$hit" in
        ''|*/*|*[!A-Za-z0-9._-]*)
            die "无法解析 latest release tag（网络受限或 API 限流），可用 --tag 手动指定" ;;
    esac

    TOOLCHAIN_TAG=$hit
    log "latest release tag：$TOOLCHAIN_TAG"
}

# 解压 tar.gz：优先用系统 tar；失败时（旧内核缺 openat2，GNU tar 1.35 会报
# "Cannot mkdir/open: Function not implemented"）清掉残留并用 7z 重试。
extract_tarball() {   # <tarball> <dest-dir> <expected-top-dir>
    if tar -xzf "$1" -C "$2" 2>/dev/null; then
        return 0
    fi

    rm -rf "$3"

    sevenz=
    for c in 7z 7zz 7za; do
        if command -v "$c" >/dev/null 2>&1; then sevenz=$c; break; fi
    done
    if [ -z "$sevenz" ]; then
        warn "tar 解压失败，且没有 7z 可重试（内核 $(uname -r) 缺 openat2 时需 Linux 5.6+ 或安装 7zip）"
        return 1
    fi

    log "tar 解压失败，改用 7z 重试"
    "$sevenz" x -y -tgzip -so "$1" 2>/dev/null \
        | "$sevenz" x -y -si -ttar -o"$2" >/dev/null || return 1
    [ -d "$3" ] || return 1
    return 0
}

if [ "$DO_CLEAN" = 1 ]; then
    log "清理：$PREFIX"
    rm -rf "$PREFIX"
fi

CACHE="$PREFIX/downloads"
mkdir -p "$CACHE"

fetch() {   # fetch <url> <dest>
    if [ "$DL" = curl ]; then
        curl -fL --retry 3 --connect-timeout 20 -o "$2" "$1"
    else
        wget -O "$2" "$1"
    fi
}

resolve_latest_tag

# 下载 SHA256SUMS（拿不到就跳过校验，只提示）；按 tag 分文件，latest 变化时不会误用旧校验和
SUMS="$CACHE/SHA256SUMS-$TOOLCHAIN_TAG"
if [ "$NO_VERIFY" = 0 ] && [ ! -s "$SUMS" ]; then
    if fetch "$TOOLCHAIN_BASE_URL/$TOOLCHAIN_TAG/SHA256SUMS" "$SUMS" >/dev/null 2>&1; then
        log "已获取 SHA256SUMS"
    else
        rm -f "$SUMS"
        warn "无法获取 SHA256SUMS，跳过完整性校验"
    fi
fi

verify_pkg() {   # verify_pkg <file> <basename>
    [ "$NO_VERIFY" = 0 ] && [ -s "$SUMS" ] || return 0
    expected=$(awk -v f="$2" '$2 == f { print $1 }' "$SUMS")
    [ -n "$expected" ] || { warn "$2 不在 SHA256SUMS 中，跳过校验"; return 0; }
    actual=$(sha256sum "$1" | awk '{print $1}')
    [ "$expected" = "$actual" ] || return 1
    return 0
}

ok_archs=""
failed=""
for a in $ARCHS; do
    triple=$(triple_for "$a")
    root="$PREFIX/$TOOLCHAIN_TAG-$a"
    gcc="$root/bin/$triple-gcc"

    if [ ! -x "$gcc" ]; then
        pkg="$TOOLCHAIN_TAG-$a.tar.gz"
        url="$TOOLCHAIN_BASE_URL/$TOOLCHAIN_TAG/$pkg"
        tarball="$CACHE/$pkg"

        if [ -f "$tarball" ] && verify_pkg "$tarball" "$pkg"; then
            log "[$a] 使用缓存的 $pkg"
        else
            rm -f "$tarball"
            log "[$a] 下载 $pkg"
            fetch "$url" "$tarball" || { warn "[$a] 下载失败：$url"; failed="$failed $a"; continue; }
            if ! verify_pkg "$tarball" "$pkg"; then
                warn "[$a] $pkg 校验失败（sha256 不匹配）"
                rm -f "$tarball"
                failed="$failed $a"
                continue
            fi
        fi

        log "[$a] 解压到 $PREFIX"
        rm -rf "$root"
        if ! extract_tarball "$tarball" "$PREFIX" "$root"; then
            warn "[$a] 解压失败"
            failed="$failed $a"
            continue
        fi
    else
        log "[$a] 已存在工具链：$triple，跳过下载"
    fi

    [ -x "$gcc" ] || { warn "[$a] 未找到 $gcc"; failed="$failed $a"; continue; }
    ok_archs="$ok_archs $a"
done

# 校验工具链能否编译 C23（项目固定 -std=c23，需要 GCC 13+）
check_c23() {
    printf 'int main(void) { return 0; }\n' > "$1/probe.c"
    if ! "$2" -std=c23 -c "$1/probe.c" -o "$1/probe.o" >/dev/null 2>&1; then
        warn "$2 不支持 -std=c23"
        return 1
    fi
    return 0
}

# 该工具链的 musl 未用 -fPIC 编译，static-pie 会链接失败；检测后自动退回 PIE=0
check_static_pie() {
    printf 'int main(void) { return 0; }\n' > "$1/probe.c"
    "$2" -fPIE -static-pie "$1/probe.c" -o "$1/probe" >/dev/null 2>&1
}

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

for a in $ok_archs; do
    triple=$(triple_for "$a")
    if ! check_c23 "$TMP_DIR" "$PREFIX/$TOOLCHAIN_TAG-$a/bin/$triple-gcc"; then
        failed="$failed $a"
    fi
done

if [ "$TOOLCHAIN_ONLY" = 1 ]; then
    log "仅准备工具链（--toolchain-only），跳过项目编译"
else
    [ -n "$ok_archs" ] || die "没有可用的工具链，无法编译项目"

    # 让项目 Makefile 能按工具链前缀找到配套的 objcopy / strip
    for a in $ok_archs; do
        PATH="$PREFIX/$TOOLCHAIN_TAG-$a/bin:$PATH"
    done
    export PATH

    # PIE 是 make 的全局参数，不能按架构区分：只要有一个架构的 musl 不支持
    # static-pie（libc.a 非 -fPIC，arm64 就是这种情况），就统一用 PIE=0。
    pie_bad=""
    for a in $ok_archs; do
        check_static_pie "$TMP_DIR" \
            "$PREFIX/$TOOLCHAIN_TAG-$a/bin/$(triple_for "$a")-gcc" || pie_bad="$pie_bad $a"
    done
    if [ -n "$pie_bad" ]; then
        pie_off=1
        warn "以下架构的工具链不支持 static-pie：$pie_bad；统一改用 PIE=0（仍是全静态 ELF，无 ASLR）"
    else
        pie_off=0
    fi

    log "用预编译工具链编译项目：$ok_archs"
    set -- all -j"$JOBS"
    for a in $ok_archs; do
        set -- "$@" "CC_$a=$PREFIX/$TOOLCHAIN_TAG-$a/bin/$(triple_for "$a")-gcc"
    done
    if [ "$pie_off" = 1 ]; then
        set -- "$@" PIE=0
    fi
    ( cd "$PROJECT_DIR" && make "$@" )
fi

if [ -n "$failed" ]; then
    warn "以下架构失败：$failed"
fi

if [ -d "$PROJECT_DIR/bin" ]; then
    log "产物："
    for f in "$PROJECT_DIR"/bin/pcdn-detect-*; do
        [ -f "$f" ] || continue
        case "$f" in *.debug) continue ;; esac
        rel=${f#"$PROJECT_DIR"/}
        printf '    %-32s %s\n' "$rel" "$(file -b "$f" | cut -d, -f1-4)"
    done
fi

[ -z "$failed" ] || exit 1
log "完成"
