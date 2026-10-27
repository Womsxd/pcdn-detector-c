#!/bin/sh
#
# toolchain.sh —— 下载 / 解压 / 清理 musl-cross 预编译交叉工具链。
#
# 工具链来源：https://github.com/WomsxdTools/musl-libc-toolchains
#   （musl 1.2.6 + GCC 15.1.0，x86_64 host，解压即用；每个架构一个 tar.gz，约 100 MB）
#
# 用法：
#   ./script/toolchain.sh                    确保全部架构的工具链就位（缺哪个装哪个）
#   ./script/toolchain.sh -t "arm64 amd64"   只处理指定架构
#   ./script/toolchain.sh --list             列出已就位的工具链
#   ./script/toolchain.sh --clean            删除已下载/解压的工具链
#   ./script/toolchain.sh --tag <tag>        固定 release（默认 latest）
#   ./script/toolchain.sh --base-url <url>   换镜像源
#   ./script/toolchain.sh --no-verify        跳过 SHA256 校验
#
# 环境变量：TOOLCHAIN_TAG / TOOLCHAIN_REPO
#
# 目录：
#   .toolchains/<tag>-<arch>/   解压好的工具链（对应 <triple>-gcc / <triple>-objcopy）
#   .toolchains/downloads/      下载的 tar.gz 缓存（可复用、可离线）
#
# 也可以被 source：script/gcc-static.sh 与 script/gcc-dynamic.sh 通过 common.sh 的
# ensure_toolchains 调用 toolchain_ensure_archs，缺哪个架构就装哪个。
#
# 注意：latest 指向新版本后，旧版本的目录与 tar.gz 不会自动删除；回收空间用 --clean。

if [ -z "${COMMON_LOADED:-}" ]; then
    . "$(dirname "$0")/common.sh"
fi

PREFIX="$PROJECT_DIR/.toolchains"
CACHE="$PREFIX/downloads"
TOOLCHAIN_REPO="${TOOLCHAIN_REPO:-WomsxdTools/musl-libc-toolchains}"
TOOLCHAIN_TAG="${TOOLCHAIN_TAG:-latest}"
TOOLCHAIN_BASE_URL="${TOOLCHAIN_BASE_URL:-https://github.com/$TOOLCHAIN_REPO/releases/download}"
NO_VERIFY=${NO_VERIFY:-0}

usage() {
    sed -n '2,/^if \[ -z/{/^if \[ -z/d; s/^# \{0,1\}//; p}' "$0"
    exit 0
}

setup_downloader() {
    [ -n "$DL" ] && return 0
    if command -v curl >/dev/null 2>&1; then
        DL=curl
    elif command -v wget >/dev/null 2>&1; then
        DL=wget
    else
        warn "缺少下载工具：curl 或 wget"
        return 1
    fi
}
DL=${DL:-}

fetch() {   # fetch <url> <dest>
    if [ "$DL" = curl ]; then
        curl -fL --retry 3 --connect-timeout 20 -o "$2" "$1"
    else
        wget -O "$2" "$1"
    fi
}

# 把 latest 解析成真实 tag：优先 GitHub API，失败时跟随 releases/latest 的跳转。
resolve_tag() {
    # 可能被 gcc-static.sh 等脚本在 set -u 下 source，未初始化时不能用 $_TAG
    [ -n "${_TAG:-}" ] && { echo "$_TAG"; return 0; }
    [ "$TOOLCHAIN_TAG" = latest ] || { echo "$TOOLCHAIN_TAG"; return 0; }

    _hit=
    if [ "$DL" = curl ]; then
        _hit=$(curl -fsSL --retry 2 --connect-timeout 20 \
                   -H 'Accept: application/vnd.github+json' \
                   "https://api.github.com/repos/$TOOLCHAIN_REPO/releases/latest" 2>/dev/null \
               | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$_hit" ]; then
            _hit=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --retry 2 --connect-timeout 20 \
                       "https://github.com/$TOOLCHAIN_REPO/releases/latest" 2>/dev/null) || _hit=
            case "$_hit" in
                */releases/tag/*) _hit=${_hit##*/releases/tag/} ;;
                *)                _hit= ;;
            esac
        fi
    else
        _hit=$(wget -qO- --timeout=20 --tries=2 --header='Accept: application/vnd.github+json' \
                   "https://api.github.com/repos/$TOOLCHAIN_REPO/releases/latest" 2>/dev/null \
               | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$_hit" ]; then
            _hit=$(wget --spider -S --max-redirect=0 --timeout=20 --tries=1 \
                       "https://github.com/$TOOLCHAIN_REPO/releases/latest" 2>&1 \
                   | sed -n 's/^[[:space:]]*[Ll]ocation:[[:space:]]*//p' | tr -d '\r' \
                   | sed -n 's#.*/releases/tag/##p' | head -n 1) || _hit=
        fi
    fi

    case "$_hit" in
        ''|*/*|*[!A-Za-z0-9._-]*) return 1 ;;
    esac
    _TAG=$_hit
    echo "$_TAG"
}

# SHA256SUMS 按 tag 缓存，拿不到就只提示、不中断
load_sums() {   # <tag>
    [ "$NO_VERIFY" = 0 ] || return 0
    [ -n "${_SUMS_TAG:-}" ] && [ "$_SUMS_TAG" = "$1" ] && return 0
    SUMS="$CACHE/SHA256SUMS-$1"
    if [ ! -s "$SUMS" ]; then
        if fetch "$TOOLCHAIN_BASE_URL/$1/SHA256SUMS" "$SUMS" >/dev/null 2>&1; then
            log "已获取 SHA256SUMS"
        else
            rm -f "$SUMS"
            warn "无法获取 SHA256SUMS，跳过完整性校验"
        fi
    fi
    _SUMS_TAG=$1
    return 0
}

verify_pkg() {   # verify_pkg <file> <basename>
    [ "$NO_VERIFY" = 0 ] && [ -n "${SUMS:-}" ] && [ -s "$SUMS" ] || return 0
    _expected=$(awk -v f="$2" '$2 == f { print $1 }' "$SUMS")
    [ -n "$_expected" ] || { warn "$2 不在 SHA256SUMS 中，跳过校验"; return 0; }
    _actual=$(sha256sum "$1" | awk '{print $1}')
    [ "$_expected" = "$_actual" ] || return 1
    return 0
}

# 解压由 common.sh 的 extract_tarball 统一提供（tar → 7z → python3 三级兜底）。

# 安装单个架构的工具链
toolchain_install_one() {   # <tag> <arch>
    _tag=$1
    _arch=$2
    _triple=$(gcc_triple "$_arch") || { warn "未知架构：$_arch"; return 1; }
    _root="$PREFIX/$_tag-$_arch"

    if [ -x "$_root/bin/$_triple-gcc" ]; then
        log "[$_arch] 已存在：$_triple-gcc"
        return 0
    fi

    _pkg="$_tag-$_arch.tar.gz"
    _tarball="$CACHE/$_pkg"
    mkdir -p "$CACHE"

    if [ -s "$_tarball" ] && verify_pkg "$_tarball" "$_pkg"; then
        log "[$_arch] 使用缓存的 $_pkg"
    else
        rm -f "$_tarball"
        log "[$_arch] 下载 $_pkg"
        if ! fetch "$TOOLCHAIN_BASE_URL/$_tag/$_pkg" "$_tarball"; then
            warn "[$_arch] 下载失败：$TOOLCHAIN_BASE_URL/$_tag/$_pkg"
            return 1
        fi
        if ! verify_pkg "$_tarball" "$_pkg"; then
            warn "[$_arch] $_pkg SHA256 校验失败"
            rm -f "$_tarball"
            return 1
        fi
    fi

    log "[$_arch] 解压到 $PREFIX"
    rm -rf "$_root"
    if ! extract_tarball "$_tarball" "$PREFIX" "$_root"; then
        warn "[$_arch] 解压失败"
        return 1
    fi
    if [ ! -x "$_root/bin/$_triple-gcc" ]; then
        warn "[$_arch] 解压后未找到 $_root/bin/$_triple-gcc"
        return 1
    fi
    log "[$_arch] 就绪：$_root/bin/$_triple-gcc"
}

# 供 common.sh 的 ensure_toolchains 调用
toolchain_ensure_archs() {   # [archs...]
    _want=${1:-$ARCHS}
    if ! setup_downloader; then
        return 1
    fi

    _need=
    for _a in $_want; do
        [ -n "$(toolchain_dir "$_a")" ] || _need="$_need $_a"
    done
    if [ -z "$_need" ]; then
        log "工具链已就位$_want"
        return 0
    fi

    _tag=$(resolve_tag) || { warn "无法解析工具链 release tag（网络受限或 API 限流，可用 --tag 指定）"; return 1; }
    log "工具链 release：$_tag"
    load_sums "$_tag"

    _failed=
    for _a in $_need; do
        toolchain_install_one "$_tag" "$_a" || _failed="$_failed $_a"
    done
    if [ -n "$_failed" ]; then
        warn "以下架构的工具链没有装好：$_failed"
        return 1
    fi
    return 0
}

toolchain_list() {
    _any=
    for _a in $ARCHS; do
        _triple=$(gcc_triple "$_a")
        _d=$(toolchain_dir "$_a")
        if [ -n "$_d" ]; then
            printf '    %-7s %-26s %s\n' "$_a" "$_triple" "$_d"
            _any=1
        else
            printf '    %-7s %-26s %s\n' "$_a" "$_triple" "（未安装）"
        fi
    done
    [ -n "$_any" ] || log "还没有安装任何工具链，运行 ./script/toolchain.sh 安装"
    return 0
}

toolchain_main() {
    _archs=$ARCHS
    _mode=ensure
    while [ $# -gt 0 ]; do
        case "$1" in
            -t|--targets) [ $# -ge 2 ] || die "$1 需要参数"; _archs=$2; shift 2 ;;
            --tag)        [ $# -ge 2 ] || die "$1 需要参数"; TOOLCHAIN_TAG=$2; shift 2 ;;
            --base-url)   [ $# -ge 2 ] || die "$1 需要参数"; TOOLCHAIN_BASE_URL=$2; shift 2 ;;
            --clean)      _mode=clean; shift ;;
            --list)       _mode=list; shift ;;
            --no-verify)  NO_VERIFY=1; shift ;;
            -h|--help)    usage ;;
            *) die "未知参数：$1（-h 查看用法）" ;;
        esac
    done

    case "$_mode" in
        clean)
            log "清理：$PREFIX"
            rm -rf "$PREFIX"
            ;;
        list)
            log "工具链：$PREFIX"
            toolchain_list
            ;;
        ensure)
            toolchain_ensure_archs "$_archs" || exit 1
            log "完成"
            ;;
    esac
}

if [ "${0##*/}" = "toolchain.sh" ]; then
    toolchain_main "$@"
fi
