#!/bin/sh
#
# zig.sh —— 下载官方 zig（https://ziglang.org/download/）到 .zig/，供 script/zig-*.sh 使用。
#
# 用法：
#   ./script/zig.sh                      安装最新稳定版
#   ./script/zig.sh --version 0.17.0     安装指定版本
#   ./script/zig.sh --master             安装 master（每日构建）
#   ./script/zig.sh --list               列出已下载的版本
#   ./script/zig.sh --path               打印当前会使用的 zig（不下载）
#   ./script/zig.sh --clean              删除 .zig/（含下载缓存）
#   ./script/zig.sh --base-url <url>     换镜像源（默认 https://ziglang.org）
#
# 目录：
#   .zig/zig-<platform>-<version>/   解压后的官方包（包内自带 zig）
#   .zig/downloads/                  下载的 tar.xz 与 index.json 缓存
#
# 装好后 script/zig-static.sh、script/zig-dynamic.sh 会自动发现，解析顺序：
#   $ZIG → .zig/（取版本号最大的）→ PATH 里的 zig。
#
# 校验：按 index.json 里的 shasum 做 SHA256 校验；拿不到索引时按 URL 约定下载并只提示。

if [ -z "${COMMON_LOADED:-}" ]; then
    . "$(dirname "$0")/common.sh"
fi

ZIG_HOME="$PROJECT_DIR/.zig"
ZIG_CACHE="$ZIG_HOME/downloads"
ZIG_BASE_URL="${ZIG_BASE_URL:-https://ziglang.org}"
INDEX_URL="$ZIG_BASE_URL/download/index.json"

usage() {
    sed -n '2,/^if \[ -z/{/^if \[ -z/d; s/^# \{0,1\}//; p}' "$0"
    exit 0
}

# 当前机器对应的 zig 资产平台名
zig_platform() {
    case "$(uname -m)" in
        x86_64|amd64)   echo x86_64-linux ;;
        aarch64|arm64)  echo aarch64-linux ;;
        riscv64)        echo riscv64-linux ;;
        armv7l)         echo arm-linux-gnueabihf ;;
        i386|i686)      echo x86-linux ;;
        *)              return 1 ;;
    esac
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

# 从 index.json 里取某个版本的 tarball 与 shasum：输出 "<tarball> <shasum>"
#   want = latest（第一个非 master 的条目，index.json 里按版本降序）/ master / 具体版本号
index_lookup() {
    [ -s "$ZIG_CACHE/index.json" ] || return 0
    awk -v want="$1" -v plat="$2" '
        /^  "[^"]+": *\{/ {
            v = $0
            sub(/^  "/, "", v)
            sub(/".*$/, "", v)
            cur = v
            next
        }
        $0 ~ ("^    \"" plat "\": *\\{") { inp = 1; tarball = ""; shasum = ""; next }
        inp && /"tarball":/ {
            t = $0; sub(/.*"tarball": *"/, "", t); sub(/".*$/, "", t); tarball = t
            next
        }
        inp && /"shasum":/ {
            s = $0; sub(/.*"shasum": *"/, "", s); sub(/".*$/, "", s); shasum = s
            next
        }
        inp && /^    \},?$/ {
            inp = 0
            if (tarball != "" && (want == "latest" ? cur != "master" : cur == want)) {
                print tarball, shasum
                exit
            }
        }
    ' "$ZIG_CACHE/index.json"
}

# 解析出要安装的版本：输出 "<tarball> <shasum>"
resolve_target() {   # <latest|master|版本号> <plat>
    _want=$1
    _plat=$2
    mkdir -p "$ZIG_CACHE"
    if [ ! -s "$ZIG_CACHE/index.json" ]; then
        log "获取官方索引：$INDEX_URL"
        fetch "$INDEX_URL" "$ZIG_CACHE/index.json" >/dev/null 2>&1 \
            || { warn "无法获取 index.json（网络受限？）"; rm -f "$ZIG_CACHE/index.json"; }
    fi

    _hit=$(index_lookup "$_want" "$_plat")
    if [ -n "$_hit" ]; then
        echo "$_hit"
        return 0
    fi

    case "$_want" in
        latest|master)
            return 1
            ;;
        *)
            # 索引里找不到时按 URL 约定拼一个（跳过校验）
            warn "索引里没有 $_want/$_plat，按 URL 约定尝试"
            echo "$ZIG_BASE_URL/download/$_want/zig-$_plat-$_want.tar.xz -"
            return 0
            ;;
    esac
}

install_zig() {   # <latest|master|版本号> <plat>
    _want=$1
    _plat=$2

    _target=$(resolve_target "$_want" "$_plat") \
        || die "无法解析 zig 版本（网络受限？可用 --version <版本号> 指定）"
    _url=$(echo "$_target" | awk '{print $1}')
    _shasum=$(echo "$_target" | awk '{print $2}')
    [ -n "$_url" ] || die "无法解析 zig 下载地址"

    _file=$(basename "$_url")
    _stem=${_file%.tar.xz}
    _dest="$ZIG_HOME/$_stem"

    if [ -x "$_dest/zig" ]; then
        log "已存在：.zig/$_stem"
        printf '    %s\n' "$_dest/zig"
        return 0
    fi

    _tarball="$ZIG_CACHE/$_file"
    mkdir -p "$ZIG_CACHE"
    if [ ! -s "$_tarball" ]; then
        log "下载 $_file"
        fetch "$_url" "$_tarball" || { rm -f "$_tarball"; die "下载失败：$_url"; }
    else
        log "使用缓存的 $_file"
    fi

    case "$_shasum" in
        ''|-)
            warn "没有 shasum，跳过校验"
            ;;
        *)
            _actual=$(sha256sum "$_tarball" | awk '{print $1}')
            if [ "$_actual" != "$_shasum" ]; then
                rm -f "$_tarball"
                die "SHA256 校验失败：$_file（已删除，可重试）"
            fi
            ;;
    esac

    log "解压到 .zig/"
    extract_tarball "$_tarball" "$ZIG_HOME" "$_dest" || die "解压失败"
    [ -x "$_dest/zig" ] || die "解压后未找到 $_dest/zig"

    log "已安装：.zig/$_stem"
    printf '    %s（%s）\n' "$_dest/zig" "$("$_dest/zig" version 2>/dev/null || echo '版本未知')"
    log "script/zig-*.sh 会自动使用它；也可以用 ZIG=$_dest/zig 显式指定"
}

zig_list() {
    _found=
    for _d in "$ZIG_HOME"/*/; do
        [ -x "$_d/zig" ] || continue
        printf '    %-40s %s\n' "$(basename "$_d")" "$("$_d/zig" version 2>/dev/null || echo '?')"
        _found=1
    done
    if [ -z "$_found" ]; then
        log "还没有下载任何 zig，运行 ./script/zig.sh 安装"
    else
        log "当前会使用：$(zig_bin)"
    fi
    return 0
}

zig_main() {
    _mode=install
    _ver=latest
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)   [ $# -ge 2 ] || die "$1 需要参数"; _ver=$2; shift 2 ;;
            --master)    _ver=master; shift ;;
            --list)      _mode=list; shift ;;
            --path)      _mode=path; shift ;;
            --clean)     _mode=clean; shift ;;
            --base-url)  [ $# -ge 2 ] || die "$1 需要参数"; ZIG_BASE_URL=$2; INDEX_URL="$ZIG_BASE_URL/download/index.json"; shift 2 ;;
            -h|--help)   usage ;;
            *) die "未知参数：$1（-h 查看用法）" ;;
        esac
    done

    case "$_mode" in
        clean)
            log "清理：$ZIG_HOME"
            rm -rf "$ZIG_HOME"
            ;;
        list)
            log "zig（$ZIG_HOME）："
            zig_list
            ;;
        path)
            _z=$(zig_bin)
            [ -n "$_z" ] || die "未找到 zig：先用 ./script/zig.sh 安装，或 ZIG=/path/to/zig 指定"
            echo "$_z"
            ;;
        install)
            _plat=$(zig_platform) || die "不支持的宿主机架构：$(uname -m)（请手工从 ziglang.org 下载）"
            setup_downloader || exit 1
            install_zig "$_ver" "$_plat"
            ;;
    esac
}

if [ "${0##*/}" = "zig.sh" ]; then
    zig_main "$@"
fi
