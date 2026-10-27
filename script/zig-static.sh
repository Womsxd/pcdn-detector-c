#!/bin/sh
#
# zig-static.sh —— 用官方 zig 交叉编译全部架构的全静态产物（musl libc）。
#
# 产物：bin/zig-static/pcdn-detect-<arch>（+ .debug）
#       默认 static-pie（保留 ASLR）。zig 只有在链接命令里同时看到 -fPIE 时才会真的出
#       static-pie，所以这里的 CC 里带着 -fPIE；探测不到 PIE 时自动退回 PIE=0。
#
# 用法：
#   ./script/zig-static.sh                   全部架构：mipsle mips armv7 arm64 amd64
#   ./script/zig-static.sh -t "arm64 amd64"  只构建指定架构
#   ./script/zig-static.sh -j 8              指定 make 并行度（默认 nproc）
#   ZIG=/opt/zig/zig ./script/zig-static.sh  指定 zig 路径
#
# 依赖：官方 zig（建议 0.17+，可用 ./script/zig.sh 下载到 .zig/）
#       解析顺序：$ZIG → .zig/ → PATH 里的 zig
#       llvm-objcopy / llvm-strip（交叉符号拆分，宿主 GNU binutils 只认本机架构）
#       不需要任何 musl 交叉工具链。
set -eu
. "$(dirname "$0")/common.sh"

usage() {
    sed -n '2,/^set -eu/{/^set -eu/d; s/^# \{0,1\}//; p}' "$0"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--targets) [ $# -ge 2 ] || die "$1 需要参数"; ARCHS=$2; shift 2 ;;
        -j|--jobs)    [ $# -ge 2 ] || die "$1 需要参数"; JOBS=$2; shift 2 ;;
        -h|--help)    usage ;;
        *) die "未知参数：$1（-h 查看用法）" ;;
    esac
done

validate_archs
check_jobs
require_zig
require_llvm_binutils

failed=
for a in $ARCHS; do
    triple=$(zig_musl_triple "$a")
    cc="$ZIG cc -target $triple -fPIE"
    pie=$(choose_pie "$cc" 1)
    if [ "$pie" = 1 ]; then
        : # CC 里的 -fPIE 就是打开 static-pie 的条件
    else
        warn "[$a] 当前 zig 无法用 -static-pie 产出 PIE（0.17 以下会静默退化），退回 PIE=0"
        cc="$ZIG cc -target $triple"
    fi
    build_variant zig-static "$a" "$cc" 1 "$pie" "$OBJCOPY" "$STRIP" \
        || { warn "[$a] 构建失败"; failed="$failed $a"; }
done

finish zig-static "$failed"
