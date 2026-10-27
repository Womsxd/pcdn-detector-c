#!/bin/sh
#
# zig-dynamic.sh —— 用官方 zig 交叉编译全部架构的动态链接产物，libc 可选 glibc / musl。
#
# 产物：bin/zig-dynamic-<glibc|musl>/pcdn-detect-<arch>（+ .debug）
#       pie executable，动态链接；musl 目标必须显式加 -dynamic，否则 zig 会按默认
#       静态链接出 static-pie（不报错，只是"动态"变成了"静态"）。
#
# 用法：
#   ./script/zig-dynamic.sh                   全部架构，默认 glibc
#   ./script/zig-dynamic.sh --libc musl       动态链接 musl
#   ./script/zig-dynamic.sh --libc musl -t "arm64 amd64"
#   ZIG=/opt/zig/zig ./script/zig-dynamic.sh  指定 zig 路径
#
# 运行期要求：
#   glibc 目标 —— 目标机需要版本不低于 zig 默认 glibc 的运行库，interpreter 形如
#                 /lib/ld-linux-<arch>.so.<n>
#   musl 目标  —— 目标机需要 musl 动态加载器，interpreter 形如 /lib/ld-musl-<arch>.so.1，
#                 DT_NEEDED=libc.so；glibc 主机上只有装了 musl 才能运行
#   要"拷到任意 Linux 直接跑"，请用 zig-static.sh。
#
# 依赖：官方 zig（建议 0.17+，可用 ./script/zig.sh 下载到 .zig/）、llvm-objcopy / llvm-strip。
#       zig 解析顺序：$ZIG → .zig/ → PATH。
set -eu
. "$(dirname "$0")/common.sh"

LIBC=glibc

usage() {
    sed -n '2,/^set -eu/{/^set -eu/d; s/^# \{0,1\}//; p}' "$0"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--targets) [ $# -ge 2 ] || die "$1 需要参数"; ARCHS=$2; shift 2 ;;
        -j|--jobs)    [ $# -ge 2 ] || die "$1 需要参数"; JOBS=$2; shift 2 ;;
        --libc)       [ $# -ge 2 ] || die "$1 需要参数（glibc 或 musl）"; LIBC=$2; shift 2 ;;
        -h|--help)    usage ;;
        *) die "未知参数：$1（-h 查看用法）" ;;
    esac
done

case "$LIBC" in
    glibc) VARIANT=zig-dynamic-glibc ;;
    musl)  VARIANT=zig-dynamic-musl ;;
    *)     die "--libc 只支持 glibc 或 musl（当前：$LIBC）" ;;
esac

validate_archs
check_jobs
require_zig
require_llvm_binutils

failed=
for a in $ARCHS; do
    if [ "$LIBC" = musl ]; then
        triple=$(zig_musl_triple "$a")
        base="$ZIG cc -target $triple -dynamic"   # musl 目标默认静态，必须显式 -dynamic
    else
        triple=$(zig_glibc_triple "$a")
        base="$ZIG cc -target $triple"            # glibc 目标默认就是动态链接
    fi
    pie=$(choose_pie "$base -fPIE" 0)
    if [ "$pie" = 1 ]; then
        cc="$base -fPIE"
    else
        warn "[$a] 无法产出 PIE，退回 PIE=0（无 ASLR）"
        cc=$base
    fi
    build_variant "$VARIANT" "$a" "$cc" 0 "$pie" "$OBJCOPY" "$STRIP" \
        || { warn "[$a] 构建失败"; failed="$failed $a"; }
done

finish "$VARIANT" "$failed"
