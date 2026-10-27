#!/bin/sh
#
# gcc-dynamic.sh —— 用 musl-cross 的 GCC 交叉编译全部架构的动态链接产物。
#
# 产物：bin/gcc-dynamic/pcdn-detect-<arch>（+ .debug），pie executable，动态链接 musl：
#       interpreter 形如 /lib/ld-musl-<arch>.so.1，DT_NEEDED=libc.so
#       工具链不支持 -pie 时自动退回 PIE=0（无 ASLR）。
#
# 用法：
#   ./script/gcc-dynamic.sh                   全部架构：mipsle mips armv7 arm64 amd64
#   ./script/gcc-dynamic.sh -t "arm64 amd64"  只构建指定架构
#   ./script/gcc-dynamic.sh -j 8              指定 make 并行度（默认 nproc）
#
# 注意：动态产物要在目标机上运行，目标机必须有 musl 动态加载器
#       （Alpine / OpenWrt 默认自带；glibc 发行版需要额外安装 musl）。
#       要"拷到任意 Linux 直接跑"，请用 gcc-static.sh。
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
ensure_toolchains

failed=
for a in $ARCHS; do
    dir=$(toolchain_dir "$a")
    if [ -z "$dir" ]; then
        warn "[$a] 缺少工具链，跳过"
        failed="$failed $a"
        continue
    fi
    triple=$(gcc_triple "$a")
    cc="$dir/bin/$triple-gcc"
    pie=$(choose_pie "$cc" 0)
    [ "$pie" = 1 ] || warn "[$a] 工具链不支持 -pie，退回 PIE=0（无 ASLR）"
    build_variant gcc-dynamic "$a" "$cc" 0 "$pie" \
        "$dir/bin/$triple-objcopy" "$dir/bin/$triple-strip" \
        || { warn "[$a] 构建失败"; failed="$failed $a"; }
done

finish gcc-dynamic "$failed"
