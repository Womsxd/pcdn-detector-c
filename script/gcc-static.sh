#!/bin/sh
#
# gcc-static.sh —— 用 musl-cross 的 GCC 交叉编译全部架构的全静态产物。
#
# 产物：bin/gcc-static/pcdn-detect-<arch>（+ .debug）
#       默认 static-pie（保留 ASLR）；工具链的 musl 不支持 static-pie 时自动退回 PIE=0，
#       仍是全静态 ELF，只是没有 ASLR。
#
# 用法：
#   ./script/gcc-static.sh                   全部架构：mipsle mips armv7 arm64 amd64
#   ./script/gcc-static.sh -t "arm64 amd64"  只构建指定架构
#   ./script/gcc-static.sh -j 8              指定 make 并行度（默认 nproc）
#   DEBUG=1 ./script/gcc-static.sh           保留完整调试符号，不拆分 .debug
#
# 工具链：复用 .toolchains/ 下的 musl-cross，缺失时由 script/toolchain.sh 自动拉取。
#         产物在 bin/gcc-static/，不会覆盖 `make all` 的 bin/pcdn-detect-<arch>。
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
    pie=$(choose_pie "$cc" 1)
    [ "$pie" = 1 ] || warn "[$a] 工具链不支持 static-pie，退回 PIE=0（全静态，无 ASLR）"
    build_variant gcc-static "$a" "$cc" 1 "$pie" \
        "$dir/bin/$triple-objcopy" "$dir/bin/$triple-strip" \
        || { warn "[$a] 构建失败"; failed="$failed $a"; }
done

finish gcc-static "$failed"
