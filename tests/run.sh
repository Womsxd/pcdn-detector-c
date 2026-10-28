#!/bin/sh
# 构建并运行单元 / 集成测试
# 从 make 调用时会继承 CC / CFLAGS / LDFLAGS，从而在 musl 静态构建下也验证同一套工具链。
set -eu
cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OBJ_DIR="${OBJ_DIR:-build/local}"

if [ -z "${CFLAGS:-}" ]; then
    CFLAGS="-std=c23 -O1 -g -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -Isrc \
-Ithird_party/tomlc99 -Ithird_party/uthash/include -Ithird_party/cJSON \
-Ithird_party/picohttpparser"
fi
LDFLAGS="${LDFLAGS:-} -pthread"

# 直接运行时先构建主程序；由 `make test` 调用时产物已存在且已按正确模式链接，
# 不再重复 make（否则会丢掉调用方传入的 LDFLAGS，例如 -static）。
if [ ! -x bin/pcdn-detect ]; then
    # shellcheck disable=SC2086
    make -s CC="$CC" LDFLAGS="$LDFLAGS"
fi

CORE_OBJS="$OBJ_DIR/config.o $OBJ_DIR/filter.o $OBJ_DIR/detector.o $OBJ_DIR/state.o \
$OBJ_DIR/firewall.o $OBJ_DIR/util.o $OBJ_DIR/toml.o"
FIREWALL_OBJS="$OBJ_DIR/config.o $OBJ_DIR/firewall.o $OBJ_DIR/filter.o $OBJ_DIR/util.o $OBJ_DIR/toml.o"
BLOCKER_OBJS="$OBJ_DIR/blocker.o $OBJ_DIR/firewall.o $OBJ_DIR/config.o $OBJ_DIR/filter.o \
$OBJ_DIR/state.o $OBJ_DIR/util.o $OBJ_DIR/toml.o"
HTTP_OBJS="$OBJ_DIR/httpapi.o $OBJ_DIR/http.o $OBJ_DIR/blocker.o $OBJ_DIR/detector.o \
$OBJ_DIR/filter.o $OBJ_DIR/config.o $OBJ_DIR/state.o $OBJ_DIR/firewall.o $OBJ_DIR/util.o \
$OBJ_DIR/toml.o $OBJ_DIR/cJSON.o $OBJ_DIR/picohttpparser.o"

# shellcheck disable=SC2086
$CC $CFLAGS tests/test_core.c $CORE_OBJS -o $OBJ_DIR/test_core $LDFLAGS
# shellcheck disable=SC2086
$CC $CFLAGS tests/test_http.c $HTTP_OBJS -o $OBJ_DIR/test_http $LDFLAGS
# shellcheck disable=SC2086
$CC $CFLAGS tests/test_firewall.c $FIREWALL_OBJS -o $OBJ_DIR/test_firewall $LDFLAGS
# shellcheck disable=SC2086
$CC $CFLAGS tests/test_blocker.c $BLOCKER_OBJS -o $OBJ_DIR/test_blocker $LDFLAGS
# shellcheck disable=SC2086
$CC $CFLAGS tests/test_firewall_backends.c $FIREWALL_OBJS -o $OBJ_DIR/test_fw_backends $LDFLAGS

./$OBJ_DIR/test_core
./$OBJ_DIR/test_firewall
./$OBJ_DIR/test_blocker
./$OBJ_DIR/test_fw_backends
./$OBJ_DIR/test_http

# CLI 冒烟测试
./bin/pcdn-detect --version | grep -q '0.0.1-beta.2+'
./bin/pcdn-detect --help 2>&1 | grep -q 'https://github.com/Womsxd/pcdn-detector-c'
./bin/pcdn-detect --help 2>&1 | grep -q 'https://cnb.cool/womsxd/pcdn-detector-c'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
./bin/pcdn-detect --init-config "$tmp" >/dev/null
./bin/pcdn-detect -T -c "$tmp/pcdn-detect.toml" -i lo >/dev/null
if ./bin/pcdn-detect --init-config "$tmp" >/dev/null 2>&1; then
    echo "FAIL: --init-config 不应覆盖已存在的文件" >&2
    exit 1
fi
if ./bin/pcdn-detect -T -c "$tmp/pcdn-detect.toml" >/dev/null 2>&1; then
    echo "FAIL: 缺少 interface 时 -T 应失败" >&2
    exit 1
fi

echo "all tests: OK"
