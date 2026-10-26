#!/bin/sh
# 构建并运行单元 / 集成测试
set -eu
cd "$(dirname "$0")/.."

make -s

CFLAGS="-std=c23 -O1 -g -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -Isrc \
-Ithird_party/tomlc99 -Ithird_party/uthash/include -Ithird_party/cJSON \
-Ithird_party/picohttpparser"

CORE_OBJS="build/config.o build/filter.o build/detector.o build/state.o build/firewall.o \
build/util.o build/toml.o"
FIREWALL_OBJS="build/config.o build/firewall.o build/filter.o build/util.o build/toml.o"
BLOCKER_OBJS="build/blocker.o build/firewall.o build/config.o build/filter.o build/state.o \
build/util.o build/toml.o"
HTTP_OBJS="build/httpapi.o build/http.o build/blocker.o build/detector.o build/filter.o \
build/config.o build/state.o build/firewall.o build/util.o build/toml.o build/cJSON.o \
build/picohttpparser.o"

# shellcheck disable=SC2086
cc $CFLAGS tests/test_core.c $CORE_OBJS -o build/test_core -pthread
# shellcheck disable=SC2086
cc $CFLAGS tests/test_http.c $HTTP_OBJS -o build/test_http -pthread
# shellcheck disable=SC2086
cc $CFLAGS tests/test_firewall.c $FIREWALL_OBJS -o build/test_firewall -pthread
# shellcheck disable=SC2086
cc $CFLAGS tests/test_blocker.c $BLOCKER_OBJS -o build/test_blocker -pthread
# shellcheck disable=SC2086
cc $CFLAGS tests/test_firewall_backends.c $FIREWALL_OBJS -o build/test_fw_backends -pthread

./build/test_core
./build/test_firewall
./build/test_blocker
./build/test_fw_backends
./build/test_http

# CLI 冒烟测试
./bin/pcdn-detect --version | grep -q '0.0.1-beta.1+'
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
