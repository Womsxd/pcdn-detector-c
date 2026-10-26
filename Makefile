# pcdn-detect C23 版本
#
# 依赖均以 git submodule 形式放在 third_party/ 下：
#   third_party/tomlc99         TOML 解析
#   third_party/cJSON           JSON 编解码
#   third_party/uthash          哈希表 / 集合
#   third_party/picohttpparser  HTTP/1.1 请求解析
#
# 首次检出后执行：make deps

CC      ?= cc
GIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION  ?= 0.0.1-beta.1

# 默认发布构建：调试信息拆到独立文件，主程序 strip。
# make DEBUG=1 可保留完整调试信息在可执行文件中。
DEBUG      ?= 0
OBJCOPY    ?= $(if $(filter %gcc,$(CC)),$(CC:gcc=objcopy),objcopy)
STRIP      ?= $(if $(filter %gcc,$(CC)),$(CC:gcc=strip),strip)
STRIP_FLAGS?= --strip-unneeded

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c23 -Wall -Wextra -Wno-unused-parameter -Wshadow -Wformat=2 \
           -D_GNU_SOURCE -DPCDN_GIT_HASH=\"$(GIT_HASH)\" -DPCDN_BASE_VERSION=\"$(VERSION)\" \
           -Isrc -Ithird_party/tomlc99 -Ithird_party/cJSON -Ithird_party/uthash/include \
           -Ithird_party/picohttpparser
LDFLAGS += -pthread

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
OBJ += build/toml.o build/cJSON.o build/picohttpparser.o

BIN        := bin/pcdn-detect
DEBUG_FILE := $(BIN).debug
.DEFAULT_GOAL := $(BIN)

.PHONY: deps check-deps clean test release debug

deps:
	git submodule update --init --recursive

check-deps:
	@test -f third_party/tomlc99/toml.c && test -f third_party/cJSON/cJSON.c \
		&& test -f third_party/uthash/include/uthash.h \
		&& test -f third_party/picohttpparser/picohttpparser.c \
		|| (echo "缺少 third_party 依赖，请先运行：make deps"; exit 1)

$(BIN): $(OBJ) | check-deps bin
	$(CC) $(OBJ) -o $@ $(LDFLAGS)
ifeq ($(DEBUG),1)
	@echo "调试构建：完整调试符号保留在 $@"
else
	$(OBJCOPY) --only-keep-debug $@ $(DEBUG_FILE)
	$(STRIP) $(STRIP_FLAGS) $@
	cd $(dir $@) && $(OBJCOPY) --add-gnu-debuglink=$(notdir $(DEBUG_FILE)) $(notdir $@)
	chmod 0644 $(DEBUG_FILE)
	@echo "已拆分调试符号：$(DEBUG_FILE)"
endif

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/toml.o: third_party/tomlc99/toml.c | build
	$(CC) $(CFLAGS) -Wno-unused-parameter -Wno-discarded-qualifiers -c $< -o $@

build/cJSON.o: third_party/cJSON/cJSON.c | build
	$(CC) $(CFLAGS) -Wno-unused-parameter -c $< -o $@

build/picohttpparser.o: third_party/picohttpparser/picohttpparser.c | build
	$(CC) $(CFLAGS) -Wno-unused-parameter -c $< -o $@

build bin:
	mkdir -p $@

test: $(BIN)
	./tests/run.sh

# 切换构建模式时建议用这两个目标，避免增量构建沿用旧模式
release:
	$(MAKE) clean
	$(MAKE) DEBUG=0

debug:
	$(MAKE) clean
	$(MAKE) DEBUG=1

clean:
	rm -rf build bin
