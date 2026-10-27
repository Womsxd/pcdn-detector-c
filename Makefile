# pcdn-detect C23 版本
#
# 依赖均以 git submodule 形式放在 third_party/ 下：
#   third_party/tomlc99         TOML 解析
#   third_party/cJSON           JSON 编解码
#   third_party/uthash          哈希表 / 集合
#   third_party/picohttpparser  HTTP/1.1 请求解析
#
# 首次检出后执行：make deps
#
# 目标：
#   make / make build   本机架构构建，产出 bin/pcdn-detect
#   make all            多 CPU 架构构建，产物 bin/pcdn-detect-<arch>
#   make <arch>         单个架构构建（mipsle / mips / armv7 / arm64 / amd64）
#   make test           构建并运行单元 / HTTP 集成 / CLI 冒烟测试
#   make deps          拉取 third_party 子模块
#   make clean         清理产物
#
# 参数：
#   DEBUG=1       保留完整调试符号（默认 0：符号拆到 *.debug，主程序 strip）
#   STATIC=1      Musl libc 全静态链接，产物可直接分发到任意 Linux
#   PIE=0         关闭 PIE（默认 1：动态用 -pie、静态用 -static-pie，保留 ASLR）
#   ARCH=<arch>   指定目标架构（决定产物名与工具链）
#   VARIANT=<名>  产物放 bin/<名>/、中间文件放 build/<名>/，多套构建互不覆盖
#
# 多架构 / 多编译器（GCC、zig）的现成组合见 script/ 目录，那里负责选工具链，
# Makefile 只负责编译、链接与产物校验。

APP       := pcdn-detect
GIT_HASH  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION   ?= 0.0.1-beta.1

DEBUG  ?= 0
STATIC ?= 0
PIE    ?= 1

# 支持交叉编译的架构，产物命名与 Go 版本一致（bin/pcdn-detect-<arch>）
ARCHS := mipsle mips armv7 arm64 amd64
ARCH  ?=

PROJECT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# 各架构的交叉工具链。产物是纯静态 ELF，只依赖内核 ABI，因此与部署发行版无关：
# 默认优先使用通用 musl 交叉工具链（musl.cc / Alpine / Bootlin 的 <triple>-gcc），
# OpenWrt 官方工具链作为同架构的备选，谁在 PATH 里就用谁；也可用 CC_<arch> 直接覆盖：
#   make all CC_arm64=aarch64-linux-musl-gcc
#
# 候选名单（含 musl.cc / Alpine / OpenWrt 的三种命名）由 script/common.sh 统一给出，
# 与 script/ 下的构建脚本共用同一份架构→triple 表，避免两处漂移。
probe_cc = $(shell for c in $(1); do command -v $$c >/dev/null 2>&1 && { echo $$c; break; }; done)
cc_candidates = $(shell "$(PROJECT_DIR)/script/common.sh" --cc-candidates $(1) 2>/dev/null)

_CC_mipsle = $(or $(call probe_cc, $(call cc_candidates,mipsle)), mipsel-linux-musl-gcc)
_CC_mips   = $(or $(call probe_cc, $(call cc_candidates,mips)),   mips-linux-musl-gcc)
_CC_armv7  = $(or $(call probe_cc, $(call cc_candidates,armv7)),  armv7l-linux-musleabihf-gcc)
_CC_arm64  = $(or $(call probe_cc, $(call cc_candidates,arm64)),  aarch64-linux-musl-gcc)
_CC_amd64  = $(or $(call probe_cc, $(call cc_candidates,amd64)),  cc)

CC_mipsle ?= $(_CC_mipsle)
CC_mips   ?= $(_CC_mips)
CC_armv7  ?= $(_CC_armv7)
CC_arm64  ?= $(_CC_arm64)
CC_amd64  ?= $(_CC_amd64)
# 本机 STATIC=1 构建用的编译器（Alpine 等 musl 发行版上 cc 本身就是 musl）
MUSL_CC   ?= $(_CC_amd64)

# 命令行 / 环境显式指定的 CC 优先；其次按 ARCH 取对应工具链；否则按 STATIC 选择
ifeq ($(origin CC),default)
ifneq ($(ARCH),)
CC := $(strip $(or $(CC_$(ARCH)),cc))
else
CC := $(if $(filter 1,$(STATIC)),$(MUSL_CC),cc)
endif
endif

# 静态链接必须使用 Musl：glibc 的 getaddrinfo / NSS 在静态链接下依赖 dlopen，
# 会静默退化为只能解析 /etc/hosts。这里提前拦下来，避免产出“能编译、运行期失灵”的二进制。
ifeq ($(filter 1,$(STATIC)),1)
GLIBC_PROBE := $(shell $(CC) -dM -E -include features.h -x c /dev/null 2>/dev/null \
                       | grep -q __GLIBC__ && echo glibc)
ifneq ($(GLIBC_PROBE),)
$(error STATIC=1 需要 Musl 工具链，当前 CC=$(CC) 指向 glibc；请指定 CC=musl-gcc（或 CC=<arch>-linux-musl-gcc），或安装 musl 工具链后重试)
endif
endif

# objcopy / strip 前缀推导：
#   aarch64-linux-musl-gcc → aarch64-linux-musl-objcopy（交叉工具链通常成对提供）
#   musl-gcc / musl-clang  → 宿主 objcopy / strip（musl 官方 wrapper 没有配套 binutils）
CC_BIN          := $(notdir $(firstword $(CC)))
BINUTILS_PREFIX := $(if $(filter %gcc %clang,$(CC_BIN)),$(patsubst %gcc,%,$(patsubst %clang,%,$(CC_BIN))))
ifeq ($(BINUTILS_PREFIX),musl-)
BINUTILS_PREFIX :=
endif
OBJCOPY    ?= $(BINUTILS_PREFIX)objcopy
STRIP      ?= $(BINUTILS_PREFIX)strip
STRIP_FLAGS?= --strip-unneeded

# 少数发行版（Fedora 的 musl-gcc）的 musl sysroot 不带内核头文件（linux/、asm/）。
# 编译器找不到 linux/filter.h 时，把宿主内核头目录追加到搜索路径末尾：用 -idirafter 而非
# -isystem/-I，保证 musl 自身头文件永远优先，只有 musl 缺失的头才会落到宿主目录。
# 自带内核头文件的交叉工具链（OpenWrt 等）不会触发；真触发了又跨架构时请显式指定 KERNEL_INC。
KERNEL_HEADERS_DIR ?= /usr/include
ifeq ($(shell $(CC) -E -include linux/filter.h -x c /dev/null >/dev/null 2>&1 && echo yes),)
KERNEL_INC ?= -idirafter $(KERNEL_HEADERS_DIR)
endif

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c23 -Wall -Wextra -Wno-unused-parameter -Wshadow -Wformat=2 \
           -D_GNU_SOURCE -DPCDN_GIT_HASH=\"$(GIT_HASH)\" -DPCDN_BASE_VERSION=\"$(VERSION)\" \
           -Isrc -Ithird_party/tomlc99 -Ithird_party/cJSON -Ithird_party/uthash/include \
           -Ithird_party/picohttpparser $(KERNEL_INC)
LDFLAGS += -pthread

# 函数 / 数据各自独立成 section，配合链接期 --gc-sections 剔除未被引用的代码与数据，
# 缩小全静态二进制体积。ctor/dtor 数组由链接脚本 KEEP，不受影响。
CFLAGS  += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

# PIE 默认开启（与链接方式无关）：动态链接用 -pie，静态链接用 -static-pie，
# 编译侧配套 -fPIE。PIE=0 时显式关闭，产出固定加载地址的可执行文件。
ifeq ($(filter 1,$(PIE)),1)
CFLAGS  += -fPIE
ifeq ($(filter 1,$(STATIC)),1)
LDFLAGS += -static-pie
else
LDFLAGS += -pie
endif
else
CFLAGS  += -fno-pie
ifeq ($(filter 1,$(STATIC)),1)
LDFLAGS += -static -no-pie
else
LDFLAGS += -no-pie
endif
endif

# 每种构建组合使用独立的目标文件目录：不同对齐方式 / 不同 libc / PIE 与非 PIE 的 .o
# 混在一起链接会得到悄悄出错的二进制，物理隔离比事后排查便宜得多。
# VARIANT 非空时再多一层目录（bin/<variant>/、build/<variant>/），供 script/ 下多套
# 构建（gcc/zig、静态/动态）并存使用，互不覆盖。
PIE_SUFFIX := $(if $(filter 1,$(PIE)),,-nopie)
OUTDIR     := bin$(if $(VARIANT),/$(VARIANT))
OBJDIR     := $(if $(VARIANT),build/$(VARIANT)/,$(if $(ARCH),build/$(ARCH),$(if $(filter 1,$(STATIC)),build/static,build/local)))$(PIE_SUFFIX)

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=$(OBJDIR)/%.o)
OBJ += $(OBJDIR)/toml.o $(OBJDIR)/cJSON.o $(OBJDIR)/picohttpparser.o

BIN        := $(OUTDIR)/$(APP)$(if $(ARCH),-$(ARCH))
DEBUG_FILE := $(BIN).debug
MODE_STAMP := $(OUTDIR)/.link-mode$(if $(ARCH),-$(ARCH))
.DEFAULT_GOAL := build

.PHONY: all build test clean deps check-deps FORCE $(ARCHS)

# 只构建本机存在对应工具链的架构，缺失的给出提示而不是中断整个构建
AVAIL_ARCHS := $(foreach a,$(ARCHS),$(if $(shell command -v $(firstword $(CC_$(a))) >/dev/null 2>&1 && echo yes),$(a)))

all: $(AVAIL_ARCHS)
	@$(foreach a,$(filter-out $(AVAIL_ARCHS),$(ARCHS)),echo "跳过 $(a)：未找到交叉工具链 $(strip $(CC_$(a)))（可用 CC_$(a)=<路径> 覆盖）" >&2;)
	@echo "产物："
	@ls -l bin/$(APP)-* 2>/dev/null || true

build: $(BIN)

# 单架构交叉构建：静态链接，产物 bin/pcdn-detect-<arch>
$(ARCHS): %:
	@command -v $(firstword $(CC_$*)) >/dev/null 2>&1 \
		|| { echo "未找到交叉工具链 $(strip $(CC_$*))（可用 CC_$*=<路径> 覆盖）" >&2; exit 1; }
	$(MAKE) --no-print-directory ARCH=$* CC="$(strip $(CC_$*))" STATIC=1

deps:
	git submodule update --init --recursive

check-deps:
	@test -f third_party/tomlc99/toml.c && test -f third_party/cJSON/cJSON.c \
		&& test -f third_party/uthash/include/uthash.h \
		&& test -f third_party/picohttpparser/picohttpparser.c \
		|| (echo "缺少 third_party 依赖，请先运行：make deps"; exit 1)

# 记录上次的链接参数：STATIC / PIE / DEBUG 变化时强制重新链接，
# 避免把上一步的静态（或未剥离）二进制当成当前模式的产物。
$(MODE_STAMP): FORCE | $(OUTDIR)
	@echo 'STATIC=$(STATIC) PIE=$(PIE) DEBUG=$(DEBUG)' | cmp -s - $@ \
		|| echo 'STATIC=$(STATIC) PIE=$(PIE) DEBUG=$(DEBUG)' > $@

$(BIN): $(OBJ) $(MODE_STAMP) | check-deps $(OBJDIR) $(OUTDIR)
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
ifeq ($(filter 1,$(STATIC)),1)
	@file -b $@ | grep -qE 'static[a-z-]* linked' \
		|| { echo "$@ 不是全静态可执行文件：$$(file -b $@)" >&2; exit 1; }
	@echo "静态链接校验通过：$$(file -b $@ | cut -d, -f1-3)"
endif
# PIE 由链接参数决定，工具链的默认值可能不一致，这里按 PIE= 的意图校验
ifeq ($(filter 1,$(PIE)),1)
	@file -b $@ | grep -qE 'pie' \
		|| { echo "$@ 不是 PIE 可执行文件：$$(file -b $@)" >&2; exit 1; }
else
	@! file -b $@ | grep -qE 'pie' \
		|| { echo "$@ 不应是 PIE 可执行文件：$$(file -b $@)" >&2; exit 1; }
endif

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/toml.o: third_party/tomlc99/toml.c | $(OBJDIR)
	$(CC) $(CFLAGS) -Wno-unused-parameter -Wno-discarded-qualifiers -c $< -o $@

$(OBJDIR)/cJSON.o: third_party/cJSON/cJSON.c | $(OBJDIR)
	$(CC) $(CFLAGS) -Wno-unused-parameter -c $< -o $@

$(OBJDIR)/picohttpparser.o: third_party/picohttpparser/picohttpparser.c | $(OBJDIR)
	$(CC) $(CFLAGS) -Wno-unused-parameter -c $< -o $@

$(OBJDIR) $(OUTDIR):
	mkdir -p $@

test: $(BIN)
	@test -z "$(ARCH)" || { echo "test 只能在本机架构上运行（当前 ARCH=$(ARCH)）" >&2; exit 1; }
	CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" OBJ_DIR="$(OBJDIR)" ./tests/run.sh

clean:
	rm -rf build bin
