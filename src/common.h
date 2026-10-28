/* common.h —— 公共基础类型与工具宏 */
#ifndef PCDN_COMMON_H
#define PCDN_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifndef PCDN_BASE_VERSION
#define PCDN_BASE_VERSION "0.0.1-beta.2"
#endif
#ifndef PCDN_GIT_HASH
#define PCDN_GIT_HASH "unknown"
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* IPv4 地址族为 4，IPv6 为 6；v4-mapped 在解析/展示时归一化为 IPv4。 */
typedef struct {
    uint8_t b[6];
} pcdn_mac;

typedef struct {
    uint8_t v6;      /* 0 = IPv4，1 = IPv6 */
    uint8_t b[16];   /* IPv4 使用前 4 字节 */
    bool valid;
} pcdn_ip;

/* MAC / IP / 前缀 */
bool mac_parse(const char *s, pcdn_mac *out, char *err, size_t errlen);
void mac_format(const pcdn_mac *mac, char *buf, size_t cap);
bool mac_equal(const pcdn_mac *a, const pcdn_mac *b);

bool ip_parse(const char *s, pcdn_ip *out, char *err, size_t errlen);
void ip_format(const pcdn_ip *ip, char *buf, size_t cap);
int ip_compare(const pcdn_ip *a, const pcdn_ip *b);
bool ip_equal(const pcdn_ip *a, const pcdn_ip *b);
bool ip_is_public(const pcdn_ip *ip);
bool ip_is_loopback(const pcdn_ip *ip);
bool ip_is_linklocal(const pcdn_ip *ip);
bool ip_is_private(const pcdn_ip *ip);
int ip_family(const pcdn_ip *ip);

typedef struct {
    pcdn_ip base;
    uint8_t bits;
} pcdn_prefix;

bool prefix_contains(const pcdn_prefix *p, const pcdn_ip *ip);

/* 动态字符串缓冲 */
typedef struct {
    char *p;
    size_t n;
    size_t cap;
} strbuf;

void sb_init(strbuf *sb);
void sb_free(strbuf *sb);
char *sb_detach(strbuf *sb);
void sb_add(strbuf *sb, const char *s);
void sb_addn(strbuf *sb, const char *s, size_t n);
void sb_addf(strbuf *sb, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_addc(strbuf *sb, char c);
void sb_reset(strbuf *sb);

/* 内存分配：失败即终止进程（与 Go 的 OOM 行为等价，便于上层忽略返回值） */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t size);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* 错误信息格式化：始终以 NUL 结尾 */
void set_err(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* 当前时间（纳秒）：抓包时间戳与检测窗口使用同一时钟 */
int64_t now_ns(void);

/* 单调时钟毫秒（用于超时） */
int64_t mono_ms(void);

#endif
