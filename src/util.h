/* util.h —— 日志、时长/字节格式化、隐私掩码、时区解析 */
#ifndef PCDN_UTIL_H
#define PCDN_UTIL_H

#include "common.h"

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3,
} log_level;

void log_set_level(log_level lv);
log_level log_get_level(void);
bool log_parse_level(const char *s, log_level *out, char *err, size_t errlen);
const char *log_level_name(log_level lv);
void log_msg(log_level lv, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void log_fatal(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

#define log_debug(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define log_info(...) log_msg(LOG_INFO, __VA_ARGS__)
#define log_warn(...) log_msg(LOG_WARN, __VA_ARGS__)
#define log_error(...) log_msg(LOG_ERROR, __VA_ARGS__)

/* Go 风格的 Duration 字符串（60s -> 1m0s） */
void fmt_duration(int64_t ns, char *buf, size_t cap);
/* 解析 "60s" / "1.5h" / "2h45m" / "0"；不支持负数 */
bool parse_duration(const char *s, int64_t *out_ns, char *err, size_t errlen);
/* 解析 "16MiB" / "24M" / 纯字节数 */
bool parse_byte_size(const char *s, int64_t *out, char *err, size_t errlen);
/* Go 风格字节数（3.4MiB） */
void human_bytes(uint64_t n, char *buf, size_t cap);

/* 端口表达式：单个端口、范围 a-b、斜杠列表 a/b/c（可混用） */
bool parse_port_expr(const char *expr, uint16_t **out, size_t *nout, char *err, size_t errlen);

/* 隐私模式：设备自身 MAC / IP 的掩码展示 */
void mask_device_mac(bool hide, const pcdn_mac *mac, char *buf, size_t cap);
void mask_device_ip(bool hide, const pcdn_ip *ip, char *buf, size_t cap);

/*
 * 解析日志时区：依次尝试 flag、TZ 环境变量、/etc/TZ。
 * 成功时设置进程 TZ（tzset）并写回展示标签，返回 true。
 * source 为来源说明，offset 形如 +08:00。
 */
bool tz_resolve(const char *flag, char *label, size_t label_cap,
                const char **source, char *offset, size_t offset_cap);

#endif
