/* filter.h —— 按「设备 MAC + 本地端口」的黑白名单过滤 */
#ifndef PCDN_FILTER_H
#define PCDN_FILTER_H

#include "common.h"

typedef struct device_filter device_filter;

bool filter_create(const char *mode, char **blacklist, size_t nblack, char **whitelist,
                   size_t nwhite, device_filter **out, char *err, size_t errlen);
bool filter_allow_key(const device_filter *f, pcdn_mac mac, uint16_t port);
bool filter_is_empty(const device_filter *f);
void filter_describe(const device_filter *f, char *buf, size_t cap);

/* 引用计数：detector、blocker 与 app 可能同时持有同一份名单（热重载后旧名单
 * 仍被 worker 线程使用），各自持有一份引用，最后一份释放时才真正销毁。 */
void filter_ref(device_filter *f);
void filter_free(device_filter *f); /* 释放一份引用；引用归零时销毁 */

#endif
