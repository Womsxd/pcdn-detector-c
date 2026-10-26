/* state.h —— reload 兜底重启时的告警会话 / 封禁状态继承（二进制 PCST v1） */
#ifndef PCDN_STATE_H
#define PCDN_STATE_H

#include "common.h"

enum {
    STATE_FAMILY_NONE = 0,
    STATE_FAMILY_V4 = 1,
    STATE_FAMILY_V6 = 2,
};

typedef struct {
    pcdn_mac mac;
    uint16_t port;
    uint8_t proto;
    uint8_t family;
    bool applied;
    uint16_t refs;
    pcdn_ip ip;
} state_ban;

typedef struct {
    pcdn_mac mac;
    pcdn_ip ip;
} state_fullban;

typedef struct {
    pcdn_mac mac;
    uint16_t port;
    uint8_t proto;
    bool v6;
    pcdn_ip ip;
    int64_t alert_start_ns;
    int64_t last_active_ns;
    int reported_count;
} state_session;

typedef struct {
    int64_t saved_at;
    state_session *sessions;
    size_t nsessions;
    state_ban *bans;
    size_t nbans;
    state_fullban *fullbanned;
    size_t nfull;
    pcdn_mac *upnp_blocked;
    size_t nupnp_blocked;
    pcdn_mac *upnp_allowed;
    size_t nupnp_allowed;
    bool upnp_all;
} state_file;

/* 文件不存在时 *out == NULL 且返回 true */
bool state_load(const char *path, state_file **out, char *err, size_t errlen);
bool state_save(const char *path, const state_file *st, char *err, size_t errlen);
void state_remove(const char *path);
void state_free(state_file *st);

#endif
