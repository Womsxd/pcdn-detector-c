/* blocker.h —— 告警事件到封禁 / 解封的协调，含全端口封禁与 UPnP 拦截 */
#ifndef PCDN_BLOCKER_H
#define PCDN_BLOCKER_H

#include "detector.h"
#include "firewall.h"
#include "state.h"

typedef struct blocker blocker;

typedef struct {
    bool enabled;
    char mode[16]; /* on / device */
    int threshold;
    char **devices;
    size_t ndevices;
} blocker_fullban_cfg;

typedef struct {
    bool enabled;
    bool block_all;
    char **targets;
    size_t ntargets;
} blocker_upnp_cfg;

blocker *blocker_create(firewall *fw, bool hide, const blocker_fullban_cfg *fb,
                        const blocker_upnp_cfg *up);
void blocker_close(blocker *b);
void blocker_free(blocker *b);
void blocker_set_hide(blocker *b, bool hide);

/* 热替换名单（内部持有一份引用，可反复调用）：解封并清出新名单已排除的
 * 端口封禁，后续封禁事件也按新名单过滤。 */
void blocker_set_filter(blocker *b, device_filter *filter);

const alert_sink *blocker_alert_sink(blocker *b, void **ctx);

void blocker_force_unban(blocker *b, const char *mac, uint16_t port, const char *proto,
                         int *removed, char *err, size_t errlen);

typedef struct {
    char mac[18];
    uint16_t port;
    char proto[4];
    char family[3];
    int refs;
    char ip[64];
    bool applied;
} ban_view;

typedef struct {
    ban_view *bans;
    size_t nbans;
    char **full_banned;
    size_t nfull;
    char **upnp_blocked;
    size_t nupnp_blocked;
    char **upnp_allowed;
    size_t nupnp_allowed;
    bool upnp_all;
} blocker_snapshot;

void blocker_snapshot_get(blocker *b, blocker_snapshot *out);
void blocker_snapshot_free(blocker_snapshot *s);

typedef struct {
    int active_bans;
    int full_banned;
    int upnp_blocked;
    int upnp_allowed;
    bool upnp_all;
} blocker_counts;

void blocker_counts_get(blocker *b, blocker_counts *out);

typedef struct {
    char mac[18];
    uint16_t port;
    char proto[4];
    char family[3]; /* 空串表示同时覆盖 v4/v6 */
} ban_rule_view;

typedef struct {
    bool both;
    ban_rule_view *rules;
    size_t nrules;
    char **full;
    size_t nfull;
    uint16_t *allow;
    size_t nallow;
} ban_index;

void blocker_ban_index_get(blocker *b, ban_index *out);
void ban_index_free(ban_index *ix);
bool ban_index_banned(const ban_index *ix, const char *mac, uint16_t port, const char *proto,
                      bool v6);

bool blocker_block_state(blocker *b, state_file *out, char *err, size_t errlen);
void blocker_restore(blocker *b, const state_file *st);
void blocker_adopt_sessions(blocker *b, const state_session *sessions, size_t n);

#endif
