/* detector.h —— 滑动窗口统计与 PCDN 告警 */
#ifndef PCDN_DETECTOR_H
#define PCDN_DETECTOR_H

#include "common.h"
#include "filter.h"
#include "state.h"

typedef struct detector detector;

typedef struct {
    pcdn_mac mac;
    pcdn_ip ip;
    uint16_t local_port;
    pcdn_ip remote_ip;
    bool up;
    bool v6;
    uint8_t proto; /* 6 = TCP，17 = UDP */
    int length;
    int64_t ts_ns;
} observation;

typedef struct {
    void (*on_alert_start)(void *ctx, const char *mac, const char *ip, uint16_t port,
                           const char *proto);
    void (*on_alert_end)(void *ctx, const char *mac, const char *ip, uint16_t port,
                         const char *proto);
} alert_sink;

detector *detector_create(int threshold, int64_t window, int64_t alert_duration,
                          device_filter *filter, bool hide, bool low_memory, int peer_limit,
                          int max_ports);
void detector_destroy(detector *d);
void detector_set_sink(detector *d, const alert_sink *sink, void *ctx);
void detector_observe(detector *d, const observation *o);
void detector_scan(detector *d, int64_t now_ns);

void detector_set_params(detector *d, int threshold, int64_t window, int64_t alert_duration);
void detector_set_hide(detector *d, bool hide);
void detector_set_low_memory(detector *d, bool low_memory);
void detector_set_peer_limit(detector *d, int limit);
void detector_set_max_ports(detector *d, int limit);
void detector_set_filter(detector *d, device_filter *filter);

void detector_counts(detector *d, int *devices, int *alerts);
void detector_summary(detector *d);

/* ---- HTTP API 快照 ---- */

typedef struct {
    int ports;
    int banned;
    int udp_ports;
    int udp_banned;
    int tcp_ports;
    int tcp_banned;
} detector_fam_stat;

typedef struct {
    char mac[18];
    detector_fam_stat v4;
    detector_fam_stat v6;
} detector_device_summary;

/* 由调用方提供“某端口当前是否被封禁”的查询：detector 在锁内遍历端口时回调，
 * 避免把整份端口列表复制出去再逐个查询。回调必须只读、不加锁。 */
typedef bool (*detector_banned_fn)(void *ctx, const char *mac, uint16_t port, uint8_t proto,
                                   bool v6);

typedef struct {
    int tracked_devices;
    int alerts;
    int64_t port_evictions;
    int64_t port_drops;
    detector_device_summary *devices;
    size_t ndevices;
} detector_overview;

void detector_overview_get(detector *d, detector_banned_fn banned_fn, void *ctx,
                           detector_overview *out);
void detector_overview_free(detector_overview *ov);

typedef struct {
    uint16_t port;
    uint8_t proto;
    bool v6;
    int peer_count;
    uint64_t up_bytes;
    uint64_t down_bytes;
    bool alerting;
} port_view;

typedef struct {
    char mac[18];
    port_view *ports;
    size_t nports;
} detector_device_view;

void detector_device_view_free(detector_device_view *v);
bool detector_device_snapshot(detector *d, pcdn_mac mac, detector_device_view *out);

typedef struct {
    uint16_t port;
    uint8_t proto;
    bool v6;
    int peer_count;
    char **ips;
    size_t nips;
    bool truncated;
} detector_peer_view;

void detector_peer_view_free(detector_peer_view *v);
bool detector_peers_page(detector *d, pcdn_mac mac, uint16_t port, uint8_t proto, bool v6,
                         int64_t offset, int limit, detector_peer_view *out);

bool detector_alert_sessions(detector *d, state_session **out, size_t *n);
void detector_restore_sessions(detector *d, const state_session *sessions, size_t n);

#endif
