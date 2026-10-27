#include "detector.h"

#include <arpa/inet.h>
#include <pthread.h>

#include "uthash.h"
#include "util.h"

#define PROTO_TCP 6
#define PROTO_UDP 17
#define INLINE_PEERS 4
#define MIN_COMPACT_PEAK 64
#define COMPACT_RATIO 4
#define PORTS_EVICT_PERCENT 10
#define EXPIRY_BUCKETS 10
#define DROP_LOG_EVERY 100000
#define ALERT_LOG_MAX_IPS 20

/* ------------------------------------------------------------------ */
/* 数据结构                                                            */
/* ------------------------------------------------------------------ */

typedef struct peer_entry {
    uint8_t key[16];
    int64_t last_seen_ns;
    bool reported;
    UT_hash_handle hh;
} peer_entry;

typedef struct {
    peer_entry *head;
    size_t keylen;
    int count;
    int peak;
} peer_set;

typedef struct {
    peer_set peers;
    uint8_t ip[16];
    bool ip_valid;
    uint64_t up_bytes;
    uint64_t down_bytes;
    int64_t last_active_ns;
    int64_t alert_start_ns;
    int reported_count;
} port_stat;

typedef struct port_entry {
    uint32_t key; /* port | proto << 16 */
    uint16_t port;
    uint8_t proto;
    port_stat *stat;
    UT_hash_handle hh;
} port_entry;

typedef struct {
    port_entry *head;
    int count;
    int peak;
} port_table;

typedef struct device {
    pcdn_mac mac;
    port_table v4;
    port_table v6;
    UT_hash_handle hh;
} device;

struct detector {
    pthread_mutex_t mu;
    device *devices;
    int devices_peak;
    int threshold;
    int64_t window;
    int64_t alert_duration;
    const alert_sink *sink;
    void *sink_ctx;
    bool hide;
    bool low_memory;
    int peer_limit;
    int max_ports;
    device_filter *filter;
    int64_t port_evictions;
    int64_t port_drops;
    int alerts;
};

static _Thread_local size_t g_sort_keylen;

static int cmp_peer_key(const void *a, const void *b)
{
    return memcmp(a, b, g_sort_keylen);
}

static const char *proto_name(uint8_t proto)
{
    return proto == PROTO_TCP ? "tcp" : "udp";
}

/* ------------------------------------------------------------------ */
/* 对端集合                                                            */
/* ------------------------------------------------------------------ */

static peer_entry *peer_find(peer_set *s, const uint8_t *key)
{
    peer_entry *e = NULL;
    HASH_FIND(hh, s->head, key, (unsigned)s->keylen, e);
    return e;
}

static peer_entry *peer_touch(peer_set *s, const uint8_t *key, int64_t ts)
{
    peer_entry *e = peer_find(s, key);
    if (e) {
        e->last_seen_ns = ts;
        return e;
    }
    e = xcalloc(1, sizeof(*e));
    memcpy(e->key, key, s->keylen);
    e->last_seen_ns = ts;
    HASH_ADD(hh, s->head, key, (unsigned)s->keylen, e);
    s->count++;
    if (s->count > s->peak)
        s->peak = s->count;
    return e;
}

static void peer_evict(peer_set *s, int64_t now_ns, int64_t window_ns)
{
    peer_entry *e, *tmp;
    HASH_ITER(hh, s->head, e, tmp)
    {
        if (now_ns - e->last_seen_ns > window_ns) {
            HASH_DEL(s->head, e);
            free(e);
            s->count--;
        }
    }
}

static void peer_clear(peer_set *s)
{
    peer_entry *e, *tmp;
    HASH_ITER(hh, s->head, e, tmp)
    {
        HASH_DEL(s->head, e);
        free(e);
    }
    s->head = NULL;
    s->count = 0;
    s->peak = 0;
}

static void peer_set_free(peer_set *s)
{
    peer_clear(s);
}

static int peer_mark_all_reported(peer_set *s)
{
    int n = 0;
    for (peer_entry *e = s->head; e; e = e->hh.next) {
        e->reported = true;
        n++;
    }
    return n;
}

static void peer_clear_reported(peer_set *s)
{
    for (peer_entry *e = s->head; e; e = e->hh.next)
        e->reported = false;
}

static uint8_t (*peer_collect_new(peer_set *s, size_t *nout))[16]
{
    size_t cap = (size_t)s->count;
    uint8_t(*keys)[16] = cap ? xmalloc(cap * 16) : NULL;
    size_t n = 0;
    for (peer_entry *e = s->head; e; e = e->hh.next) {
        if (e->reported)
            continue;
        e->reported = true;
        /* IPv4 只写前 4 字节，其余必须清零：元素会整体参与 qsort 交换 */
        memset(keys[n], 0, 16);
        memcpy(keys[n], e->key, s->keylen);
        n++;
    }
    *nout = n;
    return keys;
}

static uint8_t (*peer_keys(peer_set *s, size_t *nout))[16]
{
    size_t cap = (size_t)s->count;
    uint8_t(*keys)[16] = cap ? xmalloc(cap * 16) : NULL;
    size_t n = 0;
    for (peer_entry *e = s->head; e; e = e->hh.next) {
        memset(keys[n], 0, 16);
        memcpy(keys[n], e->key, s->keylen);
        n++;
    }
    *nout = n;
    return keys;
}

static void peer_compact(peer_set *s)
{
    if (!s->head) {
        s->peak = 0;
        return;
    }
    if (s->peak < MIN_COMPACT_PEAK || s->count * COMPACT_RATIO > s->peak) {
        if (s->peak < s->count)
            s->peak = s->count;
        return;
    }
    size_t n = (size_t)s->count;
    peer_entry **items = n ? xmalloc(n * sizeof(peer_entry *)) : NULL;
    size_t i = 0;
    for (peer_entry *e = s->head; e; e = e->hh.next)
        items[i++] = e;
    HASH_CLEAR(hh, s->head);
    s->head = NULL;
    for (i = 0; i < n; i++) {
        memset(&items[i]->hh, 0, sizeof(items[i]->hh));
        HASH_ADD(hh, s->head, key, (unsigned)s->keylen, items[i]);
    }
    free(items);
    s->peak = s->count;
}

static void peer_record_peak(peer_set *s)
{
    if (s->count > s->peak)
        s->peak = s->count;
}

static void format_peer_key(const uint8_t *key, size_t keylen, char *buf, size_t cap)
{
    if (keylen == 4) {
        inet_ntop(AF_INET, key, buf, (socklen_t)cap);
        return;
    }
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(key, mapped, 12) == 0)
        inet_ntop(AF_INET, key + 12, buf, (socklen_t)cap);
    else
        inet_ntop(AF_INET6, key, buf, (socklen_t)cap);
}

/* 按地址数值序排序后格式化前 limit 个对端 IP；返回逗号分隔字符串 */
static char *format_peer_ips(uint8_t (*keys)[16], size_t n, size_t keylen, int limit,
                             size_t *shown)
{
    if (n == 0) {
        if (shown)
            *shown = 0;
        return xstrdup("");
    }
    g_sort_keylen = keylen;
    qsort(keys, n, 16, cmp_peer_key);
    size_t take = n;
    if (limit > 0 && take > (size_t)limit)
        take = (size_t)limit;
    strbuf sb;
    sb_init(&sb);
    for (size_t i = 0; i < take; i++) {
        if (i)
            sb_add(&sb, ", ");
        char buf[64];
        format_peer_key(keys[i], keylen, buf, sizeof(buf));
        sb_add(&sb, buf);
    }
    if (shown)
        *shown = take;
    return sb_detach(&sb);
}

/* ------------------------------------------------------------------ */
/* 端口表 / 设备表                                                     */
/* ------------------------------------------------------------------ */

static port_entry *port_find(port_table *t, uint16_t port, uint8_t proto)
{
    uint32_t key = (uint32_t)port | ((uint32_t)proto << 16);
    port_entry *e = NULL;
    HASH_FIND(hh, t->head, &key, sizeof(key), e);
    return e;
}

static port_entry *port_create(port_table *t, uint16_t port, uint8_t proto, bool v6)
{
    port_entry *e = xcalloc(1, sizeof(*e));
    e->key = (uint32_t)port | ((uint32_t)proto << 16);
    e->port = port;
    e->proto = proto;
    e->stat = xcalloc(1, sizeof(port_stat));
    e->stat->peers.keylen = v6 ? 16 : 4;
    HASH_ADD(hh, t->head, key, sizeof(e->key), e);
    t->count++;
    if (t->count > t->peak)
        t->peak = t->count;
    return e;
}

static void port_remove(port_table *t, port_entry *e)
{
    HASH_DEL(t->head, e);
    peer_set_free(&e->stat->peers);
    free(e->stat);
    free(e);
    t->count--;
}

static void port_table_free(port_table *t)
{
    port_entry *e, *tmp;
    HASH_ITER(hh, t->head, e, tmp)
    {
        HASH_DEL(t->head, e);
        peer_set_free(&e->stat->peers);
        free(e->stat);
        free(e);
    }
    t->head = NULL;
    t->count = 0;
    t->peak = 0;
}

static void port_table_compact(port_table *t)
{
    if (!t->head) {
        t->peak = 0;
        return;
    }
    if (t->peak < MIN_COMPACT_PEAK || t->count * COMPACT_RATIO > t->peak) {
        if (t->peak < t->count)
            t->peak = t->count;
        return;
    }
    size_t n = (size_t)t->count;
    port_entry **items = n ? xmalloc(n * sizeof(port_entry *)) : NULL;
    size_t i = 0;
    for (port_entry *e = t->head; e; e = e->hh.next)
        items[i++] = e;
    HASH_CLEAR(hh, t->head);
    t->head = NULL;
    for (i = 0; i < n; i++) {
        memset(&items[i]->hh, 0, sizeof(items[i]->hh));
        HASH_ADD(hh, t->head, key, sizeof(items[i]->key), items[i]);
    }
    free(items);
    t->peak = t->count;
}

static device *device_find(detector *d, pcdn_mac mac)
{
    device *dev = NULL;
    HASH_FIND(hh, d->devices, &mac, sizeof(mac), dev);
    return dev;
}

static device *device_get(detector *d, pcdn_mac mac)
{
    device *dev = device_find(d, mac);
    if (dev)
        return dev;
    dev = xcalloc(1, sizeof(*dev));
    dev->mac = mac;
    HASH_ADD(hh, d->devices, mac, sizeof(dev->mac), dev);
    return dev;
}

static void device_free(device *dev)
{
    port_table_free(&dev->v4);
    port_table_free(&dev->v6);
    free(dev);
}

static int device_port_total(const device *dev)
{
    return dev->v4.count + dev->v6.count;
}

static pcdn_ip stat_device_ip(const port_stat *ps, bool v6)
{
    pcdn_ip ip;
    memset(&ip, 0, sizeof(ip));
    if (!ps->ip_valid)
        return ip;
    ip.valid = true;
    ip.v6 = v6 ? 1 : 0;
    memcpy(ip.b, ps->ip, v6 ? 16 : 4);
    return ip;
}

/* ------------------------------------------------------------------ */
/* 端口淘汰                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    port_entry *entry;
    bool v6;
    int bucket;
    int peers;
    int64_t last_active;
} port_candidate;

static int expiry_bucket(int64_t now_ns, int64_t last_active_ns, int64_t window_ns)
{
    if (window_ns <= 0)
        return 0;
    int64_t remaining = window_ns - (now_ns - last_active_ns);
    if (remaining <= 0)
        return 0;
    int b = (int)(remaining * EXPIRY_BUCKETS / window_ns);
    if (b >= EXPIRY_BUCKETS)
        b = EXPIRY_BUCKETS - 1;
    return b;
}

static int cmp_candidate(const void *pa, const void *pb)
{
    const port_candidate *a = pa, *b = pb;
    if (a->bucket != b->bucket)
        return a->bucket - b->bucket;
    if (a->peers != b->peers)
        return a->peers - b->peers;
    if (a->last_active != b->last_active)
        return (a->last_active > b->last_active) - (a->last_active < b->last_active);
    if (a->entry->port != b->entry->port)
        return (int)a->entry->port - (int)b->entry->port;
    if (a->entry->proto != b->entry->proto)
        return (int)a->entry->proto - (int)b->entry->proto;
    return (int)a->v6 - (int)b->v6;
}

static int device_evict_ports(detector *d, device *dev, int64_t now_ns, int quota)
{
    if (quota <= 0)
        return 0;
    size_t cap = (size_t)device_port_total(dev);
    port_candidate *cands = cap ? xmalloc(cap * sizeof(*cands)) : NULL;
    size_t n = 0;
    for (int pass = 0; pass < 2; pass++) {
        port_table *t = pass == 0 ? &dev->v4 : &dev->v6;
        for (port_entry *e = t->head; e; e = e->hh.next) {
            if (e->stat->alert_start_ns != 0)
                continue;
            cands[n].entry = e;
            cands[n].v6 = pass == 1;
            cands[n].bucket = expiry_bucket(now_ns, e->stat->last_active_ns, d->window);
            cands[n].peers = e->stat->peers.count;
            cands[n].last_active = e->stat->last_active_ns;
            n++;
        }
    }
    if (n == 0) {
        free(cands);
        return 0;
    }
    qsort(cands, n, sizeof(*cands), cmp_candidate);
    int removed = 0;
    for (size_t i = 0; i < n && removed < quota; i++) {
        port_table *t = cands[i].v6 ? &dev->v6 : &dev->v4;
        port_remove(t, cands[i].entry);
        removed++;
    }
    free(cands);
    return removed;
}

static bool make_port_room(detector *d, device *dev, int64_t now_ns)
{
    if (d->max_ports <= 0)
        return true;
    int total = device_port_total(dev);
    if (total < d->max_ports)
        return true;
    int quota = total * PORTS_EVICT_PERCENT / 100;
    if (quota < 1)
        quota = 1;
    int n = device_evict_ports(d, dev, now_ns, quota);
    d->port_evictions += n;
    return n > 0;
}

/* ------------------------------------------------------------------ */
/* 告警                                                                */
/* ------------------------------------------------------------------ */

static char *truncated_note(size_t total, size_t shown)
{
    if (total <= shown)
        return NULL;
    char buf[128];
    snprintf(buf, sizeof(buf), "（共 %zu 个，仅列前 %zu 个）", total, shown);
    return xstrdup(buf);
}

static void check_port(detector *d, device *dev, pcdn_mac mac, uint16_t port, uint8_t proto,
                       port_stat *ps, bool v6, int64_t now_ns)
{
    (void)dev;
    const char *pname = proto_name(proto);
    char macbuf[32], ipbuf[64], macmask[32], ipmask[64];
    mac_format(&mac, macbuf, sizeof(macbuf));
    mask_device_mac(d->hide, &mac, macmask, sizeof(macmask));
    pcdn_ip ip = stat_device_ip(ps, v6);
    ip_format(&ip, ipbuf, sizeof(ipbuf));
    mask_device_ip(d->hide, &ip, ipmask, sizeof(ipmask));

    if (ps->alert_start_ns == 0) {
        if (ps->peers.count < d->threshold)
            return;
        ps->alert_start_ns = now_ns;
        size_t nkeys = 0;
        uint8_t(*keys)[16] = peer_keys(&ps->peers, &nkeys);
        char total[64];
        fmt_duration(d->window, total, sizeof(total));
        size_t shown = 0;
        char *ips = format_peer_ips(keys, nkeys, v6 ? 16 : 4, ALERT_LOG_MAX_IPS, &shown);
        char *note = truncated_note(nkeys, shown);
        char up[32], down[32];
        human_bytes(ps->up_bytes, up, sizeof(up));
        human_bytes(ps->down_bytes, down, sizeof(down));
        d->alerts++;
        log_info("%s(%s) 的端口 %d(%s) 疑似产生PCDN行为（近 %s 内 %zu 个对端IP，累计上行 %s / "
                 "下行 %s），相关IP为%s: %s",
                 macmask, ipmask, port, pname, total, nkeys, up, down, note ? note : "", ips);
        free(note);
        free(ips);
        free(keys);
        if (d->sink && d->sink->on_alert_start)
            d->sink->on_alert_start(d->sink_ctx, macbuf, ipbuf, port, pname);
        if (d->low_memory) {
            ps->reported_count = (int)nkeys;
            peer_clear(&ps->peers);
        } else {
            ps->reported_count = peer_mark_all_reported(&ps->peers);
        }
        return;
    }

    if (ps->last_active_ns > ps->alert_start_ns)
        ps->alert_start_ns = ps->last_active_ns;

    if (now_ns - ps->alert_start_ns > d->alert_duration) {
        char up[32], down[32];
        human_bytes(ps->up_bytes, up, sizeof(up));
        human_bytes(ps->down_bytes, down, sizeof(down));
        log_info("%s(%s) 的端口 %d(%s) PCDN行为结束（本轮累计 %d 个对端IP，累计上行 %s / 下行 "
                 "%s）",
                 macmask, ipmask, port, pname, ps->reported_count, up, down);
        if (d->sink && d->sink->on_alert_end)
            d->sink->on_alert_end(d->sink_ctx, macbuf, ipbuf, port, pname);
        ps->alert_start_ns = 0;
        peer_clear_reported(&ps->peers);
        ps->reported_count = 0;
        return;
    }

    size_t nnew = 0;
    uint8_t(*newkeys)[16] = peer_collect_new(&ps->peers, &nnew);
    if (nnew == 0) {
        free(newkeys);
        return;
    }
    ps->reported_count += (int)nnew;
    size_t shown = 0;
    char *ips = format_peer_ips(newkeys, nnew, v6 ? 16 : 4, ALERT_LOG_MAX_IPS, &shown);
    char *note = truncated_note(nnew, shown);
    char up[32], down[32];
    human_bytes(ps->up_bytes, up, sizeof(up));
    human_bytes(ps->down_bytes, down, sizeof(down));
    d->alerts++;
    log_info("%s(%s) 的端口 %d(%s) 持续产生PCDN行为（本轮累计 %d 个对端IP，累计上行 %s / 下行 "
             "%s），新增相关IP为%s: %s",
             macmask, ipmask, port, pname, ps->reported_count, up, down, note ? note : "", ips);
    free(note);
    free(ips);
    free(newkeys);
}

static void scan_table(detector *d, device *dev, pcdn_mac mac, port_table *t, bool v6,
                       int64_t now_ns)
{
    if (t->count > t->peak)
        t->peak = t->count;
    port_entry *e, *tmp;
    HASH_ITER(hh, t->head, e, tmp)
    {
        peer_record_peak(&e->stat->peers);
        peer_evict(&e->stat->peers, now_ns, d->window);
        check_port(d, dev, mac, e->port, e->proto, e->stat, v6, now_ns);
        if (e->stat->peers.count == 0 && e->stat->alert_start_ns == 0) {
            HASH_DEL(t->head, e);
            peer_set_free(&e->stat->peers);
            free(e->stat);
            free(e);
            t->count--;
        } else {
            peer_compact(&e->stat->peers);
        }
    }
    port_table_compact(t);
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

detector *detector_create(int threshold, int64_t window, int64_t alert_duration,
                          device_filter *filter, bool hide, bool low_memory, int peer_limit,
                          int max_ports)
{
    detector *d = xcalloc(1, sizeof(*d));
    pthread_mutex_init(&d->mu, NULL);
    d->threshold = threshold;
    d->window = window;
    d->alert_duration = alert_duration;
    d->filter = filter;
    d->hide = hide;
    d->low_memory = low_memory;
    d->peer_limit = peer_limit;
    d->max_ports = max_ports;
    return d;
}

void detector_destroy(detector *d)
{
    if (!d)
        return;
    device *dev, *tmp;
    HASH_ITER(hh, d->devices, dev, tmp)
    {
        HASH_DEL(d->devices, dev);
        device_free(dev);
    }
    filter_free(d->filter);
    pthread_mutex_destroy(&d->mu);
    free(d);
}

void detector_set_sink(detector *d, const alert_sink *sink, void *ctx)
{
    pthread_mutex_lock(&d->mu);
    d->sink = sink;
    d->sink_ctx = ctx;
    pthread_mutex_unlock(&d->mu);
}

void detector_set_params(detector *d, int threshold, int64_t window, int64_t alert_duration)
{
    pthread_mutex_lock(&d->mu);
    d->threshold = threshold;
    if (d->peer_limit > 0 && d->peer_limit < threshold)
        d->peer_limit = threshold;
    d->window = window;
    d->alert_duration = alert_duration;
    pthread_mutex_unlock(&d->mu);
}

void detector_set_hide(detector *d, bool hide)
{
    pthread_mutex_lock(&d->mu);
    d->hide = hide;
    pthread_mutex_unlock(&d->mu);
}

void detector_set_low_memory(detector *d, bool low_memory)
{
    pthread_mutex_lock(&d->mu);
    d->low_memory = low_memory;
    pthread_mutex_unlock(&d->mu);
}

void detector_set_peer_limit(detector *d, int limit)
{
    pthread_mutex_lock(&d->mu);
    d->peer_limit = limit;
    pthread_mutex_unlock(&d->mu);
}

void detector_set_max_ports(detector *d, int limit)
{
    pthread_mutex_lock(&d->mu);
    d->max_ports = limit;
    pthread_mutex_unlock(&d->mu);
}

void detector_set_filter(detector *d, device_filter *filter)
{
    pthread_mutex_lock(&d->mu);
    device_filter *old = d->filter;
    d->filter = filter;
    pthread_mutex_unlock(&d->mu);
    filter_free(old);
}

/* ------------------------------------------------------------------ */
/* 观测                                                                */
/* ------------------------------------------------------------------ */

static void drop_new_port(detector *d, const observation *o)
{
    d->port_drops++;
    if (d->port_drops != 1 && d->port_drops % DROP_LOG_EVERY != 0)
        return;
    char mac[32], ip[64], macm[32], ipm[64];
    mac_format(&o->mac, mac, sizeof(mac));
    ip_format(&o->ip, ip, sizeof(ip));
    mask_device_mac(d->hide, &o->mac, macm, sizeof(macm));
    mask_device_ip(d->hide, &o->ip, ipm, sizeof(ipm));
    log_warn("%s(%s) 的端口 %d(%s) 因端口条目达到上限（每设备 %d 个）且无端口可提前过期被丢弃"
             "（累计丢弃 %" PRId64 " 个报文）",
             macm, ipm, o->local_port, proto_name(o->proto), d->max_ports, d->port_drops);
}

void detector_observe(detector *d, const observation *o)
{
    pthread_mutex_lock(&d->mu);
    if (!filter_allow_key(d->filter, o->mac, o->local_port)) {
        pthread_mutex_unlock(&d->mu);
        return;
    }
    device *dev = device_get(d, o->mac);
    port_table *t = o->v6 ? &dev->v6 : &dev->v4;
    port_entry *e = port_find(t, o->local_port, o->proto);
    if (!e) {
        if (!make_port_room(d, dev, o->ts_ns)) {
            drop_new_port(d, o);
            pthread_mutex_unlock(&d->mu);
            return;
        }
        e = port_create(t, o->local_port, o->proto, o->v6);
    }
    port_stat *ps = e->stat;
    if (o->ip.valid) {
        memset(ps->ip, 0, sizeof(ps->ip));
        memcpy(ps->ip, o->ip.b, o->v6 ? 16 : 4);
        ps->ip_valid = true;
    }
    ps->last_active_ns = o->ts_ns;

    if (d->low_memory && ps->alert_start_ns != 0) {
        if (o->up)
            ps->up_bytes += (uint64_t)o->length;
        else
            ps->down_bytes += (uint64_t)o->length;
        pthread_mutex_unlock(&d->mu);
        return;
    }

    uint8_t key[16] = {0};
    size_t keylen = o->v6 ? 16 : 4;
    memcpy(key, o->remote_ip.b, keylen);
    peer_entry *p = peer_find(&ps->peers, key);
    if (!p && d->peer_limit > 0 && ps->peers.count >= d->peer_limit) {
        if (o->up)
            ps->up_bytes += (uint64_t)o->length;
        else
            ps->down_bytes += (uint64_t)o->length;
        pthread_mutex_unlock(&d->mu);
        return;
    }
    peer_touch(&ps->peers, key, o->ts_ns);
    if (o->up)
        ps->up_bytes += (uint64_t)o->length;
    else
        ps->down_bytes += (uint64_t)o->length;
    pthread_mutex_unlock(&d->mu);
}

/* ------------------------------------------------------------------ */
/* 扫描                                                                */
/* ------------------------------------------------------------------ */

void detector_scan(detector *d, int64_t now_ns)
{
    pthread_mutex_lock(&d->mu);
    int ndev = HASH_COUNT(d->devices);
    if (ndev > d->devices_peak)
        d->devices_peak = ndev;

    device *dev, *tmp;
    HASH_ITER(hh, d->devices, dev, tmp)
    {
        scan_table(d, dev, dev->mac, &dev->v4, false, now_ns);
        scan_table(d, dev, dev->mac, &dev->v6, true, now_ns);
        if (d->max_ports > 0) {
            int total = device_port_total(dev);
            if (total > d->max_ports) {
                int n = device_evict_ports(d, dev, now_ns, total - d->max_ports);
                d->port_evictions += n;
            }
        }
        if (dev->v4.count == 0 && dev->v6.count == 0) {
            HASH_DEL(d->devices, dev);
            device_free(dev);
        }
    }

    int count = HASH_COUNT(d->devices);
    if (d->devices_peak >= MIN_COMPACT_PEAK && count * COMPACT_RATIO <= d->devices_peak) {
        size_t n = (size_t)count;
        device **items = n ? xmalloc(n * sizeof(device *)) : NULL;
        size_t i = 0;
        for (device *x = d->devices; x; x = x->hh.next)
            items[i++] = x;
        HASH_CLEAR(hh, d->devices);
        d->devices = NULL;
        for (i = 0; i < n; i++) {
            memset(&items[i]->hh, 0, sizeof(items[i]->hh));
            HASH_ADD(hh, d->devices, mac, sizeof(items[i]->mac), items[i]);
        }
        free(items);
        d->devices_peak = count;
    }
    pthread_mutex_unlock(&d->mu);
}

void detector_counts(detector *d, int *devices, int *alerts)
{
    pthread_mutex_lock(&d->mu);
    if (devices)
        *devices = HASH_COUNT(d->devices);
    if (alerts)
        *alerts = d->alerts;
    pthread_mutex_unlock(&d->mu);
}

void detector_summary(detector *d)
{
    pthread_mutex_lock(&d->mu);
    log_info("统计：当前跟踪设备 %d 个，累计告警 %d 次；端口上限提前过期 %" PRId64
             " 个端口、丢弃 %" PRId64 " 个新端口报文",
             HASH_COUNT(d->devices), d->alerts, d->port_evictions, d->port_drops);
    pthread_mutex_unlock(&d->mu);
}

/* ------------------------------------------------------------------ */
/* 快照（HTTP API）                                                    */
/* ------------------------------------------------------------------ */

static int cmp_device_summary(const void *a, const void *b)
{
    const detector_device_summary *x = a, *y = b;
    return strcmp(x->mac, y->mac);
}

static void fam_stat_add(detector_fam_stat *s, uint8_t proto, bool banned)
{
    s->ports++;
    if (banned)
        s->banned++;
    if (proto == PROTO_TCP) {
        s->tcp_ports++;
        if (banned)
            s->tcp_banned++;
    } else {
        s->udp_ports++;
        if (banned)
            s->udp_banned++;
    }
}

void detector_overview_free(detector_overview *ov)
{
    if (!ov)
        return;
    free(ov->devices);
    memset(ov, 0, sizeof(*ov));
}

void detector_overview_get(detector *d, detector_banned_fn banned_fn, void *ctx,
                           detector_overview *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&d->mu);
    int ndev = HASH_COUNT(d->devices);
    out->tracked_devices = ndev;
    out->alerts = d->alerts;
    out->port_evictions = d->port_evictions;
    out->port_drops = d->port_drops;
    size_t n = ndev > 0 ? (size_t)ndev : 0;
    out->devices = n ? xcalloc(n, sizeof(*out->devices)) : NULL;
    out->ndevices = 0;
    for (device *dev = d->devices; dev; dev = dev->hh.next) {
        detector_device_summary *dst = &out->devices[out->ndevices++];
        mac_format(&dev->mac, dst->mac, sizeof(dst->mac));
        for (int pass = 0; pass < 2; pass++) {
            port_table *t = pass == 0 ? &dev->v4 : &dev->v6;
            detector_fam_stat *st = pass == 0 ? &dst->v4 : &dst->v6;
            for (port_entry *e = t->head; e; e = e->hh.next) {
                bool banned =
                    banned_fn ? banned_fn(ctx, dst->mac, e->port, e->proto, pass == 1) : false;
                fam_stat_add(st, e->proto, banned);
            }
        }
    }
    pthread_mutex_unlock(&d->mu);
    if (out->ndevices > 1)
        qsort(out->devices, out->ndevices, sizeof(*out->devices), cmp_device_summary);
}

void detector_device_view_free(detector_device_view *v)
{
    if (!v)
        return;
    free(v->ports);
    memset(v, 0, sizeof(*v));
}

static int cmp_port_view(const void *a, const void *b)
{
    const port_view *x = a, *y = b;
    if (x->port != y->port)
        return (int)x->port - (int)y->port;
    if (x->proto != y->proto)
        return (int)x->proto - (int)y->proto;
    return (int)x->v6 - (int)y->v6;
}

bool detector_device_snapshot(detector *d, pcdn_mac mac, detector_device_view *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&d->mu);
    device *dev = device_find(d, mac);
    if (!dev) {
        pthread_mutex_unlock(&d->mu);
        return false;
    }
    mac_format(&dev->mac, out->mac, sizeof(out->mac));
    size_t total = (size_t)device_port_total(dev);
    out->ports = total ? xcalloc(total, sizeof(port_view)) : NULL;
    out->nports = 0;
    for (int pass = 0; pass < 2; pass++) {
        port_table *t = pass == 0 ? &dev->v4 : &dev->v6;
        for (port_entry *e = t->head; e; e = e->hh.next) {
            port_view *v = &out->ports[out->nports++];
            v->port = e->port;
            v->proto = e->proto;
            v->v6 = pass == 1;
            v->peer_count = e->stat->peers.count;
            v->up_bytes = e->stat->up_bytes;
            v->down_bytes = e->stat->down_bytes;
            v->alerting = e->stat->alert_start_ns != 0;
        }
    }
    pthread_mutex_unlock(&d->mu);
    if (out->nports > 1)
        qsort(out->ports, out->nports, sizeof(port_view), cmp_port_view);
    return true;
}

void detector_peer_view_free(detector_peer_view *v)
{
    if (!v)
        return;
    for (size_t i = 0; i < v->nips; i++)
        free(v->ips[i]);
    free(v->ips);
    memset(v, 0, sizeof(*v));
}

bool detector_peers_page(detector *d, pcdn_mac mac, uint16_t port, uint8_t proto, bool v6,
                         int64_t offset, int limit, detector_peer_view *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&d->mu);
    device *dev = device_find(d, mac);
    if (!dev) {
        pthread_mutex_unlock(&d->mu);
        return false;
    }
    port_table *t = v6 ? &dev->v6 : &dev->v4;
    port_entry *e = port_find(t, port, proto);
    if (!e) {
        pthread_mutex_unlock(&d->mu);
        return false;
    }
    size_t nkeys = 0;
    uint8_t(*keys)[16] = peer_keys(&e->stat->peers, &nkeys);
    int total = e->stat->peers.count;
    pthread_mutex_unlock(&d->mu);

    out->port = port;
    out->proto = proto;
    out->v6 = v6;
    out->peer_count = total;
    if (offset < 0)
        offset = 0;
    if (offset >= (int64_t)nkeys || nkeys == 0) {
        free(keys);
        out->ips = NULL;
        out->nips = 0;
        out->truncated = false;
        return true;
    }
    g_sort_keylen = v6 ? 16 : 4;
    qsort(keys, nkeys, 16, cmp_peer_key);
    size_t start = (size_t)offset;
    size_t take = nkeys - start;
    if (limit > 0 && take > (size_t)limit)
        take = (size_t)limit;
    out->ips = take ? xmalloc(take * sizeof(char *)) : NULL;
    out->nips = 0;
    for (size_t i = 0; i < take; i++) {
        char buf[64];
        format_peer_key(keys[start + i], v6 ? 16 : 4, buf, sizeof(buf));
        out->ips[out->nips++] = xstrdup(buf);
    }
    out->truncated = start + take < nkeys;
    free(keys);
    return true;
}

/* ------------------------------------------------------------------ */
/* 状态导出 / 恢复                                                     */
/* ------------------------------------------------------------------ */

bool detector_alert_sessions(detector *d, state_session **out, size_t *n)
{
    *out = NULL;
    *n = 0;
    pthread_mutex_lock(&d->mu);
    size_t count = 0;
    for (device *dev = d->devices; dev; dev = dev->hh.next) {
        for (port_entry *e = dev->v4.head; e; e = e->hh.next)
            if (e->stat->alert_start_ns != 0)
                count++;
        for (port_entry *e = dev->v6.head; e; e = e->hh.next)
            if (e->stat->alert_start_ns != 0)
                count++;
    }
    state_session *arr = count ? xcalloc(count, sizeof(*arr)) : NULL;
    size_t idx = 0;
    for (device *dev = d->devices; dev; dev = dev->hh.next) {
        for (int pass = 0; pass < 2; pass++) {
            port_table *t = pass == 0 ? &dev->v4 : &dev->v6;
            for (port_entry *e = t->head; e; e = e->hh.next) {
                if (e->stat->alert_start_ns == 0)
                    continue;
                state_session *s = &arr[idx++];
                s->mac = dev->mac;
                s->port = e->port;
                s->proto = e->proto;
                s->v6 = pass == 1;
                s->ip = stat_device_ip(e->stat, pass == 1);
                s->alert_start_ns = e->stat->alert_start_ns;
                s->last_active_ns = e->stat->last_active_ns;
                s->reported_count = e->stat->reported_count;
            }
        }
    }
    pthread_mutex_unlock(&d->mu);
    *out = arr;
    *n = idx;
    return true;
}

void detector_restore_sessions(detector *d, const state_session *sessions, size_t n)
{
    if (n == 0)
        return;
    pthread_mutex_lock(&d->mu);
    for (size_t i = 0; i < n; i++) {
        const state_session *s = &sessions[i];
        device *dev = device_get(d, s->mac);
        port_table *t = s->v6 ? &dev->v6 : &dev->v4;
        port_entry *e = port_find(t, s->port, s->proto);
        if (!e)
            e = port_create(t, s->port, s->proto, s->v6);
        port_stat *ps = e->stat;
        memset(ps->ip, 0, sizeof(ps->ip));
        if (s->ip.valid)
            memcpy(ps->ip, s->ip.b, s->v6 ? 16 : 4);
        ps->ip_valid = s->ip.valid;
        ps->alert_start_ns = s->alert_start_ns;
        ps->last_active_ns = s->last_active_ns;
        ps->reported_count = s->reported_count;
    }
    pthread_mutex_unlock(&d->mu);
}
