#include "blocker.h"

#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>

#include "uthash.h"
#include "util.h"

#define QUEUE_CAP 256
#define PROTO_UDP "udp"
#define PROTO_TCP "tcp"
#define PROTO_UDP_ID 17

/* IPv6 文本最长 45 字节（含 NUL 46），ban_state 与格式化缓冲统一用它 */
#define IPS_TEXT_MAX 46
#define PROTO_TCP_ID 6

/* 队列元素只存二进制地址：256 项 × 28B = 7KiB（原来是 × 90B ≈ 23KiB）。
 * 出队后再格式化回字符串，代价是每条事件一次 mac_format / ip_format。 */
typedef struct {
    pcdn_mac mac;
    uint16_t port;
    pcdn_ip ip;
    uint8_t proto; /* PROTO_UDP_ID / PROTO_TCP_ID */
    bool ban;
} block_event;

/* key 实际最长 "aa:bb:cc:dd:ee:ff:65535:udp:v6" = 30B，ips 最长 IPv6 文本 45B：
 * 收紧后整条约 232B（glibc chunk 240，原 320B → 336），封禁条目多时收益明显。 */
typedef struct ban_state {
    char key[48];
    char mac[18];
    char proto[4];
    char ips[2][IPS_TEXT_MAX];
    uint16_t port;
    uint32_t refs[2];
    uint8_t fam;
    uint8_t last;
    bool applied;
    UT_hash_handle hh;
} ban_state;

typedef struct {
    char key[32]; /* mac:port */
    char mac[18];
    uint16_t port;
    int refs;
    UT_hash_handle hh;
} port_ref;

typedef struct {
    char key[18];
    UT_hash_handle hh;
} str_set;

typedef struct {
    char key[18];
    char val[64];
    UT_hash_handle hh;
} str_val;

struct blocker {
    firewall *fw;
    atomic_bool hide; /* 热更新线程写，worker 线程读 */

    pthread_t worker;
    bool worker_started;
    pthread_t refresher;
    bool refresher_started;

    pthread_mutex_t qmu;
    pthread_cond_t qcond;
    block_event queue[QUEUE_CAP];
    int qhead;
    int qtail;
    int qcount;
    bool stopping;
    bool closed;

    pthread_mutex_t mu;
    ban_state *active;
    port_ref *ports;
    str_set *full_banned;
    str_set *upnp_blocked;
    str_set *upnp_allowed;
    bool upnp_all;
    str_val *dev_ip;

    bool fb_enabled;
    char fb_mode[16];
    int fb_threshold;
    str_set *fb_devices;

    /* 当前名单（持有一份引用）：热重载后新名单已排除的端口不再封禁，
     * 已存在的封禁由 blocker_set_filter 解封。 */
    device_filter *filter;

    bool up_enabled;
    bool up_block_all;
    str_set *up_targets;
};

/* ------------------------------------------------------------------ */
/* 集合辅助                                                            */
/* ------------------------------------------------------------------ */

static bool set_contains(str_set *s, const char *key)
{
    str_set *e = NULL;
    HASH_FIND_STR(s, key, e);
    return e != NULL;
}

static void set_add(str_set **s, const char *key)
{
    if (set_contains(*s, key))
        return;
    str_set *e = xcalloc(1, sizeof(*e));
    snprintf(e->key, sizeof(e->key), "%s", key);
    HASH_ADD_STR(*s, key, e);
}

static void set_del(str_set **s, const char *key)
{
    str_set *e = NULL;
    HASH_FIND_STR(*s, key, e);
    if (e) {
        HASH_DEL(*s, e);
        free(e);
    }
}

static void set_free(str_set **s)
{
    str_set *e, *tmp;
    HASH_ITER(hh, *s, e, tmp)
    {
        HASH_DEL(*s, e);
        free(e);
    }
    *s = NULL;
}

static void set_keys(str_set *s, char ***out, size_t *n)
{
    *out = NULL;
    *n = 0;
    size_t count = HASH_COUNT(s);
    if (count == 0)
        return;
    char **arr = xmalloc(count * sizeof(char *));
    size_t i = 0;
    for (str_set *e = s; e; e = e->hh.next)
        arr[i++] = xstrdup(e->key);
    *out = arr;
    *n = i;
}

static const char *dev_ip_get_nolock(blocker *b, const char *mac)
{
    str_val *e = NULL;
    HASH_FIND_STR(b->dev_ip, mac, e);
    return e ? e->val : "";
}

/* 内部缓冲会被 worker 线程并发改写，必须在锁内拷贝到调用方缓冲后再使用 */
static void dev_ip_copy(blocker *b, const char *mac, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    pthread_mutex_lock(&b->mu);
    str_val *e = NULL;
    HASH_FIND_STR(b->dev_ip, mac, e);
    snprintf(out, cap, "%s", e ? e->val : "");
    pthread_mutex_unlock(&b->mu);
}

static void dev_ip_set(blocker *b, const char *mac, const char *ip)
{
    if (!ip || !ip[0])
        return;
    str_val *e = NULL;
    HASH_FIND_STR(b->dev_ip, mac, e);
    if (!e) {
        e = xcalloc(1, sizeof(*e));
        snprintf(e->key, sizeof(e->key), "%s", mac);
        HASH_ADD_STR(b->dev_ip, key, e);
    }
    snprintf(e->val, sizeof(e->val), "%s", ip);
}

static void fmt_masked(bool hide, const char *mac, const char *ip, char *mb, size_t mcap,
                       char *ib, size_t icap)
{
    char e[128];
    pcdn_mac m;
    if (mac && mac_parse(mac, &m, e, sizeof(e)))
        mask_device_mac(hide, &m, mb, mcap);
    else
        snprintf(mb, mcap, "%s", mac ? mac : "");
    if (ip && ip[0]) {
        pcdn_ip a;
        if (ip_parse(ip, &a, e, sizeof(e)))
            mask_device_ip(hide, &a, ib, icap);
        else
            snprintf(ib, icap, "%s", ip);
    } else {
        if (icap)
            ib[0] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* 引用计数                                                            */
/* ------------------------------------------------------------------ */

static int fam_idx(const char *ip)
{
    return (ip && strchr(ip, ':')) ? 1 : 0;
}

static const char *fam_name(int idx)
{
    return idx == 1 ? "v6" : "v4";
}

static const char *proto_name(uint8_t proto)
{
    return proto == PROTO_TCP_ID ? PROTO_TCP : PROTO_UDP;
}

static int state_total(const ban_state *st)
{
    return (int)st->refs[0] + (int)st->refs[1];
}

static const char *state_ip(const ban_state *st)
{
    return st->ips[st->last];
}

static void make_port_key(const char *mac, uint16_t port, char *buf, size_t cap)
{
    snprintf(buf, cap, "%s:%u", mac, port);
}

static void bump_port_locked(blocker *b, const char *mac, uint16_t port, int delta)
{
    char key[32];
    make_port_key(mac, port, key, sizeof(key));
    port_ref *e = NULL;
    HASH_FIND_STR(b->ports, key, e);
    if (!e) {
        if (delta <= 0)
            return;
        e = xcalloc(1, sizeof(*e));
        snprintf(e->key, sizeof(e->key), "%s", key);
        snprintf(e->mac, sizeof(e->mac), "%s", mac);
        e->port = port;
        HASH_ADD_STR(b->ports, key, e);
    }
    e->refs += delta;
    if (e->refs <= 0) {
        HASH_DEL(b->ports, e);
        free(e);
    }
}

static int dev_port_count_locked(blocker *b, const char *mac)
{
    int n = 0;
    for (port_ref *e = b->ports; e; e = e->hh.next) {
        if (strcmp(e->mac, mac) == 0 && e->refs > 0)
            n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* 日志 / 下发                                                         */
/* ------------------------------------------------------------------ */

static int apply_one(blocker *b, bool ban, const char *mac, const char *ip, uint16_t port,
                     const char *proto)
{
    char mb[64], ib[64];
    fmt_masked(atomic_load(&b->hide), mac, ip, mb, sizeof(mb), ib, sizeof(ib));
    char label[8];
    snprintf(label, sizeof(label), "%s", proto);
    for (char *p = label; *p; p++)
        *p = (char)toupper((unsigned char)*p);
    int rc = ban ? firewall_ban(b->fw, mac, ip, port, proto)
                 : firewall_unban(b->fw, mac, ip, port, proto);
    if (rc != 0) {
        log_error("%s设备 %s(%s) 的 %s 端口 %d 失败", ban ? "封禁" : "解封", mb, ib, label, port);
        return -1;
    }
    log_info("已%s设备 %s(%s) 的 %s 端口 %d", ban ? "封禁" : "解封", mb, ib, label, port);
    return 0;
}

static void apply_full(blocker *b, bool ban, const char *mac, const char *ip);

static void remove_redundant_port_rules(blocker *b, const char *mac)
{
    struct {
        char ip[64];
        uint16_t port;
        char proto[4];
    } *entries = NULL;
    size_t n = 0;
    pthread_mutex_lock(&b->mu);
    for (ban_state *st = b->active; st; st = st->hh.next) {
        if (strcmp(st->mac, mac) != 0 || !st->applied || strcmp(st->proto, PROTO_UDP) != 0)
            continue;
        st->applied = false;
        entries = xrealloc(entries, (n + 1) * sizeof(*entries));
        snprintf(entries[n].ip, sizeof(entries[n].ip), "%s", state_ip(st));
        entries[n].port = st->port;
        snprintf(entries[n].proto, sizeof(entries[n].proto), "%s", st->proto);
        n++;
    }
    pthread_mutex_unlock(&b->mu);
    for (size_t i = 0; i < n; i++)
        apply_one(b, false, mac, entries[i].ip, entries[i].port, entries[i].proto);
    free(entries);
}

static bool fullban_applies(blocker *b, const char *mac)
{
    if (!b->fb_enabled || !b->fw || !firewall_fullban_enabled(b->fw))
        return false;
    if (strcmp(b->fb_mode, "device") == 0)
        return set_contains(b->fb_devices, mac);
    return true;
}

static void apply_full(blocker *b, bool ban, const char *mac, const char *ip)
{
    char mb[64], ib[64];
    fmt_masked(atomic_load(&b->hide), mac, ip, mb, sizeof(mb), ib, sizeof(ib));
    if (ban) {
        if (firewall_full_ban(b->fw, mac, ip) != 0) {
            log_error("对设备 %s 执行全 UDP 端口封禁失败", mb);
            pthread_mutex_lock(&b->mu);
            set_del(&b->full_banned, mac);
            pthread_mutex_unlock(&b->mu);
            return;
        }
        size_t n = 0;
        const uint16_t *ports = firewall_fullban_allow_ports(b->fw, &n);
        strbuf sb;
        sb_init(&sb);
        for (size_t i = 0; i < n; i++)
            sb_addf(&sb, "%s%u", i ? "," : "", ports[i]);
        log_info("设备 %s 被封禁端口数达到 %d，已执行全 UDP 端口封禁（仅放行端口：%s）", mb,
                 b->fb_threshold, sb.p ? sb.p : "");
        sb_free(&sb);
        remove_redundant_port_rules(b, mac);
        return;
    }
    if (firewall_full_unban(b->fw, mac, ip) != 0) {
        log_error("解除设备 %s 的全 UDP 端口封禁失败", mb);
        return;
    }
    log_info("设备 %s 已无被封禁端口，已解除全 UDP 端口封禁", mb);
}

static void maybe_full_ban(blocker *b, const char *mac, const char *ip)
{
    if (!fullban_applies(b, mac))
        return;
    pthread_mutex_lock(&b->mu);
    int count = dev_port_count_locked(b, mac);
    bool active = set_contains(b->full_banned, mac);
    bool do_ban = false, do_unban = false;
    if (!active && count >= b->fb_threshold) {
        set_add(&b->full_banned, mac);
        do_ban = true;
    } else if (active && count == 0) {
        set_del(&b->full_banned, mac);
        do_unban = true;
    }
    pthread_mutex_unlock(&b->mu);
    if (do_ban)
        apply_full(b, true, mac, ip);
    else if (do_unban)
        apply_full(b, false, mac, ip);
}

static bool upnp_active(blocker *b)
{
    return b->up_enabled && b->fw && firewall_upnp_enabled(b->fw);
}

static bool apply_upnp_ban(blocker *b, bool ban, const char *mac)
{
    if (!upnp_active(b))
        return false;
    pthread_mutex_lock(&b->mu);
    bool already = set_contains(b->upnp_blocked, mac);
    pthread_mutex_unlock(&b->mu);
    if (ban == already)
        return false;

    char mb[64], ib[64], ip[64];
    dev_ip_copy(b, mac, ip, sizeof(ip));
    fmt_masked(atomic_load(&b->hide), mac, ip, mb, sizeof(mb), ib, sizeof(ib));
    if (ban) {
        if (firewall_upnp_ban(b->fw, mac, ip) != 0) {
            log_error("拦截设备 %s 的 UPnP 请求失败", mb);
            return false;
        }
        pthread_mutex_lock(&b->mu);
        set_add(&b->upnp_blocked, mac);
        pthread_mutex_unlock(&b->mu);
        log_info("已拦截设备 %s 的 UPnP 请求", mb);
        return true;
    }
    if (firewall_upnp_unban(b->fw, mac, ip) != 0) {
        log_error("解除设备 %s 的 UPnP 拦截失败", mb);
        return false;
    }
    pthread_mutex_lock(&b->mu);
    set_del(&b->upnp_blocked, mac);
    pthread_mutex_unlock(&b->mu);
    log_info("已解除设备 %s 的 UPnP 拦截", mb);
    return true;
}

static bool apply_upnp_allow(blocker *b, bool allow, const char *mac)
{
    if (!upnp_active(b))
        return false;
    pthread_mutex_lock(&b->mu);
    bool already = set_contains(b->upnp_allowed, mac);
    pthread_mutex_unlock(&b->mu);
    if (allow == already)
        return false;

    char mb[64], ib[64], ip[64];
    dev_ip_copy(b, mac, ip, sizeof(ip));
    fmt_masked(atomic_load(&b->hide), mac, ip, mb, sizeof(mb), ib, sizeof(ib));
    if (allow) {
        if (firewall_upnp_allow(b->fw, mac, ip) != 0) {
            log_error("放行设备 %s 的 UPnP 请求失败", mb);
            return false;
        }
        pthread_mutex_lock(&b->mu);
        set_add(&b->upnp_allowed, mac);
        pthread_mutex_unlock(&b->mu);
        log_info("已放行设备 %s 的 UPnP 请求", mb);
        return true;
    }
    if (firewall_upnp_disallow(b->fw, mac, ip) != 0) {
        log_error("取消设备 %s 的 UPnP 放行失败", mb);
        return false;
    }
    pthread_mutex_lock(&b->mu);
    set_del(&b->upnp_allowed, mac);
    pthread_mutex_unlock(&b->mu);
    log_info("已取消设备 %s 的 UPnP 放行", mb);
    return true;
}

static void apply_static_upnp(blocker *b)
{
    if (!upnp_active(b))
        return;
    if (b->up_block_all) {
        if (firewall_upnp_block_all(b->fw) != 0) {
            log_error("拦截全部 UPnP 请求失败");
        } else {
            pthread_mutex_lock(&b->mu);
            b->upnp_all = true;
            pthread_mutex_unlock(&b->mu);
            log_info("已拦截全部进入路由器的 UPnP 请求");
        }
        for (str_set *e = b->up_targets; e; e = e->hh.next)
            apply_upnp_allow(b, true, e->key);
        return;
    }
    for (str_set *e = b->up_targets; e; e = e->hh.next)
        apply_upnp_ban(b, true, e->key);
}

/* ------------------------------------------------------------------ */
/* 事件处理                                                            */
/* ------------------------------------------------------------------ */

static void enqueue(blocker *b, const block_event *ev)
{
    pthread_mutex_lock(&b->qmu);
    if (b->qcount >= QUEUE_CAP) {
        pthread_mutex_unlock(&b->qmu);
        char macstr[18], ipstr[64], mb[64], ib[64];
        mac_format(&ev->mac, macstr, sizeof(macstr));
        ip_format(&ev->ip, ipstr, sizeof(ipstr));
        fmt_masked(atomic_load(&b->hide), macstr, ipstr, mb, sizeof(mb), ib, sizeof(ib));
        log_warn("警告：封禁事件队列已满，丢弃 %s:%u 的事件", mb, ev->port);
        return;
    }
    b->queue[b->qtail] = *ev;
    b->qtail = (b->qtail + 1) % QUEUE_CAP;
    b->qcount++;
    pthread_cond_signal(&b->qcond);
    pthread_mutex_unlock(&b->qmu);
}

static void handle_event(blocker *b, const block_event *ev)
{
    char macstr[18], ipstr[IPS_TEXT_MAX];
    mac_format(&ev->mac, macstr, sizeof(macstr));
    ip_format(&ev->ip, ipstr, sizeof(ipstr));
    const char *ev_proto = proto_name(ev->proto);

    char key[96];
    if (firewall_ban_both(b->fw))
        snprintf(key, sizeof(key), "%s:%u:%s", macstr, ev->port, ev_proto);
    else
        snprintf(key, sizeof(key), "%s:%u:%s:%s", macstr, ev->port, ev_proto,
                 firewall_addr_family(ipstr));

    pthread_mutex_lock(&b->mu);
    /* 名单已排除的端口不再下发封禁（解封事件照常处理，避免旧封禁残留）。 */
    if (ev->ban && !filter_allow_key(b->filter, ev->mac, ev->port)) {
        pthread_mutex_unlock(&b->mu);
        return;
    }
    ban_state *st = NULL;
    HASH_FIND_STR(b->active, key, st);
    if (ev->ban) {
        int i = fam_idx(ipstr);
        if (!st) {
            st = xcalloc(1, sizeof(*st));
            snprintf(st->key, sizeof(st->key), "%s", key);
            snprintf(st->mac, sizeof(st->mac), "%s", macstr);
            snprintf(st->proto, sizeof(st->proto), "%s", ev_proto);
            st->port = ev->port;
            st->fam = (uint8_t)i;
            HASH_ADD_STR(b->active, key, st);
            bump_port_locked(b, macstr, ev->port, 1);
        }
        st->refs[i]++;
        snprintf(st->ips[i], sizeof(st->ips[i]), "%s", ipstr);
        st->last = (uint8_t)i;
        dev_ip_set(b, macstr, ipstr);
        bool first = state_total(st) == 1;
        bool full = ev->proto == PROTO_UDP_ID && set_contains(b->full_banned, macstr);
        if (first)
            st->applied = !full;
        pthread_mutex_unlock(&b->mu);

        if (first && !full)
            apply_one(b, true, macstr, ipstr, ev->port, ev_proto);
        maybe_full_ban(b, macstr, ipstr);
        return;
    }

    if (!st) {
        pthread_mutex_unlock(&b->mu);
        return;
    }
    int i = fam_idx(ipstr);
    if (st->refs[i] > 0)
        st->refs[i]--;
    else if (st->refs[1 - i] > 0)
        st->refs[1 - i]--;
    bool last = state_total(st) <= 0;
    char st_ip[64], st_proto[4];
    bool applied = st->applied;
    snprintf(st_ip, sizeof(st_ip), "%s", state_ip(st));
    snprintf(st_proto, sizeof(st_proto), "%s", st->proto);
    if (last) {
        HASH_DEL(b->active, st);
        free(st);
        bump_port_locked(b, macstr, ev->port, -1);
    }
    pthread_mutex_unlock(&b->mu);

    if (last && applied)
        apply_one(b, false, macstr, st_ip, ev->port, st_proto);
    maybe_full_ban(b, macstr, ipstr);
}

static void *worker_main(void *arg)
{
    blocker *b = arg;
    for (;;) {
        pthread_mutex_lock(&b->qmu);
        while (b->qcount == 0 && !b->stopping)
            pthread_cond_wait(&b->qcond, &b->qmu);
        if (b->stopping) {
            pthread_mutex_unlock(&b->qmu);
            return NULL;
        }
        block_event ev = b->queue[b->qhead];
        b->qhead = (b->qhead + 1) % QUEUE_CAP;
        b->qcount--;
        pthread_mutex_unlock(&b->qmu);
        handle_event(b, &ev);
    }
}

/* ------------------------------------------------------------------ */
/* 兜底解封 / 刷新                                                     */
/* ------------------------------------------------------------------ */

static void refresh_bans(blocker *b)
{
    if (!b->fw || firewall_ban_ttl(b->fw) <= 0)
        return;
    typedef struct {
        char mac[18];
        char ip[64];
        uint16_t port;
        char proto[4];
        bool full;
    } entry;
    entry *list = NULL;
    size_t n = 0;
    pthread_mutex_lock(&b->mu);
    for (ban_state *st = b->active; st; st = st->hh.next) {
        if (!st->applied)
            continue;
        list = xrealloc(list, (n + 1) * sizeof(*list));
        snprintf(list[n].mac, sizeof(list[n].mac), "%s", st->mac);
        snprintf(list[n].ip, sizeof(list[n].ip), "%s", state_ip(st));
        list[n].port = st->port;
        snprintf(list[n].proto, sizeof(list[n].proto), "%s", st->proto);
        list[n].full = false;
        n++;
    }
    for (str_set *e = b->full_banned; e; e = e->hh.next) {
        list = xrealloc(list, (n + 1) * sizeof(*list));
        snprintf(list[n].mac, sizeof(list[n].mac), "%s", e->key);
        snprintf(list[n].ip, sizeof(list[n].ip), "%s", dev_ip_get_nolock(b, e->key));
        list[n].port = 0;
        list[n].proto[0] = '\0';
        list[n].full = true;
        n++;
    }
    pthread_mutex_unlock(&b->mu);

    int failed = 0;
    for (size_t i = 0; i < n; i++) {
        int rc = list[i].full ? firewall_full_ban(b->fw, list[i].mac, list[i].ip)
                              : firewall_ban(b->fw, list[i].mac, list[i].ip, list[i].port,
                                             list[i].proto);
        if (rc != 0)
            failed++;
    }
    free(list);
    if (failed > 0)
        log_warn("警告：刷新 %d 条封禁元素的超时失败（可能因刷新失败而提前失效）", failed);
}

static void *refresh_main(void *arg)
{
    blocker *b = arg;
    int64_t last = mono_ms();
    for (;;) {
        pthread_mutex_lock(&b->qmu);
        bool stop = b->stopping;
        pthread_mutex_unlock(&b->qmu);
        if (stop)
            return NULL;
        struct timespec req = {.tv_sec = 0, .tv_nsec = 200000000L};
        nanosleep(&req, NULL);

        int64_t ttl = b->fw ? firewall_ban_ttl(b->fw) : 0;
        int64_t interval = ttl > 0 ? ttl / 3 : 60000000000LL;
        if (interval < 1000000000LL)
            interval = 1000000000LL;
        if (mono_ms() - last >= interval / 1000000LL) {
            last = mono_ms();
            if (ttl > 0)
                refresh_bans(b);
        }
    }
}

static void unban_all_rules(blocker *b)
{
    if (!b->fw)
        return;
    typedef struct {
        char mac[18];
        char ip[64];
        uint16_t port;
        char proto[4];
    } target;
    target *targets = NULL;
    size_t nt = 0;
    char **full = NULL, **blocked = NULL, **allowed = NULL;
    size_t nfull = 0, nblocked = 0, nallowed = 0;
    bool upnp_all;

    pthread_mutex_lock(&b->mu);
    for (ban_state *st = b->active; st; st = st->hh.next) {
        if (!st->applied)
            continue;
        targets = xrealloc(targets, (nt + 1) * sizeof(*targets));
        snprintf(targets[nt].mac, sizeof(targets[nt].mac), "%s", st->mac);
        snprintf(targets[nt].ip, sizeof(targets[nt].ip), "%s", state_ip(st));
        targets[nt].port = st->port;
        snprintf(targets[nt].proto, sizeof(targets[nt].proto), "%s", st->proto);
        nt++;
    }
    set_keys(b->full_banned, &full, &nfull);
    set_keys(b->upnp_blocked, &blocked, &nblocked);
    set_keys(b->upnp_allowed, &allowed, &nallowed);
    upnp_all = b->upnp_all;
    pthread_mutex_unlock(&b->mu);

    for (size_t i = 0; i < nt; i++) {
        char mb[64], ib[64], label[8];
        fmt_masked(atomic_load(&b->hide), targets[i].mac, targets[i].ip, mb, sizeof(mb), ib, sizeof(ib));
        snprintf(label, sizeof(label), "%s", targets[i].proto);
        for (char *p = label; *p; p++)
            *p = (char)toupper((unsigned char)*p);
        if (firewall_unban(b->fw, targets[i].mac, targets[i].ip, targets[i].port,
                           targets[i].proto) != 0) {
            log_error("解封设备 %s(%s) 的 %s 端口 %d 失败", mb, ib, label, targets[i].port);
            continue;
        }
        log_info("已解封设备 %s(%s) 的 %s 端口 %d", mb, ib, label, targets[i].port);
    }
    for (size_t i = 0; i < nfull; i++) {
        char mb[64], ib[64], ip[64];
        dev_ip_copy(b, full[i], ip, sizeof(ip));
        fmt_masked(atomic_load(&b->hide), full[i], ip, mb, sizeof(mb), ib, sizeof(ib));
        if (firewall_full_unban(b->fw, full[i], ip) != 0) {
            log_error("解除设备 %s 的全 UDP 端口封禁失败", mb);
            continue;
        }
        log_info("已解除设备 %s 的全 UDP 端口封禁", mb);
    }
    for (size_t i = 0; i < nblocked; i++) {
        char mb[64], ib[64], ip[64];
        dev_ip_copy(b, blocked[i], ip, sizeof(ip));
        fmt_masked(atomic_load(&b->hide), blocked[i], ip, mb, sizeof(mb), ib, sizeof(ib));
        if (firewall_upnp_unban(b->fw, blocked[i], ip) != 0) {
            log_error("解除设备 %s 的 UPnP 拦截失败", mb);
            continue;
        }
        log_info("已解除设备 %s 的 UPnP 拦截", mb);
    }
    for (size_t i = 0; i < nallowed; i++) {
        char mb[64], ib[64], ip[64];
        dev_ip_copy(b, allowed[i], ip, sizeof(ip));
        fmt_masked(atomic_load(&b->hide), allowed[i], ip, mb, sizeof(mb), ib, sizeof(ib));
        if (firewall_upnp_disallow(b->fw, allowed[i], ip) != 0) {
            log_error("取消设备 %s 的 UPnP 放行失败", mb);
            continue;
        }
        log_info("已取消设备 %s 的 UPnP 放行", mb);
    }
    if (upnp_all) {
        if (firewall_upnp_unblock_all(b->fw) != 0)
            log_error("解除全部 UPnP 拦截失败");
        else
            log_info("已解除全部 UPnP 拦截");
    }
    free(targets);
    for (size_t i = 0; i < nfull; i++)
        free(full[i]);
    for (size_t i = 0; i < nblocked; i++)
        free(blocked[i]);
    for (size_t i = 0; i < nallowed; i++)
        free(allowed[i]);
    free(full);
    free(blocked);
    free(allowed);
}

static void reset_state_locked(blocker *b)
{
    ban_state *st, *tmp;
    HASH_ITER(hh, b->active, st, tmp)
    {
        HASH_DEL(b->active, st);
        free(st);
    }
    port_ref *pr, *ptmp;
    HASH_ITER(hh, b->ports, pr, ptmp)
    {
        HASH_DEL(b->ports, pr);
        free(pr);
    }
    set_free(&b->full_banned);
    set_free(&b->upnp_blocked);
    set_free(&b->upnp_allowed);
    b->upnp_all = false;
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

static bool event_from_strings(block_event *ev, bool ban, const char *mac, const char *ip,
                               uint16_t port, const char *proto)
{
    char err[128];
    memset(ev, 0, sizeof(*ev));
    ev->ban = ban;
    ev->port = port;
    if (!mac_parse(mac, &ev->mac, err, sizeof(err)))
        return false; /* 上游始终传格式化后的 MAC，解析失败说明数据异常，丢弃事件 */
    /* 空串 / 无效地址保持 valid=false，出队时格式化回空串，与原行为一致 */
    (void)ip_parse(ip, &ev->ip, err, sizeof(err));
    ev->proto = (proto && strcmp(proto, PROTO_TCP) == 0) ? PROTO_TCP_ID : PROTO_UDP_ID;
    return true;
}

static void on_alert_start(void *ctx, const char *mac, const char *ip, uint16_t port,
                           const char *proto)
{
    block_event ev;
    if (event_from_strings(&ev, true, mac, ip, port, proto))
        enqueue(ctx, &ev);
}

static void on_alert_end(void *ctx, const char *mac, const char *ip, uint16_t port,
                         const char *proto)
{
    block_event ev;
    if (event_from_strings(&ev, false, mac, ip, port, proto))
        enqueue(ctx, &ev);
}

static const alert_sink g_sink = {.on_alert_start = on_alert_start,
                                  .on_alert_end = on_alert_end};

const alert_sink *blocker_alert_sink(blocker *b, void **ctx)
{
    if (ctx)
        *ctx = b;
    return &g_sink;
}

blocker *blocker_create(firewall *fw, bool hide, const blocker_fullban_cfg *fb,
                        const blocker_upnp_cfg *up)
{
    blocker *b = xcalloc(1, sizeof(*b));
    b->fw = fw;
    atomic_init(&b->hide, hide);
    pthread_mutex_init(&b->qmu, NULL);
    pthread_cond_init(&b->qcond, NULL);
    pthread_mutex_init(&b->mu, NULL);
    b->fb_threshold = 1;
    if (fb && fb->enabled) {
        b->fb_enabled = true;
        snprintf(b->fb_mode, sizeof(b->fb_mode), "%s", fb->mode);
        b->fb_threshold = fb->threshold > 0 ? fb->threshold : 1;
        for (size_t i = 0; i < fb->ndevices; i++)
            set_add(&b->fb_devices, fb->devices[i]);
    }
    if (up && up->enabled) {
        b->up_enabled = true;
        b->up_block_all = up->block_all;
        for (size_t i = 0; i < up->ntargets; i++)
            set_add(&b->up_targets, up->targets[i]);
    }

    apply_static_upnp(b);

    b->worker_started = pthread_create(&b->worker, NULL, worker_main, b) == 0;
    b->refresher_started = pthread_create(&b->refresher, NULL, refresh_main, b) == 0;
    return b;
}

void blocker_close(blocker *b)
{
    if (!b)
        return;
    pthread_mutex_lock(&b->qmu);
    if (b->closed) {
        pthread_mutex_unlock(&b->qmu);
        return;
    }
    b->closed = true;
    b->stopping = true;
    pthread_cond_broadcast(&b->qcond);
    pthread_mutex_unlock(&b->qmu);

    if (b->worker_started)
        pthread_join(b->worker, NULL);
    if (b->refresher_started)
        pthread_join(b->refresher, NULL);
    unban_all_rules(b);

    pthread_mutex_lock(&b->mu);
    reset_state_locked(b);
    pthread_mutex_unlock(&b->mu);
}

void blocker_set_hide(blocker *b, bool hide)
{
    if (b)
        atomic_store(&b->hide, hide);
}

/* 热替换名单：新名单已排除的设备 / 端口会被解封并清出内存状态，
 * 同时后续封禁事件也按新名单过滤（见 handle_event）。 */
void blocker_set_filter(blocker *b, device_filter *f)
{
    if (!b)
        return;
    filter_ref(f);

    typedef struct {
        char key[96];
        char mac[18];
        char ip[64];
        char proto[4];
        uint16_t port;
        bool applied;
    } victim;

    pthread_mutex_lock(&b->mu);
    device_filter *old = b->filter;
    b->filter = f;
    victim *victims = NULL;
    size_t n = 0;
    for (ban_state *st = b->active; st; st = st->hh.next) {
        pcdn_mac mac;
        char perr[64];
        if (!mac_parse(st->mac, &mac, perr, sizeof(perr)))
            continue;
        if (filter_allow_key(f, mac, st->port))
            continue;
        victims = xrealloc(victims, (n + 1) * sizeof(*victims));
        snprintf(victims[n].key, sizeof(victims[n].key), "%s", st->key);
        snprintf(victims[n].mac, sizeof(victims[n].mac), "%s", st->mac);
        snprintf(victims[n].ip, sizeof(victims[n].ip), "%s", state_ip(st));
        snprintf(victims[n].proto, sizeof(victims[n].proto), "%s", st->proto);
        victims[n].port = st->port;
        victims[n].applied = st->applied;
        n++;
    }
    pthread_mutex_unlock(&b->mu);
    filter_free(old);

    /* 先解封再清记录；解封失败时保留记录，下一次重载或自然过期可重试 */
    for (size_t i = 0; i < n; i++) {
        if (victims[i].applied && apply_one(b, false, victims[i].mac, victims[i].ip,
                                            victims[i].port, victims[i].proto) != 0)
            continue;
        pthread_mutex_lock(&b->mu);
        ban_state *st = NULL;
        HASH_FIND_STR(b->active, victims[i].key, st);
        if (st) {
            HASH_DEL(b->active, st);
            free(st);
            bump_port_locked(b, victims[i].mac, victims[i].port, -1);
        }
        pthread_mutex_unlock(&b->mu);
    }

    /* 端口数下降后可能需要解除全端口封禁（按设备去重后各评估一次） */
    for (size_t i = 0; i < n; i++) {
        bool dup = false;
        for (size_t j = 0; j < i && !dup; j++)
            dup = strcmp(victims[j].mac, victims[i].mac) == 0;
        if (!dup)
            maybe_full_ban(b, victims[i].mac, victims[i].ip);
    }
    free(victims);
}

void blocker_free(blocker *b)
{
    if (!b)
        return;
    filter_free(b->filter);
    set_free(&b->full_banned);
    set_free(&b->upnp_blocked);
    set_free(&b->upnp_allowed);
    set_free(&b->fb_devices);
    set_free(&b->up_targets);
    str_val *e, *tmp;
    HASH_ITER(hh, b->dev_ip, e, tmp)
    {
        HASH_DEL(b->dev_ip, e);
        free(e);
    }
    pthread_mutex_destroy(&b->qmu);
    pthread_cond_destroy(&b->qcond);
    pthread_mutex_destroy(&b->mu);
    free(b);
}

/* ------------------------------------------------------------------ */
/* 手动解封                                                            */
/* ------------------------------------------------------------------ */

void blocker_force_unban(blocker *b, const char *mac, uint16_t port, const char *proto,
                         int *removed, char *err, size_t errlen)
{
    *removed = 0;
    if (!b || !b->fw) {
        set_err(err, errlen, "防火墙未启用");
        return;
    }
    pcdn_mac m;
    if (!mac_parse(mac, &m, err, errlen)) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "MAC 无效：\"%s\"", mac);
        set_err(err, errlen, "%s", tmp);
        return;
    }
    char macstr[32];
    mac_format(&m, macstr, sizeof(macstr));

    char p[8];
    snprintf(p, sizeof(p), "%s", proto ? proto : "");
    for (char *q = p; *q; q++)
        *q = (char)tolower((unsigned char)*q);
    if (strcmp(p, PROTO_UDP) != 0 && strcmp(p, PROTO_TCP) != 0) {
        set_err(err, errlen, "proto 无效：\"%s\"（可选 udp / tcp）", proto ? proto : "");
        return;
    }

    typedef struct {
        char ip[IPS_TEXT_MAX];
        char proto[4];
    } target;
    target *targets = NULL;
    size_t nt = 0;

    pthread_mutex_lock(&b->mu);
    ban_state *st, *tmp;
    HASH_ITER(hh, b->active, st, tmp)
    {
        if (strcmp(st->mac, macstr) != 0 || st->port != port || strcmp(st->proto, p) != 0)
            continue;
        if (st->applied) {
            targets = xrealloc(targets, (nt + 1) * sizeof(*targets));
            snprintf(targets[nt].ip, sizeof(targets[nt].ip), "%s", state_ip(st));
            snprintf(targets[nt].proto, sizeof(targets[nt].proto), "%s", st->proto);
            nt++;
        }
        HASH_DEL(b->active, st);
        free(st);
        bump_port_locked(b, macstr, port, -1);
        (*removed)++;
    }
    pthread_mutex_unlock(&b->mu);

    char first_err[512] = {0};
    for (size_t i = 0; i < nt; i++) {
        char mb[64], ib[64], label[8];
        fmt_masked(atomic_load(&b->hide), macstr, targets[i].ip, mb, sizeof(mb), ib, sizeof(ib));
        snprintf(label, sizeof(label), "%s", targets[i].proto);
        for (char *q = label; *q; q++)
            *q = (char)toupper((unsigned char)*q);
        if (firewall_unban(b->fw, macstr, targets[i].ip, port, targets[i].proto) != 0) {
            log_error("手动解封设备 %s 的 %s 端口 %d 失败", mb, label, port);
            if (first_err[0] == '\0')
                snprintf(first_err, sizeof(first_err), "防火墙命令执行失败");
            continue;
        }
        log_info("已手动解封设备 %s 的 %s 端口 %d", mb, label, port);
    }
    free(targets);
    char cur_ip[64];
    dev_ip_copy(b, macstr, cur_ip, sizeof(cur_ip));
    maybe_full_ban(b, macstr, cur_ip);
    if (first_err[0])
        set_err(err, errlen, "%s", first_err);
}

/* ------------------------------------------------------------------ */
/* 快照 / 索引                                                         */
/* ------------------------------------------------------------------ */

static int cmp_str_ptr(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int cmp_ban_view(const void *pa, const void *pb)
{
    const ban_view *a = pa, *b = pb;
    int c = strcmp(a->mac, b->mac);
    if (c)
        return c;
    if (a->port != b->port)
        return (int)a->port - (int)b->port;
    return strcmp(a->proto, b->proto);
}

void blocker_snapshot_get(blocker *b, blocker_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    if (!b)
        return;
    pthread_mutex_lock(&b->mu);
    size_t count = HASH_COUNT(b->active);
    out->bans = count ? xcalloc(count, sizeof(ban_view)) : NULL;
    out->nbans = 0;
    for (ban_state *st = b->active; st; st = st->hh.next) {
        ban_view *v = &out->bans[out->nbans++];
        snprintf(v->mac, sizeof(v->mac), "%s", st->mac);
        v->port = st->port;
        snprintf(v->proto, sizeof(v->proto), "%s", st->proto);
        snprintf(v->family, sizeof(v->family), "%s", fam_name(st->fam));
        v->refs = state_total(st);
        snprintf(v->ip, sizeof(v->ip), "%s", state_ip(st));
        v->applied = st->applied;
    }
    set_keys(b->full_banned, &out->full_banned, &out->nfull);
    set_keys(b->upnp_blocked, &out->upnp_blocked, &out->nupnp_blocked);
    set_keys(b->upnp_allowed, &out->upnp_allowed, &out->nupnp_allowed);
    out->upnp_all = b->upnp_all;
    pthread_mutex_unlock(&b->mu);

    if (out->nbans > 1)
        qsort(out->bans, out->nbans, sizeof(ban_view), cmp_ban_view);
    if (out->nfull > 1)
        qsort(out->full_banned, out->nfull, sizeof(char *), cmp_str_ptr);
    if (out->nupnp_blocked > 1)
        qsort(out->upnp_blocked, out->nupnp_blocked, sizeof(char *), cmp_str_ptr);
    if (out->nupnp_allowed > 1)
        qsort(out->upnp_allowed, out->nupnp_allowed, sizeof(char *), cmp_str_ptr);
}

void blocker_snapshot_free(blocker_snapshot *s)
{
    if (!s)
        return;
    free(s->bans);
    for (size_t i = 0; i < s->nfull; i++)
        free(s->full_banned[i]);
    for (size_t i = 0; i < s->nupnp_blocked; i++)
        free(s->upnp_blocked[i]);
    for (size_t i = 0; i < s->nupnp_allowed; i++)
        free(s->upnp_allowed[i]);
    free(s->full_banned);
    free(s->upnp_blocked);
    free(s->upnp_allowed);
    memset(s, 0, sizeof(*s));
}

void blocker_counts_get(blocker *b, blocker_counts *out)
{
    memset(out, 0, sizeof(*out));
    if (!b)
        return;
    pthread_mutex_lock(&b->mu);
    out->active_bans = HASH_COUNT(b->active);
    out->full_banned = HASH_COUNT(b->full_banned);
    out->upnp_blocked = HASH_COUNT(b->upnp_blocked);
    out->upnp_allowed = HASH_COUNT(b->upnp_allowed);
    out->upnp_all = b->upnp_all;
    pthread_mutex_unlock(&b->mu);
}

static int cmp_ban_rule_key(const void *pa, const void *pb)
{
    const ban_rule_view *a = pa, *b = pb;
    int c = strcmp(a->mac, b->mac);
    if (c != 0)
        return c;
    if (a->port != b->port)
        return (int)a->port - (int)b->port;
    c = strcmp(a->proto, b->proto);
    if (c != 0)
        return c;
    return strcmp(a->family, b->family);
}

void blocker_ban_index_get(blocker *b, ban_index *out)
{
    memset(out, 0, sizeof(*out));
    if (!b)
        return;
    pthread_mutex_lock(&b->mu);
    out->both = b->fw ? firewall_ban_both(b->fw) : false;
    size_t count = HASH_COUNT(b->active);
    out->rules = count ? xcalloc(count, sizeof(ban_rule_view)) : NULL;
    out->nrules = 0;
    for (ban_state *st = b->active; st; st = st->hh.next) {
        ban_rule_view *v = &out->rules[out->nrules++];
        snprintf(v->mac, sizeof(v->mac), "%s", st->mac);
        v->port = st->port;
        snprintf(v->proto, sizeof(v->proto), "%s", st->proto);
        if (out->both)
            v->family[0] = '\0';
        else
            snprintf(v->family, sizeof(v->family), "%s", fam_name(st->fam));
    }
    set_keys(b->full_banned, &out->full, &out->nfull);
    pthread_mutex_unlock(&b->mu);

    /* 排序后 ban_index_banned 用二分查找：/devices 会对每个端口查一次 */
    if (out->nrules > 1)
        qsort(out->rules, out->nrules, sizeof(*out->rules), cmp_ban_rule_key);

    if (b->fw) {
        size_t n = 0;
        const uint16_t *allow = firewall_fullban_allow_ports(b->fw, &n);
        if (n > 0) {
            out->allow = xmalloc(n * sizeof(uint16_t));
            memcpy(out->allow, allow, n * sizeof(uint16_t));
            out->nallow = n;
        }
    }
}

void ban_index_free(ban_index *ix)
{
    if (!ix)
        return;
    free(ix->rules);
    for (size_t i = 0; i < ix->nfull; i++)
        free(ix->full[i]);
    free(ix->full);
    free(ix->allow);
    memset(ix, 0, sizeof(*ix));
}

bool ban_index_banned(const ban_index *ix, const char *mac, uint16_t port, const char *proto,
                      bool v6)
{
    if (!ix)
        return false;
    for (size_t i = 0; i < ix->nfull; i++) {
        if (strcmp(ix->full[i], mac) != 0)
            continue;
        if (strcmp(proto, PROTO_UDP) != 0)
            break;
        bool allowed = false;
        for (size_t k = 0; k < ix->nallow; k++) {
            if (ix->allow[k] == port) {
                allowed = true;
                break;
            }
        }
        if (!allowed)
            return true;
        break;
    }
    const char *family = "";
    if (!ix->both)
        family = v6 ? "v6" : "v4";
    /* rules 已按 (mac, port, proto, family) 字典序排好，二分查找 */
    size_t lo = 0, hi = ix->nrules;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const ban_rule_view *r = &ix->rules[mid];
        int c = strcmp(r->mac, mac);
        if (c == 0) {
            if (r->port != port) {
                c = r->port < port ? -1 : 1;
            } else {
                c = strcmp(r->proto, proto);
                if (c == 0)
                    c = strcmp(r->family, family);
            }
        }
        if (c < 0)
            lo = mid + 1;
        else if (c > 0)
            hi = mid;
        else
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* 状态导出 / 恢复                                                     */
/* ------------------------------------------------------------------ */

static uint8_t family_to_u8(const char *f)
{
    if (strcmp(f, "v4") == 0)
        return STATE_FAMILY_V4;
    if (strcmp(f, "v6") == 0)
        return STATE_FAMILY_V6;
    return STATE_FAMILY_NONE;
}

static const char *u8_to_family(uint8_t f)
{
    if (f == STATE_FAMILY_V4)
        return "v4";
    if (f == STATE_FAMILY_V6)
        return "v6";
    return "";
}

static bool parse_addr_opt(const char *s, pcdn_ip *ip)
{
    memset(ip, 0, sizeof(*ip));
    if (!s || !s[0])
        return false;
    char e[128];
    return ip_parse(s, ip, e, sizeof(e));
}

bool blocker_block_state(blocker *b, state_file *out, char *err, size_t errlen)
{
    (void)err;
    (void)errlen;
    /* 只重置本函数负责的字段；saved_at / sessions 可能已由调用方填好 */
    out->bans = NULL;
    out->nbans = 0;
    out->fullbanned = NULL;
    out->nfull = 0;
    out->upnp_blocked = NULL;
    out->nupnp_blocked = 0;
    out->upnp_allowed = NULL;
    out->nupnp_allowed = 0;
    out->upnp_all = false;
    if (!b)
        return true;
    pthread_mutex_lock(&b->mu);
    size_t cap = HASH_COUNT(b->active) * 2;
    out->bans = cap ? xcalloc(cap, sizeof(state_ban)) : NULL;
    for (ban_state *st = b->active; st; st = st->hh.next) {
        pcdn_mac mac;
        char e[128];
        if (!mac_parse(st->mac, &mac, e, sizeof(e)))
            continue;
        for (int i = 0; i < 2; i++) {
            if (st->refs[i] == 0)
                continue;
            state_ban *be = &out->bans[out->nbans++];
            be->mac = mac;
            be->port = st->port;
            be->proto = strcmp(st->proto, PROTO_TCP) == 0 ? 6 : 17;
            be->family = family_to_u8(fam_name(i));
            parse_addr_opt(st->ips[i], &be->ip);
            be->refs = (uint16_t)st->refs[i];
            be->applied = st->applied;
        }
    }
    out->fullbanned = HASH_COUNT(b->full_banned)
                          ? xcalloc(HASH_COUNT(b->full_banned), sizeof(state_fullban))
                          : NULL;
    for (str_set *e = b->full_banned; e; e = e->hh.next) {
        pcdn_mac mac;
        char errbuf[128];
        if (!mac_parse(e->key, &mac, errbuf, sizeof(errbuf)))
            continue;
        state_fullban *fe = &out->fullbanned[out->nfull++];
        fe->mac = mac;
        parse_addr_opt(dev_ip_get_nolock(b, e->key), &fe->ip);
    }
    size_t n = HASH_COUNT(b->upnp_blocked);
    out->upnp_blocked = n ? xcalloc(n, sizeof(pcdn_mac)) : NULL;
    for (str_set *e = b->upnp_blocked; e; e = e->hh.next) {
        pcdn_mac mac;
        char errbuf[128];
        if (mac_parse(e->key, &mac, errbuf, sizeof(errbuf)))
            out->upnp_blocked[out->nupnp_blocked++] = mac;
    }
    n = HASH_COUNT(b->upnp_allowed);
    out->upnp_allowed = n ? xcalloc(n, sizeof(pcdn_mac)) : NULL;
    for (str_set *e = b->upnp_allowed; e; e = e->hh.next) {
        pcdn_mac mac;
        char errbuf[128];
        if (mac_parse(e->key, &mac, errbuf, sizeof(errbuf)))
            out->upnp_allowed[out->nupnp_allowed++] = mac;
    }
    out->upnp_all = b->upnp_all;
    pthread_mutex_unlock(&b->mu);
    return true;
}

/* 按状态还原并重新下发封禁（启动继承 / 防火墙迁移时调用，使用当前防火墙后端）。
 * UPnP 的静态策略（名单 / 全量拦截）不在这里恢复：blocker_create 已按当前配置应用，
 * 旧状态文件中已撤销的权限不应被重新下发。 */
void blocker_restore(blocker *b, const state_file *st)
{
    if (!b || !st || !b->fw)
        return;

    /* 统计每个设备在状态文件里的端口数，决定是否恢复全端口封禁 */
    str_set *mac_ports = NULL;
    for (size_t i = 0; i < st->nbans; i++) {
        char mac[18], key[32];
        mac_format(&st->bans[i].mac, mac, sizeof(mac));
        if (!filter_allow_key(b->filter, st->bans[i].mac, st->bans[i].port))
            continue;
        make_port_key(mac, st->bans[i].port, key, sizeof(key));
        set_add(&mac_ports, key);
    }
    str_set *restore_full = NULL;
    for (size_t i = 0; i < st->nfull; i++) {
        char mac[18];
        mac_format(&st->fullbanned[i].mac, mac, sizeof(mac));
        int ports = 0;
        for (str_set *e = mac_ports; e; e = e->hh.next) {
            if (strncmp(e->key, mac, strlen(mac)) == 0 && e->key[strlen(mac)] == ':')
                ports++;
        }
        if (fullban_applies(b, mac) && ports >= b->fb_threshold)
            set_add(&restore_full, mac);
    }

    for (size_t i = 0; i < st->nbans; i++) {
        const state_ban *e = &st->bans[i];
        char mac[18], ip[IPS_TEXT_MAX], proto[4], key[96];
        if (!filter_allow_key(b->filter, e->mac, e->port))
            continue;
        mac_format(&e->mac, mac, sizeof(mac));
        ip_format(&e->ip, ip, sizeof(ip));
        snprintf(proto, sizeof(proto), "%s", e->proto == 6 ? PROTO_TCP : PROTO_UDP);
        if (firewall_ban_both(b->fw))
            snprintf(key, sizeof(key), "%s:%u:%s", mac, e->port, proto);
        else
            snprintf(key, sizeof(key), "%s:%u:%s:%s", mac, e->port, proto,
                     firewall_addr_family(ip));
        bool applied = e->applied;
        if (!applied && strcmp(proto, PROTO_UDP) == 0 && !set_contains(restore_full, mac))
            applied = true;
        const char *family = u8_to_family(e->family);
        if (family[0] == '\0')
            family = firewall_addr_family(ip);
        int i_fam = strcmp(family, "v6") == 0 ? 1 : 0;
        unsigned refs = e->refs < 1 ? 1 : e->refs;

        pthread_mutex_lock(&b->mu);
        ban_state *existing = NULL;
        HASH_FIND_STR(b->active, key, existing);
        bool do_apply = false;
        if (existing) {
            existing->refs[i_fam] += refs;
            snprintf(existing->ips[i_fam], sizeof(existing->ips[i_fam]), "%s", ip);
            if (applied && !existing->applied) {
                existing->applied = true;
                do_apply = true;
            }
        } else {
            ban_state *ns = xcalloc(1, sizeof(*ns));
            snprintf(ns->key, sizeof(ns->key), "%s", key);
            snprintf(ns->mac, sizeof(ns->mac), "%s", mac);
            snprintf(ns->proto, sizeof(ns->proto), "%s", proto);
            ns->port = e->port;
            ns->fam = (uint8_t)i_fam;
            ns->last = (uint8_t)i_fam;
            ns->refs[i_fam] = refs;
            snprintf(ns->ips[i_fam], sizeof(ns->ips[i_fam]), "%s", ip);
            ns->applied = applied;
            HASH_ADD_STR(b->active, key, ns);
            bump_port_locked(b, mac, e->port, 1);
            do_apply = applied;
        }
        pthread_mutex_unlock(&b->mu);

        if (do_apply) {
            if (firewall_ban(b->fw, mac, ip, e->port, proto) != 0) {
                char mb[64], ib[64];
                fmt_masked(atomic_load(&b->hide), mac, ip, mb, sizeof(mb), ib, sizeof(ib));
                log_error("继承封禁设备 %s 的 %s 端口 %d 失败", mb, proto, e->port);
            }
        }
    }

    for (size_t i = 0; i < st->nfull; i++) {
        char mac[18], ip[64];
        mac_format(&st->fullbanned[i].mac, mac, sizeof(mac));
        ip_format(&st->fullbanned[i].ip, ip, sizeof(ip));
        if (!set_contains(restore_full, mac))
            continue;
        pthread_mutex_lock(&b->mu);
        bool already = set_contains(b->full_banned, mac);
        if (!already)
            set_add(&b->full_banned, mac);
        pthread_mutex_unlock(&b->mu);
        if (already)
            continue;
        if (firewall_full_ban(b->fw, mac, ip) != 0) {
            char mb[64], ib[64];
            fmt_masked(atomic_load(&b->hide), mac, ip, mb, sizeof(mb), ib, sizeof(ib));
            log_error("继承全 UDP 端口封禁设备 %s 失败", mb);
            pthread_mutex_lock(&b->mu);
            set_del(&b->full_banned, mac);
            pthread_mutex_unlock(&b->mu);
        }
    }

    set_free(&mac_ports);
    set_free(&restore_full);
}

void blocker_adopt_sessions(blocker *b, const state_session *sessions, size_t n)
{
    if (!b || !b->fw || n == 0)
        return;

    typedef struct {
        pcdn_mac mac;
        uint16_t port;
        uint8_t proto;
        uint8_t family;
        pcdn_ip ip;
        uint16_t refs;
    } adopt;
    adopt *list = xcalloc(n, sizeof(adopt));
    size_t nl = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t family = sessions[i].v6 ? STATE_FAMILY_V6 : STATE_FAMILY_V4;
        size_t k;
        for (k = 0; k < nl; k++) {
            if (mac_equal(&list[k].mac, &sessions[i].mac) && list[k].port == sessions[i].port &&
                list[k].proto == sessions[i].proto && list[k].family == family) {
                list[k].refs++;
                break;
            }
        }
        if (k == nl) {
            list[nl].mac = sessions[i].mac;
            list[nl].port = sessions[i].port;
            list[nl].proto = sessions[i].proto;
            list[nl].family = family;
            list[nl].ip = sessions[i].ip;
            list[nl].refs = 1;
            nl++;
        }
    }
    state_file st;
    memset(&st, 0, sizeof(st));
    st.bans = xcalloc(nl ? nl : 1, sizeof(state_ban));
    for (size_t i = 0; i < nl; i++) {
        state_ban *be = &st.bans[st.nbans++];
        be->mac = list[i].mac;
        be->port = list[i].port;
        be->proto = list[i].proto;
        be->family = list[i].family;
        be->ip = list[i].ip;
        be->refs = list[i].refs;
        be->applied = true;
    }
    blocker_restore(b, &st);

    /* 补发后按设备重新评估全端口封禁 */
    for (size_t i = 0; i < nl; i++) {
        bool first = true;
        for (size_t k = 0; k < i; k++) {
            if (mac_equal(&list[k].mac, &list[i].mac)) {
                first = false;
                break;
            }
        }
        if (!first)
            continue;
        char mac[18], ip[64];
        mac_format(&list[i].mac, mac, sizeof(mac));
        ip_format(&list[i].ip, ip, sizeof(ip));
        maybe_full_ban(b, mac, ip);
    }
    free(st.bans);
    free(list);
}
