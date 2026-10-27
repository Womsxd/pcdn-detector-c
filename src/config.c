#include "config.h"

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "filter.h"
#include "firewall.h"
#include "toml.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */

#define DEFAULT_THRESHOLD 20
#define DEFAULT_WINDOW_NS (60LL * 1000000000LL)
#define DEFAULT_ALERT_NS (10LL * 60LL * 1000000000LL)
#define DEFAULT_INTERVAL_NS (2LL * 1000000000LL)
#define DEFAULT_FRAME_SIZE 2048
#define DEFAULT_BLOCK_SIZE 65536
#define DEFAULT_NUM_BLOCKS 4
#define DEFAULT_SNAPLEN 256
#define MIN_SNAPLEN 64
#define DEFAULT_PEER_LIMIT 1000
#define PEER_LIMIT_FACTOR 10
#define DEFAULT_MAX_PORTS 512
#define DEFAULT_FULLBAN_THRESHOLD 5
#define DEFAULT_HTTP_LISTEN "127.0.0.1:8080"
#define DEFAULT_DEVICE_IP_LIMIT 200
#define DEFAULT_CORS_MAX_AGE 600
#define STATE_FILE_NAME "pcdn-detect.state"
#define TOKEN_ALLOW_NO_TOKEN "allow-no-token"
/* 与 Go 版 internal/config/defaults.go 的 pageSize = 4096 保持一致。
 * 不能叫 PAGE_SIZE：musl 的 <limits.h> 也定义了 PAGE_SIZE，会触发宏重定义警告。 */
#define RING_PAGE_SIZE 4096

static const char *const config_candidates[] = {"config.toml", "pcdn-detect.toml"};
static const char *const config_create_names[] = {"pcdn-detect.toml"};

static const uint16_t default_fullban_allow[] = {53, 123, 67, 68, 546, 547};
static const uint16_t default_upnp_ports[] = {1900, 5000};

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

static char *dupstr(const char *s)
{
    return s ? xstrdup(s) : NULL;
}

static bool str_empty(const char *s)
{
    if (!s)
        return true;
    while (*s) {
        if (!isspace((unsigned char)*s))
            return false;
        s++;
    }
    return true;
}

static bool str_in(const char *s, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(s, list[i]) == 0)
            return true;
    }
    return false;
}

static bool str_eq(const char *a, const char *b)
{
    if (!a || !b)
        return a == b;
    return strcmp(a, b) == 0;
}

static void free_port_items(port_item *items, size_t n)
{
    if (!items)
        return;
    for (size_t i = 0; i < n; i++)
        free(items[i].sval);
    free(items);
}

static void free_list_entries(list_entry *entries, size_t n)
{
    if (!entries)
        return;
    for (size_t i = 0; i < n; i++) {
        free(entries[i].mac);
        free_port_items(entries[i].ports, entries[i].nports);
    }
    free(entries);
}

static void warnings_add(config_result *res, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    res->warnings = xrealloc(res->warnings, (res->nwarnings + 1) * sizeof(char *));
    res->warnings[res->nwarnings++] = xstrdup(buf);
}

/* ------------------------------------------------------------------ */
/* 默认值 / 释放                                                       */
/* ------------------------------------------------------------------ */

void config_default(config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->detect.threshold = DEFAULT_THRESHOLD;
    cfg->detect.window = DEFAULT_WINDOW_NS;
    cfg->detect.alert_duration = DEFAULT_ALERT_NS;
    cfg->detect.interval = DEFAULT_INTERVAL_NS;

    cfg->capture.iface = dupstr("");
    cfg->capture.promisc = true;
    cfg->capture.frame_size = DEFAULT_FRAME_SIZE;
    cfg->capture.block_size = DEFAULT_BLOCK_SIZE;
    cfg->capture.num_blocks = DEFAULT_NUM_BLOCKS;
    cfg->capture.snaplen = DEFAULT_SNAPLEN;
    cfg->capture.protocol = dupstr("udp");

    cfg->memory.memory_limit = dupstr("");
    cfg->log.level = dupstr("warn");
    cfg->log.timezone = dupstr("");
    cfg->http.listen = dupstr(DEFAULT_HTTP_LISTEN);
    cfg->http.token = dupstr("");
    cfg->http.state_dir = dupstr("");
    cfg->filter.list_mode = dupstr("whitelist");

    cfg->firewall.backend = dupstr("");
    cfg->firewall.ban_both = true;
    cfg->firewall.hook_cmd = dupstr("");
    cfg->firewall.ipt_chain = dupstr("");
    cfg->firewall.ipt_input_chain = dupstr("");
    cfg->firewall.ipt_ban_chain = dupstr("");
    cfg->firewall.ipt_upnp_chain = dupstr("");
    cfg->firewall.nft_table = dupstr("");
    cfg->firewall.nft_set = dupstr("");
    cfg->firewall.nft_hook = dupstr("");
    cfg->firewall.nft_input_hook = dupstr("");
    cfg->full_ban.mode = dupstr("off");
    cfg->full_ban.threshold = DEFAULT_FULLBAN_THRESHOLD;
    cfg->full_ban.hook_cmd = dupstr("");
    cfg->upnp.mode = dupstr("off");
    cfg->upnp.hook_cmd = dupstr("");
}

void config_free(config_t *cfg)
{
    if (!cfg)
        return;
    free(cfg->capture.iface);
    free(cfg->capture.protocol);
    free(cfg->memory.memory_limit);
    free(cfg->log.level);
    free(cfg->log.timezone);
    free(cfg->http.listen);
    free(cfg->http.token);
    free(cfg->http.state_dir);
    for (size_t i = 0; i < cfg->http.ncors; i++)
        free(cfg->http.cors_origins[i]);
    free(cfg->http.cors_origins);
    free(cfg->filter.list_mode);
    free_list_entries(cfg->filter.blacklist, cfg->filter.nblack);
    free_list_entries(cfg->filter.whitelist, cfg->filter.nwhite);
    free(cfg->firewall.backend);
    free(cfg->firewall.hook_cmd);
    free(cfg->firewall.ipt_chain);
    free(cfg->firewall.ipt_input_chain);
    free(cfg->firewall.ipt_ban_chain);
    free(cfg->firewall.ipt_upnp_chain);
    free(cfg->firewall.nft_table);
    free(cfg->firewall.nft_set);
    free(cfg->firewall.nft_hook);
    free(cfg->firewall.nft_input_hook);
    free(cfg->full_ban.mode);
    free_port_items(cfg->full_ban.allow, cfg->full_ban.nallow);
    free(cfg->full_ban.hook_cmd);
    free(cfg->upnp.mode);
    free_port_items(cfg->upnp.ports, cfg->upnp.nports);
    free(cfg->upnp.hook_cmd);
    memset(cfg, 0, sizeof(*cfg));
}

void config_result_free(config_result *res)
{
    if (!res)
        return;
    config_free(&res->cfg);
    free(res->path);
    for (size_t i = 0; i < res->nwarnings; i++)
        free(res->warnings[i]);
    free(res->warnings);
    memset(res, 0, sizeof(*res));
}

static bool proto_valid(const char *p)
{
    return strcmp(p, "udp") == 0 || strcmp(p, "tcp") == 0 || strcmp(p, "all") == 0;
}

void config_apply_defaults(config_t *cfg)
{
    if (cfg->detect.threshold <= 0)
        cfg->detect.threshold = DEFAULT_THRESHOLD;
    if (cfg->detect.window <= 0)
        cfg->detect.window = DEFAULT_WINDOW_NS;
    if (cfg->detect.alert_duration <= 0)
        cfg->detect.alert_duration = DEFAULT_ALERT_NS;
    if (cfg->detect.interval <= 0)
        cfg->detect.interval = DEFAULT_INTERVAL_NS;

    int frame, block, blocks;
    config_ring_params(cfg, &frame, &block, &blocks);
    cfg->capture.frame_size = frame;
    cfg->capture.block_size = block;
    cfg->capture.num_blocks = blocks;

    if (!cfg->capture.protocol || !proto_valid(cfg->capture.protocol)) {
        free(cfg->capture.protocol);
        cfg->capture.protocol = dupstr("udp");
    }
    cfg->capture.snaplen = config_snaplen_value(cfg);

    if (!cfg->full_ban.mode || cfg->full_ban.mode[0] == '\0') {
        free(cfg->full_ban.mode);
        cfg->full_ban.mode = dupstr("off");
    }
    if (cfg->full_ban.threshold <= 0)
        cfg->full_ban.threshold = DEFAULT_FULLBAN_THRESHOLD;
    if (!cfg->upnp.mode || cfg->upnp.mode[0] == '\0') {
        free(cfg->upnp.mode);
        cfg->upnp.mode = dupstr("off");
    }
    if (!cfg->http.listen || str_empty(cfg->http.listen)) {
        free(cfg->http.listen);
        cfg->http.listen = dupstr(DEFAULT_HTTP_LISTEN);
    }
    if (!cfg->log.level || str_empty(cfg->log.level)) {
        free(cfg->log.level);
        cfg->log.level = dupstr("warn");
    } else {
        for (char *p = cfg->log.level; *p; p++)
            *p = (char)tolower((unsigned char)*p);
    }
    if (!cfg->filter.list_mode || cfg->filter.list_mode[0] == '\0') {
        free(cfg->filter.list_mode);
        cfg->filter.list_mode = dupstr("whitelist");
    }
}

/* ------------------------------------------------------------------ */
/* 生效值                                                              */
/* ------------------------------------------------------------------ */

void config_ring_params(const config_t *cfg, int *frame, int *block, int *blocks)
{
    int f = cfg->capture.frame_size;
    int b = cfg->capture.block_size;
    int n = cfg->capture.num_blocks;
    if (f <= 0 || b <= 0 || n < 1 || b % RING_PAGE_SIZE != 0 || b % f != 0) {
        *frame = DEFAULT_FRAME_SIZE;
        *block = DEFAULT_BLOCK_SIZE;
        *blocks = DEFAULT_NUM_BLOCKS;
        return;
    }
    *frame = f;
    *block = b;
    *blocks = n;
}

int config_snaplen_value(const config_t *cfg)
{
    int frame, block, blocks;
    config_ring_params(cfg, &frame, &block, &blocks);
    int n = cfg->capture.snaplen;
    if (n <= 0)
        n = DEFAULT_SNAPLEN;
    if (n < MIN_SNAPLEN)
        n = MIN_SNAPLEN;
    if (n > frame)
        n = frame;
    return n;
}

const char *config_capture_proto(const config_t *cfg)
{
    const char *p = cfg->capture.protocol;
    if (p && strcmp(p, "tcp") == 0)
        return "tcp";
    if (p && strcmp(p, "all") == 0)
        return "all";
    return "udp";
}

const char *config_capture_proto_label(const config_t *cfg)
{
    const char *p = config_capture_proto(cfg);
    if (strcmp(p, "tcp") == 0)
        return "TCP";
    if (strcmp(p, "all") == 0)
        return "UDP+TCP";
    return "UDP";
}

static int normalize_peer_limit(int limit, int threshold)
{
    if (limit <= 0)
        return 0;
    if (limit < threshold)
        return threshold;
    return limit;
}

int config_peer_limit_value(const config_t *cfg)
{
    int v = DEFAULT_PEER_LIMIT;
    /* 阈值可由配置给到 INT32_MAX，乘系数前必须提升到 64 位并饱和到上限 */
    int64_t scaled = (int64_t)cfg->detect.threshold * PEER_LIMIT_FACTOR;
    if (scaled > v)
        v = scaled > PCDN_LIMIT_MAX ? PCDN_LIMIT_MAX : (int)scaled;
    if (cfg->memory.low_memory)
        v = cfg->detect.threshold;
    if (cfg->memory.has_peer_limit)
        v = cfg->memory.peer_limit;
    int r = normalize_peer_limit(v, cfg->detect.threshold);
    return r > PCDN_LIMIT_MAX ? PCDN_LIMIT_MAX : r;
}

int config_max_ports_value(const config_t *cfg)
{
    if (!cfg->memory.has_max_ports)
        return DEFAULT_MAX_PORTS;
    if (cfg->memory.max_ports <= 0)
        return 0;
    return cfg->memory.max_ports > PCDN_LIMIT_MAX ? PCDN_LIMIT_MAX : cfg->memory.max_ports;
}

int config_device_ip_limit(const config_t *cfg)
{
    if (!cfg->http.has_device_ip_limit || cfg->http.device_ip_limit <= 0)
        return DEFAULT_DEVICE_IP_LIMIT;
    return cfg->http.device_ip_limit;
}

int config_cors_max_age(const config_t *cfg)
{
    if (!cfg->http.has_cors_max_age)
        return DEFAULT_CORS_MAX_AGE;
    if (cfg->http.cors_max_age < 0)
        return 0;
    return cfg->http.cors_max_age;
}

const char *config_http_listen(const config_t *cfg)
{
    if (str_empty(cfg->http.listen))
        return DEFAULT_HTTP_LISTEN;
    return cfg->http.listen;
}

bool config_http_no_token(const config_t *cfg)
{
    const char *t = cfg->http.token;
    if (!t)
        return false;
    while (isspace((unsigned char)*t))
        t++;
    size_t n = strlen(t);
    while (n > 0 && isspace((unsigned char)t[n - 1]))
        n--;
    const char *want = TOKEN_ALLOW_NO_TOKEN;
    return strlen(want) == n && strncmp(t, want, n) == 0;
}

const char *config_http_bearer_token(const config_t *cfg)
{
    if (config_http_no_token(cfg))
        return "";
    return cfg->http.token ? cfg->http.token : "";
}

char *config_state_file_path(const config_t *cfg)
{
    const char *dir = cfg->http.state_dir;
    if (!dir || str_empty(dir))
        dir = "/tmp";
    size_t n = strlen(dir) + strlen(STATE_FILE_NAME) + 2;
    char *p = xmalloc(n);
    snprintf(p, n, "%s/%s", dir, STATE_FILE_NAME);
    return p;
}

bool config_ban_both(const config_t *cfg)
{
    return cfg->firewall.ban_both;
}

bool config_fullban_enabled(const config_t *cfg)
{
    return cfg->full_ban.mode && strcmp(cfg->full_ban.mode, "off") != 0;
}

bool config_upnp_enabled(const config_t *cfg)
{
    return cfg->upnp.mode && strcmp(cfg->upnp.mode, "off") != 0;
}

int config_fullban_threshold(const config_t *cfg)
{
    return cfg->full_ban.threshold > 0 ? cfg->full_ban.threshold : DEFAULT_FULLBAN_THRESHOLD;
}

/* ------------------------------------------------------------------ */
/* 端口表达式（解析实现见 util.c）                                      */
/* ------------------------------------------------------------------ */

static char *ports_expr(const port_item *items, size_t n, char *err, size_t errlen)
{
    if (n == 0)
        return xstrdup("");
    strbuf sb;
    sb_init(&sb);
    for (size_t i = 0; i < n; i++) {
        if (i)
            sb_addc(&sb, '/');
        if (items[i].is_str) {
            if (!items[i].sval || items[i].sval[0] == '\0') {
                set_err(err, errlen, "端口表达式为空");
                sb_free(&sb);
                return NULL;
            }
            sb_add(&sb, items[i].sval);
        } else {
            sb_addf(&sb, "%" PRId64, items[i].ival);
        }
    }
    return sb_detach(&sb);
}

bool config_parse_port_items(const port_item *items, size_t n, uint16_t **out, size_t *nout,
                             char *err, size_t errlen)
{
    *out = NULL;
    *nout = 0;
    if (n == 0)
        return true;
    char *expr = ports_expr(items, n, err, errlen);
    if (!expr)
        return false;
    bool ok = parse_port_expr(expr, out, nout, err, errlen);
    free(expr);
    return ok;
}

static int cmp_u16(const void *a, const void *b)
{
    uint16_t x = *(const uint16_t *)a;
    uint16_t y = *(const uint16_t *)b;
    return (x > y) - (x < y);
}

static void sort_dedup(uint16_t *ports, size_t *n)
{
    if (*n == 0)
        return;
    qsort(ports, *n, sizeof(uint16_t), cmp_u16);
    size_t j = 1;
    for (size_t i = 1; i < *n; i++) {
        if (ports[i] != ports[j - 1])
            ports[j++] = ports[i];
    }
    *n = j;
}

static bool ports_or_default(const port_item *items, size_t n, const uint16_t *def,
                             size_t ndef, uint16_t **out, size_t *nout, char *err,
                             size_t errlen)
{
    if (!config_parse_port_items(items, n, out, nout, err, errlen))
        return false;
    if (*nout == 0) {
        *out = xmalloc(ndef * sizeof(uint16_t));
        memcpy(*out, def, ndef * sizeof(uint16_t));
        *nout = ndef;
    }
    sort_dedup(*out, nout);
    return true;
}

bool config_fullban_allow(const config_t *cfg, uint16_t **out, size_t *n, char *err,
                          size_t errlen)
{
    if (!ports_or_default(cfg->full_ban.allow, cfg->full_ban.nallow, default_fullban_allow,
                          ARRAY_LEN(default_fullban_allow), out, n, err, errlen)) {
        if (err && errlen) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "[full_ban] allow：%s", err);
            snprintf(err, errlen, "%s", tmp);
        }
        return false;
    }
    return true;
}

bool config_upnp_ports(const config_t *cfg, uint16_t **out, size_t *n, char *err, size_t errlen)
{
    if (!ports_or_default(cfg->upnp.ports, cfg->upnp.nports, default_upnp_ports,
                          ARRAY_LEN(default_upnp_ports), out, n, err, errlen)) {
        if (err && errlen) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "[upnp] ports：%s", err);
            snprintf(err, errlen, "%s", tmp);
        }
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* 名单                                                                */
/* ------------------------------------------------------------------ */

bool config_list_entries(const config_t *cfg, char ***black, size_t *nblack, char ***white,
                         size_t *nwhite, char *err, size_t errlen)
{
    *black = NULL;
    *white = NULL;
    *nblack = 0;
    *nwhite = 0;

    for (int pass = 0; pass < 2; pass++) {
        const list_entry *entries = pass == 0 ? cfg->filter.blacklist : cfg->filter.whitelist;
        size_t n = pass == 0 ? cfg->filter.nblack : cfg->filter.nwhite;
        char ***dst = pass == 0 ? black : white;
        size_t *dstn = pass == 0 ? nblack : nwhite;
        const char *label = pass == 0 ? "黑名单" : "白名单";
        for (size_t i = 0; i < n; i++) {
            if (!entries[i].enabled)
                continue;
            if (str_empty(entries[i].mac)) {
                set_err(err, errlen, "%s条目缺少 mac 字段", label);
                return false;
            }
            char *expr = ports_expr(entries[i].ports, entries[i].nports, err, errlen);
            if (!expr) {
                char tmp[512];
                snprintf(tmp, sizeof(tmp), "%s %s：%s", label, entries[i].mac, err ? err : "");
                set_err(err, errlen, "%s", tmp);
                return false;
            }
            char *item;
            if (expr[0] == '\0') {
                item = xstrdup(entries[i].mac);
            } else {
                size_t len = strlen(entries[i].mac) + strlen(expr) + 2;
                item = xmalloc(len);
                snprintf(item, len, "%s:%s", entries[i].mac, expr);
            }
            free(expr);
            *dst = xrealloc(*dst, (*dstn + 1) * sizeof(char *));
            (*dst)[(*dstn)++] = item;
        }
    }
    return true;
}

bool config_blacklist_port_warnings(const config_t *cfg, char ***macs, size_t *n, char *err,
                                    size_t errlen)
{
    (void)err;
    (void)errlen;
    *macs = NULL;
    *n = 0;
    if (!cfg->filter.list_mode || strcmp(cfg->filter.list_mode, "blacklist") != 0)
        return true;
    for (size_t i = 0; i < cfg->filter.nblack; i++) {
        const list_entry *e = &cfg->filter.blacklist[i];
        if (!e->enabled || str_empty(e->mac) || e->nports == 0)
            continue;
        *macs = xrealloc(*macs, (*n + 1) * sizeof(char *));
        (*macs)[(*n)++] = xstrdup(e->mac);
    }
    return true;
}

static bool mac_in_list(const char *mac, char **list, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(mac, list[i]) == 0)
            return true;
    }
    return false;
}

static bool collect_list_macs(const list_entry *entries, size_t n, bool marked_only,
                              char ***out, size_t *nout, char *err, size_t errlen)
{
    for (size_t i = 0; i < n; i++) {
        const list_entry *e = &entries[i];
        if (!e->enabled)
            continue;
        if (marked_only && !e->upnp)
            continue;
        if (str_empty(e->mac)) {
            set_err(err, errlen, "条目缺少 mac 字段");
            return false;
        }
        pcdn_mac mac;
        if (!mac_parse(e->mac, &mac, err, errlen)) {
            char tmp[256];
            snprintf(tmp, sizeof(tmp), "条目 MAC 无效：\"%s\"", e->mac);
            set_err(err, errlen, "%s", tmp);
            return false;
        }
        char s[32];
        mac_format(&mac, s, sizeof(s));
        if (mac_in_list(s, *out, *nout))
            continue;
        *out = xrealloc(*out, (*nout + 1) * sizeof(char *));
        (*out)[(*nout)++] = xstrdup(s);
    }
    return true;
}

bool config_fullban_devices(const config_t *cfg, char ***out, size_t *n, char *err,
                            size_t errlen)
{
    *out = NULL;
    *n = 0;
    for (int pass = 0; pass < 2; pass++) {
        const list_entry *entries = pass == 0 ? cfg->filter.blacklist : cfg->filter.whitelist;
        size_t cnt = pass == 0 ? cfg->filter.nblack : cfg->filter.nwhite;
        for (size_t i = 0; i < cnt; i++) {
            const list_entry *e = &entries[i];
            if (!e->enabled || !e->full_ban)
                continue;
            if (str_empty(e->mac)) {
                set_err(err, errlen, "full_ban 条目缺少 mac 字段");
                return false;
            }
            pcdn_mac mac;
            if (!mac_parse(e->mac, &mac, err, errlen)) {
                char tmp[256];
                snprintf(tmp, sizeof(tmp), "full_ban 条目 MAC 无效：\"%s\"", e->mac);
                set_err(err, errlen, "%s", tmp);
                return false;
            }
            char s[32];
            mac_format(&mac, s, sizeof(s));
            if (mac_in_list(s, *out, *n))
                continue;
            *out = xrealloc(*out, (*n + 1) * sizeof(char *));
            (*out)[(*n)++] = xstrdup(s);
        }
    }
    return true;
}

void upnp_filter_free(upnp_filter *f)
{
    if (!f)
        return;
    for (size_t i = 0; i < f->ndevices; i++)
        free(f->devices[i]);
    free(f->devices);
    memset(f, 0, sizeof(*f));
}

bool config_upnp_filter_value(const config_t *cfg, upnp_filter *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    if (!config_upnp_enabled(cfg))
        return true;

    bool marked = strcmp(cfg->upnp.mode, "device") == 0;
    if (cfg->filter.list_mode && strcmp(cfg->filter.list_mode, "blacklist") == 0) {
        out->block_all = false;
        return collect_list_macs(cfg->filter.blacklist, cfg->filter.nblack, marked,
                                 &out->devices, &out->ndevices, err, errlen);
    }
    /* 白名单（默认）模式：拦截全部，仅放行名单内设备 */
    out->block_all = true;
    return collect_list_macs(cfg->filter.whitelist, cfg->filter.nwhite, marked, &out->devices,
                             &out->ndevices, err, errlen);
}

/* ------------------------------------------------------------------ */
/* TOML 读取辅助（tomlc99）                                            */
/* ------------------------------------------------------------------ */

static bool check_unknown(const toml_table_t *tbl, const char *path,
                          const char *const *known, size_t nknown, char *err, size_t errlen)
{
    for (int i = 0;; i++) {
        const char *key = toml_key_in(tbl, i);
        if (!key)
            break;
        if (!str_in(key, known, nknown)) {
            if (path && path[0])
                set_err(err, errlen, "未知配置项：%s.%s", path, key);
            else
                set_err(err, errlen, "未知配置项：%s", key);
            return false;
        }
    }
    return true;
}

static bool get_table(const toml_table_t *tbl, const char *key, const char *path,
                      const toml_table_t **out, char *err, size_t errlen)
{
    *out = NULL;
    if (!toml_key_exists(tbl, key))
        return true;
    const toml_table_t *t = toml_table_in(tbl, key);
    if (!t) {
        set_err(err, errlen, "配置项 %s 类型错误（需要表）", path);
        return false;
    }
    *out = t;
    return true;
}

static bool get_str(const toml_table_t *tbl, const char *key, const char *path, char **dst,
                    char *err, size_t errlen)
{
    if (!toml_key_exists(tbl, key))
        return true;
    toml_datum_t d = toml_string_in(tbl, key);
    if (!d.ok) {
        set_err(err, errlen, "配置项 %s 类型错误（需要字符串）", path);
        return false;
    }
    free(*dst);
    *dst = xstrdup(d.u.s);
    free(d.u.s);
    return true;
}

static bool get_bool(const toml_table_t *tbl, const char *key, const char *path, bool *dst,
                     char *err, size_t errlen)
{
    if (!toml_key_exists(tbl, key))
        return true;
    toml_datum_t d = toml_bool_in(tbl, key);
    if (!d.ok) {
        set_err(err, errlen, "配置项 %s 类型错误（需要布尔值）", path);
        return false;
    }
    *dst = d.u.b != 0;
    return true;
}

static bool get_int(const toml_table_t *tbl, const char *key, const char *path, int *dst,
                    bool *present, char *err, size_t errlen)
{
    if (!toml_key_exists(tbl, key))
        return true;
    toml_datum_t d = toml_int_in(tbl, key);
    if (!d.ok) {
        set_err(err, errlen, "配置项 %s 类型错误（需要整数）", path);
        return false;
    }
    if (d.u.i < INT32_MIN || d.u.i > INT32_MAX) {
        set_err(err, errlen, "配置项 %s 超出范围", path);
        return false;
    }
    *dst = (int)d.u.i;
    if (present)
        *present = true;
    return true;
}

static bool get_duration(const toml_table_t *tbl, const char *key, const char *path,
                         int64_t *dst, char *err, size_t errlen)
{
    if (!toml_key_exists(tbl, key))
        return true;
    toml_datum_t di = toml_int_in(tbl, key);
    if (di.ok) {
        if (di.u.i > INT64_MAX / 1000000000LL || di.u.i < INT64_MIN / 1000000000LL) {
            set_err(err, errlen, "配置项 %s 时长超出范围", path);
            return false;
        }
        *dst = di.u.i * 1000000000LL;
        return true;
    }
    toml_datum_t ds = toml_string_in(tbl, key);
    if (!ds.ok) {
        set_err(err, errlen, "配置项 %s 类型错误（需要字符串时长或整数秒）", path);
        return false;
    }
    bool ok = parse_duration(ds.u.s, dst, err, errlen);
    free(ds.u.s);
    return ok;
}

static bool get_ports(const toml_table_t *tbl, const char *key, const char *path,
                      port_item **out, size_t *nout, char *err, size_t errlen)
{
    if (!toml_key_exists(tbl, key))
        return true;
    toml_array_t *arr = toml_array_in(tbl, key);
    if (!arr) {
        set_err(err, errlen, "配置项 %s 类型错误（需要数组）", path);
        return false;
    }
    int n = toml_array_nelem(arr);
    port_item *items = xcalloc((size_t)(n > 0 ? n : 1), sizeof(port_item));
    for (int i = 0; i < n; i++) {
        toml_datum_t di = toml_int_at(arr, i);
        if (di.ok) {
            items[i].is_str = false;
            items[i].ival = di.u.i;
            continue;
        }
        toml_datum_t ds = toml_string_at(arr, i);
        if (ds.ok) {
            items[i].is_str = true;
            items[i].sval = xstrdup(ds.u.s);
            free(ds.u.s);
            continue;
        }
        for (int j = 0; j < i; j++)
            free(items[j].sval);
        free(items);
        set_err(err, errlen, "配置项 %s 的元素类型无效（需要整数或字符串）", path);
        return false;
    }
    free_port_items(*out, *nout);
    *out = items;
    *nout = (size_t)n;
    return true;
}

static bool get_str_array(const toml_table_t *tbl, const char *key, const char *path,
                          char ***out, size_t *nout, char *err, size_t errlen)
{
    if (!toml_key_exists(tbl, key))
        return true;
    toml_array_t *arr = toml_array_in(tbl, key);
    if (!arr) {
        set_err(err, errlen, "配置项 %s 类型错误（需要字符串数组）", path);
        return false;
    }
    int n = toml_array_nelem(arr);
    char **items = xcalloc((size_t)(n > 0 ? n : 1), sizeof(char *));
    for (int i = 0; i < n; i++) {
        toml_datum_t d = toml_string_at(arr, i);
        if (!d.ok) {
            for (int j = 0; j < i; j++)
                free(items[j]);
            free(items);
            set_err(err, errlen, "配置项 %s 的元素类型无效（需要字符串）", path);
            return false;
        }
        items[i] = xstrdup(d.u.s);
        free(d.u.s);
    }
    for (size_t i = 0; i < *nout; i++)
        free((*out)[i]);
    free(*out);
    *out = items;
    *nout = (size_t)n;
    return true;
}

/* ------------------------------------------------------------------ */
/* 解析                                                                */
/* ------------------------------------------------------------------ */

static bool parse_list_entries(const toml_table_t *tbl, const char *key, const char *path,
                               list_entry **out, size_t *nout, char *err, size_t errlen)
{
    static const char *const known[] = {"mac", "ports", "enabled", "full_ban", "upnp"};
    if (!toml_key_exists(tbl, key))
        return true;
    toml_array_t *arr = toml_array_in(tbl, key);
    if (!arr) {
        set_err(err, errlen, "配置项 %s 类型错误（需要数组表）", path);
        return false;
    }
    int n = toml_array_nelem(arr);
    list_entry *entries = xcalloc((size_t)(n > 0 ? n : 1), sizeof(list_entry));
    for (int i = 0; i < n; i++) {
        toml_table_t *t = toml_table_at(arr, i);
        char itempath[128];
        snprintf(itempath, sizeof(itempath), "%s[%d]", path, i);
        if (!t) {
            set_err(err, errlen, "配置项 %s 类型错误（需要表）", itempath);
            goto fail;
        }
        if (!check_unknown(t, itempath, known, ARRAY_LEN(known), err, errlen))
            goto fail;
        entries[i].mac = xstrdup("");
        entries[i].enabled = true;
        if (!get_str(t, "mac", itempath, &entries[i].mac, err, errlen))
            goto fail;
        if (!get_ports(t, "ports", itempath, &entries[i].ports, &entries[i].nports, err,
                       errlen))
            goto fail;
        if (!get_bool(t, "enabled", itempath, &entries[i].enabled, err, errlen))
            goto fail;
        if (!get_bool(t, "full_ban", itempath, &entries[i].full_ban, err, errlen))
            goto fail;
        if (!get_bool(t, "upnp", itempath, &entries[i].upnp, err, errlen))
            goto fail;
    }
    free_list_entries(*out, *nout);
    *out = entries;
    *nout = (size_t)n;
    return true;
fail:
    free_list_entries(entries, (size_t)n);
    return false;
}

static bool normalize_list_mode(const char *s, char **out, char *err, size_t errlen)
{
    const char *orig = s;
    char buf[32];
    size_t n = 0;
    while (s && isspace((unsigned char)*s))
        s++;
    while (s && *s && n + 1 < sizeof(buf)) {
        buf[n++] = (char)tolower((unsigned char)*s);
        s++;
    }
    while (n > 0 && isspace((unsigned char)buf[n - 1]))
        n--;
    buf[n] = '\0';
    if (n == 0 || strcmp(buf, "whitelist") == 0 || strcmp(buf, "white") == 0 ||
        strcmp(buf, "wl") == 0) {
        free(*out);
        *out = xstrdup("whitelist");
        return true;
    }
    if (strcmp(buf, "blacklist") == 0 || strcmp(buf, "black") == 0 || strcmp(buf, "bl") == 0) {
        free(*out);
        *out = xstrdup("blacklist");
        return true;
    }
    set_err(err, errlen, "list_mode 无效 \"%s\"（可选 blacklist / whitelist）",
            orig ? orig : "");
    return false;
}

static bool normalize_proto(const char *s, char **out, char *err, size_t errlen)
{
    const char *orig = s;
    char buf[16];
    size_t n = 0;
    while (s && isspace((unsigned char)*s))
        s++;
    while (s && *s && n + 1 < sizeof(buf)) {
        buf[n++] = (char)tolower((unsigned char)*s);
        s++;
    }
    buf[n] = '\0';
    if (n == 0 || strcmp(buf, "udp") == 0) {
        free(*out);
        *out = xstrdup("udp");
        return true;
    }
    if (strcmp(buf, "tcp") == 0 || strcmp(buf, "all") == 0) {
        free(*out);
        *out = xstrdup(buf);
        return true;
    }
    set_err(err, errlen, "protocol 无效 \"%s\"（可选 udp / tcp / all）", orig ? orig : "");
    return false;
}

static bool normalize_mode(const char *s, const char *what, char **out, char *err,
                           size_t errlen)
{
    const char *orig = s;
    char buf[32];
    size_t n = 0;
    while (s && isspace((unsigned char)*s))
        s++;
    while (s && *s && n + 1 < sizeof(buf)) {
        buf[n++] = (char)tolower((unsigned char)*s);
        s++;
    }
    while (n > 0 && isspace((unsigned char)buf[n - 1]))
        n--;
    buf[n] = '\0';
    const char *val = NULL;
    if (n == 0 || strcmp(buf, "off") == 0 || strcmp(buf, "none") == 0 ||
        strcmp(buf, "disable") == 0 || strcmp(buf, "disabled") == 0)
        val = "off";
    else if (strcmp(buf, "on") == 0 || strcmp(buf, "all") == 0 ||
             strcmp(buf, "enable") == 0 || strcmp(buf, "enabled") == 0)
        val = "on";
    else if (strcmp(buf, "device") == 0 || strcmp(buf, "dev") == 0 ||
             strcmp(buf, "filter") == 0)
        val = "device";
    if (!val) {
        set_err(err, errlen, "%s 无效 \"%s\"（可选 off / on / device）", what,
                orig ? orig : "");
        return false;
    }
    free(*out);
    *out = xstrdup(val);
    return true;
}

static bool parse_detect(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"threshold", "window", "alert_duration", "interval"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "detect", "detect", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "detect", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (!get_int(t, "threshold", "detect.threshold", &cfg->detect.threshold, NULL, err, errlen))
        return false;
    if (!get_duration(t, "window", "detect.window", &cfg->detect.window, err, errlen))
        return false;
    if (!get_duration(t, "alert_duration", "detect.alert_duration", &cfg->detect.alert_duration,
                      err, errlen))
        return false;
    if (!get_duration(t, "interval", "detect.interval", &cfg->detect.interval, err, errlen))
        return false;
    return true;
}

static bool parse_capture(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"interface", "promisc",    "frame_size",
                                        "block_size", "num_blocks", "snaplen",
                                        "protocol"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "capture", "capture", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "capture", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (!get_str(t, "interface", "capture.interface", &cfg->capture.iface, err, errlen))
        return false;
    if (!get_bool(t, "promisc", "capture.promisc", &cfg->capture.promisc, err, errlen))
        return false;
    if (!get_int(t, "frame_size", "capture.frame_size", &cfg->capture.frame_size, NULL, err,
                 errlen))
        return false;
    if (!get_int(t, "block_size", "capture.block_size", &cfg->capture.block_size, NULL, err,
                 errlen))
        return false;
    if (!get_int(t, "num_blocks", "capture.num_blocks", &cfg->capture.num_blocks, NULL, err,
                 errlen))
        return false;
    if (!get_int(t, "snaplen", "capture.snaplen", &cfg->capture.snaplen, NULL, err, errlen))
        return false;
    if (toml_key_exists(t, "protocol")) {
        toml_datum_t d = toml_string_in(t, "protocol");
        if (!d.ok) {
            set_err(err, errlen, "配置项 capture.protocol 类型错误（需要字符串）");
            return false;
        }
        bool ok = normalize_proto(d.u.s, &cfg->capture.protocol, err, errlen);
        free(d.u.s);
        if (!ok)
            return false;
    }
    return true;
}

static bool parse_memory(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"memory_limit", "gc_percent", "low_memory",
                                        "peer_limit", "max_ports"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "memory", "memory", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "memory", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (!get_str(t, "memory_limit", "memory.memory_limit", &cfg->memory.memory_limit, err,
                 errlen))
        return false;
    if (!get_int(t, "gc_percent", "memory.gc_percent", &cfg->memory.gc_percent,
                 &cfg->memory.has_gc_percent, err, errlen))
        return false;
    if (!get_bool(t, "low_memory", "memory.low_memory", &cfg->memory.low_memory, err, errlen))
        return false;
    if (!get_int(t, "peer_limit", "memory.peer_limit", &cfg->memory.peer_limit,
                 &cfg->memory.has_peer_limit, err, errlen))
        return false;
    if (!get_int(t, "max_ports", "memory.max_ports", &cfg->memory.max_ports,
                 &cfg->memory.has_max_ports, err, errlen))
        return false;
    return true;
}

static bool parse_log(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"level", "timezone", "hide_address"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "log", "log", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "log", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (!get_str(t, "level", "log.level", &cfg->log.level, err, errlen))
        return false;
    if (!get_str(t, "timezone", "log.timezone", &cfg->log.timezone, err, errlen))
        return false;
    if (!get_bool(t, "hide_address", "log.hide_address", &cfg->log.hide_address, err, errlen))
        return false;
    return true;
}

static bool parse_http(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"enabled",      "listen",
                                        "token",        "device_ip_limit",
                                        "state_dir",    "cors_allowed_origins",
                                        "cors_allow_credentials", "cors_max_age"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "http", "http", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "http", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (!get_bool(t, "enabled", "http.enabled", &cfg->http.enabled, err, errlen))
        return false;
    if (!get_str(t, "listen", "http.listen", &cfg->http.listen, err, errlen))
        return false;
    if (!get_str(t, "token", "http.token", &cfg->http.token, err, errlen))
        return false;
    if (!get_int(t, "device_ip_limit", "http.device_ip_limit", &cfg->http.device_ip_limit,
                 &cfg->http.has_device_ip_limit, err, errlen))
        return false;
    if (!get_str(t, "state_dir", "http.state_dir", &cfg->http.state_dir, err, errlen))
        return false;
    if (!get_str_array(t, "cors_allowed_origins", "http.cors_allowed_origins",
                       &cfg->http.cors_origins, &cfg->http.ncors, err, errlen))
        return false;
    if (!get_bool(t, "cors_allow_credentials", "http.cors_allow_credentials",
                  &cfg->http.cors_allow_credentials, err, errlen))
        return false;
    if (!get_int(t, "cors_max_age", "http.cors_max_age", &cfg->http.cors_max_age,
                 &cfg->http.has_cors_max_age, err, errlen))
        return false;
    return true;
}

static bool parse_filter(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"list_mode", "blacklist", "whitelist"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "filter", "filter", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "filter", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (toml_key_exists(t, "list_mode")) {
        toml_datum_t d = toml_string_in(t, "list_mode");
        if (!d.ok) {
            set_err(err, errlen, "配置项 filter.list_mode 类型错误（需要字符串）");
            return false;
        }
        bool ok = normalize_list_mode(d.u.s, &cfg->filter.list_mode, err, errlen);
        free(d.u.s);
        if (!ok)
            return false;
    }
    if (!parse_list_entries(t, "blacklist", "filter.blacklist", &cfg->filter.blacklist,
                            &cfg->filter.nblack, err, errlen))
        return false;
    if (!parse_list_entries(t, "whitelist", "filter.whitelist", &cfg->filter.whitelist,
                            &cfg->filter.nwhite, err, errlen))
        return false;
    return true;
}

static bool parse_firewall(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"enabled", "backend", "ban_both", "ban_active_alerts",
                                        "timeout", "hook", "iptables", "nftables"};
    static const char *const hook_known[] = {"cmd"};
    static const char *const ipt_known[] = {"chain", "input_chain", "ban_chain", "upnp_chain"};
    static const char *const nft_known[] = {"table", "set", "hook", "input_hook", "ban_ttl"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "firewall", "firewall", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "firewall", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (!get_bool(t, "enabled", "firewall.enabled", &cfg->firewall.enabled, err, errlen))
        return false;
    if (!get_str(t, "backend", "firewall.backend", &cfg->firewall.backend, err, errlen))
        return false;
    if (!get_bool(t, "ban_both", "firewall.ban_both", &cfg->firewall.ban_both, err, errlen))
        return false;
    if (!get_bool(t, "ban_active_alerts", "firewall.ban_active_alerts",
                  &cfg->firewall.ban_active_alerts, err, errlen))
        return false;
    if (!get_duration(t, "timeout", "firewall.timeout", &cfg->firewall.timeout_ns, err, errlen))
        return false;

    const toml_table_t *hook = NULL;
    if (!get_table(t, "hook", "firewall.hook", &hook, err, errlen))
        return false;
    if (hook) {
        if (!check_unknown(hook, "firewall.hook", hook_known, ARRAY_LEN(hook_known), err,
                           errlen))
            return false;
        if (!get_str(hook, "cmd", "firewall.hook.cmd", &cfg->firewall.hook_cmd, err, errlen))
            return false;
    }
    const toml_table_t *ipt = NULL;
    if (!get_table(t, "iptables", "firewall.iptables", &ipt, err, errlen))
        return false;
    if (ipt) {
        if (!check_unknown(ipt, "firewall.iptables", ipt_known, ARRAY_LEN(ipt_known), err,
                           errlen))
            return false;
        if (!get_str(ipt, "chain", "firewall.iptables.chain", &cfg->firewall.ipt_chain, err,
                     errlen))
            return false;
        if (!get_str(ipt, "input_chain", "firewall.iptables.input_chain",
                     &cfg->firewall.ipt_input_chain, err, errlen))
            return false;
        if (!get_str(ipt, "ban_chain", "firewall.iptables.ban_chain",
                     &cfg->firewall.ipt_ban_chain, err, errlen))
            return false;
        if (!get_str(ipt, "upnp_chain", "firewall.iptables.upnp_chain",
                     &cfg->firewall.ipt_upnp_chain, err, errlen))
            return false;
    }
    const toml_table_t *nft = NULL;
    if (!get_table(t, "nftables", "firewall.nftables", &nft, err, errlen))
        return false;
    if (nft) {
        if (!check_unknown(nft, "firewall.nftables", nft_known, ARRAY_LEN(nft_known), err,
                           errlen))
            return false;
        if (!get_str(nft, "table", "firewall.nftables.table", &cfg->firewall.nft_table, err,
                     errlen))
            return false;
        if (!get_str(nft, "set", "firewall.nftables.set", &cfg->firewall.nft_set, err, errlen))
            return false;
        if (!get_str(nft, "hook", "firewall.nftables.hook", &cfg->firewall.nft_hook, err,
                     errlen))
            return false;
        if (!get_str(nft, "input_hook", "firewall.nftables.input_hook",
                     &cfg->firewall.nft_input_hook, err, errlen))
            return false;
        if (!get_duration(nft, "ban_ttl", "firewall.nftables.ban_ttl",
                          &cfg->firewall.nft_ban_ttl_ns, err, errlen))
            return false;
    }
    return true;
}

static bool parse_fullban(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"mode", "threshold", "allow", "hook"};
    static const char *const hook_known[] = {"cmd"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "full_ban", "full_ban", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "full_ban", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (toml_key_exists(t, "mode")) {
        toml_datum_t d = toml_string_in(t, "mode");
        if (!d.ok) {
            set_err(err, errlen, "配置项 full_ban.mode 类型错误（需要字符串）");
            return false;
        }
        bool ok = normalize_mode(d.u.s, "full_ban", &cfg->full_ban.mode, err, errlen);
        free(d.u.s);
        if (!ok)
            return false;
    }
    if (!get_int(t, "threshold", "full_ban.threshold", &cfg->full_ban.threshold, NULL, err,
                 errlen))
        return false;
    if (!get_ports(t, "allow", "full_ban.allow", &cfg->full_ban.allow, &cfg->full_ban.nallow,
                   err, errlen))
        return false;
    const toml_table_t *hook = NULL;
    if (!get_table(t, "hook", "full_ban.hook", &hook, err, errlen))
        return false;
    if (hook) {
        if (!check_unknown(hook, "full_ban.hook", hook_known, ARRAY_LEN(hook_known), err,
                           errlen))
            return false;
        if (!get_str(hook, "cmd", "full_ban.hook.cmd", &cfg->full_ban.hook_cmd, err, errlen))
            return false;
    }
    return true;
}

static bool parse_upnp(const toml_table_t *root, config_t *cfg, char *err, size_t errlen)
{
    static const char *const known[] = {"mode", "ports", "hook"};
    static const char *const hook_known[] = {"cmd"};
    const toml_table_t *t = NULL;
    if (!get_table(root, "upnp", "upnp", &t, err, errlen))
        return false;
    if (!t)
        return true;
    if (!check_unknown(t, "upnp", known, ARRAY_LEN(known), err, errlen))
        return false;
    if (toml_key_exists(t, "mode")) {
        toml_datum_t d = toml_string_in(t, "mode");
        if (!d.ok) {
            set_err(err, errlen, "配置项 upnp.mode 类型错误（需要字符串）");
            return false;
        }
        bool ok = normalize_mode(d.u.s, "upnp", &cfg->upnp.mode, err, errlen);
        free(d.u.s);
        if (!ok)
            return false;
    }
    if (!get_ports(t, "ports", "upnp.ports", &cfg->upnp.ports, &cfg->upnp.nports, err, errlen))
        return false;
    const toml_table_t *hook = NULL;
    if (!get_table(t, "hook", "upnp.hook", &hook, err, errlen))
        return false;
    if (hook) {
        if (!check_unknown(hook, "upnp.hook", hook_known, ARRAY_LEN(hook_known), err, errlen))
            return false;
        if (!get_str(hook, "cmd", "upnp.hook.cmd", &cfg->upnp.hook_cmd, err, errlen))
            return false;
    }
    return true;
}

bool config_parse(const char *data, size_t len, config_t *cfg, char *err, size_t errlen)
{
    static const char *const root_known[] = {"detect", "capture", "memory",  "log",
                                             "http",   "filter",  "firewall", "full_ban",
                                             "upnp"};
    config_default(cfg);

    char *buf = xmalloc(len + 1);
    memcpy(buf, data, len);
    buf[len] = '\0';
    char perr[512] = {0};
    toml_table_t *root = toml_parse(buf, perr, sizeof(perr));
    free(buf);
    if (!root) {
        set_err(err, errlen, "%s", perr[0] ? perr : "TOML 解析失败");
        config_free(cfg);
        return false;
    }

    bool ok = check_unknown(root, "", root_known, ARRAY_LEN(root_known), err, errlen) &&
              parse_detect(root, cfg, err, errlen) && parse_capture(root, cfg, err, errlen) &&
              parse_memory(root, cfg, err, errlen) && parse_log(root, cfg, err, errlen) &&
              parse_http(root, cfg, err, errlen) && parse_filter(root, cfg, err, errlen) &&
              parse_firewall(root, cfg, err, errlen) &&
              parse_fullban(root, cfg, err, errlen) && parse_upnp(root, cfg, err, errlen);
    toml_free(root);
    if (!ok) {
        config_free(cfg);
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* 校验                                                                */
/* ------------------------------------------------------------------ */

static bool split_host_port(const char *s, char *host, size_t hostcap, int *port, char *err,
                            size_t errlen)
{
    const char *p = s;
    const char *colon = NULL;
    host[0] = '\0';
    *port = -1;
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end) {
            set_err(err, errlen, "listen 无效（缺少 ']'）：%s", s);
            return false;
        }
        size_t n = (size_t)(end - p - 1);
        if (n >= hostcap)
            n = hostcap - 1;
        memcpy(host, p + 1, n);
        host[n] = '\0';
        if (end[1] != ':') {
            set_err(err, errlen, "listen 无效（应为 host:port）：%s", s);
            return false;
        }
        colon = end + 1;
    } else {
        colon = strrchr(p, ':');
        if (!colon) {
            set_err(err, errlen, "listen 无效（应为 host:port）：%s", s);
            return false;
        }
        size_t n = (size_t)(colon - p);
        if (n >= hostcap)
            n = hostcap - 1;
        memcpy(host, p, n);
        host[n] = '\0';
    }
    const char *ps = colon + 1;
    if (*ps == '\0') {
        set_err(err, errlen, "listen 端口无效：%s", s);
        return false;
    }
    for (const char *q = ps; *q; q++) {
        if (!isdigit((unsigned char)*q)) {
            set_err(err, errlen, "listen 端口无效：%s", s);
            return false;
        }
    }
    long v = strtol(ps, NULL, 10);
    if (v < 0 || v > 65535) {
        set_err(err, errlen, "listen 端口无效：%s", s);
        return false;
    }
    *port = (int)v;
    return true;
}

static bool is_loopback_host(const char *host)
{
    if (str_empty(host))
        return false;
    if (strcmp(host, "localhost") == 0)
        return true;
    pcdn_ip ip;
    char e[128];
    if (!ip_parse(host, &ip, e, sizeof(e)))
        return false;
    return ip_is_loopback(&ip);
}

static bool validate_cors_origin(const char *origin, char *err, size_t errlen)
{
    const char *p = origin;
    while (isspace((unsigned char)*p))
        p++;
    size_t len = strlen(p);
    while (len > 0 && isspace((unsigned char)p[len - 1]))
        len--;
    if (len == 0) {
        set_err(err, errlen, "[http] cors_allowed_origins 不能包含空来源");
        return false;
    }
    char *o = xstrndup(p, len);
    if (strcmp(o, "*") == 0) {
        free(o);
        return true;
    }
    char *sep = strstr(o, "://");
    if (!sep) {
        set_err(err, errlen,
                "[http] cors_allowed_origins 中的来源无效（应为 scheme://host[:port]，或 "
                "\"*\"）：\"%s\"",
                origin);
        free(o);
        return false;
    }
    *sep = '\0';
    char *scheme = o;
    for (char *q = scheme; *q; q++)
        *q = (char)tolower((unsigned char)*q);
    if (strcmp(scheme, "http") != 0 && strcmp(scheme, "https") != 0) {
        set_err(err, errlen, "[http] cors_allowed_origins 中的来源仅支持 http / https：\"%s\"",
                origin);
        free(o);
        return false;
    }
    char *authority = sep + 3;
    char *slash = strchr(authority, '/');
    if (slash) {
        if (strcmp(slash, "/") != 0) {
            set_err(err, errlen, "[http] cors_allowed_origins 中的来源不能带路径：\"%s\"",
                    origin);
            free(o);
            return false;
        }
        *slash = '\0';
    }
    if (authority[0] == '\0' || strchr(authority, '@') || strchr(authority, '?') ||
        strchr(authority, '#') || strchr(authority, '*')) {
        set_err(err, errlen,
                "[http] cors_allowed_origins 中的来源不能带查询 / 片段 / 用户信息或通配子域："
                "\"%s\"",
                origin);
        free(o);
        return false;
    }
    free(o);
    return true;
}

/* HTTP 配置校验（listen 有默认值，故基于整个 config） */
bool config_validate_http(const config_t *cfg, char *err, size_t errlen)
{
    for (size_t i = 0; i < cfg->http.ncors; i++) {
        if (!validate_cors_origin(cfg->http.cors_origins[i], err, errlen))
            return false;
    }
    bool any = false;
    for (size_t i = 0; i < cfg->http.ncors; i++) {
        const char *o = cfg->http.cors_origins[i];
        while (isspace((unsigned char)*o))
            o++;
        if (strcmp(o, "*") == 0)
            any = true;
    }
    if (cfg->http.cors_allow_credentials && any) {
        set_err(err, errlen,
                "[http] cors_allow_credentials = true 时不能使用通配来源 \"*\"，请显式列出允许"
                "的来源");
        return false;
    }
    if (cfg->http.has_cors_max_age && cfg->http.cors_max_age < 0) {
        set_err(err, errlen, "[http] cors_max_age 不能为负数：%d", cfg->http.cors_max_age);
        return false;
    }
    if (!cfg->http.enabled)
        return true;
    char host[256];
    int port = 0;
    if (!split_host_port(config_http_listen(cfg), host, sizeof(host), &port, err, errlen))
        return false;
    (void)port;
    if (!is_loopback_host(host) && config_http_bearer_token(cfg)[0] == '\0' &&
        !config_http_no_token(cfg)) {
        set_err(err, errlen,
                "[http] listen 绑定到非回环地址 %s 时必须配置 http.token（如确需无鉴权，可设 "
                "token = \"allow-no-token\"）",
                config_http_listen(cfg));
        return false;
    }
    return true;
}

bool config_validate(const config_t *cfg, char *err, size_t errlen)
{
    if (str_empty(cfg->capture.iface)) {
        set_err(err, errlen,
                "[capture] interface 未配置：请填写网卡名（如 br-lan），或使用 -i/--interface "
                "指定");
        return false;
    }
    if (cfg->detect.threshold <= 0) {
        set_err(err, errlen, "[detect] threshold 必须大于 0，得到 %d", cfg->detect.threshold);
        return false;
    }
    if (cfg->detect.threshold > PCDN_LIMIT_MAX) {
        set_err(err, errlen, "[detect] threshold 不能超过 %d，得到 %d", PCDN_LIMIT_MAX,
                cfg->detect.threshold);
        return false;
    }
    char d1[64], d2[64], d3[64];
    if (cfg->detect.window <= 0) {
        fmt_duration(cfg->detect.window, d1, sizeof(d1));
        set_err(err, errlen, "[detect] window 必须大于 0，得到 %s", d1);
        return false;
    }
    if (cfg->detect.alert_duration <= 0) {
        fmt_duration(cfg->detect.alert_duration, d2, sizeof(d2));
        set_err(err, errlen, "[detect] alert_duration 必须大于 0，得到 %s", d2);
        return false;
    }
    if (cfg->detect.interval <= 0) {
        fmt_duration(cfg->detect.interval, d3, sizeof(d3));
        set_err(err, errlen, "[detect] interval 必须大于 0，得到 %s", d3);
        return false;
    }

    log_level lv;
    char lerr[256];
    if (!str_empty(cfg->log.level) && !log_parse_level(cfg->log.level, &lv, lerr, sizeof(lerr))) {
        set_err(err, errlen, "[log] %s", lerr);
        return false;
    }

    if (!str_empty(cfg->memory.memory_limit)) {
        int64_t v;
        char merr[256];
        if (!parse_byte_size(cfg->memory.memory_limit, &v, merr, sizeof(merr))) {
            set_err(err, errlen, "[memory] memory_limit 无效：%s", merr);
            return false;
        }
    }
    if (cfg->memory.has_gc_percent &&
        (cfg->memory.gc_percent < 1 || cfg->memory.gc_percent > 1000)) {
        set_err(err, errlen,
                "[memory] gc_percent 须在 1~1000 之间，得到 %d（推荐 20~50）",
                cfg->memory.gc_percent);
        return false;
    }
    if (cfg->memory.has_peer_limit && cfg->memory.peer_limit > PCDN_LIMIT_MAX) {
        set_err(err, errlen, "[memory] peer_limit 不能超过 %d，得到 %d", PCDN_LIMIT_MAX,
                cfg->memory.peer_limit);
        return false;
    }
    if (cfg->memory.has_max_ports && cfg->memory.max_ports > PCDN_LIMIT_MAX) {
        set_err(err, errlen, "[memory] max_ports 不能超过 %d，得到 %d", PCDN_LIMIT_MAX,
                cfg->memory.max_ports);
        return false;
    }

    if (!cfg->filter.list_mode ||
        (strcmp(cfg->filter.list_mode, "blacklist") != 0 &&
         strcmp(cfg->filter.list_mode, "whitelist") != 0)) {
        set_err(err, errlen, "[filter] list_mode 无效：\"%s\"（可选 blacklist / whitelist）",
                cfg->filter.list_mode ? cfg->filter.list_mode : "");
        return false;
    }
    char **black = NULL, **white = NULL;
    size_t nb = 0, nw = 0;
    if (!config_list_entries(cfg, &black, &nb, &white, &nw, err, errlen)) {
        char tmp[600];
        snprintf(tmp, sizeof(tmp), "[filter] %s", err);
        set_err(err, errlen, "%s", tmp);
        goto fail_lists;
    }
    device_filter *flt = NULL;
    char ferr[512];
    if (!filter_create(cfg->filter.list_mode, black, nb, white, nw, &flt, ferr, sizeof(ferr))) {
        set_err(err, errlen, "[filter] %s", ferr);
        goto fail_lists;
    }
    bool empty = filter_is_empty(flt);
    filter_free(flt);
    if (empty) {
        set_err(err, errlen,
                "[filter] list_mode = \"blacklist\" 但未配置 blacklist，将不会检测任何设备");
        goto fail_lists;
    }
    for (size_t i = 0; i < nb; i++)
        free(black[i]);
    for (size_t i = 0; i < nw; i++)
        free(white[i]);
    free(black);
    free(white);

    uint16_t *ports = NULL;
    size_t nports = 0;
    if (!config_fullban_allow(cfg, &ports, &nports, err, errlen))
        return false;
    free(ports);
    ports = NULL;
    nports = 0;
    if (config_fullban_enabled(cfg)) {
        char **devs = NULL;
        size_t ndev = 0;
        if (!config_fullban_devices(cfg, &devs, &ndev, err, errlen)) {
            char tmp[600];
            snprintf(tmp, sizeof(tmp), "[full_ban] %s", err);
            set_err(err, errlen, "%s", tmp);
            for (size_t i = 0; i < ndev; i++)
                free(devs[i]);
            free(devs);
            return false;
        }
        for (size_t i = 0; i < ndev; i++)
            free(devs[i]);
        free(devs);
    }
    ports = NULL;
    nports = 0;
    if (!config_upnp_ports(cfg, &ports, &nports, err, errlen))
        return false;
    free(ports);
    if (config_upnp_enabled(cfg)) {
        upnp_filter uf;
        if (!config_upnp_filter_value(cfg, &uf, err, errlen)) {
            char tmp[600];
            snprintf(tmp, sizeof(tmp), "[upnp] %s", err);
            set_err(err, errlen, "%s", tmp);
            upnp_filter_free(&uf);
            return false;
        }
        upnp_filter_free(&uf);
    }
    if (!config_validate_http(cfg, err, errlen))
        return false;
    if (cfg->firewall.enabled && !firewall_validate_config(cfg, err, errlen))
        return false;
    return true;

fail_lists:
    for (size_t i = 0; i < nb; i++)
        free(black[i]);
    for (size_t i = 0; i < nw; i++)
        free(white[i]);
    free(black);
    free(white);
    return false;
}

/* ------------------------------------------------------------------ */
/* 加载 / 创建                                                         */
/* ------------------------------------------------------------------ */

static bool read_file(const char *path, char **out, size_t *outlen, int *enoent, char *err,
                      size_t errlen)
{
    *out = NULL;
    *outlen = 0;
    *enoent = 0;
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            *enoent = 1;
        set_err(err, errlen, "%s", strerror(errno));
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        set_err(err, errlen, "%s", strerror(errno));
        return false;
    }
    long sz = ftell(f);
    if (sz < 0 || sz > 8 * 1024 * 1024) {
        fclose(f);
        set_err(err, errlen, "文件过大或无法读取");
        return false;
    }
    rewind(f);
    char *buf = xmalloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    if (ferror(f)) {
        fclose(f);
        free(buf);
        set_err(err, errlen, "%s", strerror(errno));
        return false;
    }
    fclose(f);
    buf[rd] = '\0';
    *out = buf;
    *outlen = rd;
    return true;
}

static bool load_explicit(const char *path, config_result *res, char *err, size_t errlen)
{
    char *data = NULL;
    size_t len = 0;
    int enoent = 0;
    char rerr[512];
    if (!read_file(path, &data, &len, &enoent, rerr, sizeof(rerr))) {
        if (enoent)
            set_err(err, errlen, "指定的配置文件不存在：%s", path);
        else
            set_err(err, errlen, "读取配置文件 %s 失败：%s", path, rerr);
        return false;
    }
    config_t cfg;
    if (!config_parse(data, len, &cfg, rerr, sizeof(rerr))) {
        free(data);
        set_err(err, errlen, "解析配置文件 %s 失败：%s", path, rerr);
        return false;
    }
    free(data);
    config_apply_defaults(&cfg);
    memset(res, 0, sizeof(*res));
    res->cfg = cfg;
    res->path = xstrdup(path);
    return true;
}

static bool create_default_file(const char *path, char *err, size_t errlen)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno == EEXIST)
            set_err(err, errlen, "配置文件 %s 已存在，无法创建默认配置", path);
        else
            set_err(err, errlen, "创建配置文件 %s 失败：%s", path, strerror(errno));
        return false;
    }
    size_t len = strlen(config_template);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, config_template + off, len - off);
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            set_err(err, errlen, "写入配置文件 %s 失败：%s", path, strerror(errno));
            return false;
        }
        off += (size_t)n;
    }
    if (close(fd) != 0) {
        set_err(err, errlen, "关闭配置文件 %s 失败：%s", path, strerror(errno));
        return false;
    }
    return true;
}

bool config_load(config_t *cfg, const char *explicit_path, bool has_explicit, bool strict,
                 config_result *res, char *err, size_t errlen)
{
    memset(res, 0, sizeof(*res));
    if (has_explicit) {
        if (!load_explicit(explicit_path ? explicit_path : "", res, err, errlen)) {
            config_result_free(res);
            return false;
        }
        *cfg = res->cfg;
        memset(&res->cfg, 0, sizeof(res->cfg));
        return true;
    }

    for (size_t i = 0; i < ARRAY_LEN(config_candidates); i++) {
        const char *name = config_candidates[i];
        char *data = NULL;
        size_t len = 0;
        int enoent = 0;
        char rerr[512];
        if (!read_file(name, &data, &len, &enoent, rerr, sizeof(rerr))) {
            if (enoent)
                continue;
            warnings_add(res, "读取配置文件 %s 失败，已跳过：%s", name, rerr);
            continue;
        }
        config_t parsed;
        if (!config_parse(data, len, &parsed, rerr, sizeof(rerr))) {
            free(data);
            warnings_add(res, "解析配置文件 %s 失败，已跳过：%s", name, rerr);
            continue;
        }
        free(data);
        config_apply_defaults(&parsed);
        res->cfg = parsed;
        res->path = xstrdup(name);
        *cfg = parsed;
        memset(&res->cfg, 0, sizeof(res->cfg));
        return true;
    }

    if (strict) {
        if (res->nwarnings > 0) {
            strbuf sb;
            sb_init(&sb);
            for (size_t i = 0; i < res->nwarnings; i++) {
                if (i)
                    sb_add(&sb, "；");
                sb_add(&sb, res->warnings[i]);
            }
            set_err(err, errlen, "没有可用的配置文件：%s", sb.p ? sb.p : "");
            sb_free(&sb);
        } else {
            set_err(err, errlen,
                    "未找到配置文件（已查找：config.toml、pcdn-detect.toml），请用 -c/--config "
                    "指定路径");
        }
        return false;
    }

    const char *created = config_create_names[0];
    if (!create_default_file(created, err, errlen)) {
        if (res->nwarnings > 0)
            set_err(err, errlen, "%s；且创建默认配置失败：%s",
                    res->warnings[res->nwarnings - 1], err);
        return false;
    }
    config_t def;
    config_default(&def);
    res->path = xstrdup(created);
    res->created = true;
    *cfg = def;
    return true;
}

bool config_write_default(const char *dir, char *path, size_t pathcap, char *err, size_t errlen)
{
    if (str_empty(dir)) {
        set_err(err, errlen, "未指定要生成配置文件的目录");
        return false;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        if (errno == ENOENT)
            set_err(err, errlen, "目录不存在：%s（请先创建该目录）", dir);
        else
            set_err(err, errlen, "检查目录 %s 失败：%s", dir, strerror(errno));
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        set_err(err, errlen, "%s 不是目录", dir);
        return false;
    }
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", dir, config_create_names[0]);
    if (access(p, F_OK) == 0) {
        set_err(err, errlen, "%s 已存在，未覆盖（如需重新生成请先删除该文件）", p);
        return false;
    }
    if (!create_default_file(p, err, errlen))
        return false;
    snprintf(path, pathcap, "%s", p);
    return true;
}

/* ------------------------------------------------------------------ */
/* 配置比较（reload）                                                  */
/* ------------------------------------------------------------------ */

bool config_capture_equal(const capture_cfg *a, const capture_cfg *b)
{
    return str_eq(a->iface, b->iface) && a->promisc == b->promisc &&
           a->frame_size == b->frame_size && a->block_size == b->block_size &&
           a->num_blocks == b->num_blocks && a->snaplen == b->snaplen &&
           str_eq(a->protocol, b->protocol);
}

bool config_detect_equal(const detect_cfg *a, const detect_cfg *b)
{
    return a->threshold == b->threshold && a->window == b->window &&
           a->alert_duration == b->alert_duration && a->interval == b->interval;
}

static bool port_items_equal(const port_item *a, size_t na, const port_item *b, size_t nb)
{
    if (na != nb)
        return false;
    for (size_t i = 0; i < na; i++) {
        if (a[i].is_str != b[i].is_str)
            return false;
        if (a[i].is_str) {
            if (!str_eq(a[i].sval, b[i].sval))
                return false;
        } else if (a[i].ival != b[i].ival) {
            return false;
        }
    }
    return true;
}

static bool list_entries_equal(const list_entry *a, size_t na, const list_entry *b, size_t nb)
{
    if (na != nb)
        return false;
    for (size_t i = 0; i < na; i++) {
        if (!str_eq(a[i].mac, b[i].mac) || a[i].enabled != b[i].enabled ||
            a[i].full_ban != b[i].full_ban || a[i].upnp != b[i].upnp)
            return false;
        if (!port_items_equal(a[i].ports, a[i].nports, b[i].ports, b[i].nports))
            return false;
    }
    return true;
}

bool config_filter_equal(const filter_cfg *a, const filter_cfg *b)
{
    return str_eq(a->list_mode, b->list_mode) &&
           list_entries_equal(a->blacklist, a->nblack, b->blacklist, b->nblack) &&
           list_entries_equal(a->whitelist, a->nwhite, b->whitelist, b->nwhite);
}

static bool fw_equal(const firewall_cfg *a, const firewall_cfg *b)
{
    return a->enabled == b->enabled && str_eq(a->backend, b->backend) &&
           a->ban_both == b->ban_both && a->ban_active_alerts == b->ban_active_alerts &&
           a->timeout_ns == b->timeout_ns && str_eq(a->hook_cmd, b->hook_cmd) &&
           str_eq(a->ipt_chain, b->ipt_chain) &&
           str_eq(a->ipt_input_chain, b->ipt_input_chain) &&
           str_eq(a->ipt_ban_chain, b->ipt_ban_chain) &&
           str_eq(a->ipt_upnp_chain, b->ipt_upnp_chain) &&
           str_eq(a->nft_table, b->nft_table) && str_eq(a->nft_set, b->nft_set) &&
           str_eq(a->nft_hook, b->nft_hook) &&
           str_eq(a->nft_input_hook, b->nft_input_hook) &&
           a->nft_ban_ttl_ns == b->nft_ban_ttl_ns;
}

bool config_firewall_equal(const config_t *a, const config_t *b)
{
    return fw_equal(&a->firewall, &b->firewall) &&
           str_eq(a->full_ban.mode, b->full_ban.mode) &&
           a->full_ban.threshold == b->full_ban.threshold &&
           port_items_equal(a->full_ban.allow, a->full_ban.nallow, b->full_ban.allow,
                            b->full_ban.nallow) &&
           str_eq(a->full_ban.hook_cmd, b->full_ban.hook_cmd) &&
           str_eq(a->upnp.mode, b->upnp.mode) &&
           port_items_equal(a->upnp.ports, a->upnp.nports, b->upnp.ports, b->upnp.nports) &&
           str_eq(a->upnp.hook_cmd, b->upnp.hook_cmd);
}

bool config_http_cors_equal(const config_t *a, const config_t *b)
{
    if (a->http.ncors != b->http.ncors)
        return false;
    for (size_t i = 0; i < a->http.ncors; i++) {
        if (!str_eq(a->http.cors_origins[i], b->http.cors_origins[i]))
            return false;
    }
    return a->http.cors_allow_credentials == b->http.cors_allow_credentials &&
           a->http.has_cors_max_age == b->http.has_cors_max_age &&
           a->http.cors_max_age == b->http.cors_max_age;
}

/* ------------------------------------------------------------------ */
/* 默认配置模板（tomlc99 解析；与 Go 版本保持一致，另标注 C 运行时的差异） */
/* ------------------------------------------------------------------ */

const char *const config_template =
    "# pcdn-detect 配置文件（首次启动自动生成于当前工作目录，TOML 格式）\n"
    "#\n"
    "# 命令行参数优先于本文件：显式指定的参数会覆盖此处的同名配置。\n"
    "# 配置按功能分块：[detect] 检测、[capture] 抓包、[memory] 内存、\n"
    "# [log] 日志展示、[http] HTTP API、[filter] 黑白名单、[firewall] 防火墙对接、\n"
    "# [full_ban] 全端口封禁、[upnp] UPnP 拦截（后三者默认注释）。\n"
    "\n"
    "# ===== 检测参数 =====\n"
    "[detect]\n"
    "# 触发次数：同一设备同一端口在检测时长内出现的不同远端公网 IP 数量达到该值即判定疑似 PCDN\n"
    "threshold = 20\n"
    "\n"
    "# 检测时长（滑动窗口），支持 \"60s\"、\"5m\"、\"1h\"，也接受整数秒\n"
    "window = \"60s\"\n"
    "\n"
    "# 持续提示时长：期间只要该端口仍有流量（任意对端，无论新旧）就刷新计时器；超过该时长\n"
    "# 没有任何流量则输出「PCDN行为结束」并静默（期间出现新对端时额外输出「持续产生PCDN行为」）\n"
    "alert_duration = \"10m\"\n"
    "\n"
    "# 检测扫描间隔\n"
    "interval = \"2s\"\n"
    "\n"
    "# ===== 抓包 =====\n"
    "[capture]\n"
    "# 要监听的网卡名称（必填），例如 br-lan、br0、eth0\n"
    "interface = \"\"\n"
    "\n"
    "# 是否开启混杂模式\n"
    "promisc = true\n"
    "\n"
    "# 抓包环形缓冲：总内存 = block_size * num_blocks（字节）。\n"
    "# 默认 65536 * 4 = 256KiB；若抓包出现丢包可适当增大 num_blocks（如 8 = 512KiB）。\n"
    "#   frame_size  单个帧上限（字节），须能整除 block_size；默认 2048；\n"
    "#   block_size  每个块大小（字节），须为页大小(4096)与 frame_size 的整数倍；\n"
    "#   num_blocks  块数量，至少为 1。\n"
    "# snaplen 为内核层 BPF 每包复制到用户态的最大字节数（默认 256，只需头部）。\n"
    "frame_size = 2048\n"
    "block_size = 65536\n"
    "num_blocks = 4\n"
    "snaplen = 256\n"
    "\n"
    "# protocol 为内核层过滤器放行的传输层协议（默认 \"udp\"）：\n"
    "#   \"udp\" = 仅放行 UDP；\"tcp\" = 仅放行 TCP；\"all\" = UDP + TCP。\n"
    "# 三种取值都会在内核层丢弃 ARP、STP、ICMP/ICMPv6 等无关报文。\n"
    "# 防火墙的封禁协议随此设置变化（封禁抓包层实际统计的协议）。\n"
    "protocol = \"udp\"\n"
    "\n"
    "# ===== 内存 =====\n"
    "[memory]\n"
    "# 说明：C 版本没有 GC，以下 memory_limit / gc_percent 两项仅为兼容既有配置而保留，\n"
    "# 会被校验但不产生运行时效果；低内存模式 / 对端上限 / 端口上限仍然完全生效。\n"
    "# memory_limit = \"32MiB\"\n"
    "# gc_percent = 30\n"
    "\n"
    "# 低内存模式：端口触发告警后清空对端列表且不再记录新对端，仅保留触发状态\n"
    "low_memory = false\n"
    "\n"
    "# 单端口对端记录上限；省略时默认 max(1000, threshold × 10)，0 表示不限制\n"
    "# peer_limit = 1000\n"
    "\n"
    "# 单设备端口条目上限；省略时默认 512，0 表示不限制\n"
    "# max_ports = 512\n"
    "\n"
    "# ===== 日志展示 =====\n"
    "[log]\n"
    "# 日志输出等级：debug / info / warn / error（默认 warn）\n"
    "level = \"warn\"\n"
    "\n"
    "# 日志时区：IANA 名称（如 Asia/Shanghai）或 POSIX 串（如 CST-8）；留空表示自动读取\n"
    "timezone = \"\"\n"
    "\n"
    "# 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC\n"
    "hide_address = false\n"
    "\n"
    "# ===== HTTP API =====\n"
    "[http]\n"
    "enabled = false\n"
    "listen = \"127.0.0.1:8080\"\n"
    "token = \"\"\n"
    "device_ip_limit = 200\n"
    "# cors_allowed_origins = []\n"
    "# cors_allow_credentials = false\n"
    "# cors_max_age = 600\n"
    "# state_dir = \"\"\n"
    "\n"
    "# ===== 黑白名单 =====\n"
    "[filter]\n"
    "# \"whitelist\"（默认，名单内不检测；空名单即检测全部）或 \"blacklist\"（只检测名单内）\n"
    "list_mode = \"whitelist\"\n"
    "\n"
    "# [[filter.blacklist]]\n"
    "# mac = \"aa:bb:cc:dd:ee:ff\"\n"
    "# ports = [40000, \"40001-40010\"]\n"
    "# enabled = true\n"
    "# full_ban = true\n"
    "# upnp = true\n"
    "\n"
    "# [[filter.whitelist]]\n"
    "# mac = \"aa:bb:cc:dd:ee:ff\"\n"
    "\n"
    "# ===== 防火墙对接 =====\n"
    "# [firewall]\n"
    "# enabled = false\n"
    "# backend = \"hook\"                 # hook / iptables / nftables\n"
    "# ban_both = true\n"
    "# ban_active_alerts = false\n"
    "# timeout = \"5s\"\n"
    "#\n"
    "# [firewall.hook]\n"
    "# cmd = \"my-hook {action} {mac} {ip} {port} {family} {proto}\"\n"
    "#\n"
    "# [firewall.iptables]\n"
    "# chain = \"FORWARD\"\n"
    "# input_chain = \"INPUT\"\n"
    "# ban_chain = \"PCDN_DETECT\"\n"
    "# upnp_chain = \"PCDN_DETECT_UPNP\"\n"
    "#\n"
    "# [firewall.nftables]\n"
    "# table = \"pcdn_detect\"\n"
    "# set = \"banned\"\n"
    "# hook = \"prerouting\"\n"
    "# input_hook = \"input\"\n"
    "# ban_ttl = \"30m\"\n"
    "\n"
    "# ===== 全 UDP 端口封禁 =====\n"
    "# [full_ban]\n"
    "# mode = \"off\"                    # off / on / device\n"
    "# threshold = 5\n"
    "# allow = [53, 123, 67, 68, 546, 547]\n"
    "# [full_ban.hook]\n"
    "# cmd = \"\"\n"
    "\n"
    "# ===== UPnP 拦截 =====\n"
    "# [upnp]\n"
    "# mode = \"off\"                    # off / on / device\n"
    "# ports = [1900, 5000]\n"
    "# [upnp.hook]\n"
    "# cmd = \"\"\n";
