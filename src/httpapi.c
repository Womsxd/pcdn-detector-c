 #include "httpapi.h"

#include <ctype.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "cJSON.h"
#include "http.h"
#include "util.h"

typedef struct {
    char **origins;
    size_t n;
    bool any;
    bool credentials;
    int max_age;
} cors_policy;

struct httpapi {
    detector *det;
    pthread_mutex_t mu;
    blocker *blk;
    char *token;
    int ip_limit;
    cors_policy cors;
    char *listen;
    reload_fn reload;
    void *reload_ctx;
    http_server *srv;
};

static time_t g_process_start;
static pthread_once_t g_process_start_once = PTHREAD_ONCE_INIT;

void reload_result_free(reload_result *r)
{
    if (!r)
        return;
    for (size_t i = 0; i < r->napplied; i++)
        free(r->applied[i]);
    for (size_t i = 0; i < r->nrestart; i++)
        free(r->restart_required[i]);
    free(r->applied);
    free(r->restart_required);
    memset(r, 0, sizeof(*r));
}

static void json_send(http_response *res, int code, cJSON *root)
{
    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    strbuf sb;
    sb_init(&sb);
    if (s) {
        sb_add(&sb, s);
        free(s);
    }
    sb_addc(&sb, '\n');
    http_response_set_body(res, code, "application/json; charset=utf-8", sb.p, sb.n);
    sb_free(&sb);
}

static void json_error(http_response *res, int code, const char *fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "error", msg);
    json_send(res, code, root);
}

static void init_process_start(void)
{
    g_process_start = time(NULL);
}

static int64_t uptime_seconds(void)
{
    /* 多个请求线程并发读取，初始化必须只做一次且对之后所有读可见 */
    pthread_once(&g_process_start_once, init_process_start);
    return (int64_t)(time(NULL) - g_process_start);
}

/* ------------------------------------------------------------------ */
/* CORS                                                                */
/* ------------------------------------------------------------------ */

static void cors_free(cors_policy *p)
{
    for (size_t i = 0; i < p->n; i++)
        free(p->origins[i]);
    free(p->origins);
    memset(p, 0, sizeof(*p));
}

static char *canonical_origin(const char *origin)
{
    if (!origin)
        return xstrdup("");
    while (isspace((unsigned char)*origin))
        origin++;
    size_t len = strlen(origin);
    while (len > 0 && isspace((unsigned char)origin[len - 1]))
        len--;
    char *o = xstrndup(origin, len);
    if (strcmp(o, "*") == 0)
        return o;
    if (len > 0 && o[len - 1] == '/')
        o[len - 1] = '\0';
    char *sep = strstr(o, "://");
    if (sep) {
        *sep = '\0';
        for (char *p = o; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        for (char *p = sep + 3; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        char *res = xmalloc(strlen(o) + 3 + strlen(sep + 3) + 1);
        sprintf(res, "%s://%s", o, sep + 3);
        free(o);
        return res;
    }
    for (char *p = o; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return o;
}

static void cors_set(httpapi *a, char **origins, size_t n, bool credentials, int max_age)
{
    cors_policy p;
    memset(&p, 0, sizeof(p));
    p.credentials = credentials;
    p.max_age = max_age < 0 ? 0 : max_age;
    for (size_t i = 0; i < n; i++) {
        char *o = canonical_origin(origins[i]);
        if (o[0] == '\0') {
            free(o);
            continue;
        }
        if (strcmp(o, "*") == 0) {
            p.any = true;
            free(o);
            continue;
        }
        bool dup = false;
        for (size_t k = 0; k < p.n; k++) {
            if (strcmp(p.origins[k], o) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            p.origins = xrealloc(p.origins, (p.n + 1) * sizeof(char *));
            p.origins[p.n++] = o;
        } else {
            free(o);
        }
    }
    if (p.any)
        p.credentials = false;

    pthread_mutex_lock(&a->mu);
    cors_free(&a->cors);
    a->cors = p;
    pthread_mutex_unlock(&a->mu);
}

static void cors_snapshot(httpapi *a, cors_policy *p)
{
    memset(p, 0, sizeof(*p));
    pthread_mutex_lock(&a->mu);
    p->any = a->cors.any;
    p->credentials = a->cors.credentials;
    p->max_age = a->cors.max_age;
    p->n = a->cors.n;
    if (p->n) {
        p->origins = xmalloc(p->n * sizeof(char *));
        for (size_t i = 0; i < p->n; i++)
            p->origins[i] = xstrdup(a->cors.origins[i]);
    }
    pthread_mutex_unlock(&a->mu);
}

static const char *cors_allow_origin(const cors_policy *p, const char *origin)
{
    if (p->any)
        return "*";
    char *c = canonical_origin(origin);
    for (size_t i = 0; i < p->n; i++) {
        if (strcmp(p->origins[i], c) == 0) {
            free(c);
            return origin;
        }
    }
    free(c);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* 路由 / 鉴权                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *method;
    const char *path;
    void (*fn)(httpapi *a, const http_request *req, http_response *res);
} route_def;

static void handle_health(httpapi *a, const http_request *req, http_response *res);
static void handle_status(httpapi *a, const http_request *req, http_response *res);
static void handle_devices(httpapi *a, const http_request *req, http_response *res);
static void handle_device(httpapi *a, const http_request *req, http_response *res);
static void handle_peers(httpapi *a, const http_request *req, http_response *res);
static void handle_blocks(httpapi *a, const http_request *req, http_response *res);
static void handle_unban(httpapi *a, const http_request *req, http_response *res);
static void handle_reload(httpapi *a, const http_request *req, http_response *res);
static void handle_memory(httpapi *a, const http_request *req, http_response *res);

static const route_def g_routes[] = {
    {"GET", "/api/v1/health", handle_health},
    {"GET", "/api/v1/status", handle_status},
    {"GET", "/api/v1/devices", handle_devices},
    {"GET", "/api/v1/device", handle_device},
    {"GET", "/api/v1/peers", handle_peers},
    {"GET", "/api/v1/blocks", handle_blocks},
    {"POST", "/api/v1/unban", handle_unban},
    {"POST", "/api/v1/reload", handle_reload},
    {"GET", "/dev/memory", handle_memory},
};

static bool path_exists(const char *path)
{
    for (size_t i = 0; i < ARRAY_LEN(g_routes); i++) {
        if (strcmp(g_routes[i].path, path) == 0)
            return true;
    }
    return false;
}

static bool method_allowed(const char *path, const char *method)
{
    for (size_t i = 0; i < ARRAY_LEN(g_routes); i++) {
        if (strcmp(g_routes[i].path, path) != 0)
            continue;
        if (strcmp(g_routes[i].method, method) == 0)
            return true;
        if (strcmp(method, "HEAD") == 0 && strcmp(g_routes[i].method, "GET") == 0)
            return true;
    }
    return false;
}

static void allow_methods(const char *path, char *buf, size_t cap)
{
    const char *methods[8];
    size_t n = 0;
    for (size_t i = 0; i < ARRAY_LEN(g_routes); i++) {
        if (strcmp(g_routes[i].path, path) != 0)
            continue;
        bool dup = false;
        for (size_t k = 0; k < n; k++) {
            if (strcmp(methods[k], g_routes[i].method) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup && n < ARRAY_LEN(methods))
            methods[n++] = g_routes[i].method;
        if (strcmp(g_routes[i].method, "GET") == 0) {
            bool has_head = false;
            for (size_t k = 0; k < n; k++) {
                if (strcmp(methods[k], "HEAD") == 0)
                    has_head = true;
            }
            if (!has_head && n < ARRAY_LEN(methods))
                methods[n++] = "HEAD";
        }
    }
    /* 简单插入排序（方法数很少） */
    for (size_t i = 1; i < n; i++) {
        const char *key = methods[i];
        size_t j = i;
        while (j > 0 && strcmp(methods[j - 1], key) > 0) {
            methods[j] = methods[j - 1];
            j--;
        }
        methods[j] = key;
    }
    size_t off = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < n && off + 2 < cap; i++)
        off += (size_t)snprintf(buf + off, cap - off, "%s%s", i ? ", " : "", methods[i]);
}

static bool ct_equal(const char *a, size_t an, const char *b, size_t bn)
{
    if (an != bn)
        return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < an; i++)
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

static void dispatch(void *ctx, const http_request *req, http_response *res)
{
    httpapi *a = ctx;

    cors_policy cors;
    cors_snapshot(a, &cors);
    pthread_mutex_lock(&a->mu);
    char *token = a->token ? xstrdup(a->token) : NULL;
    pthread_mutex_unlock(&a->mu);

    const char *origin = http_request_header(req, "Origin");
    bool preflight = strcmp(req->method, "OPTIONS") == 0 &&
                     http_request_header(req, "Access-Control-Request-Method") != NULL;
    if ((cors.any || cors.n > 0) && origin) {
        http_response_add_header(res, "Vary", "Origin");
        const char *allow = cors_allow_origin(&cors, origin);
        if (allow) {
            http_response_add_header(res, "Access-Control-Allow-Origin", allow);
            if (cors.credentials)
                http_response_add_header(res, "Access-Control-Allow-Credentials", "true");
        }
        if (preflight) {
            if (!allow) {
                res->status = 204;
                goto out;
            }
            http_response_add_header(res, "Vary", "Access-Control-Request-Method");
            const char *req_headers = http_request_header(req, "Access-Control-Request-Headers");
            if (req_headers && req_headers[0]) {
                http_response_add_header(res, "Access-Control-Allow-Headers", req_headers);
                http_response_add_header(res, "Vary", "Access-Control-Request-Headers");
            } else {
                http_response_add_header(res, "Access-Control-Allow-Headers",
                                         "Authorization, Content-Type");
            }
            if (!path_exists(req->path)) {
                json_error(res, 404, "未找到该端点");
                goto out;
            }
            char allowed[64];
            allow_methods(req->path, allowed, sizeof(allowed));
            http_response_add_header(res, "Access-Control-Allow-Methods", allowed);

            char want[32];
            snprintf(want, sizeof(want), "%s",
                     http_request_header(req, "Access-Control-Request-Method"));
            for (char *p = want; *p; p++)
                *p = (char)toupper((unsigned char)*p);
            if (!method_allowed(req->path, want)) {
                http_response_add_header(res, "Allow", allowed);
                json_error(res, 405, "方法不允许");
                goto out;
            }
            if (cors.max_age > 0) {
                char age[16];
                snprintf(age, sizeof(age), "%d", cors.max_age);
                http_response_add_header(res, "Access-Control-Max-Age", age);
            }
            res->status = 204;
            goto out;
        }
    }

    if (token && token[0]) {
        const char *h = http_request_header(req, "Authorization");
        const char *prefix = "Bearer ";
        bool ok = false;
        if (h && strncmp(h, prefix, strlen(prefix)) == 0) {
            const char *given = h + strlen(prefix);
            ok = ct_equal(given, strlen(given), token, strlen(token));
        }
        if (!ok) {
            json_error(res, 401, "未授权：需要有效的 Bearer 令牌");
            goto out;
        }
    }

    if (!path_exists(req->path)) {
        json_error(res, 404, "未找到该端点");
        goto out;
    }

    for (size_t i = 0; i < ARRAY_LEN(g_routes); i++) {
        if (strcmp(g_routes[i].path, req->path) != 0)
            continue;
        bool match = strcmp(g_routes[i].method, req->method) == 0 ||
                     (strcmp(req->method, "HEAD") == 0 &&
                      strcmp(g_routes[i].method, "GET") == 0);
        if (match) {
            g_routes[i].fn(a, req, res);
            goto out;
        }
    }
    {
        char allowed[64];
        allow_methods(req->path, allowed, sizeof(allowed));
        http_response_add_header(res, "Allow", allowed);
        json_error(res, 405, "方法不允许");
    }

out:
    free(token);
    cors_free(&cors);
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

static bool listen_is_loopback(const char *listen)
{
    char host[256];
    const char *p = listen;
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end)
            return false;
        size_t n = (size_t)(end - p - 1);
        if (n >= sizeof(host))
            n = sizeof(host) - 1;
        memcpy(host, p + 1, n);
        host[n] = '\0';
    } else {
        const char *colon = strrchr(p, ':');
        if (!colon)
            return false;
        size_t n = (size_t)(colon - p);
        if (n >= sizeof(host))
            n = sizeof(host) - 1;
        memcpy(host, p, n);
        host[n] = '\0';
    }
    if (host[0] == '\0')
        return false;
    if (strcmp(host, "localhost") == 0)
        return true;
    pcdn_ip ip;
    char e[128];
    if (!ip_parse(host, &ip, e, sizeof(e)))
        return false;
    return ip_is_loopback(&ip);
}

httpapi *httpapi_create(detector *det, blocker *blk, const config_t *cfg, reload_fn fn,
                        void *fn_ctx, char *err, size_t errlen)
{
    {
        char verr[512] = {0};
        if (!config_validate_http(cfg, verr, sizeof(verr))) {
            set_err(err, errlen, "%s", verr);
            return NULL;
        }
    }
    httpapi *a = xcalloc(1, sizeof(*a));
    a->det = det;
    a->blk = blk;
    a->reload = fn;
    a->reload_ctx = fn_ctx;
    a->ip_limit = config_device_ip_limit(cfg);
    a->token = xstrdup(config_http_bearer_token(cfg));
    a->listen = xstrdup(config_http_listen(cfg));
    pthread_mutex_init(&a->mu, NULL);
    cors_set(a, cfg->http.cors_origins, cfg->http.ncors, cfg->http.cors_allow_credentials,
             config_cors_max_age(cfg));

    if (config_http_bearer_token(cfg)[0] == '\0' && !listen_is_loopback(a->listen))
        log_warn("警告：HTTP API 绑定在非回环地址 %s 且未启用鉴权，请确保所在网络可信",
                 a->listen);

    a->srv = http_server_create(a->listen, dispatch, a, err, errlen);
    if (!a->srv) {
        httpapi_free(a);
        return NULL;
    }
    return a;
}

int httpapi_start(httpapi *a, char *err, size_t errlen)
{
    if (!a || !a->srv)
        return -1;
    pthread_once(&g_process_start_once, init_process_start);
    return http_server_start(a->srv, err, errlen);
}

void httpapi_stop(httpapi *a)
{
    if (a && a->srv)
        http_server_stop(a->srv);
}

void httpapi_free(httpapi *a)
{
    if (!a)
        return;
    if (a->srv)
        http_server_free(a->srv);
    free(a->token);
    free(a->listen);
    cors_free(&a->cors);
    pthread_mutex_destroy(&a->mu);
    free(a);
}

void httpapi_set_blocker(httpapi *a, blocker *blk)
{
    pthread_mutex_lock(&a->mu);
    a->blk = blk;
    pthread_mutex_unlock(&a->mu);
}

void httpapi_set_token(httpapi *a, const char *token)
{
    pthread_mutex_lock(&a->mu);
    free(a->token);
    a->token = xstrdup(token ? token : "");
    pthread_mutex_unlock(&a->mu);
}

void httpapi_set_ip_limit(httpapi *a, int limit)
{
    if (limit <= 0)
        limit = 1;
    pthread_mutex_lock(&a->mu);
    a->ip_limit = limit;
    pthread_mutex_unlock(&a->mu);
}

void httpapi_set_cors(httpapi *a, char **origins, size_t n, bool allow_credentials, int max_age)
{
    cors_set(a, origins, n, allow_credentials, max_age);
}

static blocker *get_blocker(httpapi *a)
{
    pthread_mutex_lock(&a->mu);
    blocker *b = a->blk;
    pthread_mutex_unlock(&a->mu);
    return b;
}

/* ------------------------------------------------------------------ */
/* 查询参数                                                            */
/* ------------------------------------------------------------------ */

static bool parse_i64(const char *s, int64_t *out)
{
    if (!s || !*s)
        return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return false;
    *out = v;
    return true;
}

static bool parse_bool_param(const char *s, bool *out)
{
    if (strcmp(s, "1") == 0 || strcmp(s, "true") == 0) {
        *out = true;
        return true;
    }
    if (strcmp(s, "0") == 0 || strcmp(s, "false") == 0) {
        *out = false;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* 统计 JSON                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int ports;
    int banned;
    int udp_ports;
    int udp_banned;
    int tcp_ports;
    int tcp_banned;
} fam_stat;

static void fam_add(fam_stat *s, const char *proto, bool banned)
{
    s->ports++;
    if (banned)
        s->banned++;
    if (strcmp(proto, "tcp") == 0) {
        s->tcp_ports++;
        if (banned)
            s->tcp_banned++;
    } else {
        s->udp_ports++;
        if (banned)
            s->udp_banned++;
    }
}

static cJSON *fam_json(const fam_stat *s)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "ports", s->ports);
    cJSON_AddNumberToObject(o, "banned", s->banned);
    cJSON *udp = cJSON_CreateObject();
    cJSON_AddNumberToObject(udp, "ports", s->udp_ports);
    cJSON_AddNumberToObject(udp, "banned", s->udp_banned);
    cJSON_AddItemToObject(o, "udp", udp);
    cJSON *tcp = cJSON_CreateObject();
    cJSON_AddNumberToObject(tcp, "ports", s->tcp_ports);
    cJSON_AddNumberToObject(tcp, "banned", s->tcp_banned);
    cJSON_AddItemToObject(o, "tcp", tcp);
    return o;
}

static const char *proto_label(uint8_t proto)
{
    return proto == 6 ? "tcp" : "udp";
}

/* ------------------------------------------------------------------ */
/* 处理函数                                                            */
/* ------------------------------------------------------------------ */

static void handle_health(httpapi *a, const http_request *req, http_response *res)
{
    (void)a;
    (void)req;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "ok");
    cJSON_AddNumberToObject(o, "uptime_seconds", (double)uptime_seconds());
    json_send(res, 200, o);
}

static void handle_status(httpapi *a, const http_request *req, http_response *res)
{
    (void)req;
    int devices = 0, alerts = 0;
    detector_counts(a->det, &devices, &alerts);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "ok");
    cJSON_AddNumberToObject(o, "uptime_seconds", (double)uptime_seconds());
    cJSON_AddNumberToObject(o, "tracked_devices", devices);
    cJSON_AddNumberToObject(o, "alerts", alerts);
    blocker *b = get_blocker(a);
    blocker_counts c;
    memset(&c, 0, sizeof(c));
    if (b)
        blocker_counts_get(b, &c);
    cJSON_AddNumberToObject(o, "active_bans", c.active_bans);
    cJSON_AddNumberToObject(o, "full_banned", c.full_banned);
    cJSON_AddNumberToObject(o, "upnp_blocked", c.upnp_blocked);
    cJSON_AddNumberToObject(o, "upnp_allowed", c.upnp_allowed);
    cJSON_AddBoolToObject(o, "upnp_all", c.upnp_all);
    json_send(res, 200, o);
}

static void handle_devices(httpapi *a, const http_request *req, http_response *res)
{
    (void)req;
    detector_overview ov;
    detector_overview_get(a->det, &ov);
    blocker *b = get_blocker(a);
    ban_index ix;
    memset(&ix, 0, sizeof(ix));
    if (b)
        blocker_ban_index_get(b, &ix);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "tracked_devices", ov.tracked_devices);
    cJSON_AddNumberToObject(o, "alerts", ov.alerts);
    cJSON_AddNumberToObject(o, "port_evictions", (double)ov.port_evictions);
    cJSON_AddNumberToObject(o, "port_drops", (double)ov.port_drops);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < ov.ndevices; i++) {
        device_port_keys *dp = &ov.devices[i];
        fam_stat v4, v6;
        memset(&v4, 0, sizeof(v4));
        memset(&v6, 0, sizeof(v6));
        for (size_t k = 0; k < dp->nkeys; k++) {
            port_key_view *key = &dp->keys[k];
            const char *proto = proto_label(key->proto);
            bool banned = ban_index_banned(&ix, dp->mac, key->port, proto, key->v6);
            fam_add(key->v6 ? &v6 : &v4, proto, banned);
        }
        cJSON *dev = cJSON_CreateObject();
        cJSON_AddStringToObject(dev, "mac", dp->mac);
        cJSON_AddItemToObject(dev, "ipv4", fam_json(&v4));
        cJSON_AddItemToObject(dev, "ipv6", fam_json(&v6));
        cJSON_AddItemToArray(arr, dev);
    }
    cJSON_AddItemToObject(o, "devices", arr);
    json_send(res, 200, o);

    ban_index_free(&ix);
    detector_overview_free(&ov);
}

static bool ix_full_banned(const ban_index *ix, const char *mac)
{
    for (size_t i = 0; i < ix->nfull; i++) {
        if (strcmp(ix->full[i], mac) == 0)
            return true;
    }
    return false;
}

static void handle_device(httpapi *a, const http_request *req, http_response *res)
{
    char macstr[128];
    if (!http_request_query(req, "mac", macstr, sizeof(macstr)) || macstr[0] == '\0') {
        json_error(res, 400, "缺少 mac 参数");
        return;
    }
    pcdn_mac mac;
    char merr[128];
    if (!mac_parse(macstr, &mac, merr, sizeof(merr))) {
        json_error(res, 400, "mac 参数无效：%s", merr);
        return;
    }
    char norm[32];
    mac_format(&mac, norm, sizeof(norm));

    char fam[32] = "all";
    http_request_query(req, "family", fam, sizeof(fam));
    int fam_filter = 0; /* 0=all 1=v4 2=v6 */
    if (strcasecmp(fam, "all") == 0 || fam[0] == '\0') {
        fam_filter = 0;
    } else if (strcasecmp(fam, "v4") == 0 || strcasecmp(fam, "ipv4") == 0 ||
               strcmp(fam, "4") == 0) {
        fam_filter = 1;
    } else if (strcasecmp(fam, "v6") == 0 || strcasecmp(fam, "ipv6") == 0 ||
               strcmp(fam, "6") == 0) {
        fam_filter = 2;
    } else {
        json_error(res, 400, "family 参数无效（可选 all / v4 / v6）");
        return;
    }

    char state[32] = "all";
    http_request_query(req, "state", state, sizeof(state));
    int state_filter = 0; /* 0=all 1=banned 2=unbanned */
    if (strcasecmp(state, "all") == 0 || state[0] == '\0') {
        state_filter = 0;
    } else if (strcasecmp(state, "banned") == 0) {
        state_filter = 1;
    } else if (strcasecmp(state, "unbanned") == 0) {
        state_filter = 2;
    } else {
        json_error(res, 400, "state 参数无效（可选 all / banned / unbanned）");
        return;
    }

    int limit = 200;
    char lim[32];
    if (http_request_query(req, "limit", lim, sizeof(lim))) {
        int64_t v;
        if (!parse_i64(lim, &v) || v <= 0) {
            json_error(res, 400, "limit 参数无效（应为正整数）");
            return;
        }
        limit = v > 1000 ? 1000 : (int)v;
    }
    int64_t page = 1;
    char pg[32];
    if (http_request_query(req, "page", pg, sizeof(pg))) {
        if (!parse_i64(pg, &page) || page < 1) {
            json_error(res, 400, "page 参数无效（应为正整数）");
            return;
        }
    }
    int64_t offset;
    if (page - 1 > (INT64_C(1) << 62) / limit)
        offset = INT64_C(1) << 62;
    else
        offset = (page - 1) * limit;

    detector_device_view dv;
    if (!detector_device_snapshot(a->det, mac, &dv)) {
        json_error(res, 404, "未找到该设备");
        return;
    }
    blocker *b = get_blocker(a);
    ban_index ix;
    memset(&ix, 0, sizeof(ix));
    if (b)
        blocker_ban_index_get(b, &ix);

    fam_stat v4, v6;
    memset(&v4, 0, sizeof(v4));
    memset(&v6, 0, sizeof(v6));
    cJSON *ports = cJSON_CreateArray();
    int matched = 0;
    int added = 0;
    for (size_t i = 0; i < dv.nports; i++) {
        port_view *p = &dv.ports[i];
        const char *proto = proto_label(p->proto);
        bool banned = ban_index_banned(&ix, norm, p->port, proto, p->v6);
        fam_add(p->v6 ? &v6 : &v4, proto, banned);
        if (fam_filter == 1 && p->v6)
            continue;
        if (fam_filter == 2 && !p->v6)
            continue;
        if (state_filter == 1 && !banned)
            continue;
        if (state_filter == 2 && banned)
            continue;
        int64_t idx = matched++;
        if (idx < offset)
            continue;
        if (added >= limit)
            continue;
        cJSON *po = cJSON_CreateObject();
        cJSON_AddNumberToObject(po, "port", p->port);
        cJSON_AddStringToObject(po, "proto", proto);
        cJSON_AddBoolToObject(po, "v6", p->v6);
        cJSON_AddNumberToObject(po, "peer_count", p->peer_count);
        cJSON_AddNumberToObject(po, "up_bytes", (double)p->up_bytes);
        cJSON_AddNumberToObject(po, "down_bytes", (double)p->down_bytes);
        cJSON_AddBoolToObject(po, "alerting", p->alerting);
        cJSON_AddBoolToObject(po, "banned", banned);
        cJSON_AddItemToArray(ports, po);
        added++;
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "mac", dv.mac);
    cJSON_AddBoolToObject(o, "full_banned", ix_full_banned(&ix, dv.mac));
    cJSON_AddItemToObject(o, "ipv4", fam_json(&v4));
    cJSON_AddItemToObject(o, "ipv6", fam_json(&v6));
    cJSON_AddNumberToObject(o, "page", (double)page);
    cJSON_AddNumberToObject(o, "limit", limit);
    cJSON_AddNumberToObject(o, "matched", matched);
    cJSON_AddBoolToObject(o, "truncated", (int64_t)matched > offset + added);
    cJSON_AddItemToObject(o, "ports", ports);
    json_send(res, 200, o);

    ban_index_free(&ix);
    detector_device_view_free(&dv);
}

static void handle_peers(httpapi *a, const http_request *req, http_response *res)
{
    char macstr[128];
    if (!http_request_query(req, "mac", macstr, sizeof(macstr)) || macstr[0] == '\0') {
        json_error(res, 400, "缺少 mac 参数");
        return;
    }
    pcdn_mac mac;
    char merr[128];
    if (!mac_parse(macstr, &mac, merr, sizeof(merr))) {
        json_error(res, 400, "mac 参数无效：%s", merr);
        return;
    }
    char portstr[32];
    if (!http_request_query(req, "port", portstr, sizeof(portstr)) || portstr[0] == '\0') {
        json_error(res, 400, "缺少 port 参数");
        return;
    }
    int64_t portv;
    if (!parse_i64(portstr, &portv) || portv < 0 || portv > 65535) {
        json_error(res, 400, "port 参数无效（应为 0-65535）");
        return;
    }
    char proto[16] = "udp";
    http_request_query(req, "proto", proto, sizeof(proto));
    uint8_t protoid;
    if (strcasecmp(proto, "udp") == 0) {
        protoid = 17;
    } else if (strcasecmp(proto, "tcp") == 0) {
        protoid = 6;
    } else {
        json_error(res, 400, "proto 参数无效（可选 udp / tcp）");
        return;
    }
    bool v6 = false;
    char v6str[16];
    if (http_request_query(req, "v6", v6str, sizeof(v6str))) {
        if (!parse_bool_param(v6str, &v6)) {
            json_error(res, 400, "v6 参数无效（可选 true / false）");
            return;
        }
    }
    pthread_mutex_lock(&a->mu);
    int limit = a->ip_limit;
    pthread_mutex_unlock(&a->mu);
    char lim[32];
    if (http_request_query(req, "limit", lim, sizeof(lim))) {
        int64_t v;
        if (!parse_i64(lim, &v) || v <= 0) {
            json_error(res, 400, "limit 参数无效（应为正整数）");
            return;
        }
        if (v < limit)
            limit = (int)v;
    }
    int64_t page = 1;
    char pg[32];
    if (http_request_query(req, "page", pg, sizeof(pg))) {
        if (!parse_i64(pg, &page) || page < 1) {
            json_error(res, 400, "page 参数无效（应为正整数）");
            return;
        }
    }
    int64_t offset;
    if (page - 1 > (INT64_C(1) << 62) / limit)
        offset = INT64_C(1) << 62;
    else
        offset = (page - 1) * limit;

    detector_peer_view pv;
    if (!detector_peers_page(a->det, mac, (uint16_t)portv, protoid, v6, offset, limit, &pv)) {
        json_error(res, 404, "未找到该设备 / 端口");
        return;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "port", pv.port);
    cJSON_AddStringToObject(o, "proto", proto_label(pv.proto));
    cJSON_AddBoolToObject(o, "v6", pv.v6);
    cJSON_AddNumberToObject(o, "page", (double)page);
    cJSON_AddNumberToObject(o, "limit", limit);
    cJSON_AddNumberToObject(o, "peer_count", pv.peer_count);
    cJSON *ips = cJSON_CreateArray();
    for (size_t i = 0; i < pv.nips; i++)
        cJSON_AddItemToArray(ips, cJSON_CreateString(pv.ips[i]));
    cJSON_AddItemToObject(o, "peer_ips", ips);
    cJSON_AddBoolToObject(o, "truncated", pv.truncated);
    json_send(res, 200, o);
    detector_peer_view_free(&pv);
}

static void handle_blocks(httpapi *a, const http_request *req, http_response *res)
{
    (void)req;
    blocker *b = get_blocker(a);
    blocker_snapshot s;
    memset(&s, 0, sizeof(s));
    if (b)
        blocker_snapshot_get(b, &s);
    cJSON *o = cJSON_CreateObject();
    cJSON *bans = cJSON_CreateArray();
    for (size_t i = 0; i < s.nbans; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "mac", s.bans[i].mac);
        cJSON_AddNumberToObject(e, "port", s.bans[i].port);
        cJSON_AddStringToObject(e, "proto", s.bans[i].proto);
        cJSON_AddStringToObject(e, "family", s.bans[i].family);
        cJSON_AddNumberToObject(e, "refs", s.bans[i].refs);
        if (s.bans[i].ip[0])
            cJSON_AddStringToObject(e, "ip", s.bans[i].ip);
        cJSON_AddBoolToObject(e, "applied", s.bans[i].applied);
        cJSON_AddItemToArray(bans, e);
    }
    cJSON_AddItemToObject(o, "bans", bans);
    cJSON *full = cJSON_CreateArray();
    for (size_t i = 0; i < s.nfull; i++)
        cJSON_AddItemToArray(full, cJSON_CreateString(s.full_banned[i]));
    cJSON_AddItemToObject(o, "full_banned", full);
    cJSON *blocked = cJSON_CreateArray();
    for (size_t i = 0; i < s.nupnp_blocked; i++)
        cJSON_AddItemToArray(blocked, cJSON_CreateString(s.upnp_blocked[i]));
    cJSON_AddItemToObject(o, "upnp_blocked", blocked);
    cJSON *allowed = cJSON_CreateArray();
    for (size_t i = 0; i < s.nupnp_allowed; i++)
        cJSON_AddItemToArray(allowed, cJSON_CreateString(s.upnp_allowed[i]));
    cJSON_AddItemToObject(o, "upnp_allowed", allowed);
    cJSON_AddBoolToObject(o, "upnp_all", s.upnp_all);
    json_send(res, 200, o);
    blocker_snapshot_free(&s);
}

static void handle_unban(httpapi *a, const http_request *req, http_response *res)
{
    blocker *b = get_blocker(a);
    if (!b) {
        json_error(res, 503, "防火墙未启用，无法解封");
        return;
    }
    cJSON *root = req->body ? cJSON_ParseWithLength(req->body, req->body_len) : NULL;
    if (!root || !cJSON_IsObject(root)) {
        if (root)
            cJSON_Delete(root);
        json_error(res, 400, "请求体解析失败：需要 JSON 对象");
        return;
    }
    cJSON *jmac = cJSON_GetObjectItemCaseSensitive(root, "mac");
    cJSON *jport = cJSON_GetObjectItemCaseSensitive(root, "port");
    cJSON *jproto = cJSON_GetObjectItemCaseSensitive(root, "proto");
    if (!cJSON_IsString(jmac) || !jmac->valuestring || jmac->valuestring[0] == '\0') {
        cJSON_Delete(root);
        json_error(res, 400, "缺少 mac 字段");
        return;
    }
    if (!cJSON_IsNumber(jport) || jport->valuedouble < 0 || jport->valuedouble > 65535) {
        cJSON_Delete(root);
        json_error(res, 400, "port 无效（应为 0-65535）");
        return;
    }
    const char *proto = "udp";
    if (cJSON_IsString(jproto) && jproto->valuestring[0])
        proto = jproto->valuestring;
    char p[8];
    snprintf(p, sizeof(p), "%s", proto);
    for (char *q = p; *q; q++)
        *q = (char)tolower((unsigned char)*q);
    if (strcmp(p, "udp") != 0 && strcmp(p, "tcp") != 0) {
        cJSON_Delete(root);
        json_error(res, 400, "proto 无效（可选 udp / tcp）");
        return;
    }
    char macbuf[128];
    snprintf(macbuf, sizeof(macbuf), "%s", jmac->valuestring);
    int removed = 0;
    char err[512] = {0};
    blocker_force_unban(b, macbuf, (uint16_t)jport->valuedouble, p, &removed, err, sizeof(err));
    cJSON_Delete(root);

    if (err[0] && removed == 0) {
        json_error(res, 500, "解封失败：%s", err);
        return;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "unbanned", removed);
    if (err[0])
        cJSON_AddStringToObject(o, "error", err);
    json_send(res, 200, o);
}

static void handle_reload(httpapi *a, const http_request *req, http_response *res)
{
    (void)req;
    if (!a->reload) {
        json_error(res, 503, "重载不可用");
        return;
    }
    reload_result rr;
    memset(&rr, 0, sizeof(rr));
    char err[1024] = {0};
    int rc = a->reload(a->reload_ctx, &rr, err, sizeof(err));
    if (rc != 0) {
        json_error(res, 400, "重载失败：%s", err);
        reload_result_free(&rr);
        return;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON *applied = cJSON_CreateArray();
    for (size_t i = 0; i < rr.napplied; i++)
        cJSON_AddItemToArray(applied, cJSON_CreateString(rr.applied[i]));
    cJSON_AddItemToObject(o, "applied", applied);
    if (rr.nrestart > 0) {
        cJSON *restart = cJSON_CreateArray();
        for (size_t i = 0; i < rr.nrestart; i++)
            cJSON_AddItemToArray(restart, cJSON_CreateString(rr.restart_required[i]));
        cJSON_AddItemToObject(o, "restart_required", restart);
    } else {
        cJSON_AddItemToObject(o, "restart_required", cJSON_CreateNull());
    }
    cJSON_AddBoolToObject(o, "restarting", rr.restarting);
    json_send(res, 200, o);
    reload_result_free(&rr);
}

static long read_status_threads(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return 1;
    char line[256];
    long threads = 1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Threads:", 8) == 0) {
            threads = strtol(line + 8, NULL, 10);
            break;
        }
    }
    fclose(f);
    return threads;
}

static void handle_memory(httpapi *a, const http_request *req, http_response *res)
{
    (void)req;
    long pagesize = sysconf(_SC_PAGESIZE);
    unsigned long vm = 0, rss = 0;
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) {
        if (fscanf(f, "%lu %lu", &vm, &rss) != 2) {
            vm = rss = 0;
        }
        fclose(f);
    }
    int devices = 0, alerts = 0;
    detector_counts(a->det, &devices, &alerts);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "version", PCDN_BASE_VERSION "+" PCDN_GIT_HASH);
    cJSON_AddNumberToObject(o, "uptime_seconds", (double)uptime_seconds());
    cJSON_AddNumberToObject(o, "num_cpu", sysconf(_SC_NPROCESSORS_ONLN));
    cJSON_AddNumberToObject(o, "threads", (double)read_status_threads());
    cJSON_AddNumberToObject(o, "rss_bytes", (double)(rss * (unsigned long)pagesize));
    cJSON_AddNumberToObject(o, "vm_bytes", (double)(vm * (unsigned long)pagesize));
    cJSON_AddNumberToObject(o, "tracked_devices", devices);
    cJSON_AddNumberToObject(o, "alerts", alerts);
    json_send(res, 200, o);
}
