/* 核心模块单元测试：配置 / 过滤 / 检测 / 状态文件 */
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

#include "config.h"
#include "detector.h"
#include "filter.h"
#include "state.h"
#include "util.h"

static int g_fail;

#define CHECK(cond)                                                                            \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
            g_fail++;                                                                          \
        }                                                                                      \
    } while (0)

static pcdn_mac mac_of(const char *s)
{
    pcdn_mac m;
    char e[128];
    if (!mac_parse(s, &m, e, sizeof(e))) {
        fprintf(stderr, "bad mac %s\n", s);
        exit(1);
    }
    return m;
}

static pcdn_ip ip_of(const char *s)
{
    pcdn_ip ip;
    char e[128];
    if (!ip_parse(s, &ip, e, sizeof(e))) {
        fprintf(stderr, "bad ip %s\n", s);
        exit(1);
    }
    return ip;
}

static observation mk_obs(const char *mac, uint16_t port, const char *remote, int64_t ts)
{
    observation o;
    memset(&o, 0, sizeof(o));
    o.mac = mac_of(mac);
    o.ip = ip_of("192.168.1.10");
    o.local_port = port;
    o.remote_ip = ip_of(remote);
    o.up = true;
    o.v6 = false;
    o.proto = 17;
    o.length = 1000;
    o.ts_ns = ts;
    return o;
}

typedef struct {
    int starts;
    int ends;
} sink_ctx;

static void on_start(void *ctx, const char *mac, const char *ip, uint16_t port,
                     const char *proto)
{
    (void)mac;
    (void)ip;
    (void)port;
    (void)proto;
    ((sink_ctx *)ctx)->starts++;
}

static void on_end(void *ctx, const char *mac, const char *ip, uint16_t port, const char *proto)
{
    (void)mac;
    (void)ip;
    (void)port;
    (void)proto;
    ((sink_ctx *)ctx)->ends++;
}

static void test_filter(void)
{
    char **black = NULL, **white = NULL;
    size_t nb = 0, nw = 0;
    black = xmalloc(2 * sizeof(char *));
    black[0] = xstrdup("aa:bb:cc:dd:ee:ff:40000-40002");
    black[1] = xstrdup("11:22:33:44:55:66");
    nb = 2;
    device_filter *f = NULL;
    char err[512];
    CHECK(filter_create("blacklist", black, nb, white, nw, &f, err, sizeof(err)));
    CHECK(filter_allow_key(f, mac_of("aa:bb:cc:dd:ee:ff"), 40001));
    CHECK(!filter_allow_key(f, mac_of("aa:bb:cc:dd:ee:ff"), 40003));
    CHECK(filter_allow_key(f, mac_of("11:22:33:44:55:66"), 1));
    CHECK(!filter_allow_key(f, mac_of("22:22:22:22:22:22"), 1));
    CHECK(!filter_is_empty(f));
    char desc[512];
    filter_describe(f, desc, sizeof(desc));
    CHECK(strstr(desc, "黑名单") != NULL);
    filter_free(f);

    f = NULL;
    CHECK(filter_create("whitelist", NULL, 0, black, nb, &f, err, sizeof(err)));
    CHECK(!filter_allow_key(f, mac_of("aa:bb:cc:dd:ee:ff"), 40000));
    CHECK(filter_allow_key(f, mac_of("aa:bb:cc:dd:ee:ff"), 40005));
    CHECK(filter_allow_key(f, mac_of("22:22:22:22:22:22"), 1));
    filter_free(f);

    for (size_t i = 0; i < nb; i++)
        free(black[i]);
    free(black);
}

static void test_detector_alerts(void)
{
    detector *d = detector_create(3, 5000000000LL, 3000000000LL, NULL, false, false, 100, 0);
    CHECK(d != NULL);
    sink_ctx sc = {0};
    alert_sink sink = {.on_alert_start = on_start, .on_alert_end = on_end};
    detector_set_sink(d, &sink, &sc);

    int64_t t0 = 1700000000000000000LL;
    observation o1 = mk_obs("aa:bb:cc:dd:ee:01", 40000, "1.1.1.1", t0);
    observation o2 = mk_obs("aa:bb:cc:dd:ee:01", 40000, "2.2.2.2", t0);
    observation o3 = mk_obs("aa:bb:cc:dd:ee:01", 40000, "3.3.3.3", t0);
    detector_observe(d, &o1);
    detector_observe(d, &o2);
    detector_observe(d, &o3);
    detector_scan(d, t0);
    CHECK(sc.starts == 1);
    CHECK(sc.ends == 0);

    observation o4 = mk_obs("aa:bb:cc:dd:ee:01", 40000, "4.4.4.4", t0 + 1000000000LL);
    detector_observe(d, &o4);
    detector_peer_view dbg;
    CHECK(detector_peers_page(d, mac_of("aa:bb:cc:dd:ee:01"), 40000, 17, false, 0, 100, &dbg));
    CHECK(dbg.peer_count == 4);
    detector_peer_view_free(&dbg);
    detector_scan(d, t0 + 1000000000LL);
    int dev_dbg = 0, alerts_dbg = 0;
    detector_counts(d, &dev_dbg, &alerts_dbg);
    CHECK(alerts_dbg == 2);
    CHECK(sc.starts == 1);

    detector_scan(d, t0 + 6000000000LL);
    CHECK(sc.ends == 1);

    detector_scan(d, t0 + 10000000000LL);
    int devices = -1, alerts = -1;
    detector_counts(d, &devices, &alerts);
    CHECK(devices == 0);
    CHECK(alerts == 2);

    detector_destroy(d);
}

static void test_detector_limits(void)
{
    detector *d = detector_create(2, 5000000000LL, 3000000000LL, NULL, false, false, 2, 0);
    int64_t t0 = 1700000000000000000LL;
    observation a = mk_obs("aa:bb:cc:dd:ee:02", 40000, "1.1.1.1", t0);
    observation b = mk_obs("aa:bb:cc:dd:ee:02", 40000, "2.2.2.2", t0);
    observation c = mk_obs("aa:bb:cc:dd:ee:02", 40000, "3.3.3.3", t0);
    detector_observe(d, &a);
    detector_observe(d, &b);
    detector_observe(d, &c);
    pcdn_mac mac = mac_of("aa:bb:cc:dd:ee:02");
    detector_peer_view pv;
    CHECK(detector_peers_page(d, mac, 40000, 17, false, 0, 100, &pv));
    CHECK(pv.peer_count == 2);
    CHECK(pv.nips == 2);
    detector_peer_view_free(&pv);
    detector_destroy(d);

    /* 端口上限：3 个端口 + max_ports=2 -> 淘汰一个 */
    d = detector_create(5, 5000000000LL, 3000000000LL, NULL, false, false, 100, 2);
    observation p1 = mk_obs("aa:bb:cc:dd:ee:03", 1000, "1.1.1.1", t0);
    observation p2 = mk_obs("aa:bb:cc:dd:ee:03", 1001, "1.1.1.2", t0);
    observation p3 = mk_obs("aa:bb:cc:dd:ee:03", 1002, "1.1.1.3", t0);
    detector_observe(d, &p1);
    detector_observe(d, &p2);
    detector_observe(d, &p3);
    detector_device_view dv;
    CHECK(detector_device_snapshot(d, mac_of("aa:bb:cc:dd:ee:03"), &dv));
    CHECK(dv.nports == 2);
    bool has1000 = false, has1001 = false, has1002 = false;
    for (size_t i = 0; i < dv.nports; i++) {
        if (dv.ports[i].port == 1000)
            has1000 = true;
        if (dv.ports[i].port == 1001)
            has1001 = true;
        if (dv.ports[i].port == 1002)
            has1002 = true;
    }
    CHECK(!has1000);
    CHECK(has1001);
    CHECK(has1002);
    detector_device_view_free(&dv);

    detector_overview ov;
    detector_overview_get(d, &ov);
    CHECK(ov.port_evictions == 1);
    detector_overview_free(&ov);
    detector_destroy(d);
}

static void test_detector_session_restore(void)
{
    detector *d = detector_create(2, 5000000000LL, 3000000000LL, NULL, false, false, 100, 0);
    int64_t t0 = 1700000000000000000LL;
    observation a = mk_obs("aa:bb:cc:dd:ee:07", 40000, "1.1.1.1", t0);
    observation b = mk_obs("aa:bb:cc:dd:ee:07", 40000, "2.2.2.2", t0);
    detector_observe(d, &a);
    detector_observe(d, &b);
    detector_scan(d, t0);
    state_session *sessions = NULL;
    size_t ns = 0;
    CHECK(detector_alert_sessions(d, &sessions, &ns));
    CHECK(ns == 1);
    detector_destroy(d);

    detector *d2 = detector_create(2, 5000000000LL, 3000000000LL, NULL, false, false, 100, 0);
    sink_ctx sc = {0};
    alert_sink sink = {.on_alert_start = on_start, .on_alert_end = on_end};
    detector_set_sink(d2, &sink, &sc);
    detector_restore_sessions(d2, sessions, ns);
    free(sessions);
    detector_scan(d2, t0 + 10000000000LL);
    CHECK(sc.ends == 1);
    int devices = 1, alerts = 0;
    detector_counts(d2, &devices, &alerts);
    CHECK(devices == 0);
    detector_destroy(d2);
}

static void test_state(void)
{
    state_file *st = xcalloc(1, sizeof(*st));
    st->saved_at = 12345;
    st->nsessions = 1;
    st->sessions = xcalloc(1, sizeof(state_session));
    st->sessions[0].mac = mac_of("aa:bb:cc:dd:ee:04");
    st->sessions[0].port = 40000;
    st->sessions[0].proto = 17;
    st->sessions[0].v6 = false;
    st->sessions[0].ip = ip_of("192.168.1.20");
    st->sessions[0].alert_start_ns = 111;
    st->sessions[0].last_active_ns = 222;
    st->sessions[0].reported_count = 3;

    st->nbans = 1;
    st->bans = xcalloc(1, sizeof(state_ban));
    st->bans[0].mac = mac_of("aa:bb:cc:dd:ee:04");
    st->bans[0].port = 40000;
    st->bans[0].proto = 17;
    st->bans[0].family = STATE_FAMILY_V4;
    st->bans[0].applied = true;
    st->bans[0].refs = 1;
    st->bans[0].ip = ip_of("192.168.1.20");

    st->nfull = 1;
    st->fullbanned = xcalloc(1, sizeof(state_fullban));
    st->fullbanned[0].mac = mac_of("aa:bb:cc:dd:ee:05");
    st->fullbanned[0].ip = ip_of("1.2.3.4");

    st->nupnp_blocked = 1;
    st->upnp_blocked = xcalloc(1, sizeof(pcdn_mac));
    st->upnp_blocked[0] = mac_of("aa:bb:cc:dd:ee:06");
    st->upnp_all = true;

    char path[256];
    snprintf(path, sizeof(path), "/tmp/pcdn-detect-test-%d.state", (int)getpid());
    char err[512];
    CHECK(state_save(path, st, err, sizeof(err)));
    state_free(st);

    state_file *loaded = NULL;
    CHECK(state_load(path, &loaded, err, sizeof(err)));
    CHECK(loaded != NULL);
    if (loaded) {
        CHECK(loaded->saved_at == 12345);
        CHECK(loaded->nsessions == 1);
        CHECK(loaded->nbans == 1);
        CHECK(loaded->nfull == 1);
        CHECK(loaded->nupnp_blocked == 1);
        CHECK(loaded->upnp_all);
        CHECK(loaded->bans[0].port == 40000);
        CHECK(loaded->sessions[0].reported_count == 3);
        state_free(loaded);
    }
    state_remove(path);
}

static void test_config(void)
{
    const char *toml =
        "[detect]\n"
        "threshold = 4\n"
        "window = 30\n"
        "alert_duration = \"2m\"\n"
        "interval = \"1s\"\n"
        "[capture]\n"
        "interface = \"br-lan\"\n"
        "promisc = false\n"
        "protocol = \"ALL\"\n"
        "[memory]\n"
        "low_memory = true\n"
        "peer_limit = 3\n"
        "max_ports = 0\n"
        "[log]\n"
        "level = \"INFO\"\n"
        "[http]\n"
        "enabled = false\n"
        "cors_allowed_origins = [\"https://admin.example.com\", \"http://192.168.1.2:5173\"]\n"
        "[filter]\n"
        "list_mode = \"blacklist\"\n"
        "[[filter.blacklist]]\n"
        "mac = \"aa:bb:cc:dd:ee:ff\"\n"
        "[[filter.blacklist]]\n"
        "mac = \"11:22:33:44:55:66\"\n"
        "ports = [40000, \"40001-40002\"]\n"
        "upnp = true\n"
        "[full_ban]\n"
        "mode = \"on\"\n"
        "allow = [53, \"123\", 53]\n"
        "[upnp]\n"
        "mode = \"on\"\n"
        "ports = [1900, \"5000\"]\n";

    config_t cfg;
    char err[1024];
    CHECK(config_parse(toml, strlen(toml), &cfg, err, sizeof(err)));
    config_apply_defaults(&cfg);
    CHECK(cfg.detect.threshold == 4);
    CHECK(cfg.detect.window == 30000000000LL);
    CHECK(cfg.detect.alert_duration == 120000000000LL);
    CHECK(strcmp(cfg.capture.protocol, "all") == 0);
    CHECK(cfg.capture.promisc == false);
    CHECK(cfg.memory.low_memory);
    CHECK(config_peer_limit_value(&cfg) == 4); /* 低内存默认 = threshold；显式 3 抬到 4 */
    CHECK(config_max_ports_value(&cfg) == 0);
    CHECK(strcmp(cfg.log.level, "info") == 0);
    CHECK(cfg.http.ncors == 2);
    CHECK(config_fullban_enabled(&cfg));
    CHECK(config_upnp_enabled(&cfg));
    CHECK(strcmp(cfg.upnp.mode, "on") == 0);

    char **black = NULL, **white = NULL;
    size_t nb = 0, nw = 0;
    CHECK(config_list_entries(&cfg, &black, &nb, &white, &nw, err, sizeof(err)));
    CHECK(nb == 2);
    CHECK(strcmp(black[0], "aa:bb:cc:dd:ee:ff") == 0);
    CHECK(strcmp(black[1], "11:22:33:44:55:66:40000/40001-40002") == 0);
    for (size_t i = 0; i < nb; i++)
        free(black[i]);
    free(black);
    free(white);

    uint16_t *ports = NULL;
    size_t np = 0;
    CHECK(config_fullban_allow(&cfg, &ports, &np, err, sizeof(err)));
    CHECK(np == 2);
    CHECK(ports[0] == 53 && ports[1] == 123);
    free(ports);
    ports = NULL;
    np = 0;
    CHECK(config_upnp_ports(&cfg, &ports, &np, err, sizeof(err)));
    CHECK(np == 2 && ports[0] == 1900 && ports[1] == 5000);
    free(ports);

    CHECK(config_validate(&cfg, err, sizeof(err)));
    config_free(&cfg);

    const char *bad = "[detect]\nthreshold = 1\nunknown_key = 2\n";
    config_t c2;
    CHECK(!config_parse(bad, strlen(bad), &c2, err, sizeof(err)));
    CHECK(strstr(err, "未知配置项") != NULL);

    /* 模板必须能被解析 */
    config_t c3;
    CHECK(config_parse(config_template, strlen(config_template), &c3, err, sizeof(err)));
    config_apply_defaults(&c3);
    config_free(&c3);
}

static void test_peer_limit_overflow(void)
{
    /* 阈值可由配置给到 INT32_MAX：推导默认对端上限时不得因 int 溢出而变成 0 或负数，
     * 否则「单端口对端上限」会静默失效、内存不再受控。 */
    config_t cfg;
    config_default(&cfg);
    cfg.detect.threshold = INT32_MAX;
    int v = config_peer_limit_value(&cfg);
    CHECK(v > 0);
    CHECK(v >= cfg.detect.threshold);
    config_free(&cfg);

    config_default(&cfg);
    cfg.detect.threshold = INT32_MAX;
    cfg.memory.low_memory = true;
    v = config_peer_limit_value(&cfg);
    CHECK(v > 0);
    config_free(&cfg);

    config_default(&cfg);
    cfg.detect.threshold = 1000000000;
    cfg.memory.has_peer_limit = true;
    cfg.memory.peer_limit = 500;
    v = config_peer_limit_value(&cfg);
    CHECK(v == 500 || v == 1000000000);
    config_free(&cfg);
}

static void test_util(void)
{
    char buf[64];
    fmt_duration(60000000000LL, buf, sizeof(buf));
    CHECK(strcmp(buf, "1m0s") == 0);
    fmt_duration(1500000000LL, buf, sizeof(buf));
    CHECK(strcmp(buf, "1.5s") == 0);
    fmt_duration(2000000000LL, buf, sizeof(buf));
    CHECK(strcmp(buf, "2s") == 0);
    human_bytes(3ULL * 1024 * 1024 / 2, buf, sizeof(buf));
    CHECK(strcmp(buf, "1.5MiB") == 0);

    int64_t ns = 0;
    CHECK(parse_duration("2h45m", &ns, buf, sizeof(buf)));
    CHECK(ns == 9900000000000LL);
    CHECK(!parse_duration("abc", &ns, buf, sizeof(buf)));
    CHECK(parse_duration("0", &ns, buf, sizeof(buf)));
    CHECK(ns == 0);

    int64_t bytes = 0;
    CHECK(parse_byte_size("16MiB", &bytes, buf, sizeof(buf)));
    CHECK(bytes == 16LL * 1024 * 1024);
    CHECK(parse_byte_size("24M", &bytes, buf, sizeof(buf)));
    CHECK(bytes == 24LL * 1024 * 1024);

    CHECK(ip_is_public(&(pcdn_ip){0} ) == false);
    pcdn_ip ip = ip_of("1.1.1.1");
    CHECK(ip_is_public(&ip));
    ip = ip_of("192.168.1.1");
    CHECK(!ip_is_public(&ip));
    ip = ip_of("100.64.0.1");
    CHECK(ip_is_public(&ip));
    ip = ip_of("2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3");
    CHECK(ip_is_public(&ip));
    ip = ip_of("fe80::1");
    CHECK(!ip_is_public(&ip));

    char mbuf[64], ibuf[64];
    mask_device_mac(true, &(pcdn_mac){.b = {0x60, 0x21, 0x01, 0x1b, 0x0a, 0x23}}, mbuf,
                    sizeof(mbuf));
    CHECK(strcmp(mbuf, "60:21:...:23") == 0);
    pcdn_ip pub = ip_of("112.245.115.51");
    mask_device_ip(true, &pub, ibuf, sizeof(ibuf));
    CHECK(strcmp(ibuf, "112.*.*.51") == 0);
    pcdn_ip pub6 = ip_of("2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3");
    mask_device_ip(true, &pub6, ibuf, sizeof(ibuf));
    CHECK(strcmp(ibuf, "2408:8240:...:b2a3") == 0);
    pcdn_ip priv = ip_of("192.168.1.100");
    mask_device_ip(true, &priv, ibuf, sizeof(ibuf));
    CHECK(strcmp(ibuf, "192.168.1.100") == 0);

    char label[128], off[16];
    const char *src = NULL;
    CHECK(tz_resolve("UTC", label, sizeof(label), &src, off, sizeof(off)));
    CHECK(strcmp(label, "UTC") == 0);
    CHECK(strcmp(off, "+00:00") == 0);
    CHECK(tz_resolve("CST-8", label, sizeof(label), &src, off, sizeof(off)));
    CHECK(strcmp(label, "CST") == 0);
    CHECK(strcmp(off, "+08:00") == 0);
    CHECK(tz_resolve("+08:00", label, sizeof(label), &src, off, sizeof(off)));
    CHECK(strcmp(label, "+08:00") == 0);
    CHECK(strcmp(off, "+08:00") == 0);
}

int main(void)
{
    log_set_level(LOG_ERROR);
    test_util();
    test_config();
    test_peer_limit_overflow();
    test_filter();
    test_detector_alerts();
    test_detector_limits();
    test_detector_session_restore();
    test_state();
    if (g_fail) {
        fprintf(stderr, "%d 项检查失败\n", g_fail);
        return 1;
    }
    printf("test_core: OK\n");
    return 0;
}
