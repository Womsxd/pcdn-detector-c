#include "app.h"

#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blocker.h"
#include "capture.h"
#include "config.h"
#include "detector.h"
#include "filter.h"
#include "firewall.h"
#include "http.h"
#include "httpapi.h"
#include "state.h"
#include "util.h"

#define TOKEN_ALLOW_NO_TOKEN "allow-no-token"

typedef struct {
    char *iface;
    bool iface_set;
    int trigger;
    bool trigger_set;
    int64_t window;
    bool window_set;
    int64_t alert_duration;
    bool alert_set;
    bool promisc;
    bool promisc_set;
    int64_t interval;
    bool interval_set;
    char *timezone;
    bool tz_set;
    bool hide;
    bool hide_set;
    bool low_memory;
    bool low_set;
    int peer_limit;
    bool peer_set;
    int max_ports;
    bool max_set;
    char protocol[16];
    bool proto_set;
} cli_overrides;

typedef struct {
    config_t cfg;
    config_result res;
    cli_overrides ov;
    char *explicit_path;
    bool has_explicit;
    bool handled;
} cli_result;

typedef struct {
    pthread_mutex_t mu;
    config_t cfg;
    char *explicit_path;
    bool has_explicit;
    cli_overrides ov;
    detector *det;
    capturer *cap;
    firewall *fw;
    blocker *blk;
    httpapi *api;
    int peer_limit;
    pthread_mutex_t interval_mu;
    int64_t interval;
    bool restart_requested;
    atomic_bool stop;
    pthread_t scan_thread;
    bool scan_started;
    pthread_t signal_thread;
    bool signal_started;
    blocker **retired;
    size_t nretired;
    firewall **retired_fw;
    size_t nretired_fw;
    int argc;
    char **argv;
} app_t;

static int app_reload(void *ctx, reload_result *res, char *err, size_t errlen);

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

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static const char *version_string(void)
{
    return PCDN_BASE_VERSION "+" PCDN_GIT_HASH;
}

static bool flag_requested(int argc, char **argv, const char *const *names, size_t n)
{
    for (int i = 1; i < argc; i++) {
        for (size_t k = 0; k < n; k++) {
            if (strcmp(argv[i], names[k]) == 0)
                return true;
        }
    }
    return false;
}

static char *extract_value_flag(int argc, char **argv, const char *const *names, size_t n,
                                bool *found)
{
    *found = false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        for (size_t k = 0; k < n; k++) {
            size_t nl = strlen(names[k]);
            if (strncmp(a, names[k], nl) == 0 && a[nl] == '=') {
                *found = true;
                return xstrdup(a + nl + 1);
            }
            if (strcmp(a, names[k]) == 0) {
                *found = true;
                if (i + 1 < argc)
                    return xstrdup(argv[i + 1]);
                return NULL;
            }
        }
    }
    return NULL;
}

static char *extract_init_config(int argc, char **argv, bool *requested, char *err,
                                 size_t errlen)
{
    *requested = false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--init-config=", 14) == 0) {
            *requested = true;
            const char *v = a + 14;
            if (str_empty(v)) {
                set_err(err, errlen, "--init-config 缺少目录参数");
                return NULL;
            }
            return xstrdup(v);
        }
        if (strcmp(a, "--init-config") == 0) {
            *requested = true;
            if (i + 1 < argc) {
                if (str_empty(argv[i + 1])) {
                    set_err(err, errlen, "--init-config 缺少目录参数");
                    return NULL;
                }
                return xstrdup(argv[i + 1]);
            }
            set_err(err, errlen, "--init-config 缺少目录参数");
            return NULL;
        }
    }
    return NULL;
}

static void print_usage(FILE *out, const config_t *cfg)
{
    char w[64], a[64], iv[64];
    fmt_duration(cfg->detect.window, w, sizeof(w));
    fmt_duration(cfg->detect.alert_duration, a, sizeof(a));
    fmt_duration(cfg->detect.interval, iv, sizeof(iv));
    fprintf(out, "PCDN 行为检测工具（运行于 OpenWrt / Linux 路由器）\n\n");
    fprintf(out, "仓库地址:\n");
    fprintf(out, "  https://github.com/Womsxd/pcdn-detector-c\n");
    fprintf(out, "  https://cnb.cool/womsxd/pcdn-detector-c\n\n");
    fprintf(out, "用法: pcdn-detect [选项]\n\n");
    fprintf(out, "选项（短/长形式等价）:\n");
    fprintf(out, "  -i, --interface <网卡>       要监听的网卡名称（必填），如 br-lan、br0、eth0\n");
    fprintf(out, "  -n, --count <次数>           触发次数：窗口内同一设备同一端口的不同远端公网 "
                 "IP 数（默认 %d，最大 %d）\n",
            cfg->detect.threshold, PCDN_LIMIT_MAX);
    fprintf(out, "  -t, --window <时长>          检测时长（滑动窗口，默认 %s）\n", w);
    fprintf(out, "  -a, --alert-duration <时长>  持续提示时长（默认 %s）\n", a);
    fprintf(out, "  -p, --promisc <布尔>         是否开启混杂模式（默认 %s）\n",
            cfg->capture.promisc ? "true" : "false");
    fprintf(out, "  -s, --interval <时长>        检测扫描间隔（默认 %s）\n", iv);
    fprintf(out, "  -z, --timezone <时区>        日志时区，IANA 名称或 POSIX 串；默认自动读取\n");
    fprintf(out, "  -H, --hide-address <布尔>    隐藏设备自身的 IPv6/公网地址与 MAC（默认 %s）\n",
            cfg->log.hide_address ? "true" : "false");
    fprintf(out, "  -L, --low-memory <布尔>      低内存模式：触发告警后清空对端列表且不再记录新对端"
                 "（默认 %s）\n",
            cfg->memory.low_memory ? "true" : "false");
    fprintf(out,
            "      --peer-limit <数量>      单端口对端记录上限（默认 %d，0 表示不限制，最大 %d；无短选项）\n",
            config_peer_limit_value(cfg), PCDN_LIMIT_MAX);
    fprintf(out,
            "      --max-ports <数量>       单设备端口条目上限（默认 %d，0 表示不限制，最大 %d；无短选项）\n",
            config_max_ports_value(cfg), PCDN_LIMIT_MAX);
    fprintf(out, "  -P, --protocol <协议>        抓包协议：udp / tcp / all（默认 %s）\n",
            config_capture_proto(cfg));
    fprintf(out, "  -c, --config <路径>          指定配置文件路径（只读取该文件，不自动创建）\n");
    fprintf(out, "      --init-config <目录>     在指定目录生成默认配置文件模板并退出（无短选项；"
                 "目录必须已存在）\n");
    fprintf(out, "  -T, --test-config            仅校验配置文件与命令行参数，通过后退出（不启动、"
                 "不创建文件）\n");
    fprintf(out, "  -v, --version                显示版本信息（%s）\n", version_string());
    fprintf(out, "  -h, --help                   显示本帮助\n\n");
    fprintf(out, "时长写法：60s、5m、1h，或纯秒数。\n");
    fprintf(out, "配置：按顺序查找当前目录下的 config.toml、pcdn-detect.toml（TOML 格式）；\n");
    fprintf(out, "      均不存在或加载失败时自动创建 pcdn-detect.toml；命令行参数优先于配置文件。\n\n");
    fprintf(out, "示例: pcdn-detect -i br-lan -n 20 -t 60s\n");
}

static bool parse_bool_str(const char *s, bool *out)
{
    if (strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0 || strcasecmp(s, "t") == 0) {
        *out = true;
        return true;
    }
    if (strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0 || strcasecmp(s, "f") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static void cli_usage_error(const char *fmt, ...)
{
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fprintf(stderr, "错误：%s\n", msg);
    config_t tmp;
    config_default(&tmp);
    print_usage(stderr, &tmp);
    config_free(&tmp);
    exit(2);
}

static void parse_args(int argc, char **argv, const config_t *cfg, cli_overrides *ov)
{
    char *iface = xstrdup(cfg->capture.iface);
    int trigger = cfg->detect.threshold;
    int64_t window = cfg->detect.window;
    int64_t alert = cfg->detect.alert_duration;
    bool promisc = cfg->capture.promisc;
    int64_t interval = cfg->detect.interval;
    char *tz = xstrdup(cfg->log.timezone);
    bool hide = cfg->log.hide_address;
    bool low = cfg->memory.low_memory;
    int peer = config_peer_limit_value(cfg);
    int maxp = config_max_ports_value(cfg);
    char proto[16];
    snprintf(proto, sizeof(proto), "%s", config_capture_proto(cfg));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0')
            continue;
        if (strcmp(arg, "--") == 0)
            break;
        const char *body = arg + 1;
        if (*body == '-')
            body++;
        char name[64];
        const char *eq = strchr(body, '=');
        size_t nl = eq ? (size_t)(eq - body) : strlen(body);
        if (nl >= sizeof(name))
            cli_usage_error("未知参数：%s", arg);
        memcpy(name, body, nl);
        name[nl] = '\0';
        const char *val = eq ? eq + 1 : NULL;

#define IS(n) (strcmp(name, n) == 0)
#define NEEDVAL()                                                                              \
    do {                                                                                       \
        if (!val) {                                                                            \
            if (i + 1 >= argc)                                                                 \
                cli_usage_error("参数 %s 缺少取值", arg);                                       \
            val = argv[++i];                                                                   \
        }                                                                                      \
    } while (0)

        if (IS("i") || IS("interface")) {
            NEEDVAL();
            char *tmp = xstrdup(val ? val : "");
            free(iface);
            iface = tmp;
            ov->iface_set = true;
        } else if (IS("n") || IS("count")) {
            NEEDVAL();
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (!end || *end != '\0' || v <= 0 || v > PCDN_LIMIT_MAX)
                cli_usage_error("-n/--count 触发次数必须在 1~%d 之间", PCDN_LIMIT_MAX);
            trigger = (int)v;
            ov->trigger_set = true;
        } else if (IS("t") || IS("window")) {
            NEEDVAL();
            char e[256];
            if (!parse_duration(val, &window, e, sizeof(e)))
                cli_usage_error("%s", e);
            ov->window_set = true;
        } else if (IS("a") || IS("alert-duration")) {
            NEEDVAL();
            char e[256];
            if (!parse_duration(val, &alert, e, sizeof(e)))
                cli_usage_error("%s", e);
            ov->alert_set = true;
        } else if (IS("p") || IS("promisc")) {
            if (val) {
                if (!parse_bool_str(val, &promisc))
                    cli_usage_error("布尔值无效：%s", val);
            } else {
                promisc = true;
            }
            ov->promisc_set = true;
        } else if (IS("s") || IS("interval")) {
            NEEDVAL();
            char e[256];
            if (!parse_duration(val, &interval, e, sizeof(e)))
                cli_usage_error("%s", e);
            ov->interval_set = true;
        } else if (IS("z") || IS("timezone")) {
            NEEDVAL();
            free(tz);
            tz = xstrdup(val);
            ov->tz_set = true;
        } else if (IS("H") || IS("hide-address")) {
            if (val) {
                if (!parse_bool_str(val, &hide))
                    cli_usage_error("布尔值无效：%s", val);
            } else {
                hide = true;
            }
            ov->hide_set = true;
        } else if (IS("L") || IS("low-memory")) {
            if (val) {
                if (!parse_bool_str(val, &low))
                    cli_usage_error("布尔值无效：%s", val);
            } else {
                low = true;
            }
            ov->low_set = true;
        } else if (IS("peer-limit")) {
            NEEDVAL();
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (!end || *end != '\0' || v < 0 || v > PCDN_LIMIT_MAX)
                cli_usage_error("--peer-limit 必须是 0~%d 之间的整数（0 表示不限制）",
                                PCDN_LIMIT_MAX);
            peer = (int)v;
            ov->peer_set = true;
        } else if (IS("max-ports")) {
            NEEDVAL();
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (!end || *end != '\0' || v < 0 || v > PCDN_LIMIT_MAX)
                cli_usage_error("--max-ports 必须是 0~%d 之间的整数（0 表示不限制）",
                                PCDN_LIMIT_MAX);
            maxp = (int)v;
            ov->max_set = true;
        } else if (IS("P") || IS("protocol")) {
            NEEDVAL();
            char e[256];
            char lower[16];
            size_t k = 0;
            const char *p = val;
            while (*p && k + 1 < sizeof(lower)) {
                lower[k++] = (char)tolower((unsigned char)*p);
                p++;
            }
            lower[k] = '\0';
            if (k == 0)
                snprintf(lower, sizeof(lower), "udp");
            if (strcmp(lower, "udp") != 0 && strcmp(lower, "tcp") != 0 &&
                strcmp(lower, "all") != 0) {
                snprintf(e, sizeof(e), "protocol 无效 \"%s\"（可选 udp / tcp / all）", val);
                cli_usage_error("%s", e);
            }
            snprintf(proto, sizeof(proto), "%s", lower);
            ov->proto_set = true;
        } else if (IS("c") || IS("config") || IS("T") || IS("test-config") || IS("v") ||
                   IS("version") || IS("h") || IS("help") || IS("init-config")) {
            /* 已在预扫描阶段处理 */
            if ((IS("c") || IS("config") || IS("init-config")) && !val)
                i++;
        } else {
            cli_usage_error("未知参数：%s", arg);
        }
#undef IS
#undef NEEDVAL
    }

    /* 生效值规范化 */
    if (alert <= 0)
        alert = 60000000000LL;
    if (interval <= 0)
        interval = 2000000000LL;
    if (maxp < 0)
        maxp = 0;
    int eff_peer;
    if (ov->peer_set) {
        eff_peer = peer;
        if (eff_peer <= 0)
            eff_peer = 0;
        else if (eff_peer < trigger)
            eff_peer = trigger;
    } else {
        int v = 1000;
        int64_t scaled = (int64_t)trigger * 10;
        if (scaled > v)
            v = scaled > PCDN_LIMIT_MAX ? PCDN_LIMIT_MAX : (int)scaled;
        if (low)
            v = trigger;
        if (cfg->memory.has_peer_limit)
            v = cfg->memory.peer_limit;
        if (v <= 0)
            eff_peer = 0;
        else if (v < trigger)
            eff_peer = trigger;
        else
            eff_peer = v;
    }
    /* 配置文件里的显式值可能未经过 config_validate（非 -T 路径），这里再兜一次底 */
    if (eff_peer > PCDN_LIMIT_MAX)
        eff_peer = PCDN_LIMIT_MAX;

    free(ov->iface);
    ov->iface = iface;
    ov->trigger = trigger;
    ov->window = window;
    ov->alert_duration = alert;
    ov->promisc = promisc;
    ov->interval = interval;
    free(ov->timezone);
    ov->timezone = tz;
    ov->hide = hide;
    ov->low_memory = low;
    ov->peer_limit = eff_peer;
    ov->max_ports = maxp;
    snprintf(ov->protocol, sizeof(ov->protocol), "%s", proto);
}

static void apply_overrides(config_t *cfg, const cli_overrides *ov)
{
    if (ov->iface_set) {
        free(cfg->capture.iface);
        cfg->capture.iface = xstrdup(ov->iface ? ov->iface : "");
    }
    if (ov->trigger_set)
        cfg->detect.threshold = ov->trigger;
    if (ov->window_set)
        cfg->detect.window = ov->window;
    if (ov->alert_set)
        cfg->detect.alert_duration = ov->alert_duration;
    if (ov->promisc_set)
        cfg->capture.promisc = ov->promisc;
    if (ov->interval_set)
        cfg->detect.interval = ov->interval;
    if (ov->tz_set) {
        free(cfg->log.timezone);
        cfg->log.timezone = xstrdup(ov->timezone ? ov->timezone : "");
    }
    if (ov->hide_set)
        cfg->log.hide_address = ov->hide;
    if (ov->low_set)
        cfg->memory.low_memory = ov->low_memory;
    if (ov->peer_set) {
        cfg->memory.has_peer_limit = true;
        cfg->memory.peer_limit = ov->peer_limit;
    }
    if (ov->max_set) {
        cfg->memory.has_max_ports = true;
        cfg->memory.max_ports = ov->max_ports;
    }
    if (ov->proto_set) {
        free(cfg->capture.protocol);
        cfg->capture.protocol = xstrdup(ov->protocol);
    }
}

static bool cli_is_help(int argc, char **argv)
{
    static const char *const names[] = {"-h", "-help", "--help"};
    return flag_requested(argc, argv, names, ARRAY_LEN(names));
}

static bool cli_is_version(int argc, char **argv)
{
    static const char *const names[] = {"-v", "-v=true", "--version", "-version",
                                        "--version=true"};
    return flag_requested(argc, argv, names, ARRAY_LEN(names));
}

static bool cli_is_test(int argc, char **argv)
{
    static const char *const names[] = {"-T", "-T=true", "--test-config", "-test-config",
                                        "--test-config=true"};
    return flag_requested(argc, argv, names, ARRAY_LEN(names));
}

static void parse_cli(int argc, char **argv, cli_result *out)
{
    memset(out, 0, sizeof(*out));
    if (cli_is_version(argc, argv)) {
        printf("%s\n", version_string());
        out->handled = true;
        return;
    }
    bool init_requested = false;
    char ierr[512] = {0};
    char *init_dir = extract_init_config(argc, argv, &init_requested, ierr, sizeof(ierr));
    if (init_requested) {
        if (!init_dir) {
            fprintf(stderr, "错误：%s\n", ierr[0] ? ierr : "--init-config 缺少目录参数");
            exit(2);
        }
        char path[1024];
        if (!config_write_default(init_dir, path, sizeof(path), ierr, sizeof(ierr))) {
            fprintf(stderr, "错误：生成配置文件失败：%s\n", ierr);
            free(init_dir);
            exit(1);
        }
        printf("已生成配置文件：%s\n", path);
        free(init_dir);
        out->handled = true;
        return;
    }
    if (cli_is_help(argc, argv)) {
        config_t tmp;
        config_default(&tmp);
        print_usage(stderr, &tmp);
        config_free(&tmp);
        out->handled = true;
        return;
    }

    bool has_cfg = false;
    static const char *const cfg_names[] = {"--config", "-config", "-c"};
    char *cfg_path = extract_value_flag(argc, argv, cfg_names, ARRAY_LEN(cfg_names), &has_cfg);
    bool test = cli_is_test(argc, argv);

    config_t cfg;
    config_result res;
    char err[1024] = {0};
    if (!config_load(&cfg, cfg_path, has_cfg, test, &res, err, sizeof(err))) {
        fprintf(stderr, "错误：%s\n", err);
        free(cfg_path);
        exit(1);
    }
    out->cfg = cfg;
    out->res = res;
    out->explicit_path = cfg_path;
    out->has_explicit = has_cfg;

    parse_args(argc, argv, &out->cfg, &out->ov);
    apply_overrides(&out->cfg, &out->ov);

    if (test) {
        for (size_t i = 0; i < out->res.nwarnings; i++)
            fprintf(stderr, "警告：%s\n", out->res.warnings[i]);
        char verr[1024] = {0};
        if (!config_validate(&out->cfg, verr, sizeof(verr))) {
            fprintf(stderr, "配置检查失败：%s\n", verr);
            exit(1);
        }
        printf("配置检查通过：%s\n", out->res.path ? out->res.path : "");
        out->handled = true;
        return;
    }

    if (str_empty(out->cfg.capture.iface)) {
        fprintf(stderr, "错误：未指定网卡，请用 -i/--interface 指定，或在配置文件中设置 "
                        "interface，例如 -i br-lan\n");
        print_usage(stderr, &out->cfg);
        exit(2);
    }
    if (out->cfg.detect.threshold <= 0) {
        fprintf(stderr, "错误：-n/--count 触发次数必须大于 0\n");
        exit(2);
    }
    if (out->cfg.detect.threshold > PCDN_LIMIT_MAX) {
        fprintf(stderr, "错误：-n/--count 触发次数不能超过 %d\n", PCDN_LIMIT_MAX);
        exit(2);
    }
    if (out->cfg.detect.window <= 0) {
        fprintf(stderr, "错误：-t/--window 时长必须大于 0\n");
        exit(2);
    }
}

/* ------------------------------------------------------------------ */
/* 初始化                                                              */
/* ------------------------------------------------------------------ */

static device_filter *setup_filter(const config_t *cfg)
{
    char **black = NULL, **white = NULL;
    size_t nb = 0, nw = 0;
    char err[512];
    if (!config_list_entries(cfg, &black, &nb, &white, &nw, err, sizeof(err)))
        log_fatal("名单配置错误：%s", err);
    device_filter *flt = NULL;
    if (!filter_create(cfg->filter.list_mode, black, nb, white, nw, &flt, err, sizeof(err)))
        log_fatal("名单配置错误：%s", err);
    for (size_t i = 0; i < nb; i++)
        free(black[i]);
    for (size_t i = 0; i < nw; i++)
        free(white[i]);
    free(black);
    free(white);
    if (filter_is_empty(flt))
        log_fatal("list_mode=blacklist 但未配置 blacklist，将不会检测任何设备，请先补充名单");
    char desc[512];
    filter_describe(flt, desc, sizeof(desc));
    log_info("名单：%s", desc);
    char **macs = NULL;
    size_t nm = 0;
    if (config_blacklist_port_warnings(cfg, &macs, &nm, err, sizeof(err)) && nm > 0) {
        strbuf sb;
        sb_init(&sb);
        for (size_t i = 0; i < nm; i++)
            sb_addf(&sb, "%s%s", i ? ", " : "", macs[i]);
        log_warn("警告：黑名单中 %zu 个条目配置了端口（%s）：仅这些端口会被检测，若端口范围不足"
                 "可能导致漏检（缺少拦截），建议留空以检测该设备全部端口",
                 nm, sb.p ? sb.p : "");
        sb_free(&sb);
    }
    for (size_t i = 0; i < nm; i++)
        free(macs[i]);
    free(macs);
    return flt;
}

static void free_str_array(char **arr, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(arr[i]);
    free(arr);
}

static int init_firewall(app_t *a)
{
    if (!a->cfg.firewall.enabled) {
        if (config_fullban_enabled(&a->cfg))
            log_warn("警告：已配置 [full_ban] mode = \"%s\" 但未启用防火墙（[firewall] enabled "
                     "= true），该模式不会生效",
                     a->cfg.full_ban.mode);
        if (config_upnp_enabled(&a->cfg))
            log_warn("警告：已配置 [upnp] mode = \"%s\" 但未启用防火墙（[firewall] enabled = "
                     "true），该模式不会生效",
                     a->cfg.upnp.mode);
        return 0;
    }
    upnp_filter uf;
    memset(&uf, 0, sizeof(uf));
    char err[512];
    if (!config_upnp_filter_value(&a->cfg, &uf, err, sizeof(err)))
        log_fatal("UPnP 拦截配置错误：%s", err);

    firewall *fw = firewall_create(&a->cfg, &uf, err, sizeof(err));
    if (!fw) {
        upnp_filter_free(&uf);
        log_fatal("防火墙配置错误：%s", err);
    }
    blocker_fullban_cfg fb;
    memset(&fb, 0, sizeof(fb));
    fb.enabled = firewall_fullban_enabled(fw);
    fb.threshold = config_fullban_threshold(&a->cfg);
    snprintf(fb.mode, sizeof(fb.mode), "%s", a->cfg.full_ban.mode);
    if (fb.enabled && strcmp(fb.mode, "device") == 0 &&
        !config_fullban_devices(&a->cfg, &fb.devices, &fb.ndevices, err, sizeof(err))) {
        free_str_array(fb.devices, fb.ndevices);
        firewall_cleanup(fw);
        firewall_free(fw);
        upnp_filter_free(&uf);
        log_fatal("全端口封禁配置错误：%s", err);
    }
    blocker_upnp_cfg up;
    memset(&up, 0, sizeof(up));
    bool block_all = uf.block_all;
    up.enabled = firewall_upnp_enabled(fw);
    up.block_all = block_all;
    up.targets = uf.devices;
    up.ntargets = uf.ndevices;
    /* uf.devices 所有权移交给 up（blocker 内部会复制，稍后统一释放） */
    uf.devices = NULL;
    uf.ndevices = 0;

    blocker *blk = blocker_create(fw, a->cfg.log.hide_address, &fb, &up);
    free_str_array(fb.devices, fb.ndevices);
    free_str_array(up.targets, up.ntargets);
    upnp_filter_free(&uf);

    a->fw = fw;
    a->blk = blk;
    char desc[1024];
    firewall_describe(fw, desc, sizeof(desc));
    log_info("已启用防火墙对接：%s", desc);
    if (firewall_fullban_enabled(fw)) {
        size_t np = 0;
        const uint16_t *ports = firewall_fullban_allow_ports(fw, &np);
        strbuf sb;
        sb_init(&sb);
        for (size_t i = 0; i < np; i++)
            sb_addf(&sb, "%s%u", i ? "," : "", ports[i]);
        log_info("已启用全 UDP 端口封禁：模式=%s，触发阈值=%d 个被封禁端口，放行端口=%s",
                 a->cfg.full_ban.mode, config_fullban_threshold(&a->cfg), sb.p ? sb.p : "");
        sb_free(&sb);
        if (strcmp(a->cfg.full_ban.mode, "device") == 0 && fb.ndevices == 0)
            log_warn("警告：[full_ban] mode = \"device\" 但 filter 名单中没有任何条目配置 "
                     "full_ban = true，该模式不会对任何设备生效");
    }
    if (firewall_upnp_enabled(fw)) {
        const char *scope = block_all ? "拦截全部进入路由器的 UPnP，仅放行名单内设备"
                                      : "仅拦截名单内设备";
        size_t np = 0;
        const uint16_t *ports = firewall_upnp_ports(fw, &np);
        strbuf sb;
        sb_init(&sb);
        for (size_t i = 0; i < np; i++)
            sb_addf(&sb, "%s%u", i ? "," : "", ports[i]);
        log_info("已启用 UPnP 拦截：模式=%s，范围=%s，拦截目的端口=%s，关联设备=%zu 个",
                 a->cfg.upnp.mode, scope, sb.p ? sb.p : "", up.ntargets);
        sb_free(&sb);
        if (strcmp(a->cfg.upnp.mode, "device") == 0 && up.ntargets == 0)
            log_warn("警告：[upnp] mode = \"device\" 但名单中没有任何条目配置 upnp = true，该"
                     "模式不会对任何设备生效");
    }
    return 0;
}

static void restore_state(app_t *a)
{
    char *path = config_state_file_path(&a->cfg);
    state_file *st = NULL;
    char err[512];
    if (!state_load(path, &st, err, sizeof(err))) {
        log_warn("警告：状态文件 %s 损坏，已忽略：%s", path, err);
        state_remove(path);
        free(path);
        return;
    }
    if (!st) {
        free(path);
        return;
    }
    if (a->det)
        detector_restore_sessions(a->det, st->sessions, st->nsessions);
    if (a->blk) {
        blocker_restore(a->blk, st);
        if (a->cfg.firewall.ban_active_alerts) {
            state_session *sessions = NULL;
            size_t n = 0;
            detector_alert_sessions(a->det, &sessions, &n);
            blocker_adopt_sessions(a->blk, sessions, n);
            free(sessions);
            log_info("已按当前告警补发封禁（ban_active_alerts = true）");
        }
    }
    state_remove(path);
    log_info("已继承重启前的封禁状态：%zu 条端口封禁、%zu 台全端口封禁、%zu 个告警会话",
             st->nbans, st->nfull, st->nsessions);
    state_free(st);
    free(path);
}

static int app_start_http(app_t *a, const config_t *cfg, char *err, size_t errlen)
{
    httpapi *api = httpapi_create(a->det, a->blk, cfg, app_reload, a, err, errlen);
    if (!api)
        return -1;
    if (httpapi_start(api, err, errlen) != 0) {
        httpapi_free(api);
        return -1;
    }
    a->api = api;
    const char *auth = "无鉴权";
    if (config_http_bearer_token(cfg)[0] != '\0')
        auth = "Bearer 鉴权";
    else if (config_http_no_token(cfg))
        auth = "无鉴权（token = allow-no-token）";
    log_info("HTTP API 已启用：http://%s（%s；/peers 每端口对端 IP 上限 %d）",
             config_http_listen(cfg), auth, config_device_ip_limit(cfg));
    return 0;
}

static void app_stop_http(app_t *a)
{
    if (a->api) {
        httpapi_stop(a->api);
        httpapi_free(a->api);
        a->api = NULL;
    }
}

static void app_retire_blocker(app_t *a, blocker *b)
{
    if (!b)
        return;
    a->retired = xrealloc(a->retired, (a->nretired + 1) * sizeof(blocker *));
    a->retired[a->nretired++] = b;
}

static void app_retire_firewall(app_t *a, firewall *fw)
{
    if (!fw)
        return;
    a->retired_fw = xrealloc(a->retired_fw, (a->nretired_fw + 1) * sizeof(firewall *));
    a->retired_fw[a->nretired_fw++] = fw;
}

/* ------------------------------------------------------------------ */
/* reload                                                              */
/* ------------------------------------------------------------------ */

static void reload_add(char ***arr, size_t *n, const char *s)
{
    *arr = xrealloc(*arr, (*n + 1) * sizeof(char *));
    (*arr)[(*n)++] = xstrdup(s);
}

static char *join_list(char **arr, size_t n)
{
    if (n == 0)
        return xstrdup("无");
    strbuf sb;
    sb_init(&sb);
    for (size_t i = 0; i < n; i++)
        sb_addf(&sb, "%s%s", i ? ", " : "", arr[i]);
    return sb_detach(&sb);
}

static int reload_fallback(app_t *a, const config_t *newcfg, state_file *snap,
                           const char *reason, const char *cause, reload_result *res, char *err,
                           size_t errlen)
{
    log_error("原地重载失败（%s：%s），回退到重启", reason, cause ? cause : "");
    snap->saved_at = time(NULL);
    char *path = config_state_file_path(newcfg);
    char serr[512];
    if (!state_save(path, snap, serr, sizeof(serr))) {
        set_err(err, errlen, "原地重载失败（%s：%s）且保存状态文件失败：%s", reason,
                cause ? cause : "", serr);
        free(path);
        return -1;
    }
    free(path);
    res->restart_required = xrealloc(res->restart_required, sizeof(char *));
    res->restart_required[0] = xstrdup(reason);
    res->nrestart = 1;
    res->restarting = true;
    a->restart_requested = true;
    atomic_store(&a->stop, true);
    if (a->cap)
        capturer_stop(a->cap);
    return 0;
}

static int app_reload(void *ctx, reload_result *res, char *err, size_t errlen)
{
    app_t *a = ctx;
    /*
     * HTTP 请求线程不能阻塞在重载锁上：SIGHUP 重载可能正持锁并等待所有 HTTP
     * 连接结束（例如切换 HTTP 监听），此时阻塞会形成 ABBA 死锁。
     */
    if (http_server_in_callback()) {
        if (pthread_mutex_trylock(&a->mu) != 0) {
            set_err(err, errlen, "另一个重载正在进行，请稍后重试");
            return -1;
        }
    } else {
        pthread_mutex_lock(&a->mu);
    }
    int rc = -1;
    config_result cres;
    memset(&cres, 0, sizeof(cres));
    config_t nc;
    memset(&nc, 0, sizeof(nc));
    bool nc_valid = false;
    state_file *snap = NULL;
    upnp_filter uf;
    memset(&uf, 0, sizeof(uf));
    bool uf_valid = false;
    char *applied_text = NULL;

    if (!config_load(&nc, a->explicit_path, a->has_explicit, false, &cres, err, errlen))
        goto out;
    nc_valid = true;
    for (size_t i = 0; i < cres.nwarnings; i++)
        log_warn("警告：%s", cres.warnings[i]);
    apply_overrides(&nc, &a->ov);
    {
        char verr[1024] = {0};
        if (!config_validate(&nc, verr, sizeof(verr))) {
            set_err(err, errlen, "配置校验失败：%s", verr);
            goto out;
        }
    }

    snap = xcalloc(1, sizeof(*snap));
    snap->saved_at = time(NULL);
    if (a->blk)
        blocker_block_state(a->blk, snap, err, errlen);
    if (a->det)
        detector_alert_sessions(a->det, &snap->sessions, &snap->nsessions);

    /* 1) 抓包原地重配 */
    if (!config_capture_equal(&a->cfg.capture, &nc.capture)) {
        if (!a->cap) {
            set_err(err, errlen, "抓包未就绪，无法重载 [capture]");
            goto out;
        }
        char cerr[512] = {0};
        if (capturer_reconfigure(a->cap, &nc, nc.capture.promisc, cerr, sizeof(cerr)) != 0) {
            if (reload_fallback(a, &nc, snap, "capture", cerr, res, err, errlen) != 0)
                goto out;
            rc = 0;
            goto out;
        }
        reload_add(&res->applied, &res->napplied, "capture");
        log_info("抓包配置已原地更新：网卡=%s，protocol=\"%s\"，snaplen=%dB，混杂模式=%s",
                 nc.capture.iface, config_capture_proto(&nc), config_snaplen_value(&nc),
                 nc.capture.promisc ? "true" : "false");
    }

    /* 2) 防火墙 / blocker */
    bool fw_changed = !config_firewall_equal(&a->cfg, &nc) ||
                      (nc.firewall.enabled &&
                       strcmp(config_capture_proto(&a->cfg), config_capture_proto(&nc)) != 0);
    if (fw_changed) {
        if (nc.firewall.enabled) {
            char uerr[512] = {0};
            if (!config_upnp_filter_value(&nc, &uf, uerr, sizeof(uerr))) {
                if (reload_fallback(a, &nc, snap, "firewall", uerr, res, err, errlen) != 0)
                    goto out;
                rc = 0;
                goto out;
            }
            uf_valid = true;
        }

        /* 先摘掉 sink / HTTP 指针，再停止旧 blocker */
        if (a->det)
            detector_set_sink(a->det, NULL, NULL);
        if (a->api)
            httpapi_set_blocker(a->api, NULL);
        if (a->blk) {
            blocker_close(a->blk);
            app_retire_blocker(a, a->blk);
            a->blk = NULL;
        }
        if (a->fw) {
            firewall_cleanup(a->fw);
            /* 不立即 free：并发 HTTP 处理器可能仍持有旧 blocker -> fw 指针 */
            app_retire_firewall(a, a->fw);
            a->fw = NULL;
        }

        if (nc.firewall.enabled) {
            char ferr[512] = {0};
            firewall *nfw = firewall_create(&nc, &uf, ferr, sizeof(ferr));
            if (!nfw) {
                if (reload_fallback(a, &nc, snap, "firewall", ferr, res, err, errlen) != 0)
                    goto out;
                rc = 0;
                goto out;
            }
            blocker_fullban_cfg fb;
            memset(&fb, 0, sizeof(fb));
            fb.enabled = firewall_fullban_enabled(nfw);
            fb.threshold = config_fullban_threshold(&nc);
            snprintf(fb.mode, sizeof(fb.mode), "%s", nc.full_ban.mode);
            if (fb.enabled && strcmp(fb.mode, "device") == 0 &&
                !config_fullban_devices(&nc, &fb.devices, &fb.ndevices, ferr, sizeof(ferr))) {
                free_str_array(fb.devices, fb.ndevices);
                firewall_cleanup(nfw);
                firewall_free(nfw);
                if (reload_fallback(a, &nc, snap, "firewall", ferr, res, err, errlen) != 0)
                    goto out;
                rc = 0;
                goto out;
            }
            blocker_upnp_cfg up;
            memset(&up, 0, sizeof(up));
            up.enabled = firewall_upnp_enabled(nfw);
            up.block_all = uf.block_all;
            up.targets = uf.devices;
            up.ntargets = uf.ndevices;
            uf.devices = NULL;
            uf.ndevices = 0;
            blocker *nblk = blocker_create(nfw, nc.log.hide_address, &fb, &up);
            free_str_array(fb.devices, fb.ndevices);
            free_str_array(up.targets, up.ntargets);
            blocker_restore(nblk, snap);
            a->fw = nfw;
            a->blk = nblk;
            if (a->det) {
                void *sink_ctx = NULL;
                const alert_sink *sink = blocker_alert_sink(nblk, &sink_ctx);
                detector_set_sink(a->det, sink, sink_ctx);
            }
            if (a->api)
                httpapi_set_blocker(a->api, nblk);
            char desc[1024];
            firewall_describe(nfw, desc, sizeof(desc));
            log_info("防火墙已原地切换：%s", desc);
        } else {
            a->fw = NULL;
            a->blk = NULL;
            log_info("防火墙已关闭");
        }
        reload_add(&res->applied, &res->napplied, "firewall");
    }

    /* 3) HTTP 监听 */
    bool http_restart = a->cfg.http.enabled != nc.http.enabled ||
                        strcmp(config_http_listen(&a->cfg), config_http_listen(&nc)) != 0 ||
                        (nc.http.enabled && !a->api);
    if (http_restart) {
        if (http_server_in_callback()) {
            if (reload_fallback(a, &nc, snap, "http",
                                "HTTP 监听变更不能在请求处理线程内原地重启", res, err,
                                errlen) != 0)
                goto out;
            rc = 0;
            goto out;
        }
        app_stop_http(a);
        if (nc.http.enabled) {
            char herr[512] = {0};
            if (app_start_http(a, &nc, herr, sizeof(herr)) != 0) {
                set_err(err, errlen, "重启 HTTP 监听失败：%s", herr);
                goto out;
            }
        } else {
            log_info("HTTP API 已关闭");
        }
        reload_add(&res->applied, &res->napplied, "http");
    }

    /* 4) 无失败风险的热更新 */
    if (!config_detect_equal(&a->cfg.detect, &nc.detect)) {
        detector_set_params(a->det, nc.detect.threshold, nc.detect.window,
                            nc.detect.alert_duration);
        pthread_mutex_lock(&a->interval_mu);
        a->interval = nc.detect.interval;
        pthread_mutex_unlock(&a->interval_mu);
        reload_add(&res->applied, &res->napplied, "detect");
    }
    if (a->cfg.memory.low_memory != nc.memory.low_memory) {
        detector_set_low_memory(a->det, nc.memory.low_memory);
        reload_add(&res->applied, &res->napplied, "memory.low_memory");
    }
    {
        int next_peer = config_peer_limit_value(&nc);
        if (next_peer != a->peer_limit) {
            detector_set_peer_limit(a->det, next_peer);
            a->peer_limit = next_peer;
            reload_add(&res->applied, &res->napplied, "memory.peer_limit");
        }
    }
    if (config_max_ports_value(&a->cfg) != config_max_ports_value(&nc)) {
        detector_set_max_ports(a->det, config_max_ports_value(&nc));
        reload_add(&res->applied, &res->napplied, "memory.max_ports");
    }
    if (strcmp(a->cfg.log.level, nc.log.level) != 0) {
        log_level lv;
        char lerr[256];
        if (log_parse_level(nc.log.level, &lv, lerr, sizeof(lerr)))
            log_set_level(lv);
        log_info("日志等级已更新：%s", nc.log.level);
        reload_add(&res->applied, &res->napplied, "log.level");
    }
    if (strcmp(a->cfg.log.timezone, nc.log.timezone) != 0) {
        char label[128], offset[16];
        const char *src = NULL;
        tz_resolve(nc.log.timezone, label, sizeof(label), &src, offset, sizeof(offset));
        log_info("日志时区已更新：%s（来源：%s）", label, src ? src : "");
        reload_add(&res->applied, &res->napplied, "log.timezone");
    }
    if (a->cfg.log.hide_address != nc.log.hide_address) {
        detector_set_hide(a->det, nc.log.hide_address);
        if (a->blk)
            blocker_set_hide(a->blk, nc.log.hide_address);
        reload_add(&res->applied, &res->napplied, "log.hide_address");
    }
    if (!config_filter_equal(&a->cfg.filter, &nc.filter)) {
        char **black = NULL, **white = NULL;
        size_t nb = 0, nw = 0;
        char ferr[512] = {0};
        device_filter *nf = NULL;
        if (!config_list_entries(&nc, &black, &nb, &white, &nw, ferr, sizeof(ferr)) ||
            !filter_create(nc.filter.list_mode, black, nb, white, nw, &nf, ferr,
                           sizeof(ferr))) {
            log_warn("警告：名单配置错误，已保持原名单：%s", ferr);
        } else {
            detector_set_filter(a->det, nf);
            char desc[512];
            filter_describe(nf, desc, sizeof(desc));
            log_info("名单已热更新：%s", desc);
            reload_add(&res->applied, &res->napplied, "filter");
        }
        for (size_t i = 0; i < nb; i++)
            free(black[i]);
        for (size_t i = 0; i < nw; i++)
            free(white[i]);
        free(black);
        free(white);
    }
    if (a->api) {
        if (strcmp(config_http_bearer_token(&a->cfg), config_http_bearer_token(&nc)) != 0) {
            httpapi_set_token(a->api, config_http_bearer_token(&nc));
            reload_add(&res->applied, &res->napplied, "http.token");
        }
        if (config_device_ip_limit(&a->cfg) != config_device_ip_limit(&nc)) {
            httpapi_set_ip_limit(a->api, config_device_ip_limit(&nc));
            reload_add(&res->applied, &res->napplied, "http.device_ip_limit");
        }
        if (!config_http_cors_equal(&a->cfg, &nc)) {
            httpapi_set_cors(a->api, nc.http.cors_origins, nc.http.ncors,
                             nc.http.cors_allow_credentials, config_cors_max_age(&nc));
            reload_add(&res->applied, &res->napplied, "http.cors");
        }
    }

    config_free(&a->cfg);
    a->cfg = nc;
    memset(&nc, 0, sizeof(nc));
    nc_valid = false;
    applied_text = join_list(res->applied, res->napplied);
    log_info("配置已原地重载：%s", applied_text);
    rc = 0;

out:
    if (rc != 0) {
        /* 返回错误前保持旧配置；nc 释放 */
    }
    if (uf_valid)
        upnp_filter_free(&uf);
    if (snap)
        state_free(snap);
    if (nc_valid)
        config_free(&nc);
    config_result_free(&cres);
    free(applied_text);
    pthread_mutex_unlock(&a->mu);
    return rc;
}

/* ------------------------------------------------------------------ */
/* 线程                                                                */
/* ------------------------------------------------------------------ */

static void *scan_main(void *arg)
{
    app_t *a = arg;
    while (!atomic_load(&a->stop)) {
        pthread_mutex_lock(&a->interval_mu);
        int64_t interval = a->interval;
        pthread_mutex_unlock(&a->interval_mu);
        int64_t deadline = mono_ms() + interval / 1000000LL;
        while (!atomic_load(&a->stop) && mono_ms() < deadline) {
            struct timespec req = {.tv_sec = 0, .tv_nsec = 50000000L};
            nanosleep(&req, NULL);
        }
        if (atomic_load(&a->stop))
            break;
        detector_scan(a->det, now_ns());
    }
    return NULL;
}

static void *signal_main(void *arg)
{
    app_t *a = arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    for (;;) {
        int sig = 0;
        if (sigwait(&set, &sig) != 0)
            continue;
        if (atomic_load(&a->stop))
            break;
        if (sig == SIGHUP) {
            reload_result rr;
            memset(&rr, 0, sizeof(rr));
            char err[1024] = {0};
            int rc = app_reload(a, &rr, err, sizeof(err));
            if (rc != 0) {
                log_warn("SIGHUP 重载配置失败：%s", err);
            } else if (rr.restarting) {
                log_info("SIGHUP 已触发重启以应用新配置");
            } else {
                char *joined = join_list(rr.applied, rr.napplied);
                log_info("SIGHUP 已重载配置：%s", joined);
                free(joined);
            }
            reload_result_free(&rr);
        } else {
            if (!atomic_load(&a->stop))
                log_info("收到退出信号，正在停止...");
            atomic_store(&a->stop, true);
            if (a->cap)
                capturer_stop(a->cap);
            break;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

static void app_free(app_t *a)
{
    app_stop_http(a);
    if (a->blk) {
        blocker_close(a->blk);
        blocker_free(a->blk);
        a->blk = NULL;
    }
    if (a->fw) {
        firewall_cleanup(a->fw);
        firewall_free(a->fw);
        a->fw = NULL;
    }
    for (size_t i = 0; i < a->nretired; i++)
        blocker_free(a->retired[i]);
    free(a->retired);
    for (size_t i = 0; i < a->nretired_fw; i++)
        firewall_free(a->retired_fw[i]);
    free(a->retired_fw);
    if (a->det)
        detector_destroy(a->det);
    if (a->cap)
        capturer_destroy(a->cap);
    config_free(&a->cfg);
    free(a->explicit_path);
    free(a->ov.iface);
    free(a->ov.timezone);
    pthread_mutex_destroy(&a->mu);
    pthread_mutex_destroy(&a->interval_mu);
}

int app_main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    /* 先屏蔽信号：后续创建的所有线程都会继承该掩码，只有 sigwait 线程处理 */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    cli_result cli;
    parse_cli(argc, argv, &cli);
    if (cli.handled) {
        config_free(&cli.cfg);
        config_result_free(&cli.res);
        free(cli.explicit_path);
        free(cli.ov.iface);
        free(cli.ov.timezone);
        return 0;
    }

    app_t a;
    memset(&a, 0, sizeof(a));
    pthread_mutex_init(&a.mu, NULL);
    pthread_mutex_init(&a.interval_mu, NULL);
    atomic_init(&a.stop, false);
    a.cfg = cli.cfg;
    memset(&cli.cfg, 0, sizeof(cli.cfg));
    a.explicit_path = cli.explicit_path;
    a.has_explicit = cli.has_explicit;
    a.ov = cli.ov;
    a.interval = a.cfg.detect.interval;
    a.argc = argc;
    a.argv = argv;
    a.peer_limit = cli.ov.peer_limit;

    /* 日志时区 / 等级 / 配置来源 */
    char label[128], offset[16];
    const char *tzsrc = NULL;
    tz_resolve(a.cfg.log.timezone, label, sizeof(label), &tzsrc, offset, sizeof(offset));
    log_level lv = LOG_WARN;
    {
        char lerr[256];
        log_parse_level(a.cfg.log.level, &lv, lerr, sizeof(lerr));
    }
    log_set_level(lv);
    log_info("日志时区：%s（来源：%s，当前偏移 %s）", label, tzsrc ? tzsrc : "", offset);
    log_info("日志等级：%s（可在 [log] level 中调整，或热重载生效）", log_level_name(lv));
    if (cli.res.path) {
        for (size_t i = 0; i < cli.res.nwarnings; i++)
            log_warn("警告：%s", cli.res.warnings[i]);
        if (cli.res.created)
            log_info("未找到可用的配置文件，已创建默认配置：%s", cli.res.path);
        else
            log_info("已加载配置文件：%s", cli.res.path);
    }

    if (!str_empty(a.cfg.memory.memory_limit))
        log_warn("提示：memory_limit 仅 Go 版本生效，C 版本已忽略（%s）",
                 a.cfg.memory.memory_limit);
    if (a.cfg.memory.has_gc_percent)
        log_warn("提示：gc_percent 仅 Go 版本生效，C 版本已忽略（%d）", a.cfg.memory.gc_percent);

    device_filter *flt = setup_filter(&a.cfg);
    a.det = detector_create(a.cfg.detect.threshold, a.cfg.detect.window,
                            a.cfg.detect.alert_duration, flt, a.cfg.log.hide_address,
                            a.cfg.memory.low_memory, a.peer_limit,
                            config_max_ports_value(&a.cfg));
    if (a.cfg.memory.low_memory)
        log_info("已启用低内存模式：端口触发告警后清空对端列表且不再记录新对端，仅保留触发状态");
    if (a.peer_limit > 0)
        log_info("单端口对端记录上限：%d（达到后不再记录该端口的新对端，可配置 peer_limit / "
                 "--peer-limit，0 表示不限制）",
                 a.peer_limit);
    else
        log_info("单端口对端记录上限：不限制（peer_limit = 0）");
    int maxp = config_max_ports_value(&a.cfg);
    if (maxp > 0)
        log_info("单设备端口条目上限：%d（达到后按「最接近过期 + 同档内对端最少」提前过期 10%% "
                 "的端口，可配置 max_ports / --max-ports，0 表示不限制）",
                 maxp);
    else
        log_info("单设备端口条目上限：不限制（max_ports = 0）");

    if (init_firewall(&a) != 0)
        log_fatal("防火墙初始化失败");
    if (a.blk) {
        void *sink_ctx = NULL;
        const alert_sink *sink = blocker_alert_sink(a.blk, &sink_ctx);
        detector_set_sink(a.det, sink, sink_ctx);
    }
    restore_state(&a);

    if (a.cfg.http.enabled) {
        char herr[512] = {0};
        if (app_start_http(&a, &a.cfg, herr, sizeof(herr)) != 0) {
            app_free(&a);
            log_fatal("HTTP API 启动失败：%s", herr);
        }
    }

    char cerr[512] = {0};
    a.cap = capturer_create(a.cfg.capture.iface, a.cfg.capture.promisc, &a.cfg, a.det, cerr,
                            sizeof(cerr));
    if (!a.cap) {
        /* 与 Go 版本一致：启动失败也要解封并清理防火墙规则 */
        if (a.blk) {
            detector_set_sink(a.det, NULL, NULL);
            blocker_close(a.blk);
        }
        if (a.fw)
            firewall_cleanup(a.fw);
        log_fatal("初始化抓包失败（网卡 %s）：%s（请确认已以 root 运行且网卡存在）",
                  a.cfg.capture.iface, cerr);
    }

    int frame, block, blocks;
    config_ring_params(&a.cfg, &frame, &block, &blocks);
    char totalbuf[32];
    human_bytes((uint64_t)block * (uint64_t)blocks, totalbuf, sizeof(totalbuf));
    log_info("抓包缓冲：frame=%dB，block=%dB × %d 块 = %s，snaplen=%dB（可在 [capture] 中调整）",
             frame, block, blocks, totalbuf, config_snaplen_value(&a.cfg));
    log_info("内核抓包过滤：放行 %s（protocol = \"%s\"，可在 [capture] 中调整）",
             config_capture_proto_label(&a.cfg), config_capture_proto(&a.cfg));

    if (pthread_create(&a.scan_thread, NULL, scan_main, &a) == 0)
        a.scan_started = true;
    if (pthread_create(&a.signal_thread, NULL, signal_main, &a) == 0)
        a.signal_started = true;

    char win[64], alert[64], inter[64];
    fmt_duration(a.cfg.detect.window, win, sizeof(win));
    fmt_duration(a.cfg.detect.alert_duration, alert, sizeof(alert));
    fmt_duration(a.cfg.detect.interval, inter, sizeof(inter));
    log_info("开始监听网卡 %s：触发阈值=%d，时长=%s，持续提示时长=%s，扫描间隔=%s",
             a.cfg.capture.iface, a.cfg.detect.threshold, win, alert, inter);
    if (a.cfg.http.enabled)
        log_info("配置热重载：SIGHUP（kill -HUP <pid>）或 POST /api/v1/reload");
    else
        log_info("配置热重载：SIGHUP（kill -HUP <pid>）");

    char rerr[512] = {0};
    int run_rc = capturer_run(a.cap, rerr, sizeof(rerr));

    /* 退出流程 */
    atomic_store(&a.stop, true);
    pthread_mutex_lock(&a.mu);
    if (a.scan_started)
        pthread_join(a.scan_thread, NULL);
    detector_scan(a.det, now_ns());
    detector_summary(a.det);
    if (a.blk)
        detector_set_sink(a.det, NULL, NULL);
    pthread_mutex_unlock(&a.mu);

    if (a.signal_started) {
        pthread_kill(a.signal_thread, SIGTERM);
        pthread_join(a.signal_thread, NULL);
    }

    /* 先停 HTTP（等待在途请求），再解封并清理防火墙 */
    app_free(&a);
    config_result_free(&cli.res);

    if (run_rc != 0)
        log_fatal("抓包异常退出：%s", rerr);

    if (a.restart_requested) {
        log_info("正在重启以应用新配置（继承封禁状态）...");
        execv("/proc/self/exe", argv);
        log_error("自重启失败：%s（进程退出；若由 procd/systemd 托管将被重新拉起）",
                  strerror(errno));
        return 0;
    }
    log_info("已退出");
    return 0;
}
