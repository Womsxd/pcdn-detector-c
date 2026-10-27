#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* 内存与错误                                                          */
/* ------------------------------------------------------------------ */

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "错误：内存不足（申请 %zu 字节）\n", n);
        exit(1);
    }
    return p;
}

void *xcalloc(size_t n, size_t size)
{
    void *p = calloc(n ? n : 1, size ? size : 1);
    if (!p) {
        fprintf(stderr, "错误：内存不足（申请 %zu × %zu 字节）\n", n, size);
        exit(1);
    }
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fprintf(stderr, "错误：内存不足（申请 %zu 字节）\n", n);
        exit(1);
    }
    return q;
}

char *xstrdup(const char *s)
{
    if (!s)
        return NULL;
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

char *xstrndup(const char *s, size_t n)
{
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

void set_err(char *err, size_t cap, const char *fmt, ...)
{
    if (!err || cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* 字符串缓冲                                                          */
/* ------------------------------------------------------------------ */

void sb_init(strbuf *sb)
{
    sb->p = NULL;
    sb->n = 0;
    sb->cap = 0;
}

void sb_free(strbuf *sb)
{
    free(sb->p);
    sb_init(sb);
}

void sb_reset(strbuf *sb)
{
    sb->n = 0;
    if (sb->p)
        sb->p[0] = '\0';
}

static void sb_reserve(strbuf *sb, size_t extra)
{
    /* 长度来自配置 / HTTP 体等外部输入：先排除 size_t 溢出，避免退化为小缓冲区 */
    if (extra >= SIZE_MAX - sb->n)
        log_fatal("字符串缓冲长度溢出（当前 %zu，追加 %zu）", sb->n, extra);
    size_t need = sb->n + extra + 1;
    if (need <= sb->cap)
        return;
    size_t cap = sb->cap ? sb->cap : 64;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    sb->p = xrealloc(sb->p, cap);
    sb->cap = cap;
}

void sb_addn(strbuf *sb, const char *s, size_t n)
{
    sb_reserve(sb, n);
    memcpy(sb->p + sb->n, s, n);
    sb->n += n;
    sb->p[sb->n] = '\0';
}

void sb_add(strbuf *sb, const char *s)
{
    if (s)
        sb_addn(sb, s, strlen(s));
}

void sb_addc(strbuf *sb, char c)
{
    sb_reserve(sb, 1);
    sb->p[sb->n++] = c;
    sb->p[sb->n] = '\0';
}

void sb_addf(strbuf *sb, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need > 0) {
        sb_reserve(sb, (size_t)need);
        vsnprintf(sb->p + sb->n, (size_t)need + 1, fmt, ap2);
        sb->n += (size_t)need;
    }
    va_end(ap2);
}

char *sb_detach(strbuf *sb)
{
    char *p = sb->p;
    sb_init(sb);
    return p ? p : xstrdup("");
}

/* ------------------------------------------------------------------ */
/* MAC / IP                                                            */
/* ------------------------------------------------------------------ */

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* 支持 aa:bb:cc:dd:ee:ff、aa-bb-...、aabb.ccdd.eeff */
bool mac_parse(const char *s, pcdn_mac *out, char *err, size_t errlen)
{
    if (!s)
        goto bad;
    while (isspace((unsigned char)*s))
        s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        len--;

    if (len == 17 && (s[2] == ':' || s[2] == '-')) {
        char sep = s[2];
        for (int i = 0; i < 6; i++) {
            if (i > 0 && s[i * 3 - 1] != sep)
                goto bad;
            int hi = hexval((unsigned char)s[i * 3]);
            int lo = hexval((unsigned char)s[i * 3 + 1]);
            if (hi < 0 || lo < 0)
                goto bad;
            out->b[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }
    if (len == 14 && s[4] == '.' && s[9] == '.') {
        const char *p = s;
        for (int i = 0; i < 6; i++) {
            if (i == 2 || i == 4)
                p++;
            int hi = hexval((unsigned char)p[0]);
            int lo = hexval((unsigned char)p[1]);
            if (hi < 0 || lo < 0)
                goto bad;
            out->b[i] = (uint8_t)((hi << 4) | lo);
            p += 2;
        }
        return true;
    }
bad:
    set_err(err, errlen, "MAC 无效：\"%s\"", s ? s : "");
    return false;
}

void mac_format(const pcdn_mac *mac, char *buf, size_t cap)
{
    snprintf(buf, cap, "%02x:%02x:%02x:%02x:%02x:%02x", mac->b[0], mac->b[1],
             mac->b[2], mac->b[3], mac->b[4], mac->b[5]);
}

bool mac_equal(const pcdn_mac *a, const pcdn_mac *b)
{
    return memcmp(a->b, b->b, 6) == 0;
}

bool ip_parse(const char *s, pcdn_ip *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    if (!s)
        goto bad;
    while (isspace((unsigned char)*s))
        s++;
    if (s[0] == '\0')
        goto bad;

    if (inet_pton(AF_INET, s, out->b) == 1) {
        out->v6 = 0;
        out->valid = true;
        return true;
    }
    uint8_t tmp[16];
    if (inet_pton(AF_INET6, s, tmp) == 1) {
        /* v4-mapped 归一化为 IPv4（与 Go 的 Unmap 一致） */
        static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (memcmp(tmp, mapped, 12) == 0) {
            memcpy(out->b, tmp + 12, 4);
            out->v6 = 0;
        } else {
            memcpy(out->b, tmp, 16);
            out->v6 = 1;
        }
        out->valid = true;
        return true;
    }
bad:
    set_err(err, errlen, "IP 无效：\"%s\"", s ? s : "");
    return false;
}

void ip_format(const pcdn_ip *ip, char *buf, size_t cap)
{
    if (!ip || !ip->valid) {
        if (cap) buf[0] = '\0';
        return;
    }
    if (!ip->v6) {
        inet_ntop(AF_INET, ip->b, buf, (socklen_t)cap);
        return;
    }
    inet_ntop(AF_INET6, ip->b, buf, (socklen_t)cap);
}

int ip_compare(const pcdn_ip *a, const pcdn_ip *b)
{
    if (!a->valid || !b->valid)
        return (int)a->valid - (int)b->valid;
    if (a->v6 != b->v6)
        return a->v6 ? 1 : -1;
    return memcmp(a->b, b->b, a->v6 ? 16 : 4);
}

bool ip_equal(const pcdn_ip *a, const pcdn_ip *b)
{
    if (a->valid != b->valid || a->v6 != b->v6)
        return false;
    if (!a->valid)
        return true;
    return memcmp(a->b, b->b, a->v6 ? 16 : 4) == 0;
}

int ip_family(const pcdn_ip *ip)
{
    return ip->v6 ? 6 : 4;
}

bool ip_is_loopback(const pcdn_ip *ip)
{
    if (!ip->valid)
        return false;
    if (ip->v6) {
        static const uint8_t lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return memcmp(ip->b, lo, 16) == 0;
    }
    return ip->b[0] == 127;
}

bool ip_is_linklocal(const pcdn_ip *ip)
{
    if (!ip->valid)
        return false;
    if (!ip->v6)
        return ip->b[0] == 169 && ip->b[1] == 254;
    return ip->b[0] == 0xfe && (ip->b[1] & 0xc0) == 0x80;
}

bool ip_is_private(const pcdn_ip *ip)
{
    if (!ip->valid)
        return false;
    if (!ip->v6) {
        if (ip->b[0] == 10)
            return true;
        if (ip->b[0] == 172 && (ip->b[1] & 0xf0) == 16)
            return true;
        if (ip->b[0] == 192 && ip->b[1] == 168)
            return true;
        return false;
    }
    if (ip->b[0] == 0xfd || ip->b[0] == 0xfc)
        return true;
    return false;
}

bool ip_is_public(const pcdn_ip *ip)
{
    if (!ip || !ip->valid)
        return false;
    /* v4-mapped 归一化后按 IPv4 判定 */
    pcdn_ip v4 = *ip;
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (v4.v6 && memcmp(v4.b, mapped, 12) == 0) {
        uint8_t tmp[4];
        memcpy(tmp, v4.b + 12, 4);
        memset(v4.b, 0, sizeof(v4.b));
        memcpy(v4.b, tmp, 4);
        v4.v6 = 0;
    }
    if (!v4.v6) {
        const uint8_t *b = v4.b;
        if (b[0] == 0) /* 0.0.0.0/8 */
            return false;
        if (b[0] == 127) /* loopback */
            return false;
        if (b[0] >= 224 && b[0] <= 239) /* multicast 224/4 */
            return false;
        if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255)
            return false;
        if (ip_is_linklocal(&v4))
            return false;
        if (ip_is_private(&v4))
            return false;
        return true;
    }
    /* IPv6 */
    static const uint8_t zero[16] = {0};
    if (memcmp(v4.b, zero, 16) == 0) /* :: */
        return false;
    if (v4.b[0] == 0xff) /* ff00::/8 */
        return false;
    if (ip_is_linklocal(&v4))
        return false;
    if (ip_is_private(&v4))
        return false;
    return true;
}

bool prefix_contains(const pcdn_prefix *p, const pcdn_ip *ip)
{
    if (!p->base.valid || !ip->valid || p->base.v6 != ip->v6)
        return false;
    unsigned bits = p->bits;
    unsigned maxbits = p->base.v6 ? 128 : 32;
    if (bits > maxbits)
        bits = maxbits;
    unsigned full = bits / 8;
    unsigned rem = bits % 8;
    if (full && memcmp(p->base.b, ip->b, full) != 0)
        return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xff << (8 - rem));
        if ((p->base.b[full] & mask) != (ip->b[full] & mask))
            return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* 日志                                                                */
/* ------------------------------------------------------------------ */

static log_level g_level = LOG_WARN;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_names[] = {"debug", "info", "warn", "error"};

void log_set_level(log_level lv)
{
    if (lv < LOG_DEBUG)
        lv = LOG_DEBUG;
    if (lv > LOG_ERROR)
        lv = LOG_ERROR;
    g_level = lv;
}

log_level log_get_level(void)
{
    return g_level;
}

const char *log_level_name(log_level lv)
{
    if (lv < LOG_DEBUG || lv > LOG_ERROR)
        return "unknown";
    return level_names[lv];
}

bool log_parse_level(const char *s, log_level *out, char *err, size_t errlen)
{
    char buf[32];
    size_t n = 0;
    if (!s)
        s = "";
    while (isspace((unsigned char)*s))
        s++;
    while (*s && n + 1 < sizeof(buf)) {
        buf[n++] = (char)tolower((unsigned char)*s);
        s++;
    }
    while (n > 0 && isspace((unsigned char)buf[n - 1]))
        n--;
    buf[n] = '\0';

    if (strcmp(buf, "debug") == 0) {
        *out = LOG_DEBUG;
        return true;
    }
    if (strcmp(buf, "info") == 0) {
        *out = LOG_INFO;
        return true;
    }
    if (strcmp(buf, "warn") == 0 || strcmp(buf, "warning") == 0) {
        *out = LOG_WARN;
        return true;
    }
    if (strcmp(buf, "error") == 0) {
        *out = LOG_ERROR;
        return true;
    }
    set_err(err, errlen, "日志等级无效：\"%s\"（可选 debug / info / warn / error）", s);
    return false;
}

void log_msg(log_level lv, const char *fmt, ...)
{
    if (lv < g_level)
        return;
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y/%m/%d %H:%M:%S", &tm);

    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_log_mutex);
    fprintf(stdout, "%s %s\n", ts, msg);
    fflush(stdout);
    pthread_mutex_unlock(&g_log_mutex);
}

void log_fatal(const char *fmt, ...)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y/%m/%d %H:%M:%S", &tm);

    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_log_mutex);
    fprintf(stdout, "%s %s\n", ts, msg);
    fflush(stdout);
    pthread_mutex_unlock(&g_log_mutex);
    exit(1);
}

/* ------------------------------------------------------------------ */
/* 时长 / 字节                                                         */
/* ------------------------------------------------------------------ */

void fmt_duration(int64_t ns, char *buf, size_t cap)
{
    if (ns == 0) {
        snprintf(buf, cap, "0s");
        return;
    }
    bool neg = ns < 0;
    uint64_t u = neg ? (uint64_t)(-(ns + 1)) + 1 : (uint64_t)ns;
    char tmp[64];
    size_t pos = 0;
    if (neg)
        tmp[pos++] = '-';

    if (u < 1000ULL * 1000 * 1000) {
        /* < 1s：ns / µs / ms，最多保留 3 位小数并去掉尾随 0 */
        double v;
        const char *unit;
        if (u < 1000ULL * 1000) {
            v = (double)u / 1000.0;
            unit = "\xC2\xB5s"; /* µs */
            if (u < 1000) {
                v = (double)u;
                unit = "ns";
            }
        } else {
            v = (double)u / 1e6;
            unit = "ms";
        }
        snprintf(tmp + pos, sizeof(tmp) - pos, "%.3f", v);
        char *dot = strchr(tmp + pos, '.');
        if (dot) {
            char *e = tmp + strlen(tmp);
            while (e > dot + 1 && e[-1] == '0')
                *--e = '\0';
            if (e > dot && e[-1] == '.')
                *--e = '\0';
        }
        snprintf(buf, cap, "%s%s", tmp, unit);
        return;
    }

    uint64_t total_sec = u / 1000000000ULL;
    uint64_t frac_ns = u % 1000000000ULL;
    uint64_t h = total_sec / 3600;
    uint64_t m = (total_sec % 3600) / 60;
    uint64_t s = total_sec % 60;

    pos = 0;
    if (neg)
        tmp[pos++] = '-';
    if (h > 0)
        pos += (size_t)snprintf(tmp + pos, sizeof(tmp) - pos, "%" PRIu64 "h", h);
    if (h > 0 || m > 0)
        pos += (size_t)snprintf(tmp + pos, sizeof(tmp) - pos, "%" PRIu64 "m", m);
    if (frac_ns == 0) {
        snprintf(tmp + pos, sizeof(tmp) - pos, "%" PRIu64 "s", s);
    } else {
        char frac[16];
        snprintf(frac, sizeof(frac), "%09" PRIu64, frac_ns);
        size_t fl = strlen(frac);
        while (fl > 1 && frac[fl - 1] == '0')
            frac[--fl] = '\0';
        snprintf(tmp + pos, sizeof(tmp) - pos, "%" PRIu64 ".%ss", s, frac);
    }
    snprintf(buf, cap, "%s", tmp);
}

bool parse_duration(const char *s, int64_t *out_ns, char *err, size_t errlen)
{
    if (!s)
        goto bad;
    while (isspace((unsigned char)*s))
        s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        len--;
    if (len == 0)
        goto bad;
    char *buf = xstrndup(s, len);
    const char *p = buf;

    bool neg = false;
    if (*p == '+' || *p == '-') {
        neg = (*p == '-');
        p++;
    }
    if (*p == '\0') {
        free(buf);
        goto bad;
    }
    if (strcmp(p, "0") == 0) {
        *out_ns = 0;
        free(buf);
        return true;
    }

    long double total = 0;
    bool any = false;
    while (*p) {
        if (!isdigit((unsigned char)*p) && *p != '.')
            break;
        char *end = NULL;
        long double v = strtold(p, &end);
        if (end == p)
            break;
        p = end;
        const char *unit = p;
        size_t ulen = 0;
        if (strncmp(p, "ns", 2) == 0) {
            ulen = 2;
            v *= 1e-9L;
        } else if (strncmp(p, "us", 2) == 0 || strncmp(p, "\xC2\xB5s", 3) == 0 ||
                   strncmp(p, "\xCE\xBCs", 3) == 0) {
            ulen = (p[0] == 'u') ? 2 : 3;
            v *= 1e-6L;
        } else if (strncmp(p, "ms", 2) == 0) {
            ulen = 2;
            v *= 1e-3L;
        } else if (p[0] == 's') {
            ulen = 1;
        } else if (p[0] == 'm') {
            ulen = 1;
            v *= 60.0L;
        } else if (p[0] == 'h') {
            ulen = 1;
            v *= 3600.0L;
        } else {
            free(buf);
            goto bad;
        }
        (void)unit;
        total += v;
        any = true;
        p += ulen;
    }
    if (!any || *p != '\0') {
        free(buf);
        goto bad;
    }
    if (total > 9.2e18L)
        total = 9.2e18L;
    int64_t ns = (int64_t)(total * 1e9L);
    *out_ns = neg ? -ns : ns;
    free(buf);
    return true;
bad:
    set_err(err, errlen, "无效时长 \"%s\"（示例：60s、5m、1h）", s ? s : "");
    return false;
}

bool parse_byte_size(const char *s, int64_t *out, char *err, size_t errlen)
{
    if (!s)
        goto bad;
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0') {
        *out = 0;
        return true;
    }
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (end == s || errno != 0 || v < 0)
        goto bad;
    const char *u = end;
    while (isspace((unsigned char)*u))
        u++;
    char unit[16];
    size_t n = 0;
    while (*u && n + 1 < sizeof(unit)) {
        unit[n++] = (char)tolower((unsigned char)*u);
        u++;
    }
    while (n > 0 && isspace((unsigned char)unit[n - 1]))
        n--;
    unit[n] = '\0';

    int64_t mult;
    if (strcmp(unit, "") == 0 || strcmp(unit, "b") == 0)
        mult = 1;
    else if (strcmp(unit, "k") == 0 || strcmp(unit, "kb") == 0 || strcmp(unit, "kib") == 0)
        mult = 1LL << 10;
    else if (strcmp(unit, "m") == 0 || strcmp(unit, "mb") == 0 || strcmp(unit, "mib") == 0)
        mult = 1LL << 20;
    else if (strcmp(unit, "g") == 0 || strcmp(unit, "gb") == 0 || strcmp(unit, "gib") == 0)
        mult = 1LL << 30;
    else {
        set_err(err, errlen, "无效的内存单位 \"%s\"（可用 B/K/M/G）", unit);
        return false;
    }
    *out = (int64_t)(v * (double)mult);
    return true;
bad:
    set_err(err, errlen, "无效的内存大小 \"%s\"（示例：16MiB、24M、262144）", s ? s : "");
    return false;
}

void human_bytes(uint64_t n, char *buf, size_t cap)
{
    const uint64_t unit = 1024;
    if (n < unit) {
        snprintf(buf, cap, "%" PRIu64 "B", n);
        return;
    }
    uint64_t div = unit;
    int exp = 0;
    for (uint64_t m = n / unit; m >= unit; m /= unit) {
        div *= unit;
        exp++;
    }
    snprintf(buf, cap, "%.1f%ciB", (double)n / (double)div, "KMGTPE"[exp]);
}

/* ------------------------------------------------------------------ */
/* 端口表达式                                                          */
/* ------------------------------------------------------------------ */

static bool parse_single_port(const char *s, uint16_t *out)
{
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return false;
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || v < 0 || v > 65535)
        return false;
    while (isspace((unsigned char)*end))
        end++;
    if (*end != '\0')
        return false;
    *out = (uint16_t)v;
    return true;
}

bool parse_port_expr(const char *expr, uint16_t **out, size_t *nout, char *err, size_t errlen)
{
    *out = NULL;
    *nout = 0;
    size_t cap = 0;
    char *copy = xstrdup(expr ? expr : "");
    char *seg = copy;
    bool ok = true;
    for (;;) {
        char *slash = strchr(seg, '/');
        if (slash)
            *slash = '\0';
        while (isspace((unsigned char)*seg))
            seg++;
        size_t sl = strlen(seg);
        while (sl > 0 && isspace((unsigned char)seg[sl - 1]))
            seg[--sl] = '\0';
        if (*seg == '\0') {
            set_err(err, errlen, "端口表达式含空段：\"%s\"", expr);
            ok = false;
            break;
        }
        char *dash = strchr(seg, '-');
        if (dash) {
            *dash = '\0';
            uint16_t lo, hi;
            if (!parse_single_port(seg, &lo) || !parse_single_port(dash + 1, &hi)) {
                set_err(err, errlen, "端口无效：\"%s\"", seg);
                ok = false;
                break;
            }
            if (lo > hi) {
                set_err(err, errlen, "端口范围无效：\"%u-%u\"", lo, hi);
                ok = false;
                break;
            }
            for (unsigned p = lo; p <= hi; p++) {
                if (*nout == cap) {
                    cap = cap ? cap * 2 : 16;
                    *out = xrealloc(*out, cap * sizeof(uint16_t));
                }
                (*out)[(*nout)++] = (uint16_t)p;
            }
        } else {
            uint16_t p;
            if (!parse_single_port(seg, &p)) {
                set_err(err, errlen, "端口无效：\"%s\"", seg);
                ok = false;
                break;
            }
            if (*nout == cap) {
                cap = cap ? cap * 2 : 16;
                *out = xrealloc(*out, cap * sizeof(uint16_t));
            }
            (*out)[(*nout)++] = p;
        }
        if (!slash)
            break;
        seg = slash + 1;
    }
    free(copy);
    if (!ok) {
        free(*out);
        *out = NULL;
        *nout = 0;
    }
    return ok;
}

/* ------------------------------------------------------------------ */
/* 隐私掩码                                                            */
/* ------------------------------------------------------------------ */

static void mask_address(const char *s, char *buf, size_t cap)
{
    /* MAC / IPv6：保留前两段与最后一段（按 ':' 切分，保留空段） */
    if (strchr(s, ':')) {
        int segments = 1;
        for (const char *p = s; *p; p++) {
            if (*p == ':')
                segments++;
        }
        const char *p1 = strchr(s, ':');
        const char *p2 = p1 ? strchr(p1 + 1, ':') : NULL;
        const char *last = strrchr(s, ':');
        if (segments < 4 || !p1 || !p2 || !last || last <= p2) {
            snprintf(buf, cap, "%s", s);
            return;
        }
        snprintf(buf, cap, "%.*s:...:%s", (int)(p2 - s), s, last + 1);
        return;
    }
    /* IPv4：保留首段与末段，中间两段写作 * */
    int segments = 1;
    for (const char *p = s; *p; p++) {
        if (*p == '.')
            segments++;
    }
    const char *p1 = strchr(s, '.');
    const char *last = strrchr(s, '.');
    if (segments < 4 || !p1 || !last || last <= p1) {
        snprintf(buf, cap, "%s", s);
        return;
    }
    snprintf(buf, cap, "%.*s.*.*.%s", (int)(p1 - s), s, last + 1);
}

void mask_device_mac(bool hide, const pcdn_mac *mac, char *buf, size_t cap)
{
    char s[32];
    mac_format(mac, s, sizeof(s));
    if (!hide) {
        snprintf(buf, cap, "%s", s);
        return;
    }
    mask_address(s, buf, cap);
}

void mask_device_ip(bool hide, const pcdn_ip *ip, char *buf, size_t cap)
{
    char s[64];
    ip_format(ip, s, sizeof(s));
    if (!hide || !ip->valid) {
        snprintf(buf, cap, "%s", s);
        return;
    }
    if (!ip->v6 && !ip_is_public(ip)) {
        snprintf(buf, cap, "%s", s);
        return;
    }
    mask_address(s, buf, cap);
}

/* ------------------------------------------------------------------ */
/* 时区                                                                */
/* ------------------------------------------------------------------ */

static bool parse_hms(const char *s, int *secs)
{
    int vals[3] = {0, 0, 0};
    int n = 0;
    while (*s && n < 3) {
        if (!isdigit((unsigned char)*s))
            return false;
        char *end = NULL;
        long v = strtol(s, &end, 10);
        if (end == s || v < 0 || v > 100000)
            return false;
        vals[n++] = (int)v;
        s = end;
        if (*s == ':')
            s++;
        else
            break;
    }
    int total = vals[0] * 3600;
    if (n > 1)
        total += vals[1] * 60;
    if (n > 2)
        total += vals[2];
    *secs = total;
    return true;
}

/* 解析 POSIX 时区串，返回缩写名与是否合法 */
static bool parse_posix_tz(const char *s, char *name, size_t name_cap)
{
    const char *p = s;
    if (*p == '<') {
        const char *e = strchr(p, '>');
        if (!e || e == p + 1)
            return false;
        size_t n = (size_t)(e - p - 1);
        if (n >= name_cap)
            n = name_cap - 1;
        memcpy(name, p + 1, n);
        name[n] = '\0';
        p = e + 1;
    } else {
        const char *st = p;
        while (isalpha((unsigned char)*p))
            p++;
        if (p == st)
            return false;
        size_t n = (size_t)(p - st);
        if (n >= name_cap)
            n = name_cap - 1;
        memcpy(name, st, n);
        name[n] = '\0';
    }
    if (*p == '\0')
        return true;
    if (*p == '+' || *p == '-')
        p++;
    int secs;
    const char *off = p;
    char tmp[16];
    size_t n = 0;
    while ((isdigit((unsigned char)*p) || *p == ':') && n + 1 < sizeof(tmp))
        tmp[n++] = *p++;
    tmp[n] = '\0';
    if (!parse_hms(tmp, &secs))
        return false;
    (void)off;
    /* 允许尾部 DST 规则（如 ,M3.2.0,M11.1.0），glibc 可直接解析 */
    if (*p != '\0' && *p != ',')
        return false;
    return true;
}

static bool numeric_offset(const char *s, int *seconds, char *label, size_t label_cap)
{
    const char *p = s;
    int sign = 1;
    if (*p == '+' || *p == '-') {
        if (*p == '-')
            sign = -1;
        p++;
    } else if (!isdigit((unsigned char)*p)) {
        return false;
    }
    int secs = 0;
    if (!parse_hms(p, &secs))
        return false;
    if (secs > 24 * 3600)
        return false;
    *seconds = sign * secs;
    snprintf(label, label_cap, "%s", s);
    return true;
}

static bool set_tz_value(const char *tz)
{
    if (setenv("TZ", tz, 1) != 0)
        return false;
    tzset();
    return true;
}

/* 尝试应用一个时区值；成功时写回展示标签（与 Go 的 Location.String() 语义接近） */
static bool try_tz_value(const char *cand, char *label, size_t label_cap)
{
    if (!cand || !*cand)
        return false;
    if (strcmp(cand, "UTC") == 0 || strcmp(cand, "GMT") == 0) {
        if (!set_tz_value(cand))
            return false;
        if (label)
            snprintf(label, label_cap, "%s", cand);
        return true;
    }
    if (strchr(cand, '/')) {
        char path[512];
        snprintf(path, sizeof(path), "/usr/share/zoneinfo/%s", cand);
        struct stat st;
        if (stat(path, &st) != 0)
            return false;
        if (!set_tz_value(cand))
            return false;
        if (label)
            snprintf(label, label_cap, "%s", cand);
        return true;
    }
    if (isdigit((unsigned char)cand[0]) || cand[0] == '+' || cand[0] == '-') {
        int secs = 0;
        char nm[64];
        if (!numeric_offset(cand, &secs, nm, sizeof(nm)))
            return false;
        /* POSIX 偏移 = UTC - 本地时间；纯数字写法按 ISO（东正西负）解释 */
        int posix = -secs;
        int a = posix < 0 ? -posix : posix;
        char tzbuf[128];
        /* 缩写名使用固定占位符：展示标签仍用用户输入的原始值 */
        (void)nm;
        snprintf(tzbuf, sizeof(tzbuf), "XXX%c%d:%02d:%02d", posix < 0 ? '-' : '+',
                 a / 3600, (a % 3600) / 60, a % 60);
        if (!set_tz_value(tzbuf))
            return false;
        if (label)
            snprintf(label, label_cap, "%s", cand);
        return true;
    }
    char nm[64];
    if (!parse_posix_tz(cand, nm, sizeof(nm)))
        return false;
    /* 与 Go 版本一致：POSIX 串只取标准时间偏移，忽略 DST 规则 */
    char stdbuf[128];
    size_t n = 0;
    while (cand[n] && cand[n] != ',' && n + 1 < sizeof(stdbuf)) {
        stdbuf[n] = cand[n];
        n++;
    }
    stdbuf[n] = '\0';
    if (!set_tz_value(stdbuf))
        return false;
    if (label)
        snprintf(label, label_cap, "%s", nm);
    return true;
}

bool tz_resolve(const char *flag, char *label, size_t label_cap,
                const char **source, char *offset, size_t offset_cap)
{
    const char *src = NULL;
    bool ok = false;

    if (flag && *flag && try_tz_value(flag, label, label_cap)) {
        src = "-tz 参数";
        ok = true;
    }
    if (!ok) {
        const char *env = getenv("TZ");
        if (env && *env && try_tz_value(env, label, label_cap)) {
            src = "TZ 环境变量";
            ok = true;
        }
    }
    if (!ok) {
        char buf[256] = {0};
        FILE *f = fopen("/etc/TZ", "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f)) {
                size_t n = strlen(buf);
                while (n > 0 && isspace((unsigned char)buf[n - 1]))
                    buf[--n] = '\0';
                if (n > 0 && try_tz_value(buf, label, label_cap)) {
                    src = "/etc/TZ";
                    ok = true;
                }
            }
            fclose(f);
        }
    }
    if (!ok) {
        unsetenv("TZ");
        tzset();
        src = "系统默认";
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        if (label) {
            char abbr[64];
            if (strftime(abbr, sizeof(abbr), "%Z", &tm) > 0 && abbr[0])
                snprintf(label, label_cap, "%s", abbr);
            else
                snprintf(label, label_cap, "UTC");
        }
    }

    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    if (offset) {
        char z[16] = "+0000";
        strftime(z, sizeof(z), "%z", &tm);
        if (strlen(z) == 5)
            snprintf(offset, offset_cap, "%.3s:%.2s", z, z + 3);
        else
            snprintf(offset, offset_cap, "%s", z);
    }
    if (source)
        *source = src ? src : "系统默认";
    return true;
}

int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}
