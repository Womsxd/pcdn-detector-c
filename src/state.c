#include "state.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

#define STATE_MAGIC "PCST"
#define STATE_VERSION 1
#define STATE_HEADER 13
#define STATE_MAX_U16 65535

typedef struct {
    uint8_t *p;
    size_t n;
    size_t cap;
} buf;

typedef struct {
    const uint8_t *p;
    size_t n;
    size_t off;
    bool err;
} reader;

static void buf_put(buf *b, const void *data, size_t n)
{
    if (b->n + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->n + n)
            cap *= 2;
        b->p = xrealloc(b->p, cap);
        b->cap = cap;
    }
    memcpy(b->p + b->n, data, n);
    b->n += n;
}

static void put_u8(buf *b, uint8_t v) { buf_put(b, &v, 1); }

static void put_u16(buf *b, uint16_t v)
{
    uint8_t t[2] = {(uint8_t)(v & 0xff), (uint8_t)(v >> 8)};
    buf_put(b, t, 2);
}

static void put_u32(buf *b, uint32_t v)
{
    uint8_t t[4] = {(uint8_t)(v & 0xff), (uint8_t)((v >> 8) & 0xff),
                    (uint8_t)((v >> 16) & 0xff), (uint8_t)((v >> 24) & 0xff)};
    buf_put(b, t, 4);
}

static void put_i64(buf *b, int64_t v)
{
    put_u32(b, (uint32_t)((uint64_t)v & 0xffffffffu));
    put_u32(b, (uint32_t)((uint64_t)v >> 32));
}

static void put_addr(buf *b, const pcdn_ip *ip)
{
    if (!ip->valid) {
        put_u8(b, 0);
    } else if (!ip->v6) {
        put_u8(b, 4);
        buf_put(b, ip->b, 4);
    } else {
        put_u8(b, 16);
        buf_put(b, ip->b, 16);
    }
}

static uint32_t crc32_ieee(const uint8_t *data, size_t n)
{
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < n; i++)
        crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}

static uint8_t r_u8(reader *r)
{
    if (r->err || r->off + 1 > r->n) {
        r->err = true;
        return 0;
    }
    return r->p[r->off++];
}

static uint16_t r_u16(reader *r)
{
    if (r->err || r->off + 2 > r->n) {
        r->err = true;
        return 0;
    }
    uint16_t v = (uint16_t)(r->p[r->off] | ((uint16_t)r->p[r->off + 1] << 8));
    r->off += 2;
    return v;
}

static uint32_t r_u32(reader *r)
{
    if (r->err || r->off + 4 > r->n) {
        r->err = true;
        return 0;
    }
    uint32_t v = (uint32_t)r->p[r->off] | ((uint32_t)r->p[r->off + 1] << 8) |
                 ((uint32_t)r->p[r->off + 2] << 16) | ((uint32_t)r->p[r->off + 3] << 24);
    r->off += 4;
    return v;
}

static int64_t r_i64(reader *r)
{
    uint32_t lo = r_u32(r);
    uint32_t hi = r_u32(r);
    return (int64_t)(((uint64_t)hi << 32) | lo);
}

static void r_bytes(reader *r, void *dst, size_t n)
{
    if (r->err || r->off + n > r->n) {
        r->err = true;
        memset(dst, 0, n);
        return;
    }
    memcpy(dst, r->p + r->off, n);
    r->off += n;
}

static pcdn_ip r_addr(reader *r)
{
    pcdn_ip ip;
    memset(&ip, 0, sizeof(ip));
    uint8_t n = r_u8(r);
    if (n == 4) {
        r_bytes(r, ip.b, 4);
        ip.v6 = 0;
        ip.valid = true;
    } else if (n == 16) {
        r_bytes(r, ip.b, 16);
        ip.v6 = 1;
        ip.valid = true;
    } else if (n > 0) {
        if (r->err || r->off + n > r->n) {
            r->err = true;
        } else {
            r->off += n;
        }
    }
    return ip;
}

void state_free(state_file *st)
{
    if (!st)
        return;
    free(st->sessions);
    free(st->bans);
    free(st->fullbanned);
    free(st->upnp_blocked);
    free(st->upnp_allowed);
    free(st);
}

static bool encode(const state_file *st, buf *payload, char *err, size_t errlen)
{
    put_i64(payload, st->saved_at);
    if (st->nsessions > STATE_MAX_U16 || st->nbans > STATE_MAX_U16 ||
        st->nfull > STATE_MAX_U16 || st->nupnp_blocked > STATE_MAX_U16 ||
        st->nupnp_allowed > STATE_MAX_U16) {
        set_err(err, errlen, "状态条目数超出上限");
        return false;
    }
    put_u16(payload, (uint16_t)st->nsessions);
    for (size_t i = 0; i < st->nsessions; i++) {
        const state_session *s = &st->sessions[i];
        buf_put(payload, s->mac.b, 6);
        put_u16(payload, s->port);
        put_u8(payload, s->proto);
        put_u8(payload, s->v6 ? 1 : 0);
        put_addr(payload, &s->ip);
        put_i64(payload, s->alert_start_ns);
        put_i64(payload, s->last_active_ns);
        put_u32(payload, (uint32_t)s->reported_count);
    }
    put_u16(payload, (uint16_t)st->nbans);
    for (size_t i = 0; i < st->nbans; i++) {
        const state_ban *b = &st->bans[i];
        buf_put(payload, b->mac.b, 6);
        put_u16(payload, b->port);
        put_u8(payload, b->proto);
        put_u8(payload, b->family);
        put_u8(payload, b->applied ? 1 : 0);
        put_u16(payload, b->refs);
        put_addr(payload, &b->ip);
    }
    put_u16(payload, (uint16_t)st->nfull);
    for (size_t i = 0; i < st->nfull; i++) {
        buf_put(payload, st->fullbanned[i].mac.b, 6);
        put_addr(payload, &st->fullbanned[i].ip);
    }
    put_u16(payload, (uint16_t)st->nupnp_blocked);
    for (size_t i = 0; i < st->nupnp_blocked; i++)
        buf_put(payload, st->upnp_blocked[i].b, 6);
    put_u16(payload, (uint16_t)st->nupnp_allowed);
    for (size_t i = 0; i < st->nupnp_allowed; i++)
        buf_put(payload, st->upnp_allowed[i].b, 6);
    put_u8(payload, st->upnp_all ? 1 : 0);
    return true;
}

static bool decode(const uint8_t *data, size_t n, state_file **out, char *err, size_t errlen)
{
    if (n < STATE_HEADER) {
        set_err(err, errlen, "文件长度不足");
        return false;
    }
    if (memcmp(data, STATE_MAGIC, 4) != 0) {
        set_err(err, errlen, "魔数不匹配");
        return false;
    }
    if (data[4] != STATE_VERSION) {
        set_err(err, errlen, "版本不支持：%u", data[4]);
        return false;
    }
    reader hdr = {.p = data + 5, .n = n - 5};
    uint32_t crc = r_u32(&hdr);
    uint32_t plen = r_u32(&hdr);
    if (hdr.err || plen != n - STATE_HEADER) {
        set_err(err, errlen, "负载长度不匹配");
        return false;
    }
    const uint8_t *payload = data + STATE_HEADER;
    if (crc32_ieee(payload, plen) != crc) {
        set_err(err, errlen, "CRC 校验失败");
        return false;
    }

    state_file *st = xcalloc(1, sizeof(*st));
    reader r = {.p = payload, .n = plen};
    st->saved_at = r_i64(&r);

    uint16_t nses = r_u16(&r);
    if (!r.err && nses) {
        st->sessions = xcalloc(nses, sizeof(state_session));
        for (uint16_t i = 0; i < nses && !r.err; i++) {
            state_session *s = &st->sessions[st->nsessions];
            r_bytes(&r, s->mac.b, 6);
            s->port = r_u16(&r);
            s->proto = r_u8(&r);
            s->v6 = (r_u8(&r) & 1) != 0;
            s->ip = r_addr(&r);
            s->alert_start_ns = r_i64(&r);
            s->last_active_ns = r_i64(&r);
            s->reported_count = (int)r_u32(&r);
            if (!r.err)
                st->nsessions++;
        }
    }

    uint16_t nb = r_u16(&r);
    if (!r.err && nb) {
        st->bans = xcalloc(nb, sizeof(state_ban));
        for (uint16_t i = 0; i < nb && !r.err; i++) {
            state_ban *b = &st->bans[st->nbans];
            r_bytes(&r, b->mac.b, 6);
            b->port = r_u16(&r);
            b->proto = r_u8(&r);
            b->family = r_u8(&r);
            b->applied = (r_u8(&r) & 1) != 0;
            b->refs = r_u16(&r);
            b->ip = r_addr(&r);
            if (!r.err)
                st->nbans++;
        }
    }

    uint16_t nf = r_u16(&r);
    if (!r.err && nf) {
        st->fullbanned = xcalloc(nf, sizeof(state_fullban));
        for (uint16_t i = 0; i < nf && !r.err; i++) {
            state_fullban *f = &st->fullbanned[st->nfull];
            r_bytes(&r, f->mac.b, 6);
            f->ip = r_addr(&r);
            if (!r.err)
                st->nfull++;
        }
    }

    uint16_t nub = r_u16(&r);
    if (!r.err && nub) {
        st->upnp_blocked = xcalloc(nub, sizeof(pcdn_mac));
        for (uint16_t i = 0; i < nub && !r.err; i++) {
            r_bytes(&r, st->upnp_blocked[i].b, 6);
            if (!r.err)
                st->nupnp_blocked++;
        }
    }
    uint16_t nua = r_u16(&r);
    if (!r.err && nua) {
        st->upnp_allowed = xcalloc(nua, sizeof(pcdn_mac));
        for (uint16_t i = 0; i < nua && !r.err; i++) {
            r_bytes(&r, st->upnp_allowed[i].b, 6);
            if (!r.err)
                st->nupnp_allowed++;
        }
    }
    st->upnp_all = (r_u8(&r) & 1) != 0;
    if (r.err) {
        state_free(st);
        set_err(err, errlen, "负载不完整");
        return false;
    }
    *out = st;
    return true;
}

static bool mkdir_p(const char *path, char *err, size_t errlen)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0)
        return true;
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] != '/')
            continue;
        tmp[i] = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
            set_err(err, errlen, "创建目录 %s 失败：%s", tmp, strerror(errno));
            return false;
        }
        tmp[i] = '/';
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        set_err(err, errlen, "创建目录 %s 失败：%s", tmp, strerror(errno));
        return false;
    }
    return true;
}

bool state_save(const char *path, const state_file *st, char *err, size_t errlen)
{
    buf payload = {0};
    if (!encode(st, &payload, err, errlen)) {
        free(payload.p);
        return false;
    }
    buf out = {0};
    buf_put(&out, STATE_MAGIC, 4);
    put_u8(&out, STATE_VERSION);
    put_u32(&out, crc32_ieee(payload.p, payload.n));
    put_u32(&out, (uint32_t)payload.n);
    buf_put(&out, payload.p, payload.n);

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (!mkdir_p(dir, err, errlen)) {
            free(payload.p);
            free(out.p);
            return false;
        }
    }

    char tmpl[1200];
    snprintf(tmpl, sizeof(tmpl), "%s.tmp-XXXXXX", path);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        set_err(err, errlen, "创建状态临时文件失败：%s", strerror(errno));
        free(payload.p);
        free(out.p);
        return false;
    }
    bool ok = true;
    if (fchmod(fd, 0600) != 0) {
        set_err(err, errlen, "设置状态文件权限失败：%s", strerror(errno));
        ok = false;
    }
    size_t off = 0;
    while (ok && off < out.n) {
        ssize_t n = write(fd, out.p + off, out.n - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            set_err(err, errlen, "写入状态文件失败：%s", strerror(errno));
            ok = false;
            break;
        }
        off += (size_t)n;
    }
    if (ok && fsync(fd) != 0) {
        set_err(err, errlen, "同步状态文件失败：%s", strerror(errno));
        ok = false;
    }
    if (close(fd) != 0 && ok) {
        set_err(err, errlen, "关闭状态文件失败：%s", strerror(errno));
        ok = false;
    }
    if (ok && rename(tmpl, path) != 0) {
        set_err(err, errlen, "重命名状态文件失败：%s", strerror(errno));
        ok = false;
    }
    if (!ok)
        unlink(tmpl);
    free(payload.p);
    free(out.p);
    return ok;
}

bool state_load(const char *path, state_file **out, char *err, size_t errlen)
{
    *out = NULL;
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            return true;
        set_err(err, errlen, "%s", strerror(errno));
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        set_err(err, errlen, "%s", strerror(errno));
        return false;
    }
    long sz = ftell(f);
    if (sz < 0 || sz > 64 * 1024 * 1024) {
        fclose(f);
        set_err(err, errlen, "状态文件长度非法");
        return false;
    }
    rewind(f);
    uint8_t *data = xmalloc((size_t)sz);
    size_t rd = fread(data, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) {
        free(data);
        set_err(err, errlen, "读取状态文件失败");
        return false;
    }
    bool ok = decode(data, rd, out, err, errlen);
    free(data);
    return ok;
}

void state_remove(const char *path)
{
    if (unlink(path) != 0 && errno != ENOENT)
        log_warn("警告：删除状态文件 %s 失败：%s", path, strerror(errno));
}
