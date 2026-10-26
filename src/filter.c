#include "filter.h"

#include "uthash.h"
#include "util.h"

typedef struct port_rule {
    pcdn_mac mac;
    bool all;
    uint16_t *ports;
    size_t nports;
    UT_hash_handle hh;
} port_rule;

struct device_filter {
    char mode[16];
    port_rule *blacklist;
    port_rule *whitelist;
    size_t nblack;
    size_t nwhite;
};

/* 解析 "MAC" 或 "MAC:端口表达式"（MAC 恰好 6 段，第 7 段起为端口表达式） */
static bool parse_mac_entry(const char *raw, pcdn_mac *mac, uint16_t **ports, size_t *nports,
                            bool *has_ports, char *err, size_t errlen)
{
    *ports = NULL;
    *nports = 0;
    *has_ports = false;

    const char *p = raw;
    while (isspace((unsigned char)*p))
        p++;
    size_t len = strlen(p);
    while (len > 0 && isspace((unsigned char)p[len - 1]))
        len--;
    if (len == 0) {
        set_err(err, errlen, "空条目");
        return false;
    }

    size_t colon_idx = 0;
    int colons = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == ':' && ++colons == 6) {
            colon_idx = i;
            break;
        }
    }

    char macbuf[80];
    if (colons == 6) {
        if (colon_idx >= sizeof(macbuf)) {
            set_err(err, errlen, "MAC 无效：\"%s\"", raw);
            return false;
        }
        memcpy(macbuf, p, colon_idx);
        macbuf[colon_idx] = '\0';
        const char *expr = p + colon_idx + 1;
        if (!parse_port_expr(expr, ports, nports, err, errlen))
            return false;
        if (*nports == 0) {
            set_err(err, errlen, "端口表达式为空");
            return false;
        }
        *has_ports = true;
    } else {
        if (len >= sizeof(macbuf)) {
            set_err(err, errlen, "MAC 无效：\"%s\"", raw);
            return false;
        }
        memcpy(macbuf, p, len);
        macbuf[len] = '\0';
    }

    char merr[128];
    if (!mac_parse(macbuf, mac, merr, sizeof(merr))) {
        free(*ports);
        *ports = NULL;
        *nports = 0;
        *has_ports = false;
        set_err(err, errlen, "MAC 无效：\"%s\"", macbuf);
        return false;
    }
    return true;
}

static bool rule_add(port_rule **head, size_t *count, const char *item, const char *label,
                     char *err, size_t errlen)
{
    pcdn_mac mac;
    uint16_t *ports = NULL;
    size_t nports = 0;
    bool has_ports = false;
    if (!parse_mac_entry(item, &mac, &ports, &nports, &has_ports, err, errlen)) {
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s条目无效：%s", label, err);
        set_err(err, errlen, "%s", tmp);
        return false;
    }

    port_rule *r = NULL;
    HASH_FIND(hh, *head, &mac, sizeof(mac), r);
    if (!r) {
        r = xcalloc(1, sizeof(*r));
        r->mac = mac;
        HASH_ADD(hh, *head, mac, sizeof(mac), r);
        (*count)++;
    }
    if (!has_ports) {
        r->all = true;
    } else {
        for (size_t i = 0; i < nports; i++) {
            bool dup = false;
            for (size_t j = 0; j < r->nports; j++) {
                if (r->ports[j] == ports[i]) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                r->ports = xrealloc(r->ports, (r->nports + 1) * sizeof(uint16_t));
                r->ports[r->nports++] = ports[i];
            }
        }
    }
    free(ports);
    return true;
}

bool filter_create(const char *mode, char **blacklist, size_t nblack, char **whitelist,
                   size_t nwhite, device_filter **out, char *err, size_t errlen)
{
    *out = NULL;
    device_filter *f = xcalloc(1, sizeof(*f));
    snprintf(f->mode, sizeof(f->mode), "%s", mode ? mode : "whitelist");

    for (size_t i = 0; i < nblack; i++) {
        if (!rule_add(&f->blacklist, &f->nblack, blacklist[i], "黑名单", err, errlen)) {
            filter_free(f);
            return false;
        }
    }
    for (size_t i = 0; i < nwhite; i++) {
        if (!rule_add(&f->whitelist, &f->nwhite, whitelist[i], "白名单", err, errlen)) {
            filter_free(f);
            return false;
        }
    }
    *out = f;
    return true;
}

static bool rule_match(const port_rule *r, uint16_t port)
{
    if (!r)
        return false;
    if (r->all)
        return true;
    for (size_t i = 0; i < r->nports; i++) {
        if (r->ports[i] == port)
            return true;
    }
    return false;
}

bool filter_allow_key(const device_filter *f, pcdn_mac mac, uint16_t port)
{
    if (!f)
        return true;
    if (strcmp(f->mode, "blacklist") == 0) {
        port_rule *r = NULL;
        HASH_FIND(hh, f->blacklist, &mac, sizeof(mac), r);
        return rule_match(r, port);
    }
    port_rule *r = NULL;
    HASH_FIND(hh, f->whitelist, &mac, sizeof(mac), r);
    return !rule_match(r, port);
}

bool filter_is_empty(const device_filter *f)
{
    return f && strcmp(f->mode, "blacklist") == 0 && f->nblack == 0;
}

void filter_describe(const device_filter *f, char *buf, size_t cap)
{
    if (!f) {
        snprintf(buf, cap, "未启用（检测全部设备）");
        return;
    }
    if (strcmp(f->mode, "blacklist") == 0) {
        size_t exact = 0;
        for (port_rule *r = f->blacklist; r; r = r->hh.next) {
            if (!r->all)
                exact++;
        }
        if (exact == 0)
            snprintf(buf, cap, "黑名单（只检测名单内的 %zu 个设备）", f->nblack);
        else
            snprintf(buf, cap, "黑名单（只检测名单内的 %zu 个设备，其中 %zu 个仅限指定端口）",
                     f->nblack, exact);
        return;
    }
    if (f->nwhite == 0) {
        snprintf(buf, cap, "白名单（名单为空，检测全部设备）");
        return;
    }
    size_t exact = 0;
    for (port_rule *r = f->whitelist; r; r = r->hh.next) {
        if (!r->all)
            exact++;
    }
    snprintf(buf, cap, "白名单（名单内 %zu 个 MAC 不检测，其中 %zu 个仅限指定端口）", f->nwhite,
             exact);
}

void filter_free(device_filter *f)
{
    if (!f)
        return;
    port_rule *r, *tmp;
    HASH_ITER(hh, f->blacklist, r, tmp)
    {
        HASH_DEL(f->blacklist, r);
        free(r->ports);
        free(r);
    }
    HASH_ITER(hh, f->whitelist, r, tmp)
    {
        HASH_DEL(f->whitelist, r);
        free(r->ports);
        free(r);
    }
    free(f);
}
