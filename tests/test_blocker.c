/* blocker 测试：引用计数、全 UDP 端口封禁联动、手动解封 */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blocker.h"
#include "config.h"
#include "firewall.h"
#include "util.h"

static int g_fail;

#define CHECK(cond)                                                                            \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
            g_fail++;                                                                          \
        }                                                                                      \
    } while (0)

typedef struct {
    int bans;
    int applied;
    int full;
} snap_counts;

static snap_counts snapshot_counts(blocker *b)
{
    blocker_snapshot s;
    blocker_snapshot_get(b, &s);
    snap_counts c = {.bans = (int)s.nbans, .full = (int)s.nfull};
    for (size_t i = 0; i < s.nbans; i++) {
        if (s.bans[i].applied)
            c.applied++;
    }
    blocker_snapshot_free(&s);
    return c;
}

static bool wait_counts(blocker *b, int bans, int full, int applied, int timeout_ms)
{
    for (int i = 0; i < timeout_ms / 20; i++) {
        snap_counts c = snapshot_counts(b);
        if (c.bans == bans && c.full == full && c.applied == applied)
            return true;
        struct timespec req = {.tv_sec = 0, .tv_nsec = 20000000L};
        nanosleep(&req, NULL);
    }
    return false;
}

int main(void)
{
    log_set_level(LOG_ERROR);
    char script[256], out[256];
    snprintf(script, sizeof(script), "/tmp/pcdn-blk-test-%d.sh", (int)getpid());
    snprintf(out, sizeof(out), "/tmp/pcdn-blk-out-%d.txt", (int)getpid());
    FILE *f = fopen(script, "w");
    if (!f)
        return 1;
    fprintf(f, "#!/bin/sh\necho \"$@\" >> %s\n", out);
    fclose(f);
    chmod(script, 0700);
    unlink(out);

    char toml[4096];
    snprintf(toml, sizeof(toml),
             "[capture]\ninterface=\"lo\"\n"
             "[firewall]\nenabled=true\nbackend=\"hook\"\nban_both=true\n"
             "[firewall.hook]\ncmd=\"%s p {action} {mac} {ip} {port} {family} {proto}\"\n"
             "[full_ban]\nmode=\"on\"\nthreshold=2\nallow=[53,123]\n"
             "[full_ban.hook]\ncmd=\"%s f {action} {mac} {ip} {family} {ports}\"\n",
             script, script);
    config_t cfg;
    char err[1024];
    if (!config_parse(toml, strlen(toml), &cfg, err, sizeof(err)) ||
        !config_validate(&cfg, err, sizeof(err))) {
        fprintf(stderr, "config: %s\n", err);
        return 1;
    }
    upnp_filter uf = {0};
    firewall *fw = firewall_create(&cfg, &uf, err, sizeof(err));
    if (!fw) {
        fprintf(stderr, "firewall: %s\n", err);
        return 1;
    }
    blocker_fullban_cfg fb = {.enabled = true, .threshold = 2};
    snprintf(fb.mode, sizeof(fb.mode), "on");
    blocker_upnp_cfg up = {0};
    blocker *b = blocker_create(fw, false, &fb, &up);
    void *ctx = NULL;
    const alert_sink *sink = blocker_alert_sink(b, &ctx);
    const char *mac = "aa:bb:cc:dd:ee:ff";
    const char *ip = "1.2.3.4";

    sink->on_alert_start(ctx, mac, ip, 40000, "udp");
    CHECK(wait_counts(b, 1, 0, 1, 2000));

    sink->on_alert_start(ctx, mac, ip, 40001, "udp");
    CHECK(wait_counts(b, 2, 1, 0, 2000));

    sink->on_alert_end(ctx, mac, ip, 40000, "udp");
    sink->on_alert_end(ctx, mac, ip, 40001, "udp");
    CHECK(wait_counts(b, 0, 0, 0, 2000));

    /* ban_both=true 时 v4/v6 同端口合并为一个条目、引用计数为 2 */
    sink->on_alert_start(ctx, mac, ip, 40003, "tcp");
    sink->on_alert_start(ctx, mac, "2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", 40003, "tcp");
    CHECK(wait_counts(b, 1, 0, 1, 2000));
    sink->on_alert_end(ctx, mac, ip, 40003, "tcp");
    CHECK(wait_counts(b, 1, 0, 1, 2000));
    sink->on_alert_end(ctx, mac, "2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", 40003, "tcp");
    CHECK(wait_counts(b, 0, 0, 0, 2000));

    /* 手动解封 */
    sink->on_alert_start(ctx, mac, ip, 40002, "udp");
    CHECK(wait_counts(b, 1, 0, 1, 2000));
    int removed = 0;
    char uerr[512] = {0};
    blocker_force_unban(b, mac, 40002, "udp", &removed, uerr, sizeof(uerr));
    CHECK(removed == 1);
    CHECK(wait_counts(b, 0, 0, 0, 2000));

    /* 状态导出 / 恢复：恢复后应重新下发端口封禁 */
    sink->on_alert_start(ctx, mac, ip, 40004, "udp");
    CHECK(wait_counts(b, 1, 0, 1, 2000));
    state_file *st = xcalloc(1, sizeof(*st));
    CHECK(blocker_block_state(b, st, err, sizeof(err)));
    char uerr2[512] = {0};
    int removed2 = 0;
    blocker_force_unban(b, mac, 40004, "udp", &removed2, uerr2, sizeof(uerr2));
    CHECK(removed2 == 1);
    CHECK(wait_counts(b, 0, 0, 0, 2000));

    blocker_close(b);
    blocker_free(b);

    blocker *b2 = blocker_create(fw, false, &fb, &up);
    blocker_restore(b2, st);
    CHECK(wait_counts(b2, 1, 0, 1, 2000));
    blocker_close(b2);
    blocker_free(b2);
    state_free(st);

    int lines = 0;
    bool saw_port_ban = false, saw_full_ban = false, saw_full_unban = false,
         saw_port_unban = false;
    f = fopen(out, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            lines++;
            if (strstr(line, "p ban aa:bb:cc:dd:ee:ff 1.2.3.4 40000 v4 udp"))
                saw_port_ban = true;
            if (strstr(line, "f ban aa:bb:cc:dd:ee:ff 1.2.3.4 v4 53,123"))
                saw_full_ban = true;
            if (strstr(line, "f unban aa:bb:cc:dd:ee:ff 1.2.3.4 v4 53,123"))
                saw_full_unban = true;
            if (strstr(line, "p unban aa:bb:cc:dd:ee:ff 1.2.3.4 40000 v4 udp"))
                saw_port_unban = true;
        }
        fclose(f);
    }
    CHECK(lines > 0);
    CHECK(saw_port_ban);
    CHECK(saw_full_ban);
    CHECK(saw_full_unban);
    CHECK(saw_port_unban);

    firewall_cleanup(fw);
    firewall_free(fw);
    config_free(&cfg);
    unlink(script);
    unlink(out);

    if (g_fail) {
        fprintf(stderr, "%d 项检查失败\n", g_fail);
        return 1;
    }
    printf("test_blocker: OK\n");
    return 0;
}
