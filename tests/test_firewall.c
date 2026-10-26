/* hook 后端测试：验证占位符替换、v4/v6 双发、全端口与 UPnP 参数 */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

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

int main(void)
{
    log_set_level(LOG_ERROR);
    char script[256], out[256];
    snprintf(script, sizeof(script), "/tmp/pcdn-fw-test-%d.sh", (int)getpid());
    snprintf(out, sizeof(out), "/tmp/pcdn-fw-out-%d.txt", (int)getpid());
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
             "[full_ban.hook]\ncmd=\"%s f {action} {mac} {ip} {family} {ports}\"\n"
             "[upnp]\nmode=\"on\"\nports=[1900,5000]\n"
             "[upnp.hook]\ncmd=\"%s u {action} {mac} {ip} {family} {ports}\"\n",
             script, script, script);
    config_t cfg;
    char err[1024];
    if (!config_parse(toml, strlen(toml), &cfg, err, sizeof(err))) {
        fprintf(stderr, "parse: %s\n", err);
        return 1;
    }
    config_apply_defaults(&cfg);
    if (!config_validate(&cfg, err, sizeof(err))) {
        fprintf(stderr, "validate: %s\n", err);
        return 1;
    }
    upnp_filter uf = {.block_all = false};
    firewall *fw = firewall_create(&cfg, &uf, err, sizeof(err));
    if (!fw) {
        fprintf(stderr, "create: %s\n", err);
        return 1;
    }
    CHECK(firewall_ban_both(fw));
    CHECK(firewall_fullban_enabled(fw));
    CHECK(firewall_upnp_enabled(fw));
    size_t n = 0;
    const uint16_t *ports = firewall_fullban_allow_ports(fw, &n);
    CHECK(n == 2 && ports[0] == 53 && ports[1] == 123);

    CHECK(firewall_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4", 40000, "udp") == 0);
    CHECK(firewall_unban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4", 40000, "udp") == 0);
    CHECK(firewall_full_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_full_unban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_upnp_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_upnp_unban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_upnp_block_all(fw) == 0);
    CHECK(firewall_upnp_unblock_all(fw) == 0);

    int lines = 0;
    bool saw_p_v4 = false, saw_p_v6 = false, saw_f = false, saw_u = false;
    f = fopen(out, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            lines++;
            if (strstr(line, "p ban aa:bb:cc:dd:ee:ff 1.2.3.4 40000 v4 udp"))
                saw_p_v4 = true;
            if (strstr(line, "p ban aa:bb:cc:dd:ee:ff 1.2.3.4 40000 v6 udp"))
                saw_p_v6 = true;
            if (strstr(line, "f ban aa:bb:cc:dd:ee:ff 1.2.3.4 v4 53,123"))
                saw_f = true;
            if (strstr(line, "u block-all") && strstr(line, "v4 1900,5000"))
                saw_u = true;
        }
        fclose(f);
    }
    CHECK(lines >= 10);
    CHECK(saw_p_v4);
    CHECK(saw_p_v6);
    CHECK(saw_f);
    CHECK(saw_u);

    /* 纯配置校验：链名冲突 / 非法 nft hook 应被拒绝 */
    config_t bad;
    memset(&bad, 0, sizeof(bad));
    config_default(&bad);
    bad.firewall.enabled = true;
    free(bad.firewall.backend);
    bad.firewall.backend = xstrdup("iptables");
    free(bad.firewall.ipt_ban_chain);
    bad.firewall.ipt_ban_chain = xstrdup("FORWARD");
    CHECK(!firewall_validate_config(&bad, err, sizeof(err)));
    free(bad.firewall.ipt_ban_chain);
    bad.firewall.ipt_ban_chain = xstrdup("");
    free(bad.firewall.backend);
    bad.firewall.backend = xstrdup("nftables");
    free(bad.firewall.nft_hook);
    bad.firewall.nft_hook = xstrdup("bad-hook");
    CHECK(!firewall_validate_config(&bad, err, sizeof(err)));
    free(bad.firewall.nft_hook);
    bad.firewall.nft_hook = xstrdup("prerouting");
    CHECK(firewall_validate_config(&bad, err, sizeof(err)));
    config_free(&bad);

    config_free(&cfg);
    firewall_free(fw);
    unlink(script);
    unlink(out);

    if (g_fail) {
        fprintf(stderr, "%d 项检查失败\n", g_fail);
        return 1;
    }
    printf("test_firewall: OK\n");
    return 0;
}
