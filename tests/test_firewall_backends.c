/* iptables / nftables 后端命令拼装测试（用假命令记录参数，不触碰真实防火墙） */
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

static void write_script(const char *path, const char *name, const char *log)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        exit(1);
    }
    fprintf(f, "#!/bin/sh\necho \"%s $*\" >> %s\n", name, log);
    fprintf(f, "if [ \"$3\" = \"-C\" ]; then exit 1; fi\nexit 0\n");
    fclose(f);
    chmod(path, 0700);
}

static char *read_all(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return xstrdup("");
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *buf = xmalloc((size_t)n + 1);
    size_t rd = fread(buf, 1, (size_t)n, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

int main(void)
{
    log_set_level(LOG_ERROR);
    char dir[256], log[256];
    snprintf(dir, sizeof(dir), "/tmp/pcdn-fwbin-%d", (int)getpid());
    snprintf(log, sizeof(log), "/tmp/pcdn-fwbin-%d.log", (int)getpid());
    mkdir(dir, 0700);
    char path[512];
    snprintf(path, sizeof(path), "%s/iptables", dir);
    write_script(path, "iptables", log);
    snprintf(path, sizeof(path), "%s/ip6tables", dir);
    write_script(path, "ip6tables", log);
    snprintf(path, sizeof(path), "%s/nft", dir);
    write_script(path, "nft", log);
    unlink(log);

    char newpath[2048];
    const char *oldpath = getenv("PATH");
    snprintf(newpath, sizeof(newpath), "%s:%s", dir, oldpath ? oldpath : "/usr/bin:/bin");
    setenv("PATH", newpath, 1);

    const char *ipt_toml =
        "[capture]\ninterface=\"lo\"\n"
        "[firewall]\nenabled=true\nbackend=\"iptables\"\nban_both=true\n"
        "[full_ban]\nmode=\"on\"\nthreshold=2\nallow=[53]\n"
        "[upnp]\nmode=\"on\"\nports=[1900]\n";
    config_t cfg;
    char err[1024];
    if (!config_parse(ipt_toml, strlen(ipt_toml), &cfg, err, sizeof(err)) ||
        !config_validate(&cfg, err, sizeof(err))) {
        fprintf(stderr, "ipt config: %s\n", err);
        return 1;
    }
    upnp_filter uf = {.block_all = false};
    firewall *fw = firewall_create(&cfg, &uf, err, sizeof(err));
    if (!fw) {
        fprintf(stderr, "ipt create: %s\n", err);
        return 1;
    }
    CHECK(firewall_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4", 40000, "udp") == 0);
    CHECK(firewall_unban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4", 40000, "udp") == 0);
    CHECK(firewall_full_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_full_unban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_upnp_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_upnp_allow(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    firewall_cleanup(fw);
    firewall_free(fw);
    config_free(&cfg);

    char *out = read_all(log);
    CHECK(strstr(out, "iptables -w 5 -N PCDN_DETECT") != NULL);
    CHECK(strstr(out, "ip6tables -w 5 -N PCDN_DETECT") != NULL);
    CHECK(strstr(out, "iptables -w 5 -I FORWARD -j PCDN_DETECT") != NULL);
    CHECK(strstr(out, "iptables -w 5 -I PCDN_DETECT -m mac --mac-source "
                      "aa:bb:cc:dd:ee:ff -p udp --sport 40000 -j DROP") != NULL);
    CHECK(strstr(out, "ip6tables -w 5 -I PCDN_DETECT -m mac --mac-source "
                      "aa:bb:cc:dd:ee:ff -p udp --sport 40000 -j DROP") != NULL);
    CHECK(strstr(out, "--dports 53 -j ACCEPT") != NULL);
    CHECK(strstr(out, "iptables -w 5 -I PCDN_DETECT_UPNP -m mac --mac-source "
                      "aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 1900 -j DROP") != NULL);
    CHECK(strstr(out, "iptables -w 5 -I PCDN_DETECT_UPNP -m mac --mac-source "
                      "aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 1900 -j ACCEPT") != NULL);
    CHECK(strstr(out, "-w 5 -D FORWARD -j PCDN_DETECT") != NULL);
    CHECK(strstr(out, "-w 5 -F PCDN_DETECT") != NULL);
    CHECK(strstr(out, "-w 5 -X PCDN_DETECT") != NULL);
    free(out);
    unlink(log);

    const char *nft_toml =
        "[capture]\ninterface=\"lo\"\n"
        "[firewall]\nenabled=true\nbackend=\"nftables\"\nban_both=true\n"
        "[firewall.nftables]\ntable=\"pcdn_detect\"\nset=\"banned\"\nhook=\"prerouting\"\n"
        "[full_ban]\nmode=\"on\"\nthreshold=2\nallow=[53,123]\n"
        "[upnp]\nmode=\"on\"\nports=[1900,5000]\n";
    if (!config_parse(nft_toml, strlen(nft_toml), &cfg, err, sizeof(err)) ||
        !config_validate(&cfg, err, sizeof(err))) {
        fprintf(stderr, "nft config: %s\n", err);
        return 1;
    }
    memset(&uf, 0, sizeof(uf));
    fw = firewall_create(&cfg, &uf, err, sizeof(err));
    if (!fw) {
        fprintf(stderr, "nft create: %s\n", err);
        return 1;
    }
    CHECK(firewall_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4", 40000, "udp") == 0);
    CHECK(firewall_full_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    CHECK(firewall_upnp_ban(fw, "aa:bb:cc:dd:ee:ff", "1.2.3.4") == 0);
    firewall_cleanup(fw);
    firewall_free(fw);
    config_free(&cfg);

    out = read_all(log);
    CHECK(strstr(out, "nft add table bridge pcdn_detect") != NULL);
    CHECK(strstr(out, "nft add chain bridge pcdn_detect pcdn_detect { type filter hook "
                      "prerouting priority -150 ; }") != NULL);
    CHECK(strstr(out, "nft add set bridge pcdn_detect banned_v4_udp { type ether_addr . "
                      "inet_service ; }") != NULL);
    CHECK(strstr(out, "nft add rule bridge pcdn_detect pcdn_detect ether type ip ip protocol "
                      "udp ether saddr . udp sport @banned_v4_udp drop") != NULL);
    CHECK(strstr(out, "nft add element bridge pcdn_detect banned_v4_udp { "
                      "aa:bb:cc:dd:ee:ff . 40000 }") != NULL);
    CHECK(strstr(out, "nft add element bridge pcdn_detect banned_v6_udp { "
                      "aa:bb:cc:dd:ee:ff . 40000 }") != NULL);
    CHECK(strstr(out, "nft add element bridge pcdn_detect banned_fullban_macs { "
                      "aa:bb:cc:dd:ee:ff }") != NULL);
    CHECK(strstr(out, "nft add element bridge pcdn_detect banned_upnp_macs { "
                      "aa:bb:cc:dd:ee:ff }") != NULL);
    CHECK(strstr(out, "nft delete table bridge pcdn_detect") != NULL);
    free(out);

    unlink(log);
    char p[512];
    snprintf(p, sizeof(p), "%s/iptables", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/ip6tables", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/nft", dir);
    unlink(p);
    rmdir(dir);

    if (g_fail) {
        fprintf(stderr, "%d 项检查失败\n", g_fail);
        return 1;
    }
    printf("test_firewall_backends: OK\n");
    return 0;
}
