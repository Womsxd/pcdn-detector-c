#include "firewall.h"

#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "util.h"

enum { FW_HOOK = 1, FW_IPTABLES, FW_NFTABLES };

#define DEFAULT_CHAIN "FORWARD"
#define DEFAULT_INPUT_CHAIN "INPUT"
#define DEFAULT_IPT_BAN_CHAIN "PCDN_DETECT"
#define DEFAULT_IPT_UPNP_CHAIN "PCDN_DETECT_UPNP"
#define IPT_CHAIN_MAX 28
#define DEFAULT_NFT_TABLE "pcdn_detect"
#define DEFAULT_NFT_SET "banned"

struct firewall {
    int backend;
    char *hook_cmd;
    char *chain;
    char *ban_chain;
    char *hook;
    char *table;
    char *set;
    bool ban_both;
    bool has_v6;
    char protos[2][4];
    int nprotos;
    int64_t ban_ttl_ns;
    int timeout_ms;

    bool full_ban;
    uint16_t *fullban_allow;
    size_t n_fullban_allow;
    char *fullban_hook;

    bool upnp;
    bool upnp_block_all;
    uint16_t *upnp_ports;
    size_t n_upnp_ports;
    char *upnp_chain;
    char *upnp_rule_chain;
    char *upnp_input_hook;
    char *upnp_hook_cmd;
};

/* ------------------------------------------------------------------ */
/* 命令执行                                                            */
/* ------------------------------------------------------------------ */

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

static char *trim_lower_dup(const char *s)
{
    if (!s)
        return xstrdup("");
    while (isspace((unsigned char)*s))
        s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        n--;
    char *p = xstrndup(s, n);
    for (char *q = p; *q; q++)
        *q = (char)tolower((unsigned char)*q);
    return p;
}

static bool command_exists(const char *name)
{
    if (strchr(name, '/'))
        return access(name, X_OK) == 0;
    const char *path = getenv("PATH");
    if (!path)
        path = "/usr/sbin:/usr/bin:/sbin:/bin";
    char *copy = xstrdup(path);
    char *save = NULL;
    bool found = false;
    for (char *dir = strtok_r(copy, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/%s", dir, name);
        if (access(buf, X_OK) == 0) {
            found = true;
            break;
        }
    }
    free(copy);
    return found;
}

static int run_command(char *const argv[], int timeout_ms, char *err, size_t errlen)
{
    if (timeout_ms <= 0)
        timeout_ms = 5000;

    char cmdline[1024];
    size_t off = 0;
    cmdline[0] = '\0';
    for (int i = 0; argv[i] && off + 2 < sizeof(cmdline); i++) {
        int n = snprintf(cmdline + off, sizeof(cmdline) - off, "%s%s", i ? " " : "", argv[i]);
        if (n < 0)
            break;
        off += (size_t)n;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        set_err(err, errlen, "%s：创建管道失败：%s", cmdline, strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        set_err(err, errlen, "%s：fork 失败：%s", cmdline, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    char out[4096];
    size_t outn = 0;
    bool eof = false, timedout = false;
    int64_t deadline = mono_ms() + timeout_ms;
    while (!eof) {
        int64_t remain = deadline - mono_ms();
        if (remain <= 0) {
            timedout = true;
            break;
        }
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN | POLLHUP};
        int pr = poll(&pfd, 1, (int)(remain > 100 ? 100 : remain));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0)
            continue;
        char buf[512];
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) {
            size_t take = (size_t)n;
            if (outn + take >= sizeof(out))
                take = sizeof(out) - outn - 1;
            memcpy(out + outn, buf, take);
            outn += take;
        } else if (n == 0) {
            eof = true;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
    }
    close(pipefd[0]);
    out[outn] = '\0';
    while (outn > 0 && isspace((unsigned char)out[outn - 1]))
        out[--outn] = '\0';

    int status = 0;
    if (timedout) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        set_err(err, errlen, "%s：命令执行超时（%d ms）", cmdline, timeout_ms);
        return -1;
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            set_err(err, errlen, "%s：等待命令失败：%s", cmdline, strerror(errno));
            return -1;
        }
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;
    if (WIFEXITED(status))
        set_err(err, errlen, "%s：exit status %d（输出：%s）", cmdline, WEXITSTATUS(status), out);
    else if (WIFSIGNALED(status))
        set_err(err, errlen, "%s：被信号 %d 终止（输出：%s）", cmdline, WTERMSIG(status), out);
    else
        set_err(err, errlen, "%s：执行失败（输出：%s）", cmdline, out);
    return -1;
}

/* ------------------------------------------------------------------ */
/* 字符串辅助                                                          */
/* ------------------------------------------------------------------ */

static char *replace_all(const char *src, const char *needle, const char *repl)
{
    strbuf sb;
    sb_init(&sb);
    size_t nl = strlen(needle);
    const char *p = src;
    while (*p) {
        const char *hit = strstr(p, needle);
        if (!hit) {
            sb_add(&sb, p);
            break;
        }
        sb_addn(&sb, p, (size_t)(hit - p));
        sb_add(&sb, repl);
        p = hit + nl;
    }
    return sb_detach(&sb);
}

static char *render_cmd(const char *tpl, const char *action, const char *mac, const char *ip,
                        uint16_t port, const char *family, const char *proto)
{
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", port);
    char *s = replace_all(tpl ? tpl : "", "{action}", action);
    char *t = replace_all(s, "{mac}", mac ? mac : "");
    free(s);
    s = replace_all(t, "{ip}", ip ? ip : "");
    free(t);
    t = replace_all(s, "{port}", portbuf);
    free(s);
    s = replace_all(t, "{family}", family);
    free(t);
    t = replace_all(s, "{proto}", proto);
    free(s);
    return t;
}

static char *render_full_cmd(const char *tpl, const char *action, const char *mac,
                             const char *ip, const char *family, const uint16_t *ports,
                             size_t nports)
{
    strbuf sb;
    sb_init(&sb);
    for (size_t i = 0; i < nports; i++)
        sb_addf(&sb, "%s%u", i ? "," : "", ports[i]);
    char *csv = sb_detach(&sb);
    char *s = replace_all(tpl ? tpl : "", "{action}", action);
    char *t = replace_all(s, "{mac}", mac ? mac : "");
    free(s);
    s = replace_all(t, "{ip}", ip ? ip : "");
    free(t);
    t = replace_all(s, "{family}", family);
    free(s);
    s = replace_all(t, "{ports}", csv);
    free(t);
    free(csv);
    return s;
}

static const char *addr_family(const char *ip)
{
    return (ip && strchr(ip, ':')) ? "v6" : "v4";
}

const char *firewall_addr_family(const char *ip)
{
    return addr_family(ip);
}

static const char *ip_for_family(const char *ip, const char *family)
{
    if (!ip || ip[0] == '\0' || strcmp(addr_family(ip), family) != 0)
        return "";
    return ip;
}

static void ports_csv(const uint16_t *ports, size_t n, char *buf, size_t cap)
{
    size_t off = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < n && off + 8 < cap; i++)
        off += (size_t)snprintf(buf + off, cap - off, "%s%u", i ? "," : "", ports[i]);
}

/* ------------------------------------------------------------------ */
/* 配置校验                                                            */
/* ------------------------------------------------------------------ */

static bool nft_hook_valid(const char *hook)
{
    return strcmp(hook, "prerouting") == 0 || strcmp(hook, "input") == 0 ||
           strcmp(hook, "forward") == 0 || strcmp(hook, "output") == 0 ||
           strcmp(hook, "postrouting") == 0;
}

static char *nft_hook_norm(const char *hook, const char *def, char *err, size_t errlen)
{
    char *h = trim_lower_dup(hook ? hook : "");
    if (h[0] == '\0') {
        free(h);
        return xstrdup(def);
    }
    if (!nft_hook_valid(h)) {
        set_err(err, errlen,
                "nftables hook 无效 \"%s\"（bridge 族可选 prerouting / input / forward / "
                "output / postrouting）",
                hook);
        free(h);
        return NULL;
    }
    return h;
}

static bool ipt_chain_name_valid(const char *name, char *err, size_t errlen)
{
    if (!name || name[0] == '\0') {
        set_err(err, errlen, "不能为空");
        return false;
    }
    if (strlen(name) > IPT_CHAIN_MAX) {
        set_err(err, errlen, "长度不能超过 %d 个字符", IPT_CHAIN_MAX);
        return false;
    }
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
            set_err(err, errlen, "只能包含字母、数字、下划线与连字符：\"%s\"", name);
            return false;
        }
    }
    return true;
}

static bool validate_ipt_chains(const char *hook, const char *input, const char *ban,
                                const char *upnp, char *err, size_t errlen)
{
    if (!ipt_chain_name_valid(ban, err, errlen)) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "[firewall.iptables] ban_chain 无效：%s", err);
        set_err(err, errlen, "%s", tmp);
        return false;
    }
    if (!ipt_chain_name_valid(upnp, err, errlen)) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "[firewall.iptables] upnp_chain 无效：%s", err);
        set_err(err, errlen, "%s", tmp);
        return false;
    }
    if (strcmp(ban, hook) == 0 || strcmp(ban, input) == 0) {
        set_err(err, errlen, "[firewall.iptables] ban_chain 不能与 chain / input_chain 相同（%s）",
                ban);
        return false;
    }
    if (strcmp(upnp, hook) == 0 || strcmp(upnp, input) == 0) {
        set_err(err, errlen,
                "[firewall.iptables] upnp_chain 不能与 chain / input_chain 相同（%s）", upnp);
        return false;
    }
    if (strcmp(ban, upnp) == 0) {
        set_err(err, errlen, "[firewall.iptables] ban_chain 与 upnp_chain 不能相同（%s）", ban);
        return false;
    }
    return true;
}

bool firewall_validate_config(const config_t *cfg, char *err, size_t errlen)
{
    char *backend = trim_lower_dup(cfg->firewall.backend);
    bool ok = true;
    if (strcmp(backend, "hook") == 0) {
        if (str_empty(cfg->firewall.hook_cmd)) {
            set_err(err, errlen, "backend = \"hook\" 需要配置 [firewall.hook] 的 cmd");
            ok = false;
        } else if (config_fullban_enabled(cfg) && str_empty(cfg->full_ban.hook_cmd)) {
            set_err(err, errlen,
                    "backend = \"hook\" 启用 full_ban 时需要配置 [full_ban.hook] 的 cmd");
            ok = false;
        } else if (config_upnp_enabled(cfg) && str_empty(cfg->upnp.hook_cmd)) {
            set_err(err, errlen, "backend = \"hook\" 启用 upnp 时需要配置 [upnp.hook] 的 cmd");
            ok = false;
        }
    } else if (strcmp(backend, "iptables") == 0) {
        const char *hook = str_empty(cfg->firewall.ipt_chain) ? DEFAULT_CHAIN
                                                              : cfg->firewall.ipt_chain;
        const char *input = str_empty(cfg->firewall.ipt_input_chain)
                                ? DEFAULT_INPUT_CHAIN
                                : cfg->firewall.ipt_input_chain;
        const char *ban = str_empty(cfg->firewall.ipt_ban_chain)
                              ? DEFAULT_IPT_BAN_CHAIN
                              : cfg->firewall.ipt_ban_chain;
        const char *upnp = str_empty(cfg->firewall.ipt_upnp_chain)
                               ? DEFAULT_IPT_UPNP_CHAIN
                               : cfg->firewall.ipt_upnp_chain;
        ok = validate_ipt_chains(hook, input, ban, upnp, err, errlen);
    } else if (strcmp(backend, "nftables") == 0) {
        char e[256];
        char *h = nft_hook_norm(cfg->firewall.nft_hook, "prerouting", e, sizeof(e));
        if (!h) {
            set_err(err, errlen, "%s", e);
            ok = false;
        } else {
            free(h);
            if (config_upnp_enabled(cfg)) {
                h = nft_hook_norm(cfg->firewall.nft_input_hook, "input", e, sizeof(e));
                if (!h) {
                    set_err(err, errlen, "%s", e);
                    ok = false;
                } else {
                    free(h);
                }
            }
        }
    } else {
        set_err(err, errlen, "firewall.backend 无效 \"%s\"（可选 hook / iptables / nftables）",
                cfg->firewall.backend ? cfg->firewall.backend : "");
        ok = false;
    }
    free(backend);
    if (!ok)
        return false;

    if (config_fullban_enabled(cfg)) {
        uint16_t *ports = NULL;
        size_t n = 0;
        if (!config_fullban_allow(cfg, &ports, &n, err, errlen))
            return false;
        free(ports);
    }
    if (config_upnp_enabled(cfg)) {
        uint16_t *ports = NULL;
        size_t n = 0;
        if (!config_upnp_ports(cfg, &ports, &n, err, errlen))
            return false;
        free(ports);
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* 构建                                                                */
/* ------------------------------------------------------------------ */

static void set_protos(firewall *fw, const char *protocol)
{
    fw->nprotos = 0;
    if (strcmp(protocol, "tcp") == 0) {
        snprintf(fw->protos[fw->nprotos++], 4, "%s", "tcp");
    } else if (strcmp(protocol, "all") == 0) {
        snprintf(fw->protos[fw->nprotos++], 4, "%s", "udp");
        snprintf(fw->protos[fw->nprotos++], 4, "%s", "tcp");
    } else {
        snprintf(fw->protos[fw->nprotos++], 4, "%s", "udp");
    }
}

static const char *const *target_families(const firewall *fw, const char *ip, int *n)
{
    static const char *both[2] = {"v4", "v6"};
    static _Thread_local const char *one[1];
    if (fw->ban_both) {
        *n = 2;
        return both;
    }
    one[0] = addr_family(ip);
    *n = 1;
    return one;
}

/* ---- iptables ---- */

static int ipt_run(firewall *fw, const char *bin, const char *const *args, int nargs, char *err,
                   size_t errlen)
{
    char *argv[40];
    int n = 0;
    argv[n++] = (char *)bin;
    argv[n++] = (char *)"-w";
    argv[n++] = (char *)"5";
    for (int i = 0; i < nargs && n < 38; i++)
        argv[n++] = (char *)args[i];
    argv[n] = NULL;
    return run_command(argv, fw->timeout_ms, err, errlen);
}

static void reset_ipt_chain(firewall *fw, const char *bin, const char *hook, const char *chain)
{
    char e[512];
    const char *a1[] = {"-D", hook, "-j", chain};
    ipt_run(fw, bin, a1, 4, e, sizeof(e));
    const char *a2[] = {"-F", chain};
    ipt_run(fw, bin, a2, 2, e, sizeof(e));
    const char *a3[] = {"-X", chain};
    ipt_run(fw, bin, a3, 2, e, sizeof(e));
}

static void setup_iptables(firewall *fw)
{
    char e[512];
    for (int b = 0; b < 2; b++) {
        const char *bin = b == 0 ? "iptables" : "ip6tables";
        if (b == 1 && !fw->has_v6)
            continue;
        reset_ipt_chain(fw, bin, fw->chain, fw->ban_chain);
        const char *n1[] = {"-N", fw->ban_chain};
        ipt_run(fw, bin, n1, 2, e, sizeof(e));
        const char *i1[] = {"-I", fw->chain, "-j", fw->ban_chain};
        ipt_run(fw, bin, i1, 4, e, sizeof(e));

        if (!fw->upnp_chain)
            continue;
        reset_ipt_chain(fw, bin, fw->upnp_chain, fw->upnp_rule_chain);
        if (fw->upnp) {
            const char *n2[] = {"-N", fw->upnp_rule_chain};
            ipt_run(fw, bin, n2, 2, e, sizeof(e));
            const char *i2[] = {"-I", fw->upnp_chain, "-j", fw->upnp_rule_chain};
            ipt_run(fw, bin, i2, 4, e, sizeof(e));
        }
    }
}

static int ipt_set(firewall *fw, bool ban, const char *mac, uint16_t port, const char *ip,
                   const char *proto)
{
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", port);
    int nfam = 0;
    const char *const *fams = target_families(fw, ip, &nfam);
    char first_err[512] = {0};
    int rc = 0;
    for (int i = 0; i < nfam; i++) {
        if (strcmp(fams[i], "v6") == 0 && !fw->has_v6)
            continue;
        const char *bin = strcmp(fams[i], "v6") == 0 ? "ip6tables" : "iptables";
        const char *rule[] = {"-m", "mac", "--mac-source", mac, "-p", proto,
                              "--sport", portbuf, "-j", "DROP"};
        char e[512];
        if (ban) {
            const char *check[40];
            int n = 0;
            check[n++] = (char *)"-C";
            check[n++] = fw->ban_chain;
            for (size_t k = 0; k < ARRAY_LEN(rule); k++)
                check[n++] = (char *)rule[k];
            if (ipt_run(fw, bin, check, n, e, sizeof(e)) == 0)
                continue;
            const char *ins[40];
            n = 0;
            ins[n++] = (char *)"-I";
            ins[n++] = fw->ban_chain;
            for (size_t k = 0; k < ARRAY_LEN(rule); k++)
                ins[n++] = (char *)rule[k];
            if (ipt_run(fw, bin, ins, n, e, sizeof(e)) != 0 && rc == 0) {
                snprintf(first_err, sizeof(first_err), "%s", e);
                rc = -1;
            }
        } else {
            const char *del[40];
            int n = 0;
            del[n++] = (char *)"-D";
            del[n++] = fw->ban_chain;
            for (size_t k = 0; k < ARRAY_LEN(rule); k++)
                del[n++] = (char *)rule[k];
            if (ipt_run(fw, bin, del, n, e, sizeof(e)) != 0 && rc == 0) {
                snprintf(first_err, sizeof(first_err), "%s", e);
                rc = -1;
            }
        }
    }
    if (rc != 0)
        log_error("iptables 规则下发失败：%s", first_err);
    return rc;
}

static int ipt_full_ban(firewall *fw, bool ban, const char *mac)
{
    char ports[256];
    ports_csv(fw->fullban_allow, fw->n_fullban_allow, ports, sizeof(ports));
    const char *base[] = {"-m", "mac", "--mac-source", mac, "-p", "udp"};
    int rc = 0;
    for (int b = 0; b < 2; b++) {
        const char *bin = b == 0 ? "iptables" : "ip6tables";
        if (b == 1 && !fw->has_v6)
            continue;
        for (int ruleidx = 0; ruleidx < 2; ruleidx++) {
            if (ruleidx == 1 && (fw->n_fullban_allow == 0 || ports[0] == '\0'))
                continue;
            const char *args[40];
            int n = 0;
            args[n++] = (char *)(ban ? "-I" : "-D");
            args[n++] = fw->ban_chain;
            for (size_t k = 0; k < ARRAY_LEN(base); k++)
                args[n++] = (char *)base[k];
            if (ruleidx == 1) {
                args[n++] = (char *)"-m";
                args[n++] = (char *)"multiport";
                args[n++] = (char *)"--dports";
                args[n++] = ports;
                args[n++] = (char *)"-j";
                args[n++] = (char *)"ACCEPT";
            } else {
                args[n++] = (char *)"-j";
                args[n++] = (char *)"DROP";
            }
            char e[512];
            if (ban) {
                /* 先 -C 去重：把 -I 换成 -C 重新执行一次 */
                const char *chk[40];
                int m = 0;
                chk[m++] = (char *)"-C";
                chk[m++] = fw->ban_chain;
                for (int k = 2; k < n; k++)
                    chk[m++] = args[k];
                if (ipt_run(fw, bin, chk, m, e, sizeof(e)) == 0)
                    continue;
            }
            if (ipt_run(fw, bin, args, n, e, sizeof(e)) != 0) {
                log_error("iptables 全端口封禁失败：%s", e);
                rc = -1;
            }
        }
    }
    return rc;
}

static int ipt_upnp_rules(firewall *fw, bool ban, const char *mac, const char *target)
{
    char ports[256];
    ports_csv(fw->upnp_ports, fw->n_upnp_ports, ports, sizeof(ports));
    int rc = 0;
    for (int b = 0; b < 2; b++) {
        const char *bin = b == 0 ? "iptables" : "ip6tables";
        if (b == 1 && !fw->has_v6)
            continue;
        for (int p = 0; p < 2; p++) {
            const char *proto = p == 0 ? "udp" : "tcp";
            const char *rule[16];
            int rn = 0;
            if (mac && mac[0]) {
                rule[rn++] = "-m";
                rule[rn++] = "mac";
                rule[rn++] = "--mac-source";
                rule[rn++] = mac;
            }
            rule[rn++] = "-p";
            rule[rn++] = proto;
            if (fw->n_upnp_ports > 0 && ports[0]) {
                rule[rn++] = "-m";
                rule[rn++] = "multiport";
                rule[rn++] = "--dports";
                rule[rn++] = ports;
            }
            rule[rn++] = "-j";
            rule[rn++] = target;

            char e[512];
            if (ban) {
                const char *chk[32];
                int n = 0;
                chk[n++] = (char *)"-C";
                chk[n++] = fw->upnp_rule_chain;
                for (int k = 0; k < rn; k++)
                    chk[n++] = (char *)rule[k];
                if (ipt_run(fw, bin, chk, n, e, sizeof(e)) == 0)
                    continue;
                const char *ins[32];
                n = 0;
                ins[n++] = (char *)"-I";
                ins[n++] = fw->upnp_rule_chain;
                for (int k = 0; k < rn; k++)
                    ins[n++] = (char *)rule[k];
                if (ipt_run(fw, bin, ins, n, e, sizeof(e)) != 0) {
                    log_error("iptables UPnP 规则下发失败：%s", e);
                    rc = -1;
                }
            } else {
                const char *del[32];
                int n = 0;
                del[n++] = (char *)"-D";
                del[n++] = fw->upnp_rule_chain;
                for (int k = 0; k < rn; k++)
                    del[n++] = (char *)rule[k];
                if (ipt_run(fw, bin, del, n, e, sizeof(e)) != 0) {
                    log_error("iptables UPnP 规则移除失败：%s", e);
                    rc = -1;
                }
            }
        }
    }
    return rc;
}

/* ---- nftables ---- */

static int nft_run(firewall *fw, const char *stmt, char *err, size_t errlen)
{
    char *argv[4] = {(char *)"nft", (char *)stmt, NULL};
    return run_command(argv, fw->timeout_ms, err, errlen);
}

static void nft_setup(firewall *fw)
{
    char e[512];
    char stmt[1024];
    snprintf(stmt, sizeof(stmt), "delete table bridge %s", fw->table);
    nft_run(fw, stmt, e, sizeof(e));

    snprintf(stmt, sizeof(stmt), "add table bridge %s", fw->table);
    if (nft_run(fw, stmt, e, sizeof(e)) != 0)
        log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);

    snprintf(stmt, sizeof(stmt),
             "add chain bridge %s %s { type filter hook %s priority -150 ; }", fw->table,
             fw->table, fw->hook);
    if (nft_run(fw, stmt, e, sizeof(e)) != 0)
        log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);

    const char *timeoutflag = fw->ban_ttl_ns > 0 ? " flags timeout ;" : "";
    for (int f = 0; f < 2; f++) {
        const char *fam = f == 0 ? "v4" : "v6";
        for (int p = 0; p < fw->nprotos; p++) {
            snprintf(stmt, sizeof(stmt),
                     "add set bridge %s %s_%s_%s { type ether_addr . inet_service ;%s }",
                     fw->table, fw->set, fam, fw->protos[p], timeoutflag);
            if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        }
    }
    for (int p = 0; p < fw->nprotos; p++) {
        const char *proto = fw->protos[p];
        snprintf(stmt, sizeof(stmt),
                 "add rule bridge %s %s ether type ip ip protocol %s ether saddr . %s sport "
                 "@%s_v4_%s drop",
                 fw->table, fw->table, proto, proto, fw->set, proto);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        snprintf(stmt, sizeof(stmt),
                 "add rule bridge %s %s ether type ip6 meta l4proto %s ether saddr . %s sport "
                 "@%s_v6_%s drop",
                 fw->table, fw->table, proto, proto, fw->set, proto);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
    }

    if (fw->full_ban) {
        char ports[256];
        ports_csv(fw->fullban_allow, fw->n_fullban_allow, ports, sizeof(ports));
        snprintf(stmt, sizeof(stmt), "add set bridge %s %s_fullban_macs { type ether_addr ;%s }",
                 fw->table, fw->set, timeoutflag);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        snprintf(stmt, sizeof(stmt), "add set bridge %s %s_fullban_allow { type inet_service ; }",
                 fw->table, fw->set);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        if (ports[0]) {
            snprintf(stmt, sizeof(stmt), "add element bridge %s %s_fullban_allow { %s }",
                     fw->table, fw->set, ports);
            if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        }
        snprintf(stmt, sizeof(stmt),
                 "add rule bridge %s %s ether type ip ip protocol udp ether saddr "
                 "@%s_fullban_macs udp dport @%s_fullban_allow accept",
                 fw->table, fw->table, fw->set, fw->set);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        snprintf(stmt, sizeof(stmt),
                 "add rule bridge %s %s ether type ip ip protocol udp ether saddr "
                 "@%s_fullban_macs drop",
                 fw->table, fw->table, fw->set);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        snprintf(stmt, sizeof(stmt),
                 "add rule bridge %s %s ether type ip6 meta l4proto udp ether saddr "
                 "@%s_fullban_macs udp dport @%s_fullban_allow accept",
                 fw->table, fw->table, fw->set, fw->set);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
        snprintf(stmt, sizeof(stmt),
                 "add rule bridge %s %s ether type ip6 meta l4proto udp ether saddr "
                 "@%s_fullban_macs drop",
                 fw->table, fw->table, fw->set);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
    }

    if (fw->upnp) {
        char upchain[128];
        snprintf(upchain, sizeof(upchain), "%s_upnp", fw->table);
        snprintf(stmt, sizeof(stmt),
                 "add chain bridge %s %s { type filter hook %s priority -150 ; }", fw->table,
                 upchain, fw->upnp_input_hook);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);

        char dports[256];
        ports_csv(fw->upnp_ports, fw->n_upnp_ports, dports, sizeof(dports));
        for (int p = 0; p < 2; p++) {
            const char *proto = p == 0 ? "udp" : "tcp";
            char dp[300];
            if (dports[0])
                snprintf(dp, sizeof(dp), " %s dport { %s }", proto, dports);
            else
                dp[0] = '\0';
            if (fw->upnp_block_all) {
                snprintf(stmt, sizeof(stmt), "add set bridge %s %s_upnp_allow { type ether_addr ; }",
                         fw->table, fw->set);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
                snprintf(stmt, sizeof(stmt),
                         "add rule bridge %s %s ether type ip ip protocol %s ether saddr "
                         "@%s_upnp_allow%s accept",
                         fw->table, upchain, proto, fw->set, dp);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
                snprintf(stmt, sizeof(stmt),
                         "add rule bridge %s %s ether type ip ip protocol %s%s drop", fw->table,
                         upchain, proto, dp);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
                snprintf(stmt, sizeof(stmt),
                         "add rule bridge %s %s ether type ip6 meta l4proto %s ether saddr "
                         "@%s_upnp_allow%s accept",
                         fw->table, upchain, proto, fw->set, dp);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
                snprintf(stmt, sizeof(stmt),
                         "add rule bridge %s %s ether type ip6 meta l4proto %s%s drop", fw->table,
                         upchain, proto, dp);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
            } else {
                snprintf(stmt, sizeof(stmt), "add set bridge %s %s_upnp_macs { type ether_addr ; }",
                         fw->table, fw->set);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
                snprintf(stmt, sizeof(stmt),
                         "add rule bridge %s %s ether type ip ip protocol %s ether saddr "
                         "@%s_upnp_macs%s drop",
                         fw->table, upchain, proto, fw->set, dp);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
                snprintf(stmt, sizeof(stmt),
                         "add rule bridge %s %s ether type ip6 meta l4proto %s ether saddr "
                         "@%s_upnp_macs%s drop",
                         fw->table, upchain, proto, fw->set, dp);
                if (nft_run(fw, stmt, e, sizeof(e)) != 0)
                    log_warn("警告：nft 初始化语句失败（可能已存在）：%s", e);
            }
        }
    }
}

static int nft_element(firewall *fw, const char *verb, const char *setname, const char *elem)
{
    char stmt[512];
    char e[512];
    snprintf(stmt, sizeof(stmt), "%s element bridge %s %s { %s }", verb, fw->table, setname, elem);
    return nft_run(fw, stmt, e, sizeof(e));
}

static int nft_port_set(firewall *fw, bool ban, const char *mac, uint16_t port, const char *ip,
                        const char *proto)
{
    int nfam = 0;
    const char *const *fams = target_families(fw, ip, &nfam);
    int rc = 0;
    for (int i = 0; i < nfam; i++) {
        char setname[256];
        snprintf(setname, sizeof(setname), "%s_%s_%s", fw->set, fams[i], proto);
        char elem[128];
        if (ban && fw->ban_ttl_ns > 0) {
            snprintf(elem, sizeof(elem), "%s . %u timeout %llds", mac, port,
                     (long long)(fw->ban_ttl_ns / 1000000000LL));
        } else {
            snprintf(elem, sizeof(elem), "%s . %u", mac, port);
        }
        if (nft_element(fw, ban ? "add" : "delete", setname, elem) != 0)
            rc = -1;
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* 对外接口                                                            */
/* ------------------------------------------------------------------ */

firewall *firewall_create(const config_t *cfg, const upnp_filter *upf, char *err, size_t errlen)
{
    if (!firewall_validate_config(cfg, err, errlen))
        return NULL;

    firewall *fw = xcalloc(1, sizeof(*fw));
    fw->timeout_ms = cfg->firewall.timeout_ns > 0 ? (int)(cfg->firewall.timeout_ns / 1000000) : 5000;
    fw->ban_both = cfg->firewall.ban_both;
    fw->has_v6 = true;
    fw->hook_cmd = xstrdup(cfg->firewall.hook_cmd);
    fw->chain = xstrdup(str_empty(cfg->firewall.ipt_chain) ? DEFAULT_CHAIN
                                                           : cfg->firewall.ipt_chain);
    fw->ban_chain = xstrdup(str_empty(cfg->firewall.ipt_ban_chain)
                                ? DEFAULT_IPT_BAN_CHAIN
                                : cfg->firewall.ipt_ban_chain);
    fw->hook = trim_lower_dup(cfg->firewall.nft_hook);
    fw->table = xstrdup(str_empty(cfg->firewall.nft_table) ? DEFAULT_NFT_TABLE
                                                           : cfg->firewall.nft_table);
    fw->set = xstrdup(str_empty(cfg->firewall.nft_set) ? DEFAULT_NFT_SET : cfg->firewall.nft_set);
    fw->ban_ttl_ns = cfg->firewall.nft_ban_ttl_ns;
    if (fw->ban_ttl_ns < 0)
        fw->ban_ttl_ns = 0;
    if (fw->ban_ttl_ns > 0 && fw->ban_ttl_ns < 1000000000LL)
        fw->ban_ttl_ns = 1000000000LL;
    set_protos(fw, config_capture_proto(cfg));

    fw->full_ban = config_fullban_enabled(cfg);
    if (fw->full_ban) {
        if (!config_fullban_allow(cfg, &fw->fullban_allow, &fw->n_fullban_allow, err, errlen)) {
            firewall_free(fw);
            return NULL;
        }
        fw->fullban_hook = xstrdup(cfg->full_ban.hook_cmd);
    }
    fw->upnp = config_upnp_enabled(cfg);
    if (fw->upnp) {
        if (!config_upnp_ports(cfg, &fw->upnp_ports, &fw->n_upnp_ports, err, errlen)) {
            firewall_free(fw);
            return NULL;
        }
        fw->upnp_block_all = upf ? upf->block_all : false;
        fw->upnp_hook_cmd = xstrdup(cfg->upnp.hook_cmd);
    }

    char *backend = trim_lower_dup(cfg->firewall.backend);
    if (strcmp(backend, "hook") == 0) {
        fw->backend = FW_HOOK;
    } else if (strcmp(backend, "iptables") == 0) {
        fw->backend = FW_IPTABLES;
        fw->upnp_chain = xstrdup(str_empty(cfg->firewall.ipt_input_chain)
                                     ? DEFAULT_INPUT_CHAIN
                                     : cfg->firewall.ipt_input_chain);
        fw->upnp_rule_chain = xstrdup(str_empty(cfg->firewall.ipt_upnp_chain)
                                          ? DEFAULT_IPT_UPNP_CHAIN
                                          : cfg->firewall.ipt_upnp_chain);
        if (!command_exists("iptables")) {
            set_err(err, errlen, "未找到 iptables 命令");
            free(backend);
            firewall_free(fw);
            return NULL;
        }
        if (!command_exists("ip6tables")) {
            fw->has_v6 = false;
            log_warn("警告：未找到 ip6tables 命令，已忽略 IPv6 封禁；如已启用 ban_both，将只封禁 "
                     "IPv4");
        }
        setup_iptables(fw);
    } else if (strcmp(backend, "nftables") == 0) {
        fw->backend = FW_NFTABLES;
        char e[256];
        if (fw->hook[0] == '\0') {
            free(fw->hook);
            fw->hook = xstrdup("prerouting");
        }
        if (!nft_hook_valid(fw->hook)) {
            set_err(err, errlen, "nftables hook 无效 \"%s\"", fw->hook);
            free(backend);
            firewall_free(fw);
            return NULL;
        }
        if (strcmp(fw->hook, "prerouting") != 0)
            log_warn("警告：nftables hook = \"%s\" 非 prerouting；PCDN 属于三层路由流量（目的 "
                     "MAC 为路由器自身），仅 prerouting 能命中，其他钩子可能只覆盖二层桥接转发、"
                     "导致封禁失效",
                     fw->hook);
        if (fw->upnp) {
            char *ih = nft_hook_norm(cfg->firewall.nft_input_hook, "input", e, sizeof(e));
            if (!ih) {
                set_err(err, errlen, "%s", e);
                free(backend);
                firewall_free(fw);
                return NULL;
            }
            fw->upnp_input_hook = ih;
        }
        if (!command_exists("nft")) {
            set_err(err, errlen, "未找到 nft 命令");
            free(backend);
            firewall_free(fw);
            return NULL;
        }
        nft_setup(fw);
    } else {
        set_err(err, errlen, "firewall.backend 无效 \"%s\"（可选 hook / iptables / nftables）",
                cfg->firewall.backend ? cfg->firewall.backend : "");
        free(backend);
        firewall_free(fw);
        return NULL;
    }
    free(backend);
    return fw;
}

void firewall_free(firewall *fw)
{
    if (!fw)
        return;
    free(fw->hook_cmd);
    free(fw->chain);
    free(fw->ban_chain);
    free(fw->hook);
    free(fw->table);
    free(fw->set);
    free(fw->fullban_allow);
    free(fw->fullban_hook);
    free(fw->upnp_ports);
    free(fw->upnp_chain);
    free(fw->upnp_rule_chain);
    free(fw->upnp_input_hook);
    free(fw->upnp_hook_cmd);
    free(fw);
}

int firewall_ban(firewall *fw, const char *mac, const char *ip, uint16_t port,
                 const char *proto)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK) {
        int n = 0;
        const char *const *fams = target_families(fw, ip, &n);
        char first[512] = {0};
        int rc = 0;
        for (int i = 0; i < n; i++) {
            char *cmd = render_cmd(fw->hook_cmd, "ban", mac, ip, port, fams[i], proto);
            char *argv[] = {(char *)"sh", (char *)"-c", cmd, NULL};
            char e[512];
            if (run_command(argv, fw->timeout_ms, e, sizeof(e)) != 0) {
                if (rc == 0)
                    snprintf(first, sizeof(first), "%s", e);
                rc = -1;
            }
            free(cmd);
        }
        if (rc != 0)
            log_error("%s", first);
        return rc;
    }
    if (fw->backend == FW_IPTABLES)
        return ipt_set(fw, true, mac, port, ip, proto);
    return nft_port_set(fw, true, mac, port, ip, proto);
}

int firewall_unban(firewall *fw, const char *mac, const char *ip, uint16_t port,
                   const char *proto)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK) {
        int n = 0;
        const char *const *fams = target_families(fw, ip, &n);
        char first[512] = {0};
        int rc = 0;
        for (int i = 0; i < n; i++) {
            char *cmd = render_cmd(fw->hook_cmd, "unban", mac, ip, port, fams[i], proto);
            char *argv[] = {(char *)"sh", (char *)"-c", cmd, NULL};
            char e[512];
            if (run_command(argv, fw->timeout_ms, e, sizeof(e)) != 0) {
                if (rc == 0)
                    snprintf(first, sizeof(first), "%s", e);
                rc = -1;
            }
            free(cmd);
        }
        if (rc != 0)
            log_error("%s", first);
        return rc;
    }
    if (fw->backend == FW_IPTABLES)
        return ipt_set(fw, false, mac, port, ip, proto);
    return nft_port_set(fw, false, mac, port, ip, proto);
}

static int hook_full(firewall *fw, const char *action, const char *mac, const char *ip)
{
    char first[512] = {0};
    int rc = 0;
    const char *fams[2] = {"v4", "v6"};
    for (int i = 0; i < 2; i++) {
        char *cmd = render_full_cmd(fw->fullban_hook, action, mac, ip_for_family(ip, fams[i]),
                                    fams[i], fw->fullban_allow, fw->n_fullban_allow);
        char *argv[] = {(char *)"sh", (char *)"-c", cmd, NULL};
        char e[512];
        if (run_command(argv, fw->timeout_ms, e, sizeof(e)) != 0) {
            if (rc == 0)
                snprintf(first, sizeof(first), "%s", e);
            rc = -1;
        }
        free(cmd);
    }
    if (rc != 0)
        log_error("%s", first);
    return rc;
}

int firewall_full_ban(firewall *fw, const char *mac, const char *ip)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_full(fw, "ban", mac, ip);
    if (fw->backend == FW_IPTABLES)
        return ipt_full_ban(fw, true, mac);
    char elem[128];
    char setname[256];
    snprintf(setname, sizeof(setname), "%s_fullban_macs", fw->set);
    if (fw->ban_ttl_ns > 0) {
        snprintf(elem, sizeof(elem), "%s timeout %llds", mac,
                 (long long)(fw->ban_ttl_ns / 1000000000LL));
    } else {
        snprintf(elem, sizeof(elem), "%s", mac);
    }
    return nft_element(fw, "add", setname, elem);
}

int firewall_full_unban(firewall *fw, const char *mac, const char *ip)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_full(fw, "unban", mac, ip);
    if (fw->backend == FW_IPTABLES)
        return ipt_full_ban(fw, false, mac);
    char setname[256];
    snprintf(setname, sizeof(setname), "%s_fullban_macs", fw->set);
    return nft_element(fw, "delete", setname, mac);
}

static int hook_upnp(firewall *fw, const char *action, const char *mac, const char *ip)
{
    char first[512] = {0};
    int rc = 0;
    const char *fams[2] = {"v4", "v6"};
    for (int i = 0; i < 2; i++) {
        char *cmd = render_full_cmd(fw->upnp_hook_cmd, action, mac, ip_for_family(ip, fams[i]),
                                    fams[i], fw->upnp_ports, fw->n_upnp_ports);
        char *argv[] = {(char *)"sh", (char *)"-c", cmd, NULL};
        char e[512];
        if (run_command(argv, fw->timeout_ms, e, sizeof(e)) != 0) {
            if (rc == 0)
                snprintf(first, sizeof(first), "%s", e);
            rc = -1;
        }
        free(cmd);
    }
    if (rc != 0)
        log_error("%s", first);
    return rc;
}

int firewall_upnp_ban(firewall *fw, const char *mac, const char *ip)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_upnp(fw, "ban", mac, ip);
    if (fw->backend == FW_IPTABLES)
        return ipt_upnp_rules(fw, true, mac, "DROP");
    char setname[256];
    snprintf(setname, sizeof(setname), "%s_upnp_macs", fw->set);
    return nft_element(fw, "add", setname, mac);
}

int firewall_upnp_unban(firewall *fw, const char *mac, const char *ip)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_upnp(fw, "unban", mac, ip);
    if (fw->backend == FW_IPTABLES)
        return ipt_upnp_rules(fw, false, mac, "DROP");
    char setname[256];
    snprintf(setname, sizeof(setname), "%s_upnp_macs", fw->set);
    return nft_element(fw, "delete", setname, mac);
}

int firewall_upnp_block_all(firewall *fw)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_upnp(fw, "block-all", "", "");
    if (fw->backend == FW_IPTABLES)
        return ipt_upnp_rules(fw, true, "", "DROP");
    return 0;
}

int firewall_upnp_unblock_all(firewall *fw)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_upnp(fw, "unblock-all", "", "");
    if (fw->backend == FW_IPTABLES)
        return ipt_upnp_rules(fw, false, "", "DROP");
    return 0;
}

int firewall_upnp_allow(firewall *fw, const char *mac, const char *ip)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_upnp(fw, "allow", mac, ip);
    if (fw->backend == FW_IPTABLES)
        return ipt_upnp_rules(fw, true, mac, "ACCEPT");
    char setname[256];
    snprintf(setname, sizeof(setname), "%s_upnp_allow", fw->set);
    return nft_element(fw, "add", setname, mac);
}

int firewall_upnp_disallow(firewall *fw, const char *mac, const char *ip)
{
    if (!fw)
        return -1;
    if (fw->backend == FW_HOOK)
        return hook_upnp(fw, "disallow", mac, ip);
    if (fw->backend == FW_IPTABLES)
        return ipt_upnp_rules(fw, false, mac, "ACCEPT");
    char setname[256];
    snprintf(setname, sizeof(setname), "%s_upnp_allow", fw->set);
    return nft_element(fw, "delete", setname, mac);
}

void firewall_cleanup(firewall *fw)
{
    if (!fw)
        return;
    char e[512];
    if (fw->backend == FW_NFTABLES) {
        char stmt[512];
        snprintf(stmt, sizeof(stmt), "delete table bridge %s", fw->table);
        if (nft_run(fw, stmt, e, sizeof(e)) != 0)
            log_error("退出时清除 nftables 表 %s 失败：%s", fw->table, e);
        else
            log_info("退出时已清除 nftables 表 %s", fw->table);
    } else if (fw->backend == FW_IPTABLES) {
        for (int b = 0; b < 2; b++) {
            const char *bin = b == 0 ? "iptables" : "ip6tables";
            if (b == 1 && !fw->has_v6)
                continue;
            reset_ipt_chain(fw, bin, fw->chain, fw->ban_chain);
            if (fw->upnp_chain)
                reset_ipt_chain(fw, bin, fw->upnp_chain, fw->upnp_rule_chain);
        }
        log_info("退出时已清理 iptables 专用链 %s / %s", fw->ban_chain,
                 fw->upnp_rule_chain ? fw->upnp_rule_chain : "");
    }
}

void firewall_describe(const firewall *fw, char *buf, size_t cap)
{
    if (!fw) {
        if (cap) buf[0] = '\0';
        return;
    }
    char protos[16] = {0};
    for (int i = 0; i < fw->nprotos; i++) {
        if (i)
            strncat(protos, "/", sizeof(protos) - strlen(protos) - 1);
        strncat(protos, fw->protos[i], sizeof(protos) - strlen(protos) - 1);
    }
    for (char *p = protos; *p; p++)
        *p = (char)toupper((unsigned char)*p);
    const char *scope = fw->ban_both ? "同时封禁 v4/v6" : "按地址族单独封禁";
    strbuf sb;
    sb_init(&sb);
    if (fw->backend == FW_HOOK) {
        sb_addf(&sb, "自定义命令（hook，封禁 %s，%s）", protos, scope);
    } else if (fw->backend == FW_IPTABLES) {
        sb_addf(&sb, "iptables/ip6tables（%s → %s，按源 MAC + %s 源端口丢弃，%s）", fw->chain,
                fw->ban_chain, protos, scope);
        if (!fw->has_v6)
            sb_add(&sb, "；未找到 ip6tables，已忽略 IPv6");
    } else {
        sb_addf(&sb,
                "nftables（bridge %s 表，%s 钩子，集合 %s_v4/%s_v6，按源 MAC + %s 源端口丢弃，"
                "%s）",
                fw->table, fw->hook, fw->set, fw->set, protos, scope);
    }
    if (fw->full_ban) {
        char ports[256];
        ports_csv(fw->fullban_allow, fw->n_fullban_allow, ports, sizeof(ports));
        sb_addf(&sb, "；全 UDP 端口封禁已启用（放行端口：%s）", ports);
    }
    if (fw->upnp) {
        char ports[256];
        ports_csv(fw->upnp_ports, fw->n_upnp_ports, ports, sizeof(ports));
        const char *scope2 = fw->upnp_block_all ? "拦截全部 + 放行名单" : "仅拦截名单设备";
        const char *loc = fw->backend == FW_IPTABLES
                              ? "链"
                              : (fw->backend == FW_NFTABLES ? "钩子" : "hook 命令");
        const char *locname = fw->backend == FW_IPTABLES
                                  ? fw->upnp_chain
                                  : (fw->backend == FW_NFTABLES ? fw->upnp_input_hook : "");
        sb_addf(&sb, "；UPnP 拦截已启用（目的端口：%s，%s %s，%s）", ports, loc,
                locname ? locname : "", scope2);
    }
    snprintf(buf, cap, "%s", sb.p ? sb.p : "");
    sb_free(&sb);
}

bool firewall_ban_both(const firewall *fw)
{
    return fw && fw->ban_both;
}

int64_t firewall_ban_ttl(const firewall *fw)
{
    return fw ? fw->ban_ttl_ns : 0;
}

bool firewall_fullban_enabled(const firewall *fw)
{
    return fw && fw->full_ban;
}

const uint16_t *firewall_fullban_allow_ports(const firewall *fw, size_t *n)
{
    if (!fw) {
        *n = 0;
        return NULL;
    }
    *n = fw->n_fullban_allow;
    return fw->fullban_allow;
}

bool firewall_upnp_enabled(const firewall *fw)
{
    return fw && fw->upnp;
}

const uint16_t *firewall_upnp_ports(const firewall *fw, size_t *n)
{
    if (!fw) {
        *n = 0;
        return NULL;
    }
    *n = fw->n_upnp_ports;
    return fw->upnp_ports;
}
