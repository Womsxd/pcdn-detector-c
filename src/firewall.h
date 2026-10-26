/* firewall.h —— hook / iptables / nftables 三种封禁后端 */
#ifndef PCDN_FIREWALL_H
#define PCDN_FIREWALL_H

#include "config.h"

typedef struct firewall firewall;

/* 纯配置校验：不执行命令、不访问系统（reload 预检 / --test-config 共用） */
bool firewall_validate_config(const config_t *cfg, char *err, size_t errlen);

/* 构建后端并完成初始化（iptables/nftables 会创建链/表） */
firewall *firewall_create(const config_t *cfg, const upnp_filter *upf, char *err, size_t errlen);

void firewall_free(firewall *fw);
void firewall_cleanup(firewall *fw);
void firewall_describe(const firewall *fw, char *buf, size_t cap);

int firewall_ban(firewall *fw, const char *mac, const char *ip, uint16_t port,
                 const char *proto);
int firewall_unban(firewall *fw, const char *mac, const char *ip, uint16_t port,
                   const char *proto);
int firewall_full_ban(firewall *fw, const char *mac, const char *ip);
int firewall_full_unban(firewall *fw, const char *mac, const char *ip);
int firewall_upnp_ban(firewall *fw, const char *mac, const char *ip);
int firewall_upnp_unban(firewall *fw, const char *mac, const char *ip);
int firewall_upnp_block_all(firewall *fw);
int firewall_upnp_unblock_all(firewall *fw);
int firewall_upnp_allow(firewall *fw, const char *mac, const char *ip);
int firewall_upnp_disallow(firewall *fw, const char *mac, const char *ip);

bool firewall_ban_both(const firewall *fw);
int64_t firewall_ban_ttl(const firewall *fw);
bool firewall_fullban_enabled(const firewall *fw);
const uint16_t *firewall_fullban_allow_ports(const firewall *fw, size_t *n);
bool firewall_upnp_enabled(const firewall *fw);
const uint16_t *firewall_upnp_ports(const firewall *fw, size_t *n);
const char *firewall_addr_family(const char *ip);

#endif
