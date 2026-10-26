/* config.h —— TOML 配置结构、默认值、加载与校验 */
#ifndef PCDN_CONFIG_H
#define PCDN_CONFIG_H

#include "common.h"

typedef struct {
    bool is_str;   /* true：表达式字符串；false：整数端口 */
    int64_t ival;
    char *sval;
} port_item;

typedef struct {
    char *mac;
    port_item *ports;
    size_t nports;
    bool enabled;  /* 缺省 true */
    bool full_ban;
    bool upnp;
} list_entry;

typedef struct {
    int threshold;
    int64_t window;
    int64_t alert_duration;
    int64_t interval;
} detect_cfg;

typedef struct {
    char *iface;
    bool promisc;
    int frame_size;
    int block_size;
    int num_blocks;
    int snaplen;
    char *protocol;
} capture_cfg;

typedef struct {
    char *memory_limit;
    bool has_gc_percent;
    int gc_percent;
    bool low_memory;
    bool has_peer_limit;
    int peer_limit;
    bool has_max_ports;
    int max_ports;
} memory_cfg;

typedef struct {
    char *level;
    char *timezone;
    bool hide_address;
} log_cfg;

typedef struct {
    bool enabled;
    char *listen;
    char *token;
    bool has_device_ip_limit;
    int device_ip_limit;
    char *state_dir;
    char **cors_origins;
    size_t ncors;
    bool cors_allow_credentials;
    bool has_cors_max_age;
    int cors_max_age;
} http_cfg;

typedef struct {
    char *list_mode;
    list_entry *blacklist;
    size_t nblack;
    list_entry *whitelist;
    size_t nwhite;
} filter_cfg;

typedef struct {
    bool enabled;
    char *backend;
    bool ban_both;
    bool ban_active_alerts;
    int64_t timeout_ns;
    char *hook_cmd;
    char *ipt_chain;
    char *ipt_input_chain;
    char *ipt_ban_chain;
    char *ipt_upnp_chain;
    char *nft_table;
    char *nft_set;
    char *nft_hook;
    char *nft_input_hook;
    int64_t nft_ban_ttl_ns;
} firewall_cfg;

typedef struct {
    char *mode;
    int threshold;
    port_item *allow;
    size_t nallow;
    char *hook_cmd;
} fullban_cfg;

typedef struct {
    char *mode;
    port_item *ports;
    size_t nports;
    char *hook_cmd;
} upnp_cfg;

typedef struct {
    detect_cfg detect;
    capture_cfg capture;
    memory_cfg memory;
    log_cfg log;
    http_cfg http;
    filter_cfg filter;
    firewall_cfg firewall;
    fullban_cfg full_ban;
    upnp_cfg upnp;
} config_t;

typedef struct {
    config_t cfg;
    char *path;
    bool created;
    char **warnings;
    size_t nwarnings;
} config_result;

void config_result_free(config_result *res);

void config_default(config_t *cfg);
void config_free(config_t *cfg);
void config_apply_defaults(config_t *cfg);
bool config_parse(const char *data, size_t len, config_t *cfg, char *err, size_t errlen);

/* strict：不自动创建默认配置（--test-config 使用） */
bool config_load(config_t *cfg, const char *explicit_path, bool has_explicit, bool strict,
                 config_result *res, char *err, size_t errlen);
bool config_write_default(const char *dir, char *path, size_t pathcap, char *err,
                          size_t errlen);
bool config_validate(const config_t *cfg, char *err, size_t errlen);
/* 仅校验 [http]（httpapi 启动时使用） */
bool config_validate_http(const config_t *cfg, char *err, size_t errlen);

/* 生效值 */
const char *config_capture_proto(const config_t *cfg);
const char *config_capture_proto_label(const config_t *cfg);
void config_ring_params(const config_t *cfg, int *frame, int *block, int *blocks);
int config_snaplen_value(const config_t *cfg);
int config_peer_limit_value(const config_t *cfg);
int config_max_ports_value(const config_t *cfg);
int config_device_ip_limit(const config_t *cfg);
int config_cors_max_age(const config_t *cfg);
const char *config_http_listen(const config_t *cfg);
bool config_http_no_token(const config_t *cfg);
const char *config_http_bearer_token(const config_t *cfg);
char *config_state_file_path(const config_t *cfg);
bool config_ban_both(const config_t *cfg);
bool config_fullban_enabled(const config_t *cfg);
bool config_upnp_enabled(const config_t *cfg);
int config_fullban_threshold(const config_t *cfg);

/* 名单与端口 */
bool config_parse_port_items(const port_item *items, size_t n, uint16_t **out, size_t *nout,
                             char *err, size_t errlen);
bool config_fullban_allow(const config_t *cfg, uint16_t **out, size_t *n, char *err,
                          size_t errlen);
bool config_upnp_ports(const config_t *cfg, uint16_t **out, size_t *n, char *err,
                       size_t errlen);
bool config_fullban_devices(const config_t *cfg, char ***out, size_t *n, char *err,
                            size_t errlen);
bool config_list_entries(const config_t *cfg, char ***black, size_t *nblack, char ***white,
                         size_t *nwhite, char *err, size_t errlen);
bool config_blacklist_port_warnings(const config_t *cfg, char ***macs, size_t *n, char *err,
                                    size_t errlen);

typedef struct {
    bool block_all;
    char **devices;
    size_t ndevices;
} upnp_filter;

void upnp_filter_free(upnp_filter *f);
bool config_upnp_filter_value(const config_t *cfg, upnp_filter *out, char *err, size_t errlen);

/* reload 比较 */
bool config_capture_equal(const capture_cfg *a, const capture_cfg *b);
bool config_detect_equal(const detect_cfg *a, const detect_cfg *b);
bool config_filter_equal(const filter_cfg *a, const filter_cfg *b);
bool config_firewall_equal(const config_t *a, const config_t *b);
bool config_http_cors_equal(const config_t *a, const config_t *b);

extern const char *const config_template;

#endif
