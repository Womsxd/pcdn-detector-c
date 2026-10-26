/* httpapi.h —— HTTP API：运行时状态、手动解封、重载配置 */
#ifndef PCDN_HTTPAPI_H
#define PCDN_HTTPAPI_H

#include "blocker.h"
#include "config.h"
#include "detector.h"

typedef struct {
    char **applied;
    size_t napplied;
    char **restart_required;
    size_t nrestart;
    bool restarting;
} reload_result;

void reload_result_free(reload_result *r);

typedef int (*reload_fn)(void *ctx, reload_result *res, char *err, size_t errlen);

typedef struct httpapi httpapi;

httpapi *httpapi_create(detector *det, blocker *blk, const config_t *cfg, reload_fn fn,
                        void *fn_ctx, char *err, size_t errlen);
int httpapi_start(httpapi *a, char *err, size_t errlen);
void httpapi_stop(httpapi *a);
void httpapi_free(httpapi *a);

void httpapi_set_blocker(httpapi *a, blocker *blk);
void httpapi_set_token(httpapi *a, const char *token);
void httpapi_set_ip_limit(httpapi *a, int limit);
void httpapi_set_cors(httpapi *a, char **origins, size_t n, bool allow_credentials, int max_age);

#endif
