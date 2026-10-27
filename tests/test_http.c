/* HTTP API 集成测试：启动真实监听并用 curl 验证鉴权 / CORS / 路由 */
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "detector.h"
#include "httpapi.h"
#include "util.h"

static int g_fail;

#define CHECK(cond)                                                                            \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
            g_fail++;                                                                          \
        }                                                                                      \
    } while (0)

static atomic_int g_reload_calls;

static int reload_stub(void *ctx, reload_result *res, char *err, size_t errlen)
{
    (void)ctx;
    (void)err;
    (void)errlen;
    atomic_fetch_add(&g_reload_calls, 1);
    res->applied = xmalloc(sizeof(char *));
    res->applied[0] = xstrdup("detect");
    res->napplied = 1;
    return 0;
}

static int run_curl(const char *args, char *body, size_t bodycap, char *headers,
                    size_t headcap, int *status)
{
    char bodypath[128], headpath[128];
    snprintf(bodypath, sizeof(bodypath), "/tmp/pcdn-http-body-%d", (int)getpid());
    snprintf(headpath, sizeof(headpath), "/tmp/pcdn-http-head-%d", (int)getpid());
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "curl -s --max-time 5 -o %s -D %s -w '%%{http_code}' %s > /tmp/pcdn-http-code-%d",
             bodypath, headpath, args, (int)getpid());
    int rc = system(cmd);
    (void)rc;
    char codepath[128];
    snprintf(codepath, sizeof(codepath), "/tmp/pcdn-http-code-%d", (int)getpid());
    FILE *f = fopen(codepath, "r");
    *status = 0;
    if (f) {
        if (fscanf(f, "%d", status) != 1)
            *status = 0;
        fclose(f);
    }
    body[0] = '\0';
    f = fopen(bodypath, "r");
    if (f) {
        size_t n = fread(body, 1, bodycap - 1, f);
        body[n] = '\0';
        fclose(f);
    }
    headers[0] = '\0';
    f = fopen(headpath, "r");
    if (f) {
        size_t n = fread(headers, 1, headcap - 1, f);
        headers[n] = '\0';
        fclose(f);
    }
    unlink(bodypath);
    unlink(headpath);
    unlink(codepath);
    return 0;
}

int main(void)
{
    log_set_level(LOG_ERROR);
    const char *toml =
        "[capture]\n"
        "interface = \"lo\"\n"
        "[http]\n"
        "enabled = true\n"
        "listen = \"127.0.0.1:18081\"\n"
        "token = \"secret\"\n"
        "device_ip_limit = 50\n"
        "cors_allowed_origins = [\"https://x.example\"]\n"
        "cors_max_age = 60\n";
    config_t cfg;
    char err[1024];
    if (!config_parse(toml, strlen(toml), &cfg, err, sizeof(err)) ||
        !config_validate(&cfg, err, sizeof(err))) {
        fprintf(stderr, "config error: %s\n", err);
        return 1;
    }
    detector *det = detector_create(20, 60000000000LL, 600000000000LL, NULL, false, false, 1000,
                                    512);
    pcdn_mac dmac;
    pcdn_ip dip, r1, r2, r3, r6;
    char perr[128];
    mac_parse("aa:bb:cc:dd:ee:ff", &dmac, perr, sizeof(perr));
    ip_parse("192.168.1.10", &dip, perr, sizeof(perr));
    ip_parse("1.1.1.1", &r1, perr, sizeof(perr));
    ip_parse("2.2.2.2", &r2, perr, sizeof(perr));
    ip_parse("3.3.3.3", &r3, perr, sizeof(perr));
    ip_parse("2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", &r6, perr, sizeof(perr));
    observation o1 = {.mac = dmac, .ip = dip, .local_port = 40000, .remote_ip = r1,
                      .up = true, .v6 = false, .proto = 17, .length = 100,
                      .ts_ns = now_ns()};
    observation o2 = o1;
    o2.remote_ip = r2;
    observation o3 = {.mac = dmac, .ip = dip, .local_port = 40001, .remote_ip = r3,
                      .up = false, .v6 = false, .proto = 6, .length = 200,
                      .ts_ns = now_ns()};
    observation o4 = {.mac = dmac, .ip = dip, .local_port = 40002, .remote_ip = r6,
                      .up = true, .v6 = true, .proto = 17, .length = 300,
                      .ts_ns = now_ns()};
    detector_observe(det, &o1);
    detector_observe(det, &o2);
    detector_observe(det, &o3);
    detector_observe(det, &o4);

    httpapi *api = httpapi_create(det, NULL, &cfg, reload_stub, NULL, err, sizeof(err));
    if (!api) {
        fprintf(stderr, "httpapi_create: %s\n", err);
        return 1;
    }
    if (httpapi_start(api, err, sizeof(err)) != 0) {
        fprintf(stderr, "httpapi_start: %s\n", err);
        return 1;
    }
    usleep(200000);

    char body[8192], headers[8192];
    int status = 0;

    run_curl("http://127.0.0.1:18081/api/v1/health", body, sizeof(body), headers,
             sizeof(headers), &status);
    CHECK(status == 401);
    CHECK(strstr(body, "未授权") != NULL);

    run_curl("-H 'Authorization: Bearer wrong' http://127.0.0.1:18081/api/v1/health", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 401);

    run_curl("-H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/health", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "\"status\":\"ok\"") != NULL);
    CHECK(strstr(headers, "Content-Type: application/json") != NULL);

    run_curl("-I -H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/health", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(headers, "Content-Length:") != NULL);

    run_curl("-H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/status", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "tracked_devices") != NULL);
    CHECK(strstr(body, "active_bans") != NULL);

    run_curl("-H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/devices", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "\"mac\":\"aa:bb:cc:dd:ee:ff\"") != NULL);
    CHECK(strstr(body, "\"ports\":2") != NULL);

    run_curl("-H 'Authorization: Bearer secret' "
             "'http://127.0.0.1:18081/api/v1/device?mac=aa:bb:cc:dd:ee:ff&family=v4'",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "\"matched\":2") != NULL);
    CHECK(strstr(body, "\"port\":40000") != NULL);
    CHECK(strstr(body, "\"banned\":false") != NULL);

    run_curl("-H 'Authorization: Bearer secret' "
             "'http://127.0.0.1:18081/api/v1/peers?mac=aa:bb:cc:dd:ee:ff&port=40000'",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "\"peer_count\":2") != NULL);
    CHECK(strstr(body, "\"1.1.1.1\"") != NULL);
    CHECK(strstr(body, "\"2.2.2.2\"") != NULL);

    run_curl("-H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/blocks", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "\"bans\":[]") != NULL);

    run_curl("-H 'Authorization: Bearer secret' http://127.0.0.1:18081/dev/memory", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "rss_bytes") != NULL);
    CHECK(strstr(body, "version") != NULL);

    run_curl("-H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/nope", body,
             sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 404);

    run_curl("-X POST -H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/health",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 405);
    CHECK(strstr(headers, "Allow:") != NULL);

    run_curl("-X POST -H 'Authorization: Bearer secret' -d '{\"mac\":\"aa:bb:cc:dd:ee:ff\","
             "\"port\":1}' http://127.0.0.1:18081/api/v1/unban",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 503);

    run_curl("-X POST -H 'Authorization: Bearer secret' -d '{\"mac\":\"bad\",\"port\":1}' "
             "http://127.0.0.1:18081/api/v1/unban",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 503);

    run_curl("-X POST -H 'Authorization: Bearer secret' http://127.0.0.1:18081/api/v1/reload",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 200);
    CHECK(strstr(body, "\"applied\":[\"detect\"]") != NULL);
    CHECK(atomic_load(&g_reload_calls) == 1);

    /* CORS 预检不需要 Authorization */
    run_curl("-X OPTIONS -H 'Origin: https://x.example' -H 'Access-Control-Request-Method: GET' "
             "http://127.0.0.1:18081/api/v1/health",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 204);
    CHECK(strstr(headers, "Access-Control-Allow-Origin: https://x.example") != NULL);
    CHECK(strstr(headers, "Access-Control-Allow-Methods: GET, HEAD") != NULL);
    CHECK(strstr(headers, "Access-Control-Max-Age: 60") != NULL);

    run_curl("-X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: "
             "GET' http://127.0.0.1:18081/api/v1/health",
             body, sizeof(body), headers, sizeof(headers), &status);
    CHECK(status == 204);
    CHECK(strstr(headers, "Access-Control-Allow-Origin") == NULL);

    httpapi_stop(api);
    httpapi_free(api);
    detector_destroy(det);
    config_free(&cfg);

    if (g_fail) {
        fprintf(stderr, "%d 项检查失败\n", g_fail);
        return 1;
    }
    printf("test_http: OK\n");
    return 0;
}
