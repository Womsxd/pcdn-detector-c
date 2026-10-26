/* http.h —— 极简 HTTP/1.1 服务端（picohttpparser 解析请求） */
#ifndef PCDN_HTTP_H
#define PCDN_HTTP_H

#include "common.h"

typedef struct {
    char method[16];
    const char *path; /* buf 内的路径（不含查询串） */
    size_t path_len;
    const char *query; /* 原始查询串 */
    size_t query_len;
    const char *headers[64];
    const char *values[64];
    size_t nheaders;
    const char *body;
    size_t body_len;
} http_request;

typedef struct {
    int status;
    char content_type[128];
    strbuf body;
    strbuf headers;
} http_response;

typedef void (*http_handler_fn)(void *ctx, const http_request *req, http_response *res);

typedef struct http_server http_server;

http_server *http_server_create(const char *listen_addr, http_handler_fn handler, void *ctx,
                                char *err, size_t errlen);
int http_server_start(http_server *s, char *err, size_t errlen);
void http_server_stop(http_server *s);
void http_server_free(http_server *s);
const char *http_server_addr(const http_server *s);
/* 当前线程是否正在处理某个 HTTP 请求（用于避免在请求线程里停止并等待自身） */
bool http_server_in_callback(void);

void http_response_init(http_response *res);
void http_response_free(http_response *res);
void http_response_set_body(http_response *res, int status, const char *content_type,
                            const char *body, size_t len);
void http_response_add_header(http_response *res, const char *name, const char *value);

const char *http_request_header(const http_request *req, const char *name);
bool http_request_query(const http_request *req, const char *name, char *out, size_t cap);

#endif
