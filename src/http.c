#include "http.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "picohttpparser.h"
#include "util.h"

#define MAX_HEADER 16384
#define MAX_BODY (1024 * 1024)
#define MAX_REQUEST_LINE 4096
#define HEADER_TIMEOUT_MS 5000
#define IDLE_TIMEOUT_MS 30000
#define WRITE_TIMEOUT_MS 10000
#define MAX_HEADERS 64

struct http_server {
    int listen_fd;
    char *addr;
    http_handler_fn handler;
    void *ctx;
    pthread_t thread;
    bool started;
    atomic_bool stopping;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    int active;
    int *clients;
    size_t nclients;
    size_t capclients;
};

static _Thread_local http_server *tls_server;

bool http_server_in_callback(void)
{
    return tls_server != NULL;
}

static const char *status_text(int code)
{
    switch (code) {
    case 200:
        return "OK";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 404:
        return "Not Found";
    case 408:
        return "Request Timeout";
    case 405:
        return "Method Not Allowed";
    case 413:
        return "Payload Too Large";
    case 414:
        return "URI Too Long";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 503:
        return "Service Unavailable";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "OK";
    }
}

void http_response_init(http_response *res)
{
    memset(res, 0, sizeof(*res));
    res->status = 200;
    res->trailing_newline = false;
    snprintf(res->content_type, sizeof(res->content_type), "application/json; charset=utf-8");
    sb_init(&res->body);
    sb_init(&res->headers);
}

void http_response_free(http_response *res)
{
    if (!res)
        return;
    sb_free(&res->body);
    sb_free(&res->headers);
}

void http_response_set_body(http_response *res, int status, const char *content_type,
                            const char *body, size_t len)
{
    res->status = status;
    res->trailing_newline = false;
    if (content_type)
        snprintf(res->content_type, sizeof(res->content_type), "%s", content_type);
    sb_reset(&res->body);
    sb_addn(&res->body, body ? body : "", len);
}

void http_response_add_header(http_response *res, const char *name, const char *value)
{
    sb_addf(&res->headers, "%s: %s\r\n", name, value);
}

const char *http_request_header(const http_request *req, const char *name)
{
    size_t n = strlen(name);
    for (size_t i = 0; i < req->nheaders; i++) {
        const char *h = req->headers[i];
        size_t hl = strlen(h);
        if (hl != n)
            continue;
        bool eq = true;
        for (size_t k = 0; k < n; k++) {
            if (tolower((unsigned char)h[k]) != tolower((unsigned char)name[k])) {
                eq = false;
                break;
            }
        }
        if (eq)
            return req->values[i];
    }
    return NULL;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void url_decode(const char *s, size_t n, char *out, size_t cap)
{
    size_t j = 0;
    for (size_t i = 0; i < n && j + 1 < cap; i++) {
        if (s[i] == '+') {
            out[j++] = ' ';
        } else if (s[i] == '%' && i + 2 < n) {
            int hi = hexval((unsigned char)s[i + 1]);
            int lo = hexval((unsigned char)s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out[j++] = (char)((hi << 4) | lo);
                i += 2;
            } else {
                out[j++] = s[i];
            }
        } else {
            out[j++] = s[i];
        }
    }
    out[j] = '\0';
}

bool http_request_query(const http_request *req, const char *name, char *out, size_t cap)
{
    if (!req->query || req->query_len == 0)
        return false;
    const char *p = req->query;
    const char *end = p + req->query_len;
    while (p < end) {
        const char *amp = memchr(p, '&', (size_t)(end - p));
        const char *seg_end = amp ? amp : end;
        const char *eq = memchr(p, '=', (size_t)(seg_end - p));
        const char *kend = eq ? eq : seg_end;
        char key[128];
        url_decode(p, (size_t)(kend - p), key, sizeof(key));
        if (strcmp(key, name) == 0) {
            char val[512];
            if (eq)
                url_decode(eq + 1, (size_t)(seg_end - eq - 1), val, sizeof(val));
            else
                val[0] = '\0';
            snprintf(out, cap, "%s", val);
            return true;
        }
        p = amp ? amp + 1 : end;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* 读写                                                                */
/* ------------------------------------------------------------------ */

static ssize_t read_deadline(int fd, void *buf, size_t cap, int64_t deadline)
{
    for (;;) {
        int64_t remain = deadline - mono_ms();
        if (remain <= 0)
            return -2;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, (int)(remain > 1000 ? 1000 : remain));
        if (pr == 0)
            continue;
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ssize_t n = recv(fd, buf, cap, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        return n;
    }
}

static bool send_all_deadline(int fd, const char *buf, size_t n, int64_t deadline)
{
    size_t off = 0;
    while (off < n) {
        int64_t remain = deadline - mono_ms();
        if (remain <= 0)
            return false;
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, (int)(remain > 1000 ? 1000 : remain));
        if (pr == 0)
            continue;
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        ssize_t w = send(fd, buf + off, n - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return false;
        }
        off += (size_t)w;
    }
    return true;
}

static void send_simple_error(int fd, int code, const char *msg, bool close_conn)
{
    char body[512];
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", msg);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json; charset=utf-8\r\n"
                     "Content-Length: %zu\r\nConnection: %s\r\n\r\n%s",
                     code, status_text(code), strlen(body), close_conn ? "close" : "keep-alive",
                     body);
    if (n > 0)
        send_all_deadline(fd, buf, (size_t)n, mono_ms() + 5000);
}

/* ------------------------------------------------------------------ */
/* 服务端                                                              */
/* ------------------------------------------------------------------ */

static bool split_listen(const char *addr, char *host, size_t hostcap, char *port,
                         size_t portcap)
{
    const char *p = addr;
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end)
            return false;
        size_t n = (size_t)(end - p - 1);
        if (n >= hostcap)
            return false;
        memcpy(host, p + 1, n);
        host[n] = '\0';
        if (end[1] != ':')
            return false;
        snprintf(port, portcap, "%s", end + 2);
        return true;
    }
    const char *colon = strrchr(p, ':');
    if (!colon)
        return false;
    size_t n = (size_t)(colon - p);
    if (n >= hostcap)
        return false;
    memcpy(host, p, n);
    host[n] = '\0';
    snprintf(port, portcap, "%s", colon + 1);
    return true;
}

http_server *http_server_create(const char *listen_addr, http_handler_fn handler, void *ctx,
                                char *err, size_t errlen)
{
    char host[256], port[32];
    if (!listen_addr || !split_listen(listen_addr, host, sizeof(host), port, sizeof(port))) {
        set_err(err, errlen, "listen 无效（应为 host:port）：%s", listen_addr ? listen_addr : "");
        return NULL;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
    if (rc != 0) {
        set_err(err, errlen, "解析监听地址 %s 失败：%s", listen_addr, gai_strerror(rc));
        return NULL;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0)
            continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 128) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        set_err(err, errlen, "监听 %s 失败：%s", listen_addr, strerror(errno));
        return NULL;
    }

    http_server *s = xcalloc(1, sizeof(*s));
    s->listen_fd = fd;
    s->addr = xstrdup(listen_addr);
    s->handler = handler;
    s->ctx = ctx;
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cond, NULL);
    atomic_init(&s->stopping, false);
    return s;
}

const char *http_server_addr(const http_server *s)
{
    return s ? s->addr : "";
}

static void client_add(http_server *s, int fd)
{
    pthread_mutex_lock(&s->mu);
    if (s->nclients == s->capclients) {
        s->capclients = s->capclients ? s->capclients * 2 : 8;
        s->clients = xrealloc(s->clients, s->capclients * sizeof(int));
    }
    s->clients[s->nclients++] = fd;
    s->active++;
    pthread_mutex_unlock(&s->mu);
}

static void client_remove(http_server *s, int fd)
{
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->nclients; i++) {
        if (s->clients[i] == fd) {
            s->clients[i] = s->clients[s->nclients - 1];
            s->nclients--;
            break;
        }
    }
    s->active--;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->mu);
}

static void write_response(int fd, const http_response *res, bool head_only, bool keep_alive)
{
    char date[64];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);

    size_t body_len = res->body.n + (res->trailing_newline ? 1u : 0u);
    char head[1024];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\nDate: %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Connection: %s\r\n",
                     res->status, status_text(res->status), date,
                     res->content_type[0] ? res->content_type : "application/octet-stream",
                     body_len, keep_alive ? "keep-alive" : "close");
    if (n < 0)
        return;
    int64_t deadline = mono_ms() + WRITE_TIMEOUT_MS;
    if (!send_all_deadline(fd, head, (size_t)n, deadline))
        return;
    if (res->headers.n > 0 && !send_all_deadline(fd, res->headers.p, res->headers.n, deadline))
        return;
    if (!send_all_deadline(fd, "\r\n", 2, deadline))
        return;
    if (head_only)
        return;
    if (res->body.n > 0 && !send_all_deadline(fd, res->body.p, res->body.n, deadline))
        return;
    if (res->trailing_newline)
        send_all_deadline(fd, "\n", 1, deadline);
}

typedef struct {
    http_server *s;
    int fd;
} conn_arg;

static void *conn_main(void *arg)
{
    conn_arg *ca = arg;
    http_server *s = ca->s;
    int fd = ca->fd;
    free(ca);

    struct timeval snd_tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv));

    char *buf = xmalloc(MAX_HEADER + 1);
    bool first = true;
    for (;;) {
        if (atomic_load(&s->stopping))
            break;
        size_t len = 0;
        int pret = -2;
        const char *method = NULL, *path = NULL;
        size_t method_len = 0, path_len = 0;
        int minor = 0;
        struct phr_header headers[MAX_HEADERS];
        size_t nheaders = 0;
        int64_t deadline = mono_ms() + (first ? HEADER_TIMEOUT_MS : IDLE_TIMEOUT_MS);

        while (pret == -2) {
            if (len >= MAX_HEADER) {
                send_simple_error(fd, 431, "请求头过大", true);
                goto done;
            }
            ssize_t n = read_deadline(fd, buf + len, MAX_HEADER - len, deadline);
            if (n == -2) {
                if (len == 0)
                    goto done;
                send_simple_error(fd, 408, "读取请求超时", true);
                goto done;
            }
            if (n <= 0)
                goto done;
            len += (size_t)n;
            buf[len] = '\0';
            nheaders = MAX_HEADERS;
            pret = phr_parse_request(buf, len, &method, &method_len, &path, &path_len, &minor,
                                     headers, &nheaders, 0);
        }
        first = false;
        if (pret < 0) {
            send_simple_error(fd, 400, "请求格式错误", true);
            goto done;
        }
        if (minor > 1) {
            send_simple_error(fd, 505, "不支持的 HTTP 版本", true);
            goto done;
        }

        /* 请求行长度限制 */
        const char *eol = memmem(buf, len, "\r\n", 2);
        if (!eol || (size_t)(eol - buf) > MAX_REQUEST_LINE) {
            send_simple_error(fd, 414, "请求行过长", true);
            goto done;
        }

        http_request req;
        memset(&req, 0, sizeof(req));
        size_t mlen = method_len < sizeof(req.method) - 1 ? method_len : sizeof(req.method) - 1;
        memcpy(req.method, method, mlen);
        req.method[mlen] = '\0';
        char *pathbuf = (char *)path;
        size_t plen = path_len;
        char *qmark = memchr(pathbuf, '?', plen);
        if (qmark) {
            req.query = qmark + 1;
            req.query_len = plen - (size_t)(qmark - pathbuf) - 1;
            plen = (size_t)(qmark - pathbuf);
        }
        pathbuf[plen] = '\0';
        req.path = pathbuf;
        req.path_len = plen;
        for (size_t i = 0; i < nheaders && req.nheaders < 64; i++) {
            if (!headers[i].name)
                continue;
            /* pico 返回的是缓冲区内的切片：就地补 NUL，后续可直接当 C 字符串使用 */
            char *namep = (char *)headers[i].name;
            char *valuep = (char *)headers[i].value;
            namep[headers[i].name_len] = '\0';
            valuep[headers[i].value_len] = '\0';
            char name[128];
            size_t nl = headers[i].name_len < sizeof(name) - 1 ? headers[i].name_len
                                                               : sizeof(name) - 1;
            memcpy(name, namep, nl);
            name[nl] = '\0';
            char value[1024];
            size_t vl = headers[i].value_len < sizeof(value) - 1 ? headers[i].value_len
                                                                 : sizeof(value) - 1;
            memcpy(value, valuep, vl);
            value[vl] = '\0';
            if (strcasecmp(name, "transfer-encoding") == 0) {
                send_simple_error(fd, 501, "不支持 Transfer-Encoding", true);
                goto done;
            }
            if (strcasecmp(name, "content-length") == 0) {
                char *end = NULL;
                errno = 0;
                long long cl = strtoll(value, &end, 10);
                if (errno != 0 || end == value || *end != '\0' || cl < 0) {
                    send_simple_error(fd, 400, "Content-Length 无效", true);
                    goto done;
                }
                if (cl > MAX_BODY) {
                    send_simple_error(fd, 413, "请求体过大", true);
                    goto done;
                }
                req.body_len = (size_t)cl;
            }
            /* 头名与头值在请求存活期间有效（指向 buf） */
            req.headers[req.nheaders] = headers[i].name;
            req.values[req.nheaders] = headers[i].value;
            req.nheaders++;
        }

        size_t have = len - (size_t)pret;
        char *body = NULL;
        if (req.body_len > 0) {
            body = xmalloc(req.body_len);
            size_t copy = have < req.body_len ? have : req.body_len;
            memcpy(body, buf + pret, copy);
            size_t got = copy;
            int64_t bdeadline = mono_ms() + HEADER_TIMEOUT_MS;
            while (got < req.body_len) {
                ssize_t n = read_deadline(fd, body + got, req.body_len - got, bdeadline);
                if (n <= 0) {
                    free(body);
                    send_simple_error(fd, 400, "读取请求体失败", true);
                    goto done;
                }
                got += (size_t)n;
            }
            req.body = body;
        }

        http_response res;
        http_response_init(&res);
        tls_server = s;
        s->handler(s->ctx, &req, &res);
        tls_server = NULL;

        const char *conn_hdr = http_request_header(&req, "Connection");
        bool keep_alive;
        if (minor >= 1)
            keep_alive = !(conn_hdr && strcasecmp(conn_hdr, "close") == 0);
        else
            keep_alive = conn_hdr && strcasecmp(conn_hdr, "keep-alive") == 0;
        if (atomic_load(&s->stopping))
            keep_alive = false;

        write_response(fd, &res, strcmp(req.method, "HEAD") == 0, keep_alive);
        http_response_free(&res);
        free(body);
        if (!keep_alive)
            break;
    }

done:
    free(buf);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    client_remove(s, fd);
    return NULL;
}

static void *accept_main(void *arg)
{
    http_server *s = arg;
    while (!atomic_load(&s->stopping)) {
        struct pollfd pfd = {.fd = s->listen_fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) {
            if (pr < 0 && errno != EINTR)
                break;
            continue;
        }
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int fd = accept4(s->listen_fd, (struct sockaddr *)&ss, &sl, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (atomic_load(&s->stopping))
                break;
            continue;
        }
        client_add(s, fd);
        conn_arg *ca = xmalloc(sizeof(*ca));
        ca->s = s;
        ca->fd = fd;
        pthread_t th;
        if (pthread_create(&th, NULL, conn_main, ca) != 0) {
            free(ca);
            client_remove(s, fd);
            close(fd);
            continue;
        }
        pthread_detach(th);
    }
    return NULL;
}

int http_server_start(http_server *s, char *err, size_t errlen)
{
    if (!s)
        return -1;
    if (s->started)
        return 0;
    if (pthread_create(&s->thread, NULL, accept_main, s) != 0) {
        set_err(err, errlen, "创建 HTTP 服务线程失败");
        return -1;
    }
    s->started = true;
    return 0;
}

void http_server_stop(http_server *s)
{
    if (!s)
        return;
    if (atomic_exchange(&s->stopping, true)) {
        /* 另一个线程已在停止流程中，等待其完成 */
        pthread_mutex_lock(&s->mu);
        while (s->active > 0)
            pthread_cond_wait(&s->cond, &s->mu);
        pthread_mutex_unlock(&s->mu);
        return;
    }
    /* accept 线程用 poll 轮询（200ms），先通知退出再关闭监听 fd */
    if (s->started) {
        pthread_join(s->thread, NULL);
        s->started = false;
    }
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->nclients; i++)
        shutdown(s->clients[i], SHUT_RDWR);
    while (s->active > 0)
        pthread_cond_wait(&s->cond, &s->mu);
    pthread_mutex_unlock(&s->mu);
}

void http_server_free(http_server *s)
{
    if (!s)
        return;
    http_server_stop(s);
    free(s->clients);
    free(s->addr);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->cond);
    free(s);
}
