/*
 * zx_common.h — shared plumbing for the Z-Egress proxies.
 *
 *   - a minimal HTTP/1.1 GET client, used only to pull dictionaries from the
 *     in-cluster control plane. It deliberately speaks no TLS and follows no
 *     redirects: in an air-gapped deployment the control plane is on the same
 *     network, and a proxy that cannot reach the internet is easier to defend
 *     in a security review than one that can.
 *
 *   - Prometheus counters and a tiny metrics listener, so a customer can prove
 *     the saving from their own monitoring instead of taking our word for it.
 *
 * Include after <zstd.h>.
 */

#ifndef ZX_COMMON_H
#define ZX_COMMON_H

#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Metrics                                                             */
/* ------------------------------------------------------------------ */

static atomic_ullong zx_requests     = 0;   /* every request seen           */
static atomic_ullong zx_transformed  = 0;   /* compressed or decompressed   */
static atomic_ullong zx_passthrough  = 0;   /* forwarded untouched          */
static atomic_ullong zx_fallback     = 0;   /* dictionary miss or bail-out  */
static atomic_ullong zx_errors       = 0;
static atomic_ullong zx_plain_bytes  = 0;   /* uncompressed side, cumulative*/
static atomic_ullong zx_wire_bytes   = 0;   /* compressed side, cumulative  */
static atomic_ullong zx_dict_id      = 0;

static const char *zx_role = "proxy";       /* "egress" or "ingress"        */

#define ZX_BUMP(c)      atomic_fetch_add(&(c), 1ULL)
#define ZX_ADD(c, n)    atomic_fetch_add(&(c), (unsigned long long)(n))

/* Prometheus text exposition. Kept deliberately small: these are the numbers
 * a FinOps or platform team needs to verify the saving, nothing more. */
static size_t zx_render_metrics(char *buf, size_t cap)
{
    unsigned long long plain = atomic_load(&zx_plain_bytes);
    unsigned long long wire  = atomic_load(&zx_wire_bytes);
    double ratio = plain ? 1.0 - (double)wire / (double)plain : 0.0;

    return (size_t)snprintf(buf, cap,
        "# HELP zegress_requests_total Requests seen by this proxy.\n"
        "# TYPE zegress_requests_total counter\n"
        "zegress_requests_total{role=\"%s\"} %llu\n"
        "# HELP zegress_transformed_total Requests compressed or decompressed.\n"
        "# TYPE zegress_transformed_total counter\n"
        "zegress_transformed_total{role=\"%s\"} %llu\n"
        "# HELP zegress_passthrough_total Requests forwarded untouched.\n"
        "# TYPE zegress_passthrough_total counter\n"
        "zegress_passthrough_total{role=\"%s\"} %llu\n"
        "# HELP zegress_fallback_total Dictionary misses and compression bail-outs.\n"
        "# TYPE zegress_fallback_total counter\n"
        "zegress_fallback_total{role=\"%s\"} %llu\n"
        "# HELP zegress_errors_total Failed requests.\n"
        "# TYPE zegress_errors_total counter\n"
        "zegress_errors_total{role=\"%s\"} %llu\n"
        "# HELP zegress_plain_bytes_total Cumulative bytes on the uncompressed side.\n"
        "# TYPE zegress_plain_bytes_total counter\n"
        "zegress_plain_bytes_total{role=\"%s\"} %llu\n"
        "# HELP zegress_wire_bytes_total Cumulative bytes actually sent over the network.\n"
        "# TYPE zegress_wire_bytes_total counter\n"
        "zegress_wire_bytes_total{role=\"%s\"} %llu\n"
        "# HELP zegress_ratio Achieved compression ratio since start.\n"
        "# TYPE zegress_ratio gauge\n"
        "zegress_ratio{role=\"%s\"} %.4f\n"
        "# HELP zegress_dictionary_id Dictionary currently in use, 0 if none.\n"
        "# TYPE zegress_dictionary_id gauge\n"
        "zegress_dictionary_id{role=\"%s\"} %llu\n",
        zx_role, (unsigned long long)atomic_load(&zx_requests),
        zx_role, (unsigned long long)atomic_load(&zx_transformed),
        zx_role, (unsigned long long)atomic_load(&zx_passthrough),
        zx_role, (unsigned long long)atomic_load(&zx_fallback),
        zx_role, (unsigned long long)atomic_load(&zx_errors),
        zx_role, plain,
        zx_role, wire,
        zx_role, ratio,
        zx_role, (unsigned long long)atomic_load(&zx_dict_id));
}

static void *zx_metrics_thread(void *arg)
{
    int port = *(int *)arg;
    free(arg);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return NULL;
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);

    if (bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 16) != 0) {
        fprintf(stderr, "[zx] metrics listener on :%d unavailable\n", port);
        close(lfd);
        return NULL;
    }
    fprintf(stderr, "[zx] metrics on :%d/metrics\n", port);

    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) continue;

        char req[512];
        ssize_t n = recv(c, req, sizeof req - 1, 0);   /* request is ignored */
        (void)n;

        char body[2048];
        size_t blen = zx_render_metrics(body, sizeof body);

        char head[256];
        int hlen = snprintf(head, sizeof head,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n", blen);

        if (send(c, head, (size_t)hlen, MSG_NOSIGNAL) > 0)
            send(c, body, blen, MSG_NOSIGNAL);
        close(c);
    }
}

static void zx_start_metrics(int port, const char *role)
{
    if (port <= 0) return;
    zx_role = role;
    int *p = malloc(sizeof *p);      /* freed by the thread on entry */
    if (!p) return;
    *p = port;

    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    if (pthread_create(&t, &at, zx_metrics_thread, p) != 0) free(p);
    pthread_attr_destroy(&at);
}

/* ------------------------------------------------------------------ */
/* Minimal HTTP GET, for the control plane only                        */
/* ------------------------------------------------------------------ */

/* On success stores a malloc'd body in *out and its length in *outlen; the
 * caller owns and frees it. Returns 0 on success, -1 on any failure. */
static int zx_http_get(const char *url, void **out, size_t *outlen)
{
    *out = NULL;
    *outlen = 0;

    if (strncmp(url, "http://", 7) != 0) return -1;   /* no TLS by design */

    const char *hp = url + 7;
    const char *slash = strchr(hp, '/');
    const char *path = slash ? slash : "/";

    char host[256], port[16] = "80";
    size_t hl = slash ? (size_t)(slash - hp) : strlen(hp);
    if (hl == 0 || hl >= sizeof host) return -1;
    memcpy(host, hp, hl);
    host[hl] = '\0';

    char *colon = strrchr(host, ':');
    if (colon) {
        *colon = '\0';
        snprintf(port, sizeof port, "%s", colon + 1);
    }

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    char req[1024];
    int rl = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: z-egress/0.1\r\nConnection: close\r\n\r\n", path, host);
    if (send(fd, req, (size_t)rl, MSG_NOSIGNAL) != rl) { close(fd); return -1; }

    /* Read the whole response. Dictionaries are ~110 KB and the control plane
     * is local, so buffering the lot is simpler and safe enough. */
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }

    for (;;) {
        if (len == cap) {
            if (cap > (8u << 20)) { free(buf); close(fd); return -1; }  /* 8 MB cap */
            char *nb = realloc(buf, cap * 2);
            if (!nb) { free(buf); close(fd); return -1; }   /* buf still valid */
            buf = nb;
            cap *= 2;
        }
        ssize_t r = recv(fd, buf + len, cap - len, 0);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return -1; }
        if (r == 0) break;
        len += (size_t)r;
    }
    close(fd);

    if (len < 12 || strncmp(buf, "HTTP/1.", 7) != 0) { free(buf); return -1; }
    if (strncmp(buf + 9, "200", 3) != 0) { free(buf); return -1; }

    char *hdr_end = NULL;
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            hdr_end = buf + i + 4;
            break;
        }
    if (!hdr_end) { free(buf); return -1; }

    size_t blen = len - (size_t)(hdr_end - buf);
    void *body = malloc(blen ? blen : 1);
    if (!body) { free(buf); return -1; }
    memcpy(body, hdr_end, blen);
    free(buf);                       /* response buffer done; body is owned */

    *out = body;
    *outlen = blen;
    return 0;
}

#endif /* ZX_COMMON_H */
