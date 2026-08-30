/*
 * Z-Egress Ingress v0.1 — the receiving half.
 *
 * Sits in front of the application at the far end of a compressed hop.
 * Accepts HTTP requests, and when a request arrives with
 * Content-Encoding: zstd it decompresses the body, restores
 * Content-Length, strips Content-Encoding, and forwards the original
 * bytes upstream. The application behind it needs no changes and never
 * knows compression happened.
 *
 * Dictionary handling is the interesting part. zstd writes the dictionary
 * ID into the frame header, so the sender does not need to tell us which
 * dictionary it used — we read it off the frame and look it up. If we do
 * not hold that dictionary we answer 415 with the missing ID, which is the
 * signal for the egress side to fall back to generic zstd. A version skew
 * therefore degrades to Envoy's behaviour instead of corrupting a payload.
 *
 * Build:  gcc -std=c11 -O2 -Wall -Wextra -pthread ingress.c -o z-ingress -lzstd
 * Usage:  ./z-ingress <listen_port> <app_host> <app_port> [dict_dir]
 *
 * Pair with the egress proxy:
 *   ./z-egress  8080 ingress-host 8081     (compresses)
 *   ./z-ingress 8081 127.0.0.1     9001    (decompresses)
 */

/* Z-Egress — Copyright (C) 2026 Rishikesh
 * Licensed under the GNU Affero General Public License v3.0.
 * See LICENSE for terms. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <zstd.h>
#include "zx_common.h"

#define PROXY_ENGINE       "Z-Ingress-v0.1"
#define LISTEN_BACKLOG     512
#define MAX_HEADER_BYTES   (32u * 1024u)
#define MAX_BODY_BYTES     (16u * 1024u * 1024u)   /* compressed input cap  */
#define MAX_INFLATED_BYTES (128u * 1024u * 1024u)  /* decompressed cap      */
#define MAX_EXPANSION      200                     /* refuse >200x blowup   */
#define IO_TIMEOUT_SEC     15
#define READ_CHUNK         16384u
#define MAX_HEADERS        64
#define MAX_DICTS          64

/* ------------------------------------------------------------------ */
/* Dictionary registry                                                 */
/*                                                                     */
/* Loaded once at startup and never mutated, so worker threads can read */
/* it without a lock. ZSTD_DDict is documented as safe to share across  */
/* threads; only the ZSTD_DCtx must be per-thread.                     */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned     id;      /* dictionary id as written into zstd frames   */
    ZSTD_DDict  *ddict;   /* owned; freed only at process exit           */
    char         name[256];
} dict_entry_t;

static dict_entry_t g_dicts[MAX_DICTS];
static int          g_ndicts = 0;

/* The registry was append-only-at-startup; on-demand fetching makes it mutable
 * while workers are reading it, so mutation takes this lock. DDicts themselves
 * are immutable once built, so a reader can take the pointer under the lock and
 * keep using it after releasing. */
static pthread_mutex_t g_dict_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *g_control_plane = NULL;   /* http://host:port, or NULL */

static const ZSTD_DDict *dict_lookup(unsigned id)
{
    const ZSTD_DDict *found = NULL;
    pthread_mutex_lock(&g_dict_lock);
    for (int i = 0; i < g_ndicts; i++)
        if (g_dicts[i].id == id) { found = g_dicts[i].ddict; break; }
    pthread_mutex_unlock(&g_dict_lock);
    return found;
}

/* Ask the control plane for a dictionary we have not seen. This is what turns
 * a version skew from an outage into a two-second delay: the sender rolls
 * forward, we notice an unknown id, we fetch it, and traffic keeps flowing. */
static const ZSTD_DDict *dict_fetch(unsigned id)
{
    if (!g_control_plane) return NULL;

    char url[512];
    snprintf(url, sizeof url, "%s/v1/dictionary/%u", g_control_plane, id);

    void *raw = NULL; size_t n = 0;
    if (zx_http_get(url, &raw, &n) != 0 || n == 0) { free(raw); return NULL; }

    ZSTD_DDict *dd = ZSTD_createDDict(raw, n);
    free(raw);
    if (!dd) return NULL;

    if (ZSTD_getDictID_fromDDict(dd) != id) {   /* control plane served wrong data */
        ZSTD_freeDDict(dd);
        return NULL;
    }

    pthread_mutex_lock(&g_dict_lock);
    for (int i = 0; i < g_ndicts; i++)          /* another thread may have won */
        if (g_dicts[i].id == id) {
            pthread_mutex_unlock(&g_dict_lock);
            ZSTD_freeDDict(dd);
            return g_dicts[i].ddict;
        }
    if (g_ndicts >= MAX_DICTS) {
        pthread_mutex_unlock(&g_dict_lock);
        ZSTD_freeDDict(dd);
        return NULL;
    }
    g_dicts[g_ndicts].id = id;
    g_dicts[g_ndicts].ddict = dd;
    snprintf(g_dicts[g_ndicts].name, sizeof g_dicts[g_ndicts].name,
             "fetched:%u", id);
    g_ndicts++;
    pthread_mutex_unlock(&g_dict_lock);

    fprintf(stderr, "[z-ingress] fetched dictionary %u from control plane\n", id);
    return dd;
}

/* Read one dictionary file into a DDict and register it under whatever
 * id zstd says it carries. We never trust the filename for the id. */
static int dict_load_file(const char *dir, const char *fname)
{
    if (g_ndicts >= MAX_DICTS) return -1;

    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, fname);

    FILE *fh = fopen(path, "rb");
    if (!fh) return -1;

    if (fseek(fh, 0, SEEK_END) != 0) { fclose(fh); return -1; }
    long sz = ftell(fh);
    if (sz <= 0 || sz > 8 * 1024 * 1024) { fclose(fh); return -1; }
    rewind(fh);

    /* One allocation for the raw dictionary bytes. ZSTD_createDDict()
     * copies them into the DDict, so this buffer is freed immediately
     * afterwards — the DDict does not alias it. */
    void *raw = malloc((size_t)sz);
    if (!raw) { fclose(fh); return -1; }

    if (fread(raw, 1, (size_t)sz, fh) != (size_t)sz) {
        free(raw); fclose(fh); return -1;
    }
    fclose(fh);

    ZSTD_DDict *dd = ZSTD_createDDict(raw, (size_t)sz);
    free(raw);                        /* safe: DDict owns its own copy */
    if (!dd) return -1;

    unsigned id = ZSTD_getDictID_fromDDict(dd);
    if (id == 0) { ZSTD_freeDDict(dd); return -1; }   /* not a real dict */

    g_dicts[g_ndicts].id    = id;
    g_dicts[g_ndicts].ddict = dd;
    snprintf(g_dicts[g_ndicts].name, sizeof g_dicts[g_ndicts].name, "%s", fname);
    g_ndicts++;
    return 0;
}

static void dicts_load_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "[z-ingress] no dictionary dir '%s' "
                        "(generic zstd only)\n", dir);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n > 5 && strcmp(e->d_name + n - 5, ".dict") == 0)
            if (dict_load_file(dir, e->d_name) == 0)
                fprintf(stderr, "[z-ingress] loaded dictionary %u (%s)\n",
                        g_dicts[g_ndicts - 1].id, e->d_name);
    }
    closedir(d);
}

/* ------------------------------------------------------------------ */
/* Growable buffer (same ownership contract as the egress proxy)       */
/* ------------------------------------------------------------------ */

typedef struct { char *data; size_t len, cap; } buf_t;

static int buf_reserve(buf_t *b, size_t extra)
{
    if (b->cap - b->len >= extra) return 0;
    if (extra > SIZE_MAX - b->len) return -1;
    size_t want = b->len + extra;
    size_t ncap = b->cap ? b->cap : 4096;
    while (ncap < want) {
        if (ncap > SIZE_MAX / 2) return -1;
        ncap *= 2;
    }
    char *nd = realloc(b->data, ncap);   /* on NULL the old block survives */
    if (!nd) return -1;
    b->data = nd; b->cap = ncap;
    return 0;
}

static int buf_append(buf_t *b, const void *src, size_t n)
{
    if (n == 0) return 0;
    if (buf_reserve(b, n) != 0) return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static int buf_puts(buf_t *b, const char *s) { return buf_append(b, s, strlen(s)); }

static int buf_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt); va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return -1; }
    if (buf_reserve(b, (size_t)need + 1) != 0) { va_end(ap2); return -1; }
    vsnprintf(b->data + b->len, (size_t)need + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)need;     /* trailing NUL sits past len, never sent */
    return 0;
}

static void buf_free(buf_t *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

static void set_sock_timeouts(int fd)
{
    struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

static int write_all(int fd, const void *p, size_t n)
{
    const char *c = p; size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, c + off, n - off, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static ssize_t find_header_end(const buf_t *b, size_t from)
{
    if (b->len < 4) return -1;
    size_t i = (from >= 3) ? from - 3 : 0;
    for (; i + 3 < b->len; i++)
        if (b->data[i] == '\r' && b->data[i+1] == '\n' &&
            b->data[i+2] == '\r' && b->data[i+3] == '\n')
            return (ssize_t)(i + 4);
    return -1;
}

static ssize_t read_headers(int fd, buf_t *b)
{
    size_t scanned = 0;
    for (;;) {
        ssize_t end = find_header_end(b, scanned);
        if (end > 0) return end;
        scanned = b->len;
        if (b->len >= MAX_HEADER_BYTES) return -1;
        if (buf_reserve(b, READ_CHUNK) != 0) return -1;
        ssize_t r = recv(fd, b->data + b->len, READ_CHUNK, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        b->len += (size_t)r;
    }
}

/* ------------------------------------------------------------------ */
/* Request parsing                                                     */
/* ------------------------------------------------------------------ */

typedef struct { char *name, *value; } hdr_t;

typedef struct {
    char *raw;                 /* single owning allocation for all fields */
    char *method, *target, *version;
    hdr_t hdrs[MAX_HEADERS];
    int   nhdrs;
} req_t;

static void req_free(req_t *r) { free(r->raw); r->raw = NULL; r->nhdrs = 0; }

static int req_parse(req_t *r, const char *block, size_t block_len)
{
    memset(r, 0, sizeof *r);
    r->raw = malloc(block_len + 1);        /* +1 so strstr/strchr terminate */
    if (!r->raw) return -1;
    memcpy(r->raw, block, block_len);
    r->raw[block_len] = '\0';

    char *p = r->raw, *eol = strstr(p, "\r\n");
    if (!eol) return -1;
    *eol = '\0';

    r->method = p;
    char *sp = strchr(p, ' ');
    if (!sp) return -1;
    *sp = '\0'; r->target = sp + 1;
    sp = strchr(r->target, ' ');
    if (!sp) return -1;
    *sp = '\0'; r->version = sp + 1;

    p = eol + 2;
    while (*p) {
        char *e = strstr(p, "\r\n");
        if (!e || e == p) break;
        *e = '\0';
        char *colon = strchr(p, ':');
        if (colon && r->nhdrs < MAX_HEADERS) {
            *colon = '\0';
            char *v = colon + 1;
            while (*v == ' ' || *v == '\t') v++;
            r->hdrs[r->nhdrs].name = p;
            r->hdrs[r->nhdrs].value = v;
            r->nhdrs++;
        }
        p = e + 2;
    }
    return 0;
}

static const char *hdr_get(const req_t *r, const char *n)
{
    for (int i = 0; i < r->nhdrs; i++)
        if (strcasecmp(r->hdrs[i].name, n) == 0) return r->hdrs[i].value;
    return NULL;
}

static bool hdr_is_managed(const char *n)
{
    static const char *drop[] = {
        "content-length", "content-encoding", "transfer-encoding",
        "connection", "proxy-connection", "keep-alive",
        "te", "trailer", "upgrade", NULL };
    for (int i = 0; drop[i]; i++)
        if (strcasecmp(n, drop[i]) == 0) return true;
    return false;
}

static bool parse_content_length(const char *s, size_t *out)
{
    if (!s || !*s) return false;
    size_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ' ' || *p == '\t') break;
        if (*p < '0' || *p > '9') return false;
        if (v > (SIZE_MAX - (size_t)(*p - '0')) / 10) return false;
        v = v * 10 + (size_t)(*p - '0');
    }
    if (v > MAX_BODY_BYTES) return false;
    *out = v;
    return true;
}

/* ------------------------------------------------------------------ */
/* Upstream                                                            */
/* ------------------------------------------------------------------ */

static const char *g_app_host, *g_app_port;

static int connect_app(void)
{
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_app_host, g_app_port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) set_sock_timeouts(fd);
    return fd;
}

static void relay_until_eof(int from, int to)
{
    char tmp[READ_CHUNK];
    for (;;) {
        ssize_t r = recv(from, tmp, sizeof tmp, 0);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        if (write_all(to, tmp, (size_t)r) != 0) break;
    }
}

static void pump_bidir(int a, int b)
{
    struct pollfd pfd[2];
    char tmp[READ_CHUNK];
    bool ao = true, bo = true;
    while (ao || bo) {
        int n = 0, ia = -1, ib = -1;
        if (ao) { pfd[n].fd = a; pfd[n].events = POLLIN; ia = n++; }
        if (bo) { pfd[n].fd = b; pfd[n].events = POLLIN; ib = n++; }
        if (n == 0) break;
        int pr = poll(pfd, (nfds_t)n, IO_TIMEOUT_SEC * 1000);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) break;
        if (ia >= 0 && (pfd[ia].revents & (POLLIN|POLLHUP|POLLERR))) {
            ssize_t r = recv(a, tmp, sizeof tmp, 0);
            if (r <= 0 || write_all(b, tmp, (size_t)r) != 0) { ao = false; shutdown(b, SHUT_WR); }
        }
        if (ib >= 0 && (pfd[ib].revents & (POLLIN|POLLHUP|POLLERR))) {
            ssize_t r = recv(b, tmp, sizeof tmp, 0);
            if (r <= 0 || write_all(a, tmp, (size_t)r) != 0) { bo = false; shutdown(a, SHUT_WR); }
        }
    }
}

static void send_status(int fd, const char *status, const char *extra_hdr,
                        const char *body)
{
    char out[1024];
    int n = snprintf(out, sizeof out,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "X-Proxy-Engine: " PROXY_ENGINE "\r\n"
        "%s"
        "Connection: close\r\n\r\n%s",
        status, strlen(body), extra_hdr ? extra_hdr : "", body);
    if (n > 0) write_all(fd, out, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* Connection handler                                                  */
/* ------------------------------------------------------------------ */

static void *handle_conn(void *arg)
{
    int cfd = *(int *)arg;
    free(arg);                     /* freed first thing: cannot leak later */

    buf_t   inbuf = {0};           /* raw bytes from the sender            */
    buf_t   body  = {0};           /* compressed body, reassembled         */
    buf_t   out   = {0};           /* rebuilt request for the app          */
    void   *plain = NULL;          /* decompressed payload                 */
    req_t   req   = {0};
    bool    parsed = false;
    int     afd   = -1;
    ZSTD_DCtx *dctx = NULL;

    set_sock_timeouts(cfd);

    ssize_t hend = read_headers(cfd, &inbuf);
    if (hend <= 0) goto cleanup;
    if (req_parse(&req, inbuf.data, (size_t)hend) != 0) goto cleanup;
    parsed = true;
    ZX_BUMP(zx_requests);

    const char *ce = hdr_get(&req, "Content-Encoding");
    const char *cl = hdr_get(&req, "Content-Length");
    const char *te = hdr_get(&req, "Transfer-Encoding");

    size_t body_len = 0;
    bool is_zstd = ce && strcasecmp(ce, "zstd") == 0
                      && !te && parse_content_length(cl, &body_len)
                      && body_len > 0;

    afd = connect_app();
    if (afd < 0) {
        send_status(cfd, "502 Bad Gateway", NULL, "upstream unavailable\n");
        goto cleanup;
    }

    if (!is_zstd) {
        /* Not ours to touch: forward byte for byte. */
        ZX_BUMP(zx_passthrough);
        if (write_all(afd, inbuf.data, inbuf.len) != 0) goto cleanup;
        pump_bidir(cfd, afd);
        goto cleanup;
    }

    /* ---- reassemble the compressed body ---- */

    size_t have = inbuf.len - (size_t)hend;
    if (have > body_len) have = body_len;
    if (buf_reserve(&body, body_len) != 0) goto cleanup;   /* exact size */
    if (buf_append(&body, inbuf.data + hend, have) != 0) goto cleanup;

    while (body.len < body_len) {
        size_t want = body_len - body.len;
        if (want > READ_CHUNK) want = READ_CHUNK;
        ssize_t r = recv(cfd, body.data + body.len, want, 0);
        if (r < 0) { if (errno == EINTR) continue; goto cleanup; }
        if (r == 0) goto cleanup;
        body.len += (size_t)r;
    }

    /* ---- which dictionary, if any? ---- */

    unsigned frame_dict = ZSTD_getDictID_fromFrame(body.data, body.len);
    const ZSTD_DDict *dd = NULL;

    if (frame_dict != 0) {
        dd = dict_lookup(frame_dict);
        if (!dd) dd = dict_fetch(frame_dict);      /* auto-sync before failing */
        if (!dd) {
            /* We cannot decode this. Say so precisely: the sender reads the
             * id back and falls back to generic zstd on the next request.
             * A skewed rollout degrades, it does not corrupt. */
            char xh[128];
            snprintf(xh, sizeof xh,
                     "X-Z-Egress-Missing-Dict: %u\r\n", frame_dict);
            ZX_BUMP(zx_fallback);
            fprintf(stderr, "[z-ingress] unknown dictionary %u - asked sender "
                            "to fall back\n", frame_dict);
            send_status(cfd, "415 Unsupported Media Type", xh,
                        "unknown zstd dictionary id\n");
            goto cleanup;
        }
    }

    /* ---- size the output buffer, defensively ----
     *
     * A decompressor is the natural place for a zip bomb: a few KB can
     * expand to gigabytes. Two independent caps here — an absolute
     * ceiling and a maximum expansion ratio — and the declared frame
     * size is treated as a claim to be checked, never trusted. */

    unsigned long long declared = ZSTD_getFrameContentSize(body.data, body.len);
    if (declared == ZSTD_CONTENTSIZE_ERROR) {
        send_status(cfd, "400 Bad Request", NULL, "malformed zstd frame\n");
        goto cleanup;
    }
    if (declared == ZSTD_CONTENTSIZE_UNKNOWN) {
        /* Frame carries no size. Allow the ratio cap instead. */
        declared = (unsigned long long)body.len * MAX_EXPANSION;
        if (declared > MAX_INFLATED_BYTES) declared = MAX_INFLATED_BYTES;
    }
    if (declared > MAX_INFLATED_BYTES ||
        declared > (unsigned long long)body.len * MAX_EXPANSION) {
        fprintf(stderr, "[z-ingress] refused %zu B claiming %llu B expansion\n",
                body.len, declared);
        ZX_BUMP(zx_errors);
        send_status(cfd, "413 Payload Too Large", NULL,
                    "decompressed size exceeds limit\n");
        goto cleanup;
    }

    size_t cap = (size_t)declared;
    if (cap == 0) cap = 1;
    plain = malloc(cap);            /* one allocation, exact declared size */
    if (!plain) goto cleanup;

    /* ---- decompress ---- */

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    dctx = ZSTD_createDCtx();       /* per-connection; DDicts are shared */
    if (!dctx) goto cleanup;

    size_t got = dd
        ? ZSTD_decompress_usingDDict(dctx, plain, cap, body.data, body.len, dd)
        : ZSTD_decompressDCtx(dctx, plain, cap, body.data, body.len);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double us = (double)(t1.tv_sec - t0.tv_sec) * 1e6
              + (double)(t1.tv_nsec - t0.tv_nsec) / 1e3;

    if (ZSTD_isError(got)) {
        fprintf(stderr, "[z-ingress] decode failed: %s\n",
                ZSTD_getErrorName(got));
        ZX_BUMP(zx_errors);
        send_status(cfd, "400 Bad Request", NULL, "zstd decode failed\n");
        goto cleanup;
    }

    ZX_BUMP(zx_transformed);
    ZX_ADD(zx_plain_bytes, got);
    ZX_ADD(zx_wire_bytes, body.len);
    atomic_store(&zx_dict_id, (unsigned long long)frame_dict);

    fprintf(stderr, "[z-ingress] %s %s  %zu -> %zu B  (dict %u, %.0f us)\n",
            req.method, req.target, body.len, got, frame_dict, us);

    /* ---- rebuild the original request ---- */

    if (buf_printf(&out, "%s %s %s\r\n",
                   req.method, req.target, req.version) != 0) goto cleanup;
    for (int i = 0; i < req.nhdrs; i++) {
        if (hdr_is_managed(req.hdrs[i].name)) continue;
        if (buf_printf(&out, "%s: %s\r\n",
                       req.hdrs[i].name, req.hdrs[i].value) != 0) goto cleanup;
    }
    if (buf_printf(&out, "Content-Length: %zu\r\n", got) != 0) goto cleanup;
    if (buf_printf(&out, "X-Proxy-Engine: %s\r\n", PROXY_ENGINE) != 0) goto cleanup;
    if (buf_printf(&out, "X-Z-Egress-Wire-Bytes: %zu\r\n", body.len) != 0) goto cleanup;
    if (buf_puts(&out, "Connection: close\r\n\r\n") != 0) goto cleanup;
    if (buf_append(&out, plain, got) != 0) goto cleanup;

    if (write_all(afd, out.data, out.len) != 0) goto cleanup;
    relay_until_eof(afd, cfd);

cleanup:
    /* Single exit. Everything initialised to NULL/-1, released once. */
    if (dctx) ZSTD_freeDCtx(dctx);
    free(plain);
    buf_free(&out);
    buf_free(&body);
    buf_free(&inbuf);
    if (parsed) req_free(&req);
    if (afd >= 0) close(afd);
    close(cfd);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Listener                                                            */
/* ------------------------------------------------------------------ */

static int bind_family(const char *port, int family)
{
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (rp->ai_family == AF_INET6) {
            int off = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
        }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 &&
            listen(fd, LISTEN_BACKLOG) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* IPv6 first, but many containers have it disabled and socket() itself
 * fails with EAFNOSUPPORT even after getaddrinfo() succeeds. */
static int make_listener(const char *port)
{
    int fd = bind_family(port, AF_INET6);
    if (fd < 0) fd = bind_family(port, AF_INET);
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 7) {
        fprintf(stderr,
            "usage: %s <listen_port> <app_host> <app_port> [dict_dir] "
            "[http://control-plane] [metrics_port]\n", argv[0]);
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);

    g_app_host = argv[2];
    g_app_port = argv[3];
    dicts_load_dir(argc >= 5 ? argv[4] : "./dicts");
    if (argc >= 6 && strncmp(argv[5], "http://", 7) == 0) {
        g_control_plane = argv[5];
        fprintf(stderr, "[z-ingress] control plane %s (auto-fetch enabled)\n",
                g_control_plane);
    }
    zx_start_metrics(argc >= 7 ? atoi(argv[6]) : 0, "ingress");

    int lfd = make_listener(argv[1]);
    if (lfd < 0) { perror("[z-ingress] listen"); return 1; }

    fprintf(stderr, "[z-ingress] " PROXY_ENGINE " on :%s -> %s:%s "
                    "(%d dictionaries, libzstd %s)\n",
            argv[1], g_app_host, g_app_port, g_ndicts, ZSTD_versionString());

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            perror("[z-ingress] accept");
            break;
        }
        int *slot = malloc(sizeof *slot);
        if (!slot) { close(cfd); continue; }
        *slot = cfd;
        pthread_t tid;
        if (pthread_create(&tid, &attr, handle_conn, slot) != 0) {
            free(slot);           /* neither the cell nor the fd leaks */
            close(cfd);
        }
    }

    pthread_attr_destroy(&attr);
    close(lfd);
    for (int i = 0; i < g_ndicts; i++) ZSTD_freeDDict(g_dicts[i].ddict);
    return 0;
}
