/*
 * Z-Egress v0.1 — inline HTTP/JSON egress compression proxy
 *
 * Listens on a local port, accepts HTTP/1.1 requests, and for POST/PUT
 * requests carrying a JSON body it compresses the body with libzstd
 * (level 1, ultra-fast) before forwarding to a fixed upstream. It rewrites
 * Content-Length, injects Content-Encoding: zstd and X-Proxy-Engine, and
 * relays the upstream response back to the client verbatim.
 *
 * Anything it cannot safely rewrite (GET/HEAD, chunked bodies, already
 * encoded bodies, oversized bodies, incompressible payloads) is passed
 * through byte-for-byte via a bidirectional pump.
 *
 * Build:  gcc -std=c11 -O2 -Wall -Wextra -pthread main.c -o z-egress -lzstd
 * Usage:  ./z-egress <listen_port> <upstream_host> <upstream_port>
 *
 * C11 / POSIX.1-2008. Not a production proxy — see the notes at the bottom
 * of the file for what is deliberately out of scope in v0.1.
 */
/* Z-Egress — Copyright (C) 2026 Rishikesh
 * Licensed under the GNU Affero General Public License v3.0.
 * See LICENSE for terms. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <zstd.h>
#include "zx_common.h"

/* ------------------------------------------------------------------ */
/* Tunables                                                            */
/* ------------------------------------------------------------------ */

#define PROXY_ENGINE       "Z-Egress-v0.1"
#define LISTEN_BACKLOG     512
#define MAX_HEADER_BYTES   (32u * 1024u)          /* refuse absurd header blocks */
#define MAX_BODY_BYTES     (16u * 1024u * 1024u)  /* hard cap on buffered body   */
#define MIN_COMPRESS_BYTES 256u                   /* below this zstd rarely wins */
#define ZSTD_LEVEL         1                      /* ultra-fast tier             */
#define IO_TIMEOUT_SEC     15
#define READ_CHUNK         16384u
#define MAX_HEADERS        64

static const char *g_upstream_host;
static const char *g_upstream_port;

/* Compression dictionary, loaded once at startup and never mutated, so
 * worker threads read it without a lock. ZSTD_CDict is documented as safe
 * to share across threads; only the ZSTD_CCtx must be per-thread. */
static ZSTD_CDict *g_cdict = NULL;
static unsigned    g_cdict_id = 0;

/* The floor below which compression is skipped. Generic zstd is useless on
 * tiny payloads, hence 256. With a trained dictionary that assumption is
 * inverted -- small messages are exactly where dictionaries win -- so the
 * floor drops once a dictionary is loaded. */
static size_t g_min_compress = MIN_COMPRESS_BYTES;

/* Accepts a file path or an http:// URL pointing at the control plane.
 * Pulling from the control plane is what makes rotation possible without
 * rebuilding an image or redeploying a pod. */
static int load_cdict(const char *path)
{
    if (strncmp(path, "http://", 7) == 0) {
        void *raw = NULL; size_t n = 0;
        if (zx_http_get(path, &raw, &n) != 0 || n == 0) {
            fprintf(stderr, "[z-egress] control plane fetch failed: %s\n", path);
            free(raw);
            return -1;
        }
        g_cdict = ZSTD_createCDict(raw, n, ZSTD_LEVEL);
        free(raw);                      /* CDict keeps its own copy */
        if (!g_cdict) return -1;
        g_cdict_id = ZSTD_getDictID_fromCDict(g_cdict);
        atomic_store(&zx_dict_id, (unsigned long long)g_cdict_id);
        g_min_compress = 32;
        fprintf(stderr, "[z-egress] fetched dictionary %u from control plane\n",
                g_cdict_id);
        return 0;
    }

    FILE *fh = fopen(path, "rb");
    if (!fh) { fprintf(stderr, "[z-egress] cannot open %s\n", path); return -1; }
    if (fseek(fh, 0, SEEK_END) != 0) { fclose(fh); return -1; }
    long sz = ftell(fh);
    if (sz <= 0 || sz > 8 * 1024 * 1024) { fclose(fh); return -1; }
    rewind(fh);

    /* One allocation for the raw bytes. ZSTD_createCDict() copies them into
     * the CDict, so this buffer is freed immediately and never aliased. */
    void *raw = malloc((size_t)sz);
    if (!raw) { fclose(fh); return -1; }
    if (fread(raw, 1, (size_t)sz, fh) != (size_t)sz) {
        free(raw); fclose(fh); return -1;
    }
    fclose(fh);

    g_cdict = ZSTD_createCDict(raw, (size_t)sz, ZSTD_LEVEL);
    free(raw);
    if (!g_cdict) return -1;

    g_cdict_id = ZSTD_getDictID_fromCDict(g_cdict);
    atomic_store(&zx_dict_id, (unsigned long long)g_cdict_id);
    g_min_compress = 32;          /* dictionaries pay off far lower down */
    return 0;
}

/* ------------------------------------------------------------------ */
/* Growable byte buffer                                                */
/*                                                                     */
/* Ownership rule for every buf_t in this file: the function that      */
/* declares it with `= {0}` owns it and is the only one that calls     */
/* buf_free() on it, on every exit path, via a single `goto cleanup`.  */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *data;   /* malloc'd block, or NULL while cap == 0            */
    size_t len;    /* bytes currently used                             */
    size_t cap;    /* bytes currently allocated (always >= len)        */
} buf_t;

/* Grow so at least `extra` more bytes fit. Returns 0 on success, -1 on
 * allocation failure. On failure the buffer is left completely intact —
 * realloc() does not free the old block when it returns NULL, so the
 * caller's eventual buf_free() is still correct and there is no leak. */
static int buf_reserve(buf_t *b, size_t extra)
{
    if (b->cap - b->len >= extra) return 0;      /* already have room  */

    if (extra > SIZE_MAX - b->len) return -1;    /* size_t overflow    */
    size_t want = b->len + extra;

    size_t ncap = b->cap ? b->cap : 4096;        /* first alloc: 4 KiB */
    while (ncap < want) {
        if (ncap > SIZE_MAX / 2) return -1;      /* doubling overflow  */
        ncap *= 2;                               /* amortised O(1)     */
    }

    char *nd = realloc(b->data, ncap);
    if (!nd) return -1;                          /* old b->data intact */
    b->data = nd;
    b->cap  = ncap;
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

static int buf_puts(buf_t *b, const char *s)
{
    return buf_append(b, s, strlen(s));
}

/* printf into the buffer. Measures first with a NULL/0 vsnprintf so we
 * reserve the exact number of bytes needed, then formats in place. The
 * +1 covers the NUL that vsnprintf always writes; it sits one byte past
 * b->len and is never counted as payload, so it cannot leak into the
 * wire format. */
static int buf_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);

    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return -1; }

    if (buf_reserve(b, (size_t)need + 1) != 0) { va_end(ap2); return -1; }
    vsnprintf(b->data + b->len, (size_t)need + 1, fmt, ap2);
    va_end(ap2);

    b->len += (size_t)need;   /* deliberately excludes the trailing NUL */
    return 0;
}

/* Idempotent: safe to call on a zeroed buf_t and safe to call twice. */
static void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ------------------------------------------------------------------ */
/* Socket I/O helpers                                                  */
/* ------------------------------------------------------------------ */

static void set_sock_timeouts(int fd)
{
    struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

/* Write the whole buffer or fail. Handles short writes and EINTR.
 * MSG_NOSIGNAL keeps a dead peer from raising SIGPIPE on this thread. */
static int write_all(int fd, const void *p, size_t n)
{
    const char *c = (const char *)p;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, c + off, n - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Scan for the CRLFCRLF that terminates the header block.
 * `from` is a resume hint: bytes before it were already scanned, but we
 * back up 3 bytes so a terminator straddling two recv() calls is found. */
static ssize_t find_header_end(const buf_t *b, size_t from)
{
    if (b->len < 4) return -1;
    size_t i = (from >= 3) ? from - 3 : 0;
    for (; i + 3 < b->len; i++) {
        if (b->data[i]     == '\r' && b->data[i + 1] == '\n' &&
            b->data[i + 2] == '\r' && b->data[i + 3] == '\n')
            return (ssize_t)(i + 4);
    }
    return -1;
}

/* Read until the header terminator is seen. Leftover bytes past the
 * terminator are the start of the body and stay in the buffer. */
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
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;                 /* includes EAGAIN == timeout */
        }
        if (r == 0) return -1;         /* peer closed mid-headers    */
        b->len += (size_t)r;
    }
}

/* ------------------------------------------------------------------ */
/* HTTP request parsing                                                */
/* ------------------------------------------------------------------ */

typedef struct { char *name; char *value; } hdr_t;

typedef struct {
    char *raw;                 /* owned NUL-terminated copy of the header
                                * block. Every char* below points INTO this
                                * block, so none of them are freed
                                * individually — freeing raw frees all. */
    char *method;
    char *target;
    char *version;
    hdr_t hdrs[MAX_HEADERS];
    int   nhdrs;
} req_t;

static void req_free(req_t *r)
{
    free(r->raw);              /* the single owning pointer */
    r->raw = NULL;
    r->nhdrs = 0;
}

/* Destructively tokenise a copy of the header block in place: we punch
 * NULs over the CRLFs and the header colons, which is why we work on an
 * owned copy rather than on the live socket buffer (that buffer still
 * holds body bytes we have not consumed yet). */
static int req_parse(req_t *r, const char *block, size_t block_len)
{
    memset(r, 0, sizeof *r);

    r->raw = malloc(block_len + 1);            /* +1 for the NUL below */
    if (!r->raw) return -1;
    memcpy(r->raw, block, block_len);
    r->raw[block_len] = '\0';                  /* makes strstr/strchr safe */

    char *p   = r->raw;
    char *eol = strstr(p, "\r\n");
    if (!eol) return -1;
    *eol = '\0';

    r->method = p;
    char *sp = strchr(p, ' ');
    if (!sp) return -1;
    *sp = '\0';
    r->target = sp + 1;
    sp = strchr(r->target, ' ');
    if (!sp) return -1;
    *sp = '\0';
    r->version = sp + 1;

    p = eol + 2;
    while (*p) {
        char *e = strstr(p, "\r\n");
        if (!e || e == p) break;               /* empty line ends headers */
        *e = '\0';

        char *colon = strchr(p, ':');
        if (colon && r->nhdrs < MAX_HEADERS) {
            *colon = '\0';
            char *v = colon + 1;
            while (*v == ' ' || *v == '\t') v++;   /* strip OWS */
            r->hdrs[r->nhdrs].name  = p;
            r->hdrs[r->nhdrs].value = v;
            r->nhdrs++;
        }
        p = e + 2;
    }
    return 0;
}

static const char *hdr_get(const req_t *r, const char *name)
{
    for (int i = 0; i < r->nhdrs; i++)
        if (strcasecmp(r->hdrs[i].name, name) == 0)
            return r->hdrs[i].value;
    return NULL;
}

/* Headers we regenerate ourselves or that must not be forwarded. */
static bool hdr_is_managed(const char *n)
{
    static const char *drop[] = {
        "content-length", "content-encoding", "transfer-encoding",
        "connection", "proxy-connection", "keep-alive",
        "te", "trailer", "upgrade", NULL
    };
    for (int i = 0; drop[i]; i++)
        if (strcasecmp(n, drop[i]) == 0) return true;
    return false;
}

/* Accepts application/json and any structured suffix (+json), with or
 * without parameters: "application/vnd.api+json; charset=utf-8" matches. */
static bool is_json_content_type(const char *ct)
{
    if (!ct) return false;

    size_t n = strcspn(ct, ";");                 /* cut at parameters */
    while (n > 0 && (ct[n - 1] == ' ' || ct[n - 1] == '\t')) n--;

    if (n == 16 && strncasecmp(ct, "application/json", 16) == 0) return true;
    if (n >= 5  && strncasecmp(ct + n - 5, "+json", 5) == 0)      return true;
    return false;
}

/* Strict Content-Length parse: digits only, no overflow, within cap. */
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
/* Upstream connection                                                 */
/* ------------------------------------------------------------------ */

static int connect_upstream(void)
{
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(g_upstream_host, g_upstream_port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[z-egress] getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);                      /* close before trying next addr */
        fd = -1;
    }
    freeaddrinfo(res);                  /* owned by getaddrinfo, always freed */

    if (fd >= 0) set_sock_timeouts(fd);
    return fd;
}

/* ------------------------------------------------------------------ */
/* Relay paths                                                         */
/* ------------------------------------------------------------------ */

/* One-way drain: upstream -> client until upstream EOF. Used on the
 * compressed path, where we forced Connection: close upstream. */
static void relay_until_eof(int from, int to)
{
    char tmp[READ_CHUNK];               /* stack buffer, no allocation */
    for (;;) {
        ssize_t r = recv(from, tmp, sizeof tmp, 0);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        if (write_all(to, tmp, (size_t)r) != 0) break;
    }
}

/* Two-way pump for the pass-through path, where we did not rewrite
 * framing and therefore must not assume anything about message
 * boundaries or connection reuse. */
static void pump_bidir(int a, int b)
{
    struct pollfd pfd[2];
    char tmp[READ_CHUNK];
    bool a_open = true, b_open = true;

    while (a_open || b_open) {
        int n = 0;
        int ia = -1, ib = -1;
        if (a_open) { pfd[n].fd = a; pfd[n].events = POLLIN; ia = n++; }
        if (b_open) { pfd[n].fd = b; pfd[n].events = POLLIN; ib = n++; }
        if (n == 0) break;

        int pr = poll(pfd, (nfds_t)n, IO_TIMEOUT_SEC * 1000);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) break;                          /* idle timeout */

        if (ia >= 0 && (pfd[ia].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = recv(a, tmp, sizeof tmp, 0);
            if (r <= 0 || write_all(b, tmp, (size_t)r) != 0) {
                a_open = false;
                shutdown(b, SHUT_WR);
            }
        }
        if (ib >= 0 && (pfd[ib].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = recv(b, tmp, sizeof tmp, 0);
            if (r <= 0 || write_all(a, tmp, (size_t)r) != 0) {
                b_open = false;
                shutdown(a, SHUT_WR);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Connection handler                                                  */
/* ------------------------------------------------------------------ */

static void *handle_conn(void *arg)
{
    /* The accept loop malloc'd one int to carry the fd across the thread
     * boundary (passing it as (void*)(intptr_t) would also work, but this
     * keeps the ownership transfer explicit). Copy it out and free it
     * immediately so no path can leak it. */
    int cfd = *(int *)arg;
    free(arg);

    buf_t   inbuf   = {0};   /* raw bytes off the client socket           */
    buf_t   body    = {0};   /* the reassembled request body              */
    buf_t   out     = {0};   /* the rebuilt request we send upstream      */
    void   *cbuf    = NULL;  /* zstd destination buffer                   */
    req_t   req     = {0};
    bool    parsed  = false;
    int     ufd     = -1;

    set_sock_timeouts(cfd);

    ssize_t hend = read_headers(cfd, &inbuf);
    if (hend <= 0) goto cleanup;

    if (req_parse(&req, inbuf.data, (size_t)hend) != 0) goto cleanup;
    parsed = true;
    ZX_BUMP(zx_requests);

    /* ---- eligibility: every "no" falls through to pass-through ---- */

    const char *ct  = hdr_get(&req, "Content-Type");
    const char *cl  = hdr_get(&req, "Content-Length");
    const char *te  = hdr_get(&req, "Transfer-Encoding");
    const char *ce  = hdr_get(&req, "Content-Encoding");

    bool method_ok = (strcasecmp(req.method, "POST") == 0 ||
                      strcasecmp(req.method, "PUT")  == 0 ||
                      strcasecmp(req.method, "PATCH") == 0);

    size_t body_len = 0;
    bool eligible = method_ok
                 && !te                       /* chunked: not rewritable here */
                 && !ce                       /* already encoded              */
                 && is_json_content_type(ct)
                 && parse_content_length(cl, &body_len)
                 && body_len >= g_min_compress;

    ufd = connect_upstream();
    if (ufd < 0) goto cleanup;

    if (!eligible) {
        /* Forward verbatim: inbuf still holds the headers AND any body
         * bytes that arrived in the same segment. Send the lot, then pump. */
        ZX_BUMP(zx_passthrough);
        if (write_all(ufd, inbuf.data, inbuf.len) != 0) goto cleanup;
        pump_bidir(cfd, ufd);
        goto cleanup;
    }

    /* ---- reassemble exactly body_len bytes ---- */

    size_t have = inbuf.len - (size_t)hend;          /* already buffered */
    if (have > body_len) have = body_len;            /* ignore pipelining */

    if (buf_reserve(&body, body_len) != 0) goto cleanup;   /* one alloc,
                                                            * exact size   */
    if (buf_append(&body, inbuf.data + hend, have) != 0) goto cleanup;

    while (body.len < body_len) {
        size_t want = body_len - body.len;
        if (want > READ_CHUNK) want = READ_CHUNK;
        ssize_t r = recv(cfd, body.data + body.len, want, 0);
        if (r < 0) { if (errno == EINTR) continue; goto cleanup; }
        if (r == 0) goto cleanup;                    /* truncated body */
        body.len += (size_t)r;
    }

    /* ---- compress ---- */

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* ZSTD_compressBound() is the worst-case output size for this input,
     * including the small expansion zstd may add on incompressible data.
     * Allocating it up front means ZSTD_compress() can never overrun and
     * we never need a second pass. */
    size_t bound = ZSTD_compressBound(body.len);
    cbuf = malloc(bound);
    if (!cbuf) goto cleanup;

    size_t csize;
    if (g_cdict) {
        /* Per-connection context; the CDict itself is shared read-only. */
        ZSTD_CCtx *cctx = ZSTD_createCCtx();
        if (!cctx) goto cleanup;
        csize = ZSTD_compress_usingCDict(cctx, cbuf, bound,
                                         body.data, body.len, g_cdict);
        ZSTD_freeCCtx(cctx);
    } else {
        csize = ZSTD_compress(cbuf, bound, body.data, body.len, ZSTD_LEVEL);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double us = (double)(t1.tv_sec - t0.tv_sec) * 1e6
              + (double)(t1.tv_nsec - t0.tv_nsec) / 1e3;

    /* Bail out to pass-through if zstd errored or did not actually win.
     * Never ship a body that got bigger. */
    if (ZSTD_isError(csize) || csize >= body.len) {
        if (ZSTD_isError(csize))
            fprintf(stderr, "[z-egress] zstd: %s (passthrough)\n",
                    ZSTD_getErrorName(csize));
        ZX_BUMP(zx_fallback);
        if (write_all(ufd, inbuf.data, (size_t)hend) != 0) goto cleanup;
        if (write_all(ufd, body.data, body.len) != 0) goto cleanup;
        relay_until_eof(ufd, cfd);
        goto cleanup;
    }

    ZX_BUMP(zx_transformed);
    ZX_ADD(zx_plain_bytes, body.len);
    ZX_ADD(zx_wire_bytes, csize);

    fprintf(stderr,
            "[z-egress] %s %s  %zu -> %zu B  (%.1f%% saved, dict %u, %.0f us)\n",
            req.method, req.target, body.len, csize,
            100.0 * (1.0 - (double)csize / (double)body.len), g_cdict_id, us);

    /* ---- rebuild the request ---- */

    if (buf_printf(&out, "%s %s %s\r\n",
                   req.method, req.target, req.version) != 0) goto cleanup;

    for (int i = 0; i < req.nhdrs; i++) {
        if (hdr_is_managed(req.hdrs[i].name)) continue;
        if (buf_printf(&out, "%s: %s\r\n",
                       req.hdrs[i].name, req.hdrs[i].value) != 0) goto cleanup;
    }

    if (buf_printf(&out, "Content-Length: %zu\r\n", csize) != 0) goto cleanup;
    if (buf_puts(&out, "Content-Encoding: zstd\r\n") != 0) goto cleanup;
    if (buf_puts(&out, "X-Proxy-Engine: " PROXY_ENGINE "\r\n") != 0) goto cleanup;
    if (buf_printf(&out, "X-Z-Egress-Original-Length: %zu\r\n",
                   body.len) != 0) goto cleanup;
    /* v0.1 does not do connection reuse; closing makes response framing
     * unambiguous so the relay is a simple read-to-EOF. */
    if (buf_puts(&out, "Connection: close\r\n\r\n") != 0) goto cleanup;
    if (buf_append(&out, cbuf, csize) != 0) goto cleanup;

    if (write_all(ufd, out.data, out.len) != 0) goto cleanup;

    relay_until_eof(ufd, cfd);

cleanup:
    /* Single exit point. Every resource is initialised to NULL/-1 above,
     * so this runs correctly no matter which goto got us here, and each
     * resource is released exactly once. */
    free(cbuf);
    buf_free(&out);
    buf_free(&body);
    buf_free(&inbuf);
    if (parsed) req_free(&req);
    if (ufd >= 0) close(ufd);
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
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (rp->ai_family == AF_INET6) {
            int off = 0;   /* accept IPv4-mapped clients too */
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 &&
            listen(fd, LISTEN_BACKLOG) == 0) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Prefer a dual-stack IPv6 listener, but fall back to IPv4 cleanly: many
 * container runtimes have IPv6 disabled, in which case socket(AF_INET6)
 * itself fails with EAFNOSUPPORT even though getaddrinfo() succeeded. */
static int make_listener(const char *port)
{
    int fd = bind_family(port, AF_INET6);
    if (fd < 0) fd = bind_family(port, AF_INET);
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 6) {
        fprintf(stderr,
            "usage: %s <listen_port> <upstream_host> <upstream_port> "
            "[dict_file|http://control-plane/v1/dictionary/<id>] [metrics_port]\n",
            argv[0]);
        return 2;
    }

    /* A peer that vanishes mid-write must not kill the process. */
    signal(SIGPIPE, SIG_IGN);

    g_upstream_host = argv[2];
    g_upstream_port = argv[3];

    zx_start_metrics(argc >= 6 ? atoi(argv[5]) : 0, "egress");

    if (argc >= 5 && load_cdict(argv[4]) == 0)
        fprintf(stderr, "[z-egress] dictionary %u loaded, "
                        "compression floor now %zu B\n",
                g_cdict_id, g_min_compress);

    int lfd = make_listener(argv[1]);
    if (lfd < 0) {
        perror("[z-egress] listen");
        return 1;
    }

    fprintf(stderr,
            "[z-egress] " PROXY_ENGINE " listening on :%s -> %s:%s "
            "(zstd level %d, libzstd %s)\n",
            argv[1], g_upstream_host, g_upstream_port,
            ZSTD_LEVEL, ZSTD_versionString());

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            perror("[z-egress] accept");
            break;
        }

        /* Heap cell carrying the fd to the worker. The worker frees it as
         * its very first action; if pthread_create fails we free it here
         * and close the fd, so neither can leak. */
        int *slot = malloc(sizeof *slot);
        if (!slot) { close(cfd); continue; }
        *slot = cfd;

        pthread_t tid;
        if (pthread_create(&tid, &attr, handle_conn, slot) != 0) {
            free(slot);
            close(cfd);
        }
    }

    pthread_attr_destroy(&attr);
    close(lfd);
    if (g_cdict) ZSTD_freeCDict(g_cdict);
    return 0;
}

/*
 * Out of scope in v0.1, deliberately:
 *   - TLS. This must sit inside the trust boundary, before the mTLS
 *     terminator. Compressing ciphertext gains nothing.
 *   - Chunked request bodies (passed through untouched).
 *   - Connection keep-alive and HTTP/2. Each connection handles one
 *     compressed request then closes.
 *   - Thread-per-connection does not scale past a few thousand
 *     concurrent sockets; epoll or io_uring is the next step.
 *   - Trained zstd dictionaries (ZSTD_createCDict / ZSTD_compress_usingCDict)
 *     are where the real ratio gains on small JSON live.
 */
