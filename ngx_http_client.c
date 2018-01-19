/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include "ngx_http_client.h"
#include "ngx_rbuf.h"


static void *ngx_http_client_module_create_conf(ngx_cycle_t *cycle);
static char *ngx_http_client_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_int_t ngx_http_client_process_header_line(ngx_http_request_t *r,
       ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_client_process_content_length(ngx_http_request_t *r,
       ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_client_process_connection(ngx_http_request_t *r,
       ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
       ngx_http_client_process_transfer_encoding(ngx_http_request_t *r,
       ngx_table_elt_t *h, ngx_uint_t offset);

static size_t ngx_http_client_host_len(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset);
static void   ngx_http_client_host_set(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset, ngx_buf_t *b);
static size_t ngx_http_client_user_agent_len(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset);
static void   ngx_http_client_user_agent_set(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset, ngx_buf_t *b);
static size_t ngx_http_client_connection_len(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset);
static void   ngx_http_client_connection_set(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset, ngx_buf_t *b);
static size_t ngx_http_client_accept_len(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset);
static void   ngx_http_client_accept_set(ngx_http_request_t *r,
       ngx_str_t *name, ngx_uint_t offset, ngx_buf_t *b);


static ngx_str_t ngx_http_client_method[] = {
    ngx_string("GET"),
    ngx_string("HEAD"),
    ngx_string("POST"),
    ngx_string("PUT"),
    ngx_string("DELETE"),
    ngx_string("MKCOL"),
    ngx_string("COPY"),
    ngx_string("MOVE"),
    ngx_string("OPTIONS"),
    ngx_string("PROPFIND"),
    ngx_string("PROPPATCH"),
    ngx_string("LOCK"),
    ngx_string("UNLOCK"),
    ngx_string("PATCH"),
    ngx_string("TRACE")
};

static ngx_str_t ngx_http_client_version[] = {
    ngx_string("HTTP/0.9"), /* not support, will not use */
    ngx_string("HTTP/1.0"),
    ngx_string("HTTP/1.1"),
    ngx_string("HTTP/2.0")
};

#define NGX_HTTP_CLIENT_CONNECTION_CLOSE        1
#define NGX_HTTP_CLIENT_CONNECTION_KEEP_ALIVE   2
#define NGX_HTTP_CLIENT_CONNECTION_UPGRADE      3


typedef size_t (* ngx_http_client_header_len_pt)(ngx_http_request_t *r,
        ngx_str_t *name, ngx_uint_t offset);
typedef void   (* ngx_http_client_header_set_pt)(ngx_http_request_t *r,
        ngx_str_t *name, ngx_uint_t offset, ngx_buf_t *b);

typedef struct {
    ngx_str_t                       name;
    ngx_uint_t                      offset;
    ngx_http_client_header_len_pt   header_len;
    ngx_http_client_header_set_pt   header_set;
} ngx_http_client_fill_header_t;


typedef struct {
    ngx_hash_t                      headers_in_hash;
} ngx_http_client_conf_t;


ngx_http_header_t  ngx_http_client_headers_in[] = {

    { ngx_string("Status"), offsetof(ngx_http_client_headers_in_t, status),
                 ngx_http_client_process_header_line },

    { ngx_string("Date"), offsetof(ngx_http_client_headers_in_t, date),
                 ngx_http_client_process_header_line },

    { ngx_string("Server"), offsetof(ngx_http_client_headers_in_t, server),
                 ngx_http_client_process_header_line },

    { ngx_string("Connection"),
                 offsetof(ngx_http_client_headers_in_t, connection),
                 ngx_http_client_process_connection },

    { ngx_string("Expires"), offsetof(ngx_http_client_headers_in_t, expires),
                 ngx_http_client_process_header_line },

    { ngx_string("ETag"), offsetof(ngx_http_client_headers_in_t, etag),
                 ngx_http_client_process_header_line },

    { ngx_string("X-Accel-Expires"),
                 offsetof(ngx_http_client_headers_in_t, x_accel_expires),
                 ngx_http_client_process_header_line },

    { ngx_string("X-Accel-Redirect"),
                 offsetof(ngx_http_client_headers_in_t, x_accel_redirect),
                 ngx_http_client_process_header_line },

    { ngx_string("X-Accel-Limit-Rate"),
                 offsetof(ngx_http_client_headers_in_t, x_accel_limit_rate),
                 ngx_http_client_process_header_line },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_client_headers_in_t, content_type),
                 ngx_http_client_process_header_line },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_client_headers_in_t, content_length),
                 ngx_http_client_process_content_length },

    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_client_headers_in_t, last_modified),
                 ngx_http_client_process_header_line },

    { ngx_string("Location"), offsetof(ngx_http_client_headers_in_t, location),
                 ngx_http_client_process_header_line },

    { ngx_string("Accept-Ranges"),
                 offsetof(ngx_http_client_headers_in_t, accept_ranges),
                 ngx_http_client_process_header_line },

    { ngx_string("WWW-Authenticate"),
                 offsetof(ngx_http_client_headers_in_t, www_authenticate),
                 ngx_http_client_process_header_line },

    { ngx_string("Transfer-Encoding"),
                 offsetof(ngx_http_client_headers_in_t, transfer_encoding),
                 ngx_http_client_process_transfer_encoding },

#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
                 offsetof(ngx_http_client_headers_in_t, content_encoding),
                 ngx_http_client_process_header_line },
#endif

    { ngx_null_string, 0, NULL }
};

ngx_http_client_fill_header_t ngx_http_client_fill_header[] = {

    { ngx_string("Host"), offsetof(ngx_http_client_headers_set_t, set_host),
      ngx_http_client_host_len, ngx_http_client_host_set },

    { ngx_string("User-Agent"),
      offsetof(ngx_http_client_headers_set_t, set_user_agent),
      ngx_http_client_user_agent_len, ngx_http_client_user_agent_set },

    { ngx_string("Connection"),
      offsetof(ngx_http_client_headers_set_t, set_connection),
      ngx_http_client_connection_len, ngx_http_client_connection_set },

    { ngx_string("Accept"),
      offsetof(ngx_http_client_headers_set_t, set_accept),
      ngx_http_client_accept_len, ngx_http_client_accept_set },

    { ngx_null_string, 0, NULL, NULL }
};


static ngx_command_t    ngx_http_client_commands[] = {

      ngx_null_command
};


static ngx_core_module_t    ngx_http_client_module_ctx = {
    ngx_string("http_client"),
    ngx_http_client_module_create_conf,
    ngx_http_client_init_conf
};


ngx_module_t  ngx_http_client_module = {
    NGX_MODULE_V1,
    &ngx_http_client_module_ctx,           /* module context */
    ngx_http_client_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_client_module_create_conf(ngx_cycle_t *cycle)
{
    ngx_http_client_conf_t     *hccf;

    hccf = ngx_pcalloc(cycle->pool, sizeof(ngx_http_client_conf_t));
    if (hccf == NULL) {
        return NULL;
    }

    return hccf;
}

static char *
ngx_http_client_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_http_upstream_main_conf_t  *hccf = conf;

    ngx_array_t                     headers_in;
    ngx_hash_key_t                 *hk;
    ngx_hash_init_t                 hash;
    ngx_http_header_t              *header;

    /* upstream_headers_in_hash */

    if (ngx_array_init(&headers_in, cycle->pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (header = ngx_http_client_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &hccf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = cycle->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_client_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
       ngx_uint_t offset)
{
    ngx_table_elt_t           **ph;
    ngx_http_client_ctx_t      *ctx;

    ctx = r->ctx[0];

    ph = (ngx_table_elt_t **) ((char *) &ctx->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_client_process_content_length(ngx_http_request_t *r,
       ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;

    ctx = r->ctx[0];

    if (ctx->headers_in.content_length != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "duplicate Content-Length header, %V: %V", &h->key, &h->value);
        return NGX_ERROR;
    }

    ctx->headers_in.content_length = h;
    ctx->headers_in.content_length_n = ngx_atoof(h->value.data, h->value.len);

    return NGX_OK;
}

static ngx_int_t
ngx_http_client_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
       ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;

    ctx = r->ctx[0];

    ctx->headers_in.connection = h;

    if (ngx_strcasestrn(h->value.data, "close", 5)) {
        ctx->headers_in.connection_type = NGX_HTTP_CLIENT_CONNECTION_CLOSE;
    } else if (ngx_strcasestrn(h->value.data, "keep-alive", 10)) {
        ctx->headers_in.connection_type = NGX_HTTP_CLIENT_CONNECTION_KEEP_ALIVE;
    } else if (ngx_strcasestrn(h->value.data, "upgrade", 7)) {
        ctx->headers_in.connection_type = NGX_HTTP_CLIENT_CONNECTION_UPGRADE;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_client_process_transfer_encoding(ngx_http_request_t *r,
       ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;

    ctx = r->ctx[0];

    ctx->headers_in.transfer_encoding = h;

    if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "chunked", 7 - 1)
            != NULL)
    {
        ctx->headers_in.chunked = 1;
    }

    return NGX_OK;
}

static size_t
ngx_http_client_host_len(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;
    size_t                      len;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return 0;
    }

    len = name->len + sizeof(": ") - 1 + ctx->url.host_with_port.len
        + sizeof(CRLF) - 1;

    return len;
}

static void
ngx_http_client_host_set(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset, ngx_buf_t *b)
{
    ngx_http_client_ctx_t      *ctx;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return;
    }

    b->last = ngx_cpymem(b->last, name->data, name->len);
    *b->last++ = ':'; *b->last++ = ' ';
    b->last = ngx_cpymem(b->last, ctx->url.host_with_port.data,
                         ctx->url.host_with_port.len);
    *b->last++ = CR; *b->last++ = LF;
}

static size_t
ngx_http_client_user_agent_len(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;
    size_t                      len;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return 0;
    }

    len = name->len + sizeof(": ") - 1 + ngx_strlen(NGINX_VER)
        + sizeof(CRLF) - 1;

    return len;
}

static void
ngx_http_client_user_agent_set(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset, ngx_buf_t *b)
{
    ngx_http_client_ctx_t      *ctx;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return;
    }

    b->last = ngx_cpymem(b->last, name->data, name->len);
    *b->last++ = ':'; *b->last++ = ' ';
    b->last = ngx_cpymem(b->last, NGINX_VER, ngx_strlen(NGINX_VER));
    *b->last++ = CR; *b->last++ = LF;
}

static size_t
ngx_http_client_connection_len(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;
    size_t                      len;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return 0;
    }

    len = name->len + sizeof(": ") - 1;

    if (r->http_version >= NGX_HTTP_CLIENT_VERSION_11) {
        len += sizeof("keep-alive") - 1;
    } else {
        len += sizeof("close") - 1;
    }

    len += sizeof(CRLF) - 1;

    return len;
}

static void
ngx_http_client_connection_set(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset, ngx_buf_t *b)
{
    ngx_http_client_ctx_t      *ctx;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return;
    }

    b->last = ngx_cpymem(b->last, name->data, name->len);
    *b->last++ = ':'; *b->last++ = ' ';

    if (r->http_version >= NGX_HTTP_CLIENT_VERSION_11) {
        b->last = ngx_cpymem(b->last, "keep-alive", sizeof("keep-alive") - 1);
    } else {
        b->last = ngx_cpymem(b->last, "close", sizeof("close") - 1);
    }

    *b->last++ = CR; *b->last++ = LF;
}

static size_t
ngx_http_client_accept_len(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset)
{
    ngx_http_client_ctx_t      *ctx;
    size_t                      len;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return 0;
    }

    len = name->len + sizeof(": ") - 1 + sizeof("*/*") - 1 + sizeof(CRLF) - 1;

    return len;
}

static void
ngx_http_client_accept_set(ngx_http_request_t *r, ngx_str_t *name,
        ngx_uint_t offset, ngx_buf_t *b)
{
    ngx_http_client_ctx_t      *ctx;
    unsigned                   *flag;

    ctx = r->ctx[0];

    flag = (unsigned *) ((char *) &ctx->headers_set + offset);

    if (*flag) { /* header has been set */
        return;
    }

    b->last = ngx_cpymem(b->last, name->data, name->len);
    *b->last++ = ':'; *b->last++ = ' ';
    b->last = ngx_cpymem(b->last, "*/*", sizeof("*/*") - 1);
    *b->last++ = CR; *b->last++ = LF;
}

static void
ngx_http_client_free_request(ngx_http_request_t *hcr)
{
    ngx_http_client_ctx_t      *ctx;
    ngx_client_session_t       *s;
    ngx_pool_t                 *pool;
    ngx_http_cleanup_t         *cln;

    if (hcr->pool == NULL) {
        return;
    }

    cln = hcr->cleanup;
    hcr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ctx = hcr->ctx[0];
    s = ctx->session;

    if (s) {
        s->ci->recv = NULL;
        s->ci->send = NULL;
        s->ci->closed = NULL;
        s->out = NULL;
    }

    pool = hcr->pool;
    hcr->pool = NULL;

    ngx_destroy_pool(pool);
}

static void
ngx_http_client_close_handler(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;

    r = s->data;

    ngx_http_client_free_request(r);
    ngx_client_close(s);
}

static void
ngx_http_client_read_handler(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;

    r = s->data;
    ctx = r->ctx[0];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client, read handler");

    ctx->read_handler(ctx->request, r);
}

static void
ngx_http_client_process_header(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;
    ngx_buf_t                  *b;
    ngx_connection_t           *c;
    ngx_int_t                   n, rc;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_client_conf_t     *hccf;
    ngx_event_t                *rev;

    hccf = (ngx_http_client_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                   ngx_http_client_module);

    r = s->data;
    c = r->connection;
    ctx = r->ctx[0];
    rev = r->connection->read;

    b = c->buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client, process header");

    for (;;) {

        rc = ngx_http_parse_header_line(r, b, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&ctx->headers_in.headers);
            if (h == NULL) {
                goto error;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                goto error;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&hccf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                goto error;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http server header: \"%V: %V\"", &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http server header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (ctx->headers_in.server == NULL) {
                h = ngx_list_push(&ctx->headers_in.headers);
                if (h == NULL) {
                    goto error;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (ctx->headers_in.date == NULL) {
                h = ngx_list_push(&ctx->headers_in.headers);
                if (h == NULL) {
                    goto error;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            /* clear content length if response is chunked */

            if (ctx->headers_in.chunked) {
                ctx->headers_in.content_length_n = -1;
            }

            break;
        }

        if (rc == NGX_AGAIN) {
            n = ngx_client_read(s, b);

            if (n == NGX_ERROR || n == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "http client, process header read error");
                ngx_http_client_finalize_request(r, 1);
                return;
            }

            if (n == NGX_AGAIN) {
                if (!rev->timer_set) {
                    ngx_add_timer(rev, ctx->server_header_timeout);
                }

                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    ngx_http_client_finalize_request(r, 1);
                    return;
                }

                return;
            }

            /* NGX_OK */

            continue;
        }

        /* there was error while a header line parsing */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http client, http server sent invalid header");

        goto error;
    }

    s->ci->recv = ngx_http_client_read_handler;

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    return ngx_http_client_read_handler(s);

error:
    ngx_http_client_finalize_request(r, 1);
}

static void
ngx_http_client_process_status_line(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;
    ngx_buf_t                  *b;
    ngx_connection_t           *c;
    ngx_int_t                   n, rc;
    ngx_event_t                *rev;

    r = s->data;
    c = r->connection;
    ctx = r->ctx[0];
    rev = r->connection->read;

    b = c->buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client, process status line");

    for (;;) {
        rc = ngx_http_parse_status_line(r, b, &ctx->status);

        if (rc == NGX_AGAIN) {
            n = ngx_client_read(s, b);

            if (n == NGX_ERROR || n == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "http client, process status line read error");
                ngx_http_client_finalize_request(r, 1);
                return;
            }

            if (n == NGX_AGAIN) {
                if (!rev->timer_set) {
                    ngx_add_timer(rev, ctx->server_header_timeout);
                }

                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    ngx_http_client_finalize_request(r, 1);
                    return;
                }

                return;
            }

            /* NGX_OK */

            continue;
        }

        if (rc == NGX_ERROR) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http client, recv no valid HTTP/1.0 header");

            r->http_version = NGX_HTTP_VERSION_9;
        }

        /* NGX_OK */
        break;
    }

    ctx->headers_in.http_version = ctx->status.http_version;
    ctx->headers_in.status_n = ctx->status.code;

    ctx->headers_in.status_line.len = ctx->status.end - ctx->status.start;
    ctx->headers_in.status_line.data = ngx_pcalloc(r->connection->pool,
                                       ctx->headers_in.status_line.len);
    if (ctx->headers_in.status_line.data == NULL) {
        ngx_http_client_finalize_request(r, 1);
        return;
    }
    ngx_memcpy(ctx->headers_in.status_line.data, ctx->status.start,
               ctx->headers_in.status_line.len);

    s->ci->recv = ngx_http_client_process_header;
    return ngx_http_client_process_header(s);
}

static void
ngx_http_client_wait_response_handler(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;
    ngx_buf_t                  *b;
    ngx_connection_t           *c;
    size_t                      size;
    ngx_int_t                   n;
    ngx_event_t                *rev;

    r = s->data;
    c = r->connection;
    ctx = r->ctx[0];
    size = ctx->server_header_buffer_size;
    rev = s->connection->read;

    b = c->buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client, process response handler");

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_http_client_finalize_request(r, 1);
            return;
        }

        c->buffer = b;
    } else if (b->start == NULL) {

        b->start = ngx_pcalloc(c->pool, size);
        if (b->start == NULL) {
            ngx_http_client_finalize_request(r, 1);
            return;
        }

        b->last = b->pos = b->start;
        b->end = b->last + size;
    }

    n = ngx_client_read(s, b);
    /*
     * if NGX_ERROR or no bytes read
     * if ngx_client_read return NGX_ERROR, s will reconnect
     * if 0, ngx_http_client_wait_response_handler
     *      will called next read event triggered
     */
    if (n == NGX_ERROR || n == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                "http client, process response handler read error, rc :%i", n);
        ngx_http_client_finalize_request(r, 1);
        return;
    }

    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            ngx_add_timer(rev, ctx->server_header_timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_client_finalize_request(r, 1);
            return;
        }

        return;
    }

    s->ci->recv = ngx_http_client_process_status_line;
    return ngx_http_client_process_status_line(s);
}

static ngx_int_t
ngx_http_client_reinit(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_connection_t           *c;
    ngx_http_client_ctx_t      *ctx;

    r = s->data;
    r->connection = s->peer.connection;
    c = s->peer.connection;

    /* after connect, reinit parse status for status line and chunked */
    ctx = r->ctx[0];
    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;
    ctx->length = 0;
    ctx->chain = NULL;

    s->ci->recv = ngx_http_client_wait_response_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client, reinit");

    /*
     * init ctx->headers_in, headers_in use c->pool,
     * reconnect will destroy and reinit ctx->headsers_in
     */
    ngx_memzero(&ctx->headers_in, sizeof(ngx_http_client_headers_in_t));
    if (ngx_list_init(&ctx->headers_in.headers, c->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    ctx->headers_in.content_length_n = -1;

    /*
     * init ctx->header_set
     */
    ngx_memzero(&ctx->headers_set, sizeof(ngx_http_client_headers_set_t));

    return NGX_OK;
}

static void
ngx_http_client_set_header_flag(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_http_client_fill_header_t  *h;
    ngx_http_client_ctx_t          *ctx;
    unsigned                       *flag;

    ctx = r->ctx[0];

    h = ngx_http_client_fill_header;
    while (h->name.len) {
        if (name->len == h->name.len
            && ngx_memcmp(name->data, h->name.data, name->len) == 0)
        {
            flag = (unsigned *) ((char *) &ctx->headers_set + h->offset);
            *flag = 1;

            return;
        }

        ++h;
    }
}

static size_t
ngx_http_client_default_header_len(ngx_http_request_t *r)
{
    ngx_http_client_fill_header_t  *h;
    size_t                          len;

    len = 0;

    h = ngx_http_client_fill_header;
    while (h->name.len) {
        len += h->header_len(r, &h->name, h->offset);
        ++h;
    }

    return len;
}

static void
ngx_http_client_default_header_set(ngx_http_request_t *r, ngx_buf_t *b)
{
    ngx_http_client_fill_header_t  *h;

    h = ngx_http_client_fill_header;
    while (h->name.len) {
        h->header_set(r, &h->name, h->offset, b);
        ++h;
    }
}

static ngx_buf_t *
ngx_http_client_create_request_buf(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;
    ngx_buf_t                  *b;
    ngx_keyval_t               *h;
    size_t                      len;

    r = s->data;
    ctx = r->ctx[0];

    /* Request Line */
    /* method */
    len = ngx_http_client_method[r->method].len + 1;  /* "GET " */

    /* path + args + fragment */
    if (ctx->url.path.len == 0) {
        /* no path, set "/ " as default */
        len += 2;
    } else {
        /* " uri_escape " */
        len += 1 + ngx_escape_uri(NULL, ctx->url.uri_with_args.data,
               ctx->url.uri_with_args.len, NGX_ESCAPE_URI_COMPONENT) + 1;
    }

    /* version */
    len += sizeof("HTTP/1.x") - 1 + sizeof(CRLF) - 1;

    /* Request Headers */
    /* User set headers */
    h = ctx->headers;
    while (h && h->key.len) {
        len += h->key.len + sizeof(": ") - 1 + h->value.len + sizeof(CRLF) - 1;

        ngx_http_client_set_header_flag(r, &h->key);

        ++h;
    }

    len += ngx_http_client_default_header_len(r);

    /* Request Headers end */
    len += sizeof(CRLF) - 1;

    /* start fill http request */
    b = ngx_create_temp_buf(r->connection->pool, len);
    if (b == NULL) {
        return NULL;
    }

    /* method */
    b->last = ngx_cpymem(b->last, ngx_http_client_method[r->method].data,
                         ngx_http_client_method[r->method].len);
    *b->last++ = ' ';

    /* path + args + fragment */
    *b->last++ = '/';
    if (ctx->url.path.len) {
        b->last = (u_char *) ngx_escape_uri(b->last,
                             ctx->url.uri_with_args.data,
                             ctx->url.uri_with_args.len,
                             NGX_ESCAPE_URI_COMPONENT);
    }
    *b->last++ = ' ';

    /* version */
    b->last = ngx_cpymem(b->last,
                          ngx_http_client_version[r->http_version].data,
                          ngx_http_client_version[r->http_version].len);
    *b->last++ = CR; *b->last++ = LF;

    /* Request Headers */
    ngx_http_client_default_header_set(r, b);

    /* User set headers */
    h = ctx->headers;
    while (h && h->key.len) {
        b->last = ngx_cpymem(b->last, h->key.data, h->key.len);
        *b->last++ = ':'; *b->last++ = ' ';
        b->last = ngx_cpymem(b->last, h->value.data, h->value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    /* Request Headers end */
    *b->last++ = CR; *b->last++ = LF;

    return b;
}

static void
ngx_http_client_send_header(ngx_client_session_t *s)
{
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;
    ngx_buf_t                  *b;
    ngx_chain_t                 out;
    ngx_event_t                *rev;

    r = s->data;
    ctx = r->ctx[0];

    r->connection = s->connection;
    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client, send header");

    if (ngx_http_client_reinit(s) == NGX_ERROR) {
        goto destroy;
    }

    b = ngx_http_client_create_request_buf(s);
    if (b == NULL) {
        goto destroy;
    }
    b->flush = 1;

    out.buf = b;
    out.next = NULL;

    /* send http request header */
    ngx_client_write(s, &out);

    /* user defined, for send body function callback */
    if (ctx->write_handler) {
        ctx->write_handler(ctx->request, r);
    }

    ngx_add_timer(rev, ctx->server_header_timeout);

    return;

destroy:
    ngx_http_client_finalize_request(r, 1);
}

static ngx_int_t
ngx_http_client_body_read_filter(ngx_http_request_t *hcr, ngx_chain_t **in,
        size_t size)
{
    ngx_client_session_t       *s;
    ngx_http_client_ctx_t      *ctx;
    ngx_chain_t               **cl;
    ngx_int_t                   n;
    ngx_event_t                *rev;

    ctx = hcr->ctx[0];
    s = ctx->session;
    rev = hcr->connection->read;

    for (cl = in; *cl; cl = &(*cl)->next);

    if (ctx->length == 0) {
        ctx->length = ctx->headers_in.content_length_n;
    }

    while (1) {
        *cl = ngx_get_chainbuf(size, 1);
        if (hcr->connection->buffer->last != hcr->connection->buffer->pos) {
            (*cl)->buf->pos = hcr->connection->buffer->pos;
            (*cl)->buf->last = hcr->connection->buffer->last;
            hcr->connection->buffer->pos = hcr->connection->buffer->last;
            n = NGX_OK;
        } else {
            n = ngx_client_read(s, (*cl)->buf);

            if (n == 0) {
                ngx_log_error(NGX_LOG_ERR, hcr->connection->log, ngx_errno,
                        "http client, server close");
                return 0;
            }
        }

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, hcr->connection->log, ngx_errno,
                    "http client, body read filter read ERROR");
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN) {
            ngx_put_chainbuf(*cl);
            (*cl) = NULL;

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_client_finalize_request(hcr, 1);
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        n = (*cl)->buf->last - (*cl)->buf->pos;

        ctx->rbytes += n;
        if (ctx->length != -1) {
            ctx->length -= n;
            if (ctx->length <= 0) {
                ngx_log_error(NGX_LOG_INFO, hcr->connection->log, 0,
                    "http client, body read filter read %O bytes", ctx->rbytes);
                return NGX_DONE;
            }
        }

        cl = &(*cl)->next;
    }
}

static ngx_int_t
ngx_http_client_body_chunked_filter(ngx_http_request_t *hcr, ngx_chain_t **in,
        size_t size)
{
    ngx_http_client_ctx_t      *ctx;
    ngx_chain_t               **ll, *cl = NULL;
    ngx_int_t                   rc;

    ctx = hcr->ctx[0];

    if (!ctx->headers_in.chunked) {
        return ngx_http_client_body_read_filter(hcr, in, size);
    }

    rc = ngx_http_client_body_read_filter(hcr, &cl, size);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* NGX_AGAIN */
    ngx_log_error(NGX_LOG_ERR, hcr->connection->log, 0,
            "http client, body filter return %i", rc);

    for (ll = in; *ll; ll = &(*ll)->next);

    for (;;) {

        rc = ngx_http_parse_chunked(hcr, cl->buf, &ctx->chunked);

        ngx_log_error(NGX_LOG_ERR, hcr->connection->log, 0,
                "http client, parse chunked %p %p-%p %p",
                cl->buf->start, cl->buf->pos, cl->buf->last, cl->buf->end);

        if (rc == NGX_OK) {
            /* a chunk has been parsed successfully */
            cl = cl->next;
            if (cl == NULL) {
                return NGX_OK;
            }
            continue;
        }

        if (rc == NGX_AGAIN) {
            ngx_put_chainbuf(cl);
            cl = cl->next;
            if (cl == NULL) {
                return NGX_AGAIN;
            }
            continue;
        }

        if (rc == NGX_DONE) {
            /* a whole response has been parsed successfully */
            return NGX_DONE;
        }

        ngx_log_error(NGX_LOG_ERR, hcr->connection->log, 0,
                "http client, invalid chunked response");

        return NGX_ERROR;
    }
}

ngx_http_request_t *
ngx_http_client_create_request(ngx_str_t *request_url, ngx_uint_t method,
        ngx_uint_t http_version, ngx_keyval_t *headers, ngx_log_t *log,
        ngx_http_client_handler_pt read_handler,
        ngx_http_client_handler_pt write_handler)
{
    ngx_pool_t                 *pool;
    ngx_http_request_t         *r;
    ngx_http_client_ctx_t      *ctx;
    ngx_int_t                   rc;

    if (request_url == NULL || request_url->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "http client, request_url error");
        return NULL;
    }

    pool = ngx_create_pool(4096, log);
    if (pool == NULL) {
        return NULL;
    }

    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        goto destroy;
    }

    r->pool = pool;

    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * 1);
    if (r->ctx == NULL) {
        goto destroy;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_client_ctx_t));
    if (ctx == NULL) {
        goto destroy;
    }
    r->ctx[0] = ctx;

    r->method = method > NGX_HTTP_CLIENT_TRACE ? NGX_HTTP_CLIENT_GET : method;

    r->http_version = http_version > NGX_HTTP_CLIENT_VERSION_20 ?
                      NGX_HTTP_CLIENT_VERSION_11 : http_version;

    r->request_line.data = ngx_pcalloc(r->pool, request_url->len);
    if (r->request_line.data == NULL) {
        goto destroy;
    }
    ngx_memcpy(r->request_line.data, request_url->data, request_url->len);
    r->request_line.len = request_url->len;

    /* set default config */
    ctx->server_header_timeout = 10000;
    ctx->server_header_buffer_size = 2048;

    ctx->headers = headers;
    ctx->read_handler = read_handler;
    ctx->write_handler = write_handler;

    rc = ngx_parse_request_url(&ctx->url, &r->request_line);
    if (rc == NGX_ERROR) {
        goto destroy;
    }

    return r;

destroy:
    if (pool) {
        ngx_destroy_pool(r->pool);
    }

    return NULL;
}

ngx_int_t
ngx_http_client_send(ngx_http_request_t *hcr, ngx_client_session_t *s,
        void *request, ngx_log_t *log)
{
    ngx_client_init_t          *ci;
    ngx_http_client_ctx_t      *ctx;

    if (hcr == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "http client, request is NULL");
        return NGX_ERROR;
    }

    ctx = hcr->ctx[0];

    if (s == NULL) {
        ci = ngx_client_init(&ctx->url.host, NULL, 0, log);
        ci->port = ngx_request_port(&ctx->url.scheme, &ctx->url.port);

        ci->connected = ngx_http_client_send_header;
        ci->closed = ngx_http_client_close_handler;

        s = ngx_client_connect(ci, log);
        if (s == NULL) {
            return NGX_ERROR;
        }

        s->data = hcr;
        ctx->session = s;
        ctx->request = request;
    } else {
        ci = s->ci;

        ci->closed = ngx_http_client_close_handler;

        s->data = hcr;
        ctx->session = s;
        ctx->request = request;

        ngx_http_client_send_header(s);
    }

    return NGX_OK;
}

ngx_uint_t
ngx_http_client_http_version(ngx_http_request_t *hcr)
{
    ngx_http_client_ctx_t      *ctx;

    ctx = hcr->ctx[0];

    return ctx->headers_in.http_version;
}

ngx_uint_t
ngx_http_client_status_code(ngx_http_request_t *hcr)
{
    ngx_http_client_ctx_t      *ctx;

    ctx = hcr->ctx[0];

    return ctx->headers_in.status_n;
}

ngx_str_t *
ngx_http_client_header_in(ngx_http_request_t *hcr, ngx_str_t *key)
{
    ngx_http_client_ctx_t      *ctx;
    ngx_table_elt_t            *h;
    ngx_list_part_t            *part;
    ngx_uint_t                  i;

    ctx = hcr->ctx[0];

    part = &ctx->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; ++i) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == key->len
            && ngx_strncasecmp(h[i].key.data, key->data, key->len) == 0)
        {
            return &h[i].value;
        }
    }

    return NULL;
}

ngx_int_t
ngx_http_client_write_body(ngx_http_request_t *hcr, ngx_chain_t *out)
{
    ngx_http_client_ctx_t      *ctx;
    ngx_client_session_t       *s;

    ctx = hcr->ctx[0];
    s = ctx->session;

    return ngx_client_write(s, out);
}

ngx_int_t
ngx_http_client_read_body(ngx_http_request_t *hcr, ngx_chain_t **in,
        size_t size)
{
    return ngx_http_client_body_chunked_filter(hcr, in, size);
}

void
ngx_http_client_recycle_body(ngx_chain_t *cl)
{
    ngx_chain_t                *l;

    l = cl;
    while (l) {
        ngx_put_chainbuf(l);
        l = cl->next;
        cl = l;
    }
}

void
ngx_http_client_finalize_request(ngx_http_request_t *hcr, ngx_flag_t closed)
{
    ngx_http_client_ctx_t      *ctx;
    ngx_client_session_t       *s;

    ctx = hcr->ctx[0];
    s = ctx->session;

    ngx_http_client_free_request(hcr);

    if (closed) {
        ngx_client_close(s);
    }
}
