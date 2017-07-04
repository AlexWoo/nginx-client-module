/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include "ngx_live.h"


static void *ngx_live_create_conf(ngx_cycle_t *cf);
static char *ngx_live_init_conf(ngx_cycle_t *cycle, void *conf);


#define NGX_LIVE_STREAM_LEN     512
#define NGX_LIVE_SERVERID_LEN   512


struct ngx_live_stream_s {
    u_char                      name[NGX_LIVE_STREAM_LEN];

    ngx_live_stream_t          *next;
};

struct ngx_live_server_s {
    u_char                      serverid[NGX_LIVE_SERVERID_LEN];
    ngx_uint_t                  n_stream;
    ngx_flag_t                  deleted;

    ngx_live_server_t          *next;

    ngx_live_stream_t         **streams;
};

typedef struct {
    size_t                      stream_buckets;
    size_t                      server_buckets;

    ngx_live_server_t         **servers;

    ngx_live_server_t          *free_server;
    ngx_live_stream_t          *free_stream;

    ngx_uint_t                  alloc_server_count;
    ngx_uint_t                  free_server_count;

    ngx_uint_t                  alloc_stream_count;
    ngx_uint_t                  free_stream_count;

    ngx_pool_t                 *pool;
} ngx_live_conf_t;


static ngx_command_t  ngx_live_commands[] = {

    { ngx_string("stream_buckets"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      0,
      offsetof(ngx_live_conf_t, stream_buckets),
      NULL },

    { ngx_string("server_buckets"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      0,
      offsetof(ngx_live_conf_t, server_buckets),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_live_module_ctx = {
    ngx_string("live"),
    ngx_live_create_conf,           /* create conf */
    ngx_live_init_conf              /* init conf */
};


ngx_module_t  ngx_live_module = {
    NGX_MODULE_V1,
    &ngx_live_module_ctx,           /* module context */
    ngx_live_commands,              /* module directives */
    NGX_CORE_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_live_create_conf(ngx_cycle_t *cycle)
{
    ngx_live_conf_t            *lcf;

    lcf = ngx_pcalloc(cycle->pool, sizeof(ngx_live_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->stream_buckets = NGX_CONF_UNSET_SIZE;
    lcf->server_buckets = NGX_CONF_UNSET_SIZE;

    return lcf;
}

static char *
ngx_live_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_live_conf_t            *lcf = conf;

    lcf->pool = ngx_create_pool(4096, cycle->log);
    if (lcf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_size_value(lcf->stream_buckets, 10007);
    ngx_conf_init_size_value(lcf->server_buckets, 1031);

    lcf->servers = ngx_pcalloc(lcf->pool,
            sizeof(ngx_live_server_t *) * lcf->server_buckets);
    if (lcf->servers == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_live_server_t **
ngx_live_find_server(ngx_str_t *serverid)
{
    ngx_live_conf_t            *lcf;
    ngx_live_server_t         **psrv;

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    psrv = &lcf->servers[ngx_hash_key(serverid->data, serverid->len)
                         % lcf->server_buckets];
    for (; *psrv; psrv = &(*psrv)->next) {
        if (ngx_strlen((*psrv)->serverid) == serverid->len &&
            ngx_memcmp((*psrv)->serverid, serverid->data, serverid->len) == 0)
        {
            break;
        }
    }

    return psrv;
}

static ngx_live_server_t *
ngx_live_get_server(ngx_str_t *serverid)
{
    ngx_live_conf_t            *lcf;
    ngx_live_server_t          *srv;

    if (serverid->len > NGX_LIVE_SERVERID_LEN - 1) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "serverid too long: %ui", serverid->len);
        return NULL;
    }

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    srv = lcf->free_server;
    if (srv == NULL) {
        srv = ngx_pcalloc(lcf->pool, sizeof(ngx_live_server_t));
        if (srv == NULL) {
            return NULL;
        }

        srv->streams = ngx_pcalloc(lcf->pool,
                sizeof(ngx_live_stream_t *) * lcf->stream_buckets);
        if (srv->streams == NULL) {
            return NULL;
        }

        ++lcf->alloc_server_count;
    } else {
        lcf->free_server = srv->next;
        --lcf->free_server_count;
    }

    *ngx_cpymem(srv->serverid, serverid->data, serverid->len) = 0;
    srv->deleted = 0;
    srv->n_stream = 0;

    return srv;
}

static void
ngx_live_put_server(ngx_live_server_t *server)
{
    ngx_live_conf_t            *lcf;

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    server->next = lcf->free_server;
    lcf->free_server = server;
    ++lcf->free_server_count;
}

static ngx_live_stream_t **
ngx_live_find_stream(ngx_live_server_t *server, ngx_str_t *stream)
{
    ngx_live_conf_t            *lcf;
    ngx_live_stream_t         **pst;

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    pst = &server->streams[ngx_hash_key(stream->data, stream->len)
                           % lcf->stream_buckets];
    for (; *pst; pst = &(*pst)->next) {
        if (ngx_strlen((*pst)->name) == stream->len &&
            ngx_memcmp((*pst)->name, stream->data, stream->len) == 0)
        {
            break;
        }
    }

    return pst;
}

static ngx_live_stream_t *
ngx_live_get_stream(ngx_str_t *stream)
{
    ngx_live_conf_t            *lcf;
    ngx_live_stream_t          *st;

    if (stream->len > NGX_LIVE_STREAM_LEN - 1) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "stream too long: %ui", stream->len);
        return NULL;
    }

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    st = lcf->free_stream;
    if (st == NULL) {
        st = ngx_pcalloc(lcf->pool, sizeof(ngx_live_stream_t));
        ++lcf->alloc_stream_count;
    } else {
        lcf->free_stream = st->next;
        --lcf->free_stream_count;
    }

    *ngx_cpymem(st->name, stream->data, stream->len) = 0;

    return st;
}

static void
ngx_live_put_stream(ngx_live_stream_t *st)
{
    ngx_live_conf_t            *lcf;

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    st->next = lcf->free_stream;
    lcf->free_stream = st;
    ++lcf->free_stream_count;
}

ngx_live_server_t *
ngx_live_create_server(ngx_str_t *serverid)
{
    ngx_live_server_t         **psrv;

    psrv = ngx_live_find_server(serverid);
    if (*psrv) {
        (*psrv)->deleted = 0;
        return *psrv;
    }

    *psrv = ngx_live_get_server(serverid);

    return *psrv;
}

void
ngx_live_delete_server(ngx_str_t *serverid)
{
    ngx_live_server_t         **psrv, *srv;

    psrv = ngx_live_find_server(serverid);
    if (*psrv == NULL) {
        return;
    }

    if ((*psrv)->n_stream != 0) {
        (*psrv)->deleted = 1;
    }

    if ((*psrv)->n_stream == 0) {
        srv = *psrv;
        *psrv = srv->next;
        ngx_live_put_server(srv);
    }
}

ngx_live_stream_t *
ngx_live_create_stream(ngx_str_t *serverid, ngx_str_t *stream)
{
    ngx_live_server_t         **psrv;
    ngx_live_stream_t         **pst;

    psrv = ngx_live_find_server(serverid);
    if (*psrv == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "server %V does not exist when create stream", serverid);
        return NULL;
    }

    pst = ngx_live_find_stream(*psrv, stream);

    if (*pst) {
        return *pst;
    }

    *pst = ngx_live_get_stream(stream);
    ++(*psrv)->n_stream;

    return *pst;
}

void
ngx_live_delete_stream(ngx_str_t *serverid, ngx_str_t *stream)
{
    ngx_live_server_t         **psrv;
    ngx_live_stream_t         **pst, *st;

    psrv = ngx_live_find_server(serverid);
    if (*psrv == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "server %V does not exist when delete stream", serverid);
        return;
    }

    pst = ngx_live_find_stream(*psrv, stream);
    if (*pst == NULL) {
        return;
    }

    st = *pst;
    *pst = st->next;
    ngx_live_put_stream(st);
    --(*psrv)->n_stream;

    if ((*psrv)->deleted && (*psrv)->n_stream == 0) {
        ngx_live_delete_server(serverid);
    }
}


#if (NGX_DEBUG)
static void
ngx_live_print_stream(ngx_live_stream_t *st, size_t idx)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "\t\t%z Stream(%p %s), next:%p", idx, st, st->name, st->next);
}

static void
ngx_live_print_server(ngx_live_server_t *srv, size_t idx)
{
    ngx_live_conf_t            *lcf;
    ngx_live_stream_t          *st;
    size_t                      i;

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "\t%z Server(%p %s) n_stream:%ui, deleted:%d, next:%p",
            idx, srv, srv->serverid, srv->n_stream, srv->deleted, srv->next);

    for (i = 0; i < lcf->stream_buckets; ++i) {
        st = srv->streams[i];
        while (st) {
            ngx_live_print_stream(st, i);
            st = st->next;
        }
    }
}
#endif

void
ngx_live_print()
{
#if (NGX_DEBUG)
    ngx_live_conf_t            *lcf;
    ngx_live_server_t          *srv;
    size_t                      i;

    lcf = (ngx_live_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_live_module);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "free server, alloc %ui, free %ui",
            lcf->alloc_server_count, lcf->free_server_count);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "free stream, alloc %ui, free %ui",
            lcf->alloc_stream_count, lcf->free_stream_count);

    for (i = 0; i < lcf->server_buckets; ++i) {
        srv = lcf->servers[i];
        while (srv) {
            ngx_live_print_server(srv, i);
            srv = srv->next;
        }
    }
#endif
}
