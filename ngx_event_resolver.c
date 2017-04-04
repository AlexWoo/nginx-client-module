/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include "ngx_event_resolver.h"


static void *ngx_event_resolver_create_conf(ngx_cycle_t *cycle);
static char *ngx_event_resolver_init_conf(ngx_cycle_t *cycle, void *conf);

static char *ngx_event_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


typedef struct ngx_event_resolver_ctx_s ngx_event_resolver_ctx_t;

struct ngx_event_resolver_ctx_s {
    ngx_event_resolver_handler_pt   handler;
    void                           *data;
    ngx_event_resolver_ctx_t       *next;
};

typedef struct {
    ngx_msec_t                      resolver_timeout;
    ngx_resolver_t                 *resolver;
    ngx_event_resolver_ctx_t       *free_ctx;
} ngx_event_resolver_conf_t;


static ngx_str_t    event_resolver_name = ngx_string("event_resolver");


static ngx_command_t  ngx_event_resolver_commands[] = {

	{ ngx_string("resolver"),
      NGX_EVENT_CONF|NGX_CONF_1MORE,
      ngx_event_resolver,
      0,
      0,
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_event_resolver_conf_t, resolver_timeout),
      NULL },

	  ngx_null_command
};


ngx_event_module_t  ngx_event_resolver_module_ctx = {
    &event_resolver_name,
    ngx_event_resolver_create_conf,         /* create configuration */
    ngx_event_resolver_init_conf,           /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


/* this module use ngx_cycle->log */
ngx_module_t  ngx_event_resolver_module = {
    NGX_MODULE_V1,
    &ngx_event_resolver_module_ctx,         /* module context */
    ngx_event_resolver_commands,            /* module directives */
    NGX_EVENT_MODULE,                       /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_event_resolver_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_resolver_conf_t      *conf;

    conf = ngx_pcalloc(cycle->pool, sizeof(ngx_event_resolver_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->resolver_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_event_resolver_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_resolver_conf_t      *ercf = conf;

    ngx_conf_init_msec_value(ercf->resolver_timeout, 60000);

    return NGX_CONF_OK;
}

static char *
ngx_event_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_resolver_conf_t      *ercf = conf;

    ngx_str_t                      *value;

    if (ercf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ercf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (ercf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_event_resolver_ctx_t *
ngx_event_resolver_get_ctx()
{
    ngx_event_resolver_ctx_t       *ctx;
    ngx_event_resolver_conf_t      *ercf;

    ercf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_resolver_module);

    ctx = ercf->free_ctx;
    if (ctx == NULL) {
        ctx = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_event_resolver_ctx_t));
    } else {
        ercf->free_ctx = ctx->next;
        ctx->next = NULL;
    }

    return ctx;
}

static void
ngx_event_resolver_put_ctx(ngx_event_resolver_ctx_t *ctx)
{
    ngx_event_resolver_conf_t      *ercf;

    ercf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_resolver_module);

    ctx->next = ercf->free_ctx;
    ercf->free_ctx = ctx;
}

static void
ngx_event_resolver_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_event_resolver_ctx_t       *erctx;

    erctx = ctx->data;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "event resolver, "
                "%V could not be resolved (%i: %s)", &ctx->name, ctx->state,
                ngx_resolver_strerror(ctx->state));
        goto failed;
    }

    erctx->handler(erctx->data, ctx->addrs[0].sockaddr, ctx->addrs[0].socklen);

failed:
    ngx_resolve_name_done(ctx);
    ngx_event_resolver_put_ctx(erctx);
}

void
ngx_event_resolver_start_resolver(ngx_str_t *domain,
        ngx_event_resolver_handler_pt h, void *data)
{
    ngx_event_resolver_conf_t      *ercf;
    ngx_event_resolver_ctx_t       *erctx;
    ngx_resolver_ctx_t             *ctx, temp;

    ercf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_resolver_module);

    temp.name = *domain;

    erctx = ngx_event_resolver_get_ctx();
    if (erctx == NULL) {
        return;
    }
    erctx->handler = h;
    erctx->data = data;

    ctx = ngx_resolve_start(ercf->resolver, &temp);
    if (ctx == NULL) {
        goto failed;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "event resolver, "
                "no resolver defined to resolv %V", domain);
        goto failed;
    }

    ctx->name = *domain;
    ctx->handler = ngx_event_resolver_handler;
    ctx->data = erctx;
    ctx->timeout = ercf->resolver_timeout;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "event resolver, "
                "resolv %V failed", *domain);
        goto failed;
    }

    return;

failed:
    if (ctx == NULL || ctx == NGX_NO_RESOLVER) {
        ngx_resolve_name_done(ctx);
        ngx_event_resolver_put_ctx(erctx);
    }
}

