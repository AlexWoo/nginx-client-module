#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../ngx_rbuf.h"


static char *ngx_rbuf_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_rbuf_test_commands[] = {

    { ngx_string("rbuf_test"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_rbuf_test,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_rbuf_test_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_rbuf_test_module = {
    NGX_MODULE_V1,
    &ngx_rbuf_test_module_ctx,              /* module context */
    ngx_rbuf_test_commands,                 /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rbuf_test_handler(ngx_http_request_t *r)
{
    ngx_str_t                       size;
    ngx_int_t                       key;
    u_char                         *p;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rbuf test handler");

    if (ngx_http_arg(r, (u_char *) "size", sizeof("size") - 1, &size)
            != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    key = ngx_atoi(size.data, size.len);
    p = ngx_rbuf_alloc(key);

    ngx_rbuf_print();

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rbuf free");

    ngx_rbuf_free(p);

    ngx_rbuf_print();

    r->headers_out.content_length_n = 0;
    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;

    return ngx_http_send_header(r);
}


static char *
ngx_rbuf_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_rbuf_test_handler;

    return NGX_CONF_OK;
}

