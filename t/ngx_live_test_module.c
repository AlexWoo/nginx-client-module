#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../ngx_live.h"


static char *ngx_live_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_live_test_commands[] = {

    { ngx_string("live_test"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_live_test,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_live_test_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_live_test_module = {
    NGX_MODULE_V1,
    &ngx_live_test_module_ctx,              /* module context */
    ngx_live_test_commands,                 /* module directives */
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
ngx_live_test_handler(ngx_http_request_t *r)
{
    ngx_str_t                       serverid, stream, elem;
    ngx_live_server_t              *srv;
    ngx_live_stream_t              *st;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "live test handler");

    if (ngx_http_arg(r, (u_char *) "elem", sizeof("elem") - 1,
            &elem) != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_arg(r, (u_char *) "serverid", sizeof("serverid") - 1,
            &serverid) != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (sizeof("server") - 1 == elem.len
        && ngx_memcmp("server", elem.data, elem.len) == 0)
    {
        switch (r->method) {
        case NGX_HTTP_PUT:
        case NGX_HTTP_POST:
            srv = ngx_live_create_server(&serverid);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "server %p", srv);
            break;
        case NGX_HTTP_DELETE:
            ngx_live_delete_server(&serverid);
            break;
        default:
            return NGX_HTTP_BAD_REQUEST;
        }
    } else if (sizeof("stream") - 1 == elem.len
        && ngx_memcmp("stream", elem.data, elem.len) == 0)
    {
        if (ngx_http_arg(r, (u_char *) "stream", sizeof("stream") - 1, &stream)
            != NGX_OK)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        switch (r->method) {
        case NGX_HTTP_PUT:
        case NGX_HTTP_POST:
            st = ngx_live_create_stream(&serverid, &stream);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "stream %p", st);
            break;
        case NGX_HTTP_DELETE:
            ngx_live_delete_stream(&serverid, &stream);
            break;
        default:
            return NGX_HTTP_BAD_REQUEST;
        }
    } else {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_live_print();

    r->headers_out.content_length_n = 0;
    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;

    return ngx_http_send_header(r);
}


static char *
ngx_live_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_live_test_handler;

    return NGX_CONF_OK;
}

