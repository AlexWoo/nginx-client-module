#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../ngx_request_url.h"
#include "ngx_test_macro.h"


static char *ngx_request_url_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_request_url_test_commands[] = {

    { ngx_string("request_url_test"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_request_url_test,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_request_url_test_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_request_url_test_module = {
    NGX_MODULE_V1,
    &ngx_request_url_test_module_ctx,       /* module context */
    ngx_request_url_test_commands,          /* module directives */
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
ngx_parse_request_url_test(ngx_int_t ret, char *url, char *scheme, char *user,
        char *host, char *port, char *path, char *args, char *fragment,
        char *host_with_port, char *uri_with_args)
{
    ngx_int_t                   _ret;
    ngx_str_t                   _url;
    ngx_request_url_t           rurl;

    ngx_memzero(&rurl, sizeof(ngx_request_url_t));
    _url.data = (u_char *) url;
    _url.len = ngx_strlen(url);

    _ret = ngx_parse_request_url(&rurl, &_url);
    if (ret != _ret) {
        return 0;
    }

    if (_ret == NGX_ERROR) {
        return 1;
    }

#define TEST(para)                                                      \
    if (para == NULL && rurl.para.len) {                                \
        return 0;                                                       \
    } else if (para && ngx_test_str(&rurl.para, para) == NGX_ERROR) {   \
        return 0;                                                       \
    }

    TEST(scheme)
    TEST(user)
    TEST(host)
    TEST(port)
    TEST(path)
    TEST(args)
    TEST(fragment)
    TEST(host_with_port)
    TEST(uri_with_args)

#undef TEST

    return 1;
}

static ngx_int_t
ngx_request_port_test(in_port_t expect, char *scheme, char *port)
{
    in_port_t                   ret;
    ngx_str_t                   _scheme, _port;

    _scheme.data = (u_char *) scheme;
    _scheme.len = ngx_strlen(scheme);

    _port.data = (u_char *) port;
    _port.len = ngx_strlen(port);

    ret = ngx_request_port(&_scheme, &_port);

    return ret == expect;
}

static ngx_int_t
ngx_request_url_test_handler(ngx_http_request_t *r)
{
    ngx_buf_t                  *b;
    ngx_chain_t                 cl;
    size_t                      len;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "request url test handler");

    NGX_TEST_INIT

    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR, "test",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR, "http://",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR, "http://alex@",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK, "http://alex@test",
                "http",
                "alex", "test", NULL,
                NULL, NULL, NULL,
                "test", NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR, "http://alex@test:",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK, "http://alex@test:8080",
                "http",
                "alex", "test", "8080",
                NULL, NULL, NULL,
                "test:8080", NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR, "http://@test:8080",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK, "http://test",
                "http",
                NULL, "test", NULL,
                NULL, NULL, NULL,
                "test", NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR, "http://test:",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK, "http://test:8080",
                "http",
                NULL, "test", "8080",
                NULL, NULL, NULL,
                "test:8080", NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK, "http://test:8080/",
                "http",
                NULL, "test", "8080",
                NULL, NULL, NULL,
                "test:8080", NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK, "http://test:8080/live",
                "http",
                NULL, "test", "8080",
                "live", NULL, NULL,
                "test:8080", "live"));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK,
                "http://alex@test/live/test",
                "http",
                "alex", "test", "8080",
                "live/test", NULL, NULL,
                "test", "live/test"));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR,
                "http://alex@test:80/live/test?",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK,
                "http://alex@test:80/live/test?a=b&c=d",
                "http",
                "alex", "test", "80",
                "live/test", "a=b&c=d", NULL,
                "test:80", "live/test?a=b&c=d"));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_ERROR,
                "http://alex@/live/test?a=b&c=d",
                NULL,
                NULL, NULL, NULL,
                NULL, NULL, NULL,
                NULL, NULL));
    NGX_TEST_ISOK(ngx_parse_request_url_test(NGX_OK,
                "http://alex@test:8080/live/test?a=b&c=d#test",
                "http",
                "alex", "test", "8080",
                "live/test", "a=b&c=d", "test",
                "test:8080", "live/test?a=b&c=d#test"));

    NGX_TEST_ISOK(ngx_request_port_test(0, "", "abcd"));
    NGX_TEST_ISOK(ngx_request_port_test(1234, "", "1234"));
    NGX_TEST_ISOK(ngx_request_port_test(0, "", "102222"));
    NGX_TEST_ISOK(ngx_request_port_test(0, "rtp", ""));
    NGX_TEST_ISOK(ngx_request_port_test(80, "http", ""));
    NGX_TEST_ISOK(ngx_request_port_test(443, "https", ""));
    NGX_TEST_ISOK(ngx_request_port_test(1935, "rtmp", ""));

    r->headers_out.status = NGX_HTTP_OK;

    ngx_http_send_header(r);

    len = sizeof("TEST cases 4294967296, 4294967296 pass\n") - 1;
    b = ngx_create_temp_buf(r->pool, len);

    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_snprintf(b->last, len, "TEST cases %d, %d pass\n",
            count, pass);
    b->last_buf = 1;
    b->last_in_chain = 1;

    cl.buf = b;
    cl.next = NULL;

    return ngx_http_output_filter(r, &cl);
}


static char *
ngx_request_url_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t   *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_request_url_test_handler;

    return NGX_CONF_OK;
}

