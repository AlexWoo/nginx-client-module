/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#ifndef _NGX_REQUEST_URL_H_INCLUDE_
#define _NGX_REQUEST_URL_H_INCLUDE_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * scheme://[user@]host[:port]/path[?args][#fragment]
 */
typedef struct {
    ngx_str_t                   scheme;
    ngx_str_t                   user;
    ngx_str_t                   host;
    ngx_str_t                   port;
    ngx_str_t                   path;
    ngx_str_t                   args;
    ngx_str_t                   fragment;

    ngx_str_t                   host_with_port;
    ngx_str_t                   uri_with_args;
} ngx_request_url_t;


ngx_int_t ngx_parse_request_url(ngx_request_url_t *request_url, ngx_str_t *url);
in_port_t ngx_request_port(ngx_str_t *scheme, ngx_str_t *port);


#endif
