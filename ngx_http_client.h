/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#ifndef _NGX_HTTP_CLIENT_H_INCLUDE_
#define _NGX_HTTP_CLIENT_H_INCLUDE_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_client.h"
#include "ngx_toolkit_misc.h"


#define NGX_HTTP_CLIENT_GET         0
#define NGX_HTTP_CLIENT_HEAD        1
#define NGX_HTTP_CLIENT_POST        2
#define NGX_HTTP_CLIENT_PUT         3
#define NGX_HTTP_CLIENT_DELETE      4
#define NGX_HTTP_CLIENT_MKCOL       5
#define NGX_HTTP_CLIENT_COPY        6
#define NGX_HTTP_CLIENT_MOVE        7
#define NGX_HTTP_CLIENT_OPTIONS     8
#define NGX_HTTP_CLIENT_PROPFIND    9
#define NGX_HTTP_CLIENT_PROPPATCH   10
#define NGX_HTTP_CLIENT_LOCK        11
#define NGX_HTTP_CLIENT_UNLOCK      12
#define NGX_HTTP_CLIENT_PATCH       13
#define NGX_HTTP_CLIENT_TRACE       14

#define NGX_HTTP_CLIENT_VERSION_9   0
#define NGX_HTTP_CLIENT_VERSION_10  1
#define NGX_HTTP_CLIENT_VERSION_11  2
#define NGX_HTTP_CLIENT_VERSION_20  3

typedef void (* ngx_http_client_handler_pt)(void *r, ngx_http_request_t *hcr);


/* create and set http request */

ngx_http_request_t *ngx_http_client_create(ngx_log_t *log,
    ngx_uint_t method, ngx_str_t *url, ngx_keyval_t *headers,
    ngx_http_client_handler_pt send_body, void *request);

void ngx_http_client_set_read_handler(ngx_http_request_t *r,
    ngx_http_client_handler_pt read_handler);

void ngx_http_client_set_write_handler(ngx_http_request_t *r,
    ngx_http_client_handler_pt write_handler);

void ngx_http_client_set_version(ngx_http_request_t *r, ngx_uint_t version);

void ngx_http_client_set_header_timeout(ngx_http_request_t *r,
    ngx_msec_t timeout);

/* send http request */

ngx_int_t ngx_http_client_send(ngx_http_request_t *r);

ngx_http_request_t *ngx_http_client_get(ngx_log_t *log, ngx_str_t *url,
    ngx_keyval_t *headers, void *request);

ngx_http_request_t *ngx_http_client_head(ngx_log_t *log, ngx_str_t *url,
    ngx_keyval_t *headers, void *request);

ngx_http_request_t *ngx_http_client_post(ngx_log_t *log, ngx_str_t *url,
    ngx_keyval_t *headers, ngx_http_client_handler_pt send_body, void *request);


/* get response */

ngx_uint_t ngx_http_client_http_version(ngx_http_request_t *r);

ngx_uint_t ngx_http_client_status_code(ngx_http_request_t *r);

ngx_str_t *ngx_http_client_header_in(ngx_http_request_t *r, ngx_str_t *key);

ngx_int_t ngx_http_client_write_body(ngx_http_request_t *r, ngx_chain_t *out);

ngx_int_t ngx_http_client_read_body(ngx_http_request_t *r, ngx_chain_t **in,
        size_t size);

off_t ngx_http_client_rbytes(ngx_http_request_t *r);

off_t ngx_http_client_wbytes(ngx_http_request_t *r);


/* end request */

void ngx_http_client_detach(ngx_http_request_t *r);

void ngx_http_client_finalize_request(ngx_http_request_t *r, ngx_flag_t closed);

#endif
