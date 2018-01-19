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


typedef struct {    /* for http response */
    ngx_list_t                      headers;

    ngx_uint_t                      http_version;
    ngx_uint_t                      status_n;
    ngx_str_t                       status_line;

    ngx_table_elt_t                *status;
    ngx_table_elt_t                *date;
    ngx_table_elt_t                *server;
    ngx_table_elt_t                *connection;

    ngx_table_elt_t                *expires;
    ngx_table_elt_t                *etag;
    ngx_table_elt_t                *x_accel_expires;
    ngx_table_elt_t                *x_accel_redirect;
    ngx_table_elt_t                *x_accel_limit_rate;

    ngx_table_elt_t                *content_type;
    ngx_table_elt_t                *content_length;

    ngx_table_elt_t                *last_modified;
    ngx_table_elt_t                *location;
    ngx_table_elt_t                *accept_ranges;
    ngx_table_elt_t                *www_authenticate;
    ngx_table_elt_t                *transfer_encoding;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                *content_encoding;
#endif

    off_t                           content_length_n;

    unsigned                        connection_type:2;
    unsigned                        chunked:1;
} ngx_http_client_headers_in_t;


typedef struct {
    unsigned                        set_host;
    unsigned                        set_user_agent;
    unsigned                        set_connection;
    unsigned                        set_accept;
} ngx_http_client_headers_set_t;


typedef struct {
    ngx_client_session_t           *session;
    void                           *request;

    /* Request */
    ngx_keyval_t                   *headers;

    ngx_request_url_t               url;

    /* Response */
    ngx_http_status_t               status;
    ngx_http_chunked_t              chunked;
    ngx_int_t                       length;

    /* config */
    ngx_msec_t                      server_header_timeout;
    size_t                          server_header_buffer_size;

    /* runtime */
    off_t                           rbytes;     /* read bytes */
    off_t                           wbytes;     /* write bytes */

    ngx_chain_t                    *chain;

    ngx_http_client_headers_in_t    headers_in;
    ngx_http_client_headers_set_t   headers_set;

    ngx_http_client_handler_pt      read_handler;
    ngx_http_client_handler_pt      write_handler;
} ngx_http_client_ctx_t;


ngx_http_request_t *ngx_http_client_create_request(ngx_str_t *request_url,
        ngx_uint_t method, ngx_uint_t http_version, ngx_keyval_t *headers,
        ngx_log_t *log, ngx_http_client_handler_pt read_handler,
        ngx_http_client_handler_pt write_handler);

ngx_int_t ngx_http_client_send(ngx_http_request_t *hcr, ngx_client_session_t *s,
        void *request, ngx_log_t *log);

ngx_uint_t ngx_http_client_http_version(ngx_http_request_t *hcr);

ngx_uint_t ngx_http_client_status_code(ngx_http_request_t *hcr);

ngx_str_t *ngx_http_client_header_in(ngx_http_request_t *hcr, ngx_str_t *key);

ngx_int_t ngx_http_client_write_body(ngx_http_request_t *hcr, ngx_chain_t *out);

ngx_int_t ngx_http_client_read_body(ngx_http_request_t *hcr, ngx_chain_t **in,
        size_t size);

void ngx_http_client_finalize_request(ngx_http_request_t *hcr,
        ngx_flag_t closed);


#endif
