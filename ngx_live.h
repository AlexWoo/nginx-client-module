/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#ifndef _NGX_LIVE_H_INCLUDED_
#define _NGX_LIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_live_stream_s    ngx_live_stream_t;
typedef struct ngx_live_server_s    ngx_live_server_t;


ngx_live_server_t *ngx_live_create_server(ngx_str_t *serverid);
void ngx_live_delete_server(ngx_str_t *serverid);

ngx_live_stream_t *ngx_live_create_stream(ngx_str_t *serverid,
        ngx_str_t *stream);
void ngx_live_delete_stream(ngx_str_t *serverid, ngx_str_t *stream);

void ngx_live_print();

#endif
