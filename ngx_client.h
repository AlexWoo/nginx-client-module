/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#ifndef _NGX_CLIENT_H_INCLUDED_
#define _NGX_CLIENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_client_session_s     ngx_client_session_t;

typedef void (* ngx_client_connect_pt)(ngx_client_session_t *s);
typedef void (* ngx_client_recv_pt)(ngx_client_session_t *s);
typedef void (* ngx_client_send_pt)(ngx_client_session_t *s);
typedef void (* ngx_client_closed_pt)(ngx_client_session_t *s);


struct ngx_client_session_s {
    ngx_peer_connection_t       peer;
    ngx_str_t                   server;
    in_port_t                   port;

    ngx_connection_t           *connection;

    ngx_pool_t                 *pool;
    ngx_log_t                   log;

    void                       *data;

    ngx_chain_t                *out;

    size_t                      recv;       /* recv bytes */

    ngx_msec_t                  connect_timeout;/* connect timeout */
    ngx_msec_t                  send_timeout;   /* send timeout */

    int                         type;           /* SOCK_STREAM or SOCK_DGRAM */
    int                         recvbuf;

    size_t                      postpone_output;

    unsigned                    dynamic_resolver:1;

    unsigned                    connected:1;
    unsigned                    closed:1;

    /* callback */
    ngx_client_connect_pt       client_connected; /* connect successd */
    ngx_client_recv_pt          client_recv;      /* recv msg from peer */
    ngx_client_send_pt          client_send;      /* send msg to peer */
    ngx_client_closed_pt        client_closed;    /* finalize connection */
};

ngx_client_session_t *ngx_client_create(ngx_str_t *peer, ngx_str_t *local,
        ngx_flag_t udp, ngx_log_t *log);

void ngx_client_connect(ngx_client_session_t *s, ngx_log_t *log);

ngx_int_t ngx_client_write(ngx_client_session_t *s, ngx_chain_t *out);

ngx_int_t ngx_client_read(ngx_client_session_t *s, ngx_buf_t *b);

void ngx_client_close(ngx_client_session_t *s);


#endif
