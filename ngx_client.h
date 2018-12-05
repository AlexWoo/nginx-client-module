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


typedef struct {
    ngx_pool_t                 *pool;
    ngx_log_t                   log;

    ngx_addr_t                 *local;
    ngx_str_t                   server;
    in_port_t                   port;

    ngx_msec_t                  connect_timeout;/* connect timeout */
    ngx_msec_t                  send_timeout;   /* send timeout */
    ngx_msec_t                  reconnect;      /* reconnect interval */
    ngx_int_t                   max_retries;    /* -1 for retry all the time */

    ngx_event_t                 reconnect_event;

    int                         type;           /* SOCK_STREAM or SOCK_DGRAM */
    int                         recvbuf;

    size_t                      postpone_output;

    size_t                      limit_rate;
    size_t                      limit_rate_after;
    size_t                      sendfile_max_chunk;

    unsigned                    dynamic_resolver:1;
    unsigned                    cached:1;

                                /* ngx_connection_log_error_e */
    unsigned                    log_error:3;

    ngx_client_session_t       *session;

    /* callback */
    ngx_client_connect_pt       connected;  /* connect or reconnect successd */
    ngx_client_recv_pt          recv;       /* recv msg from peer */
    ngx_client_send_pt          send;       /* send msg to peer */
    ngx_client_closed_pt        closed;     /* finalize connection */
} ngx_client_init_t;


struct ngx_client_session_s {
    ngx_peer_connection_t       peer;

    ngx_connection_t           *connection;

    ngx_pool_t                 *pool;

    void                       *data;

    ngx_chain_t                *out;

    size_t                      recv;       /* recv bytes */

    time_t                      start_sec;

    size_t                      limit_rate;
    size_t                      limit_rate_after;

    unsigned                    connected:1;
    unsigned                    closed:1;

    /* configured */
    ngx_client_init_t          *ci;
};

ngx_client_init_t *ngx_client_init(ngx_str_t *peer, ngx_str_t *local,
        ngx_flag_t udp, ngx_log_t *log);

void ngx_client_set_handler(ngx_client_session_t *s);

ngx_client_session_t *ngx_client_connect(ngx_client_init_t *ci, ngx_log_t *log);

void ngx_client_reconnect(ngx_client_session_t *s);

ngx_int_t ngx_client_write(ngx_client_session_t *s, ngx_chain_t *out);

ngx_int_t ngx_client_read(ngx_client_session_t *s, ngx_buf_t *b);

void ngx_client_close(ngx_client_session_t *s);


#endif
