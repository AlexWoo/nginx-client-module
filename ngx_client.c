/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_event_connect.h>
#include "ngx_client.h"
#include "ngx_event_resolver.h"
#include "ngx_dynamic_resolver.h"
#include "ngx_poold.h"


#define NGX_CLIENT_DISCARD_BUFFER_SIZE  4096


/*
 * stage:
 *      create client
 *      resolving
 *      connecting to server
 *      connected
 *      close
 */


static u_char *
ngx_client_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_client_session_t       *s;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    if (s->connection) {
        p = ngx_snprintf(buf, len, ", server ip: %V",
                &s->connection->addr_text);
        len -= p - buf;
        buf = p;
    }

    p = ngx_snprintf(buf, len, ", server: %V, csession: %p", &s->server, s);
    len -= p - buf;
    buf = p;

    return p;
}

static ngx_int_t
ngx_client_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_client_free_peer(ngx_peer_connection_t *pc, void *data,
        ngx_uint_t state)
{
}

static ngx_int_t
ngx_client_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            (void) ngx_connection_error(c, err,
                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
                == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_client_connected(ngx_client_session_t *s)
{
    ngx_event_t                *wev;

    if (ngx_client_test_connect(s->connection) != NGX_OK) {
        ngx_client_close(s);
        return;
    }

    s->log.action = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &s->log, 0,
            "nginx client connected");

    wev = s->connection->write;

    if (wev->timedout) { /* rev or wev timedout */
        ngx_log_error(NGX_LOG_ERR, &s->log, NGX_ETIMEDOUT,
                "server timed out");
        s->connection->timedout = 1;

        ngx_client_close(s);

        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    s->connected = 1;
    s->peer.tries = 0;

    if (s->client_connected) {
        s->client_connected(s);
    }
}

static void
ngx_client_write_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_client_session_t       *s;
    ngx_int_t                   n;

    c = ev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &s->log, 0,
            "nginx client write handler");

    if (!s->connected) {
        ngx_client_connected(s);

        return;
    }

    if (s->client_send) {
        s->client_send(s);

        return;
    }

    /* write data buffered in s->out */
    if (s->out == NULL) {
        return;
    }

    n = ngx_client_write(s, NULL);
    if (n == NGX_ERROR) {
        ngx_client_close(s);
    }
}

static void
ngx_client_read_discarded(ngx_client_session_t *s)
{
    ngx_int_t                   n;
    ngx_buf_t                   b;
    u_char                      buffer[NGX_CLIENT_DISCARD_BUFFER_SIZE];

    b.start = buffer;
    b.end = buffer + NGX_CLIENT_DISCARD_BUFFER_SIZE;

    for (;;) {
        b.pos = b.last = b.start;

        n = ngx_client_read(s, &b);

        if (n == NGX_ERROR || n == 0) {
            ngx_log_error(NGX_LOG_ERR, &s->log, ngx_errno,
                    "nginx client read discard error");
            ngx_client_close(s);

            return;
        }

        if (n == NGX_AGAIN) {
            return;
        }
    }
}

static void
ngx_client_read_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_client_session_t       *s;

    c = ev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &s->log, 0,
            "nginx client read handler");

    if (!s->connected) {
        ngx_client_connected(s);

        return;
    }

    if (s->client_recv) {
        s->client_recv(s);
    } else {
        /* read and drop */
        ngx_client_read_discarded(s);
    }
}

static void
ngx_client_connect_server(void *data, struct sockaddr *sa, socklen_t socklen)
{
    ngx_client_session_t       *s;
    ngx_connection_t           *c;
    ngx_int_t                   rc;

    s = data;

    if (sa == NULL) {
        ngx_log_error(NGX_LOG_ERR, &s->log, 0,
                "nginx client resolver peer %v failed", &s->server);
        goto failed;
    }

    ngx_inet_set_port(sa, s->port);

    s->peer.sockaddr = sa;
    s->peer.socklen = socklen;
    s->peer.name = &s->server;

    s->log.action = "connecting to server";

    rc = ngx_event_connect_peer(&s->peer);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_ERR, &s->log, ngx_errno,
                "nginx client connect peer failed");
        goto failed;
    }
    s->connection = s->peer.connection;
    c = s->connection;

    if (c->pool == NULL) {
        c->pool = NGX_CREATE_POOL(128, &s->log);
        if (c->pool == NULL) {
            goto failed;
        }
    }

    c->addr_text.data = ngx_pcalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (c->addr_text.data == NULL) {
        goto failed;
    }
    c->addr_text.len = ngx_sock_ntop(sa, socklen, c->addr_text.data,
                                     NGX_SOCKADDR_STRLEN, 1);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, &s->log, 0,
            "nginx client connect server, rc: %i", rc);

    c->log->connection = c->number;

    c->data = s;

    c->write->handler = ngx_client_write_handler;
    c->read->handler = ngx_client_read_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, s->connect_timeout);
        return;
    }

    /* NGX_OK */

    ngx_client_connected(s);

    return;

failed:
    ngx_client_close(s);
}

static void
ngx_client_resolver_server(void *data, ngx_resolver_addr_t *addrs,
        ngx_uint_t naddrs)
{
    ngx_client_session_t       *s;
    ngx_uint_t                  n;

    s = data;

    if (naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, &s->log, ngx_errno,
                "nginx client resolver failed");
        ngx_client_close(s);
        return;
    }

    n = ngx_random() % naddrs;

    ngx_client_connect_server(data, addrs[n].sockaddr, addrs[n].socklen);
}


static void
ngx_client_close_connection(ngx_client_session_t *s)
{
    ngx_connection_t           *c;
    ngx_pool_t                 *pool;

    c = s->connection;

    if (c == NULL || c->destroyed) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &s->log, 0,
            "nginx client close connection");

    s->connected = 0;
    s->connection = NULL;
    c->destroyed = 1;

    pool = c->pool;
    ngx_close_connection(c);
    NGX_DESTROY_POOL(pool);
}


ngx_client_session_t *
ngx_client_create(ngx_str_t *peer, ngx_str_t *local, ngx_flag_t udp,
        ngx_log_t *log)
{
    ngx_client_session_t       *s;
    ngx_pool_t                 *pool;
    ngx_int_t                   rc, n;
    u_char                     *p, *last;
    size_t                      plen;

    if (peer == NULL || peer->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "client init, peer is NULL");
        return NULL;
    }

    pool = NGX_CREATE_POOL(4096, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    s = ngx_pcalloc(pool, sizeof(ngx_client_session_t));
    if (s == NULL) {
        goto clear;
    }
    s->pool = pool;

    /* set log */
    // ci->log.connection not set, should set when connection established
    s->log = ngx_cycle->new_log;
    s->log.handler = ngx_client_log_error;
    s->log.data = s;
    s->log.action = "create client";

    s->log.log_level = NGX_LOG_INFO;

    /* parse peer */
    last = peer->data + peer->len;

#if (NGX_HAVE_INET6)
    if (peer->len && peer->data[0] == '[') {

        p = ngx_strlchr(peer->data, last, ']');

        if (p == NULL || p == last - 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "client init, parse peer %V error", peer);
            goto clear;
        }

        ++p;
    } else
#endif
    {
        p = ngx_strlchr(peer->data, last, ':');
        if (p == NULL) {
            p = last;
        }
    }

    s->server.len = p - peer->data;
    s->server.data = ngx_pcalloc(s->pool, s->server.len);
    if (s->server.data == NULL) {
        goto clear;
    }
    ngx_memcpy(s->server.data, peer->data, peer->len);

    if (p != last) { /* has port */
        if (*p != ':') {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "client init, parse peer %V error", peer);
            goto clear;
        }

        ++p;
        plen = last - p;

        n = ngx_atoi(p, plen);
        if (n < 1 || n > 65535) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "client init, parse peer %V error", peer);
            goto clear;
        }
        s->port = n;
    }

    /* parse local */
    if (local && local->len) {
        s->peer.local = ngx_pcalloc(s->pool, sizeof(ngx_addr_t));
        if (s->peer.local == NULL) {
            goto clear;
        }

        rc = ngx_parse_addr_port(s->pool, s->peer.local, peer->data, peer->len);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "invalid local address \"%V\"",
                    local);
            goto clear;
        }

        s->peer.local->name.data = ngx_pcalloc(s->pool, sizeof(local->len));
        if (s->peer.local->name.data == NULL) {
            goto clear;
        }
        ngx_memcpy(s->peer.local->name.data, local->data, local->len);
        s->peer.local->name.len = local->len;
    }

    /* set default */
    s->connect_timeout = 3000;
    s->send_timeout = 60000;

    s->postpone_output = 1460;

    s->dynamic_resolver = 1;

    /* set peer */
    s->peer.log = &s->log;
    s->peer.get = ngx_client_get_peer;
    s->peer.free = ngx_client_free_peer;
    s->peer.type = udp ? SOCK_DGRAM : SOCK_STREAM;
    s->peer.log_error = NGX_ERROR_INFO;

    return s;

clear:
    NGX_DESTROY_POOL(pool);

    return NULL;
}


void
ngx_client_connect(ngx_client_session_t *s, ngx_log_t *log)
{
    s->log.action = "resolving";

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, &s->log, 0, "nginx client connect %V",
            &s->server);

    /* start connect */
    if (s->dynamic_resolver) {
        ngx_dynamic_resolver_start_resolver(&s->server,
                ngx_client_connect_server, s);
    } else {
        ngx_event_resolver_start_resolver(&s->server,
                ngx_client_resolver_server, s);
    }
}


ngx_int_t
ngx_client_write(ngx_client_session_t *s, ngx_chain_t *out)
{
    off_t                       size;
    ngx_uint_t                  last, flush, sync;
    ngx_chain_t                *cl, *ln, **ll, *chain;
    ngx_connection_t           *c;
    ngx_event_t                *wev;

    c = s->peer.connection;
    wev = c->write;

    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &s->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = s->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "nginx client write, write old buf t:%d f:%d %p, "
                       "pos %p, size: %z file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "nginx client write, zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = out; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(s->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "nginx client write, write new buf t:%d f:%d %p, "
                       "pos %p, size: %z file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "nginx client write, zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "nginx client write, "
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && !flush && out && size < (off_t) s->postpone_output) {
        return NGX_OK;
    }

    if (size == 0 && !(last && c->need_last_buf)) {
        if (last || flush || sync) {
            for (cl = s->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(s->pool, ln);
            }

            s->out = NULL;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "nginx client write, the output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    chain = c->send_chain(c, s->out, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "nginx client write %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    for (cl = s->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(s->pool, ln);
    }

    s->out = chain;

    if (chain) {
        ngx_add_timer(c->write, s->send_timeout);
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client write again");
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (wev->active) { /* if NGX_OK, del write notification */
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_client_read(ngx_client_session_t *s, ngx_buf_t *b)
{
    ngx_connection_t           *c;
    ngx_int_t                   n;

    if (s == NULL || b == NULL) {
        return NGX_ERROR;
    }

    if (b->last == b->end) {
        return NGX_DECLINED;
    }

    c = s->peer.connection;

    n = c->recv(c, b->last, b->end - b->last);

    if (n == 0) {
        return 0;
    }

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    b->last += n;
    s->recv += n;

    return n;
}


void
ngx_client_close(ngx_client_session_t *s)
{
    ngx_client_closed_pt        closed;
    ngx_pool_t                 *pool;

    if (s->closed) {
        return;
    }

    s->log.action = "close";

    s->closed = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &s->log, 0,
            "nginx client close");

    if (s->client_closed) {
        closed = s->client_closed;
        s->client_closed = NULL;

        closed(s);
    }

    ngx_client_close_connection(s);

    pool = s->pool;
    NGX_DESTROY_POOL(pool); /* s alloc from pool */
}
