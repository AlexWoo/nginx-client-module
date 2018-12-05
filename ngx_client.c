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
    ngx_client_init_t          *ci;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ci = log->data;
    s = ci->session;

    if (s && s->connection) {
        p = ngx_snprintf(buf, len, ", server ip: %V",
                &s->connection->addr_text);
        len -= p - buf;
        buf = p;
    }

    p = ngx_snprintf(buf, len, ", server: %V, csession: %p", &ci->server, ci);
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
        ngx_client_reconnect(s);
        return;
    }

    s->ci->log.action = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
            "nginx client connected");

    wev = s->connection->write;

    if (wev->timedout) { /* rev or wev timedout */
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_ETIMEDOUT,
                "server timed out");
        s->connection->timedout = 1;
        ngx_client_reconnect(s);

        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    s->connected = 1;
    s->peer.tries = 0;

    if (s->ci->connected) {
        s->ci->connected(s);
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

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
            "nginx client write handler");

    if (!s->connected) {
        ngx_client_connected(s);

        return;
    }

    if (s->ci->send) {
        s->ci->send(s);

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
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
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

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
            "nginx client read handler");

    if (!s->connected) {
        ngx_client_connected(s);

        return;
    }

    if (s->ci->recv) {
        s->ci->recv(s);
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

    ngx_inet_set_port(sa, s->ci->port);

    s->peer.sockaddr = sa;
    s->peer.socklen = socklen;
    s->peer.name = &s->ci->server;

    s->ci->log.action = "connecting to server";

    rc = ngx_event_connect_peer(&s->peer);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_ERR, &s->ci->log, ngx_errno,
                "nginx client connect peer failed");
        goto failed;
    }
    s->connection = s->peer.connection;
    c = s->connection;

    if (c->pool == NULL) {
        c->pool = NGX_CREATE_POOL(128, &s->ci->log);
        if (c->pool == NULL) {
            ngx_client_reconnect(s);
            return;
        }
    }

    c->addr_text.data = ngx_pcalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (c->addr_text.data == NULL) {
        ngx_client_reconnect(s);
        return;
    }
    c->addr_text.len = ngx_sock_ntop(sa, socklen, c->addr_text.data,
                                     NGX_SOCKADDR_STRLEN, 1);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, &s->ci->log, 0,
            "nginx client connect server, rc: %i", rc);

    c->log->connection = c->number;

    c->data = s;

    c->write->handler = ngx_client_write_handler;
    c->read->handler = ngx_client_read_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, s->ci->connect_timeout);
        return;
    }

    /* NGX_OK */

    ngx_client_connected(s);

    return;

failed:
    ngx_client_reconnect(s);
}

static void
ngx_client_resolver_server(void *data, ngx_resolver_addr_t *addrs,
        ngx_uint_t naddrs)
{
    ngx_client_session_t       *s;
    ngx_uint_t                  n;

    s = data;

    if (naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, &s->ci->log, ngx_errno,
                "nginx client resolver failed");
        ngx_client_reconnect(s);
        return;
    }

    n = ngx_random() % naddrs;

    ngx_client_connect_server(data, addrs[n].sockaddr, addrs[n].socklen);
}

static ngx_client_session_t *
ngx_client_create_session(ngx_client_init_t *ci, ngx_log_t *log)
{
    ngx_client_session_t       *s;

    s = ngx_pcalloc(ci->pool, sizeof(ngx_client_session_t));
    if (s == NULL) {
        goto clear;
    }

    s->pool = ci->pool;

    s->ci = ci;

    s->peer.log = &s->ci->log;
    s->peer.get = ngx_client_get_peer;
    s->peer.free = ngx_client_free_peer;
    s->peer.local = ci->local;
    s->peer.type = ci->type;
    s->peer.rcvbuf = ci->recvbuf;
    s->peer.cached = ci->cached;
    s->peer.log_error = ci->log_error;

    ci->session = s;

    return s;

clear:
    NGX_DESTROY_POOL(ci->pool);

    return NULL;
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

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
            "nginx client close connection");

    s->connected = 0;
    s->connection = NULL;
    c->destroyed = 1;

    pool = c->pool;
    ngx_close_connection(c);
    NGX_DESTROY_POOL(pool);
}

static void
ngx_client_reconnect_handler(ngx_event_t *ev)
{
    ngx_client_session_t       *s;

    s = ev->data;

    ++s->peer.tries;

    s->ci->log.action = "resolving";

    if (s->ci->dynamic_resolver) {
        ngx_dynamic_resolver_start_resolver(&s->ci->server,
                ngx_client_connect_server, s);
    } else {
        ngx_event_resolver_start_resolver(&s->ci->server,
                ngx_client_resolver_server, s);
    }
}


ngx_client_init_t *
ngx_client_init(ngx_str_t *peer, ngx_str_t *local, ngx_flag_t udp,
        ngx_log_t *log)
{
    ngx_client_init_t          *ci;
    ngx_pool_t                 *pool = NULL;
    ngx_int_t                   rc, n;
    u_char                     *p, *last;
    size_t                      plen;

    if (peer == NULL || peer->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "client init, peer is NULL");
        goto clear;
    }

    pool = NGX_CREATE_POOL(4096, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    ci = ngx_pcalloc(pool, sizeof(ngx_client_init_t));
    if (ci == NULL) {
        goto clear;
    }
    ci->pool = pool;

    // ci->log.connection not set, should set when connection established
    ci->log = ngx_cycle->new_log;
    ci->log.handler = ngx_client_log_error;
    ci->log.data = ci;
    ci->log.action = "create client";

    ci->log_error = NGX_LOG_INFO;

    /* parse remote */
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

    ci->server.len = p - peer->data;
    ci->server.data = ngx_pcalloc(ci->pool, ci->server.len);
    if (ci->server.data == NULL) {
        goto clear;
    }
    ngx_memcpy(ci->server.data, peer->data, peer->len);

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
        ci->port = n;
    }

    /* parse local */
    if (local && local->len) {
        ci->local = ngx_pcalloc(ci->pool, sizeof(ngx_addr_t));
        if (ci->local == NULL) {
            goto clear;
        }

        rc = ngx_parse_addr_port(ci->pool, ci->local, peer->data, peer->len);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "invalid local address \"%V\"",
                    local);
            goto clear;
        }

        ci->local->name.data = ngx_pcalloc(ci->pool, sizeof(local->len));
        if (ci->local->name.data == NULL) {
            goto clear;
        }
        ngx_memcpy(ci->local->name.data, local->data, local->len);
        ci->local->name.len = local->len;
    }

    /* set default */
    ci->connect_timeout = 3000;
    ci->send_timeout = 60000;
    ci->reconnect = 1000;
    ci->max_retries = 0;

    ci->type = udp ? SOCK_DGRAM : SOCK_STREAM;

    ci->postpone_output = 1460;

    ci->dynamic_resolver = 1;

    return ci;

clear:
    if (pool) {
        NGX_DESTROY_POOL(pool);
    }

    return NULL;
}

ngx_client_session_t *
ngx_client_connect(ngx_client_init_t *ci, ngx_log_t *log)
{
    ngx_client_session_t       *s;

    /* create session */
    s = ngx_client_create_session(ci, log);
    if (s == NULL) {
        return NULL;
    }

    ci->log.action = "resolving";

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, &ci->log, 0, "nginx client connect %V",
            &s->ci->server);

    /* start connect */
    if (s->ci->dynamic_resolver) {
        ngx_dynamic_resolver_start_resolver(&s->ci->server,
                ngx_client_connect_server, s);
    } else {
        ngx_event_resolver_start_resolver(&s->ci->server,
                ngx_client_resolver_server, s);
    }

    return s;
}

void
ngx_client_reconnect(ngx_client_session_t *s)
{
    if (s->ci->max_retries != -1 &&
            s->peer.tries >= (ngx_uint_t) s->ci->max_retries)
    {
        ngx_client_close(s);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "nginx client reconnect");

    if (s->peer.connection) {
        ngx_client_close_connection(s);
    }

    if (s->ci->reconnect) {
        s->ci->reconnect_event.handler = ngx_client_reconnect_handler;
        s->ci->reconnect_event.data = s;
        s->ci->reconnect_event.log = &s->ci->log;

        ngx_add_timer(&s->ci->reconnect_event, s->ci->reconnect);
    }
}

ngx_int_t
ngx_client_write(ngx_client_session_t *s, ngx_chain_t *out)
{
    off_t                       size, sent, nsent, limit;
    ngx_uint_t                  last, flush, sync;
    ngx_msec_t                  delay;
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

    if (!last && !flush && out && size < (off_t) s->ci->postpone_output) {
        return NGX_OK;
    }

    if (c->write->delayed) {
        return NGX_AGAIN;
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

    if (s->limit_rate) {
        if (s->limit_rate_after == 0) {
            s->limit_rate_after = s->ci->limit_rate_after;
        }

        limit = (off_t) s->limit_rate * (ngx_time() - s->start_sec + 1)
                - (c->sent - s->limit_rate_after);

        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (ngx_msec_t) (- limit * 1000 / s->limit_rate + 1);
            ngx_add_timer(c->write, delay);

            return NGX_AGAIN;
        }

        if (s->ci->sendfile_max_chunk
            && (off_t) s->ci->sendfile_max_chunk < limit)
        {
            limit = s->ci->sendfile_max_chunk;
        }

    } else {
        limit = s->ci->sendfile_max_chunk;
    }

    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "nginx client write limit %O", limit);

    chain = c->send_chain(c, s->out, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "nginx client write %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    if (s->limit_rate) {

        nsent = c->sent;

        if (s->limit_rate_after) {

            sent -= s->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= s->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (ngx_msec_t) ((nsent - sent) * 1000 / s->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    if (limit && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    for (cl = s->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(s->pool, ln);
    }

    s->out = chain;

    if (chain) {
        ngx_add_timer(c->write, s->ci->send_timeout);
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

    s->ci->log.action = "close";

    if (s->ci->reconnect_event.timer_set) {
        ngx_del_timer(&s->ci->reconnect_event);
    }

    s->closed = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
            "nginx client close");

    if (s->ci->closed) {
        closed = s->ci->closed;
        s->ci->closed = NULL;

        closed(s);
    }

    ngx_client_close_connection(s);

    pool = s->pool;
    NGX_DESTROY_POOL(pool); /* s and s->ci alloc from pool */
}
