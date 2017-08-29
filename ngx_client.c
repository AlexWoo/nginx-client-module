/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_event_connect.h>
#include "ngx_client.h"
#include "ngx_event_resolver.h"


static void  ngx_client_connect_server(void *data, ngx_resolver_addr_t *addrs,
        ngx_uint_t naddrs);
static void ngx_client_close_connection(ngx_connection_t *c);


static ngx_addr_t *
ngx_client_get_local(ngx_client_session_t *s)
{
    ngx_addr_t                 *addr;
    ngx_int_t                   rc;

    if (s->ci->local.len == 0) {
        return NULL;
    }

    addr = ngx_pcalloc(s->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NULL;
    }

    rc = ngx_parse_addr(s->pool, addr, s->ci->local.data, s->ci->local.len);

    switch (rc) {
    case NGX_OK:
        addr->name = s->ci->local;
        return addr;

    case NGX_DECLINED:
        ngx_log_error(NGX_LOG_ERR, s->log, 0, "invalid local address \"%V\"",
                &s->ci->local);
        return NULL;

    default:
        return NULL;
    }
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
    ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client connected");

    s->connected = 1;
    s->peer.tries = 0;

    if (s->connect_event.timer_set) {
        ngx_del_timer(&s->connect_event);
    }

    if (s->ci->connected) {
        s->ci->connected(s);
    }
}

void
ngx_client_test_reading(ngx_client_session_t *s)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = s->peer.connection;
    rev = c->read;

    ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client test reading");

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && rev->pending_eof) {
        socklen_t  len;

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
                == -1)
        {
            err = ngx_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_client_close(s);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
            "nginx client test reading  error");

    ngx_client_reconnect(s);

    return;
}

static void
ngx_client_write_handler(ngx_client_session_t *s)
{
    ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client write handler");

    /* write data buffered in s->out */
    ngx_client_write(s, NULL);
}

static void
ngx_client_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_client_session_t       *s;

    c = ev->data;
    s = c->data;

    ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client handler");

    /* async connect failed */
    if (!s->connected && ngx_client_test_connect(c) != NGX_OK) {
        ngx_client_close_connection(c);
        s->peer.connection = NULL;
        return;
    }

    /* async connect successd */
    if (!s->connected) {
        ngx_client_connected(s);

        return;
    }

    if (ev->timedout) { /* rev or wev timedout */
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "server timed out");
        c->timedout = 1;
        ngx_client_reconnect(s);

        return;
    }

    if (ev->write) {
        ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client handler send");
        if (s->ci->send) {
            s->ci->send(s);
        }
    } else {
        ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client handler recv");
        if (s->ci->recv) {
            s->ci->recv(s);
        }
    }
}

static void
ngx_client_connect_server(void *data, ngx_resolver_addr_t *addrs,
        ngx_uint_t naddrs)
{
    ngx_client_session_t       *s;
    ngx_connection_t           *c;
    ngx_int_t                   rc;
    ngx_uint_t                  n;
    struct sockaddr_in         *sin;

    s = data;

    ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client connect server");

    if (naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, s->log, ngx_errno,
                "nginx client resolver failed");
        goto failed;
    }

    n = ngx_random() % naddrs;

    sin = (struct sockaddr_in *) addrs[n].sockaddr;
    sin->sin_port = htons(s->port);

    s->peer.sockaddr = addrs[n].sockaddr;
    s->peer.socklen = addrs[n].socklen;
    s->peer.name = &s->ci->server;

    s->connected = 0;
    rc = ngx_event_connect_peer(&s->peer);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_ERR, s->log, ngx_errno,
                "nginx client connect peer failed");
        goto failed;
    }

    c = s->peer.connection;

    c->data = s;

    c->write->handler = ngx_client_handler;
    c->read->handler = ngx_client_handler;

    if (c->pool == NULL) {
        c->pool = ngx_create_pool(128, s->log);
        if (c->pool == NULL) {
            ngx_client_close(s);
            return;
        }
    }

    c->log = s->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    if (rc == NGX_AGAIN) {
        return;
    }

    /* NGX_OK */

    ngx_client_connected(s);

    return;

failed:
    ngx_client_reconnect(s);
}

static void
ngx_client_connect_timeout(ngx_event_t *ev)
{
    ngx_client_session_t       *s;

    s = ev->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->log, ngx_errno,
                "nginx client connect to server timeout");

        ngx_client_reconnect(s);
    }
}

static ngx_client_session_t *
ngx_client_create_session(ngx_client_init_t *ci)
{
    ngx_client_session_t       *s;
    ngx_pool_t                 *pool;
    u_char                     *port, *last;
    ngx_int_t                   n;
    size_t                      len;

    ngx_log_error(NGX_LOG_INFO, ci->log, 0, "nginx client create session");

    pool = ngx_create_pool(4096, ci->log);
    if (pool == NULL) {
        return NULL;
    }

    s = ngx_pcalloc(pool, sizeof(ngx_client_session_t));
    if (s == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    s->pool = pool;
    s->log = ci->log;

    s->ci = ci;

    /* set ci default value */
    if (ci->connect_timeout == 0) { /* set default reconnect timeout */
        ci->connect_timeout = 3000;
    }

    if (ci->send_timeout == 0) { /* set default send timeout */
        ci->send_timeout = 60000;
    }

    if (ci->type == 0) {
        ci->type = SOCK_STREAM;
    }

    if (ci->postpone_output == 0) {
        ci->postpone_output = 1460;
    }

    ngx_client_set_handler(s);

    s->peer.log = s->log;
    s->peer.get = ngx_client_get_peer;
    s->peer.free = ngx_client_free_peer;
    s->peer.local = ngx_client_get_local(s);
    s->peer.type = s->ci->type;
    s->peer.rcvbuf = s->ci->recvbuf;
    s->peer.cached = s->ci->cached;
    s->peer.log_error = s->ci->log_error;

    last = s->ci->server.data + s->ci->server.len;

    s->host.data = s->ci->server.data;

    port = ngx_strlchr(s->host.data, last, ':');

    if (port) {
        s->host.len = port - s->host.data;
        ++port;

        len = last - port;

        n = ngx_atoi(port, len);

        if (n < 1 || n > 65535) {
            ngx_log_error(NGX_LOG_ERR, s->log, 0, "invalid port");
            return NULL;
        }

        s->port = (in_port_t) n;
    } else {
        s->host.len = s->ci->server.len;
    }

    return s;
}

static void
ngx_client_close_connection(ngx_connection_t *c)
{
    ngx_pool_t                 *pool;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "nginx client close connection");

    c->destroyed = 1;

    pool = c->pool;
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}

void
ngx_client_reconnect(ngx_client_session_t *s)
{
    ngx_log_error(NGX_LOG_INFO, s->log, 0, "nginx client reconnect");

    if (s->ci->max_retries && s->peer.tries > s->ci->max_retries) {
        if (s->ci->closed) {
            s->ci->closed(s);
        }
        ngx_client_close(s);

        return;
    }

    ++s->peer.tries;
    ngx_add_timer(&s->connect_event, s->ci->connect_timeout);
    if (s->peer.connection) {
        ngx_client_close_connection(s->peer.connection);
    }

    ngx_event_resolver_start_resolver(&s->host, ngx_client_connect_server, s);
}

ngx_client_session_t *
ngx_client_connect(ngx_client_init_t *ci)
{
    ngx_client_session_t       *s;

    ngx_log_error(NGX_LOG_INFO, ci->log, 0, "nginx client connect");

    /* create session */
    s = ngx_client_create_session(ci);
    if (s == NULL) {
        return NULL;
    }

    /* set connect timer */
    s->connect_event.data = s;
    s->connect_event.log = s->log;
    s->connect_event.handler = ngx_client_connect_timeout;

    ngx_add_timer(&s->connect_event, s->ci->connect_timeout);

    /* start connect */
    ngx_event_resolver_start_resolver(&s->host, ngx_client_connect_server, s);

    return s;
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
        goto error;
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
            goto error;
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
            goto error;
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
            goto error;
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

        goto error;
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
        goto error;
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
        goto again;
    }

    if (wev->active) { /* if NGX_OK, del write notification */
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            goto error;
        }
    }

    return NGX_OK;

again:
    ngx_add_timer(c->write, s->ci->send_timeout);
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        goto error;
    }

    return NGX_AGAIN;

error:
    ngx_client_reconnect(s);

    return NGX_ERROR;
}

ngx_int_t
ngx_client_read(ngx_client_session_t *s, ngx_chain_t *in)
{
    ngx_connection_t           *c;
    ngx_buf_t                  *b;
    ngx_int_t                   n;
    size_t                      bytes = 0;

    if (s == NULL || in == NULL || in->buf == NULL) {
        return NGX_ERROR;
    }

    c = s->peer.connection;

    b = in->buf;

    for (;;) {
        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_client_reconnect(s);
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_client_reconnect(s);
            }

            return bytes;
        }

        b->last += n;
        bytes += n;

        if (b->end == b->last) { /* buf full */
            return bytes;
        }
    }
}

void
ngx_client_set_handler(ngx_client_session_t *s)
{
    if (s->ci->recv == NULL) {
        s->ci->recv = ngx_client_test_reading;
    }

    if (s->ci->send == NULL) {
        s->ci->send = ngx_client_write_handler;
    }
}

void
ngx_client_close(ngx_client_session_t *s)
{
    ngx_connection_t           *c;
    ngx_pool_t                 *pool;

    c = s->peer.connection;

    ngx_log_error(NGX_LOG_INFO, s->log, 0,
            "nginx client close, connection:%p timeset:%d",
            c, s->connect_event.timer_set);

    if (c == NULL || c->destroyed) {
        goto destroyed;
    }

    ngx_client_close_connection(c);

destroyed:
    if (s->connect_event.timer_set) {
        ngx_del_timer(&s->connect_event);
    }

    pool = s->pool;
    ngx_destroy_pool(pool); /* s alloc from pool */
}
