/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_pool_t              *ngx_rbuf_pool;

static ngx_rbtree_t             ngx_rbuf_rbtree;
static ngx_rbtree_node_t        ngx_rbuf_sentinel;

static ngx_chain_t             *ngx_rbuf_free_chain;

#define ngx_rbuf_node(n) (ngx_rbuf_node_t *) (n)

#define ngx_rbuf_buf(b)                                             \
    (ngx_rbuf_t *) ((u_char *) (b) - offsetof(ngx_rbuf_t, buf))

typedef struct ngx_rbuf_s   ngx_rbuf_t;

struct ngx_rbuf_s {
    ngx_rbtree_key_t            size;
    ngx_rbuf_t                 *next;
    u_char                      buf[];
};

typedef struct {
    ngx_rbtree_node_t           node;
    ngx_rbuf_t                 *rbuf;
} ngx_rbuf_node_t;


static void
ngx_rbuf_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
        ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t         **p;

    for ( ;; ) {

        p = node->key < temp->key ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_int_t
ngx_rbuf_init()
{
    ngx_rbuf_pool = ngx_create_pool(4096, ngx_cycle->log);
    if (ngx_rbuf_pool == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&ngx_rbuf_rbtree, &ngx_rbuf_sentinel,
                    ngx_rbuf_rbtree_insert_value);

    return NGX_OK;
}

static ngx_rbuf_node_t *
ngx_rbuf_find_node(ngx_rbtree_key_t key, ngx_flag_t create)
{
    ngx_rbtree_node_t          *p, *node;

    for (p = ngx_rbuf_rbtree.root; p != &ngx_rbuf_sentinel;) {
        if (key == p->key) {
            return ngx_rbuf_node(p);
        }

        p = key < p->key ? p->left : p->right;
    }

    if (create == 0) {
        return NULL;
    }

    node = ngx_pcalloc(ngx_rbuf_pool, sizeof(ngx_rbuf_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->key = key;
    ngx_rbtree_insert(&ngx_rbuf_rbtree, node);

    return ngx_rbuf_node(node);
}

static void
ngx_rbuf_put_buf(ngx_rbuf_t *node)
{
    ngx_rbuf_node_t            *rn;

    rn = ngx_rbuf_find_node(node->size, 0);
    if (rn == NULL) {
        return;
    }

    node->next = rn->rbuf;
    rn->rbuf = node;
}

static ngx_rbuf_t *
ngx_rbuf_get_buf(ngx_rbtree_key_t key)
{
    ngx_rbuf_node_t            *rn;
    ngx_rbuf_t                 *rb;

    rn = ngx_rbuf_find_node(key, 1);
    if (rn == NULL) {
        return NULL;
    }

    rb = rn->rbuf;
    if (rb == NULL) {
        rb = ngx_pcalloc(ngx_rbuf_pool, sizeof(ngx_rbuf_t) + key);
        if (rb == NULL) {
            return NULL;
        }
        rb->size = key;
    } else {
        rn->rbuf = rb->next;
        rb->next = NULL;
    }

    return rb;
}


static u_char *
ngx_rbuf_alloc(size_t size)
{
    ngx_rbuf_t                 *rb;

    rb = ngx_rbuf_get_buf(size);

    return rb->buf;
}

static void
ngx_rbuf_free(u_char *rb)
{
    ngx_rbuf_t                 *rbuf;

    rbuf = ngx_rbuf_buf(rb);
    ngx_rbuf_put_buf(rbuf);
}


ngx_chain_t *
ngx_get_chainbuf(size_t size, ngx_flag_t rbuf)
{
    ngx_chain_t                *cl;
    u_char                     *p;

    if (ngx_rbuf_pool == NULL) {
        ngx_rbuf_init();
    }

    cl = ngx_rbuf_free_chain;
    if (cl) {
        ngx_rbuf_free_chain = cl->next;
        cl->next = NULL;
    } else {
        p = ngx_pcalloc(ngx_rbuf_pool, sizeof(ngx_chain_t) + sizeof(ngx_buf_t));
        if (p == NULL) {
            return NULL;
        }

        cl = (ngx_chain_t *)p;

        p += sizeof(ngx_chain_t);
        cl->buf = (ngx_buf_t *)p;
    }

    if (rbuf) {
        cl->buf->last = cl->buf->pos = cl->buf->start = ngx_rbuf_alloc(size);
        cl->buf->end = cl->buf->start + size;
    } else {
        cl->buf->pos = cl->buf->last = cl->buf->start = cl->buf->end = NULL;
    }
    cl->buf->memory = 1;

    return cl;
}

void
ngx_put_chainbuf(ngx_chain_t *cl, ngx_flag_t rbuf)
{
    if (ngx_rbuf_pool == NULL) {
        return;
    }

    if (cl == NULL) {
        return;
    }

    if (rbuf) {
        ngx_rbuf_free(cl->buf->pos);
    }
    cl->next = ngx_rbuf_free_chain;
    ngx_rbuf_free_chain = cl;
}


#if (NGX_DEBUG)
static void
ngx_rbuf_print_rbuf_node(ngx_rbuf_node_t *rn)
{
    ngx_rbuf_t                 *rb;

    rb = rn->rbuf;
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "!!!!rn(%p): %ui", rn, rn->node.key);

    while (rb != NULL) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "    rb(%p): %ui", rb, rb->size);
        rb = rb->next;
    }
}

static void
ngx_rbuf_print_recursion(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbuf_node_t            *rn;

    if (node == sentinel) {
        return;
    }

    rn = ngx_rbuf_node(node);
    ngx_rbuf_print_recursion(node->left, sentinel);
    ngx_rbuf_print_rbuf_node(rn);
    ngx_rbuf_print_recursion(node->right, sentinel);
}
#endif

void
ngx_rbuf_print()
{
#if (NGX_DEBUG)
    ngx_rbtree_node_t          *node;
    ngx_chain_t                *cl;

    node = ngx_rbuf_rbtree.root;
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_rbuf_print()");
    ngx_rbuf_print_recursion(node, &ngx_rbuf_sentinel);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_rbuf_free_chain");
    for (cl = ngx_rbuf_free_chain; cl; cl = cl->next) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "    %p", cl);
    }

#endif
}
