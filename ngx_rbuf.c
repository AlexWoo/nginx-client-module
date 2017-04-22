/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_rbuf_create_conf(ngx_cycle_t *cycle);
static char *ngx_rbuf_init_conf(ngx_cycle_t *cycle, void *conf);

static void ngx_rbuf_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

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

typedef struct {
    ngx_rbtree_t                rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_pool_t                 *pool;
} ngx_rbuf_conf_t;


static ngx_command_t  ngx_rbuf_commands[] = {

      ngx_null_command
};


static ngx_core_module_t  ngx_rbuf_module_ctx = {
    ngx_string("reusable_buf"),
    ngx_rbuf_create_conf,                   /* create conf */
    ngx_rbuf_init_conf                      /* init conf */
};


ngx_module_t  ngx_rbuf_module = {
    NGX_MODULE_V1,
    &ngx_rbuf_module_ctx,                   /* module context */
    ngx_rbuf_commands,                      /* module directives */
    NGX_CORE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rbuf_create_conf(ngx_cycle_t *cycle)
{
    ngx_rbuf_conf_t            *rbcf;

    rbcf = ngx_pcalloc(cycle->pool, sizeof(ngx_rbuf_conf_t));
    if (rbcf == NULL) {
        return NULL;
    }

    return rbcf;
}


static char *
ngx_rbuf_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_rbuf_conf_t            *rbcf = conf;

    rbcf->pool = ngx_create_pool(4096, cycle->log);
    if (rbcf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_rbtree_init(&rbcf->rbtree, &rbcf->sentinel,
                    ngx_rbuf_rbtree_insert_value);

    return NGX_CONF_OK;
}


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

static ngx_rbuf_node_t *
ngx_rbuf_find_node(ngx_rbtree_key_t key, ngx_flag_t create)
{
    ngx_rbuf_conf_t            *rbcf;
    ngx_rbtree_node_t          *p, *node;

    rbcf = (ngx_rbuf_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                            ngx_rbuf_module);

    for (p = rbcf->rbtree.root; p != &rbcf->sentinel;) {
        if (key == p->key) {
            return ngx_rbuf_node(p);
        }

        p = key < p->key ? p->left : p->right;
    }

    if (create == 0) {
        return NULL;
    }

    node = ngx_pcalloc(rbcf->pool, sizeof(ngx_rbuf_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->key = key;
    ngx_rbtree_insert(&rbcf->rbtree, node);

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
    ngx_rbuf_conf_t            *rbcf;

    rbcf = (ngx_rbuf_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                            ngx_rbuf_module);

    rn = ngx_rbuf_find_node(key, 1);
    if (rn == NULL) {
        return NULL;
    }

    rb = rn->rbuf;
    if (rb == NULL) {
        rb = ngx_pcalloc(rbcf->pool, sizeof(ngx_rbuf_t) + key);
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


u_char *
ngx_rbuf_alloc(size_t size)
{
    ngx_rbuf_t                 *rb;

    rb = ngx_rbuf_get_buf(size);

    return rb->buf;
}

void
ngx_rbuf_free(u_char *rb)
{
    ngx_rbuf_t                 *rbuf;

    rbuf = ngx_rbuf_buf(rb);
    ngx_rbuf_put_buf(rbuf);
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
    ngx_rbuf_conf_t            *rbcf;
    ngx_rbtree_node_t          *node;

    rbcf = (ngx_rbuf_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                            ngx_rbuf_module);

    node = rbcf->rbtree.root;
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_rbuf_print()");
    ngx_rbuf_print_recursion(node, &rbcf->sentinel);

#endif
}
