/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#ifndef _NGX_RBUF_H_INCLUDED_
#define _NGX_RBUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * paras:
 *      size: buffer size for allocate
 * return:
 *      nginx chain
 */
ngx_chain_t *ngx_get_chainbuf(size_t size);

/*
 * paras:
 *      cl: nginx chain return by ngx_rtmp_shared_get_chainbuf
 */
void ngx_put_chainbuf(ngx_chain_t *cl);

/*
 * only for test
 */
void    ngx_rbuf_print();

#endif
