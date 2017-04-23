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
 *      rbuf: whether alloc rbuf
 * return:
 *      nginx chain
 */
ngx_chain_t *ngx_get_chainbuf(size_t size, ngx_flag_t rbuf);

/*
 * paras:
 *      cl: nginx chain return by ngx_rtmp_shared_get_chainbuf
 *      rbuf: whether free rbuf
 */
void ngx_put_chainbuf(ngx_chain_t *cl, ngx_flag_t rbuf);

/*
 * only for test
 */
void    ngx_rbuf_print();

#endif
