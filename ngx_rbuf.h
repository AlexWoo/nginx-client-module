/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#ifndef _NGX_EVENT_TIMER_MODULE_H_INCLUDED_
#define _NGX_EVENT_TIMER_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * paras:
 *      size: size for allocate
 * return:
 *      buffer start pos
 */
u_char *ngx_rbuf_alloc(size_t size);

/*
 * paras:
 *      rb: buf start pos
 */
void    ngx_rbuf_free(u_char *rb);

/*
 * only for test
 */
void    ngx_rbuf_print();

#endif
