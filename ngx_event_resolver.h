/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */



#ifndef _NGX_EVENT_TIMER_MODULE_H_INCLUDED_
#define _NGX_EVENT_TIMER_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef void (* ngx_event_resolver_handler_pt)(void *data,
        struct sockaddr *sa, socklen_t socklen);


/*
 * paras:
 *      domain: domain for resolving
 *      h     : callback handler
 *      data  : data for callback
 */
void ngx_event_resolver_start_resolver(ngx_str_t *domain,
        ngx_event_resolver_handler_pt h, void *data);


#endif

