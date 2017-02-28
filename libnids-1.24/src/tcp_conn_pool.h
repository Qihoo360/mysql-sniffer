/** 
 *  Copyright (c) 2012, 2015, Qihoo 360 and/or its affiliates. All rights reserved.
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; version 2 of the
 *  License.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301  USA
 */
#ifndef _TCP_CONN_POOL_H_
#define _TCP_CONN_POOL_H_

#include <glib.h>
#include "nids.h"
void conn_pool_init(int bucket_size, int max_conn_size);
void conn_pool_destroy();
void* conn_pool_add(struct tuple4 *addr_tuple4);
void conn_pool_del(struct tcp_stream *tcp_obj);
void* conn_pool_find(struct tuple4 *addr);
#endif
