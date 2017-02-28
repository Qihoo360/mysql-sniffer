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
#include "tcp_conn_pool.h"
#include "hash.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"

#include <string.h>
#include <stdlib.h>
#include <glib.h>

typedef struct conn_pool_t {
    int bucket_size;
    GHashTable **bucket; // value of the hash table is tcp_stream*
    int conn_count;
    int max_conn_count;
    struct tcp_stream *oldest_conn;   // the oldest node in hash table
    struct tcp_stream *newest_conn;   // the newest node int hash table
    GQueue *free_queue;
    int max_free_count;
}conn_pool_t;

static conn_pool_t *conn_pool_ = NULL;

G_INLINE_FUNC void clear_tcp_stream(struct tcp_stream *tcp_obj) {
    del_tcp_closing_timeout(tcp_obj);
    purge_queue(&tcp_obj->server);
    purge_queue(&tcp_obj->client);
    if (tcp_obj->client.data) {
        free(tcp_obj->client.data);
    }
    if (tcp_obj->server.data) { 
        free(tcp_obj->server.data); 
    }

    struct lurker_node *i, *j;
    i = tcp_obj->listeners;
    while (i) {
        j = i->next;
        free(i);
        i = j;
    }
    if (tcp_obj->next_time) {
        tcp_obj->next_time->prev_time = tcp_obj->prev_time;
    }

    if (tcp_obj->prev_time) {
        tcp_obj->prev_time->next_time = tcp_obj->next_time;
    }

    if (tcp_obj == conn_pool_->oldest_conn) {
        conn_pool_->oldest_conn = tcp_obj->prev_time;
    }

    if (tcp_obj == conn_pool_->newest_conn) {
        conn_pool_->newest_conn = tcp_obj->next_time;
    }
}

static void final_free_tcp_stream(struct tcp_stream *tcp_obj) {
    clear_tcp_stream(tcp_obj);
    free(tcp_obj);
    conn_pool_->conn_count--;
}

void conn_pool_init(int bucket_size, int max_conn_count) {
    if (conn_pool_ != NULL) {
        return;
    }   

    int i;
    conn_pool_ = malloc(sizeof(conn_pool_t));
    memset(conn_pool_, 0, sizeof(conn_pool_t));
    conn_pool_->bucket_size = bucket_size;
    conn_pool_->bucket = malloc(sizeof(GHashTable*) * bucket_size);
    for (i = 0; i < bucket_size; i++) {
        conn_pool_->bucket[i] = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
    }
    conn_pool_->max_conn_count = max_conn_count;
    conn_pool_->free_queue = g_queue_new();
    conn_pool_->max_free_count = max_conn_count > 10000 ? 10000 : max_conn_count;
}

void hash_table_each(gpointer key, gpointer value, gpointer user_data) {
    if (value) {
        final_free_tcp_stream(value);
    }
}

void conn_pool_destroy() {
    if (conn_pool_ == NULL) {
        return;
    }
    int i;
    for (i = 0; i < conn_pool_->bucket_size; i++) {
        //GHashTableIter iter;
        gpointer key, value;

        GHashTable *hash_table = conn_pool_->bucket[i];
        /* g_hash_table_iter_init(&iter, hash_table); */
        /* while (g_hash_table_iter_next (&iter, &key, &value)) { */
        /*     if (value) { */
        /*        final_free_tcp_stream(value); */
        /*     } */
        /* } */
        g_hash_table_foreach(hash_table, (GHFunc)hash_table_each, NULL);
        g_hash_table_destroy(hash_table);
    }

    gpointer queue_item = NULL;
    while (queue_item = g_queue_pop_head(conn_pool_->free_queue)) {
        final_free_tcp_stream(queue_item);
    }

    g_queue_free(conn_pool_->free_queue); 
    free(conn_pool_->bucket);
    free(conn_pool_);
    conn_pool_ = NULL;
}


/**
 * when conn count >= max count, kick the oldest conn out
 */
static void remove_oldest_conn() {
    if (!conn_pool_->oldest_conn) {
        return;
    }

    struct lurker_node *i;
    int orig_client_state = conn_pool_->oldest_conn->client.state;
    struct tcp_stream* oldest_conn = conn_pool_->oldest_conn;
    oldest_conn->nids_state = NIDS_TIMED_OUT;
    for (i = oldest_conn->listeners; i; i = i->next) {
        (i->item) (oldest_conn, &i->data);
    }
    conn_pool_del(conn_pool_->oldest_conn);
    if (orig_client_state != TCP_SYN_SENT) {
        // nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, ugly_iphdr, this_tcphdr);
    }
}

/**
 * replace add_new_tcp()
 */
void* conn_pool_add(struct tuple4 *addr_tuple4) {
    //g_assert(conn_pool_ && addr_tuple4);

    gpointer duplicate_tcp = NULL;
    guint hash_key = mkhash(addr_tuple4->saddr, addr_tuple4->source, addr_tuple4->daddr, addr_tuple4->dest);
    int bucket_index = hash_key % conn_pool_->bucket_size;
    GHashTable *hash_table = conn_pool_->bucket[bucket_index];
    if (g_hash_table_lookup_extended(hash_table, &hash_key, NULL, &duplicate_tcp)) {
        return duplicate_tcp;
    }

    if (conn_pool_->conn_count >= conn_pool_->max_conn_count) {
        remove_oldest_conn();
    }
    struct tcp_stream *new_tcp = NULL;
    new_tcp = (struct tcp_stream*) g_queue_pop_head(conn_pool_->free_queue);
    if (!new_tcp) {
        new_tcp = (struct tcp_stream*) malloc(sizeof(struct tcp_stream));
    }
    memset(new_tcp, 0, sizeof(struct tcp_stream));
    guint *hash_key_ptr = g_new(guint, 1);
    *hash_key_ptr = hash_key;
    g_hash_table_insert(hash_table, hash_key_ptr, new_tcp);
    
    if (!conn_pool_->oldest_conn) {
        conn_pool_->oldest_conn = new_tcp;
    }
    if (conn_pool_->newest_conn) {
        conn_pool_->newest_conn->prev_time = new_tcp;
    }
    new_tcp->hash_key = hash_key;
    new_tcp->prev_time = NULL;
    new_tcp->next_time = conn_pool_->newest_conn;
    conn_pool_->newest_conn = new_tcp;

    conn_pool_->conn_count++;
    return new_tcp;
}

void conn_pool_del(struct tcp_stream *tcp_obj) {
    if (tcp_obj == NULL) {
        return;
    }
    
    GHashTable *hash_table = conn_pool_->bucket[tcp_obj->hash_key % conn_pool_->bucket_size];
    g_hash_table_remove(hash_table, &tcp_obj->hash_key);
    clear_tcp_stream(tcp_obj);
    if (g_queue_get_length(conn_pool_->free_queue) >= conn_pool_->max_free_count) {
        free(tcp_obj);
    } else {
        memset(tcp_obj, 0, sizeof(struct tcp_stream));
        g_queue_push_tail(conn_pool_->free_queue, tcp_obj);
    }
    conn_pool_->conn_count--;
}

void* conn_pool_find(struct tuple4 *addr) {
    guint hash_key = mkhash(addr->saddr, addr->source, addr->daddr, addr->dest);
    GHashTable *hash_table = conn_pool_->bucket[hash_key % conn_pool_->bucket_size];
    return g_hash_table_lookup(hash_table, &hash_key);
}
