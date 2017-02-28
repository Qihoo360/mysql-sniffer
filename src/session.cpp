#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <map>
#include <nids.h>
#include <signal.h>

#include "session.h"
#include "sniff-log.h"
#include "util.h"
#include "sniff-config.h"


struct comp_func{
    bool operator ()(const session_key_t& key1, const session_key_t& key2){
        return memcmp(&key1, &key2, sizeof(session_key_t)) > 0;
    }
};

typedef std::map<session_key_t, mysql_session*, comp_func> session_map; 
typedef session_map::iterator session_iterator;
static session_map* g_session_map;

query_info_t* query_info_new(){
    query_info_t* query_info = (query_info_t*)malloc(sizeof(query_info_t));
    memset(query_info, 0, sizeof(query_info_t));

    query_info->alloc_size = MYSQL_SQL_STATEMENT_BUFLEN;
    query_info->data = (char*)malloc(MYSQL_SQL_STATEMENT_BUFLEN);
    query_info->data[0] = '\0';

    return query_info;
}

int query_info_resize(query_info_t* query_info, int size){
    query_info->alloc_size += size;
    query_info->data = (char*)realloc(query_info->data, query_info->alloc_size);

    /* should we handle memory allocating error ? */
    DEBUG_ASSERT(query_info->data != NULL);

    return query_info->alloc_size;
}

void query_info_free(query_info_t* query_info){
    if(query_info != NULL){
        if(query_info->data != NULL){
            free(query_info->data);
        }
        free(query_info);
    }
    return;
}

mysql_session* mysql_session_new(){
    mysql_session* new_session;

    new_session = (mysql_session*)malloc(sizeof(mysql_session));
    memset(new_session, 0, sizeof(mysql_session));

    new_session->state = SESSION_STATE_SERVER_GREET;
    new_session->query_info = query_info_new();
    new_session->dbname = (char*)malloc(MYSQL_DB_NAME_LEN);
    new_session->dbname[0] = '\0';

    //DEBUG_PRINT("new mysql session %p\n", new_session);
    return new_session;
}

void mysql_session_free(mysql_session* sess){
    if(sess != NULL){
        if(sess->user_info != NULL){
            free(sess->user_info);
        }
        if(sess->dbname != NULL){
            free(sess->dbname);
        }
        query_info_free(sess->query_info);
        //DEBUG_PRINT("del mysql session %p\n", sess);
        free(sess);
    }
    return;
}

mysql_session* get_mysql_session(session_key_t* skey){
    session_iterator it = g_session_map->find(*skey);    
    if(it != g_session_map->end()){
        return it->second;
    }
    return NULL;
}

mysql_session* add_mysql_session(session_key_t* skey){
    mysql_session* sess = mysql_session_new();
    sess->skey = *skey;

    session_iterator it = g_session_map->find(*skey);
    if(it != g_session_map->end()){
        mysql_session_free(it->second);
    }

    (*g_session_map)[*skey] = sess;

    return sess;
}

#ifdef ENABLE_TCPREASM
mysql_session* add_mysql_resume_session(session_key_t* skey){
    log_runtime_error("adding resume session: %d:%d -> %d:%d", skey->saddr, skey->source, skey->daddr, skey->dest);
    mysql_session* sess = add_mysql_session(skey);
    sess->state = SESSION_STATE_RESUME_START;

    return sess;
}
#endif

mysql_session* del_mysql_session(session_key_t* skey){
    session_iterator it = g_session_map->find(*skey);
    if(it == g_session_map->end()){
        return NULL;
    }

    mysql_session_free(it->second);
    g_session_map->erase(it);

    return NULL;
}

int session_init(void* data){
    g_session_map = new session_map();
    return 0;
}

int session_fini(){
    session_iterator it = g_session_map->begin();    
    while(it != g_session_map->end()){
        mysql_session_free(it->second);
        it++;
    }
    delete g_session_map;

    return 0;
}

