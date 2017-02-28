#include <nids.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>

#include "session.h"
#include "mysql-dissector.h"
#include "sniff-log.h"
#include "sniff-config.h"
#include "util.h"

static char* states[] = {
    "SESSION_STATE_SERVER_GREET",
    "SESSION_STATE_LOGIN_RESPONSE",
    "SESSION_STATE_QUERY_RESULT",
    "SESSION_STATE_RESULT_PHASE2",
    "SESSION_STATE_SERVER_MAX",
    "SESSION_STATE_LOGIN_REQUEST",
    "SESSION_STATE_QUERY",
    "SESSION_STATE_CLIENT_MAX",
    "SESSION_STATE_RESUME_START",
    "SESSION_STATE_RESUME_WAIT_SERVER",
    "SESSION_STATE_RESUME_WAIT_CLIENT",
    "SESSION_STATE_MAX"
};

/*
 * sess       the mysql session
 * stream     the server message stream
 * start_pos  the start position we dissect
 * count      count the number of packets, eg. the column packets or row packets
 */
int query_res_find_eof(mysql_session* sess, half_stream* stream, char* start_pos, int* count){
    char* cur_header = start_pos;
    u_char first_byte = 1;
    int unhandled = stream->count - stream->offset - sess->handled_len;
    
    int find = 0;
    while(1){
        if(unhandled < MYSQL_PACKET_HEADER_LEN || unhandled < MYSQL_PACKET_HEADER_LEN + PACKET_LEN(cur_header)){
            find = 0;
            break;
        }
        //log_runtime_error("handled: %d pkt-len: %d, pkt-num: %d\n", stream->count-stream->offset-unhandled, PACKET_LEN(cur_header), PACKET_NUM(cur_header));
        first_byte = *(cur_header + MYSQL_PACKET_HEADER_LEN);
        unhandled -= MYSQL_PACKET_HEADER_LEN + PACKET_LEN(cur_header);
        cur_header += MYSQL_PACKET_HEADER_LEN + PACKET_LEN(cur_header);
        if(first_byte == MYSQL_EOF_MARKER){
            find = 1;
            break;
        }
        (*count)++;
    }
    sess->handled_len = stream->count - stream->offset - unhandled;
    //log_runtime_error("unhandled: %d \n", unhandled);
    return find;
}

int record_query_info(mysql_session* sess, char cmd, int msg_len, char* msg){
    if(msg_len <= 0 || msg == NULL){
        return 0;
    }
    query_info_t* info = sess->query_info;

    gettimeofday(&info->query_end, NULL);

    /* the query is in one packet */
    if(info->query_start.tv_sec == 0){
        info->query_start = info->query_end;
    }
    /* allocate enough memory */
    while(info->alloc_size <= msg_len){
        query_info_resize(info, MYSQL_SQL_STATEMENT_BUFLEN);
    }

    info->cmd = cmd;
    info->count = msg_len;
    memcpy(info->data, msg, msg_len);
    info->data[msg_len] = '\0';

    return 0;
}

int decode_mysql_lenenc_int(const u_char* data, int datalen){
    char value[4] = {0,0,0,0};
    if(*data < MYSQL_LENENC_INT_ONEBYTE){
        return *data;
    }
    switch(*data){
        case MYSQL_LENENC_INT_TWOBYTE:
            if(datalen >= 3){
                value[0] = data[1];
                value[1] = data[2];
            }
            break;
        case MYSQL_LENENC_INT_THREEBYTE:
            if(datalen >= 4){
                value[0] = data[1];
                value[1] = data[2];
                value[2] = data[3];
            }
            break;
        /* don't decode 8-byte integer */
        case MYSQL_LENENC_INT_EIGHTBYTE:
        case MYSQL_LENENC_INT_ERR:
        default:
            break;
    }
    return *(int*)value;
}

int record_db_info(mysql_session* sess, char cmd, int msg_len, char* msg){
    if(msg_len <= 0 || msg == NULL){
        return 0;
    }
    query_info_t* info = sess->query_info;
    
    gettimeofday(&info->query_end, NULL);

    /* the query is in one packet */
    if(info->query_start.tv_sec == 0){
        info->query_start = info->query_end;
    }

    if(msg_len >= MYSQL_DB_NAME_LEN){
        memcpy(sess->dbname, msg, MYSQL_DB_NAME_LEN - 1);
        sess->dbname[MYSQL_DB_NAME_LEN - 1] = '\0';
        snprintf(info->data, info->alloc_size, "use %s", sess->dbname);
        info->count = strlen(info->data);
    }else{
        memcpy(sess->dbname, msg, msg_len);
        sess->dbname[msg_len] = '\0';
        snprintf(info->data, info->alloc_size, "use %s", sess->dbname);
        info->count = strlen(info->data);
    }
    return 0;
}

/*
 * 0  if it is an incomplete mysql packet
 * 1  if it is a complete mysql packet
 */
int mysql_dissect_is_complete(half_stream* stream, mysql_session* sess){
    int pkt_len = PACKET_LEN(stream->data);
    int received_data_len = stream->count - stream->offset;

    if(pkt_len > received_data_len - MYSQL_PACKET_HEADER_LEN){
        /* 
         * this is an incomplete packet, we should wait until the libnids  
         * has buffered all packets and gives us a notification.
         */
        log_runtime_error("Incomplete Query packet! pkt-len: %d received-len:%d", pkt_len, received_data_len);
        //debug_print_stream(stream);
        return 0;
    }else if(pkt_len == received_data_len - MYSQL_PACKET_HEADER_LEN){
        /* that is exactly we want! */
        return 1;
    }else{
        /*we have received more data than one complete packet !!! */
        /* may not happend ? */
        return 1;
    }
    return 1;
}

int mysql_dissect_greet(mysql_session* sess, half_stream* stream){
    log_runtime_error("Server: Greet ");
    debug_print_stream(stream);
    sess->state = SESSION_STATE_LOGIN_REQUEST;

    /*TODO:
     * record the protocol version
     */
    return 0;
}

int mysql_dissect_login_request(mysql_session* sess, half_stream* stream){
    log_runtime_error("Client: Login ");
    //debug_print_stream(stream);
    sess->state = SESSION_STATE_LOGIN_RESPONSE;

    if(!mysql_dissect_is_complete(stream, sess)){
        sess->handled_len = 0;
        return STREAM_DISCARD;
    }

    user_info_t* user_info = (user_info_t*)malloc(sizeof(user_info_t));
    memset(user_info, 0, sizeof(user_info_t));

    /* Refer: http://dev.mysql.com/doc/internals/en/connection-phase-packets.html */
    mysql_login_client_info* client_info = (mysql_login_client_info*)PACKET_MSG(stream->data);
    if(PACKET_LEN(stream->data) > sizeof(mysql_login_client_info)){
        /* get the user name*/
        char* user_name = (char*)client_info + sizeof(mysql_login_client_info);
        int name_len = strlen(user_name);
        strncpy(user_info->username, user_name, MYSQL_USERNAME_MAX_LEN);
        user_info->username[MYSQL_USERNAME_MAX_LEN - 1] = '\0'; 

        /* get the database name */
        if(client_info->capability & CLIENT_CONNECT_WITH_DB){
            /* version 4.1 protocol */
            // TODO: can not assume the mysql is using version 4.1, 
            // see https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
            // 1. first, we need to skip auth field, but auth field is not just the CLIENT_SECURE_CONNECTION flags set,
            // it may be CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA or others.
            // if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA {
            //     lenenc-int     length of auth-response
            //         string[n]      auth-response
            // } else if capabilities & CLIENT_SECURE_CONNECTION {
            //     1              length of auth-response
            //         string[n]      auth-response
            // } else {
            //     string[NUL]    auth-response
            // }
            if(client_info->capability & CLIENT_SECURE_CONNECTION){
                int auth_resp_len = *(user_name + name_len + 1);
                char* dbname = user_name + name_len + auth_resp_len + 1 + 1;
                strncpy(sess->dbname, dbname, MYSQL_DB_NAME_LEN);
                sess->dbname[MYSQL_DB_NAME_LEN - 1] = '\0';
            }
        }
    }

    sess->user_info = user_info;
    return 0;
}

int mysql_dissect_login_resp(mysql_session* sess, half_stream* stream){
    log_runtime_error("Server: Login Response ");
    debug_print_stream(stream);
    sess->state = SESSION_STATE_QUERY;
    /* TODO: add login failed handling */

    return 0;
}

int mysql_handle_client_cmd(mysql_session* sess, char cmd, int msg_len, char* msg){
    int ret = 0;
    switch(cmd){
        case COM_QUIT:
            ret = SESSION_DEL;
            break;
        case COM_QUERY:
            ret = record_query_info(sess, cmd, msg_len, msg);
            sess->state = SESSION_STATE_QUERY_RESULT;
            break; 
        case COM_INIT_DB:
            ret = record_db_info(sess, cmd, msg_len, msg);
            sess->state = SESSION_STATE_QUERY_RESULT;
            break;
        case COM_PING:
            /* we can also set state to SESSION_STATE_RESUME_WAIT_CLIENT 
             * to ignore the server response.
             * the difference is that SESSION_IGNORE_NEXT can only ignore next packet, while 
             * SESSION_STATE_RESUME_WAIT_CLIENT can ignore all packets of next direction.
             * here the response for PING is small enough to be sent in one packet, so they have
             * the same effect.
             * */
            ret = SESSION_IGNORE_NEXT;
            break;
        case COM_BINLOG_DUMP:
            /* TODO: add binlog support. we should add new state to support it. */
            break;
        case COM_STMT_PREPARE:
            /* TODO: */
            break;
        default:
            /* as we cannot determine the type of the client command, we should ignore 
             * all packets of server->client direction later.
             */
            sess->state = SESSION_STATE_RESUME_WAIT_CLIENT;
            break;
    }
    return ret;
}

int mysql_dissect_query(mysql_session* sess, half_stream* stream){
    /*
     * expect the next packet to be the result of the query, however 
     * if the query is too long to send at once, the next packet
     * will still come from client. 
     * In that case we should get the mysql packet length according to its protocol
     * and if we haven't get the whole packet, we just ignore this notification
     * and wait for next.
     */
    if(!mysql_dissect_is_complete(stream, sess)){
        query_info_t* info = sess->query_info;
        DEBUG_ASSERT(info != NULL);
        /* first incomplete request packet */
        if(info->query_start.tv_sec == 0){
            gettimeofday(&info->query_start, NULL);
        }
        sess->handled_len = 0;
        return STREAM_DISCARD;
    }
    char* client_msg = PACKET_MSG(stream->data);
    int pkt_len = PACKET_LEN(stream->data);

    DEBUG_ASSERT(pkt_len >= 1);

    char cmd = MYSQL_COMMAND(client_msg);
    int ret;
    ret = mysql_handle_client_cmd(sess, cmd, pkt_len - MYSQL_COMMAND_LEN, client_msg + MYSQL_COMMAND_LEN);

    return ret;
}


/*looking for the second eof */
int mysql_dissect_query_result_phase2(mysql_session* sess, half_stream* stream){
    log_runtime_error("Entering Server Result Phase2...");
    int ret = 0;

    int second_eof = query_res_find_eof(sess, stream, stream->data, &sess->query_info->row_num);
    if(!second_eof){
        sess->state = SESSION_STATE_RESULT_PHASE2;
        ret = STREAM_DISCARD;
    }else{
        query_info_t* info = sess->query_info;
        gettimeofday(&info->result_end, NULL);
        sess->state = SESSION_STATE_QUERY;
    }

    return ret;
}

int mysql_dissect_query_result(mysql_session* sess, half_stream* stream){
    int ret = 0;

    char* msg = PACKET_MSG(stream->data);
    u_char first_byte = *msg;

    query_info_t* info = sess->query_info;
    gettimeofday(&info->result_start, NULL);

    log_runtime_error("Server: Query Result New data: %d", stream->count - stream->offset);

    /* Response: the length of OK packet is supposed to be greater than 7(header counts in).*/ 
    if(first_byte == 0 && PACKET_LEN(stream->data) >= 3){
        info->result_end = info->result_start;
        sess->state = SESSION_STATE_QUERY;
        /* the size of affect row is not fixed. */
        sess->query_info->row_num = decode_mysql_lenenc_int((const u_char*)msg + 1, PACKET_LEN(stream->data) - 1);
        return 0;
    /* Response: Error packet */
    }else if(first_byte == MYSQL_LENENC_INT_ERR && PACKET_LEN(stream->data) >= 3){
        sess->state = SESSION_STATE_QUERY;
        int err_code = *(short*)(msg + 1);
        /* ERROR 1064 means there is a parsing error
         * we won't record such query.
         */
        return err_code == 1064? SESSION_IGNORE_WRONG_SYNTAX : 0;
    }

    /* if the results have data rows, we will see TWO packet with EOF marker.
     * The first one is to hint that all the columns have been sent,
     * and the second one means that all rows have been sent.
     */
    int first_eof = query_res_find_eof(sess, stream, stream->data, &sess->query_info->col_num); 
    if(first_eof){
        log_runtime_error("Entering Server Result Phase2 from QueryResult state...");
        int second_eof = query_res_find_eof(sess, stream, stream->data + sess->handled_len,&sess->query_info->row_num);
        /* if we have not handled all data, we should return STREAM_DISCARD, and set handled_len
         * to data length we have handled.
         * otherwise, we return 0 means we have handled all data and set handled_len to 0
         */
        if(!second_eof){
            sess->state = SESSION_STATE_RESULT_PHASE2;
            ret = STREAM_DISCARD;
        }else{
            sess->state = SESSION_STATE_QUERY;
            sess->handled_len = 0;
            info->result_end = info->result_start;
            ret = 0;
        }
    }else{
        /* the state will not change, but we may haven't handled all data
         * so we should use nids_discard() to notify that we have data left in stream->data.
         * the length is stored in sess->handled_len
         */
        ret = STREAM_DISCARD;
    }
        
    return ret;
}

/*
 * handle the message send by server
 */
int handle_server_msg(half_stream* stream, mysql_session* sess){
    int ret = 0;
    if(sess->ignore_flag){
        sess->state = SESSION_STATE_QUERY;
        return 0;
    }
    switch(sess->state){
        case SESSION_STATE_SERVER_GREET:
            /* expected to be a greeting msg */
            ret = mysql_dissect_greet(sess, stream);
            break;
        case SESSION_STATE_LOGIN_RESPONSE:
            ret = mysql_dissect_login_resp(sess, stream); 
            break;
        case SESSION_STATE_QUERY_RESULT:
            ret = mysql_dissect_query_result(sess, stream);
            break;
        case SESSION_STATE_RESULT_PHASE2:
            ret = mysql_dissect_query_result_phase2(sess, stream);
            break;

        /* PANIC: we have gone to the wrong state */
        case SESSION_STATE_LOGIN_REQUEST:
        case SESSION_STATE_QUERY:
        default:
            /* go to the recovery start state */
            log_runtime_error("get a wrong state when handling server msg. current state: %s", states[sess->state]);
            sess->state = SESSION_STATE_RESUME_START;    
            break;
    }

    if(sess->state == SESSION_STATE_QUERY){
        if(/* ret != SESSION_IGNORE_WRONG_SYNTAX &&*/ sess->query_info->data[0] != '\0'){
            log_session_query(sess);
        }
        /*VERY IMPORTANT: clean the temporary session data of current query*/
        memset(sess->query_info, 0, offsetof(query_info_t, alloc_size));
        sess->query_info->data[0] = '\0';
        sess->handled_len = 0;
    }
    return ret;
}

int handle_client_msg(half_stream* stream, mysql_session* sess){
    int ret = 0;
    switch(sess->state){
        case SESSION_STATE_LOGIN_REQUEST:
            ret = mysql_dissect_login_request(sess, stream);
            break;
        case SESSION_STATE_QUERY:
            ret = mysql_dissect_query(sess, stream);
            break;

        /* PANIC: we have gone to the wrong state */
        case SESSION_STATE_SERVER_GREET:
        case SESSION_STATE_LOGIN_RESPONSE:
        case SESSION_STATE_QUERY_RESULT:
        case SESSION_STATE_RESULT_PHASE2:
        default:
            /* go to the recovery start state */
            log_runtime_error("get a wrong state when handling client msg. current state: %s", states[sess->state]);
            sess->state = SESSION_STATE_RESUME_START;    
            break;
    }
    return ret;
}

int handle_msg(half_stream* stream, int msg_type, mysql_session* sess){
    int ret = 0;
    switch(msg_type){
        case MYSQL_CLIENT_MSG:
            ret = handle_client_msg(stream, sess);
            break;
        case MYSQL_SERVER_MSG:
            ret = handle_server_msg(stream, sess);
            break;
        default:
            DEBUG_ASSERT(0);
            break;
    }

    sess->ignore_flag = (ret == SESSION_IGNORE_NEXT);
    return ret;
}

int handle_resume_state(mysql_session* sess, int msg_type){
    int go = SESSION_STATE_PROCESS_DISCARD;
    if(sess->state < SESSION_STATE_RESUME_START){
        /* we are at correct state */ 
        return SESSION_STATE_PROCESS_CONTINUE;
    }
    log_runtime_error("handle resume state: current state: %s msg_type: %s ", states[sess->state], msg_type?"server":"client");
    switch(sess->state){
        case SESSION_STATE_RESUME_START:
            if(msg_type == MYSQL_SERVER_MSG){
                sess->state = SESSION_STATE_RESUME_WAIT_CLIENT;
            }else{
                sess->state = SESSION_STATE_RESUME_WAIT_SERVER;
            }
            break;
        case SESSION_STATE_RESUME_WAIT_CLIENT:
            if(msg_type == MYSQL_CLIENT_MSG){
                /* only at here can we go to SESSION_STATE_QUERY to handle the client query */
                sess->state = SESSION_STATE_QUERY; 
                go = SESSION_STATE_PROCESS_CONTINUE;
            }
            break;
        case SESSION_STATE_RESUME_WAIT_SERVER:
            if(msg_type == MYSQL_SERVER_MSG){
                sess->state = SESSION_STATE_RESUME_WAIT_CLIENT;
            }
            break;
        default:
            break;
    }
    return go;
}

int mysql_dissector(struct tcp_stream* tcp, void** no_need_param){
    struct half_stream* stream;
    int msg_type;
    int ret = 0;

    if(tcp->client.count_new){
        stream = &tcp->client;
        /* the msg is sent by server so the message is server type*/
        msg_type = MYSQL_SERVER_MSG;
    }else{
        stream = &tcp->server;
        msg_type = MYSQL_CLIENT_MSG;
    }

    mysql_session* sess = get_mysql_session(&tcp->addr); 
    /* FIXME: it shouldn't be null, but it can be null in some case.*/
    //DEBUG_ASSERT(sess != NULL);
    if(sess != NULL){
        ret = handle_resume_state(sess, msg_type);
        if(ret == SESSION_STATE_PROCESS_CONTINUE){
            ret = handle_msg(stream, msg_type, sess);
            if(ret == STREAM_DISCARD){
                /* leave the data we have received but not unhandled to next call */
                nids_discard(tcp, sess->handled_len);
                sess->handled_len = 0;
            }
        }else{
            log_runtime_error("handle canceled due to resume state");
        }
    }else{
        log_runtime_error("Cannot get a session");
    }
    return ret;
}
