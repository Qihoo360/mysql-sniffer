#ifndef _INCLUDE_SESSION_H
#define _INCLUDE_SESSION_H

#define MAX_SESSION_COUNT   1024

#define MAKE_SESSION_ID(a,b)   ((a)<<16|(b)) 


typedef enum{
    /*server state */
    SESSION_STATE_SERVER_GREET,
    SESSION_STATE_LOGIN_RESPONSE,
    SESSION_STATE_QUERY_RESULT,
    SESSION_STATE_RESULT_PHASE2,

    SESSION_STATE_SERVER_MAX,

    /* client state */
    SESSION_STATE_LOGIN_REQUEST,
    SESSION_STATE_QUERY,
    SESSION_STATE_CLIENT_MAX,

    /* error state
     * Causes are as follows:
     * 1. dropping packet
     * 2. failing to resolve the protocol
     * 3. tcp connection resume
     * 4. other
     */
    SESSION_STATE_RESUME_START,
    SESSION_STATE_RESUME_WAIT_SERVER,
    SESSION_STATE_RESUME_WAIT_CLIENT,

    SESSION_STATE_MAX
}session_state;


#define MYSQL_USERNAME_MAX_LEN  64
#define MYSQL_PASSWORD_MAX_LEN  24


#define SESSION_STATE_PROCESS_CONTINUE    1
#define SESSION_STATE_PROCESS_DISCARD     0

typedef struct{
    char username[MYSQL_USERNAME_MAX_LEN];
    char password[MYSQL_PASSWORD_MAX_LEN];
    int total_query_count;
    int total_execute_time;
    char charset;
}user_info_t;

typedef struct{
	struct timeval query_start;
	struct timeval query_end;
    struct timeval result_start;
    struct timeval result_end;
    int col_num;
    int row_num;
    /* the member above will be reset to 0 every time the query is end 
     * cause we cannot really determine the start of query.
     */
    int alloc_size;    // buffer size we allocated
    int count;         // actual data length
    int cmd;           // mysql client command
    char* data;        // buffer
}query_info_t;

#define MYSQL_SQL_STATEMENT_BUFLEN   4096

typedef struct tuple4 session_key_t;
typedef struct log_file_t log_file_t;

#define MYSQL_DB_NAME_LEN  1024

typedef struct{
    session_key_t skey;    
    session_state state; //the state of the session
    user_info_t* user_info;
    query_info_t* query_info;
    int ignore_flag;   //if we should ignore the next packet 
    int handled_len;   //the data len we have handled in a notification, valid when STREAM_DISCARD is returned
    log_file_t* log;
    char* dbname;
}mysql_session;

#ifdef __cplusplus
extern "C" {
#endif

int session_init(void*);
int session_fini();
mysql_session* get_mysql_session(session_key_t* skey);
mysql_session* add_mysql_session(session_key_t* skey);
#ifdef ENABLE_TCPREASM
mysql_session* add_mysql_resume_session(session_key_t* skey);
#endif
mysql_session* del_mysql_session(session_key_t* skey);

int query_info_resize(query_info_t* query_info, int size);


#ifdef __cplusplus
}
#endif
#endif
