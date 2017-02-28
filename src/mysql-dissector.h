#ifndef _INCLUDE_MYSQL_DISSECTOR_H
#define _INCLUDE_MYSQL_DISSECTOR_H


#define MAGIC_NUM   9
typedef enum{
    STREAM_DISCARD = MAGIC_NUM,
    STREAM_CONTINUE,

    SESSION_DEL,
    SESSION_IGNORE_NEXT,
    SESSION_IGNORE_WRONG_SYNTAX,

    RET_MAX
}RET_TYPE;

typedef enum{
    COM_SLEEP,
    COM_QUIT,
    COM_INIT_DB,
    COM_QUERY,
    COM_FIELD_LIST,

    COM_CREATE_DB,
    COM_DROP_DB,
    COM_REFRESH,
    COM_SHUTDOWN,
    COM_STATISTICS,

    COM_PROCESS_INFO,
    COM_CONNECT,
    COM_PROCESS_KILL,
    COM_DEBUG,
    COM_PING,

    COM_TIME,
    COM_DELAYED_INSERT,
    COM_CHANGE_USER,
    COM_BINLOG_DUMP,

    COM_TABLE_DUMP,
    COM_CONNECT_OUT,
    COM_REGISTER_SLAVE,

    COM_STMT_PREPARE,
    COM_STMT_EXECUTE,
    COM_STMT_SEND_LONG_DATA,
    COM_STMT_CLOSE,

    COM_STMT_RESET,
    COM_SET_OPTION,
    COM_STMT_FETCH,
    COM_DAEMON,

    COM_END
}COMMAND;


#define CLIENT_LONG_PASSWORD	1	/* new more secure passwords */
#define CLIENT_FOUND_ROWS	2	/* Found instead of affected rows */
#define CLIENT_LONG_FLAG	4	/* Get all column flags */
#define CLIENT_CONNECT_WITH_DB	8	/* One can specify db on connect */
#define CLIENT_NO_SCHEMA	16	/* Don't allow database.table.column */
#define CLIENT_COMPRESS		32	/* Can use compression protocol */
#define CLIENT_ODBC		64	/* Odbc client */
#define CLIENT_LOCAL_FILES	128	/* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE	256	/* Ignore spaces before '(' */
#define CLIENT_PROTOCOL_41	512	/* New 4.1 protocol */
#define CLIENT_INTERACTIVE	1024	/* This is an interactive client */
#define CLIENT_SSL              2048	/* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE   4096    /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS	8192	/* Client knows about transactions */
#define CLIENT_RESERVED         16384   /* Old flag for 4.1 protocol  */
#define CLIENT_SECURE_CONNECTION 32768  /* New 4.1 authentication */
#define CLIENT_MULTI_STATEMENTS (1UL << 16) /* Enable/disable multi-stmt support */
#define CLIENT_MULTI_RESULTS    (1UL << 17) /* Enable/disable multi-results */


typedef enum{
    MYSQL_CLIENT_MSG,
    MYSQL_SERVER_MSG
}mysql_msg;

typedef enum{
    OUTPUT_TIME = COM_END + 1,
    SERVER_TYPE_END
}server_msg_type;


typedef struct half_stream half_stream;

#define MYSQL_PACKET_HEADER_LEN  4
#define PACKET_LEN(data)    ((*(int*)data)&0x00ffffff)
#define PACKET_NUM(data)    (*((u_char*)data + MYSQL_PACKET_HEADER_LEN - 1))
#define PACKET_MSG(data)     ((char*)data + MYSQL_PACKET_HEADER_LEN)

/* Refer: [https://dev.mysql.com/doc/internals/en/integer.html] */
#define MYSQL_LENENC_INT_ONEBYTE       0xfb
#define MYSQL_LENENC_INT_TWOBYTE       0xfc 
#define MYSQL_LENENC_INT_THREEBYTE     0xfd 
#define MYSQL_LENENC_INT_EIGHTBYTE     0xfe 
#define MYSQL_LENENC_INT_ERR           0xff 

#define MYSQL_EOF_MARKER     0xfe 

#define MYSQL_COMMAND(msg)  (*msg)
#define MYSQL_COMMAND_LEN    1


#define MYSQL_LOGIN_CHARSET_LEN     (1+23)

/* a fixed length header of client login request */
typedef struct{
    u_int capability;
    u_int maxpacket;
    char charset[MYSQL_LOGIN_CHARSET_LEN];
}mysql_login_client_info;



int mysql_dissector(struct tcp_stream* tcp, void** time);


#endif
