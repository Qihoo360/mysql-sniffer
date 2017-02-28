#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <nids.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <map>
#include <string>

#include "session.h"
#include "mysql-dissector.h"
#include "sniff-config.h"
#include "sniff-log.h"
#include "util.h"


typedef std::map<int, log_file_t*> port_file_map;
typedef port_file_map::iterator iterator;

static port_file_map* g_file_map;

void debug_print_stream(half_stream* stream){
    FILE* error_log = config_get_err_log();
    if(!error_log){
        return;
    }

    fprintf(error_log, "packet len: %d ", PACKET_LEN(stream->data));
    for(int i = 0;i < stream->count_new; i++){
        fprintf(error_log, "%c", *(stream->data + i));
    }
    fprintf(error_log, "\n");
}

void format_log_name(int port, std::string& filename) {
    char day[48];
    char base_name[64];
    struct timeval tv;
    struct tm gm;

    gettimeofday(&tv, NULL);
    /* timezone, add 8 hours */
    tv.tv_sec += 8 * 3600;
    if (gmtime_r(&tv.tv_sec, &gm)) {
        strftime(day, 48, "%Y-%m-%d-%H:%M", &gm);
    }
    snprintf(base_name, 64, "%s-%d.log", day, port);
    filename = filename + config_get_logdir() + "/" + base_name;
}

/* open log for a new listening port */
static void open_log(int port, log_file_t* log){
    /* FIXME:
     * if it happened that the time_count changes after a log has saved the time_count, 
     * we will see log->time_count != time_count at log_session_query().
     * and we will get a empty log file for that time and that port
     */
    log->time_count = config_get_time_count();
    /* single log file mode */
    std::string filename(config_get_logdir());
    char port_log_name[32];

    snprintf(port_log_name, 32, "/%d.log", port);
    filename += port_log_name;
    log->logfile = fopen(filename.c_str(), "a+");
    if(log->logfile == NULL){
        log_runtime_error("open file %s failed", filename.c_str());
    }
    return;
}

static void rename_split_file(int port) {
    std::string filename, orig_filename(config_get_logdir());
    format_log_name(port, filename);
    char port_log_name[64];
    snprintf(port_log_name, 64, "/%d.log", port);
    orig_filename += port_log_name;
    if (rename(orig_filename.c_str(), filename.c_str()) !=0 ) {
        log_runtime_error("rename file from %s to %s failed", orig_filename.c_str(), filename.c_str());
    }   
}

static log_file_t* get_log_by_port(int port){
    iterator it = g_file_map->find(port);
    log_file_t* log = NULL;
    if(it != g_file_map->end()){
        log = it->second;
    }else{
        /* we are first time to open the log for the server port */
        log = (log_file_t*)malloc(sizeof(log_file_t));
        open_log(port, log);
        if(log->logfile == NULL){
            free(log);
            return NULL;
        }
        g_file_map->insert(std::make_pair(port, log));
    }
    return log;
}

void remove_newline(char* str){
    while(*str){
        if(*str == '\r' || *str == '\n'){
            *str = ' ';
        }
        str++;
    }
}

/** 
 * file is stale when it is deleted by others after fopen.
 * the only way to figure out, is using the fstat or access().
 */
int is_file_stale(FILE *tocheck_file) {
#ifdef ENABLE_DETECT_FILE_STALE
    assert(tocheck_file);
    struct stat st_info;
    return fstat(fileno(tocheck_file), &st_info) == -1 /*errno == 116, ESTALE*/;
#else
    return 0;
#endif
}

log_file_t* get_log_by_session(mysql_session* sess){
    log_file_t* log = sess->log;
    if(log == NULL){
        /* the session is first time asking to write log */
        log = get_log_by_port(sess->skey.dest);
        if(log == NULL){
            return NULL;
        }
        sess->log = log;
    }
    if(is_file_stale(log->logfile)) {
        fflush(log->logfile);
        fclose(log->logfile);
        open_log(sess->skey.dest, log);
    }

    int time_count = config_get_time_count();
    /* if we don't specify the '-s' option, the time_count will not change.
     * so we won't open new log when time changes.
     */
    if(log->time_count != time_count){
        log->time_count = time_count;
        fflush(log->logfile);
        fclose(log->logfile);

        /*open new log for a new day */
        rename_split_file(sess->skey.dest);
        open_log(sess->skey.dest, log);
        /* someone has changed the permission of the directory or other reason */
        if(log->logfile == NULL){
            g_file_map->erase(sess->skey.dest);
            free(sess->log);
            sess->log = NULL;
            return NULL;
        }
    }
    return log;
}

void log_session_query(mysql_session* sess){

    FILE* outstream = NULL;
    log_file_t* log = get_log_by_session(sess);
    if(log != NULL && log->logfile != NULL){
        outstream = log->logfile;
    }else if(!strcmp(config_get_logdir(), "stdout")){
        outstream = stdout;
    }else{
        return;
    }

    char start_tm[32];
    char execute_tm[32];
    query_info_t* info = sess->query_info; 
    format_timeval(&info->query_end, start_tm, 32);
    format_relative_time(&info->query_end, &info->result_start, execute_tm, 32);
    const char* dbname = strlen(sess->dbname) > 0 ? sess->dbname : "NULL";
    const char* username = sess->user_info ? sess->user_info->username : "NULL";

    /* truncate long query */
    int truncate_len = config_get_truncate_len();
    if(info->count <= truncate_len){
        /* may cause the origin query broken due to charset */
        remove_newline(info->data);
        fprintf(outstream, "%s\t %s\t %s\t %s\t %s\t %10d\t %s\n", 
                start_tm, 
                username,
                inet_ntoa(*(struct in_addr*)&sess->skey.saddr),
                dbname,
                execute_tm,
                info->row_num,
                info->data);
    }else if(truncate >= 0){
        info->data[truncate_len] = '\0';
        /* may cause the origin query broken due to charset */
        remove_newline(info->data);

        fprintf(outstream, "%s\t %s\t %s\t %s\t %s\t %10d\t %s...\n", 
                start_tm, 
                username,
                inet_ntoa(*(struct in_addr*)&sess->skey.saddr),
                dbname,
                execute_tm,
                info->row_num,
                info->data);
    }
}

int log_init(){
    g_file_map = new port_file_map();
    return 0;
}

void log_fini(){
    iterator it = g_file_map->begin();

    while(it != g_file_map->end()){
        fflush(it->second->logfile);
        fclose(it->second->logfile);
        free(it->second);
        it++;
    }
    delete g_file_map;
}

