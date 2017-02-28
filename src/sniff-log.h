#ifndef _INCLUDE_SNIFF_LOG_H
#define _INCLUDE_SNIFF_LOG_H


#define FILENAME_LEN    128

struct log_file_t{
    FILE* logfile;
    sig_atomic_t time_count;
};

#define log_runtime_error(fmt, ...) \
    do{ \
        FILE* err_log = config_get_err_log(); \
        if(err_log){ fprintf(err_log, "FILE: %s LINE: %d in %s:"#fmt"\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__); } \
    }while(0)

#ifdef __cplusplus
extern "C" {
#endif

void debug_print_stream(half_stream* stream);
void log_session_query(mysql_session* sess);
int log_init();
void log_fini();

#ifdef __cplusplus
}
#endif


#endif
