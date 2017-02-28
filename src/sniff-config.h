#ifndef _INCLUDE_SNIFF_CONFIG_H
#define _INCLUDE_SNIFF_CONFIG_H



typedef enum{
    PORT_RANGE,
    PORT_ENUM
}port_type;

#ifdef __cplusplus
extern "C" {
#endif

int config_init(int, char**);
void config_fini();

int config_is_log_split();
int config_is_daemon();

const char* config_get_device();
const char* config_get_logdir();
const char* config_get_pcapfile();
const char* config_get_filter();
sig_atomic_t config_get_time_count();
FILE* config_get_err_log();

void config_print();
int* config_get_ports();
int config_get_port_num();
int config_get_port_type();
int config_is_server_port(int port);
int config_get_truncate_len();
void config_set_log_split();
int config_get_tcp_stream_cnt();
#ifdef __cplusplus
}
#endif

#endif
