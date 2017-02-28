#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <nids.h>

#include "session.h"
#include "mysql-dissector.h"
#include "sniff-config.h"
#include "sniff-log.h"
#include "util.h"

/**
 * see details in nids doc/API.txt
 * set nids_params.syslog to this func, can hook the nids debug log. 
 * prevent nids to logs messages to system daemon syslogd, because nids 
 * disregarding such things like message rate per second or free disk space.
 */ 
static void nids_syslog_hook(int type, int errnum, struct ip *iph, void *data) {
    return;
}

void tcp_callback(struct tcp_stream *tcp, void** no_need_param){
    int ret = 0;
    *no_need_param = NULL; // the variable is storing in libnids, and libnids will pass it to us when tcp_callback is called again.

    switch(tcp->nids_state){
        case NIDS_JUST_EST:
            tcp->client.collect = 1;
            tcp->server.collect = 1;
            add_mysql_session(&tcp->addr);
            break;
        case NIDS_CLOSE:
        case NIDS_RESET:
        case NIDS_TIMED_OUT:
            del_mysql_session(&tcp->addr);
            break;
        case NIDS_DATA:
            ret = mysql_dissector(tcp, no_need_param); 
            if(ret == SESSION_DEL){
                del_mysql_session(&tcp->addr);
            }
            break;
#ifdef ENABLE_TCPREASM
        case NIDS_RESUME:
            tcp->client.collect = 1;
            tcp->server.collect = 1;
            add_mysql_resume_session(&tcp->addr);
            break;
#endif
        default:
            break;
    }

    return;
}

#ifdef ENABLE_TCPREASM
/*
 * 0 can't determine whether it is come from client or server.
 * 1 the packet is come from client
 * 2 the packet is come from server
 */
void tcp_resume_is_client(struct tcphdr* packet_tcphdr, struct iphdr* packet_iphdr, int* is_client){
    /* ip addresses of this machine */
    struct ifaddrs* this_addrs;
    struct ifaddrs* ifa;
    *is_client = 0;
    
    // -- TODO -- getifaddrs should call only once in the main func.
    if(getifaddrs(&this_addrs) == -1){
        log_runtime_error("%s\n", "can not get IP addresses! tcp resume will fail!");
        *is_client = 0;
        return;
    }
    struct in_addr this_ipaddr;
    int port = ntohs(packet_tcphdr->dest);
    for(ifa = this_addrs; ifa != NULL; ifa = ifa->ifa_next){
        if(ifa->ifa_addr == NULL){
            continue;
        }
        this_ipaddr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
        if(ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6){
            if(packet_iphdr->daddr == this_ipaddr.s_addr && config_is_server_port(port)){
                *is_client = NIDS_TCP_RESUME_CLIENT;
                freeifaddrs(this_addrs);
                return;
            }
        }
    }
    *is_client = NIDS_TCP_RESUME_SERVER;
    freeifaddrs(this_addrs);
}
#endif

typedef struct nids_prm nids_prm;

nids_prm* get_param_handle(){
    return &nids_params;
}

void set_nids_option(){
    nids_prm* param = get_param_handle();
    char* filename = (char*)config_get_pcapfile();
    if(strlen(filename) != 0){
        param->filename = filename;
        param->device = NULL;
    }else{
        param->device = (char*)config_get_device();
        param->pcap_filter = (char*)config_get_filter();
    }

    param->pcap_timeout = 5;
    param->n_tcp_streams = config_get_tcp_stream_cnt(); 

    /* disable the libnids port scanning detection, we dont concern about the illegal user. */
    param->scan_num_hosts = 0; 
    param->syslog = nids_syslog_hook;
}

static volatile sig_atomic_t is_shutdown;

void sig_exit_handler(int sig){
    if(is_shutdown == 0){
        log_runtime_error("program is going to shutdown!");        
    }
    is_shutdown = 1;
}

int sniffer_is_shutdown(){
    return is_shutdown == 1;
}


int main(int argc, char** argv){
    if(config_init(argc, argv) == -1){
        exit(1);    
    }

#ifdef DEBUG
    config_print();
#endif
    if(config_is_daemon()){
        daemon(1, 0);
        /* call alarm() to produce signal */
        if(config_is_log_split()){
            config_set_log_split();
        }
    }
    signal(SIGINT, sig_exit_handler);
    signal(SIGTERM, sig_exit_handler);

    set_nids_option();
    if(!nids_init()){
        fprintf(stderr, "%s\n", nids_errbuf);
        exit(1);    
    }

    /* don't check sum
     * if wrapper this code block into a function, 
     * the nids_chksum_ctl should be allocated at heap.
     */
    struct nids_chksum_ctl chksum_ctl;
    chksum_ctl.netaddr = 0;
    chksum_ctl.mask = 0;
    chksum_ctl.action = NIDS_DONT_CHKSUM;
    chksum_ctl.reserved = 0;
    nids_register_chksum_ctl(&chksum_ctl, 1);

    session_init(NULL);
    log_init();
    nids_register_tcp(tcp_callback);

#ifdef ENABLE_TCPREASM
    nids_register_tcp_resume(tcp_resume_is_client);
#endif

    nids_prm* param = get_param_handle();
    int ret = 0;
    is_shutdown = 0;
    while(!sniffer_is_shutdown()){
        /* it will return when timeout, default to 5s */
        ret = nids_dispatch(-1);
        if(param->device == NULL && ret == 0){
            /* we have read all content of the file */
            break;
        }
    }
    
    config_fini();
    session_fini();
    log_fini();
    nids_exit();
    return 0;
}
