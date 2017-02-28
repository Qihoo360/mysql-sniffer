#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <iostream>
#include <string>
#include <vector>

#include "sniff-config.h"
#include "util.h"

using std::string;
using std::vector;
using std::cout;
using std::endl;

typedef struct{
    string filter;
    string device;
    string port_range;
    string log_dir;
    string pcapfile;
    vector<int> ports;

    FILE* error_log;    
    int port_type;      /* range or enum */
    int split;          /* whether split the log */
    int daemon;         /* daemon mode */
    int error_log_on;
    int minute;          /* how often we want to change the date_flag */
    sig_atomic_t time_count;  /* check the flag to determine whether the date has changed */
    int truncate_len;
    int tcp_stream_cnt;
}sniff_config;

static sniff_config config;

void config_sigalarm_handler(int sig){
    config.time_count++;
    /* call me next time */
    alarm(config.minute * 60);
}

void split(string& s, const string& delim, vector< string >& ret) {  
    size_t last = 0;  
    size_t index = s.find_first_of(delim,last);  
    while (index != string::npos) {  
        ret.push_back(s.substr(last, index-last));  
        last = index + 1;  
        index = s.find_first_of(delim,last);  
    }  
    if (index-last > 0) {  
        ret.push_back(s.substr(last,index-last));  
    }  
}  

static int parse_cmdline_port_option(const char* optarg, const char* fragment){
    vector<string> ports;

    config.port_range.assign(optarg);
    split(config.port_range, ",", ports);
    if(ports.size() == 0){
        return -1;
    }

    char tmp[32];
    int port;

    config.filter = "";
    config.ports.clear();
    port = atoi(ports[0].c_str());
    if(port > 0 || port < 65536){
        snprintf(tmp, 32, "tcp port %d", port);
        config.ports.push_back(port);
        config.filter += tmp;
    }
    for(size_t i = 1;i < ports.size(); i++){
        port = atoi(ports[i].c_str());
        if(port <= 0 || port > 65535){
            continue;
        }
        config.ports.push_back(port);        
        snprintf(tmp, 32, " or port %d ", port);
        config.filter += tmp;
    }
    config.filter += string(" or ") + fragment;
    return 0;
}


static int parse_cmdline_port_range(const char* optarg, const char* fragment){
    vector<string> ports;
    config.port_range.assign(optarg);
    
    split(config.port_range, "-", ports);
    if(ports.size() == 2){ 
        config.ports[0] = atoi(ports[0].c_str());
        config.ports[1] = atoi(ports[1].c_str());
    }else{
        return -1;
    }
    
    if(config.ports[0] < 1 || config.ports[0] > 65535 
            || config.ports[1] < 1 || config.ports[1] > 65535){
        return -1;
    }
    if(config.ports[0] > config.ports[1]){
        int tmp = config.ports[0];
        config.ports[0] = config.ports[1];
        config.ports[1] = tmp;
    }

    config.port_type = PORT_RANGE;
    config.filter = "";
    config.filter += string("tcp portrange ") + optarg;
    return 0;
}

static int parse_cmdline_white_list(const char* optarg, string& filter){
    vector<string> ports;
    string whitelist(optarg);

    filter = "";
    split(whitelist, ",", ports);
    char tmp[32];
    for(size_t i = 0;i < ports.size();i++){
        snprintf(tmp, 32, " and not port %d ", atoi(ports[i].c_str()));
        filter += tmp;
    }
    return 0;
}

static void print_help(const char* argv0){
    fprintf(stderr,
            "Usage %s [-d] -i eth0 -p 3306,3307,3308 -l /var/log/mysql-sniffer/ -e stderr\n" 
            "         [-d] -i eth0 -r 3000-4000\n" 
            "         -d daemon mode.\n"
            "         -s how often to split the log file(minute, eg. 1440). if less than 0, split log everyday\n"
            "         -i interface. Default to eth0\n"
            "         -p port, default to 3306. Multiple ports should be splited by ','. eg. 3306,3307\n"
            "            this option has no effect when -f is set.\n"
            "         -r port range, Don't use -r and -p at the same time\n"
            "         -l query log DIRECTORY. Make sure that the directory is accessible. Default to stdout.\n"
            "         -e error log FILENAME or 'stderr'. if set to /dev/null, runtime error will not be recorded\n"
            "         -f filename. use pcap file instead capturing the network interface\n"
            "         -w white list. dont capture the port. Multiple ports should be splited by ','.\n"
            "         -t truncation length. truncate long query if it's longer than specified length. Less than 0 means no truncation\n"
            "         -n keeping tcp stream count, if not set, default is 65536. if active tcp count is larger than the specified count, mysql-sniffer will remove the oldest one\n",
            argv0);
}

static int is_logdir_accessible(const char* logdir){
    DIR* dir = opendir(logdir);
    if(dir){
        /* directory exists */
        closedir(dir);
        if(access(logdir, R_OK|W_OK|X_OK) < 0){
            return -1;
        }
        return 0;
    }else if(ENOENT == errno){
        /* directory does not exist */
        return -1;
    }else{
        /* opendir() failed */
        return -1;
    }
    /* never come here */
    return 0;
}

static int parse_cmdline_option(int argc, char** argv){
    int opt;
    int ret = 0;
    const char* filter_fragment = "(ip[6:2] & 0x1fff != 0)";
    
    int opt_len;
    string whitelist;
    while((opt = getopt(argc, argv, "dhi:s:p:l:e:f:r:w:t:n:")) != -1 && ret != -1){
        switch(opt){
            case 'd':
                config.daemon = 1;
                break;
            case 's':
                config.split = 1;
                config.minute = atoi(optarg);
                break;
            case 'i':
                config.device = optarg;
                break;
            case 'p':
                ret = parse_cmdline_port_option(optarg, filter_fragment);
                break;
            case 'l':
                config.log_dir = optarg;
                ret = is_logdir_accessible(optarg);
                if(ret == -1){
                    fprintf(stderr, "the log directory is not accessible!\n");
                }
                break;
            case 'e':
                opt_len =  strlen(optarg);
                if(!strcmp(optarg, "stderr")){
                    config.error_log = stderr;
                }else{
                    config.error_log = fopen(optarg, "wa+");
                    if(config.error_log == NULL){
                        ret = -1;
                    }
                }
                break;
            case 'f':
                config.pcapfile = optarg;
                break;
            case 'r':
                ret = parse_cmdline_port_range(optarg, filter_fragment);
                break;
            case 'w':
                ret = parse_cmdline_white_list(optarg, whitelist);
                break;
            case 't':
                config.truncate_len = atoi(optarg);
                break;
            case 'n':
                config.tcp_stream_cnt = atoi(optarg);
                break;
            case 'h':
            default:
                print_help(argv[0]);
                ret = -1;
                break;
        }
    }
    if(config.split == 1 && ret != -1){
        config_set_log_split();
    }
    if(config.truncate_len <=0){
        /* int max */
        config.truncate_len = 0x7fffffff;
    }
    config.filter += whitelist;

    return ret;
}


int config_init(int argc, char** argv){
    /* default option */
    config.split = 0;
    config.daemon = 0;
    config.error_log_on = 1;
    config.error_log = NULL;

    config.ports.push_back(3306);
    config.port_type = PORT_ENUM;

    config.device = "eth0";
    config.port_range = "3306";
    config.log_dir = "stdout";
    config.pcapfile = "";
    config.filter = "tcp port 3306 or (ip[6:2] & 0x1fff != 0)";

    config.truncate_len = 0;

    config.time_count = 0;
    config.minute = 24 * 60;
    config.tcp_stream_cnt = 65536;
    return parse_cmdline_option(argc, argv);
}

void config_print(){
    cout<<"device: "<<config.device<<endl;
    if(config.port_type == PORT_RANGE){
        printf("min port: %d, max port: %d\n", config.ports[0], config.ports[1]);
    }else{
        printf("ports: ");
        for(size_t i = 0;i < config.ports.size(); i++){
            printf("%d ", config.ports[i]);
        }
        printf("\n");
    }
    cout<<"filter: "<<config.filter<<endl;
    cout<<"log: "<<config.log_dir<<endl;
    cout<<"pcapfile: "<<config.pcapfile<<endl;
}


void config_fini(){
    if(config.error_log != NULL){
        fflush(config.error_log);
        fclose(config.error_log);
    }
}

void config_set_log_split(){
    if(config.minute <= 0){
        config.minute = 24 * 60;
    }
    signal(SIGALRM, config_sigalarm_handler);
    alarm(config.minute * 60);
}

int config_is_log_split(){
    return config.split;
}

int config_is_daemon(){
    return config.daemon;
}

FILE* config_get_err_log(){
    return config.error_log;
}

const char* config_get_device(){
    return config.device.c_str();
}
const char* config_get_pcapfile(){
    return config.pcapfile.c_str();
}

const char* config_get_logdir(){
    return config.log_dir.c_str();
}

const char* config_get_filter(){
    return config.filter.c_str();
}

sig_atomic_t config_get_time_count(){
    return config.time_count;
}

int config_get_port_type(){
    return config.port_type;
}

int config_is_server_port(int port){
    if(config.port_type == PORT_ENUM){
        for(size_t i = 0;i < config.ports.size(); i++){
            if(port == config.ports[i]){
                return 1;
            }
        }
    }else if(port >= config.ports[0] && port <= config.ports[1]){
        return 1;
    }
    return 0;
}

int config_get_truncate_len(){
    return config.truncate_len;
}

int config_get_tcp_stream_cnt() {
    return config.tcp_stream_cnt;
}
