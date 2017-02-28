#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

void* zmalloc(int size){
    char* p = (char*)malloc(size);
    memset(p, 0, size);
    return p;
}

int format_timeval(struct timeval *tv, char *buf, int sz) {
    struct tm gm;
    
    /*
     * timezone: +8 hours
     */
    tv->tv_sec += 8 * 3600;
    if (gmtime_r(&tv->tv_sec, &gm)) {
        strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &gm);
    }
    tv->tv_sec -= 8 * 3600;
    return 0;
}

int format_relative_time(struct timeval* early, struct timeval* later, char* buf, int size){
    int second = later->tv_sec > early->tv_sec ? later->tv_sec - early->tv_sec: 0;
    int msecond = later->tv_usec - early->tv_usec;
    return snprintf(buf, size, "%10dms", second * 1000 + msecond/1000);
}

