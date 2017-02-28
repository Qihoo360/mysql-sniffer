#ifndef _INCLUDE_UTIL_H
#define _INCLUDE_UTIL_H

#include <assert.h>

/* for debug */
#ifdef DEBUG
#define DEBUG_ASSERT(expr) \
    do{ \
        if(!(expr)){ \
            assert(expr); \
        } \
    }while(0)
#else
#define DEBUG_ASSERT(expr) 
#endif

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) \
        do{ \
            fprintf(stdout, fmt, ##__VA_ARGS__);\
        }while(0)
#else
#define DEBUG_PRINT(fmt, ...)
#endif 
        

#define FREE(ptr) \
    do{ if(ptr) free((ptr)); } while(0)


#ifdef __cplusplus
extern "C" {
#endif

void* zmalloc(int size);
int format_timeval(struct timeval *tv, char *buf, int sz);
int format_relative_time(struct timeval* early, struct timeval* later, char* buf, int size);


#ifdef __cplusplus
}
#endif
#endif
