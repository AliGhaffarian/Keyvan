#ifndef K1_BPF_UTIL
#define K1_BPF_UTIL

#include <k1_limits.h>

inline int k1_strcmp(char *first, char *second){
    int cnt = 0;
    while(*first && *second && cnt < K1_BPF_STRING_MAXSIZE){
        if(*first != *second)
            return *first;
        first++;
        second++;
        cnt++;
    }
    return (*first || *second);
}

#endif
