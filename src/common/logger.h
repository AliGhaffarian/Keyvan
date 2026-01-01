#ifndef K1_LOGGER
#define K1_LOGGER

#include <stdarg.h>

#ifdef NDEBUG
#define LOGGER_FMT "[%s]:"
#define LOGGER_FMT_ARGS(log_lvl) LOG_LEVELS2STR[log_lvl]
#else
#define LOGGER_FMT "[%s]: [%s:%s:%d]: "
#define LOGGER_FMT_ARGS(log_lvl) LOG_LEVELS2STR[log_lvl], __FILE__, __func__, __LINE__
#endif

enum LOG_LEVELS {
    LOG_NOLOG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_DEBUG
};

extern const char *LOG_LEVELS2STR[];
extern volatile int current_log_level;

#ifdef __BPF__
#include <k1_map.h>
//log with ringbuf
#define _log()
#else
#include <stdio.h>
#define _log(log_lvl, dest, fmt, ...) fprintf(dest, LOGGER_FMT fmt, LOGGER_FMT_ARGS(log_lvl), __VA_ARGS__);
#endif
/*
 * @param log_lvl
 * @param dest: destination FILE*, ignored for bpfside
 * @param msg: msg to be logged
 */
#define log(log_lvl, dest, fmt, ...) \
    do {                            \
    if(current_log_level > log_lvl) \
        _log(log_lvl, dest, fmt, __VA_ARGS__) \
    } while(0)


#endif //K1_LOGGER
