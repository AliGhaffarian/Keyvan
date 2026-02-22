#ifndef K1_LOGGER
#define K1_LOGGER

#include <stdarg.h>
#include <stdio.h>

#ifdef NDEBUG
#define LOGGER_FMT               "[%s]:"
#define LOGGER_FMT_ARGS(log_lvl) LOG_LEVELS2STR[log_lvl]
#else
#define LOGGER_FMT "[%s]: [%s:%s:%d]: "
#define LOGGER_FMT_ARGS(log_lvl)                                               \
    LOG_LEVELS2STR[log_lvl], __FILE__, __func__, __LINE__
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

#define _logger(log_lvl, dest, fmt, ...)                                       \
    fprintf(dest, LOGGER_FMT fmt, LOGGER_FMT_ARGS(log_lvl), ##__VA_ARGS__);
/*
 * @param log_lvl
 * @param dest: destination FILE*, ignored for bpfside
 * @param msg: msg to be logged
 */
#define logger(log_lvl, dest, fmt, ...)                                        \
    do {                                                                       \
        if(current_log_level >= log_lvl)                                       \
            _logger(log_lvl, dest, fmt, ##__VA_ARGS__)                         \
    } while(0)

enum LOG_LEVELS enum_from_string_log_levels(char *str);

#endif // K1_LOGGER
