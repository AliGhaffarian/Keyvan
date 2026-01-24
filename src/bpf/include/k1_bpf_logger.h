#ifndef K1_BPF_LOGGER
#define K1_BPF_LOGGER

// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>
#include <stdarg.h>

enum LOG_LEVELS {
    LOG_NOLOG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_DEBUG
};

__attribute__((weak))
const volatile int current_log_level SEC(".rodata") = LOG_INFO;

// TODO: make the following a char array, problem: "libbpf: relocation against
// STT_SECTION in non-exec section is not supported!"
inline char *LOG_LEVELS2STR(enum LOG_LEVELS log_lvl) {
    switch(log_lvl) {
    case(LOG_INFO):
        return "INFO";
    case(LOG_WARN):
        return "WARN";
    case(LOG_ERROR):
        return "ERROR";
    case(LOG_DEBUG):
        return "DEBUG";
    default:
        return "UNKNOWN LVL";
    }
}

#ifdef NDEBUG
#define LOGGER_FMT               "[%s]:"
#define LOGGER_FMT_ARGS(log_lvl) LOG_LEVELS2STR(log_lvl)
#else
#define LOGGER_FMT "[%s]: [%s:%s:%d]: "
#define LOGGER_FMT_ARGS(log_lvl)                                               \
    LOG_LEVELS2STR(log_lvl), __FILE__, __func__, __LINE__
#endif

#define _logger(log_lvl, stream_id, fmt, ...)                                  \
    bpf_stream_printk(                                                         \
        stream_id, LOGGER_FMT fmt, LOGGER_FMT_ARGS(log_lvl), __VA_ARGS__);

/*
 * @param log_lvl
 * @param stream_id: destination stream_id
 * @fmt__str: Format string following the same formatting as bpf_trace_printk
 * @args: Pointer to an array of u64 argument values.
 * @len_sz: Number of elements in args.
 */
#define logger(log_lvl, stream_id, fmt, ...)                                   \
    do {                                                                       \
        if(current_log_level >= log_lvl)                                       \
            _logger(log_lvl, stream_id, fmt, __VA_ARGS__)                      \
    } while(0)

#endif
