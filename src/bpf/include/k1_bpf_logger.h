#include <k1_map.h>
#include <vmlinux.h>

#define _logger(log_lvl, stream_id, fmt, args) \
    bpf_stream_vprintk(stream_id, LOGGER_FMT, LOGGER_FMT_ARGS(log_lvl), BPF_MAX_LOG_LEN, NULL); \
    bpf_stream_vprintk(stream_id, fmt, args, BPF_MAX_LOG_LEN, NULL);
#define logger(...)
