#ifndef K1_EXCEPTION_PATHNAME
#define K1_EXCEPTION_PATHNAME

#include <bpf/libbpf.h>
#include <bpf_progs.skel.h>
#include <k1_map_pairs.h>
#include <verdict_record.h>

int register_exception_pathname(
    struct bpf_progs *skel,
    char *pathname,
    uid_t uid,
    enum K1_VERDICT_HOOK verdict_hook,
    enum K1_VERDICT_MAP_TYPE verdict_map_type,
    bool is_whitelist);

#endif
