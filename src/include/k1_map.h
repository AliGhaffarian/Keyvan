#ifndef K1_USER_MAP
#define K1_USER_MAP

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <auth_list.h>


struct k1_auth_map_hash_sys {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct k1_sys_record_list);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_verdict_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct k1_verdict_record_list);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

#endif
