#ifndef K1_USER_MAP
#define K1_USER_MAP

#ifdef __BPF__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#else
#include <linux/types.h>
#endif

#include <auth_record.h>

struct k1_sys_auth_map_key {
    __u32 uid;
    enum K1_AUTH_TYPE auth_type;
};

#ifdef __BPF__
struct k1_auth_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct k1_record_list);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};


struct k1_sys_auth_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_sys_auth_map_key);
    __type(value, struct k1_sys_record);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_verdict_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct k1_verdict_record_list);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};
#endif //__BPF__

#endif
