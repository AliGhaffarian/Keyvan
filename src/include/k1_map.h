#ifndef K1_USER_MAP
#define K1_USER_MAP

#ifdef __BPF__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#else
#include <linux/types.h>
#endif

#include <auth_record.h>
#include <verdict_record.h>

struct k1_sys_auth_map_key {
    __u32 uid;
    enum K1_AUTH_TYPE auth_type;
};
struct k1_verdict_map_key {
    __u32 uid;
    enum K1_VERDICT_HOOK hook_type;
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
    __type(key, struct k1_verdict_map_key);
    __type(value, struct k1_verdict_record);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_auth_map_hash __attribute__((weak)) auth_map_hash SEC(".maps");
struct k1_verdict_map_hash __attribute__((weak)) verdict_map_hash SEC(".maps");
struct k1_sys_auth_map_hash __attribute__((weak)) sys_auth_map_hash SEC(".maps");
#endif //__BPF__

#endif
