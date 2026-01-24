#ifndef K1_MAP_DEFS
#define K1_MAP_DEFS

#ifndef __BPF__
#define __BPF__
#endif

// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>

#include <auth_record.h>
#include <verdict_record.h>
#include <k1_map_keys_values.h>

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

#endif
