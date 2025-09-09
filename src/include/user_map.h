#ifndef K1_USER_MAP
#define K1_USER_MAP

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <auth.h>


struct k1_user_map_struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct k1_auth_details_list);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

#endif
