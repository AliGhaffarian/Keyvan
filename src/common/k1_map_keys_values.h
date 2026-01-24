#ifndef K1_MAP_KEYS_VALUES
#define K1_MAP_KEYS_VALUES

#ifdef __BPF__
#include <vmlinux.h>
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

#endif
