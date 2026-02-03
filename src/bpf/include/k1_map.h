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
#include <k1_map_keys_values.h>
#include <verdict_record.h>

struct k1_verdict_map_session_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_verdict_map_session_key);
    __type(value, struct k1_verdict_map_session_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_auth_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_auth_map_key);
    __type(value, struct k1_auth_map_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_verdict_map_user_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_verdict_map_user_key);
    __type(value, struct k1_verdict_map_user_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_registered_uids_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_registered_uids_map_key);
    __type(value, DUMMY_MAP_VALUE_T); /* won't be used */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct k1_verdict_map_session_hash
    __attribute__((weak)) verdict_map_session_hash SEC(".maps");
struct k1_registered_uids_map_hash
    __attribute__((weak)) registered_uids_map_hash SEC(".maps");
struct k1_verdict_map_user_hash
    __attribute__((weak)) verdict_map_user_hash SEC(".maps");
struct k1_auth_map_hash __attribute__((weak)) auth_map_hash SEC(".maps");

#endif
