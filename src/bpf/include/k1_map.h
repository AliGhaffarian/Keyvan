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
#include <k1_map_pairs.h>
#include <verdict_record.h>

/**
 * @brief BPF map exposed by the session refcounting subsystem. Is mostly used
 * to check if a session is refcounted.
 */
struct k1_refcounting_map_session_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_refcounting_map_session_key);
    __type(value, struct k1_refcounting_map_session_value);
};

struct k1_verdict_map_session_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_verdict_map_session_key);
    __type(value, struct k1_verdict_map_session_value);
};

struct k1_auth_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_auth_map_key);
    __type(value, struct k1_auth_map_value);
};

struct k1_verdict_map_user_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_verdict_map_user_key);
    __type(value, struct k1_verdict_map_user_value);
};

/**
 * @brief BPF map that stores effective user ID of users that registered a
 * per-session verdict.
 *
 * The map has values for users that registered a per-session verdict. A lookup
 * for a user that does not returns `NULL`.
 */
struct k1_users_having_sid_verdict_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_users_having_sid_verdict_map_key);
    __type(value, DUMMY_MAP_VALUE_T); /* won't be used */
};

/**
 * @brief BPF map that stores effective user ID of users that registered
 * anything.
 *
 * The map has values for users that registered anything. A lookup for a user
 * that does not returns `NULL`.
 */
struct k1_registered_euids_map_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_registered_euids_map_key);
    __type(value, DUMMY_MAP_VALUE_T); /* won't be used */
};

struct k1_exception_map_pathname_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_exception_map_pathname_key);
    __type(value, struct k1_exception_map_pathname_value);
};

/**
 * @brief BPF map that maps files to their trusted hash.
 */
struct k1_trust_map_file2sha256_hash {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct k1_trust_map_file2sha256_key);
    __type(value, struct k1_trust_map_file2sha256_value);
};

struct k1_trust_map_file2sha256_hash
    __attribute__((weak)) trust_map_file2sha256_hash SEC(".maps");
struct k1_exception_map_pathname_hash
    __attribute__((weak)) exception_map_pathname_hash SEC(".maps");
struct k1_refcounting_map_session_hash
    __attribute__((weak)) refcounting_map_session_hash SEC(".maps");
struct k1_verdict_map_session_hash
    __attribute__((weak)) verdict_map_session_hash SEC(".maps");
struct k1_registered_euids_map_hash
    __attribute__((weak)) registered_euids_map_hash SEC(".maps");
struct k1_users_having_sid_verdict_map_hash
    __attribute__((weak)) users_having_sid_verdict_map_hash SEC(".maps");
struct k1_verdict_map_user_hash
    __attribute__((weak)) verdict_map_user_hash SEC(".maps");
struct k1_auth_map_hash __attribute__((weak)) auth_map_hash SEC(".maps");

#endif
