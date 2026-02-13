#ifndef K1_MAP_pairs
#define K1_MAP_pairs

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <linux/bpf.h>
#include <linux/types.h>
#include <sys/types.h>
#endif

#include <auth_record.h>
#include <verdict_record.h>

#define DUMMY_MAP_VALUE_T void * // is used when the map value doesn't matter

/**
 * @brief get and set macros for auth_key, to decouple the code
 */
#define AUTHMAP_KEY_SET_UID(key_ptr, u) (key_ptr)->uid = u
#define AUTHMAP_KEY_GET_UID(key_ptr)    ((key_ptr)->uid)

enum K1_VERDICT_MAP_TYPE {
    _K1_VERDICT_MAP_UNSPEC,
    K1_VERDICT_MAP_UID,
    K1_VERDICT_MAP_SID,
    _K1_VERDICT_MAP_SIZE,
};

struct k1_verdict_entry_lookup_info {
    enum K1_VERDICT_MAP_TYPE verdict_map_type;
    enum K1_VERDICT_HOOK verdict_hook;
};

struct k1_auth_map_key {
    __u32 uid;
    enum K1_AUTH_TYPE auth_type;
};

struct k1_verdict_map_user_key {
    __u32 uid;
    enum K1_VERDICT_HOOK verdict_hook;
};

struct k1_users_having_sid_verdict_map_key {
    __u32 uid;
};

struct k1_registered_uids_map_key {
    __u32 uid;
};

struct k1_auth_map_value {
    __u64 is_authenticated;
    struct k1_verdict_entry_lookup_info verdict_entry_lookup_info;
    struct k1_auth_record record;
};

struct k1_verdict_map_user_value {
    struct k1_verdict_record record;
};

struct k1_refcounting_map_session_key {
    __u64 sid;
};
struct k1_refcounting_map_session_value {
    __u64 refcount;
};

struct k1_verdict_map_session_key {
    pid_t sid;
    enum K1_VERDICT_HOOK verdict_hook;
};

struct k1_verdict_map_session_value {
    struct k1_verdict_record record;
};

struct k1_verdict_map_session_pair {
    struct k1_verdict_map_session_key key;
    struct k1_verdict_map_session_value value;
};

struct k1_auth_map_pair {
    struct k1_auth_map_key key;
    struct k1_auth_map_value value;
};

struct k1_verdict_map_user_pair {
    struct k1_verdict_map_user_key key;
    struct k1_verdict_map_user_value value;
};

struct k1_exception_map_pathname_key {
    uid_t uid;
    enum K1_VERDICT_HOOK verdict_hook;
    enum K1_VERDICT_MAP_TYPE verdict_map_type;
    __u64 inode_no;
    dev_t s_dev;
};

// if this value exists, it means this pathname is either black listed or white
// listed, we can diffrenciate using a boolean
struct k1_exception_map_pathname_value {
    bool is_whitelist;
};

struct k1_exception_map_pathname_pair {
    struct k1_exception_map_pathname_key key;
    struct k1_exception_map_pathname_value value;
};

// uniqely identify files across filesystems
struct k1_trust_map_file2sha256_key {
    __u64 inode_no;
    dev_t s_dev;
};

struct k1_trust_map_file2sha256_value {
    __u8 sha256[32];
};

struct k1_trust_map_file2sha256_pair {
    struct k1_trust_map_file2sha256_key key;
    struct k1_trust_map_file2sha256_value value;
};
#endif
