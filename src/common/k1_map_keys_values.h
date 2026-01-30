#ifndef K1_MAP_KEYS_VALUES
#define K1_MAP_KEYS_VALUES

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <linux/types.h>
#endif

#include <auth_record.h>
#include <verdict_record.h>

#define DUMMY_MAP_VALUE_T void * // is used when the map value doesn't matter

/**
 * @brief get and set macros for auth_key, to decouple the code
 */
#define AUTHMAP_KEY_SET_UID(key_ptr, u) key_ptr->uid = u
#define AUTHMAP_KEY_GET_UID(key_ptr)    key_ptr->uid

struct k1_auth_map_key {
    __u32 uid;
    enum K1_AUTH_TYPE auth_type;
};

struct k1_verdict_map_key {
    __u32 uid;
    enum K1_VERDICT_HOOK verdict_hook;
};

struct k1_registered_uids_map_key {
    __u32 uid;
};

struct k1_auth_map_value {
    struct k1_auth_record record;
};

struct k1_verdict_map_value {
    struct k1_verdict_record record;
};

struct k1_auth_map_key_value {
    struct k1_auth_map_key key;
    struct k1_auth_map_value value;
};

struct k1_verdict_map_key_value {
    struct k1_verdict_map_key key;
    struct k1_verdict_map_value value;
};

#endif
