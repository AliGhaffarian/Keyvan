#ifndef K1_BPF_UTIL
#define K1_BPF_UTIL

#ifndef __BPF__
#define __BPF__
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>
#endif

#include <auth_record.h>
#include <errno.h>
#include <helper.h>
#include <k1_limits.h>
#include <k1_map.h>
#include <k1_map_keys_values.h>
#include <verdict_record.h>

#define BPF_FOR_EACH_MAP_ELEM_STOP     1
#define BPF_FOR_EACH_MAP_ELEM_CONTINUE 0

inline int k1_strcmp(char *first, char *second) {
    int cnt = 0;
    while(*first && *second && cnt < K1_BPF_STRING_MAXSIZE) {
        if(*first != *second)
            return *first;
        first++;
        second++;
        cnt++;
    }
    return (*first || *second);
}

enum K1_FLAG_CHANGE_OPS {
    _K1_FLAG_CHANGE_OPS_ENUM_UNSPEC,
    K1_FLAG_CHANGE_SET,
    K1_FLAG_CHANGE_CLEAR,
    K1_FLAG_CHANGE_TOGGLE,
    _K1_FLAG_CHANGE_OPS_ENUM_SIZE,
};

static inline void k1_do_op_on_flag(__u64 *flag, enum K1_FLAG_CHANGE_OPS op) {
    switch(op) {
    case(K1_FLAG_CHANGE_CLEAR):
        __sync_lock_test_and_set(flag, 0);
        *flag = 0;
        break;
    case(K1_FLAG_CHANGE_SET):
        __sync_lock_test_and_set(flag, 1);
        break;
    case(K1_FLAG_CHANGE_TOGGLE):
        __sync_fetch_and_xor(flag, 1);
        break;
    // should never happen
    default:
        break;
    }
    return;
}

inline void k1_change_user_auth_state(
    struct k1_verdict_entry_lookup_info *verdict_entry_lookup_info,
    uid_t uid,
    enum K1_FLAG_CHANGE_OPS op) {

    struct k1_verdict_map_user_value *elem = NULL;
    struct k1_verdict_map_user_key key = {
        .uid = uid,
        .verdict_hook = verdict_entry_lookup_info->verdict_hook,
    };

    if(uid == INVALID_UID)
        key.uid = bpf_get_current_uid_gid() & 0xffffffff;

    elem = bpf_map_lookup_elem(&verdict_map_user_hash, &key);

    // caller needs to make sure this doesnt happen
    if(!elem)
        return;

    k1_do_op_on_flag(&elem->record.is_authenticated, op);
}

struct find_auth_record_ctx {
    struct k1_auth_map_key *key;
    struct k1_auth_map_value *result;
};

/**
 * @return on success, ctx->result points to the found auth_record, with the
 * related uid in ctx->key, on error, uid of ctx->key is INVALID_UID
 */
static long first_auth_record_with_uid_of_context(
    struct bpf_map *registered_map,
    const void *current_uid_key,
    void *value,
    void *ctx) {
    void *lookup_result;
    struct find_auth_record_ctx *ctx_casted = ctx;
    __u32 current_uid = *(__u32 *)current_uid_key;

    AUTHMAP_KEY_SET_UID(ctx_casted->key, current_uid);

    lookup_result = bpf_map_lookup_elem(&auth_map_hash, ctx_casted->key);

    if(!lookup_result) {
        AUTHMAP_KEY_SET_UID(ctx_casted->key, INVALID_UID);
        return BPF_FOR_EACH_MAP_ELEM_CONTINUE;
    }

    ctx_casted->result = lookup_result;
    return BPF_FOR_EACH_MAP_ELEM_STOP;
}

inline void *_k1_bpf_auth_map_lookup_any_uid(struct k1_auth_map_key *key) {
    __u32 tmp_ptr;
    __u32 uid_ptr;
    long err;

    struct find_auth_record_ctx ctx = {
        .key = key,
        .result = NULL,
    };

    err = bpf_for_each_map_elem(
        &registered_uids_map_hash,
        first_auth_record_with_uid_of_context,
        &ctx,
        0);
    if(err == -EINVAL)
        return NULL;

    return ctx.result;
}

/**
 * @brief lookup the auth_record related to the given key
 *
 * @param key key to search, use AUTHMAP_KEY_SET_UID(*key, INVALID_UID) to
 * search for any uid related to the rest of the key
 *
 * @return result of bpf_map_lookup_elem, if uid is INVALID_UID, result of the
 * last called bpf_map_lookup_elem if returned
 */
inline struct k1_auth_map_value *
k1_bpf_auth_map_lookup(struct k1_auth_map_key *key) {
    if(AUTHMAP_KEY_GET_UID(key) == INVALID_UID) {
        return _k1_bpf_auth_map_lookup_any_uid(key);
    }
    return bpf_map_lookup_elem((void *)&auth_map_hash, (void *)key);
}
#endif
