#ifndef K1_BPF_UTIL
#define K1_BPF_UTIL

#ifndef __BPF__
#define __BPF__
#endif
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <auth_record.h>
#include <errno.h>
#include <helper.h>
#include <k1_limits.h>
#include <k1_map.h>
#include <k1_map_pairs.h>
#include <verdict_record.h>

#define BPF_FOR_EACH_MAP_ELEM_STOP     1
#define BPF_FOR_EACH_MAP_ELEM_CONTINUE 0

enum K1_VERDICT_ACTION {
    K1_VERDICT_NOOP,
    K1_VERDICT_ALLOW,
    K1_VERDICT_DENY,
    _K1_VERDICT_DENY_SIZE,
};

enum LSM_ACTION {
    LSM_DENY = -1,
    LSM_ALLOW = 0
};

__always_inline int
verdict_action2lsm_verdict(enum K1_VERDICT_ACTION verdict_action)
{
    switch(verdict_action) {
    case K1_VERDICT_ALLOW:
        return LSM_ALLOW;
    case K1_VERDICT_DENY:
        return LSM_DENY;
    default:
        return LSM_DENY;
    }
}

inline int k1_strcmp(char *first, char *second)
{
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

static inline void k1_do_op_on_flag(__u64 *flag, enum K1_FLAG_CHANGE_OPS op)
{
    __u64 set_num = 0;
    switch(op) {
    case(K1_FLAG_CHANGE_CLEAR):
        __sync_lock_test_and_set(flag, 0);
        *flag = 0;
        break;
    case(K1_FLAG_CHANGE_SET):
        __sync_lock_test_and_set(flag, 1);
        break;
    case(K1_FLAG_CHANGE_TOGGLE):
        // TODO: can we have a xor mask that enables this in a single xor?
        bpf_printk("warning, racy operation used: toggle");
        set_num = (*flag) == 1 ? 0 : 1;
        __sync_lock_test_and_set(flag, set_num);
        break;
    // should never happen
    default:
        break;
    }
    return;
}

inline __u64 k1_bpf_get_current_sessionid()
{

    struct task_struct *current_task = NULL;
    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if(!current_task) {
        bpf_printk("unexpected error getting current session id");
        return INVALID_SESSIONID;
    }

    return BPF_CORE_READ(
        current_task, signal, pids[PIDTYPE_SID], numbers[0].nr);
}

inline __u32 k1_bpf_get_current_euid()
{
    __u32 err = INVALID_UID;
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task_btf();
    if(!current_task) {
        bpf_printk("unexpected error getting euid");
        return err;
    }
    return BPF_CORE_READ(current_task, cred, euid).val;
}

inline void k1_change_session_auth_state(
    struct k1_verdict_entry_lookup_info *verdict_entry_lookup_info,
    pid_t sessionid,
    enum K1_FLAG_CHANGE_OPS op)
{

    const int zero = 0;
    struct k1_verdict_map_session_value *elem = NULL;
    struct k1_verdict_map_session_key key = {
        .sid = sessionid,
        .verdict_hook = verdict_entry_lookup_info->verdict_hook,
    };

    if(sessionid == INVALID_SESSIONID)
        key.sid = k1_bpf_get_current_sessionid();

    elem = bpf_map_lookup_elem(&verdict_map_session_hash, &key);

    // first time operating on this session
    if(!elem) {
        // TODO: Decide what to do if this fails
        bpf_map_update_elem(&verdict_map_session_hash, &key, &zero, BPF_ANY);
        elem = bpf_map_lookup_elem(&verdict_map_session_hash, &key);

        // just to satisfay the verifier
        if(!elem)
            return;
    }

    k1_do_op_on_flag(&elem->record.is_authenticated, op);
}

inline void k1_change_user_auth_state(
    struct k1_verdict_entry_lookup_info *verdict_entry_lookup_info,
    uid_t euid,
    enum K1_FLAG_CHANGE_OPS op)
{

    struct k1_verdict_map_user_value *elem = NULL;
    struct k1_verdict_map_user_key key = {
        .euid = euid,
        .verdict_hook = verdict_entry_lookup_info->verdict_hook,
    };

    if(euid == INVALID_UID)
        key.euid = k1_bpf_get_current_euid();

    elem = bpf_map_lookup_elem(&verdict_map_user_hash, &key);

    // caller needs to make sure this doesn't happen
    if(!elem)
        return;

    k1_do_op_on_flag(&elem->record.is_authenticated, op);
}

/**
 * @brief context struct used in `first_auth_record_with_euid_of_context()`
 */
struct find_auth_record_ctx {
    struct k1_auth_map_key *key;
    struct k1_auth_map_value *result;
};

/**
 * @return on success, ctx->result points to the found auth_record, with the
 * related euid in ctx->key, on error, euid of ctx->key is INVALID_UID
 */
static long first_auth_record_with_euid_of_context(
    struct bpf_map *registered_map,
    const void *current_euid_key,
    void *value,
    void *ctx)
{
    void *lookup_result;
    struct find_auth_record_ctx *ctx_casted = ctx;
    __u32 current_euid = *(__u32 *)current_euid_key;

    AUTHMAP_KEY_SET_EUID(ctx_casted->key, current_euid);

    lookup_result = bpf_map_lookup_elem(&auth_map_hash, ctx_casted->key);

    if(!lookup_result) {
        AUTHMAP_KEY_SET_EUID(ctx_casted->key, INVALID_UID);
        return BPF_FOR_EACH_MAP_ELEM_CONTINUE;
    }

    ctx_casted->result = lookup_result;
    return BPF_FOR_EACH_MAP_ELEM_STOP;
}

inline void *_k1_bpf_auth_map_lookup_any_euid(struct k1_auth_map_key *key)
{
    __u32 tmp_ptr;
    __u32 euid_ptr;
    long err;

    struct find_auth_record_ctx ctx = {
        .key = key,
        .result = NULL,
    };

    err = bpf_for_each_map_elem(
        &registered_euids_map_hash,
        first_auth_record_with_euid_of_context,
        &ctx,
        0);
    if(err == -EINVAL)
        return NULL;

    return ctx.result;
}

/**
 * @brief lookup the auth_record related to the given key
 *
 * @param key key to search, use AUTHMAP_KEY_SET_EUID(*key, INVALID_UID) to
 * search for any euid related to the rest of the key
 *
 * @return result of bpf_map_lookup_elem, if euid is INVALID_UID, result of the
 * last called bpf_map_lookup_elem if returned
 */
inline struct k1_auth_map_value *
k1_bpf_auth_map_lookup(struct k1_auth_map_key *key)
{
    if(AUTHMAP_KEY_GET_EUID(key) == INVALID_UID) {
        return _k1_bpf_auth_map_lookup_any_euid(key);
    }
    return bpf_map_lookup_elem((void *)&auth_map_hash, (void *)key);
}

#endif
