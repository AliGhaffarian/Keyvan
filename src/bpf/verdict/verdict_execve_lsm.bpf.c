// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef __BPF__
#define __BPF__
#endif

#include <auth_record.h>
#include <k1_bpf_util.h>
#include <k1_map.h>
#include <verdict_record.h>

#define LSM_ALLOW 0
#define LSM_DENY  -1

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(verdict_execve_lsm) {

    __u64 current_sid = k1_bpf_get_current_sessionid();
    u32 uid = bpf_get_current_uid_gid() & NBYTES_MASK(4);
    struct k1_verdict_map_session_key session_key = {
        .verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
        .sid = k1_bpf_get_current_sessionid(),
    };
    struct k1_verdict_map_user_key user_key = {
        .uid = uid, .verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC};
    struct k1_verdict_map_user_value *user_elem = NULL;
    struct k1_verdict_map_session_value *session_elem = NULL;

    // is user registered for session based verdict
    if(bpf_map_lookup_elem(&users_having_sid_verdict_map_hash, &uid)) {
        if(!bpf_map_lookup_elem(&refcounting_map_session_hash, &current_sid))
            goto fallback_uid_mode;

        if((session_elem = bpf_map_lookup_elem(
                &verdict_map_session_hash, &session_key)) == NULL)
            return LSM_DENY; // no auth checker has interacted with this session
        if(!session_elem->record.is_authenticated)
            return LSM_DENY;
        return LSM_ALLOW;
    }

fallback_uid_mode:
    // fall back to uid based authentication

    user_elem = bpf_map_lookup_elem(&verdict_map_user_hash, &user_key);

    if(!user_elem)
        return LSM_ALLOW;

    if(!user_elem->record.is_authenticated)
        return LSM_DENY;

    return LSM_ALLOW;
}

char __license[] SEC("license") = "GPL";
