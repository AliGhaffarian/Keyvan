// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef __BPF__
#define __BPF__
#endif

#include <verdict_record.h>
#include <auth_record.h>
#include <k1_map.h>

#define LSM_ALLOW 0
#define LSM_DENY -1

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(verdict_execve_lsm){

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_verdict_map_key key = {
        .uid = uid,
        .hook_type = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC
    };
    struct k1_verdict_record *elem = bpf_map_lookup_elem(&verdict_map_hash, &key);
    if(!elem)
        return LSM_ALLOW;

    if(!elem->is_authenticated)
        return LSM_DENY;

    return LSM_ALLOW;
}

char __license[] SEC("license") = "GPL";
