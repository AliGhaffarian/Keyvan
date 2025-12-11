#include <vmlinux.h>
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

struct k1_verdict_map_hash __attribute__((weak)) verdict_map_hash SEC(".maps");

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(verdict_execve_lsm){

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_verdict_record_list *elem = bpf_map_lookup_elem(&verdict_map_hash, &uid);
    if(!elem)
        return LSM_ALLOW;

    for(int i = 0; i < elem->len && i < K1_MAX_USER_RECORDS; i++){
        if (K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC != elem->records[i].verdict)
            continue;

        if (!elem->records[i].is_authenticated)
            return LSM_DENY;
    }

    return LSM_ALLOW;
}

char __license[] SEC("license") = "GPL";
