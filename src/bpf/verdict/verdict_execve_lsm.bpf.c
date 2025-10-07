#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <verdict.h>
#include <auth_list.h>
#include <k1_map.h>

#define LSM_ALLOW 0
#define LSM_DENY -1

struct k1_auth_map_hash_sys __attribute__((weak)) auth_map_hash_sys SEC(".maps");

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(verdict_execve_lsm){

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_record_list *elem = bpf_map_lookup_elem(&auth_map_hash_sys, &uid);
    if(!elem)
        return LSM_ALLOW;

    for(int i = 0; i < elem->len && i < K1_MAX_USER_RECORDS; i++){
        if (K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC != elem->records[i].verdict_hook)
            continue;

        if (!elem->records[i].is_authenticated)
            return LSM_DENY;
    }

    return LSM_ALLOW;
}

char __license[] SEC("license") = "GPL";
