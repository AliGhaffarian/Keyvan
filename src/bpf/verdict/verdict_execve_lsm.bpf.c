#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <verdict.h>
#include <auth_list.h>
#include <user_map.h>

#define LSM_ALLOW 0
#define LSM_DENY -1

struct k1_user_map_struct __attribute__((weak)) k1_user_map SEC(".maps");

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(verdict_execve_lsm){

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_auth_details_list*elem = bpf_map_lookup_elem(&k1_user_map, &uid);
    if(!elem)
        return LSM_ALLOW;

    for(int i = 0; i < elem->len && i < K1_MAX_USER_AUTH_DETAILS; i++){
        if (K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC != elem->auth_details[i].verdict_hook)
            continue;

        if (!elem->auth_details[i].is_authenticated)
            return LSM_DENY;
    }

    return LSM_ALLOW;
}

char __license[] SEC("license") = "GPL";
