#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <auth_list.h>
#include <auth_check.h>
#include <user_map.h>
#include <k1_limits.h>
#include <k1_bpf_util.h>

struct k1_user_map_struct k1_user_map SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int BPF_PROG(auth_execve_check, void *a, void* b, char *filename){

    char buf[K1_BPF_STRING_MAXSIZE];
    bpf_core_read_user(buf, K1_BPF_STRING_MAXSIZE - 1, filename);
    buf[K1_BPF_STRING_MAXSIZE - 1] = 0;

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_auth_details_list*elem = bpf_map_lookup_elem(&k1_user_map, &uid);
    if(!elem){
        return 0;
    }

    for(int i = 0; i < elem->len && i < K1_MAX_USER_AUTH_DETAILS; i++){
        if( K1_AUTH_TYPE_EXECVE != elem->auth_details[i].auth_check_detail.auth_type )
            continue;

        if(k1_strcmp(buf, elem->auth_details[i].auth_check_detail.auth_execve.pathname) == 0)
            elem->auth_details[i].is_authenticated = !elem->auth_details[i].is_authenticated;

    }

    return 0;
}

char __license[] SEC("license") = "GPL";
