#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <auth_record.h>
#include <auth_cred.h>
#include <k1_map.h>
#include <k1_limits.h>
#include <k1_bpf_util.h>

struct k1_sys_auth_map_hash sys_auth_map_hash SEC(".maps");
struct k1_verdict_map_hash verdict_map_hash SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int BPF_PROG(auth_execve_check, void *a, void* b, char *filename){

    char buf[K1_BPF_STRING_MAXSIZE];
    bpf_core_read_user(buf, K1_BPF_STRING_MAXSIZE - 1, filename);
    buf[K1_BPF_STRING_MAXSIZE - 1] = 0;

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_sys_record_list *elem = bpf_map_lookup_elem(&sys_auth_map_hash, &uid);
    if(!elem){
        return 0;
    }

    for(int i = 0; i < elem->len && i < K1_MAX_USER_RECORDS; i++){
        if( K1_AUTH_TYPE_EXECVE != elem->records[i].auth_check_detail.auth_type )
            continue;

        if(k1_strcmp(buf, elem->records[i].auth_check_detail.auth_execve.pathname) == 0)
            k1_change_user_auth_state(elem->records[i].verdict_hook, uid, K1_FLAG_CHANGE_TOGGLE);
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
