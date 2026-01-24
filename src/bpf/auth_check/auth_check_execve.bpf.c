// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef __BPF__
#define __BPF__
#endif

#include <auth_cred.h>
#include <auth_record.h>
#include <k1_bpf_util.h>
#include <k1_limits.h>
#include <k1_map.h>

SEC("tp/syscalls/sys_enter_execve")
int BPF_PROG(auth_cred_execve_check, void *a, void *b, char *filename) {

    char buf[K1_BPF_STRING_MAXSIZE];
    bpf_core_read_user(buf, K1_BPF_STRING_MAXSIZE - 1, filename);
    buf[K1_BPF_STRING_MAXSIZE - 1] = 0;

    u32 uid = bpf_get_current_uid_gid() & 0xffff;
    struct k1_auth_map_key key = {
        .uid = uid,
        .auth_type = K1_AUTH_TYPE_EXECVE,
    };
    struct k1_auth_record *elem = k1_bpf_lookup_auth_record(&key);
    if(!elem) {
        return 0;
    }

    if(k1_strcmp(buf, elem->auth_cred.auth_cred_execve.pathname) == 0)
        k1_change_user_auth_state(
            elem->verdict_hook, uid, K1_FLAG_CHANGE_TOGGLE);

    return 0;
}

char __license[] SEC("license") = "GPL";
