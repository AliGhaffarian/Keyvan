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
    __u64 current_sessionid = k1_bpf_get_current_sessionid();
    char buf[K1_BPF_STRING_MAXSIZE];
    bpf_core_read_user(buf, K1_BPF_STRING_MAXSIZE - 1, filename);
    buf[K1_BPF_STRING_MAXSIZE - 1] = 0;

    u32 uid = bpf_get_current_uid_gid() & NBYTES_MASK(4);
    struct k1_auth_map_key key = {
        .uid = uid,
        .auth_type = K1_AUTH_TYPE_EXECVE,
    };
    struct k1_auth_map_value *elem = k1_bpf_auth_map_lookup(&key);
    if(!elem) {
        return 0;
    }

    if(k1_strcmp(buf, elem->record.auth_cred_execve.pathname) != 0)
        return 0;

    // TODO: users must have the option for multiple instances of authentication
    // methods of the same type, with different verdict records
    switch(elem->verdict_entry_lookup_info.verdict_map_type) {
    case K1_VERDICT_MAP_SID: {
        if(current_sessionid == INVALID_SESSIONID)
            return 0; /*unexpected*/
        if(!bpf_map_lookup_elem(
               &refcounting_map_session_hash, &current_sessionid))
            return 0; /*this session is started before us, thus not tracked*/
        bpf_printk("changing state of session");
        k1_do_op_on_flag(&elem->is_authenticated, K1_FLAG_CHANGE_TOGGLE);
        k1_change_session_auth_state(
            &elem->verdict_entry_lookup_info,
            current_sessionid,
            K1_FLAG_CHANGE_TOGGLE);
        break;
    }
    case K1_VERDICT_MAP_UID: {
        k1_do_op_on_flag(&elem->is_authenticated, K1_FLAG_CHANGE_TOGGLE);
        k1_change_user_auth_state(
            &elem->verdict_entry_lookup_info, uid, K1_FLAG_CHANGE_TOGGLE);
        break;
    }
    default:
        return 0; /*should be unreachable*/
    }
    return 0;
}

char __license[] SEC("license") = "GPL";
