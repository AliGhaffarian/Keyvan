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

// clang-format off
/**
 * not enum K1_FLAG_CHANGE_OPS, because of the following, weird compiler error:
 *
  * Keyvan/build/src/include/bpf_progs.skel.h:49:27: error: field has incomplete type 'enum K1_FLAG_CHANGE_OPS'
 * 49 |                 enum K1_FLAG_CHANGE_OPS default_action_on_cred_pass;
 *    |                                         ^
 * Keyvan/build/src/include/bpf_progs.skel.h:49:8: note: forward declaration of 'enum K1_FLAG_CHANGE_OPS'
 * 49 |                 enum K1_FLAG_CHANGE_OPS default_action_on_cred_pass;
 *    |  *
 */
// clang-format on

const int default_action_on_cred_pass = K1_FLAG_CHANGE_TOGGLE;

SEC("tp/syscalls/sys_enter_execve")
int BPF_PROG(auth_cred_execve_check, void *a, void *b, char *filename)
{
    bool cred_check = 0;
    enum K1_FLAG_CHANGE_OPS flag_change_op_on_verdict =
        _K1_FLAG_CHANGE_OPS_ENUM_UNSPEC;

    __u64 current_sessionid = k1_bpf_get_current_sessionid();
    char buf[K1_BPF_STRING_MAXSIZE];
    bpf_core_read_user(buf, K1_BPF_STRING_MAXSIZE - 1, filename);
    buf[K1_BPF_STRING_MAXSIZE - 1] = 0;

    u32 euid = k1_bpf_get_current_euid();
    struct k1_auth_map_key key = {
        .euid = euid,
        .auth_type = K1_AUTH_TYPE_EXECVE,
    };
    struct k1_auth_map_value *elem = k1_bpf_auth_map_lookup(&key);
    if(!elem) {
        return 0;
    }

    cred_check = k1_strcmp(buf, elem->record.auth_cred_execve.pathname) == 0;

    /* if cred_check has failed, we didn't change our verdict so we don't need
     * to manipulate the destination verdict if elem->is_authenticated is 1 and
     * cred check has failed, it means we still believe the verdict should
     * allow. we shouldn't stop here because continuing might prevent a value
     * creation on the verdict side (such as per-session verdict type), in that
     * case the verdict will think it should deny the request
     */
    // TODO: fix this mess, there was a bug with default value and
    // K1_VERDICT_MAP_SID, i did this workaround just to ignore it for now
    if(cred_check == 1) {
        k1_do_op_on_flag(&elem->is_authenticated, default_action_on_cred_pass);
    }

    if(elem->verdict_entry_lookup_info.verdict_map_type == K1_VERDICT_MAP_SID)
        if(cred_check == 1)
            flag_change_op_on_verdict = default_action_on_cred_pass;
        else
            return 0;
    else if(elem->is_authenticated)
        flag_change_op_on_verdict = K1_FLAG_CHANGE_SET;
    else
        flag_change_op_on_verdict = K1_FLAG_CHANGE_CLEAR;

    // TODO: users must have the option for multiple instances of authentication
    // methods of the same type, with different verdict records
    switch(elem->verdict_entry_lookup_info.verdict_map_type) {
    case K1_VERDICT_MAP_SID: {
        if(current_sessionid == INVALID_SESSIONID)
            return 0; /*unexpected*/
        if(!bpf_map_lookup_elem(
               &refcounting_map_session_hash, &current_sessionid))
            return 0; /*this session is started before us, thus not tracked*/
        bpf_printk(
            "changing state of session: TOGGLE:%d",
            flag_change_op_on_verdict == K1_FLAG_CHANGE_TOGGLE);
        k1_change_session_auth_state(
            &elem->verdict_entry_lookup_info,
            current_sessionid,
            flag_change_op_on_verdict);
        break;
    }
    case K1_VERDICT_MAP_EUID: {
        k1_change_user_auth_state(
            &elem->verdict_entry_lookup_info, euid, flag_change_op_on_verdict);
        break;
    }
    default:
        return 0; /*should be unreachable*/
    }
    return 0;
}

char __license[] SEC("license") = "GPL";
