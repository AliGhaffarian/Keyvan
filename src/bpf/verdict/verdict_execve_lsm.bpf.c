// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef __BPF__
#define __BPF__
#endif

#include <auth_record.h>
#include <k1_bpf_exception.h>
#include <k1_bpf_logger.h>
#include <k1_bpf_util.h>
#include <k1_map.h>
#include <verdict_record.h>

__always_inline enum K1_VERDICT_ACTION
verdict_execve_lsm_sid(struct linux_binprm *bprm)
{
    struct k1_exception_map_pathname_key exception_map_pathname_key = {0};
    __u64 current_sid = k1_bpf_get_current_sessionid();
    u32 euid = k1_bpf_get_current_euid();
    struct k1_verdict_map_session_value *session_elem = NULL;
    struct k1_verdict_map_session_key session_key = {
        .verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
        .sid = k1_bpf_get_current_sessionid(),
    };
    enum K1_VERDICT_ACTION exception_action = K1_VERDICT_NOOP;

    // this user is not registered for a session auth rule
    if(!bpf_map_lookup_elem(&users_having_sid_verdict_map_hash, &euid))
        return K1_VERDICT_NOOP;

    // this session started prior to keyvan's presence
    if(!bpf_map_lookup_elem(&refcounting_map_session_hash, &current_sid))
        return K1_VERDICT_NOOP;

    bpf_printk(
        "hitting refcounted session: %d, %s. inodenum: %d, s_dev: %x, euid: "
        "%d",
        session_key.sid,
        bprm->filename,
        exception_map_pathname_key.inode_no,
        exception_map_pathname_key.s_dev,
        euid);

    exception_action = k1_bpf_handle_exception_pathname(
        K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
        K1_VERDICT_MAP_SID,
        bprm->file,
        bprm->file->f_inode->i_sb->s_dev,
        euid);

    // no match for exception
    if(exception_action != K1_VERDICT_NOOP)
        return exception_action;

    if((session_elem = bpf_map_lookup_elem(
            &verdict_map_session_hash, &session_key)) == NULL)
        return K1_VERDICT_DENY; // no auth checker has interacted with this
                                // session
    if(session_elem->record.is_authenticated == 0)
        return K1_VERDICT_DENY;

    return K1_VERDICT_ALLOW;
};

__always_inline enum K1_VERDICT_ACTION
verdict_execve_lsm_euid(struct linux_binprm *bprm)
{

    enum K1_VERDICT_ACTION exception_action = K1_VERDICT_NOOP;
    u32 euid = k1_bpf_get_current_euid();
    struct k1_verdict_map_user_key user_key = {
        .euid = euid, .verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC};
    struct k1_verdict_map_user_value *user_elem = NULL;
    user_elem = bpf_map_lookup_elem(&verdict_map_user_hash, &user_key);

    // no rule for this user
    if(!user_elem)
        return K1_VERDICT_ALLOW;

    exception_action = k1_bpf_handle_exception_pathname(
        K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
        K1_VERDICT_MAP_EUID,
        bprm->file,
        bprm->file->f_inode->i_sb->s_dev,
        euid);

    if(exception_action != K1_VERDICT_NOOP)
        return exception_action;

    if(!user_elem->record.is_authenticated)
        return K1_VERDICT_DENY;

    // is authenticated
    return K1_VERDICT_ALLOW;
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(verdict_execve_lsm, struct linux_binprm *bprm)
{
    enum K1_VERDICT_ACTION verdict_action = K1_VERDICT_NOOP;

    verdict_action = verdict_execve_lsm_sid(bprm);
    if(verdict_action != K1_VERDICT_NOOP) {
        if(verdict_action == K1_VERDICT_DENY)
            bpf_printk(
                "sid mode: denying %s sid: %d euid: %d",
                bprm->filename,
                k1_bpf_get_current_sessionid(),
                k1_bpf_get_current_euid());
        return verdict_action2lsm_verdict(verdict_action);
    }

fallback_euid_mode:
    // fall back to euid based authentication
    verdict_action = verdict_execve_lsm_euid(bprm);
    if(verdict_action == K1_VERDICT_DENY)
        bpf_printk(
            "euid mode: denying %s sid: %d euid: %d",
            bprm->filename,
            k1_bpf_get_current_sessionid(),
            k1_bpf_get_current_euid());
    return verdict_action2lsm_verdict(verdict_action);
}

char __license[] SEC("license") = "GPL";
