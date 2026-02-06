// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <helper.h>
#include <k1_bpf_util.h>
#include <k1_map.h>

#ifndef __BPF__
#define __BPF__
#endif

struct k1_refcounting_map_old_sessionid_value {
    __u64 sesssoinid;
};
struct k1_refcounting_map_old_sessionid_hash {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct k1_refcounting_map_old_sessionid_value);
};
struct k1_refcounting_map_old_sessionid_hash
    __attribute__((weak)) refcounting_map_old_sessionid_hash SEC(".maps");

inline int k1_bpf_cleanup_sessionid(__u64 sid) {
    bpf_printk("cleaning up sid: %d", sid);

    struct k1_verdict_map_session_key verdict_map_session_key = {
        .verdict_hook = _K1_VERDICT_HOOK_UNSPEC, .sid = INVALID_SESSIONID};
    enum K1_VERDICT_HOOK current_verdict_hook = _K1_VERDICT_HOOK_UNSPEC;
    struct k1_refcounting_map_session_key refcounting_map_session_key = {
        .sid = sid};

    verdict_map_session_key.sid = refcounting_map_session_key.sid;
    bpf_map_delete_elem(
        &refcounting_map_session_hash, &refcounting_map_session_key.sid);
    /* refcount has hit zero, clean corresponding entries */
    bpf_for(
        current_verdict_hook,
        _K1_VERDICT_HOOK_UNSPEC + 1,
        _K1_VERDICT_HOOK_SIZE) {
        verdict_map_session_key.verdict_hook = current_verdict_hook;
        bpf_map_delete_elem(
            &verdict_map_session_hash, &verdict_map_session_key);
    }
    return 0;
}

inline __u64 k1_bpf_dec_sessionid_refcount(__u64 sessionid) {
    struct k1_refcounting_map_session_key refcounting_map_session_key = {
        .sid = sessionid};
    struct k1_refcounting_map_session_value *refcounting_map_session_value =
        NULL;

    refcounting_map_session_value = bpf_map_lookup_elem(
        &refcounting_map_session_hash, &refcounting_map_session_key);

    if(!refcounting_map_session_value)
        return -ENOENT;

    return __sync_fetch_and_sub(&refcounting_map_session_value->refcount, 1);
}

inline __u64 k1_bpf_inc_sessionid_refcount(__u64 sessionid) {
    struct k1_refcounting_map_session_key refcounting_map_session_key = {
        .sid = sessionid,
    };
    struct k1_refcounting_map_session_value *refcounting_map_session_value =
        NULL;

    refcounting_map_session_value = bpf_map_lookup_elem(
        &refcounting_map_session_hash, &refcounting_map_session_key);

    if(!refcounting_map_session_value)
        return -ENOENT;

    return __sync_fetch_and_add(&refcounting_map_session_value->refcount, 1);
}

SEC("tp/sched/sched_process_fork")
int BPF_PROG(refcount_session_sched_process_fork) {
    __u64 current_sid = k1_bpf_get_current_sessionid();
    struct k1_refcounting_map_session_value refcount_one = {.refcount = 1};
    pid_t current_uid = bpf_get_current_uid_gid() & NBYTES_MASK(4);
    void *do_track_session =
        bpf_map_lookup_elem(&users_having_sid_verdict_map_hash, &current_uid);

    if(!do_track_session)
        return 0;
    if(current_sid == INVALID_SESSIONID)
        return 0;

    /*error is ignored, a user's old sessions are not tracked*/
    k1_bpf_inc_sessionid_refcount(current_sid);

    return 0;
}
SEC("tp/syscalls/sys_exit_setsid")
int BPF_PROG(refcount_session_exit_setsid, int nr, int ret) {
    struct k1_refcounting_map_old_sessionid_value
        *refcounting_map_old_sessionid_value = NULL;
    struct k1_refcounting_map_session_key refcounting_map_session_key = {
        .sid = k1_bpf_get_current_sessionid(),
    };
    struct k1_refcounting_map_session_value refcounting_map_session_value = {
        .refcount = 1};
    struct task_struct *current_task = NULL;
    __u32 current_uid = bpf_get_current_uid_gid() & NBYTES_MASK(4);
    __u64 original_refcount = -1;

    if(ret < 0)
        return 0;
    if(!bpf_map_lookup_elem(&users_having_sid_verdict_map_hash, &current_uid))
        return 0;
    if(refcounting_map_session_key.sid == INVALID_SESSIONID)
        return 0;

    /*tracking new session*/
    bpf_map_update_elem(
        &refcounting_map_session_hash,
        &refcounting_map_session_key,
        &refcounting_map_session_value,
        BPF_ANY);

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if(!current_task)
        return 0;

    refcounting_map_old_sessionid_value = bpf_task_storage_get(
        &refcounting_map_old_sessionid_hash, current_task, NULL, 0);
    if(!refcounting_map_old_sessionid_value)
        return 0;

    /*error is ignored, a user's old sessions are not tracked*/
    original_refcount = k1_bpf_dec_sessionid_refcount(
        refcounting_map_old_sessionid_value->sesssoinid);

    if(original_refcount < 0)
        return 0;
    if(original_refcount == 1)
        k1_bpf_cleanup_sessionid(
            refcounting_map_old_sessionid_value->sesssoinid);

    return 0;
}

SEC("tp/syscalls/sys_enter_setsid")
int BPF_PROG(refcount_session_enter_setsid) {
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task_btf();
    struct k1_refcounting_map_old_sessionid_value value = {
        .sesssoinid = k1_bpf_get_current_sessionid()};

    if(value.sesssoinid == INVALID_SESSIONID)
        return 0;

    if(!current_task)
        return 0;

    struct k1_refcounting_map_old_sessionid_value *test;
    test = bpf_task_storage_get(
        &refcounting_map_old_sessionid_hash,
        current_task,
        &value,
        BPF_LOCAL_STORAGE_GET_F_CREATE);
    if(!test) {
        bpf_printk("enexpected error updating task storage");
        return 0;
    }
    if(test->sesssoinid != value.sesssoinid)
        bpf_printk(
            "task storage didn't update, expected: %d, got: %d",
            value.sesssoinid,
            test->sesssoinid);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int BPF_PROG(refcount_session_sched_process_exit) {
    __u64 current_sessionid = k1_bpf_get_current_sessionid();
    __u64 original_refcount = -1;

    if(current_sessionid == INVALID_SESSIONID) {
        bpf_printk("error getting sessionid");
        return 0;
    }
    original_refcount = k1_bpf_dec_sessionid_refcount(current_sessionid);

    if(original_refcount != 1)
        return 0;

    k1_bpf_cleanup_sessionid(current_sessionid);

    return 0;
}
