#ifndef K1_BPF_UTIL
#define K1_BPF_UTIL

#include <k1_map.h>
#include <bpf/bpf_helpers.h>
#include <k1_limits.h>
#include <verdict_record.h>

struct k1_verdict_map_hash __attribute__((weak)) verdict_map_hash SEC(".maps");

inline int k1_strcmp(char *first, char *second){
    int cnt = 0;
    while(*first && *second && cnt < K1_BPF_STRING_MAXSIZE){
        if(*first != *second)
            return *first;
        first++;
        second++;
        cnt++;
    }
    return (*first || *second);
}

enum K1_FLAG_CHANGE_OPS {
    _K1_FLAG_CHANGE_OPS_ENUM_UNSPEC,
    K1_FLAG_CHANGE_SET,
    K1_FLAG_CHANGE_CLEAR,
    K1_FLAG_CHANGE_TOGGLE,
    _K1_FLAG_CHANGE_OPS_ENUM_SIZE,
};

static inline void k1_do_op_on_flag(bool *flag, enum K1_FLAG_CHANGE_OPS op){
    switch(op){
        case (K1_FLAG_CHANGE_CLEAR): *flag = 0; break;
        case (K1_FLAG_CHANGE_SET): *flag = 1; break;
        case (K1_FLAG_CHANGE_TOGGLE): *flag ^= 1; break;
        // should never happen
        default: break;
    }
    return;
}

inline void k1_change_user_auth_state(enum K1_VERDICT_HOOK verdict, uid_t uid, enum K1_FLAG_CHANGE_OPS op){
    struct k1_verdict_map_key key = {
        .uid = uid,
        .hook_type = verdict,
    };
    struct k1_verdict_record *verdict_list_elem = bpf_map_lookup_elem(&verdict_map_hash, &key);

    //caller needs to make sure this doesnt happen
    if (!verdict_list_elem)
        return;

    k1_do_op_on_flag(&verdict_list_elem->is_authenticated, op);

}

#endif
