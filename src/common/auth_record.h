#ifndef AUTH_RECORD
#define AUTH_RECORD

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <sys/types.h>
#endif

#include <auth_cred.h>
#include <k1_limits.h>
#include <verdict_record.h>

struct k1_auth_record {
    uid_t uid;
    bool is_authenticated;
    enum K1_VERDICT_HOOK verdict_hook;
    struct k1_auth_cred auth_cred;
};

struct k1_auth_record_list {
    int len;
    struct k1_auth_record records[K1_MAX_USER_RECORDS];
};

struct k1_sys_record {
    bool is_authenticated;
    enum K1_VERDICT_HOOK verdict_hook;
    K1_AUTH_CRED_UNION;
};
#endif
