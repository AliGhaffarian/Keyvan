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
    bool is_authenticated;
    enum K1_VERDICT_HOOK verdict_hook;
    struct k1_auth_cred auth_cred;
};
#endif
