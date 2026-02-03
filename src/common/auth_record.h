#ifndef AUTH_RECORD
#define AUTH_RECORD

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <linux/types.h>
#endif

#include <auth_cred.h>
#include <k1_limits.h>
#include <verdict_record.h>

struct k1_auth_record {
    enum K1_AUTH_TYPE auth_type;
    union {
        struct k1_auth_cred_execve auth_cred_execve;
        struct k1_auth_cred_usb auth_cred_usb;
    };
};
#endif
