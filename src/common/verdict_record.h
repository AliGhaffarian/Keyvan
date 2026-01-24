#ifndef K1_VERDICT_RECORD
#define K1_VERDICT_RECORD

#include <auth_cred.h>
#include <k1_limits.h>
#include <stdbool.h>

enum K1_VERDICT_HOOK {
    _K1_VERDICT_HOOK_UNSPEC,
    K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
    _K1_VERDICT_HOOK_SIZE
};

struct k1_verdict_record {
    bool is_authenticated;
};

struct k1_verdict_record_list {
    int len;
    struct k1_verdict_record records[K1_MAX_USER_RECORDS];
};

#endif
