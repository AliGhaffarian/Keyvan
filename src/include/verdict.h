#ifndef VERDICT
#define VERDICT

#include <stdbool.h>
#include <k1_limits.h>

enum K1_VERDICT_HOOK {
    _K1_VERDICT_HOOK_UNSPEC,
    K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
    _K1_VERDICT_HOOK_SIZE
};

#endif
