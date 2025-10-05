#ifndef AUTH_LIST
#define AUTH_LIST

#include <stdbool.h>
#include <k1_limits.h>
#include <auth_check.h>
#include <verdict.h>

struct k1_auth_verdict_pair {
    enum K1_AUTH_TYPE auth_type;
    enum K1_VERDICT_HOOK verdict_hook;
};

struct k1_auth_details {
    struct k1_auth_verdict_pair auth_verdict_pair;
    bool is_authenticated;
    union {
        struct k1_auth_execve execve_details;
    };
};

struct k1_auth_details_list {
    int len;
    struct k1_auth_details auth_details[K1_MAX_USER_AUTH_DETAILS];
};
#endif
