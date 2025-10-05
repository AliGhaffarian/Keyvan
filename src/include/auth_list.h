#ifndef AUTH_LIST
#define AUTH_LIST

#include <stdbool.h>
#include <k1_limits.h>
#include <auth_check.h>
#include <verdict.h>

struct k1_auth_details {
    bool is_authenticated;
    enum K1_VERDICT_HOOK verdict_hook;
    struct k1_auth_check_detail auth_check_detail;
};

struct k1_auth_details_list {
    int len;
    struct k1_auth_details auth_details[K1_MAX_USER_AUTH_DETAILS];
};
#endif
