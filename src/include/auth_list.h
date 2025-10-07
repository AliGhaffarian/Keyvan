#ifndef AUTH_LIST
#define AUTH_LIST

#include <stdbool.h>
#include <k1_limits.h>
#include <auth_check.h>
#include <verdict.h>

struct k1_sys_record {
    bool is_authenticated;
    enum K1_VERDICT_HOOK verdict_hook;
    struct k1_auth_check_detail auth_check_detail;
};

struct k1_sys_record_list {
    int len;
    struct k1_sys_record records[K1_MAX_USER_RECORDS];
};
#endif
