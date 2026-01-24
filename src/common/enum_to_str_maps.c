#include <auth_cred.h>
#include <helper.h>
#include <string.h>

#include "enum_to_str_maps.h"

enum K1_AUTH_TYPE enum_from_string_k1_auth_type(char *str) {
    for(int i = 0; i < _K1_AUTH_ENUM_SIZE; i++)
        if(!strcmp(str, enum_to_string_k1_auth_type[i]))
            return i;
    return _K1_AUTH_UNSPEC;
};

char *enum_to_string_k1_auth_type[] = {
    [K1_AUTH_TYPE_EXECVE] = STR(K1_AUTH_TYPE_EXECVE),
    [K1_AUTH_TYPE_USB] = STR(K1_AUTH_TYPE_USB),
};

enum K1_VERDICT_HOOK enum_from_string_k1_verdict_hook(char *str) {
    for(int i = 0; i < _K1_VERDICT_HOOK_SIZE; i++)
        if(!strcmp(str, enum_to_string_k1_verdict_hook[i]))
            return i;
    return _K1_VERDICT_HOOK_UNSPEC;
};

char *enum_to_string_k1_verdict_hook[] = {
    [K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC] =
        STR(K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC),
};
