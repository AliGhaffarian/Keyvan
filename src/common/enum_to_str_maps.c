#include <auth_cred.h>
#include <helper.h>
#include <string.h>
#include <k1_map_keys_values.h>

#include "enum_to_str_maps.h"

enum K1_AUTH_TYPE enum_from_string_k1_auth_type(char *str) {
    for(int i = 0; i < _K1_AUTH_ENUM_SIZE; i++)
        if(!strcmp(str, enum_to_string_k1_auth_type[i]))
            return i;
    return _K1_AUTH_UNSPEC;
};

char *enum_to_string_k1_auth_type[] = {
    [_K1_AUTH_UNSPEC] = STR(_K1_AUTH_UNSPEC),
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
    [_K1_VERDICT_HOOK_UNSPEC] = STR(_K1_VERDICT_HOOK_UNSPEC),
    [K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC] =
        STR(K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC),
};

enum K1_VERDICT_MAP_TYPE enum_from_string_k1_verdict_map_type(char *str) {
    for(int i = 0; i < _K1_VERDICT_MAP_SIZE; i++)
        if(!strcmp(str, enum_to_string_k1_verdict_map_type[i]))
            return i;
    return _K1_VERDICT_MAP_UNSPEC;
};

char *enum_to_string_k1_verdict_map_type[] = {
    [_K1_VERDICT_MAP_UNSPEC] = STR(_K1_VERDICT_MAP_UNSPEC),
    [K1_VERDICT_MAP_UID] =
        STR(K1_VERDICT_MAP_UID),
    [K1_VERDICT_MAP_SID] = STR(K1_VERDICT_MAP_UID)
};
