#include <auth_cred.h>
#include <helper.h>
#include <k1_map_pairs.h>
#include <linux/hash_info.h>
#include <string.h>

#include "enum_to_str_maps.h"

enum K1_AUTH_TYPE enum_from_string_k1_auth_type(char *str)
{
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

enum K1_VERDICT_HOOK enum_from_string_k1_verdict_hook(char *str)
{
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

enum K1_VERDICT_MAP_TYPE enum_from_string_k1_verdict_map_type(char *str)
{
    for(int i = 0; i < _K1_VERDICT_MAP_SIZE; i++)
        if(!strcmp(str, enum_to_string_k1_verdict_map_type[i]))
            return i;
    return _K1_VERDICT_MAP_UNSPEC;
};

char *enum_to_string_k1_verdict_map_type[] = {
    [_K1_VERDICT_MAP_UNSPEC] = STR(_K1_VERDICT_MAP_UNSPEC),
    [K1_VERDICT_MAP_UID] = STR(K1_VERDICT_MAP_UID),
    [K1_VERDICT_MAP_SID] = STR(K1_VERDICT_MAP_SID)};

enum hash_algo enum_from_string_hash_algo(char *str)
{
    for(int i = 0; i < HASH_ALGO__LAST; i++)
        if(!strcmp(str, enum_to_string_k1_verdict_map_type[i]))
            return i;
    return -1;
};

// copied from
// https://elixir.bootlin.com/linux/v6.19-rc5/source/lib/crypto/hash_info.c#L11
const char *const hash_algo_name[HASH_ALGO__LAST] = {
    [HASH_ALGO_MD4] = "md4",
    [HASH_ALGO_MD5] = "md5",
    [HASH_ALGO_SHA1] = "sha1",
    [HASH_ALGO_RIPE_MD_160] = "rmd160",
    [HASH_ALGO_SHA256] = "sha256",
    [HASH_ALGO_SHA384] = "sha384",
    [HASH_ALGO_SHA512] = "sha512",
    [HASH_ALGO_SHA224] = "sha224",
    [HASH_ALGO_RIPE_MD_128] = "rmd128",
    [HASH_ALGO_RIPE_MD_256] = "rmd256",
    [HASH_ALGO_RIPE_MD_320] = "rmd320",
    [HASH_ALGO_WP_256] = "wp256",
    [HASH_ALGO_WP_384] = "wp384",
    [HASH_ALGO_WP_512] = "wp512",
    [HASH_ALGO_TGR_128] = "tgr128",
    [HASH_ALGO_TGR_160] = "tgr160",
    [HASH_ALGO_TGR_192] = "tgr192",
    [HASH_ALGO_SM3_256] = "sm3",
    [HASH_ALGO_STREEBOG_256] = "streebog256",
    [HASH_ALGO_STREEBOG_512] = "streebog512",
    [HASH_ALGO_SHA3_256] = "sha3-256",
    [HASH_ALGO_SHA3_384] = "sha3-384",
    [HASH_ALGO_SHA3_512] = "sha3-512",
};
