#ifndef K1_ENUM_TO_STRING_MAPS
#define K1_ENUM_TO_STRING_MAPS

#include <auth_cred.h>
#include <linux/hash_info.h>
#include <verdict_record.h>

extern char *enum_to_string_k1_auth_type[];
enum K1_AUTH_TYPE enum_from_string_k1_auth_type(char *);

extern char *enum_to_string_k1_verdict_hook[];
enum K1_VERDICT_HOOK enum_from_string_k1_verdict_hook(char *);

extern char *enum_to_string_k1_verdict_map_type[];
enum K1_VERDICT_MAP_TYPE enum_from_string_k1_verdict_map_type(char *);

enum hash_algo enum_from_string_hash_algo(char *str);

// copied from
// https://elixir.bootlin.com/linux/v6.19-rc5/source/lib/crypto/hash_info.c#L11
extern const char *const hash_algo_name[HASH_ALGO__LAST];
#endif
