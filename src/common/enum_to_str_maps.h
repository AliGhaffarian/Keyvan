#ifndef K1_ENUM_TO_STRING_MAPS
#define K1_ENUM_TO_STRING_MAPS

#include <auth_cred.h>
#include <verdict_record.h>

extern char *enum_to_string_k1_auth_type[];
enum K1_AUTH_TYPE enum_from_string_k1_auth_type(char *);

extern char *enum_to_string_k1_verdict_hook[];
enum K1_VERDICT_HOOK enum_from_string_k1_verdict_hook(char *);

extern char *enum_to_string_k1_verdict_map_type[];
enum K1_VERDICT_MAP_TYPE enum_from_string_k1_verdict_map_type(char *);
#endif
