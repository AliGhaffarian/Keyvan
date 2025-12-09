#ifndef K1_COMMON
#define K1_COMMON

#include <auth_cred.h>
#include <verdict_record.h>

#define _STR(x) #x
#define STR(x) _STR(x)

extern char *enum_to_string_k1_auth_type[];
enum K1_AUTH_TYPE enum_from_string_k1_auth_type(char *);

extern char *enum_to_string_k1_verdict_hook[];
enum K1_VERDICT_HOOK enum_from_string_k1_verdict_hook(char *);

#endif
