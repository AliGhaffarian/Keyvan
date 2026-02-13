#ifndef K1_PARSER_STRUCTS
#define K1_PARSER_STRUCTS

#include <k1_map_pairs.h>
#include <stdbool.h>
#include <sys/types.h>
#include <verdict_record.h>

struct k1_parsed_exception_pathname {
    char *pathname;
    uid_t uid;
    enum K1_VERDICT_HOOK verdict_hook;
    enum K1_VERDICT_MAP_TYPE verdict_map_type;
    bool is_whitelist;
};

#endif
