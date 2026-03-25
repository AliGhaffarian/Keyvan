#include "parser_enum_maps.h"
#include <string.h>

char *parser_verdict_sub_type_enum2str[] = {
    [K1_VERDICT_MAP_EUID] = "per_user",
    [K1_VERDICT_MAP_SID] = "per_session",
};

enum K1_VERDICT_MAP_TYPE parser_verdict_sub_type_str2enum(char *str)
{
    for(int i = 1; i < _K1_VERDICT_MAP_SIZE; i++)
        if(!strcmp(str, parser_verdict_sub_type_enum2str[i]))
            return i;
    return _K1_VERDICT_MAP_UNSPEC;
}
