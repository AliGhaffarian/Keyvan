#include <helper.h>
#include <k1/logger.h>
#include <string.h>

volatile int current_log_level = LOG_INFO;

const char *LOG_LEVELS2STR[] = {
    [_LOG_UNSPEC] = "ERR: out of bound enum",
    [LOG_NOLOG] = "NOLOG",
    [LOG_INFO] = "INFO",
    [LOG_WARN] = "WARN",
    [LOG_ERROR] = "ERROR",
    [LOG_DEBUG] = "DEBUG",
    [_LOG_SIZE] = "ERR:out of bound enum",
};

enum LOG_LEVELS enum_from_string_log_levels(char *str)
{
    for(int i = _LOG_UNSPEC + 1; i < _LOG_SIZE; i++)
        if(!strcmp(str, LOG_LEVELS2STR[i]))
            return i;
    return 0;
}
