#include <helper.h>
#include <k1/logger.h>
#include <string.h>

volatile int current_log_level = LOG_INFO;

const char *LOG_LEVELS2STR[] = {
    [LOG_INFO] = "INFO",
    [LOG_WARN] = "WARN",
    [LOG_ERROR] = "ERROR",
    [LOG_DEBUG] = "DEBUG",
};

enum LOG_LEVELS enum_from_string_log_levels(char *str)
{
    for(int i = LOG_INFO; i < LOG_DEBUG + 1; i++)
        if(!strcmp(str, LOG_LEVELS2STR[i]))
            return i;
    return 0;
}
