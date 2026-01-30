#include <helper.h>
#include <k1/logger.h>

volatile int current_log_level = LOG_INFO;

const char* LOG_LEVELS2STR[] = {
    [LOG_INFO] = "INFO",
    [LOG_WARN] = "WARN",
    [LOG_ERROR] = "ERROR",
    [LOG_DEBUG] = "DEBUG",
};
