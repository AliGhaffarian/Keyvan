#ifndef AUTH_CHECK
#define AUTH_CHECK

#include <stdbool.h>
#include <k1_limits.h>

enum K1_AUTH_TYPE {
    _K1_AUTH_UNSPEC,
    K1_AUTH_TYPE_EXECVE,
    _K1_AUTH_ENUM_SIZE
};

struct k1_auth_execve {
    char pathname[K1_BPF_STRING_MAXSIZE];
};

#endif
