#ifndef AUTH_CRED
#define AUTH_CRED

#include <k1_limits.h>
#include <stdbool.h>

enum K1_AUTH_TYPE {
    _K1_AUTH_UNSPEC,
    K1_AUTH_TYPE_EXECVE,
    K1_AUTH_TYPE_USB,
    _K1_AUTH_ENUM_SIZE
};

struct k1_auth_cred_execve {
    char pathname[K1_BPF_STRING_MAXSIZE];
};

struct k1_auth_cred_usb {
    char serial[K1_BPF_STRING_MAXSIZE];
};

#endif
