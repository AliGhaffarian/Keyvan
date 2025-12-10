#ifndef AUTH_CRED
#define AUTH_CRED

#include <stdbool.h>
#include <k1_limits.h>

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

#define K1_AUTH_CRED_UNION union {\
        struct k1_auth_cred_execve auth_cred_execve;\
        struct k1_auth_cred_usb auth_cred_usb;\
    }\

struct k1_auth_cred {
    enum K1_AUTH_TYPE auth_type;
    K1_AUTH_CRED_UNION;
};

#endif
