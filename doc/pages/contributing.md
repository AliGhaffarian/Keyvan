@page contributing Contributing

# Contributing

## Adding an authentication mechanism
1. Add the authentication checker BPF program under `bpf/auth_check`
2. Add the authentication type in `common/auth_cred.h` in `K1_AUTH_TYPE` enum
3. Define the credential struct in `common/auth_cred.h`
4. Add the credential struct in `K1_AUTH_CRED_UNION` in `common/auth_cred.h`
5. Update the lexer and parser
6. Update `enum_to_string_k1_auth_type` inside `common/enum_to_str_maps.c`

**Note:** Authentication checker program must call `k1_change_user_auth_state()` when intending to change a record's authentication status.

## Todo list

- Allow user to set initial value of `is_authenticated` to true
- Use logging in bpfside
- Allow per rule log level
- Hash the credentials in config file
- Unit testing
- Determine white list programs to prevent locking the user out
    - There is an on-going patch that enables the usage of hashing kfuncs inside BPF programs
- Allow multiple verdicts to associate with a auth checker
- Better logging of error handling

### Todo from source
- `src/bpf/auth_check/auth_check_execve.bpf.c`:    // TODO: users must have the option for multiple instances of authentication
- `src/bpf/include/k1_bpf_util.h`:        // TODO: Decide what to do if this fails
- `src/bpf/include/k1_bpf_logger.h`:// TODO: make the following a char array, problem: "libbpf: relocation against
- `src/libk1/exception/pathname.c`:    // TODO: free this
