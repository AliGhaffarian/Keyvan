# Keyvan (k1)

**Keyvan** (aka `k1`) is a kernel level access control mechanism implemented using eBPF.
It provides silent authentication checks and access control verdicts for resources
(files, execs, and later network actions). The goal is to allow a machine to appear
unlocked to an unauthorized user while restricting their access in order to confuse them.

## Note to Reader
This readme explains the current implementation. To see the planned, stable version, please read [this file](https://github.com/AliGhaffarian/Keyvan/blob/main/PLANNED_README.md).

## Quick demo

Example: root is restricted until the secret is executed:

```
$ls
zsh: operation not permitted: ls

$./some_secret_password
zsh: no such file or directory: ./some_secret_password

$ls
Clones  Desktop  Documents  Downloads  Templates  Tools  Videos
```

## Quick start
```
# build from source
cmake -S . -B build
cd build
make

# run Keyvan
sudo ./output/k1cli -u 1000 -a K1_AUTH_TYPE_EXECVE -p some_secret_password
```

## Features
- **Authentication checkers**: eBPF programs that implement authentication logic.
  - `K1_AUTH_TYPE_EXECVE`: authenticates a user when the secret (password) is executed (e.g. `./my_secret`).
  - `K1_AUTH_TYPE_USB`: authenticates a user when a usb device is connected that has the same serial number as the one registered as credential.
- **Verdicts**: eBPF(currently LSM based) checks that check the `is_authenticated` flag and deny access if the flag is not set.
  - `K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC`: LSM hook that is triggered when executing a file.

## Development roadmap
- [x] Proper naming convention in the source code
- [ ] Consider requiring re-authentication for each sesssion (like sudo)?
- [x] More flexible approach to store authentication information in maps
- [ ] Implement userspace daemon to load/write maps so Keyvan can persist across reboots
- [ ] Implement config parser
- [ ] Determine white list programs to prevent locking the user out
- [x] Implement logging
- [x] Implement SHA512 or port from OpenSSL(BPF and userspace side)
    - There is an on-going patch that enables the usage of hashing kfuncs inside BPF programs
- [ ] Hash the credentials before writing maps on the disc
- [ ] Web hosted documentation
- [ ] Unit testing

## Adding an authentication mechanism
1. Add the authentication checker BPF program under [`bpf/auth_check`](https://github.com/AliGhaffarian/Keyvan/blob/main/src/bpf/auth_check)
2. Add the authentication type in `include/auth_cred.h` in `K1_AUTH_TYPE` enum
3. Add the credential struct in `include/auth_cred.h`
4. Add the credential struct in `k1_auth_cred` union in `include/auth_cred.h`
5. Add `init_auth_cred_<auth_mechanism_name>()` to parse the credentials and populate the appropriate map
6. Add `init_auth_cred_<auth_mechanism_name>()` to `init_maps_based_on_args()`
7. Update `enum_to_string_k1_auth_type` inside `common/enum_to_str_maps.c`
8. Add `<authentication_mechanism_name>_help` on top of `k1cli/opt.c`

**Note:** Authentication checker program must call `k1_change_user_auth_state()` when intending to change a record's authentication status.
