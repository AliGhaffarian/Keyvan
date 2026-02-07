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

Example config:

```
# The following configs are related to uid 1000
uid: 1000

# deny execve until user executes `/some/password`
auth {
	type: execve
	pathname: /some/password #need to execute this pathname to authenticate

    verdict_sub_type: K1_VERDICT_MAP_UID

    # the following verdict associates with the container auth
    verdict {
        type: execve
    }
}
```

Running Keyvan:

```
# build from source
cmake -S . -B build
cd build
make

# run Keyvan
sudo ./output/k1cli --config-file CONFIG_FILENAME
```

## Features
- **Authentication checkers**: eBPF programs that implement authentication logic.
  - `K1_AUTH_TYPE_EXECVE`: authenticates a user when the secret (password) is executed (e.g. `./my_secret`).
  - `K1_AUTH_TYPE_USB`: authenticates a user when a usb device is connected that has the same serial number as the one registered as credential.
- **Verdicts**: eBPF(currently LSM based) checks that check the `is_authenticated` flag and deny access if the flag is not set.
  - `K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC`: LSM hook that is triggered when executing a file.

## Development roadmap
- [x] Proper naming convention in the source code
- [x] Consider requiring re-authentication for each sesssion (like sudo)?
    - This is implemented and will be usable after adding white listing subsystem
- [x] More flexible approach to store authentication information in maps
- [ ] Implement userspace daemon to load/write maps so Keyvan can persist across reboots
- [x] Implement config parser
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
3. Define the credential struct in `include/auth_cred.h`
4. Add the credential struct in `K1_AUTH_CRED_UNION` in `include/auth_cred.h`
5. Update the lexer and parser
6. Update `enum_to_string_k1_auth_type` inside `common/enum_to_str_maps.c`

**Note:** Authentication checker program must call `k1_change_user_auth_state()` when intending to change a record's authentication status.
