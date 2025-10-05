# Keyvan (k1)

**Keyvan** (aka `k1`) is a kernel level access control mechanism implemented using eBPF.
It provides silent authentication checks and access control verdicts for resources
(files, execs, and later network actions). The goal is to allow a machine to appear
unlocked to an unauthorized user while restricting their access in order to confuse them.

## Table of Contents
* [Quick demo](#quick-demo)
* [Quick start](#quick-start)
* [Notes](#notes)
* [Features (current)](#features-current)
  + [Implemented](#implemented)
  + [Planned](#planned)
* [Development roadmap](#development-roadmap)

## Quick demo

Example: root is restricted until the secret is executed:

```sh
ThisHost# ls
zsh: operation not permitted: ls

ThisHost# ./some_secret_password
zsh: no such file or directory: ./some_secret_password

ThisHost# ls
Clones  Desktop  Documents  Downloads  Templates  Tools  Videos
```

## Quick start
```
# build from source
cmake -S . -B build
cd build
make

# run Keyvan
sudo ./src/k1cli/k1cli -u 1000 -p some_secret_password
```

## Notes
The main purpose of k1cli is to communicate with a deamon that is responsible for managing the bpf programs. Until that deamon is implemented, k1cli will serve as a utility to enable using Keyvan.

## Features (current)
- **Authentication checkers**: eBPF programs that implement authentication logic.
  - `K1_AUTH_TYPE_EXECVE`: authenticates a session when the secret (password) is executed (e.g. `./my_secret`).
- **Verdicts**: eBPF(currently LSM based) checks that check the `is_authenticated` flag and deny access if the flag is not set.
  - `K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC`: LSM hook that is triggered when executing a file.

### Implemented
- [x] Execve authentication checker
- [x] File execution verdict

### Planned
- [ ] File write checker
- [ ] IOCTL-based checkers
- [ ] Network access verdict (rule based)
- [ ] Persist authentication data across reboots

## Development roadmap
- [ ] Proper naming convention in the source code
- [ ] Consider requiring re-authentication for each sesssion (like sudo)?
- [ ] More flexible approach to store authentication information in maps
- [ ] Implement a userspace daemon to load/write maps so Keyvan can persist across reboots
- [ ] Determine white list programs to prevent locking the user out
- [ ] Implement logging
- [ ] Implement SHA512 or port from OpenSSL(bpf and userspace side)
- [ ] Hash the credentials before writing maps on the disc
- [ ] Web hosted documentation
- [ ] Unit testing
