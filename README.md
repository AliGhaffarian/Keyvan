# Overview

**Keyvan** (aka `k1`) is a kernel level access control mechanism implemented using eBPF.
It provides silent authentication checks and access control verdicts for resources
(files, execs, and later network actions). The goal is to allow a machine to appear
unlocked to an unauthorized user while restricting their access in order to confuse them.

![](https://alighaffarian.github.io/Keyvan/doc/assets/demo.gif)

## Quick start

Example config:

```
# The following configs are related to uid 1000
uid: 1000

# deny execve until user executes `/some/password`
auth: {
	type: execve
	pathname: /some/password #need to execute this pathname to authenticate

    verdict_sub_type: K1_VERDICT_MAP_UID

    # the following verdict associates with the container auth
    verdict: {
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

## Planned Features
- [ ] Stealth mode
- [ ] Userspace daemon
- [ ] Userspace API
- [ ] Packet processing rules for both authentication and filtering
