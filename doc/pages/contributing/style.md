@page style Style

This page describes the preferred style of code, commit messages, etc. The commit history might contradict this documentation, in which case you should follow this document, but for things that the documentation doesn't specify, use the commit history to blend your patch in.

# Code

Preferred code style is described as a clang-format file, and if you install the pre-commit it will be automatically enforced. Sometimes the formatter will change the text unexpectedly (while commenting other programs output, almost always). In which case you should start the section you want to exclude from formatter with `// clang-format off` and end it with `// clang-format on`. Use it when you absolutely have to, leave it be if the text is perfectly readable.

# Including vmlinux.h

In the eBPF code, you should include the `vmlinux.h` first, turn the formatter off for include directive of `vmlinux.h` and then include other files you need. The reason for this is in the eBPF code, other header files will probably rely on `vmlinux.h` to be included first (it's really weird, maybe i did something wrong?), clang-format, however, doesn't understand this and will probably reposition the include directive. This might cause a compiler error.

# Commits

Commit messages should be in the following format:

```
section of the code: brief description
```

The first part need to narrow the domain of which the changes apply as much as possible. Here follows some examples:

- Changes include only a single source file, which resides in the eBPF code
```
commit 9866a72956d8f1a6cd994537d29b6b341e51e187
Author: AliGhaffarian <alighaffarian9@gmail.com>
Date:   Sat Apr 18 00:46:33 2026 +0330

    auth_check_usb_dev: fix credentials being ignored

    Ignoring credentials started since commit: 6d731fae3e1ab552cef37b746e92feb0e6d1ac89,
    when the lookup of records were unified. I removed the credential
    compare line and forgot to put it back.
```

- Changes was spread so much in the code that the section of the code is not mentioned at all
```
commit ac9e9ebd447e385c10380e906199daf01a17e35b
Author: AliGhaffarian <alighaffarian9@gmail.com>
Date:   Thu Mar 26 13:37:47 2026 +0330

    Document some structs

    Added documentation for the following structures:
    - `k1_node`
    - `k1_policy`
    - `k1_refcounting_map_session_hash`
    - `k1_registered_euids_map_hash`
    - `k1_trust_map_file2sha256_hash`
    - `k1_users_having_sid_verdict_map_hash`
    - `k1_verdict_entry_lookup_info`
    - `k1_verdict_map_session_pair`
    - `k1_verdict_map_user_pair`
```
@note for these kinds of commits that are too big to narrow down, and too small to break into multiple commits you should provide commit description of what was done.

- Changes was limited to k1cli program
```
commit 270117a249f09f5b7749db1d90a1405dd9420efa
Author: AliGhaffarian <alighaffarian9@gmail.com>
Date:   Thu Mar 26 01:08:11 2026 +0330

    k1cli: parse configurations before loading skel file
```
