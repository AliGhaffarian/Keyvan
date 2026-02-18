@page bpf_programs BPF programs

# BPF programs
Keyvan defines two kinds of BPF programs is uses, authenticate checkers, and verdicts. Their behavior is configured by the user space loader which itself is configured via the parsed configuration file. One can mix and match any of the authenticate checkers and verdicts as they please.

## Authenticate Checkers
Authenticate checkers are attached to the events where they can grab the passed credentials and compare them with their rules. If they decide to change status of a user/session, they will lookup the associated verdict map entry and change its status as needed.
Authenticate checkers are more flexible in the logic they can implement, but if they don't directly associate with a user (for example attaching a `fentry` program to a device driver function), they would have a hard time implementing per-session authentication and it's generally not recommended to do so.

## verdicts
These programs are responsible to allow/deny the associated event's procedure. For example the `execve` verdict attaches to a LSM hook that is triggered before a program is executed.
