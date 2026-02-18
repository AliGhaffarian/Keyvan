@page bpf_programs BPF programs

# BPF programs
These programs are loaded into the kernel and their behavior is determined by values in the map they access.

## Authenticate Checkers
These programs run when the event associated them happens, check if the event context matches with a `auth_check` rule, if so they change the status of corresponding entry in `verdict` map.

## verdicts
These programs are responsible to allow/deny the associated event's procedure (like executing a file). All they do is:
1. Check if a user is associated with this event
2. If so, the boolean flag in their map entry determines if the user is allowed to proceed
