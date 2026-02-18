@page pathname_exception pathname exception

# Pathname Exception

Pathnames are identified by the combination of their inode number and decoded device number.

@note The kernel uses an encoding algorithm to populate the `stat.st_device`, I don't know the reason, but for device number of files in kernel space to match, the user space needs to decode the device numbers and then use them as identification, otherwise bpfside won't be able to find them.

Pathname exception is done in two parts, registering the exception and enforcing the exception:

Registering pathname exceptions involves:
1. Resolving the real path of pathname (in case of symbolic links), inode number and decoded device number of file
2. Fetching its hash from Linux Integrity Measurement Architecture (IMA)
3. Creating the exception and file hash map entries

Enforcing the exception is a little more tricky, in different contexts, file exception might have different meanings. For example for a `execve` verdict the exception rule applies to the file currently being loaded for execution, whereas for a `open` verdict it means the rule applies to the file that is attempted for opening.

Enforcing pathname exceptions generally involves:
1. Resolving the inode number and decoded device number of file
2. If the file is in the exceptions map, verify it's integrity by retrieving the latest hash stored in IMA (except for blacklists)
3. Act according to the exception rule
