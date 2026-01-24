This document explains Keyvan in the stable version. Everything that is not implemented is marked as **TODO**.

# Keyvan
Keyvan is a suite of BPF programs that together enable various interesting authentication methods.

Some characteristics of Keyvan include:
- **TODO Hidden:** with the use of `--stealth` option, Keyvan hides its presence from the unauthorized users, making it very hard to understand why some resources are limited/unavailable
- **TODO Easy to setup:** Keyvan be initialized using a config file
- **TODO Userspace api:** Keyvan can be used by userpace programs for authentication, one instance of such usage is a login page
- **Modular architecture:** any type of authentication method can be added to Keyvan, see [adding a authenticate checker-]
- **TODO PAM(Pluggable Authentication Module) compatible:**
	- Keyvan can be used by PAM modules to query the status of authentication of a user
	- PAM can be used by Keyvan to query the status of authentication of a user

# TODO Some Use Cases
- Lock particular files in systems that their confidentiality is crucial (although you may need to learn a bit about block devices to prevent advanced users from accessing mentioned files).

- Add unique authentication methods to programs
- Control Keyvan verdicts based on own authentication methods

- Control access to system resources by using Keyvan as the verdict
- Monitor unauthorized activity within systems [and implement port knocking like authentication methods(vulnerable to sniffing?)]

# Authentication methods
- **syscall as password:** user needs to invoke a syscall that is considered as the password, like opening a file or connecting to a specific ip address
	- execve
    - TODO write
    - TODO ioctl

- **fprobe trigger as password:** user needs to do something that makes the kernel call a specific function with specific arguments.
	- USB
	- TODO wifi
	- TODO bluetooth
	- TODO ethernet
	- TODO key press combinations

# Verdicts
- **TODO Packet filtering:** restricting a user's access to the network
- **File execution/ TODO read/ TODO write**: restricting how users can access various files

# Quick start
**usage:**
```
Keyvan [-i config_file] [--stealth]
```

## TODO Config example
TODO: enforce only one auth_type per uid for PAM Exports
TODO: enforce only one type of verdict per uid
```c

# The following configs are related to uid 1000
uid: 1000

# deny execve until user executes `/some/password`
auth {
	type: execve
	pathname: /some/password/
	loglevel: (ERROR | WARN | INFO | DEBUG) #can't be used in daemonless mode
}
verdict {
	type: execve
	[pathname: /some/secret/file] # all files, if ommited
}

# a registered verdict by a the user during configuration, if false, will query daemon to then query PAM using SERVICE_NAME, keyvand will map each present pam_mod to a number during startup
auth {
    type: PAM
	pam_details: SERVICE_NAME
}
verdict {
	type: execve
}

# verdicts and auths don't need to necessarily come after each other
verdict {
    type: open
    pathname: /etc/passwd
}
verdict {
    type: open
    pathname: /etc/resolv.conf
}


# The following configs are related to root user
uid: 0

# deny access to Keyvan files until a USB device with matching serial is inserted
auth {
	type: usb
	serial: SOME_SERIAL
}
verdict {
	type: k1admin
}

# deny all outgoing packets until a packet arrives that matches the [bpfilter/iptables?] rule
auth {
	type: xdp
	rule {
		ip.src equal 192.168.1.1
		tcp.dport equal 8000
		tcp.flag equal reserved
		}
}
verdict {
	type: tc/egress
}
```

## TODO Keyvan inside a PAM module
There's an API to request authentication information from keyvand to allow the usage of authenticate methods of Keyvan inside PAM modules.
```c
// snippet of querying keyvand for a record with a simple API
```

# TODO About hidden mode
Hidden mode works by hiding Keyvan's related BPF programs and it's files residing in `/opt/Keyvan` directory, to do this a kernel module is used. you need to [compile this kernel module]() yourself if you need it.

In hidden mode, Keyvan operates in daemonless mode, it works by relying on the daemon initializing the BPF programs and then quits itself. this way an unauthorized user can't see Keyvan in systemd running services. There are drawbacks to using daemonless mode, such as disabled logging.

# Internals

## Keyvan architecture
each link from keyvand to a user space program type of a separate unix domain socket, differenciate between root and normal api user by separating sockets
``` 
Legend:
A ->--->- B: A writes to B OR B reads from A
A --<->-- B: A and B talk
*B* resresents the original B somewhere else in the diagram, for readability


--------------                 
|user space  |     PAM--<->--keyvand/k1cli
-------------------------------------------------------------------------------
|kernel space|                /\    \/                                   
--------------                |     |                                      
				              |     |                                      
				              |     |                                      
/--->-------------------------/     |                                     
/\                                  |                                     
|     /---------------------------<-|->-------------\                        
|	  \/			                				\/				         
|     |<-----< sys_auth_checkers <-----------< |sys_auth_checker_map|          
|     |<-----< auth_checkers     <-----------< |auth_checker_map|              
|     |                                                                    
|     \------------>|verdict_map|-<->--\                         
|                                      /\
/\   							       \/
\---------------------------------< verdict
```
### Diagram explanation
The following sections describe the portion of the diagram that enable PAM compatibility.

#### TODO Keyvan using a PAM module for authentication
**verdict -> keyvand:**
A verdict might want to request keyvand to query a PAM service authorization

**PAM -> keyvand:**
Response to service authorization query.

**keyvand -> verdict_map:**
Response to a verdicts request for PAM query

**verdict -> verdict_map:**
Verdict stores the result of keyvand query to verdict map

**Note:** A BPF program may not be able to wait this much, therefore we might choose to poll PAM and populate `verdict_map` ourself, as a result, all authentication changes will be delayed by polling intervals, and the process would be much simpler.

#### TODO PAM module using Keyvan for authentication
**keyvand -> PAM:**
PAM queries keyvand about the value stores in a regular map, to see if the user is authenticated.
**Note:** auth_maps would have a copy of authentication flag of the destination verdict. It will be used for queries from keyvand.

## BPF programs
These programs are loaded into the kernel and their behavior is determined by values in the map they access.

### Authenticate Checkers
These programs run when the event associated them happens, check if the event context matches with a `auth_check` rule, if so they change the status of corresponding entry in `verdict` map.

#### sys_auth_checkers
These auth_checkers are triggered directly by a user (like syscalls). Currently providing syscall as password authentication method.

#### auth_checkers
These auth_checkers are not triggered by a user (like a function call in the kernel). Currently providing fprobe as password authentication method.

### verdicts
These programs are responsible to allow/deny the associated event's procedure (like executing a file). All they do is:
1. Check if a user is associated with this event
2. If so, the boolean flag in their map entry determines if the user is allowed to proceed
