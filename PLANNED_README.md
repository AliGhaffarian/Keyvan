# Table of Content
- [What is this?](#what-is-this)
- [Who can use keyvan?](#who-can-use-keyvan)
- [Authentication methods](#authentication-methods)
- [Verdicts](#verdicts)
- [Quick start](#quick-start)
   * [Config example](#config-example)
   * [k1api example](#k1api-example)
- [About hidden mode](#about-hidden-mode)
- [Contributing](#contributing)
   * [Keyvan architecture](#keyvan-architecture)
      + [Diasgram explanation](#diasgram-explanation)
   * [Maps](#maps)
      + [PAM_map](#pam_map)
      + [API_map](#api_map)
      + [k1_sys_auth_map_hash](#k1_sys_auth_map_hash)
      + [auth_check_map](#auth_check_map)
      + [k1_verdict_map_hash](#k1_verdict_map_hash)
   * [BPF programs](#bpf-programs)
      + [Authenticate Checkers](#authenticate-checkers)
         - [sys_auth_checkers](#sys_auth_checkers)
         - [auth_checkers](#auth_checkers)
      + [verdicts](#verdicts-1)
# What is this?
Keyvan is a suite of bpf programs that together enable various interesting authentication methods.

Some characteristics of keyvan include:
- **Hidden:** with the use of `--stealth` option, keyvan hides its presence from the unauthorized users, making it very hard to understand why some resources are limited/unavailable
- **Easy to setup:** keyvan be initialized using a config file
- **Userspace api:** keyvan can be used by userpace programs for authentication, one instance of such usage is a login page
- **Modular architecture:** any type of authentication method can be added to keyvan, see [adding a authenticate checker-]
- **PAM(Pluggable Authentication Module) compatible:**
	- Keyvan can be used by pam modules to query the status of authentication of a user
	- PAM can be used by Keyvan to query the status of authentication of a user
# Who can use keyvan?
- **End users** can use Keyvan to 
	- Lock particular files in their systems that their confidentiality is crucial to them (although they may need to learn a bit about block devices to prevent advanced users from accessing mentioned files).
- **Developers** can use Keyvan to 
	- Add unique authentication methods to their programs
	- Control Keyvan verdicts based on their own authentication methods
- **System administrators** can use Keyvan to 
	- Control access to system resources by using Keyvan as the verdict
	- Monitor unauthorized activity within their systems [and implement port knocking like authentication methods(vulnerable to sniffing?)]

# Authentication methods
- **syscall as password:** user needs to invoke a syscall that is considered as the password, like opening a file or connecting to a specific ip address
- **fentry trigger as password:** user needs to do something that makes the kernel call a specific function in the kernel or a driver with specific arguments, some instances include:
	- Connecting a usb, bluetooth or wifi device
	- Pressing a combination of keys on the keyboard
# Verdicts
- **Packet filtering:** restricting a user's access to the network
- **File execution/read/write**: restricting how users can access various files
# Quick start
**usage:**
```
keyvan [-i config_file] [--stealth]
```
## Config example
TODO: enforce only one auth_type per uid for PAM Exports
TODO: enforce only one type of verdict per uid
```c
# deny execve until user executes `/some/password`
uid: 1000
auth {
	type: execve
	pathname: /some/password/
	loglevel: (ALL | ALL_FLIP) #can't be used in daemonless mode
}
verdict {
	type: execve
	pathname: (all | /some/secret/file)
}

# same as above but instead of using a verdict, will manipulate the flag on PAM_map for later queries from PAM modules
uid: 1000
auth {
	type: execve
	pathname: /some/password/
	loglevel: (ALL | ALL_FLIP) #can't be used in daemonless mode
	verdict_type: PAM_VERDICT
}

# store verdict flag on API_map for later queries by the API user
uid: 1000
auth {
	type: execve
	pathname: /some/password/
	loglevel: (ALL | ALL_FLIP) #can't be used in daemonless mode
	verdict_type: API_VERDICT 
}

# a registered verdict by a the user during configuration, if false, will query daemon to then query pam using SERVICE_NAME, keyvand will map each present pam_mod to a number during startup
uid: 1000
verdict {
	type: execve
	pam_details: SERVICE_NAME
}

# deny access to keyvan files until a usb device with matching serial is inserted
uid: 1000
auth {
	type: usb
	serial: SOME_SERIAL
}
verdict {
	type: k1admin
}

# deny all outgoing packets until a packet arrives that matches the [bpfilter/iptables?] rule
uid: 1000
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

## k1api example
Querying Keyvan to see it the user is authenticaed using usb device method
```c
#include <k1.h>

struct k1_auth_record record = {
.type = usb,
.serial = SOME_SERIAL
};
int handler = k1_register_auth_checker(&record);

bool is_authenticated = false;
while(!is_authenticated)
	is_authenticated = k1_auth_status(handler);
k1_free_handler(handler);

//do something requiring user to be authenticated
```

Allowing user to access `/bin/sudo` if `input` matches `password`
```c
#include <k1.h>

struct k1_verdict_record record = {
	.type = execve,
	.path = "/bin/sudo"
}
int uid = 1000;
k1_register_verdict(&record, uid);

if(!strcmp(input, password))
	change_verdict_status(&record, FLAG_OP_SET);
```

```
#pam snippet
```

# About hidden mode
Hidden mode works by hiding Keyvan's related bpf programs and it's files residing in `/opt/keyvan` directory, to do this a kernel module is used. you need to [compile this kernel module]() yourself if you need it.

In hidden mode, Keyvan operates in daemonless mode, it works by relying on the daemon initializing the bpf programs and then quits itself. this way an unauthorized user can't see Keyvan in systemd running services. there are drawbacks to using daemonless mode, such as disabled logging.
# Contributing
## Keyvan architecture
each link from Keyvand to a user space program type of a separate unix domain socket, differenciate between root and normal api user by separating sockets
``` 
Legend:
A ->--->- B: A writes to B, B reads from A
A --<->-- B: A and B talk
*B* resresents the original B somewhere else in the diagram, for readability


--------------                 
|user space  |     PAM--<->--keyvand/cli ----<->---program using k1api
-------------------------------------------------------------------------------
|kernel space|                /\    \/                                   
--------------                |     |                                      
				              |     |                                      
				              |     |                                      
/--->-------------------------/     |                                     
/\                                  |                                     
|     /---------------------------<-|->-------------\                        
|	  \/			                				\/				         
|     |<--|--< sys_auth_checkers <-----------< |sys_auth_checker_map|          
|     |<--|--< auth_checkers     <-----------< |auth_checker_map|              
|     |   \/                                                                   
|     |   |------------------->|API_map|--->*keyvand/cli*
|     |   |                                                                   
|     |   \------------------->|PAM_map|--->*keyvand/cli*
|     |                                                                    
|     \------------>|verdict_map|-<->--\                         
|                                      /\
/\   							       \/
\--------------------------------<  verdict
```
### Diasgram explanation
**verdict -> keyvand:**
a verdict might want to request keyvand to query a pam service authorization
note: this procedure may be replaced by kevand polling PAM and populating verdict_pam itself
**veerdict -> verdict_map:**
verdict stores the result of keyvand query to verdict map
**PAM -> keyvand:**
response to service authorization query
**keyvand -> verdict_map:**
response to a verdicts request for PAM qurery
**PAM -> PAM_map:**
query keyvand about the value stores in PAM_map, to enable pam use keyvan's authenticate checkers
**auth_checkers-> PAM_map:**
store user authentication status
## Maps
### PAM_map
**key**: uid
**value**: list of struct {auth_type, bool flag}
### API_map
**key**: api_handler (returned by keyvand)
**value**: list of struct {uid, bool flag}
### k1_sys_auth_map_hash
**key**
```c
struct k1_sys_auth_map_key {
    __u32 uid;
    enum K1_AUTH_TYPE auth_type;
};
```
**value**
```c
struct k1_sys_record {
    bool is_authenticated;
    enum K1_VERDICT_HOOK verdict_hook;
    K1_AUTH_CRED_UNION;
};
```
### auth_check_map
**key**: auth_type
**value**: list of struct {uid, auth_flag, verdict hook, auth_type}
### k1_verdict_map_hash
**key**:
```c
struct k1_verdict_map_key {
    __u32 uid;
    enum K1_VERDICT_HOOK hook_type;
};
```
**value**:
```c
struct k1_verdict_record {
    bool is_authenticated;
};
```
## BPF programs
These programs are loaded into the kernel and their behavior is determined by values in the map they access.
### Authenticate Checkers
These programs run when the event associated them happens, check if the event context matches with a `auth_check` rule, if so they change the status of corresponding entry in `verdict` map.
#### sys_auth_checkers
These auth_checkers are triggered directly by a user (like syscalls).
- **types:**
	- execve
#### auth_checkers
These auth_checkers are not triggered by a user (like a function call in the kernel)
- **types:**
	- usb
	- wifi
	- bluetooth
	- ethernet
	- key press combinations

### verdicts
These programs are responsible to allow/deny the associated event's procedure (like executing a file). All they do is to:
1. check if a user is associated with this event
2. If so, the boolean flag in their map entry determines if the user is allowed to proceed.
- **types:**
	- execve
	- tc/egress
	- xdp

