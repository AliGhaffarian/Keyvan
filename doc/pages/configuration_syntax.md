@page configuration_syntax Configuration Syntax

@tableofcontents

# Configuration Syntax

The configuration format is hierarchical. The top-level entry point must always specify a euid, followed by one or more policy definition for that user.

```
# the following policies will affect user X
euid: X
<policy1>
<policy2>
...

# the following policies will affect user Y
euid: Y
<policy1>
<policy2>
...
```

# Order of Effect

Verdict rules are triggered based on the following order, whenever one is triggered, the rest is ignored:
1. per-session exception
2. per-session verdict
3. per-user exception
4. per-user verdict

## User Identification (euid)

Every policy block begins by specifying the target user ID.

    Syntax: euid: <integer>

    Example: euid: 1000

## Policy Types

After specifying a euid, you can define one of two policy types: Authentication (auth) or Verdict (verdict).

###  Authentication Policy (auth)

The auth block defines:
- Authentication type
- Credentials
- Associated verdict

Syntax:
```
auth: {
    auth_type: <type_name>
    <specific_fields>
    [ verdict: { <verdict_body> } ]
}
```

#### auth.auth_type

The type field determines:
- How credentials are passed
- The required fields, including credentials

Supported authentication types:
1. `execve`
    - Description: checks the given `pathname` against pathname argument of `execve`, invoked by the given euid
    - Required Fields
        - pathname: The file path to the executable acting as the credential.
    - Can be used for per-session verdict: YES
2. `usb`
    - Description: monitors USB device insertions, checks `serial` against serial of inserted device
    - Required Fields
        - serial: The serial number string of the USB device.
    - Can be used for per-session verdict: NO


#### auth.verdict

An auth block can contain a nested verdict block (wrapped in braces { }) to define the verdict associated with this authentication.

### Verdict Policy (verdict)

The verdict block defines allow-lists and block-lists for system events. This can appear nested inside an auth block or as a standalone policy for a euid.
@note verdicts that are not associated with a auth checker have no way for them to change state

Syntax:
```
verdict: {
    verdict_type: <type_name>
    verdict_sub_type: <sub_type>
    [is_authenticated: (true|false)]
    [ whitelists: <pathnames> | blacklists: <pathnames>]
    [ whitelists: <pathnames> | blacklists: <pathnames>]
    ...
}
```

#### verdict.verdict_sub_type

Determines if the verdict that follows needs to work in either per-euid or per-session mode.
- Possible Values
    - per_session: per-session mode
    - per_user: per-user mode

#### verdict.type

Supported verdict types:
1. `execve`
    - Description: controls `execve` calls via LSM

#### verdict.is_authenticated

If set to true, state of verdict and authenticate checker will start as if the user is already authenticated. Once use case for this is blacklisting binaries.
- Possible Values: true and false

#### Exception Lists

You can define lists of paths that are explicitly allowed or denied. These lists contain whitespace-separated strings (no commas required).
@note Currently exception lists works only if all the pathnames point to an executable AND have been executable prior to running keyvan

whitelists: Paths that are explicitly allowed.

blacklists: Paths that are explicitly denied even if authenticated.

# Configuration Examples

This policy uses `/password` as a credential links it to a euid-based verdict map without specific whitelists defined in this block.

```
euid: 1000
auth: {
    auth_type: execve
    pathname: /password
    verdict: {
        verdict_sub_type: per_user
        verdict_type: execve
    }
}
```

Use USB authentication for euid 1001 and prevent root from accessing running `acpi`.
```
euid: 1001
auth: {
    auth_type: usb
    serial: A1B2C3D4E5
    verdict: {
        verdict_sub_type: per_session
        verdict_type: execve
        whitelists:
            /usr/bin/login
            /bin/x-window-manager
        blacklists:
            /bin/7z
    }
}

euid: 0
auth: {
    auth_type: execve
    pathname: /password
    verdict: {
        verdict_sub_type: per_user
        verdict_type: execve
        blacklists:
            /bin/acpi
    }
}
```
