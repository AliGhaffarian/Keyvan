@page configuration_syntax Configuration Syntax

@tableofcontents

# Configuration Syntax

The configuration format is hierarchical. The top-level entry point must always specify a UID, followed by one or more policy definition for that user.

```
# the following policies will affect user X
uid: X
<policy1>
<policy2>
...

# the following policies will affect user Y
uid: Y
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

## User Identification (uid)

Every policy block begins by specifying the target user ID.

    Syntax: uid: <integer>

    Example: uid: 1000

## Policy Types

After specifying a uid, you can define one of two policy types: Authentication (auth) or Verdict (verdict).

###  Authentication Policy (auth)

The auth block defines:
- Authentication type
- Credentials
- Associated verdict

Syntax:
```
auth: {
    type: <type_name>
    <specific_fields>
    verdict_sub_type: <map_type_string>
    [ verdict: { <verdict_body> } ]
}
```

#### auth.type

The type field determines:
- How credentials are passed
- The required fields, including credentials

Supported authentication types:
1. `execve`
    - Description: checks the given `pathname` against pathname argument of `execve`, invoked by the given uid
    - Required Fields
        - pathname: The file path to the executable acting as the credential.
    - Can be used for per-session verdict: YES
2. `usb`
    - Description: monitors USB device insertions, checks `serial` against serial of inserted device
    - Required Fields
        - serial: The serial number string of the USB device.
    - Can be used for per-session verdict: NO


#### auth.verdict_sub_type

Determines if the verdict that follows needs to work in either per-uid or per-session mode.
- Possible Values
    - K1_VERDICT_MAP_SID: per-session mode
    - K1_VERDICT_MAP_UID: per-user mode

#### auth.verdict

An auth block can contain a nested verdict block (wrapped in braces { }) to define the verdict associated with this authentication.

### Verdict Policy (verdict)

The verdict block defines allow-lists and block-lists for system events. This can appear nested inside an auth block or as a standalone policy for a UID.
@note verdicts that are not associated with a auth checker have no way for them to change state

Syntax:
```
verdict: {
    type: <type_name>
    [ whitelists: <pathnames> | blacklists: <pathnames>]
    [ whitelists: <pathnames> | blacklists: <pathnames>]
    ...
}
```

#### verdict.type

Supported verdict types:
1. `execve`
    - Description: controls `execve` calls via LSM

#### Exception Lists

You can define lists of paths that are explicitly allowed or denied. These lists contain whitespace-separated strings (no commas required).
@note Currently exception lists works only if all the pathnames point to an executable AND have been executable prior to running keyvan

whitelists: Paths that are explicitly allowed.

blacklists: Paths that are explicitly denied even if authenticated.

# Configuration Examples

This policy uses `/password` as a credential links it to a UID-based verdict map without specific whitelists defined in this block.

```
uid: 1000
auth: {
    type: execve
    pathname: /password
    verdict_sub_type: K1_VERDICT_MAP_UID
    verdict: {
        type: execve
    }
}
```

Use USB authentication for uid 1001 and prevent root from accessing running `acpi`.
```
uid: 1001
auth: {
    type: usb
    serial: A1B2C3D4E5
    verdict_sub_type: K1_VERDICT_MAP_SID
    verdict: {
        type: execve
        whitelists:
            /usr/bin/login
            /bin/x-window-manager
        blacklists:
            /bin/7z
    }
}

uid: 0
auth: {
    type: execve
    pathname: /password
    verdict_sub_type: K1_VERDICT_MAP_UID
    verdict: {
        type: execve
        blacklists:
            /bin/acpi
    }
}
```
