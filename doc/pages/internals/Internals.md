@page internal Internal

The following diagram shows an overview of how different components of Keyvan interact with each other.  
A -> B means A writes to B, or B reads from A.

@dot
digraph k1_architecture {
    rankdir=TB;
    compound=true;
    node [shape=box, fontsize=10];

    subgraph cluster_userspace {
        label="User Space";
        style=rounded;

        cli [label="keyvand / k1cli"];
    }

    subgraph cluster_kernelspace {
        label="Kernel Space";
        style=rounded;

        auth_checkers [label="auth_checkers"];

        users_having_sid_verdict_map [label="users_having_sid_verdict_map", shape=ellipse];
        registered_euids_map [label="registered_euids_map", shape=ellipse];
        auth_map [label="auth_map", shape=ellipse];

        verdict_user [label="verdict_map_user", shape=ellipse];
        verdict_session [label="verdict_map_session", shape=ellipse];

        verdicts [label="verdicts"];
        exception_map_pathname [label="exception_map_pathname", shape=ellipse];
        refcounting_session_subsystem [label="refcounting_session_subsystem", shape=tab];
        refcounting_map_session [label="refcounting_map_session", shape=ellipse]

        trust_map_file2sha256 [label="trust_map_file2sha256", shape=ellipse];
    }

    // User - Kernel
    cli -> users_having_sid_verdict_map;
    cli -> registered_euids_map;
    cli -> exception_map_pathname;
    cli -> auth_map;

    // Auth checker inputs
    users_having_sid_verdict_map -> refcounting_session_subsystem;
    registered_euids_map -> auth_checkers;
    auth_map -> auth_checkers;
    auth_checkers -> auth_map;

    // Verdict propagation
    auth_checkers -> verdict_user;
    auth_checkers -> verdict_session;

    verdict_user -> verdicts;

    verdict_session -> verdicts;
    refcounting_session_subsystem -> verdict_session;

    refcounting_session_subsystem -> refcounting_map_session;
    refcounting_map_session -> verdicts;
    refcounting_map_session -> auth_checkers;

    // Exceptions
    exception_map_pathname -> verdicts;

    cli -> trust_map_file2sha256;
    trust_map_file2sha256 -> verdicts;
}
@enddot

**Components**
- @subpage bpf_programs
- @subpage session_refcounting
- @subpage pathname_exception
