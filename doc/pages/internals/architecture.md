@page architecture Architecture

## Keyvan architecture
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

        users_sid_map [label="users_having_sid_verdict_map"];
        registered_uids_map [label="registered_uids_map"];
        auth_checker_map [label="auth_checker_map"];

        verdict_user [label="verdict_map_user"];
        verdict_session [label="verdict_map_session"];

        verdicts [label="verdicts"];
        exception_path_map [label="exception_map_pathname"];
    }

    // User ↔ Kernel
    cli -> auth_checkers;
    auth_checkers -> cli;

    // Auth checker inputs
    users_sid_map -> auth_checkers;
    registered_uids_map -> auth_checkers;
    auth_checker_map -> auth_checkers;

    // Verdict propagation
    auth_checkers -> verdict_user;
    auth_checkers -> verdict_session;

    verdict_user -> verdicts;
    verdicts -> verdict_user;

    verdict_session -> verdicts;
    verdicts -> verdict_session;

    // Exceptions
    exception_path_map -> verdicts;
}
@enddot
