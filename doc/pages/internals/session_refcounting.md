@page session_refcounting Session Reference Counting

@dot
digraph session_refcounting {
    newrank=true;
    graph [
        ranksep=0.8,
        nodesep=0.8,
        splines=true
    ];

    edge [
        minlen=2
    ];
    rankdir=TB;
    compound=true;
    node [shape=box, fontsize=10];

    subgraph cluster_session_refcounting_subsystem {
        label="session refcounting subsystem";
        style=rounded;

        fork [label="tp/sched/sched_process_fork"];
        exit [label="tp/sched/sched_process_exit"];
        exit_setsid [label="tp/syscalls/sys_exit_setsid"]
        enter_setsid [label="tp/syscalls/sys_enter_setsid"]

        refcounting_map_old_sessionid [label="refcounting_map_old_sessionid", shape=ellipse]
    }

    subgraph cluster_keyvan {
        label="keyvan (kernel space)";
        style=rounded;

        users_having_sid_verdict_map [label="users_having_sid_verdict_map", shape=ellipse];

        verdict_map_session [label="verdict_map_session", shape=ellipse];

        refcounting_map_session [label="refcounting_map_session", shape=ellipse];

    }

    users_having_sid_verdict_map -> fork;
    fork -> refcounting_map_session;

    users_having_sid_verdict_map -> exit_setsid;
    exit_setsid -> refcounting_map_session;
    refcounting_map_old_sessionid -> exit_setsid;
    exit_setsid -> verdict_map_session;

    enter_setsid -> refcounting_map_old_sessionid;

    exit -> refcounting_map_session;
    exit -> verdict_map_session;
}
@enddot

Per-session authentication checkers will create map elements on a per-session basis, this creates the need to clean them up after they are not used. The session reference counting subsystem keeps track of new sessions created with `setsid`, and when reference count of a session hits zero it start cleaning up map elements associated with them.

Session reference count increments when the process is forked, and is decremented when the process exists or process calls `setsid`, leaving it's current session.
