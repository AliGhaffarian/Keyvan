@page session_refcounting Session Reference Counting

# Session Reference Counting

Per-session authentication checkers will create map elements on a per-session basis, this creates the need to clean them up after they are not used. The session reference counting subsystem keeps track of new sessions created with `setsid`, and when reference count of a session hits zero it start cleaning up map elements associated with them.

Session reference count increments when the process is forked, and is decremented when the process exists or process calls `setsid`, leaving it's current session.
