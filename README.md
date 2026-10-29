# sandboxes-gateway

Status: pre-alpha.

Host network policy gateway. Enforces egress policy for TCP, UDP, DNS, HTTP,
CONNECT, and TLS; fails closed when policy or audit is unavailable.

## Boundaries

- separate process from the daemon;
- default deny;
- every deny needs a positive control in tests;
- unsupported paths are explicitly disabled, not silently allowed.


## Gateway manager

`Manager` starts one pinned `gvproxy` process per sandbox with:

- dedicated Unixgram socket;
- default-deny egress policy;
- audit log path;
- revisioned policy reload via `SIGHUP`;
- TCP port forwards;
- deterministic MAC and nerdbox network annotations.

Current tests cover config rendering, MAC derivation, validation, and safe stop.
Live gvproxy startup is not part of CI yet; it requires the pinned patched binary.
