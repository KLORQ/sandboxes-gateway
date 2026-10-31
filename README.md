# sandboxes-gateway

Status: pre-alpha.

The `registryauth` package provides host-side parsing, scoped token exchange,
and restricted transport primitives. These primitives do not authenticate a
sandbox, enforce guest egress, or enable guest registry pulls on their own.

The experimental gateway does not yet establish enforcement for DNS hostname
policy, HTTP, CONNECT, TLS inspection, IPv6 or QUIC. Audit failure behavior is
not fully validated.

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
