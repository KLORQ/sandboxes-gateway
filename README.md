# sandboxes-gateway

Status: pre-alpha.

Host network policy gateway. The current experimental gvproxy integration supports
IPv4 TCP/UDP CIDR rules and rejects domain rules it cannot enforce. DNS hostname
policy, HTTP, CONNECT, TLS inspection, IPv6 and QUIC enforcement are not yet
implemented or verified. Audit failure behavior has not been fully validated.

The `registryauth` package provides host-side parsing, scoped token exchange,
and restricted transport primitives. These primitives do not authenticate a
sandbox, enforce guest egress, or enable guest registry pulls on their own.

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
- policy reload rewrites the config, sends SIGHUP, and verifies the patched gvproxy's appended `egress policy reloaded revision=N` log acknowledgement; a missing acknowledgement stops the gateway and fails closed;
- TCP port forwards;
- deterministic MAC and nerdbox network annotations.

The manager requires a supervisor executable and a patched gvproxy supporting
the owner-lease flag. Without either component gateway startup fails closed.
The matching daemon entry point and gvproxy build patch must be deployed
together; this module alone does not supply a runnable supervisor binary.

Current tests cover config rendering, MAC derivation, validation, and safe stop.
An opt-in local test starts and stops a supplied patched gvproxy; it does not
test a VM or establish policy enforcement. It is not part of CI.
