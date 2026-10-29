# sandboxes-gateway

Status: pre-alpha.

Host network policy gateway. Enforces egress policy for TCP, UDP, DNS, HTTP,
CONNECT, and TLS; fails closed when policy or audit is unavailable.

## Boundaries

- separate process from the daemon;
- default deny;
- every deny needs a positive control in tests;
- unsupported paths are explicitly disabled, not silently allowed.
