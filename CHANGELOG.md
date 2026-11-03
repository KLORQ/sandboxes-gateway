# Changelog

## v0.0.11 — 2026-11-03

### Added

- Add a Windows gateway host layer with private named-pipe ACL checks and Windows contract tests.
- Publish a CycloneDX module SBOM as a CI artifact.

### Changed

- Normalize the Go module path to the lowercase `github.com/quoiner/sandboxes-gateway` namespace.

### Compatibility

- Windows gateway host support does not establish a Windows VM backend or end-to-end Windows sandbox support.
