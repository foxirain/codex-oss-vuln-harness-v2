# Project Policy

## Project Summary
- Describe the product, deployment model, trust boundaries, and where untrusted input arrives.

## In Scope
- Remote attack surface.
- Low-privilege to high-privilege boundary issues.
- Cross-tenant or cross-user isolation failures.
- Native memory corruption, parser bugs, and sandbox escapes.

## Out of Scope
- Denial of service only.
- Social engineering or operator misconfiguration only.
- Issues already documented as accepted risk.

## Focus Areas
- Authn/authz.
- File upload and archive processing.
- Unsafe deserialization and plugin execution.
- Command execution and filesystem trust-boundary crossings.

## Forbidden Findings
- Self-XSS in admin-only tooling.
- Theoretical bugs without concrete attacker reachability.

## Entry Points
- /api
- webhook handlers
- import pipeline
- CLI subcommands reachable from untrusted files

## Include Paths
- src/
- app/
- server/
- internal/

## Exclude Paths
- tests/
- examples/
- vendor/
- docs/

## Languages
- python
- go
- rust

## Framework Hints
- fastapi
- gin
- actix

## Hot Paths
- auth/
- upload/
- parser/

## Preferred Sinks
- command execution
- unsafe deserialization
- filesystem
- memory-sensitive native path

## Preferred Bug Classes
- auth bypass
- path traversal
- rce
- uaf

## Ignore Patterns
- generated/
- mock

## Notes
- Require concrete reachability and impact.
- Prefer findings with a clear attacker-controlled entrypoint, trust-boundary crossing, and exploitable sink.
