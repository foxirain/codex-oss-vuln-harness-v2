# Project Policy

## Project Summary
- Describe the product, deployment model, major trust boundaries, and where untrusted input arrives.
- Note whether the target is a web service, native library, CLI, desktop app, agent, or mixed system.

## In Scope
- Write vulnerability classes and security boundaries here, not path names.
- Remote attack surface reachable by unauthenticated or low-privilege users.
- Privilege boundary mistakes, auth bypass, tenant isolation failures, and trust-boundary violations.
- Memory corruption, parser bugs, unsafe deserialization, command execution, filesystem trust-boundary bugs, and sandbox escapes.

## Out of Scope
- Write excluded bug classes or operational exclusions here, not path names.
- Denial of service only.
- Social engineering, non-code issues, or dependency-only issues outside this repository's owned code.
- Findings the project explicitly documents as accepted risk.

## Focus Areas
- Describe the security-relevant subsystems or workflows to emphasize.
- Authentication and authorization boundaries.
- File handling, archive extraction, import or upload pipelines.
- Command execution, deserialization, templating, native bindings, or trust-material loading.

## Forbidden Findings
- Write findings that should be rejected even if they look superficially suspicious.
- Admin-only self-XSS.
- Theoretical hardening suggestions without a concrete attacker-controlled path.
- Test-only, example-only, or debug-only findings that do not map to production code reachability.

## Entry Points
- Put real attacker-controlled input entrypoints here: APIs, RPC methods, CLI commands, env vars, file formats, webhooks, bootstrap configs, plugin loaders.
- /api
- /graphql
- webhook handlers
- import pipeline

## Include Paths
- Put only repository paths here. These are the directories or files the harness should analyze.
- src/
- app/
- server/
- internal/

## Exclude Paths
- Put only repository paths here. These are directories or files the harness should ignore or deprioritize.
- tests/
- examples/
- vendor/
- dist/

## Languages
- List only languages actually relevant to the vulnerability-hunting target.
- python
- go
- rust

## Framework Hints
- List frameworks, runtimes, or protocol stacks that help the scanner infer entrypoints.
- fastapi
- django
- express

## Hot Paths
- Put only high-priority repository paths or exact files here. These are not bug classes.
- auth/
- upload/
- parser/

## Preferred Sinks
- Put sink categories here, not paths.
- command execution
- unsafe deserialization
- filesystem
- memory-sensitive native path

## Preferred Bug Classes
- Put realistic bug classes here, not files or subsystems.
- authz bypass
- path traversal
- ssrf
- rce
- uaf

## Ignore Patterns
- Put free-form text or path fragments here that should reduce noise.
- accepted-risk
- wontfix
- generated/

## Notes
- Record policy constraints, reporting standards, or ambiguous areas.
- Require concrete reachability and security impact.
- Keep `In Scope` for vulnerability classes, `Include Paths` for repository paths, `Hot Paths` for high-priority files or directories, and `Entry Points` for real attacker-controlled inputs.
- Prefer findings that can plausibly become a CVE or a high-confidence advisory.
