# Security Policy

## Supported versions

safe-npm is under active development. Security fixes are applied to the latest release and the `master` branch.

| Version | Supported |
|---|---|
| 0.5.x | Yes |
| < 0.5 | No |

## Reporting a vulnerability

Please do not disclose an unpatched vulnerability in a public issue, discussion, pull request or social post.

Prefer GitHub's **Private vulnerability reporting** feature on the repository Security tab when it is enabled. If private reporting is not available, contact the repository owner privately before publishing technical details.

Include, when possible:

- affected safe-npm version or commit;
- affected command and configuration;
- reproduction steps or a minimal proof of concept;
- expected and observed behavior;
- security impact;
- whether credentials, package contents or third-party data are involved.

Do not include real API keys, npm tokens, access tokens or unrelated private source code.

## Scope

Security reports may include issues such as:

- executing package code during a scan that should be static;
- lifecycle scripts running without explicit authorization;
- bypassing installation policy or risk thresholds;
- unsafe archive extraction or filesystem writes;
- secret leakage in logs, reports or AI requests;
- dependency-tree limit bypasses;
- AI validation incorrectly suppressing findings due to errors or malformed responses;
- command or argument injection;
- vulnerabilities in the GitHub Actions/release pipeline.

A false positive or false negative in a heuristic can also be reported, but it may be handled as a detection-quality bug rather than a security vulnerability depending on impact.

## Security model

safe-npm is a heuristic defense-in-depth tool. A finding is not proof of malware and a clean report is not proof that a package is safe. AI validation is optional and must not be treated as an independent trust boundary.
