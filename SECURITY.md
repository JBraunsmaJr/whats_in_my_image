# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and the version (`wimi --version`). You should get an
acknowledgement within 5 working days.

## Supported versions

Security fixes go into the latest release only.

## How this project is checked

Every push and pull request runs:

| Check | Tool |
| --- | --- |
| Static analysis (SAST) | CodeQL (`security-extended`), Bandit |
| Vulnerable dependencies, secrets, misconfiguration | Trivy, GitHub dependency review |
| Secrets in the full git history | Gitleaks |
| Workflow security (injection, permissions, unpinned actions) | zizmor, actionlint, CodeQL for Actions |
| Supply-chain practices | OpenSSF Scorecard |

Every third-party action is pinned to a full commit SHA, and every downloaded tool is verified against its published
SHA-256 checksum. Workflows run with read-only permissions by default. The tool itself has no third-party runtime
dependencies.
