# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/planetic-labs/kovcheg/security/advisories/new).

Do not open a public issue, discussion, or pull request for an undisclosed vulnerability. Include the affected component, reproducible steps, impact, and any suggested mitigation that can be shared safely. Do not include credentials, access tokens, personal data, or data copied from a real environment.

## Supported versions

Kovcheg is pre-release software. Security fixes are applied to the latest revision of the default branch only.

| Version                             | Supported |
| ----------------------------------- | --------- |
| `main`                              | Yes       |
| Older commits and unmerged branches | No        |

## Repository security controls

- GitHub secret scanning and push protection are enabled.
- Dependency updates are monitored with Dependabot.
- Pull requests run dependency review and the repository quality checks.
- Secrets belong in an approved secret store and must never be committed, printed by CI, or placed in client-side configuration.
