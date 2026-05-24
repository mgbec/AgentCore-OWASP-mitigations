# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via one of these channels:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the Security tab of this repository.
2. **Email**: Send details to the repository maintainers directly.

### What to include in your report

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity; critical issues targeted within 7 days

## Security Best Practices for Contributors

### Secrets Management

- **NEVER** commit secrets, API keys, credentials, or tokens to this repository
- Use environment variables or AWS Secrets Manager for all sensitive values
- The `.gitignore` file excludes common secret file patterns
- All credentials in this demo use AgentCore Identity token vault

### Code Security

- All dependencies must be pinned to exact versions in `requirements.txt`
- Run `pip audit` before submitting PRs to check for known vulnerabilities
- Input validation is mandatory for all user-facing endpoints
- Output filtering must be applied before returning any agent response

### Infrastructure Security

- IAM roles follow least-privilege principle (see `infrastructure/iam_roles.json`)
- Runtime deploys in VPC mode with restricted egress
- All inter-service communication uses TLS
- Session timeouts are enforced at the runtime level

## Security Controls Demonstrated

This project demonstrates mitigations for:

- **OWASP Top 10 for Agentic Applications (2026)**: ASI01–ASI10
- **OWASP GenAI Data Security Risks (2026)**: 21 data-security risk categories

See the [README](README.md) for the full risk-to-mitigation mapping.
