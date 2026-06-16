# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

This is a Linux kernel hardening audit tool. If you discover a security vulnerability, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Known Limitations

- **TOCTOU in /proc/sys reads**: The tool reads live kernel parameters from /proc/sys/. These values can change between reads. This is an inherent limitation of live system auditing.
- **Silent fopen failures**: If a kernel parameter path doesn't exist, the tool defaults to safe values. This could produce false positives on non-standard kernels.
- **History rewriting**: This repository's git history was cleaned with git-filter-repo. If you have an older clone, please re-clone from the latest remote.
