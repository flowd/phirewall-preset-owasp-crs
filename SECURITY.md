# Security Policy

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

## Reporting a Vulnerability

Email security reports to **sascha.egerer@flowd.de**. For sensitive details, encrypt your report with the PGP key published in the [`flowd/phirewall` security policy](https://github.com/flowd/phirewall/blob/main/SECURITY.md#pgp-key).

This package is security-sensitive: it parses attacker-controlled request input, reads `@pmFromFile` data files from disk, and bundles a filtered copy of the third-party OWASP Core Rule Set. Please report issues in the SecRule engine (parsing, operators, variable collection), the import tooling (`bin/crs-import`), or a behavior of the bundled rules that leaks data or bypasses/over-blocks. For a vulnerability in the OWASP CRS rules themselves, please also notify the [Core Rule Set project](https://github.com/coreruleset/coreruleset/security/policy).

## Supported Versions

This package is pre-1.0. Only the latest minor release receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Coordinated Disclosure

- We will acknowledge your report and work with you on a fix.
- Please keep the issue confidential until a fixed release is published.
- Reporters are credited in the CHANGELOG and GitHub Security Advisory unless they prefer to remain anonymous.
