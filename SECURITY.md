# Security Policy

ProtocolGate is a security tool for Web3 control-plane review. We take the
security of the project itself seriously.

## Supported Versions

ProtocolGate is in active alpha development (0.1.x). Security fixes are applied
to the latest release on the default branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security → Report a vulnerability).

When reporting, please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- The affected version or commit
- Any suggested remediation

## Scope

In scope:

- The ProtocolGate CLI, rule engine, and GitHub Action in this repository
- Issues that could cause ProtocolGate to report an unsafe control plane as
  safe (false negatives in the deterministic rules), or to leak input data

Out of scope:

- Vulnerabilities in the smart contracts or protocols you analyze with
  ProtocolGate — ProtocolGate is a readiness tool, not an audit, and does not
  replace source-code review, formal verification, or a professional audit
- The optional, separately-licensed Vestige companion project (report those to
  the Vestige repository)

## Response

We aim to acknowledge reports within a few business days and to coordinate a
fix and disclosure timeline with the reporter. Thank you for helping keep the
ecosystem safe.
