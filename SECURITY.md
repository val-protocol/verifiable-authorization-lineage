# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public issue.

- Use [GitHub private security advisories](https://github.com/val-protocol/verifiable-authorization-lineage/security/advisories/new), or
- or email **security@riga.solutions** with details and, if possible, a reproduction (RIGA Solutions, the project maintainer, hosts security intake on behalf of the project).

We aim to acknowledge within 5 business days and to coordinate a disclosure timeline with you.

## Scope

Security-relevant issues include, in particular:

- Any way to make the **offline verifier** accept a chain whose lineage does **not** trace to a human-signed root, or whose action falls **outside** its scope predicate (a soundness break — the protocol's core property).
- Canonicalization / preimage ambiguities that let two distinct payloads share a hash, or that make a chain verify under one canonicalizer and fail under another.
- Membership-proof or isolation-commitment forgery (proving inclusion of a resource not in the committed set).
- Anchor-verification bypass.

## Supported versions

The `0.1.x` line of the reference implementation receives security fixes. The spec is a draft (v0.1); soundness-affecting spec ambiguities are treated as security issues.
