# Security policy

Aestheris protects secrets and data: we take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting:
**Security** tab → **Report a vulnerability** on
[github.com/hamdok/aestheris](https://github.com/hamdok/aestheris/security/advisories/new).

Include what you can: affected version or commit, platform, steps to reproduce, impact. We
acknowledge reports within 7 days, keep you informed, and credit you in the advisory unless you
prefer otherwise. English or French.

## Scope

In scope: the `aestheris` binary — vault, gateway, policy engine, privacy shield, sandboxes
(macOS Seatbelt, Linux bubblewrap/seccomp), approval channel, audit log, `aestheris scan`.
Especially welcome: sandbox escapes, secret or real-data leaks to an agent or an AI provider,
approval bypasses, audit-log tampering.

Out of scope: vulnerabilities in the agents themselves or in upstream providers, and attacks that
require an attacker already running as your user outside the sandbox.

## Supported versions

Only the latest release on `main` receives fixes while the project is in alpha.

## What we do ourselves

Every change runs `scripts/audit.sh` in CI (cargo-deny, osv-scanner, gitleaks, trufflehog,
semgrep, zizmor, `aestheris scan`), clippy with `undocumented_unsafe_blocks` denied, and real
sandbox-escape tests on macOS and Linux. The project has **not** had an external audit yet.
