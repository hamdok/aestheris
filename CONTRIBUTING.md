# Contributing

Thanks for helping! Issues and pull requests are welcome in English or French.

Before opening a pull request:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
scripts/audit.sh          # after scripts/install-audit-tools.sh <dir>, with AUDIT_TOOLS=<dir>
```

Rules of the house:

- **Never a real secret, anywhere** — not in code, tests, logs, errors or `Debug` output. Fake keys
  in tests are split with `concat!("sk_live_", "…")` so that secret scanners (ours, gitleaks,
  trufflehog, GitHub) never see them whole.
- Every `unsafe` block carries a `// SAFETY:` comment (enforced by clippy).
- Security-relevant behavior comes with a test that proves it, ideally end to end.
- Security issues: see [SECURITY.md](SECURITY.md), not public issues.

**Contributor agreement.** Before we merge an outside contribution, we ask you to sign a
Contributor License Agreement: you keep the copyright of your work, and you allow Aestheris AI to
distribute it under Apache-2.0 and under other licenses, including commercial ones. We will
send it to you on your first pull request.
