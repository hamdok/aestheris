# Aestheris

**Let your AI agents act — without handing them your keys or your data.**

[Français](README.fr.md) · [Security policy](SECURITY.md) · [License: Apache-2.0](LICENSE)

Aestheris is an open-source trust layer that runs **on your machine**, between AI agents
(Claude Code, Codex, any agent that honors a base URL) and the outside world (LLM providers, APIs):

```text
┌ sandbox ─────┐
│    agent     │──(phantom token)──▶ Aestheris 127.0.0.1 ──(real key)──────▶ api.stripe.com
└──────────────┘                      │ policy · human approval · audit log
 ~/.ssh, ~/.aws, .env: unreadable     │ privacy shield ──([EMAIL_1], [CLIENT_2])──▶ LLM provider
```

- **Agents never hold real secrets.** They get a phantom token; the gateway injects the real key,
  from an encrypted local vault, on the way out.
- **Your AI provider never learns who your customers are.** Emails, phone numbers, IBANs, card
  numbers, client and project names, and your machine identity are replaced with typed pseudonyms
  (`[EMAIL_1]`, `[CLIENT_2]`) before a request leaves, and restored locally in the response —
  including streamed tool calls. The agent still works on real data.
- **Real values only go where your policy allows** ("phantom data"): an agent hijacked by a prompt
  injection can only exfiltrate pseudonyms.
- **The agent runs in a sandbox** (macOS Seatbelt, Linux bubblewrap + seccomp): no `~/.ssh`,
  `~/.aws`, `.env`, browser profiles, Docker socket or direct network.
- **Risky actions wait for a human** (`aestheris approve`), every request goes to a hash-chained
  audit log, and an **observe mode** measures what would have been blocked before you enforce it.

## Try it

```bash
curl -fsSL https://raw.githubusercontent.com/hamdok/aestheris/main/install.sh | sh
cd your-project
aestheris scan            # 5 seconds, no setup: what your agents can read or leak
aestheris init            # encrypted vault + ready-made policy (Claude Code, OpenAI, GitHub, Stripe)
aestheris run -- claude   # the agent works behind the gateway, in the sandbox
aestheris approve         # in another terminal: approve sensitive actions
```

The installer checks the archive's SHA-256 and, if the GitHub CLI is logged in, its build
provenance (Sigstore): `gh attestation verify <archive> --repo hamdok/aestheris` proves it was
built by this repository's CI from this code. From source: `cargo install --git
https://github.com/hamdok/aestheris --locked`. Or run the two-minute demo, which needs no
external account: `./examples/demo.sh`.

The interface speaks English, or French when your system language is French
(`AESTHERIS_LANG=en` or `fr` to choose). Issues and pull requests are welcome in either
language.

`aestheris scan` flags secrets that are published or about to be (keys in `NEXT_PUBLIC_*` /
`VITE_*` variables, in git-tracked files, in `.env` files git does not ignore, Supabase
`service_role` keys), secrets your agents can read, plaintext tokens in MCP configs (Claude,
Cursor, VS Code, Windsurf, Gemini, Codex) and agent settings that disable safeguards. It never
prints a value, filters out documentation examples, and exits with code 1 on critical findings, so
it works as a CI step or pre-commit hook (`aestheris scan --no-home`).

## Why another tool?

Each piece exists somewhere on its own: secret brokers, agent sandboxes, MCP gateways, privacy
vaults, secret scanners. Aestheris brings secrets, sandboxing, provider-side
confidentiality, human approval and evidence together, **locally, for the agents developers already
use, without modifying them** — and it is open source. It is on the company's side, not the AI
provider's.

## Status

Alpha. Tested on macOS and Ubuntu 24.04; Windows is not supported yet. **Not externally audited
yet.** Every change runs an automated audit with open-source tools (`scripts/audit.sh`):
cargo-deny and osv-scanner (vulnerable dependencies, licenses), gitleaks and trufflehog (secrets in
the whole git history), semgrep (static analysis), zizmor (GitHub Actions), and `aestheris scan`
itself.

Architecture, threat model and known limits: [docs/DESIGN.md](docs/DESIGN.md).

## Design partners wanted

We are looking for 3 to 5 pilot teams — agencies handling client data, regulated SMEs (health,
finance, legal), teams rolling out Claude Code or Codex — to shape the product. Free, hands-on
support in exchange for feedback: [apply here](https://github.com/hamdok/aestheris/issues/new?template=pilot.yml).

## Development

```bash
cargo test                                  # unit, end-to-end and real sandbox-escape tests
cargo clippy --all-targets -- -D warnings
scripts/install-audit-tools.sh ../.devtools # pinned, checksum-verified audit tools
scripts/audit.sh
```

On Ubuntu 23.10+, the Linux sandbox needs bubblewrap and a one-time AppArmor profile:
`sudo install -m 644 packaging/apparmor/bwrap /etc/apparmor.d/bwrap && sudo apparmor_parser -r /etc/apparmor.d/bwrap`.

## License

[Apache-2.0](LICENSE) for this repository; third-party notices in [NOTICE](NOTICE). The Aestheris
name and logo are trademarks, not covered by the license: see [TRADEMARKS.md](TRADEMARKS.md).
