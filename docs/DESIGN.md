# Aestheris design

How Aestheris works, what it protects against, and what it does not.

## Principle

The agent never holds anything valuable. It gets a **phantom token** instead of each real key, runs
in a **sandbox** that cannot read the machine's secrets or reach the network directly, and talks to
the outside world only through a **local gateway** that decides, injects the real key, protects the
data sent to AI providers, and records everything in a **hash-chained log**. Every check is
enforced outside the agent, where a hijacked agent cannot switch it off.

```text
┌ sandbox ─────────────┐
│ agent                │  STRIPE_API_KEY=aes_ph_…   (phantom token)
│ ~/.ssh, ~/.aws, .env │  STRIPE_API_BASE=http://127.0.0.1:PORT/stripe
│ unreadable           │
└──────────┬───────────┘
           │ only reachable address: the gateway
           ▼
┌ gateway (127.0.0.1) ─────────────────────────────────────────────────────────┐
│ session token → route → path → policy → content scan → phantom data release  │
│ → human approval → privacy shield → inject real key → forward → audit log    │
└──────────┬───────────────────────────────────────────────┬───────────────────┘
           ▼                                               ▼
   api.stripe.com (real key)                     LLM provider (pseudonyms only)
```

## Components

| Module | Role |
|---|---|
| `vault` | Encrypted vault; secrets decrypted in memory only |
| `phantom` | Per-session random tokens, compared in constant time |
| `policy` | YAML policy: routes, rules, network, sandbox, privacy, circuit breaker; validated at startup |
| `proxy` | Local reverse proxy (routes) and authenticated CONNECT proxy (egress) |
| `privacy` | Reversible pseudonymization towards AI providers, phantom data release, provenance |
| `approval` | Human approval queue and local channel (`aestheris approve`) |
| `audit`, `report` | Hash-chained NDJSON log; management report |
| `sandbox`, `sandbox_linux` | macOS Seatbelt profile; Linux bubblewrap + seccomp |
| `harden` | Gateway process hardening |
| `scan`, `gitleaks`, `project_scan` | Secret detection in traffic; `aestheris scan` for projects |
| `i18n` | English and French interface |

## Vault

```text
password ──Argon2id (64 MiB, 3 passes)──▶ KEK (never stored)
                                           │ XChaCha20-Poly1305
                                           ▼
                                         DEK (stored encrypted)
                                           │ XChaCha20-Poly1305, associated data = secret name
                                           ▼
                                         secrets (stored encrypted)
```

Changing the password re-encrypts only the DEK. Each secret is bound to its name, so swapping two
blocks in the file makes decryption fail. The file is written atomically with mode 0600. Secret
values never appear in errors, logs or `Debug` output, and are wiped from memory when dropped.

## Path of a request

The agent calls `http://127.0.0.1:PORT/<route>/<path>` with its phantom token. In order, failing
closed at each step:

1. **Route**: first path segment; unknown route → 404.
2. **Session token**: missing or wrong → 401; the real key is never injected without it.
3. **Path**: encoded separators, `.`/`..` segments and double slashes are refused rather than
   normalized, so the policy sees exactly what the upstream will see.
4. **Policy**: first matching rule wins (`allow`, `deny`, `ask`); no match → deny.
5. **Content**: plaintext secrets in the body or query (our patterns plus ~220 rule types) → 403.
6. **Phantom data** (non-model routes): pseudonyms become real only where the policy allows.
7. **Human approval** for `ask` rules; no answer before the timeout → deny.
8. **Privacy shield** (model routes): sensitive values replaced by typed pseudonyms.
9. **Injection and forwarding**: the real key is added to the configured header; responses are
   streamed back, with pseudonyms restored on the machine.

Every decision is written to the audit log, with the type of any secret found, never its value.

## Privacy shield and phantom data

On model routes (`privacy: true`), emails, phone numbers, IBANs, card numbers (checked with IIN
and Luhn), IP addresses, the user name, machine name, Git identity and the company's own terms
(clients, projects) are replaced with typed pseudonyms such as `[EMAIL_1]` or `[CLIENT_2]`
before a request leaves. Responses are rehydrated locally, including streamed responses (SSE) and
tool calls, so the agent keeps working on real data while the provider only ever sees
pseudonyms. Identifying metadata (`metadata.user_id`, `user`, SDK telemetry headers) is removed.
Supported formats: Anthropic Messages, OpenAI Chat Completions and Responses. Signed reasoning
blocks are never modified.

**Phantom data** (`privacy.release`) decides where each category may become real again: on screen
(`human`), in the agent's actions (`agent`), or only when sent to specific services
(`route:crm`). Elsewhere the value stays a pseudonym: an agent hijacked by a prompt injection can
only exfiltrate pseudonyms.

**Provenance**: responses from data sources (`phantom: true`, a CRM for instance) are
pseudonymized before they reach the agent, and `privacy.origins` limits where data from each
source may become real.

**Circuit breaker** (`guard`): above thresholds of objective signs of a hijacked agent (withheld
values, blocked secrets, repeated denials), every action requires human approval, or the session
is suspended.

## Sandbox

**macOS**: a Seatbelt profile that denies everything by default, then opens the minimum: running
programs, reading the disk except secrets, a closed list of system services, writing only to the
allowed folders and temporary folders, and the network only to the gateway's exact port. Closed:
reading `~/.ssh`, `~/.aws`, browser profiles, keychains, `.env` files and the vault; launching or
scripting other applications (`open`, AppleScript); Unix sockets (Docker, SSH agent) unless
listed; other local services; DNS; writing files that run later outside the sandbox (shell
startup files, Git hooks, editor tasks, MCP configs, LaunchAgents). Paths are passed as profile
parameters, never pasted into the profile text, so a crafted path cannot inject rules.

**Linux**: bubblewrap builds a read-only view of the disk with secrets masked, a fresh `/tmp`, new
PID/IPC namespaces and an empty network namespace, where a small relay forwards a local port to
the gateway. A seccomp filter restricts sockets to IP families and a socketpair, and blocks
`io_uring`, `ptrace`, `process_vm_*` and terminal injection (`TIOCSTI`, `TIOCLINUX`). On Ubuntu
23.10 and later, bubblewrap needs a one-time AppArmor profile (`packaging/apparmor/bwrap`).

If no sandbox is available, `aestheris run` refuses to start rather than run unprotected.

## Network egress

Outside routes, the agent can only use the gateway's authenticated CONNECT proxy: host allowlist
and ports, optional human approval for unknown hosts, and addresses checked **after** DNS
resolution: internal ranges, cloud metadata endpoints, link-local, multicast, IPv4 embedded in
IPv6, and the machine's own addresses are always refused, even in observe mode. The connection is
made to the address that was checked. Plaintext HTTP is refused.

## Human approval

`action: ask` rules (and unknown hosts, if enabled) wait for a human: a line in the terminal and a
macOS notification, answered with `aestheris approve` in another terminal, once or for the whole
session. The channel is a Unix socket in a private directory the sandbox cannot reach; peer
credentials are checked, and connections from the agent or any of its descendants are refused.
No answer before the timeout means deny. Who decided is written to the log.

## Audit log and report

One JSON event per line; each line carries the SHA-256 hash of the previous one, so any deleted,
inserted or modified line is detected (`aestheris audit verify`). The log and the policy cannot be
modified from the sandbox. `aestheris audit report` turns the log into a summary for management;
`aestheris audit exposure` shows what each AI provider received (categories and counts, never
values).

**Observe mode** (`mode: observe`) enforces nothing from the policy and records what would have
been denied, blocked, approved or pseudonymized, so a first deployment can measure the risk before
enforcing. Protections against internal addresses and metadata endpoints stay active.

## Gateway process hardening

No debugger can attach to the gateway (`PT_DENY_ATTACH` on macOS, `PR_SET_DUMPABLE` on Linux), no
core dump is written, and the gateway refuses to start if a library may have been injected
(`DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`, `LD_AUDIT`).

## Threat model

| Threat | Response |
|---|---|
| The agent leaks its key (logs, prompts, files) | It only has a phantom token, useless outside the gateway |
| Another local process uses the gateway | Session token required, compared in constant time |
| The agent calls a dangerous endpoint | Rules per method and path, deny by default |
| A plaintext secret is sent to an API | Detected and blocked |
| The vault file is stolen | Authenticated encryption, key derived with Argon2id |
| The agent reads `~/.aws`, `~/.ssh`, `.env`, the vault | Denied by the kernel sandbox |
| Exfiltration to an arbitrary server, over DNS or plain HTTP | Direct connections impossible; egress allowlist; DNS closed |
| SSRF to the internal network or cloud metadata | Addresses checked after resolution |
| Persistence through files run later (shell startup, Git hooks, MCP configs) | Writes denied |
| Irreversible action by mistake (refund, deletion) | `ask` rule: a human approves, otherwise deny |
| The agent approves its own request | Channel out of reach; agent and descendants refused |
| The AI provider learns customer data, project names, employee identity | Pseudonymized before leaving, restored on the machine |
| A prompt injection pushes the agent to exfiltrate customer data | Phantom data: only pseudonyms leave outside allowed destinations |
| A hijacked agent keeps trying | Circuit breaker: human approval required or session suspended |
| The agent erases its tracks | Hash-chained log, not writable from the sandbox |
| Memory of the gateway read by a debugger or a core dump | Debugger refused, core dumps disabled |

## Known limits

- The agent must honor its base URL variable (Claude Code, the Anthropic and OpenAI SDKs and most
  agents do). TLS interception for agents that ignore it is not implemented.
- The privacy shield recognizes structured data and the terms you declare; free-form names of
  people are not detected yet.
- Without the sandbox, human approval protects against the agent's mistakes, not against a
  malicious agent.
- Windows is not supported.
- The project has not had an external security audit yet. See [SECURITY.md](../SECURITY.md) for
  what runs on every change.
