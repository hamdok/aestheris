//! Ligne de commande `aestheris`.

use aestheris::approval::{self, Message, Scope};
use aestheris::audit;
use aestheris::error::{Error, Result};
use aestheris::policy::Policy;
use aestheris::tr;
use aestheris::vault::{KdfParams, Vault};
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "aestheris",
    version,
    about = "Trust layer between AI agents and your APIs"
)]
struct Cli {
    /// Encrypted vault (default: ~/.aestheris/vault.json)
    #[arg(long, global = true, env = "AESTHERIS_VAULT")]
    vault: Option<PathBuf>,
    /// Audit log (default: ~/.aestheris/audit.ndjson)
    #[arg(long, global = true, env = "AESTHERIS_AUDIT")]
    audit: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the secrets vault
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Set up a project: vault, keys, ready-made policy (aestheris.yaml)
    Init {
        /// Agent you will run: claude-code or generic
        #[arg(long)]
        agent: Option<String>,
        /// Service used by the agent (repeatable): anthropic, openai, github, stripe
        #[arg(long = "service")]
        services: Vec<String>,
        /// Names never to send to the AI provider (company, clients, projects), comma-separated
        #[arg(long)]
        protect: Option<String>,
        /// Start in observe mode: nothing is blocked, everything is recorded (aestheris audit report)
        #[arg(long)]
        observe: bool,
        /// Policy file to write
        #[arg(long, default_value = "aestheris.yaml")]
        output: PathBuf,
        /// Replace an existing file
        #[arg(long)]
        force: bool,
    },
    /// Check a policy file
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Run an agent behind the gateway: aestheris run -- claude
    Run {
        #[arg(long, short, default_value = "aestheris.yaml")]
        policy: PathBuf,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Start the gateway alone and print the variables to give an agent
    Serve {
        #[arg(long, short, default_value = "aestheris.yaml")]
        policy: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Answer human-approval requests (run it in another terminal)
    Approve {
        /// Target session (default: the most recent)
        #[arg(long)]
        session: Option<String>,
        /// List pending requests without answering
        #[arg(long)]
        list: bool,
    },
    /// Interne (Linux) : lancé par bubblewrap dans le bac à sable ; relais puis agent sous seccomp
    #[command(name = "__sandbox-init", hide = true)]
    SandboxInit {
        #[arg(long)]
        bridge: Option<PathBuf>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        allow_unix: bool,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Scan a project (no vault, no password): secrets your agents can read or that are already
    /// published, public variables, git-tracked .env files, plaintext tokens in MCP configs, agent
    /// settings without safeguards. Exit code 1 on critical findings.
    Scan {
        /// Project directory
        #[arg(default_value = ".")]
        path: PathBuf,
        /// JSON output (CI, tools)
        #[arg(long)]
        json: bool,
        /// Skip the home directory (MCP configs, settings, secrets): for CI
        #[arg(long)]
        no_home: bool,
        /// Paths to ignore (repeatable), e.g. 'tests/**'
        #[arg(long = "exclude")]
        excludes: Vec<String>,
    },
    /// Inspect and verify the audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// Create a vault (asks for a master password)
    Init,
    /// Add or replace a secret (value read hidden, or from standard input)
    Set { name: String },
    /// List secret names (never their values)
    List,
    /// Remove a secret
    Remove { name: String },
    /// Change the master password
    Passwd,
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate a policy and show what it allows
    Check {
        #[arg(default_value = "aestheris.yaml")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Recompute the whole chain and report any tampering
    Verify,
    /// Show the latest events
    Show {
        #[arg(long, default_value_t = 20)]
        last: usize,
    },
    /// Exposure register: what each provider received (categories, never values)
    Exposure,
    /// Report: what Aestheris did, and what it would have done in observe mode
    Report,
}

/// `aestheris approve` : affiche chaque demande et transmet la réponse de l'humain.
async fn approve(dir: &std::path::Path, session: Option<String>, list: bool) -> Result<i32> {
    use std::io::Write as _;
    use tokio::io::AsyncBufReadExt;

    // Sans session ouverte : on attend qu'une session en ouvre une (sauf pour --list).
    let mut announced = false;
    let (mut client, path) = loop {
        let candidates = match &session {
            Some(s) => vec![dir.join(format!("{s}.sock"))],
            None => approval::sockets(dir),
        };
        if session.is_none() && candidates.len() > 1 {
            eprintln!(
                "{}",
                tr!(
                    "aestheris ▸ plusieurs sessions ouvertes : la plus récente est suivie (--session pour choisir)",
                    "aestheris ▸ several sessions are open: following the most recent (--session to choose)"
                )
            );
        }
        // Le plus récent d'abord ; un canal resté d'une session interrompue ne répond pas.
        let mut connected = None;
        for p in candidates {
            if let Ok(c) = approval::Client::connect(&p).await {
                connected = Some((c, p));
                break;
            }
        }
        match connected {
            Some(c) => break c,
            None if list => {
                println!(
                    "{}",
                    tr!(
                        "Aucune session Aestheris ouverte.",
                        "No Aestheris session open."
                    )
                );
                return Ok(0);
            }
            None => {
                if !announced {
                    println!(
                        "{}",
                        tr!(
                            "En attente d'une session Aestheris… (Ctrl-C pour quitter)",
                            "Waiting for an Aestheris session… (Ctrl-C to quit)"
                        )
                    );
                    announced = true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
        }
    };
    let session_id = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    if list {
        client.list().await?;
        return match client.next().await? {
            Some(Message::List { items }) if items.is_empty() => {
                println!(
                    "{}",
                    tr!("Aucune demande en attente.", "No pending request.")
                );
                Ok(0)
            }
            Some(Message::List { items }) => {
                items.iter().for_each(show_pending);
                Ok(0)
            }
            Some(Message::Error { message }) => Err(Error::Policy(message)),
            _ => Ok(1),
        };
    }

    client.watch().await?;
    println!(
        "{}",
        tr!(fmt "Session {session_id} : en attente de demandes de validation… (Ctrl-C pour quitter)",
            "Session {session_id}: waiting for approval requests… (Ctrl-C to quit)")
    );
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut seen = std::collections::HashSet::new();
    while let Some(message) = client.next().await? {
        match message {
            Message::Pending { item } => {
                if !seen.insert(item.id) {
                    continue;
                }
                show_pending(&item);
                let (ok, scope) = loop {
                    print!(
                        "{}",
                        tr!(
                            "Autoriser ? [o]ui une fois · [s]ession entière · [n]on : ",
                            "Allow? [y]es once · whole [s]ession · [n]o: "
                        )
                    );
                    std::io::stdout().flush()?;
                    let Some(answer) = stdin.next_line().await? else {
                        return Ok(0);
                    };
                    match answer.trim().to_lowercase().as_str() {
                        "o" | "oui" | "y" | "yes" => break (true, Scope::Once),
                        "s" | "session" => break (true, Scope::Session),
                        "n" | "non" | "no" => break (false, Scope::Once),
                        _ => continue,
                    }
                };
                client.decide(item.id, ok, scope).await?;
            }
            Message::Result {
                id,
                ok: true,
                message,
            } => println!(
                "{}",
                tr!(fmt "✓ demande #{id} {message}", "✓ request #{id} {message}")
            ),
            Message::Result {
                id,
                ok: false,
                message,
            } => println!(
                "{}",
                tr!(fmt "✗ demande #{id} : {message}", "✗ request #{id}: {message}")
            ),
            Message::Error { message } => return Err(Error::Policy(message)),
            Message::List { .. } => {}
        }
    }
    println!("{}", tr!("Session terminée.", "Session ended."));
    Ok(0)
}

fn show_pending(p: &approval::Pending) {
    println!();
    let (id, kind, session, left) = (p.id, &p.kind, &p.session, p.expires_in);
    println!(
        "{}",
        tr!(fmt "━━━ Validation #{id} · {kind} · session {session} · {left} s restantes",
            "━━━ Approval #{id} · {kind} · session {session} · {left} s left")
    );
    println!("  {}", p.summary);
    for line in p.detail.lines().filter(|l| !l.trim().is_empty()) {
        println!("  │ {line}");
    }
}

/// `aestheris init` : choisit l'agent et les services, range les clés dans le coffre (en important
/// celles déjà présentes dans le terminal), écrit une politique commentée.
fn init(
    vault_path: &std::path::Path,
    agent: Option<String>,
    services: Vec<String>,
    protect: Option<String>,
    observe: bool,
    output: &std::path::Path,
    force: bool,
) -> Result<i32> {
    use aestheris::init::{self as tpl, Agent};
    if output.exists() && !force {
        let out = output.display();
        return Err(Error::Policy(
            tr!(fmt "{out} existe déjà (--force pour le remplacer)",
            "{out} already exists (--force to replace it)"),
        ));
    }
    let interactive = std::io::stdin().is_terminal();
    let agent = match agent {
        Some(a) => Agent::parse(&a)?,
        None if interactive => {
            println!(
                "{}",
                tr!(
                    "Quel agent allez-vous lancer ?\n  1. Claude Code\n  2. un autre agent (générique)",
                    "Which agent will you run?\n  1. Claude Code\n  2. another agent (generic)"
                )
            );
            match ask(tr!("Votre choix [1] : ", "Your choice [1]: "))?.as_str() {
                "" | "1" => Agent::ClaudeCode,
                "2" => Agent::Generic,
                other => return Err(unknown_choice(other)),
            }
        }
        None => {
            return Err(Error::Policy(
                tr!(
                    "précisez --agent (claude-code ou generic)",
                    "specify --agent (claude-code or generic)"
                )
                .into(),
            ));
        }
    };
    let mut chosen: Vec<&'static str> = Vec::new();
    if services.is_empty() && interactive {
        println!(
            "{}",
            tr!(
                "Quels services l'agent utilise-t-il ? (numéros séparés par des virgules)",
                "Which services does the agent use? (comma-separated numbers)"
            )
        );
        for (i, s) in tpl::SERVICES.iter().enumerate() {
            println!("  {}. {}", i + 1, s.label);
        }
        let default = if agent == Agent::ClaudeCode { "1" } else { "" };
        let answer = ask(&tr!(fmt "Votre choix [{default}] : ", "Your choice [{default}]: "))?;
        let answer = if answer.is_empty() {
            default.to_string()
        } else {
            answer
        };
        for part in answer.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let n: usize = part.parse().map_err(|_| unknown_choice(part))?;
            let s = tpl::SERVICES
                .get(n.wrapping_sub(1))
                .ok_or_else(|| unknown_choice(part))?;
            chosen.push(s.id);
        }
    } else {
        for s in &services {
            chosen.push(tpl::service(s)?.id);
        }
    }
    if agent == Agent::ClaudeCode && !chosen.contains(&"anthropic") {
        println!(
            "{}",
            tr!(
                "  (Claude Code a besoin de la route anthropic : ajoutée)",
                "  (Claude Code needs the anthropic route: added)"
            )
        );
        chosen.insert(0, "anthropic");
    }
    chosen.dedup();
    let uses_llm = chosen.iter().any(|s| *s == "anthropic" || *s == "openai");
    let protect = match protect {
        Some(p) => p,
        None if interactive && uses_llm => ask(tr!(
            "Noms à ne jamais envoyer au fournisseur d'IA (société, clients, projets), \
             séparés par des virgules [aucun] : ",
            "Names never to send to the AI provider (company, clients, projects), \
             comma-separated [none]: "
        ))?,
        None => String::new(),
    };
    let protected: Vec<String> = protect
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let observe = observe
        || (interactive
            && ask(tr!(
                "Commencer en mode observation (rien n'est bloqué, rapport ensuite) ? [o/N] ",
                "Start in observe mode (nothing is blocked, report afterwards)? [y/N] "
            ))?
            .to_lowercase()
            .starts_with(['o', 'y']));
    let mut text = tpl::render(agent, &chosen, &protected)?;
    if observe {
        text = tpl::observe_mode(&text);
    }
    let policy = Policy::parse(&text)?;

    // Coffre : créé s'il n'existe pas ; chaque clé est importée du terminal ou saisie masquée.
    let mut vault = if vault_path.exists() {
        Vault::open(vault_path, &vault_password()?)?
    } else {
        let path = vault_path.display();
        println!(
            "{}",
            tr!(fmt "Création du coffre chiffré ({path})", "Creating the encrypted vault ({path})")
        );
        Vault::create(vault_path, &new_password()?, KdfParams::default())?
    };
    let existing = vault.names();
    let mut imported: Vec<&str> = Vec::new();
    for id in &chosen {
        let s = tpl::service(id)?;
        if existing.iter().any(|n| n == s.secret) {
            let (label, secret) = (s.label, s.secret);
            println!(
                "{}",
                tr!(fmt "  ✓ {label} : clé déjà dans le coffre ({secret})",
                    "  ✓ {label}: key already in the vault ({secret})")
            );
            continue;
        }
        let from_env = s.import_from.iter().find_map(|v| {
            std::env::var(v)
                .ok()
                .filter(|x| !x.trim().is_empty())
                .map(|x| (*v, Zeroizing::new(x)))
        });
        let value = match from_env {
            Some((var, val))
                if !interactive
                    || !ask(&tr!(fmt
                        "Importer dans le coffre la clé présente dans {var} ? [O/n] ",
                        "Import the key found in {var} into the vault? [Y/n] "))?
                    .to_lowercase()
                    .starts_with('n') =>
            {
                imported.push(var);
                Some(val)
            }
            _ if interactive => {
                let label = s.label;
                let v = Zeroizing::new(rpassword::prompt_password(tr!(fmt
                    "Clé {label} (masquée ; Entrée pour plus tard) : ",
                    "{label} key (hidden; Enter to skip): "))?);
                (!v.trim().is_empty()).then_some(v)
            }
            _ => None,
        };
        match value {
            Some(v) => {
                vault.set(s.secret, v.trim())?;
                let (label, secret) = (s.label, s.secret);
                println!(
                    "{}",
                    tr!(fmt "  ✓ {label} : clé rangée dans le coffre ({secret})",
                        "  ✓ {label}: key stored in the vault ({secret})")
                );
            }
            None => {
                let (label, secret) = (s.label, s.secret);
                println!(
                    "{}",
                    tr!(fmt "  • {label} : à ajouter plus tard avec « aestheris vault set {secret} »",
                        "  • {label}: add it later with `aestheris vault set {secret}`")
                )
            }
        }
    }

    std::fs::write(output, &text)?;
    println!();
    print_policy(&policy, output);
    println!("\n{}", tr!("Ensuite :", "Next:"));
    if observe {
        println!(
            "{}",
            tr!(
                "  (mode observation : rien n'est bloqué ; bilan avec « aestheris audit report »)",
                "  (observe mode: nothing is blocked; summary with `aestheris audit report`)"
            )
        );
    }
    println!(
        "  aestheris run -- {:<12} # {}",
        agent.command(),
        tr!(
            "lance l'agent derrière la passerelle",
            "runs the agent behind the gateway"
        )
    );
    println!(
        "  aestheris approve              # {}",
        tr!(
            "dans un autre terminal : valider les actions sensibles",
            "in another terminal: approve sensitive actions"
        )
    );
    if !imported.is_empty() {
        let vars = imported.join(", ");
        println!(
            "{}",
            tr!(fmt "  Vous pouvez retirer {vars} de votre terminal : la clé est dans le coffre.",
                "  You can remove {vars} from your shell: the key is in the vault.")
        );
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = aestheris::sandbox_linux::find_bwrap(&std::env::current_dir()?) {
        println!(
            "{}",
            tr!(fmt "  ⚠ Bac à sable Linux indisponible : {e}", "  ⚠ Linux sandbox unavailable: {e}")
        );
    }
    Ok(0)
}

fn unknown_choice(choice: &str) -> Error {
    Error::Policy(tr!(fmt "choix inconnu : {choice}", "unknown choice: {choice}"))
}

/// Question simple sur le terminal ; réponse sans espaces autour.
fn ask(question: &str) -> Result<String> {
    use std::io::Write as _;
    print!("{question}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Affiche ce qu'une politique autorise (`policy check`, `init`).
fn print_policy(p: &Policy, file: &std::path::Path) {
    let yes_no = |b: bool| match (b, aestheris::i18n::fr()) {
        (true, true) => "oui",
        (false, true) => "non",
        (true, false) => "yes",
        (false, false) => "no",
    };
    let f = file.display();
    println!("{}", tr!(fmt "Politique valide : {f}", "Valid policy: {f}"));
    for r in p.routes.values() {
        let (name, up, secret, header) =
            (&r.name, &r.upstream, &r.secret, r.inject_header.as_str());
        println!(
            "\n{}",
            tr!(fmt "  {name} → {up}  (secret {secret}, injecté dans {header})",
                "  {name} → {up}  (secret {secret}, injected into {header})")
        );
        for (i, rule) in r.describe_rules().iter().enumerate() {
            println!("    {}. {rule}", i + 1);
        }
        println!("       {}", tr!("sinon : refus", "otherwise: deny"));
    }
    println!();
    let hosts = if p.allow_hosts.is_empty() {
        String::new()
    } else {
        format!(" ({})", p.allow_hosts.join(", "))
    };
    let egress = &p.egress;
    let unknown = if p.ask_unknown_hosts {
        tr!(
            " · hôtes inconnus : validation humaine",
            " · unknown hosts: human approval"
        )
    } else {
        ""
    };
    println!(
        "{}",
        tr!(fmt "  sortie réseau    : {egress}{hosts}{unknown}",
            "  network egress   : {egress}{hosts}{unknown}")
    );
    let sandbox = if p.sandbox.enabled {
        let write = p.sandbox.allow_write.join(", ");
        tr!(fmt "oui · écriture : {write}", "yes · write: {write}")
    } else {
        yes_no(false).to_string()
    };
    println!(
        "{}",
        tr!(fmt "  bac à sable      : {sandbox}", "  sandbox          : {sandbox}")
    );
    if p.uses_approval() {
        let (secs, notify) = (p.approval.timeout.as_secs(), yes_no(p.approval.notify));
        println!(
            "{}",
            tr!(fmt "  validation       : délai {secs} s, puis refus · notification {notify}",
                "  approval         : {secs} s timeout, then deny · notification {notify}")
        );
    }
    if let Some(pr) = &p.privacy {
        let routes: Vec<&str> = p
            .routes
            .values()
            .filter(|r| r.privacy)
            .map(|r| r.name.as_str())
            .collect();
        let terms: Vec<String> = pr
            .terms
            .iter()
            .map(|(k, v)| format!("{k} ({})", v.len()))
            .collect();
        let (routes, kinds, identity) =
            (routes.join(", "), pr.kinds.join(", "), yes_no(pr.identity));
        let names = if terms.is_empty() {
            String::new()
        } else {
            let t = terms.join(", ");
            tr!(fmt " · noms protégés : {t}", " · protected names: {t}")
        };
        println!(
            "{}",
            tr!(fmt "  confidentialité  : bouclier sur {routes} · détectés : {kinds}{names} · identité du poste : {identity}",
                "  confidentiality  : shield on {routes} · detected: {kinds}{names} · machine identity: {identity}")
        );
        for (cat, sinks) in &pr.release {
            let sinks = sinks.join(", ");
            println!(
                "{}",
                tr!(fmt "  données fantômes : {cat} réel seulement pour {sinks}",
                    "  phantom data     : {cat} real only for {sinks}")
            );
        }
        for (origin, sinks) in &pr.origins {
            let sinks = sinks.join(", ");
            println!(
                "{}",
                tr!(fmt "  provenance       : données de {origin} réelles seulement pour {sinks}",
                    "  provenance       : data from {origin} real only for {sinks}")
            );
        }
        let sources: Vec<&str> = p
            .routes
            .values()
            .filter(|r| r.phantom)
            .map(|r| r.name.as_str())
            .collect();
        if !sources.is_empty() {
            let sources = sources.join(", ");
            println!(
                "{}",
                tr!(fmt "  sources          : {sources} (réponses pseudonymisées avant l'agent)",
                    "  sources          : {sources} (responses pseudonymized before the agent)")
            );
        }
    }
    if let Some(g) = &p.guard {
        let (w, b, d) = (g.max_withheld, g.max_blocked, g.max_denied);
        let then = match g.on_trip {
            aestheris::policy::OnTrip::Ask => tr!(
                "validation humaine pour chaque action",
                "human approval for every action"
            ),
            aestheris::policy::OnTrip::Stop => tr!("session suspendue", "session suspended"),
        };
        println!(
            "{}",
            tr!(fmt "  disjoncteur      : {w} donnée(s) retenue(s), {b} secret(s) ou {d} refus → {then}",
                "  circuit breaker  : {w} withheld value(s), {b} secret(s) or {d} denial(s) → {then}")
        );
    }
    if !p.agent_env.is_empty() {
        let vars: Vec<String> = p
            .agent_env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let vars = vars.join(" · ");
        println!(
            "{}",
            tr!(fmt "  variables agent  : {vars}", "  agent variables  : {vars}")
        );
    }
    let secrets = match p.content_secrets {
        aestheris::policy::ContentAction::Block => tr!("bloqués", "blocked"),
        aestheris::policy::ContentAction::Allow => tr!("laissés passer", "let through"),
    };
    println!(
        "{}",
        tr!(fmt "  secrets en clair : {secrets}", "  plaintext secrets: {secrets}")
    );
}

fn home() -> PathBuf {
    std::env::var_os("AESTHERIS_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".aestheris")
        })
}

/// Mot de passe du coffre : `AESTHERIS_PASSWORD` (démos, CI) ou saisie masquée.
fn password(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("AESTHERIS_PASSWORD") {
        return Ok(Zeroizing::new(p));
    }
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(Error::Io)
}

fn new_password() -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("AESTHERIS_PASSWORD") {
        return Ok(Zeroizing::new(p));
    }
    let a = Zeroizing::new(rpassword::prompt_password(tr!(
        "Nouveau mot de passe maître (12 caractères minimum) : ",
        "New master password (12 characters minimum): "
    ))?);
    let b = Zeroizing::new(rpassword::prompt_password(tr!(
        "Confirmez : ",
        "Confirm: "
    ))?);
    if *a != *b {
        return Err(mismatch());
    }
    Ok(a)
}

fn mismatch() -> Error {
    Error::Vault(
        tr!(
            "les deux saisies ne correspondent pas",
            "the two entries do not match"
        )
        .into(),
    )
}

fn vault_password() -> Result<Zeroizing<String>> {
    password(tr!("Mot de passe du coffre : ", "Vault password: "))
}

fn secret_value(name: &str) -> Result<Zeroizing<String>> {
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(tr!(fmt
            "Valeur de {name} (masquée) : ",
            "Value of {name} (hidden): "))?));
    }
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(Zeroizing::new(
        buf.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

/// Aide en français : (sous-commande, argument, texte). Le texte anglais est dans le code.
const HELP_FR: &[(&str, &str, &str)] = &[
    (
        "",
        "",
        "Passerelle de confiance entre les agents IA et vos API",
    ),
    (
        "",
        "vault",
        "Coffre chiffré (défaut : ~/.aestheris/vault.json)",
    ),
    (
        "",
        "audit",
        "Journal d'audit (défaut : ~/.aestheris/audit.ndjson)",
    ),
    ("vault", "", "Gérer le coffre de secrets"),
    (
        "vault init",
        "",
        "Créer un coffre (demande un mot de passe maître)",
    ),
    (
        "vault set",
        "",
        "Ajouter ou remplacer un secret (saisie masquée, ou entrée standard)",
    ),
    (
        "vault list",
        "",
        "Lister les noms des secrets (jamais leurs valeurs)",
    ),
    ("vault remove", "", "Supprimer un secret"),
    ("vault passwd", "", "Changer le mot de passe maître"),
    (
        "init",
        "",
        "Préparer un projet : coffre, clés, politique prête à l'emploi (aestheris.yaml)",
    ),
    (
        "init",
        "agent",
        "Agent lancé ensuite : claude-code ou generic",
    ),
    (
        "init",
        "services",
        "Service utilisé par l'agent (répétable) : anthropic, openai, github, stripe",
    ),
    (
        "init",
        "protect",
        "Noms à ne jamais envoyer au fournisseur d'IA (société, clients, projets), séparés par des virgules",
    ),
    (
        "init",
        "observe",
        "Commencer en mode observation : rien n'est bloqué, tout est noté (aestheris audit report)",
    ),
    ("init", "output", "Fichier de politique à écrire"),
    ("init", "force", "Remplacer un fichier existant"),
    ("policy", "", "Vérifier un fichier de politique"),
    (
        "policy check",
        "",
        "Valider une politique et afficher ce qu'elle autorise",
    ),
    (
        "run",
        "",
        "Lancer un agent derrière la passerelle : aestheris run -- claude",
    ),
    (
        "serve",
        "",
        "Démarrer la passerelle seule et afficher les variables à donner à un agent",
    ),
    (
        "approve",
        "",
        "Répondre aux demandes de validation humaine (dans un autre terminal)",
    ),
    (
        "approve",
        "session",
        "Session visée (défaut : la plus récente)",
    ),
    (
        "approve",
        "list",
        "Afficher les demandes en attente sans répondre",
    ),
    (
        "scan",
        "",
        "Analyser un projet (sans coffre ni mot de passe) : secrets lisibles par les agents ou déjà publiés, variables publiques, .env suivis par git, jetons en clair dans les configurations MCP, réglages d'agent sans garde-fou. Code de retour 1 si un constat est critique.",
    ),
    ("scan", "path", "Dossier du projet"),
    ("scan", "json", "Sortie JSON (CI, outils)"),
    (
        "scan",
        "no_home",
        "Ne pas inspecter le dossier personnel (configurations MCP, réglages, secrets) : pour la CI",
    ),
    (
        "scan",
        "excludes",
        "Chemins à ignorer (répétable), par exemple 'tests/**'",
    ),
    ("audit", "", "Consulter et vérifier le journal d'audit"),
    (
        "audit verify",
        "",
        "Recalculer toute la chaîne et signaler la moindre altération",
    ),
    ("audit show", "", "Afficher les derniers événements"),
    (
        "audit exposure",
        "",
        "Registre d'exposition : ce que chaque fournisseur a reçu (catégories, jamais les valeurs)",
    ),
    (
        "audit report",
        "",
        "Rapport : ce qu'Aestheris a fait, et ce qu'il aurait fait en mode observation",
    ),
];

/// La ligne de commande, avec l'aide dans la langue de l'utilisateur.
fn command() -> clap::Command {
    use clap::CommandFactory;
    fn localize(mut cmd: clap::Command, path: &[&str]) -> clap::Command {
        let here = path.join(" ");
        for (sub, arg, text) in HELP_FR.iter().filter(|(sub, ..)| *sub == here) {
            let _ = sub;
            cmd = if arg.is_empty() {
                cmd.about(*text)
            } else {
                cmd.mut_arg(*arg, |a| a.help(*text))
            };
        }
        let names: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        for name in names {
            let mut sub_path = path.to_vec();
            sub_path.push(&name);
            let sub_path: Vec<&str> = sub_path.to_vec();
            cmd = cmd.mut_subcommand(&name, |c| localize(c, &sub_path));
        }
        cmd
    }
    let cmd = Cli::command();
    if aestheris::i18n::fr() {
        localize(cmd, &[])
    } else {
        cmd
    }
}

#[tokio::main]
async fn main() {
    use clap::FromArgMatches;
    let cli = Cli::from_arg_matches(&command().get_matches()).unwrap_or_else(|e| e.exit());
    if let Err(e) = aestheris::harden::harden_process() {
        eprintln!("aestheris ✗ {e}");
        std::process::exit(2);
    }
    match dispatch(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("aestheris ✗ {e}");
            std::process::exit(2);
        }
    }
}

async fn dispatch(cli: Cli) -> Result<i32> {
    let vault_path = cli.vault.unwrap_or_else(|| home().join("vault.json"));
    let audit_path = cli.audit.unwrap_or_else(|| home().join("audit.ndjson"));

    match cli.command {
        Command::Vault { action } => match action {
            VaultAction::Init => {
                let pw = new_password()?;
                Vault::create(&vault_path, &pw, KdfParams::default())?;
                let path = vault_path.display();
                println!(
                    "{}",
                    tr!(fmt "Coffre créé : {path}", "Vault created: {path}")
                );
                println!(
                    "{}",
                    tr!(
                        "Chiffrement : Argon2id (64 Mio, 3 passes) → XChaCha20-Poly1305, clé de données en enveloppe.",
                        "Encryption: Argon2id (64 MiB, 3 passes) → XChaCha20-Poly1305, envelope data key."
                    )
                );
                Ok(0)
            }
            VaultAction::Set { name } => {
                let pw = vault_password()?;
                let mut v = Vault::open(&vault_path, &pw)?;
                let value = secret_value(&name)?;
                v.set(&name, &value)?;
                println!(
                    "{}",
                    tr!(fmt "Secret « {name} » enregistré (chiffré).", "Secret “{name}” stored (encrypted).")
                );
                Ok(0)
            }
            VaultAction::List => {
                let pw = vault_password()?;
                let v = Vault::open(&vault_path, &pw)?;
                let names = v.names();
                if names.is_empty() {
                    println!("{}", tr!("Coffre vide.", "Empty vault."));
                }
                for n in names {
                    println!("{n}");
                }
                Ok(0)
            }
            VaultAction::Remove { name } => {
                let pw = vault_password()?;
                let mut v = Vault::open(&vault_path, &pw)?;
                if v.remove(&name)? {
                    println!(
                        "{}",
                        tr!(fmt "Secret « {name} » supprimé.", "Secret “{name}” removed.")
                    );
                    Ok(0)
                } else {
                    Err(Error::SecretMissing(name))
                }
            }
            VaultAction::Passwd => {
                let pw = password(tr!("Mot de passe actuel : ", "Current password: "))?;
                let mut v = Vault::open(&vault_path, &pw)?;
                let a = Zeroizing::new(rpassword::prompt_password(tr!(
                    "Nouveau mot de passe : ",
                    "New password: "
                ))?);
                let b = Zeroizing::new(rpassword::prompt_password(tr!(
                    "Confirmez : ",
                    "Confirm: "
                ))?);
                if *a != *b {
                    return Err(mismatch());
                }
                v.change_password(&a)?;
                println!(
                    "{}",
                    tr!(
                        "Mot de passe changé (seule la clé de données a été rechiffrée).",
                        "Password changed (only the data key was re-encrypted)."
                    )
                );
                Ok(0)
            }
        },

        Command::Policy {
            action: PolicyAction::Check { file },
        } => {
            let p = Policy::load(&file)?;
            print_policy(&p, &file);
            Ok(0)
        }

        Command::Run { policy, command } => {
            let pw = vault_password()?;
            aestheris::run::run(aestheris::run::RunOptions {
                policy: &policy,
                vault: &vault_path,
                audit: &audit_path,
                password: &pw,
                command: &command,
                run_dir: &home().join("run"),
                sandbox_init: None,
            })
            .await
        }

        Command::Approve { session, list } => approve(&home().join("run"), session, list).await,

        Command::Init {
            agent,
            services,
            protect,
            observe,
            output,
            force,
        } => init(
            &vault_path,
            agent,
            services,
            protect,
            observe,
            &output,
            force,
        ),

        Command::SandboxInit {
            bridge,
            port,
            allow_unix,
            command,
        } => aestheris::sandbox_linux::sandbox_init(bridge, port, allow_unix, &command),

        Command::Serve { policy, port } => {
            let pw = vault_password()?;
            let (gw, session) = aestheris::run::prepare(&policy, &vault_path, &audit_path, &pw)?;
            let running = aestheris::proxy::start(gw.clone(), port).await?;
            let _admin = if gw.policy().uses_approval() {
                Some(approval::serve(gw.approvals.clone(), &home().join("run"))?)
            } else {
                None
            };
            let base = format!("http://{}", running.addr);
            eprintln!(
                "{}",
                tr!(fmt "aestheris ▸ passerelle {base} · session {session} (Ctrl-C pour arrêter)",
                    "aestheris ▸ gateway {base} · session {session} (Ctrl-C to stop)")
            );
            eprintln!(
                "{}",
                tr!(
                    "aestheris ▸ variables à donner à l'agent :",
                    "aestheris ▸ variables to give the agent:"
                )
            );
            for r in gw.routes() {
                if let Some(v) = &r.env {
                    println!("export {v}={}", gw.token_for_agent());
                }
                if let Some(v) = &r.base_url_env {
                    println!("export {v}={base}/{}", r.name);
                }
            }
            tokio::signal::ctrl_c().await?;
            running.stop().await;
            Ok(0)
        }

        Command::Scan {
            path,
            json,
            no_home,
            excludes,
        } => {
            let report = aestheris::project_scan::scan(&aestheris::project_scan::Options {
                root: path,
                home: if no_home { None } else { dirs::home_dir() },
                excludes,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render_text());
            }
            Ok(i32::from(report.summary.critical > 0))
        }

        Command::Audit { action } => match action {
            AuditAction::Verify => {
                let r = audit::verify(&audit_path)?;
                if r.ok {
                    let (n, head) = (r.count, hex::encode(r.head));
                    println!(
                        "{}",
                        tr!(fmt "✓ journal intact : {n} événement(s), tête {head}",
                            "✓ log intact: {n} event(s), head {head}")
                    );
                    Ok(0)
                } else {
                    let (line, problem) = (r.broken_at.unwrap_or(0), r.problem.unwrap_or_default());
                    println!(
                        "{}",
                        tr!(fmt "✗ journal altéré à la ligne {line} : {problem}",
                            "✗ log tampered with at line {line}: {problem}")
                    );
                    Ok(1)
                }
            }
            AuditAction::Report => {
                let events = audit::tail(&audit_path, usize::MAX)?;
                print!(
                    "{}",
                    aestheris::report::render(&events, &audit_path.display().to_string())
                );
                Ok(0)
            }
            AuditAction::Exposure => {
                // route → (requêtes protégées, requêtes sans bouclier, catégorie → nombre)
                let mut by_route: std::collections::BTreeMap<
                    String,
                    (u64, u64, std::collections::BTreeMap<String, u64>),
                > = Default::default();
                for e in audit::tail(&audit_path, usize::MAX)? {
                    let (Some(route), Some("allowed")) = (e.route.clone(), e.decision.as_deref())
                    else {
                        continue;
                    };
                    if e.kind != "request" || route == "sortie" {
                        continue;
                    }
                    let entry = by_route.entry(route).or_default();
                    match e.detail.as_deref().and_then(|d| {
                        d.strip_prefix("confidentialité : ")
                            .or_else(|| d.strip_prefix("confidentiality: "))
                    }) {
                        Some(list) => {
                            entry.0 += 1;
                            for part in list.split(", ") {
                                if let Some((cat, n)) = part.split_once('×') {
                                    *entry.2.entry(cat.to_string()).or_insert(0) +=
                                        n.parse::<u64>().unwrap_or(0);
                                }
                            }
                        }
                        None => entry.1 += 1,
                    }
                }
                let path = audit_path.display();
                println!(
                    "{}",
                    tr!(fmt "Registre d'exposition : {path}", "Exposure register: {path}")
                );
                if by_route.is_empty() {
                    println!(
                        "{}",
                        tr!("  aucune requête relayée", "  no request relayed")
                    );
                }
                for (route, (protected, bare, cats)) in by_route {
                    let cats: Vec<String> = cats.iter().map(|(k, n)| format!("{k}×{n}")).collect();
                    let cats = if cats.is_empty() {
                        String::new()
                    } else {
                        let c = cats.join(", ");
                        tr!(fmt " · pseudonymisé : {c}", " · pseudonymized: {c}")
                    };
                    println!(
                        "{}",
                        tr!(fmt "  {route:<10} {protected} requête(s) avec bouclier{cats}",
                            "  {route:<10} {protected} request(s) with shield{cats}")
                    );
                    if bare > 0 {
                        let pad = "";
                        println!(
                            "{}",
                            tr!(fmt "  {pad:<10} {bare} requête(s) sans bouclier (contenu transmis tel quel)",
                                "  {pad:<10} {bare} request(s) without shield (content sent as is)")
                        );
                    }
                }
                Ok(0)
            }
            AuditAction::Show { last } => {
                for e in audit::tail(&audit_path, last)? {
                    let what = match e.kind.as_str() {
                        "request" => format!(
                            "{:<12} {:<7} {:<8} {}{}",
                            e.decision.as_deref().unwrap_or("?"),
                            e.method.as_deref().unwrap_or(""),
                            e.route.as_deref().unwrap_or("-"),
                            e.path.as_deref().unwrap_or(""),
                            if e.detected.is_empty() {
                                String::new()
                            } else {
                                format!("  [{}]", e.detected.join(", "))
                            }
                        ),
                        other => format!("{other:<12} {}", e.detail.as_deref().unwrap_or("")),
                    };
                    println!("#{:<5} {}  {}", e.seq, e.ts, what);
                    if e.kind == "request" {
                        for line in e.reason.iter().chain(e.detail.iter()) {
                            println!("{:>34} ↳ {line}", "");
                        }
                    }
                }
                Ok(0)
            }
        },
    }
}
