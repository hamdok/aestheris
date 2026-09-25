//! `aestheris run -- <commande>` : lance un agent derrière la passerelle.
//!
//! 1. charge la politique et déverrouille le coffre ;
//! 2. déchiffre en mémoire uniquement les secrets des routes ;
//! 3. démarre la passerelle sur 127.0.0.1 (port libre) ;
//! 4. lance l'agent avec, pour chaque route, la variable de clé = jeton fantôme et la variable
//!    d'URL de base = adresse de la passerelle ; toute vraie clé et le mot de passe du coffre sont
//!    retirés de son environnement ;
//! 5. à la fin : bilan de la session et tête du journal chaîné.

use crate::approval;
use crate::audit::{AuditLog, Event};
use crate::error::{Error, Result};
use crate::phantom::SessionToken;
use crate::policy::{Egress, Policy};
use crate::proxy::{self, Gateway};
#[cfg(target_os = "macos")]
use crate::sandbox::{self, SandboxSpec};
use crate::scan;
use crate::tr;
use crate::vault::Vault;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Variables jamais transmises à l'agent.
const STRIPPED_ENV: &[&str] = &["AESTHERIS_PASSWORD"];

/// Noms de variables qui portent presque toujours un secret : retirées de l'environnement de
/// l'agent (sauf si une route les redéfinit avec un jeton fantôme).
const SECRET_ENV_NAMES: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "STRIPE_API_KEY",
    "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN",
    "NPM_TOKEN",
    "HF_TOKEN",
    "DATABASE_URL",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
];

/// Variables du terminal qui contiennent un secret (par leur nom ou leur format) : à retirer.
fn leaked_env(route_envs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in std::env::vars_os() {
        let (Some(k), v) = (k.to_str().map(str::to_string), v.to_string_lossy()) else {
            continue;
        };
        if route_envs.contains(&k) || STRIPPED_ENV.contains(&k.as_str()) {
            continue;
        }
        if SECRET_ENV_NAMES.contains(&k.as_str()) || !scan::detect(&v).is_empty() {
            out.push(k);
        }
    }
    out.sort();
    out
}

pub struct RunOptions<'a> {
    pub policy: &'a Path,
    pub vault: &'a Path,
    pub audit: &'a Path,
    pub password: &'a str,
    pub command: &'a [String],
    /// Dossier des canaux de validation humaine (`~/.aestheris/run`).
    pub run_dir: &'a Path,
    /// Linux : programme `aestheris` lancé dans le bac à sable pour l'initialiser (relais, seccomp).
    /// `None` : ce programme-ci.
    pub sandbox_init: Option<&'a Path>,
}

/// Prépare une passerelle prête à démarrer (partagé par `run` et `serve`).
pub fn prepare(
    policy_path: &Path,
    vault_path: &Path,
    audit_path: &Path,
    password: &str,
) -> Result<(Arc<Gateway>, String)> {
    let policy = Policy::load(policy_path)?;
    let vault = Vault::open(vault_path, password)?;
    let mut secrets = HashMap::new();
    for route in policy.routes.values() {
        secrets.insert(route.name.clone(), vault.get(&route.secret)?);
    }
    drop(vault); // la clé de données est effacée de la mémoire ici

    let audit = Arc::new(AuditLog::open(audit_path)?);
    let session = new_session_id()?;
    let token = SessionToken::generate()?;
    let routes: Vec<String> = policy.routes.keys().cloned().collect();
    audit.append(Event {
        session: session.clone(),
        kind: "session_start".into(),
        detail: Some({
            let (routes, egress) = (routes.join(", "), &policy.egress);
            let sandbox = match (policy.sandbox.enabled, crate::i18n::fr()) {
                (true, true) => "oui",
                (false, true) => "non",
                (true, false) => "yes",
                (false, false) => "no",
            };
            tr!(fmt "routes : {routes} · bac à sable : {sandbox} · sortie réseau : {egress}",
                "routes: {routes} · sandbox: {sandbox} · network egress: {egress}")
        }),
        ..Default::default()
    })?;
    Ok((
        Arc::new(Gateway::new(
            policy,
            secrets,
            token,
            audit,
            session.clone(),
        )?),
        session,
    ))
}

pub async fn run(opts: RunOptions<'_>) -> Result<i32> {
    let (program, args) = opts.command.split_first().ok_or_else(|| {
        Error::Policy(tr!("aucune commande à lancer", "no command to run").into())
    })?;
    let (gateway, session) = prepare(opts.policy, opts.vault, opts.audit, opts.password)?;
    let running = proxy::start(gateway.clone(), 0).await?;
    let base = format!("http://{}", running.addr);

    let policy = gateway.policy();

    // Validation humaine : canal local ouvert seulement si la politique peut en demander.
    let admin = if policy.uses_approval() {
        let a = approval::serve(gateway.approvals.clone(), opts.run_dir)?;
        if !policy.sandbox.enabled {
            eprintln!(
                "{}",
                tr!(
                    "aestheris ▸ ⚠ sans bac à sable, la validation humaine protège des erreurs de l'agent, \
                     pas d'un agent malveillant (activez sandbox.enabled)",
                    "aestheris ▸ ⚠ without a sandbox, human approval protects against the agent's \
                     mistakes, not against a malicious agent (enable sandbox.enabled)"
                )
            );
        }
        Some(a)
    } else {
        None
    };

    // Bac à sable : demandé mais indisponible → refus de lancer (fail secure).
    let session_tmp = if policy.sandbox.enabled {
        Some(SessionTmp::create(&session)?)
    } else {
        None
    };
    let mut host_bridge = None;
    let mut cmd = if let Some(tmp) = &session_tmp {
        let cache = agent_cache();
        let cwd = std::env::current_dir()
            .map_err(|e| Error::Policy(format!("dossier courant illisible : {e}")))?;
        let ctx = SandboxContext {
            opts: &opts,
            policy,
            gateway: running.addr,
            cwd,
            session_tmp: tmp.0.clone(),
            agent_cache: cache.clone(),
        };
        let (mut c, bridge) = sandboxed(&ctx)?;
        host_bridge = bridge;
        c.env("TMPDIR", &tmp.0);
        if let Some(cache) = &cache {
            for (var, sub) in CACHE_ENV {
                c.env(var, cache.join(sub));
            }
        }
        c
    } else {
        let mut c = tokio::process::Command::new(program);
        c.args(args);
        c
    };

    for v in STRIPPED_ENV.iter().chain(crate::harden::INJECTION_ENV) {
        cmd.env_remove(v);
    }
    let route_envs: Vec<String> = gateway.routes().filter_map(|r| r.env.clone()).collect();
    let leaked = leaked_env(&route_envs);
    for v in &leaked {
        cmd.env_remove(v);
    }

    eprintln!(
        "{}",
        tr!(fmt "aestheris ▸ passerelle {base} · session {session}",
            "aestheris ▸ gateway {base} · session {session}")
    );
    if policy.mode == crate::policy::Mode::Observe {
        eprintln!(
            "{}",
            tr!(
                "aestheris ▸ 👁 mode observation : rien n'est bloqué ni modifié par la politique, tout est noté \
                 (bilan : aestheris audit report)",
                "aestheris ▸ 👁 observe mode: the policy blocks and modifies nothing, everything is \
                 recorded (summary: aestheris audit report)"
            )
        );
    }
    if policy.sandbox.enabled {
        let kind = if cfg!(target_os = "linux") {
            "bubblewrap + seccomp"
        } else {
            "Seatbelt"
        };
        let egress = &policy.egress;
        eprintln!(
            "{}",
            tr!(fmt "aestheris ▸ bac à sable {kind} actif · sortie réseau : {egress}",
                "aestheris ▸ {kind} sandbox active · network egress: {egress}")
        );
    }
    if !leaked.is_empty() {
        let vars = leaked.join(", ");
        eprintln!(
            "{}",
            tr!(fmt "aestheris ▸ variables secrètes retirées de l'environnement de l'agent : {vars}",
                "aestheris ▸ secret variables removed from the agent's environment: {vars}")
        );
    }
    if policy.egress != Egress::Open {
        // Tout le trafic hors routes passe par le proxy de sortie de la passerelle.
        let proxy_url = format!(
            "http://aestheris:{}@{}",
            gateway.token_for_agent(),
            running.addr
        );
        for v in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.env(v, &proxy_url);
        }
        cmd.env("NO_PROXY", "localhost,127.0.0.1")
            .env("no_proxy", "localhost,127.0.0.1");
        cmd.env("NODE_USE_ENV_PROXY", "1"); // Node.js ≥ 24 : respecter HTTPS_PROXY
    }
    for (k, v) in &policy.agent_env {
        cmd.env(k, v);
    }
    for route in gateway.routes() {
        if let Some(v) = &route.env {
            cmd.env(v, gateway.token_for_agent());
        }
        if let Some(v) = &route.base_url_env {
            cmd.env(v, format!("{base}/{}", route.name));
        }
        let (name, up) = (&route.name, &route.upstream);
        let (key, url) = (
            route.env.as_deref().unwrap_or("—"),
            route.base_url_env.as_deref().unwrap_or("—"),
        );
        eprintln!(
            "{}",
            tr!(fmt "aestheris ▸ {name:<10} → {up}  (clé : {key}, URL : {url})",
                "aestheris ▸ {name:<10} → {up}  (key: {key}, URL: {url})")
        );
    }
    cmd.env("AESTHERIS_GATEWAY", &base)
        .env("AESTHERIS_SESSION", &session);

    let mut child = cmd.kill_on_drop(true).spawn().map_err(|e| {
        Error::Policy(tr!(fmt "lancement de « {program} » impossible : {e}",
                "cannot start “{program}”: {e}"))
    })?;
    // L'agent et ses descendants ne pourront pas répondre aux demandes de validation.
    if let Some(pid) = child.id() {
        gateway.approvals.set_agent_pid(pid);
    }
    let status = supervise(&mut child).await?;
    if let Some(b) = host_bridge {
        b.abort();
    }
    running.stop().await;
    drop(admin);
    drop(session_tmp); // dossier temporaire de la session effacé

    let s = &gateway.stats;
    let n = |c: &std::sync::atomic::AtomicU64| c.load(Ordering::Relaxed);
    let (allowed, approved, observed, denied) =
        (n(&s.allowed), n(&s.approved), n(&s.observed), n(&s.denied));
    let (blocked, withheld, unauthorized, errors) = (
        n(&s.blocked),
        n(&s.withheld),
        n(&s.unauthorized),
        n(&s.errors),
    );
    let summary = tr!(fmt
        "{allowed} autorisée(s) (dont {approved} validée(s) par un humain), {observed} observée(s), {denied} refusée(s), {blocked} bloquée(s) (secret en clair), {withheld} donnée(s) fantôme(s) retenue(s), {unauthorized} sans jeton valide, {errors} erreur(s)",
        "{allowed} allowed (including {approved} approved by a human), {observed} observed, {denied} denied, {blocked} blocked (plaintext secret), {withheld} phantom value(s) withheld, {unauthorized} without a valid token, {errors} error(s)");
    let audit = gateway.audit_log();
    audit.append(Event {
        session: session.clone(),
        kind: "session_end".into(),
        detail: Some(summary.clone()),
        ..Default::default()
    })?;
    eprintln!(
        "{}",
        tr!(fmt "aestheris ▸ fin de session : {summary}", "aestheris ▸ session ended: {summary}")
    );
    let (path, head) = (audit.path().display(), &audit.head()[..16]);
    eprintln!(
        "{}",
        tr!(fmt "aestheris ▸ journal {path} · tête {head}", "aestheris ▸ log {path} · head {head}")
    );
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

/// Attend la fin de l'agent : la passerelle vit exactement aussi longtemps que lui.
/// - Ctrl-C (SIGINT) et SIGQUIT arrivent aussi à l'agent par le terminal : la passerelle les
///   ignore et laisse l'agent décider (Claude Code s'en sert pour interrompre une réponse ; si la
///   passerelle mourait, l'agent resterait sans API) ;
/// - SIGTERM, SIGHUP : transmis à l'agent ; la passerelle attend sa fin, puis s'arrête.
async fn supervise(child: &mut tokio::process::Child) -> Result<std::process::ExitStatus> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt())?;
    let mut quit = signal(SignalKind::quit())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let pid = child.id();
    let forward = |sig: libc::c_int| {
        if let Some(p) = pid {
            // SAFETY: envoi d'un signal à notre propre processus enfant. Son numéro ne peut pas
            // avoir été réattribué : tant que child.wait() (même boucle) ne l'a pas récupéré, le
            // processus terminé garde son numéro.
            unsafe { libc::kill(p as libc::pid_t, sig) };
        }
    };
    loop {
        tokio::select! {
            status = child.wait() => return Ok(status?),
            _ = int.recv() => {}
            _ = quit.recv() => {}
            _ = term.recv() => forward(libc::SIGTERM),
            _ = hup.recv() => forward(libc::SIGHUP),
        }
    }
}

/// Ce qu'il faut pour construire la commande isolée, quel que soit le système.
struct SandboxContext<'a> {
    opts: &'a RunOptions<'a>,
    policy: &'a Policy,
    gateway: std::net::SocketAddr,
    cwd: std::path::PathBuf,
    session_tmp: std::path::PathBuf,
    agent_cache: Option<std::path::PathBuf>,
}

type Sandboxed = (tokio::process::Command, Option<tokio::task::JoinHandle<()>>);

/// macOS : profil Seatbelt passé à `sandbox-exec`.
#[cfg(target_os = "macos")]
fn sandboxed(ctx: &SandboxContext) -> Result<Sandboxed> {
    let (program, args) = ctx.opts.command.split_first().expect("commande vérifiée");
    let profile = sandbox::seatbelt_profile(&SandboxSpec {
        policy: &ctx.policy.sandbox,
        egress: ctx.policy.egress,
        allow_dns: ctx.policy.allow_dns,
        gateway_port: ctx.gateway.port(),
        vault: ctx.opts.vault,
        audit: ctx.opts.audit,
        policy_file: ctx.opts.policy,
        run_dir: ctx.opts.run_dir,
        home: dirs::home_dir(),
        cwd: ctx.cwd.clone(),
        system_tmp: system_tmp(),
        session_tmp: ctx.session_tmp.clone(),
        agent_cache: ctx.agent_cache.clone(),
    })?;
    Ok((sandbox::wrap(program, args, &profile)?, None))
}

/// Linux : bubblewrap + seccomp ; en sortie restreinte, relais vers la passerelle.
#[cfg(target_os = "linux")]
fn sandboxed(ctx: &SandboxContext) -> Result<Sandboxed> {
    use crate::sandbox_linux::{self, BRIDGE_SOCKET, LinuxSpec};
    let (bwrap, disable_userns) = sandbox_linux::find_bwrap(&ctx.cwd)?;
    let init = match ctx.opts.sandbox_init {
        Some(p) => p.to_path_buf(),
        // Notre propre binaire, relancé dans le bac à sable. Le remplacer suppose déjà un accès en
        // écriture à son emplacement : l'attaquant n'y gagnerait rien.
        // nosemgrep: rust.lang.security.current-exe.current-exe
        None => std::env::current_exe()?,
    };
    let bwrap_args = sandbox_linux::bwrap_args(
        &LinuxSpec {
            policy: &ctx.policy.sandbox,
            egress: ctx.policy.egress,
            gateway_port: ctx.gateway.port(),
            vault: ctx.opts.vault,
            audit: ctx.opts.audit,
            policy_file: ctx.opts.policy,
            run_dir: ctx.opts.run_dir,
            home: dirs::home_dir(),
            cwd: ctx.cwd.clone(),
            session_tmp: ctx.session_tmp.clone(),
            agent_cache: ctx.agent_cache.clone(),
            disable_userns,
        },
        &init,
        ctx.opts.command,
    )?;
    let bridge = if ctx.policy.egress != Egress::Open {
        Some(sandbox_linux::serve_host_bridge(
            &ctx.session_tmp.join(BRIDGE_SOCKET),
            ctx.gateway,
        )?)
    } else {
        None
    };
    let mut c = tokio::process::Command::new(bwrap);
    c.args(bwrap_args);
    Ok((c, bridge))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sandboxed(_: &SandboxContext) -> Result<Sandboxed> {
    Err(Error::Policy(
        tr!(
            "bac à sable indisponible sur ce système : lancement refusé plutôt que sans protection",
            "no sandbox available on this system: refusing to start rather than run unprotected"
        )
        .into(),
    ))
}

/// Caches redirigés vers le dossier des agents (npm, Yarn, pip, uv, Go, XDG).
const CACHE_ENV: &[(&str, &str)] = &[
    ("npm_config_cache", "npm"),
    ("YARN_CACHE_FOLDER", "yarn"),
    ("PIP_CACHE_DIR", "pip"),
    ("UV_CACHE_DIR", "uv"),
    ("GOCACHE", "go-build"),
    ("GOMODCACHE", "go-mod"),
    ("XDG_CACHE_HOME", "xdg"),
];

/// Cache des agents (`~/Library/Caches/aestheris-agent`, 0700) : conservé d'une session à l'autre,
/// mais séparé des caches de l'utilisateur. Un agent ne peut donc pas y piéger un paquet que
/// l'utilisateur installerait ensuite hors du bac à sable.
fn agent_cache() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = dirs::cache_dir()?.join("aestheris-agent");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .ok()?;
    Some(dir)
}

/// Dossier temporaire propre à la session (0700), effacé à la fin : TMPDIR de l'agent et seul
/// endroit où il peut créer ou joindre des sockets Unix.
struct SessionTmp(std::path::PathBuf);

impl SessionTmp {
    fn create(session: &str) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        // Nom imprévisible (64 bits aléatoires) et création exclusive en 0700 : un dossier préparé
        // par un autre utilisateur fait échouer la création au lieu d'être réutilisé.
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let dir = std::env::temp_dir().join(format!("aestheris-{session}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| Error::Policy(format!("dossier temporaire de session : {e}")))?;
        Ok(Self(dir))
    }
}

impl Drop for SessionTmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "macos")]
/// Dossier temporaire de l'utilisateur, où `mktemp` écrit sur macOS quelle que soit TMPDIR.
/// Retenu seulement s'il est bien un dossier temporaire du système (jamais `/` ni le dossier
/// personnel, même si TMPDIR a été détournée).
fn system_tmp() -> Option<std::path::PathBuf> {
    // Validé ci-dessous : doit être un dossier temporaire du système, jamais `/` ni le dossier
    // personnel.
    // nosemgrep: rust.lang.security.temp-dir.temp-dir
    let t = std::env::temp_dir();
    let real = std::fs::canonicalize(&t).ok()?;
    let ok = ["/private/var/folders/", "/private/tmp/", "/tmp/"]
        .iter()
        .any(|p| real.starts_with(p) && real.as_os_str().len() > p.len());
    ok.then_some(t)
}

fn new_session_id() -> Result<String> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|e| {
        Error::Crypto(tr!(fmt "aléa indisponible : {e}", "randomness unavailable: {e}"))
    })?;
    Ok(hex::encode(b))
}
