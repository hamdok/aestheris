//! Bac à sable Linux : bubblewrap + seccomp.
//!
//! Pourquoi pas Landlock seul : Landlock ne sait qu'autoriser des arborescences ; il ne peut pas
//! masquer `~/.ssh` à l'intérieur d'un dossier personnel lisible. bubblewrap construit, sans droits administrateur, une vue du disque propre à l'agent :
//!
//! ```text
//! /             lecture seule (--ro-bind / /)
//! /dev, /proc   neufs (aucun périphérique de l'hôte, seulement les processus du bac à sable)
//! /tmp          neuf et vide : les sockets et fichiers temporaires de l'hôte sont invisibles
//! allow_write   seuls dossiers modifiables (+ TMPDIR de session, + cache des agents)
//! secrets       masqués : dossier → vide en lecture seule, fichier → /dev/null
//! journal, politique, .git/hooks, .zshrc, .vscode, configurations MCP… → lecture seule
//! ```
//!
//! Réseau restreint (`egress: allowlist | none`) : l'agent vit dans un espace réseau vide
//! (`--unshare-net`). Un relais, lancé dans cet espace avant l'agent (`aestheris __sandbox-init`),
//! écoute sur `127.0.0.1:<port de la passerelle>` et transmet chaque connexion au socket Unix de la
//! passerelle : les variables (URL de base, HTTPS_PROXY) restent identiques à macOS, et **rien
//! d'autre** n'est joignable : ni Internet, ni les services du poste, ni le DNS.
//!
//! Filtre seccomp appliqué à l'agent (et hérité par ses descendants) :
//! - sockets IPv4/IPv6 seulement : pas de socket Unix (Docker = accès root, agent SSH), pas de
//!   netlink, pas de vsock ; `socketpair` Unix reste permis (communication entre processus) ;
//! - `io_uring` interdit (il crée des sockets sans passer par `socket()`) ;
//! - `ptrace`, `process_vm_readv/writev` interdits ;
//! - `ioctl(TIOCSTI / TIOCLINUX)` interdits : pas d'injection de frappes dans le terminal de
//!   l'utilisateur (commandes exécutées hors du bac à sable après la session).
//!
//! Limite propre à Linux : les protections par motif (`.env`, `.zshrc`, `.git/hooks`…) portent sur
//! les fichiers présents au lancement (recherche sur 4 niveaux dans les dossiers modifiables),
//! pas sur ceux que l'agent crée ensuite. macOS, lui, applique ces motifs à tout moment.

use crate::error::{Error, Result};
use crate::policy::{Egress, SandboxPolicy};
use crate::sandbox::{HOME_SECRETS, HOME_WRITE_PROTECTED, expand_home, resolve};
use crate::tr;
use std::path::{Path, PathBuf};

/// Socket-relais vers la passerelle, dans le dossier temporaire de la session.
pub const BRIDGE_SOCKET: &str = ".aestheris-passerelle.sock";

/// Profondeur et volume maximum de la recherche des fichiers protégés par motif.
const SCAN_DEPTH: usize = 4;
const SCAN_MAX_ENTRIES: usize = 50_000;
/// Dossiers volumineux et sans configuration exécutable : non parcourus.
const SCAN_SKIP: &[&str] = &[
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
];

/// Fichiers qui s'exécutent plus tard hors du bac à sable (mêmes listes que macOS).
const DANGEROUS_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".profile",
    ".gitconfig",
    ".gitmodules",
    ".ripgreprc",
    ".mcp.json",
    ".envrc",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    "mcp.json",
    "mcp_config.json",
    "mcp-config.json",
    "claude_desktop_config.json",
    "managed-mcp.json",
    "managed-settings.json",
];
const DANGEROUS_DIRS: &[&str] = &[".vscode", ".idea", ".cursor"];
/// Chemins dangereux reconnus par leur fin (`…/.git/hooks`).
const DANGEROUS_SUFFIXES: &[&str] = &[
    ".git/hooks",
    ".claude/commands",
    ".claude/agents",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
];

pub struct LinuxSpec<'a> {
    pub policy: &'a SandboxPolicy,
    pub egress: Egress,
    pub gateway_port: u16,
    pub vault: &'a Path,
    pub audit: &'a Path,
    pub policy_file: &'a Path,
    pub run_dir: &'a Path,
    pub home: Option<PathBuf>,
    pub cwd: PathBuf,
    pub session_tmp: PathBuf,
    pub agent_cache: Option<PathBuf>,
    /// Ce bubblewrap accepte `--disable-userns` (≥ 0.8) : l'agent ne pourra pas créer d'espace
    /// utilisateur imbriqué.
    pub disable_userns: bool,
}

/// Arguments de bubblewrap : vue du disque, espaces de noms, puis l'initialisation
/// (`init` = ce programme) qui lance le relais et l'agent sous seccomp.
pub fn bwrap_args(spec: &LinuxSpec, init: &Path, command: &[String]) -> Result<Vec<String>> {
    let home = spec.home.as_deref();
    let restricted = spec.egress != Egress::Open;
    let mut a = Args::default();

    a.push(&["--die-with-parent", "--unshare-pid", "--unshare-ipc"]);
    if spec.disable_userns {
        a.push(&["--unshare-user", "--disable-userns"]);
    }
    if restricted {
        a.push(&["--unshare-net"]);
    }
    a.push(&["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]);
    a.push(&["--tmpfs", "/tmp", "--tmpfs", "/dev/shm"]);

    // --- écriture
    let mut writable: Vec<PathBuf> = Vec::new();
    for p in &spec.policy.allow_write {
        writable.push(resolve(p, home, &spec.cwd, "sandbox.allow_write")?);
    }
    let scan_roots: Vec<PathBuf> = writable.iter().filter_map(|p| real(p)).collect();
    writable.push(spec.session_tmp.clone());
    writable.extend(spec.agent_cache.iter().cloned());
    let writable: Vec<PathBuf> = dedup(writable.iter().filter_map(|p| real(p)));
    for w in &writable {
        a.bind("--bind", w, w);
    }
    // Sockets Unix listés par la politique. Attention : seccomp ne filtre pas les chemins ; dès
    // qu'un socket est permis, tout socket visible devient joignable.
    for s in &spec.policy.allow_unix_sockets {
        let p = resolve(s, home, &spec.cwd, "sandbox.allow_unix_sockets")?;
        if let Some(r) = real(&p) {
            a.bind("--bind", &r, &r);
        }
    }
    // Le programme d'initialisation doit rester exécutable même s'il est sous /tmp.
    if let Some(exe) = real(init) {
        a.bind("--ro-bind", &exe, &exe);
    }
    let visible = |p: &Path| !p.starts_with("/tmp") || writable.iter().any(|w| p.starts_with(w));

    // --- secrets : masqués (après les dossiers modifiables, pour l'emporter)
    let mut secrets: Vec<PathBuf> = Vec::new();
    if let Some(h) = home {
        secrets.extend(HOME_SECRETS.iter().map(|rel| h.join(rel)));
    }
    secrets.push(spec.vault.to_path_buf());
    secrets.push(spec.run_dir.to_path_buf());
    for p in &spec.policy.protect_paths {
        secrets.push(expand_home(p, home)?);
    }
    let mut dotenv = Vec::new();
    let mut dangerous = Vec::new();
    let mut roots = scan_roots.clone();
    roots.extend(real(&spec.cwd));
    for root in dedup(roots.into_iter()) {
        scan(&root, spec.policy, &mut dotenv, &mut dangerous);
    }
    if spec.policy.deny_dotenv {
        secrets.extend(dotenv);
    }
    for s in dedup(secrets.iter().filter_map(|p| real(p))) {
        if !visible(&s) {
            continue;
        }
        if s.is_dir() {
            a.bind_one("--tmpfs", &s);
            a.bind_one("--remount-ro", &s);
        } else {
            a.bind("--ro-bind", Path::new("/dev/null"), &s);
        }
    }

    // --- lecture seule : journal, politique, fichiers exécutés plus tard hors du bac à sable
    let mut read_only = vec![spec.audit.to_path_buf(), spec.policy_file.to_path_buf()];
    read_only.extend(dangerous);
    if let Some(h) = home {
        read_only.extend(HOME_WRITE_PROTECTED.iter().map(|rel| h.join(rel)));
    }
    for p in dedup(read_only.iter().filter_map(|p| real(p))) {
        // seulement là où l'agent pourrait écrire
        if visible(&p) && writable.iter().any(|w| p.starts_with(w)) {
            a.bind("--ro-bind", &p, &p);
        }
    }

    a.bind_one("--chdir", &spec.cwd);
    a.push(&["--"]);
    a.path(init);
    a.push(&["__sandbox-init"]);
    if restricted {
        a.bind_one("--bridge", &spec.session_tmp.join(BRIDGE_SOCKET));
        a.push(&["--port", &spec.gateway_port.to_string()]);
    }
    if !spec.policy.allow_unix_sockets.is_empty() {
        a.push(&["--allow-unix"]);
    }
    a.push(&["--"]);
    a.push(&command.iter().map(String::as_str).collect::<Vec<_>>());
    a.finish()
}

#[derive(Default)]
struct Args {
    v: Vec<String>,
    err: Option<Error>,
}

impl Args {
    fn push(&mut self, items: &[&str]) {
        self.v.extend(items.iter().map(|s| s.to_string()));
    }
    fn path(&mut self, p: &Path) {
        match p.to_str() {
            Some(s) if !s.chars().any(|c| c.is_control()) => self.v.push(s.to_string()),
            _ => {
                self.err.get_or_insert(Error::Policy(tr!(fmt
                    "chemin inutilisable : {}", "unusable path: {}",
                    p.display()
                )));
            }
        }
    }
    fn bind(&mut self, flag: &str, src: &Path, dst: &Path) {
        self.push(&[flag]);
        self.path(src);
        self.path(dst);
    }
    fn bind_one(&mut self, flag: &str, p: &Path) {
        self.push(&[flag]);
        self.path(p);
    }
    fn finish(self) -> Result<Vec<String>> {
        match self.err {
            Some(e) => Err(e),
            None => Ok(self.v),
        }
    }
}

/// Chemin réel d'un chemin existant (bubblewrap refuse de monter sur un lien symbolique).
fn real(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

fn dedup(it: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    for p in it {
        if !v.contains(&p) {
            v.push(p);
        }
    }
    v
}

/// Recherche, sous `root`, les `.env` (à masquer) et les chemins dangereux (à figer en lecture).
fn scan(
    root: &Path,
    policy: &SandboxPolicy,
    dotenv: &mut Vec<PathBuf>,
    dangerous: &mut Vec<PathBuf>,
) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            seen += 1;
            if seen > SCAN_MAX_ENTRIES {
                return;
            }
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let text = path.to_string_lossy();
            let suffix = DANGEROUS_SUFFIXES
                .iter()
                .any(|s| text.ends_with(&format!("/{s}")))
                || (!policy.allow_git_config && text.ends_with("/.git/config"));
            if ft.is_file() && (name == ".env" || name.starts_with(".env.")) {
                dotenv.push(path.clone());
            }
            if suffix
                || (ft.is_file() && DANGEROUS_FILES.contains(&name.as_str()))
                || (ft.is_dir() && DANGEROUS_DIRS.contains(&name.as_str()))
            {
                dangerous.push(path.clone());
                continue;
            }
            if ft.is_dir() && depth + 1 < SCAN_DEPTH && !SCAN_SKIP.contains(&name.as_str()) {
                // Dans .git, seuls hooks et config comptent (déjà traités ci-dessus).
                if name == ".git" {
                    for sub in ["hooks", "config"] {
                        let p = path.join(sub);
                        let is_config = sub == "config";
                        if p.exists() && (!is_config || !policy.allow_git_config) {
                            dangerous.push(p);
                        }
                    }
                    continue;
                }
                stack.push((path, depth + 1));
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Relais : hôte (socket Unix → passerelle TCP), bac à sable (TCP → Unix) */
/* ------------------------------------------------------------------ */

/// Côté hôte : le socket Unix du dossier de session mène à la passerelle.
pub fn serve_host_bridge(
    socket: &Path,
    gateway: std::net::SocketAddr,
) -> Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket).map_err(|e| {
        Error::Policy(tr!(fmt "relais {} : {e}", "relay {}: {e}", socket.display()))
    })?;
    Ok(tokio::spawn(async move {
        while let Ok((mut unix, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut tcp) = tokio::net::TcpStream::connect(gateway).await {
                    let _ = tokio::io::copy_bidirectional(&mut unix, &mut tcp).await;
                }
            });
        }
    }))
}

/// Côté bac à sable : chaque connexion à 127.0.0.1:PORT est transmise au socket de la passerelle.
/// Threads simples (pas d'exécuteur asynchrone) : le processus est déjà lancé quand ils démarrent.
pub fn run_inner_bridge(listener: std::net::TcpListener, socket: PathBuf) {
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        let socket = socket.clone();
        std::thread::spawn(move || {
            if let Ok(unix) = std::os::unix::net::UnixStream::connect(&socket) {
                pipe(tcp, unix);
            }
        });
    }
}

fn pipe(tcp: std::net::TcpStream, unix: std::os::unix::net::UnixStream) {
    use std::net::Shutdown;
    let (Ok(mut tcp_r), Ok(mut unix_w)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut tcp_r, &mut unix_w);
        let _ = unix_w.shutdown(Shutdown::Write);
    });
    let (mut unix_r, mut tcp_w) = (unix, tcp);
    let _ = std::io::copy(&mut unix_r, &mut tcp_w);
    let _ = tcp_w.shutdown(Shutdown::Write);
    let _ = up.join();
}

/* ------------------------------------------------------------------ */
/* Initialisation dans le bac à sable (`aestheris __sandbox-init`)     */
/* ------------------------------------------------------------------ */

/// Lancé par bubblewrap dans le bac à sable : ouvre le relais (réseau restreint), puis lance
/// l'agent sous seccomp et renvoie son code de sortie.
#[cfg(target_os = "linux")]
pub fn sandbox_init(
    bridge: Option<PathBuf>,
    port: Option<u16>,
    allow_unix: bool,
    command: &[String],
) -> Result<i32> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let (program, args) = command.split_first().ok_or_else(|| {
        Error::Policy(tr!("aucune commande à lancer", "no command to run").into())
    })?;
    // Relais ouvert AVANT l'agent : ses connexions attendent dans la file d'écoute.
    let listener = match (bridge, port) {
        (Some(sock), Some(port)) => {
            let l = std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
                Error::Policy(
                    tr!(fmt "relais 127.0.0.1:{port} : {e}", "relay 127.0.0.1:{port}: {e}"),
                )
            })?;
            Some((l, sock))
        }
        _ => None,
    };
    // Filtre préparé avant le fork : dans l'enfant, seuls prctl et seccomp sont appelés.
    let filter = seccomp::build(allow_unix)?;
    // Ctrl-C va à tout le groupe : l'initialisation l'ignore (gestionnaire vide, remis par défaut
    // à l'exec de l'agent) pour attendre la fin de l'agent et rendre son code.
    // SAFETY: gestionnaire sans effet, installé avant tout thread.
    unsafe {
        libc::signal(libc::SIGINT, noop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, noop as *const () as libc::sighandler_t);
    }
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    // SAFETY: entre fork et exec, seuls prctl et seccomp sont appelés, et rien n'est alloué,
    // même en cas d'erreur (le relais tourne dans un autre thread : une allocation pourrait
    // bloquer l'enfant sur un verrou de malloc tenu au moment du fork).
    unsafe {
        cmd.pre_exec(move || {
            seccompiler::apply_filter(&filter)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
    }
    let mut child = cmd.spawn().map_err(|e| {
        Error::Policy(
            tr!(fmt "lancement de « {program} » impossible : {e}", "cannot start “{program}”: {e}"),
        )
    })?;
    if let Some((l, sock)) = listener {
        std::thread::spawn(move || run_inner_bridge(l, sock));
    }
    let status = child.wait()?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

#[cfg(target_os = "linux")]
extern "C" fn noop(_: libc::c_int) {}

#[cfg(not(target_os = "linux"))]
pub fn sandbox_init(_: Option<PathBuf>, _: Option<u16>, _: bool, _: &[String]) -> Result<i32> {
    Err(Error::Policy(
        tr!(
            "__sandbox-init n'existe que sur Linux",
            "__sandbox-init only exists on Linux"
        )
        .into(),
    ))
}

#[cfg(target_os = "linux")]
mod seccomp {
    use crate::error::{Error, Result};
    use crate::tr;
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    /// Filtre de l'agent (voir l'en-tête du module).
    #[allow(clippy::unnecessary_cast)] // le type des requêtes ioctl dépend de la libc (glibc, musl)
    pub fn build(allow_unix: bool) -> Result<BpfProgram> {
        let e =
            |x: seccompiler::BackendError| Error::Policy(tr!(fmt "seccomp : {x}", "seccomp: {x}"));
        let cond = |arg: u8, op: SeccompCmpOp, v: u64| {
            SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, v).map_err(e)
        };
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for nr in [
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            rules.insert(nr, vec![]); // sans condition : toujours refusé
        }
        let mut not_allowed = vec![
            cond(0, SeccompCmpOp::Ne, libc::AF_INET as u64)?,
            cond(0, SeccompCmpOp::Ne, libc::AF_INET6 as u64)?,
        ];
        if allow_unix {
            not_allowed.push(cond(0, SeccompCmpOp::Ne, libc::AF_UNIX as u64)?);
        }
        rules.insert(
            libc::SYS_socket,
            vec![SeccompRule::new(not_allowed).map_err(e)?],
        );
        rules.insert(
            libc::SYS_socketpair,
            vec![
                SeccompRule::new(vec![cond(0, SeccompCmpOp::Ne, libc::AF_UNIX as u64)?])
                    .map_err(e)?,
            ],
        );
        rules.insert(
            libc::SYS_ioctl,
            vec![
                SeccompRule::new(vec![cond(1, SeccompCmpOp::Eq, libc::TIOCSTI as u64)?])
                    .map_err(e)?,
                SeccompRule::new(vec![cond(1, SeccompCmpOp::Eq, libc::TIOCLINUX as u64)?])
                    .map_err(e)?,
            ],
        );
        let arch = if cfg!(target_arch = "x86_64") {
            TargetArch::x86_64
        } else if cfg!(target_arch = "aarch64") {
            TargetArch::aarch64
        } else {
            return Err(Error::Policy(
                tr!(
                    "seccomp : architecture non prise en charge",
                    "seccomp: unsupported architecture"
                )
                .into(),
            ));
        };
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            arch,
        )
        .map_err(e)?;
        filter.try_into().map_err(e)
    }
}

/* ------------------------------------------------------------------ */
/* Disponibilité                                                       */
/* ------------------------------------------------------------------ */

/// bubblewrap utilisable : présent, hors du dossier courant, capable de créer ses espaces.
/// Renvoie son chemin et s'il accepte `--disable-userns`.
pub fn find_bwrap(cwd: &Path) -> Result<(PathBuf, bool)> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .filter(|d| d.is_absolute() && !d.starts_with(cwd))
        .map(|d| d.join("bwrap"))
        .find(|p| p.is_file())
        .ok_or_else(|| {
            Error::Policy(
                tr!(
                    "bac à sable demandé mais bubblewrap est absent (apt install bubblewrap, \
                     dnf install bubblewrap) : lancement refusé plutôt que sans protection",
                    "sandbox requested but bubblewrap is missing (apt install bubblewrap, \
                     dnf install bubblewrap): refusing to start rather than run unprotected"
                )
                .into(),
            )
        })?;
    let help = std::process::Command::new(&found).arg("--help").output()?;
    let disable_userns = String::from_utf8_lossy(&help.stdout).contains("--disable-userns");
    let probe = std::process::Command::new(&found)
        .args(["--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true"])
        .output()?;
    if !probe.status.success() {
        let why = String::from_utf8_lossy(&probe.stderr).trim().to_string();
        return Err(Error::Policy(tr!(fmt
            "bubblewrap ne peut pas créer d'espace de noms ({why}). Sur Ubuntu 23.10 et suivantes, \
             autorisez bubblewrap seul : sudo install -m 644 packaging/apparmor/bwrap \
             /etc/apparmor.d/bwrap && sudo apparmor_parser -r /etc/apparmor.d/bwrap. \
             Lancement refusé plutôt que sans protection",
            "bubblewrap cannot create namespaces ({why}). On Ubuntu 23.10 and later, allow \
             bubblewrap only: sudo install -m 644 packaging/apparmor/bwrap \
             /etc/apparmor.d/bwrap && sudo apparmor_parser -r /etc/apparmor.d/bwrap. \
             Refusing to start rather than run unprotected")));
    }
    Ok((found, disable_userns))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vue_du_disque_et_relais() {
        // hors de /tmp : sous Linux, le /tmp de l'hôte est de toute façon invisible dans le bac à sable
        let root = tempfile::tempdir_in(dirs::home_dir().unwrap()).unwrap();
        let home = root.path().join("home");
        let projet = home.join("projet");
        std::fs::create_dir_all(projet.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".netrc"), "machine x password y").unwrap();
        std::fs::write(projet.join(".env"), "DB_PASSWORD=x").unwrap();
        std::fs::write(projet.join(".envrc"), "export X=1").unwrap();
        std::fs::write(projet.join("aestheris.yaml"), "version: 1").unwrap();
        std::fs::write(projet.join(".git/config"), "[core]").unwrap();
        let session = root.path().join("session");
        std::fs::create_dir_all(&session).unwrap();
        let sp = SandboxPolicy {
            enabled: true,
            deny_dotenv: true,
            allow_write: vec![".".into()],
            ..Default::default()
        };
        let spec = LinuxSpec {
            policy: &sp,
            egress: Egress::None,
            gateway_port: 40123,
            vault: &home.join(".aestheris/vault.json"),
            audit: &home.join(".aestheris/audit.ndjson"),
            policy_file: &projet.join("aestheris.yaml"),
            run_dir: &home.join(".aestheris/run"),
            home: Some(home.clone()),
            cwd: projet.clone(),
            session_tmp: session.clone(),
            agent_cache: None,
            disable_userns: true,
        };
        let cmd = vec!["claude".to_string(), "--version".to_string()];
        let a = bwrap_args(&spec, Path::new("/bin/sh"), &cmd)
            .unwrap()
            .join(" ");
        let r = |p: &Path| std::fs::canonicalize(p).unwrap().display().to_string();
        assert!(a.starts_with("--die-with-parent --unshare-pid --unshare-ipc --unshare-user --disable-userns --unshare-net --ro-bind / / "));
        assert!(a.contains(&format!("--bind {0} {0}", r(&projet))));
        assert!(a.contains(&format!(
            "--tmpfs {0} --remount-ro {0}",
            r(&home.join(".ssh"))
        )));
        assert!(a.contains(&format!("--ro-bind /dev/null {}", r(&home.join(".netrc")))));
        assert!(a.contains(&format!("--ro-bind /dev/null {}", r(&projet.join(".env")))));
        for p in [".git/hooks", ".git/config", ".envrc", "aestheris.yaml"] {
            let q = r(&projet.join(p));
            assert!(
                a.contains(&format!("--ro-bind {q} {q}")),
                "{p} doit être en lecture seule"
            );
        }
        // les masques viennent après les dossiers modifiables (sinon ils seraient recouverts)
        assert!(
            a.find("--ro-bind /dev/null").unwrap()
                > a.find(&format!("--bind {}", r(&projet))).unwrap()
        );
        assert!(a.ends_with(&format!(
            "-- /bin/sh __sandbox-init --bridge {}/{BRIDGE_SOCKET} --port 40123 -- claude --version",
            session.display()
        )));
    }

    #[tokio::test]
    async fn relais_bout_en_bout() {
        // passerelle simulée : écho TCP
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join(BRIDGE_SOCKET);
        let _host = serve_host_bridge(&sock, gateway).unwrap();
        let inner = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = inner.local_addr().unwrap().port();
        std::thread::spawn(move || run_inner_bridge(inner, sock));
        let echoed = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.write_all(b"bonjour").unwrap();
            c.shutdown(std::net::Shutdown::Write).unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).unwrap();
            out
        })
        .await
        .unwrap();
        assert_eq!(echoed, "bonjour");
    }
}
