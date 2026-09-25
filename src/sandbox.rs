//! Bac à sable du processus de l'agent.
//!
//! macOS : profil Seatbelt (SBPL) passé à `sandbox-exec`. Linux : pas encore pris en charge
//! (Landlock prévu) ; on refuse alors de lancer l'agent plutôt que de le lancer sans protection
//! (fail secure).
//!
//! Stratégie : **tout est interdit par défaut** (`deny default`), puis on ouvre le strict
//! nécessaire :
//! - exécuter des programmes, lire le disque (sauf les secrets), quelques services système sûrs ;
//! - écrire uniquement dans `sandbox.allow_write` (par défaut le dossier de lancement) et dans les
//!   dossiers temporaires ;
//! - réseau : la passerelle seule (son port exact), ou tout si `network.egress: open` ;
//! - sockets Unix : ceux du dossier temporaire de la session et ceux de `allow_unix_sockets`.
//!
//! Ce que cela ferme par rapport à la v0.2 (`allow default`) : `open` et AppleScript, qui lancent ou
//! pilotent des applications hors du bac à sable ; les sockets Unix (Docker = accès root, agent SSH =
//! usage des clés) ; les autres services locaux sur `localhost` ; le DNS (canal d'exfiltration) ;
//! l'écriture dans les fichiers qui s'exécutent plus tard hors du bac à sable (`.zshrc`,
//! `.git/hooks`, `.vscode`, `.envrc`, `~/Library/LaunchAgents`…).
//!
//! Les chemins ne sont jamais recopiés dans le texte du profil : ils sont passés en paramètres
//! (`-D P0=/chemin`), ce qui rend toute injection de règles impossible.
//!
//! Dans Seatbelt, une interdiction placée après une autorisation l'emporte : toutes les
//! interdictions sont regroupées à la fin du profil.

use crate::error::{Error, Result};
use crate::policy::{Egress, SandboxPolicy};
use crate::tr;
use std::path::{Path, PathBuf};

/// Dossiers et fichiers de secrets usuels, relatifs au dossier personnel : ni lisibles ni modifiables.
pub(crate) const HOME_SECRETS: &[&str] = &[
    ".aestheris",
    ".ssh",
    ".aws",
    ".gnupg",
    ".azure",
    ".kube",
    ".docker/config.json",
    ".config/gcloud",
    ".config/gh",
    ".netrc",
    ".git-credentials",
    ".password-store",
    ".vault-token",
    "Library/Keychains",
    // jetons des gestionnaires de paquets et des outils cloud (npm reste utilisable sans ~/.npmrc)
    ".npmrc",
    ".yarnrc.yml",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".composer/auth.json",
    ".m2/settings-security.xml",
    ".pgpass",
    ".my.cnf",
    ".terraform.d/credentials.tfrc.json",
    ".databrickscfg",
    ".boto",
    ".s3cfg",
    ".oci",
    ".fly",
    ".config/op",
    ".config/rclone",
    ".config/doctl",
    ".config/hub",
    // navigateurs : cookies et mots de passe enregistrés (vol de sessions)
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/microsoft-edge",
    // trousseau Linux
    ".local/share/keyrings",
];

/// Configuration qui s'exécute hors du bac à sable (démarrage de session, Git global) : non
/// modifiable, même si l'utilisateur autorise l'écriture dans tout son dossier personnel.
pub(crate) const HOME_WRITE_PROTECTED: &[&str] = &[
    "Library/LaunchAgents",
    ".config/git",
    ".config/fish",
    // Linux : programmes lancés à l'ouverture de session et services utilisateur
    ".config/autostart",
    ".config/systemd",
];

/// Fichiers qui déclenchent l'exécution de code plus tard, hors du bac à sable, où qu'ils soient
/// (dont `.envrc` de direnv, `.npmrc`/`.yarnrc` qui choisissent
/// l'interpréteur des scripts, variantes des fichiers de démarrage du shell).
const DANGEROUS_FILES_RE: &str = r#"/\.(bashrc|bash_profile|bash_login|bash_logout|zshrc|zprofile|zshenv|zlogin|zlogout|profile|gitconfig|gitmodules|ripgreprc|mcp\.json|envrc|npmrc|yarnrc|yarnrc\.yml)$"#;

/// Configurations MCP des agents et éditeurs : un serveur MCP
/// est une commande, lancée hors du bac à sable au prochain démarrage de Cursor, Claude, VS Code…
const MCP_CONFIGS_RE: &str = r#"/(mcp\.json|mcp_config\.json|mcp-config\.json|claude_desktop_config\.json|managed-mcp\.json|managed-settings\.json)$"#;

/// Dossiers de configuration d'éditeurs et d'agents (tâches lancées à l'ouverture, commandes).
const DANGEROUS_DIRS_RE: &str =
    r#"/(\.vscode|\.idea|\.cursor|\.claude/commands|\.claude/agents)(/|$)"#;
const AGENT_SETTINGS_RE: &str = r#"/(\.claude/settings(\.local)?\.json|\.gemini/settings\.json)$"#;

/// Dossiers qu'on ne peut pas renommer : sinon `mv .git x`, écrire `x/hooks/…`, puis `mv x .git`
/// contournerait les interdictions par motif.
const UNRENAMABLE_DIRS_RE: &str =
    r#"/(\.git|\.git/hooks|\.claude|\.claude/commands|\.claude/agents|\.vscode|\.idea|\.cursor)$"#;

/// Services Mach du trousseau macOS : jamais ouverts, rappelés explicitement.
const KEYCHAIN_SERVICES: &[&str] = &[
    "com.apple.SecurityServer",
    "com.apple.securityd",
    "com.apple.securityd.xpc",
    "com.apple.security.keychaind",
    "com.apple.secd",
    "com.apple.security.agent",
];

/// Socle du profil : processus, services système sûrs, périphériques et terminaux, sans les
/// services du trousseau. Portions adaptées de travaux sous licence Apache-2.0 (voir NOTICE).
const BASE: &str = r#"(version 1)
(deny default)

; processus : les enfants héritent du bac à sable
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))
(allow user-preference-read)

; services Mach : liste fermée (ni trousseau, ni événements Apple, ni ouverture d'applications)
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.distributed_notifications@Uv3")
  (global-name "com.apple.FontObjectsServer")
  (global-name "com.apple.fonts")
  (global-name "com.apple.logd")
  (global-name "com.apple.lsd.mapdb")
  (global-name "com.apple.PowerManagement.control")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.coreservices.launchservicesd"))

(allow ipc-posix-shm)
(allow ipc-posix-sem)
(allow iokit-open
  (iokit-registry-entry-class "IOSurfaceRootUserClient")
  (iokit-registry-entry-class "RootDomainUserClient")
  (iokit-user-client-class "IOSurfaceSendRight"))
(allow iokit-get-properties)
(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))
(allow distributed-notification-post)

; sysctl : liste fermée (pas kern.procargs : arguments des autres processus)
(allow sysctl-read
  (sysctl-name "hw.activecpu") (sysctl-name "hw.busfrequency_compat") (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cacheconfig") (sysctl-name "hw.cachelinesize_compat") (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cpufrequency") (sysctl-name "hw.cpufrequency_compat") (sysctl-name "hw.cputype")
  (sysctl-name "hw.l1dcachesize_compat") (sysctl-name "hw.l1icachesize_compat")
  (sysctl-name "hw.l2cachesize_compat") (sysctl-name "hw.l3cachesize_compat")
  (sysctl-name "hw.logicalcpu") (sysctl-name "hw.logicalcpu_max") (sysctl-name "hw.machine")
  (sysctl-name "hw.model") (sysctl-name "hw.memsize") (sysctl-name "hw.ncpu")
  (sysctl-name "hw.nperflevels") (sysctl-name "hw.packages") (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.pagesize") (sysctl-name "hw.physicalcpu") (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "hw.tbfrequency_compat") (sysctl-name "hw.vectorunit")
  (sysctl-name "kern.argmax") (sysctl-name "kern.bootargs") (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfiles") (sysctl-name "kern.maxfilesperproc") (sysctl-name "kern.maxproc")
  (sysctl-name "kern.ngroups") (sysctl-name "kern.osproductversion") (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype") (sysctl-name "kern.osvariant_status") (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel") (sysctl-name "kern.sysv.semmns") (sysctl-name "kern.tcsm_available")
  (sysctl-name "kern.tcsm_enable") (sysctl-name "kern.usrstack64") (sysctl-name "kern.version")
  (sysctl-name "kern.willshutdown") (sysctl-name "machdep.cpu.brand_string")
  (sysctl-name "machdep.ptrauth_enabled") (sysctl-name "security.mac.lockdown_mode_state")
  (sysctl-name "sysctl.proc_cputype") (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm") (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel") (sysctl-name-prefix "kern.proc.all")
  (sysctl-name-prefix "kern.proc.pgrp.") (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "machdep.cpu.") (sysctl-name-prefix "net.routetable."))
(allow sysctl-write (sysctl-name "kern.tcsm_enable") (sysctl-name "kern.grade_cputype"))

; périphériques et sorties standard
(allow file-ioctl
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom")
  (literal "/dev/dtracehelper") (literal "/dev/tty"))
(allow file-write*
  (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr") (literal "/dev/tty")
  (literal "/dev/dtracehelper") (literal "/dev/autofs_nowait") (regex #"^/dev/fd/[0-9]+$"))

; terminaux : ceux créés dans le bac à sable, et ioctl sur le terminal hérité (agents interactifs)
(allow pseudo-tty)
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow file-read* file-write*
  (require-all (regex #"^/dev/ttys[0-9]+") (extension "com.apple.sandbox.pty")))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+"))

; lecture : tout le disque, sauf les secrets interdits plus bas
(allow file-read*)
"#;

pub struct SandboxSpec<'a> {
    pub policy: &'a SandboxPolicy,
    pub egress: Egress,
    /// DNS permis malgré une sortie restreinte (`network.allow_dns`).
    pub allow_dns: bool,
    /// Port de la passerelle : seule destination réseau quand la sortie est restreinte.
    pub gateway_port: u16,
    /// Coffre, journal et politique : jamais lisibles/modifiables par l'agent.
    pub vault: &'a Path,
    pub audit: &'a Path,
    pub policy_file: &'a Path,
    /// Canaux de validation humaine : l'agent ne doit jamais pouvoir y répondre.
    pub run_dir: &'a Path,
    pub home: Option<PathBuf>,
    /// Dossier de lancement : sens de `.` dans `allow_write`.
    pub cwd: PathBuf,
    /// Dossier temporaire de l'utilisateur (`mktemp` l'utilise sur macOS, quelle que soit TMPDIR).
    pub system_tmp: Option<PathBuf>,
    /// Dossier temporaire propre à la session : TMPDIR de l'agent, seuls sockets Unix permis.
    pub session_tmp: PathBuf,
    /// Caches des gestionnaires de paquets des agents, séparés de ceux de l'utilisateur.
    pub agent_cache: Option<PathBuf>,
}

/// Profil prêt pour `sandbox-exec` : texte des règles et valeurs des paramètres (`-D`).
#[derive(Debug)]
pub struct Profile {
    pub text: String,
    pub params: Vec<(String, String)>,
}

/// Le bac à sable est-il disponible sur ce système ?
pub fn available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists()
}

/// Construit le profil Seatbelt.
pub fn seatbelt_profile(spec: &SandboxSpec) -> Result<Profile> {
    let home = spec.home.as_deref();
    let mut b = Builder::default();
    b.text.push_str(BASE);

    // --- écriture : dossiers autorisés et dossiers temporaires
    let mut writable: Vec<PathBuf> = Vec::new();
    for p in &spec.policy.allow_write {
        writable.push(resolve(p, home, &spec.cwd, "sandbox.allow_write")?);
    }
    writable.extend(spec.system_tmp.iter().cloned());
    writable.push(spec.session_tmp.clone());
    writable.extend(spec.agent_cache.iter().cloned());
    b.text
        .push_str("\n; écriture : dossiers autorisés et dossiers temporaires\n");
    b.rule("(allow file-write*", "subpath", &writable)?;

    // --- réseau
    b.text.push_str("\n; réseau\n");
    if spec.egress == Egress::Open {
        b.text
            .push_str("(allow network-outbound (remote ip \"*:*\"))\n");
        b.text
            .push_str("(allow network-bind network-inbound (local ip \"*:*\"))\n");
    } else {
        b.text.push_str(&format!(
            "(allow network-outbound (remote ip \"localhost:{}\"))\n",
            spec.gateway_port
        ));
        if spec.policy.allow_local_binding {
            b.text
                .push_str("(allow network-bind network-inbound (local ip \"*:*\"))\n");
            b.text
                .push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        }
    }
    if spec.egress == Egress::Open || spec.allow_dns {
        b.text
            .push_str("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n");
    }
    // Sockets Unix : création permise, connexion seulement vers les chemins listés.
    b.text
        .push_str("(allow system-socket (socket-domain AF_UNIX))\n");
    let mut sockets = vec![spec.session_tmp.clone()];
    for s in &spec.policy.allow_unix_sockets {
        sockets.push(resolve(s, home, &spec.cwd, "sandbox.allow_unix_sockets")?);
    }
    b.rule(
        "(allow network-bind",
        "local unix-socket (subpath",
        &sockets,
    )?;
    b.rule(
        "(allow network-outbound",
        "remote unix-socket (subpath",
        &sockets,
    )?;

    // --- interdictions, en dernier pour l'emporter
    let mut deny_rw: Vec<PathBuf> = Vec::new();
    if let Some(h) = home {
        deny_rw.extend(HOME_SECRETS.iter().map(|rel| h.join(rel)));
    }
    // Le fichier du coffre lui-même (son dossier par défaut, ~/.aestheris, est déjà couvert) ;
    // on n'interdit pas son dossier parent, qui pourrait être le dossier personnel entier.
    deny_rw.push(spec.vault.to_path_buf());
    deny_rw.push(spec.run_dir.to_path_buf());
    for p in &spec.policy.protect_paths {
        deny_rw.push(expand_home(p, home)?);
    }
    b.text
        .push_str("\n; secrets sur disque : illisibles et non modifiables\n");
    b.rule("(deny file-read* file-write*", "subpath", &deny_rw)?;
    if spec.policy.deny_dotenv {
        b.text
            .push_str("(deny file-read* file-write* (regex #\"/\\.env(\\.[^/]*)?$\"))\n");
    }

    b.text.push_str("; journal d'audit et politique : l'agent ne peut ni effacer ses traces ni s'accorder des droits\n");
    b.rule(
        "(deny file-write*",
        "literal",
        &[spec.audit.to_path_buf(), spec.policy_file.to_path_buf()],
    )?;

    b.text
        .push_str("; fichiers exécutés plus tard hors du bac à sable\n");
    if let Some(h) = home {
        let protected: Vec<PathBuf> = HOME_WRITE_PROTECTED.iter().map(|rel| h.join(rel)).collect();
        b.rule("(deny file-write*", "subpath", &protected)?;
    }
    for re in [
        DANGEROUS_FILES_RE,
        MCP_CONFIGS_RE,
        DANGEROUS_DIRS_RE,
        AGENT_SETTINGS_RE,
    ] {
        b.text
            .push_str(&format!("(deny file-write* (regex #\"{re}\"))\n"));
    }
    // Hooks Git : seuls les modèles `.sample` (créés par `git init`) restent possibles.
    b.text.push_str(
        "(deny file-write* (require-all (regex #\"/\\.git/hooks/.\") (require-not (regex #\"\\.sample$\"))))\n",
    );
    if !spec.policy.allow_git_config {
        b.text
            .push_str("(deny file-write* (regex #\"/\\.git/config$\"))\n");
    }
    b.text.push_str(&format!(
        "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (regex #\"{UNRENAMABLE_DIRS_RE}\")))\n"
    ));
    // Renommer un dossier parent déplacerait un secret hors de son interdiction.
    let ancestors: Vec<PathBuf> = deny_rw
        .iter()
        .flat_map(|p| variants(p))
        .flat_map(|p| {
            p.ancestors()
                .skip(1)
                .map(Path::to_path_buf)
                .collect::<Vec<_>>()
        })
        .filter(|a| a.parent().is_some())
        .collect();
    b.text.push_str("; parents des secrets : non renommables\n");
    b.rule(
        "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (require-any",
        "literal",
        &ancestors,
    )?;

    b.text.push_str("; trousseau macOS\n");
    for svc in KEYCHAIN_SERVICES {
        b.text
            .push_str(&format!("(deny mach-lookup (global-name \"{svc}\"))\n"));
    }
    // Ces fcntl modifient un fichier par un descripteur en lecture seule.
    b.text
        .push_str("(deny system-fcntl (fcntl-command 80 110))\n");
    Ok(b.finish())
}

/// Commande enveloppée dans le bac à sable.
pub fn wrap(program: &str, args: &[String], profile: &Profile) -> Result<tokio::process::Command> {
    if !available() {
        return Err(Error::Policy(
            tr!(
                "bac à sable demandé mais indisponible sur ce système (macOS requis pour l'instant) : \
                 lancement refusé plutôt que sans protection",
                "sandbox requested but unavailable on this system (macOS required for now): \
                 refusing to start rather than run unprotected"
            )
            .into(),
        ));
    }
    let mut cmd = tokio::process::Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(&profile.text);
    for (k, v) in &profile.params {
        cmd.arg(format!("-D{k}={v}"));
    }
    cmd.arg("--").arg(program).args(args);
    Ok(cmd)
}

/// Accumule les règles et leurs paramètres `P0`, `P1`… (un paramètre par chemin distinct).
#[derive(Default)]
struct Builder {
    text: String,
    params: Vec<(String, String)>,
}

impl Builder {
    /// `(allow file-write* (subpath (param "P0")) …)` pour chaque chemin et sa forme résolue.
    /// `head` et `filter` peuvent ouvrir des parenthèses supplémentaires : elles sont refermées.
    fn rule(&mut self, head: &str, filter: &str, paths: &[PathBuf]) -> Result<()> {
        let paths = dedup(paths.iter().flat_map(|p| variants(p)));
        if paths.is_empty() {
            return Ok(());
        }
        let unclosed = |s: &str| s.matches('(').count() - s.matches(')').count();
        let inner_close = ")".repeat(unclosed(filter));
        let head_close = ")".repeat(unclosed(head));
        let mut line = String::from(head);
        for p in &paths {
            let key = self.param(p)?;
            line.push_str(&format!(" ({filter} (param \"{key}\"){inner_close})"));
        }
        line.push_str(&head_close);
        line.push('\n');
        self.text.push_str(&line);
        Ok(())
    }

    fn param(&mut self, path: &Path) -> Result<String> {
        let value = path.to_str().ok_or_else(|| {
            Error::Policy(tr!(fmt "chemin non UTF-8 : {}", "non-UTF-8 path: {}", path.display()))
        })?;
        if value.chars().any(|c| c.is_control()) {
            return Err(Error::Policy(tr!(fmt
                "caractère de contrôle dans un chemin : {value:?}", "control character in a path: {value:?}"
            )));
        }
        if let Some((k, _)) = self.params.iter().find(|(_, v)| v == value) {
            return Ok(k.clone());
        }
        let key = format!("P{}", self.params.len());
        self.params.push((key.clone(), value.to_string()));
        Ok(key)
    }

    fn finish(self) -> Profile {
        Profile {
            text: self.text,
            params: self.params,
        }
    }
}

/// `~/x` → dossier personnel ; chemin absolu tel quel ; sinon refus.
pub(crate) fn expand_home(p: &str, home: Option<&Path>) -> Result<PathBuf> {
    let path = match (p.strip_prefix("~/"), home) {
        (Some(rest), Some(h)) => h.join(rest),
        (None, Some(h)) if p == "~" => h.to_path_buf(),
        _ => PathBuf::from(p),
    };
    if !path.is_absolute() {
        return Err(Error::Policy(tr!(fmt
            "sandbox.protect_paths : chemin absolu ou ~/… attendu : {p}", "sandbox.protect_paths: absolute or ~/… path expected: {p}"
        )));
    }
    Ok(path)
}

/// Comme `expand_home`, mais un chemin relatif (dont `.`) part du dossier de lancement.
pub(crate) fn resolve(p: &str, home: Option<&Path>, cwd: &Path, field: &str) -> Result<PathBuf> {
    if p.starts_with('~') {
        return expand_home(p, home).map_err(|_| {
            Error::Policy(tr!(fmt "{field} : chemin invalide : {p}", "{field}: invalid path: {p}"))
        });
    }
    let path = Path::new(p);
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    // `.` et `..` littéraux : on normalise sans suivre de lien (la forme résolue est ajoutée ensuite).
    let mut out = PathBuf::new();
    for c in full.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Seatbelt compare des chemins réels : `/var` et `/tmp` sont des liens vers `/private/…`.
/// On couvre à la fois le chemin donné et sa forme résolue.
fn variants(path: &Path) -> Vec<PathBuf> {
    let mut out = vec![path.to_path_buf()];
    if let Ok(real) = std::fs::canonicalize(path) {
        out.push(real);
    } else if let Some(parent) = path.parent()
        && let (Ok(real_parent), Some(name)) = (std::fs::canonicalize(parent), path.file_name())
    {
        out.push(real_parent.join(name));
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(protect: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            deny_dotenv: true,
            protect_paths: protect.iter().map(|s| s.to_string()).collect(),
            allow_write: vec![".".into()],
            ..Default::default()
        }
    }

    fn spec<'a>(sp: &'a SandboxPolicy, egress: Egress) -> SandboxSpec<'a> {
        SandboxSpec {
            policy: sp,
            egress,
            allow_dns: false,
            gateway_port: 51234,
            vault: Path::new("/Users/demo/.aestheris/vault.json"),
            audit: Path::new("/Users/demo/.aestheris/audit.ndjson"),
            policy_file: Path::new("/Users/demo/projet/aestheris.yaml"),
            run_dir: Path::new("/Users/demo/.aestheris/run"),
            home: Some(PathBuf::from("/Users/demo")),
            cwd: PathBuf::from("/Users/demo/projet"),
            system_tmp: None,
            session_tmp: PathBuf::from("/Users/demo/tmp-session"),
            agent_cache: None,
        }
    }

    /// Texte du profil avec les paramètres remplacés par leurs valeurs (pour les assertions).
    fn expanded(p: &Profile) -> String {
        let mut t = p.text.clone();
        for (k, v) in p.params.iter().rev() {
            t = t.replace(&format!("(param \"{k}\")"), &format!("\"{v}\""));
        }
        t
    }

    #[test]
    fn tout_est_interdit_sauf_le_necessaire() {
        let sp = policy(&["~/clients"]);
        let p = seatbelt_profile(&spec(&sp, Egress::Allowlist)).unwrap();
        let t = expanded(&p);
        assert!(t.starts_with("(version 1)\n(deny default)"));
        // ni événements Apple, ni ouverture d'applications, ni trousseau
        assert!(!t.contains("(allow appleevent-send"));
        assert!(!t.contains("(allow lsopen"));
        assert!(!t.contains("(allow mach-lookup (global-name \"com.apple.SecurityServer\")"));
        // écriture : dossier de lancement et temporaire de session seulement
        assert!(t.contains(
            "(allow file-write* (subpath \"/Users/demo/projet\") (subpath \"/Users/demo/tmp-session\"))"
        ));
        // secrets et chemins protégés, en fin de profil
        let deny = t
            .find("(deny file-read* file-write* (subpath \"/Users/demo/.aestheris\")")
            .unwrap();
        assert!(deny > t.find("(allow file-read*)").unwrap());
        assert!(
            t[deny..]
                .lines()
                .next()
                .unwrap()
                .contains("(subpath \"/Users/demo/.ssh\")")
        );
        assert!(t.contains("(subpath \"/Users/demo/clients\")"));
        assert!(t.contains("(deny file-write* (literal \"/Users/demo/.aestheris/audit.ndjson\") (literal \"/Users/demo/projet/aestheris.yaml\"))"));
        assert!(t.contains("\\.env"));
        assert!(t.contains("zshrc") && t.contains("\\.git/hooks") && t.contains("\\.vscode"));
        assert!(t.contains("claude_desktop_config") && t.contains("mcp_config"));
        assert!(t.contains("(deny file-write* (regex #\"/\\.git/config$\"))"));
        assert!(t.contains("(subpath \"/Users/demo/Library/LaunchAgents\")"));
        // parents des secrets non renommables
        assert!(t.contains("(literal \"/Users/demo\")"));
    }

    #[test]
    fn reseau_restreint_a_la_passerelle() {
        let sp = policy(&[]);
        let t = expanded(&seatbelt_profile(&spec(&sp, Egress::None)).unwrap());
        assert!(t.contains("(allow network-outbound (remote ip \"localhost:51234\"))"));
        assert!(
            !t.contains("localhost:*"),
            "les autres services locaux doivent rester fermés"
        );
        assert!(
            !t.contains("mDNSResponder"),
            "DNS fermé par défaut quand la sortie est restreinte"
        );
        assert!(!t.contains("(remote ip \"*:*\")"));
        // sockets Unix : seulement le dossier de la session
        assert!(t.contains(
            "(allow network-outbound (remote unix-socket (subpath \"/Users/demo/tmp-session\")))"
        ));
    }

    #[test]
    fn reseau_ouvert_mais_sockets_unix_fermes() {
        let mut sp = policy(&[]);
        sp.allow_git_config = true;
        let t = expanded(&seatbelt_profile(&spec(&sp, Egress::Open)).unwrap());
        assert!(t.contains("(allow network-outbound (remote ip \"*:*\"))"));
        assert!(t.contains("mDNSResponder"));
        assert!(!t.contains("docker.sock"));
        assert!(!t.contains("/\\.git/config$"));
    }

    #[test]
    fn chemins_passes_en_parametres_jamais_dans_le_texte() {
        let sp = policy(&["/tmp/a\")\n(allow default"]);
        assert!(seatbelt_profile(&spec(&sp, Egress::Open)).is_err());
        let sp = policy(&["relatif"]);
        assert!(seatbelt_profile(&spec(&sp, Egress::Open)).is_err());
        // un guillemet dans un chemin ne peut plus fermer la chaîne : il reste dans le paramètre
        let sp = policy(&["/tmp/a\")(allow default"]);
        let p = seatbelt_profile(&spec(&sp, Egress::Open)).unwrap();
        assert!(!p.text.contains("/tmp/a"));
        assert!(p.params.iter().any(|(_, v)| v == "/tmp/a\")(allow default"));
    }
}
