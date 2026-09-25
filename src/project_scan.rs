//! `aestheris scan` : en quelques secondes, sans coffre ni mot de passe, ce que les agents d'IA
//! peuvent lire dans un projet et ce qui est déjà publié ou sur le point de l'être.
//!
//! Constats classés par gravité :
//! - **critique** (publié ou publiable) : secret dans une variable intégrée au code des
//!   navigateurs (`NEXT_PUBLIC_`, `VITE_`…), dans un fichier suivi par git, dans un `.env` que git
//!   n'ignore pas ; la clé `service_role` de Supabase est reconnue (la clé `anon`, publique par
//!   conception, est ignorée) ;
//! - **élevé** (lisible par les agents) : secret dans les fichiers du projet, jeton en clair dans
//!   une configuration MCP (projet et dossier personnel), `.env` suivi par git ;
//! - **moyen** : réglages d'agent qui retirent les garde-fous, clés Google publiques par conception.
//!
//! S'y ajoute l'inventaire des emplacements de secrets du dossier personnel (`~/.ssh`, `~/.aws`…),
//! lisibles par tout programme lancé sous le compte de l'utilisateur, et que `aestheris run` rend
//! illisibles (même liste que le bac à sable).
//!
//! Aucune valeur n'est jamais affichée ni écrite : type de secret, fichier, ligne, nom de variable.
//! Une ligne qui contient `aestheris:allow` (ou `gitleaks:allow`) est ignorée, comme les chemins
//! listés dans `.aestheris-ignore` (un motif par ligne) et ceux passés à `--exclude`. Git est appelé
//! avec `core.fsmonitor` désactivé : un dépôt piégé ne peut pas lui faire exécuter une commande.

use crate::error::{Error, Result};
use crate::scan;
use crate::tr;
use base64::Engine as _;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Dépendances, caches et sorties de compilation : volumineux, sans intérêt pour l'analyse.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    ".gradle",
    ".terraform",
    ".yarn",
    ".pnpm-store",
    "Pods",
];
const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "Cargo.lock",
    "poetry.lock",
    "uv.lock",
    "composer.lock",
    "Gemfile.lock",
    "go.sum",
];
const MAX_FILES: usize = 50_000;
/// Motifs de chemins à ignorer, propres au projet.
pub const IGNORE_FILE: &str = ".aestheris-ignore";
const MAX_SIZE: u64 = 2 << 20;

/// Configurations d'agents et de serveurs MCP du projet, analysées clé par clé.
const PROJECT_CONFIGS: &[&str] = &[
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    ".codex/config.toml",
    ".claude/settings.json",
    ".claude/settings.local.json",
];
/// Les mêmes dans le dossier personnel (Claude Code, Claude Desktop, Cursor, Windsurf, Gemini,
/// Codex, VS Code).
const HOME_CONFIGS: &[&str] = &[
    ".claude.json",
    ".claude/settings.json",
    ".cursor/mcp.json",
    ".codeium/windsurf/mcp_config.json",
    ".gemini/settings.json",
    ".codex/config.toml",
    "Library/Application Support/Claude/claude_desktop_config.json",
    ".config/Claude/claude_desktop_config.json",
    "Library/Application Support/Code/User/mcp.json",
    ".config/Code/User/mcp.json",
];

/// Préfixes que les outils de compilation intègrent au code envoyé aux navigateurs.
const PUBLIC_PREFIXES: &[&str] = &[
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
    "NUXT_PUBLIC_",
    "PUBLIC_",
    "GATSBY_",
    "VUE_APP_",
    "STORYBOOK_",
];
/// Clés publiques par conception (Firebase, Maps) : à restreindre, pas à cacher.
const PUBLIC_BY_DESIGN: &[&str] = &["GOOGLE_API_KEY"];
const PROBABLE: &str = "SECRET_PROBABLE";
/// Constats affichés par catégorie en mode texte (tous en JSON).
const MAX_LISTED: usize = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    #[serde(rename = "critical")]
    Critique,
    #[serde(rename = "high")]
    Eleve,
    #[serde(rename = "medium")]
    Moyen,
}

/// Où se trouve le problème ; l'ordre est celui de l'affichage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PublicVariable,
    GitTracked,
    EnvNotIgnored,
    AgentReadable,
    McpPlaintext,
    EnvTracked,
    AgentSettings,
    PublicByDesign,
}

impl Category {
    fn title(self) -> &'static str {
        match self {
            Self::PublicVariable => tr!(
                "Variables publiques : intégrées au code envoyé à chaque navigateur",
                "Public variables: bundled into the code sent to every browser"
            ),
            Self::GitTracked => tr!(
                "Fichiers suivis par git : le secret part avec chaque commit et reste dans l'historique",
                "Git-tracked files: the secret ships with every commit and stays in the history"
            ),
            Self::EnvNotIgnored => tr!(
                "Fichiers .env que git n'ignore pas : un « git add . » les publiera",
                ".env files git does not ignore: a `git add .` will publish them"
            ),
            Self::AgentReadable => tr!(
                "Secrets lisibles par les agents",
                "Secrets your agents can read"
            ),
            Self::McpPlaintext => tr!(
                "Jetons en clair dans les configurations MCP : lisibles par tout agent et tout programme",
                "Plaintext tokens in MCP configs: readable by any agent and any program"
            ),
            Self::EnvTracked => tr!("Fichiers .env suivis par git", "Git-tracked .env files"),
            Self::AgentSettings => tr!(
                "Réglages d'agent sans garde-fou",
                "Agent settings without safeguards"
            ),
            Self::PublicByDesign => tr!(
                "Clés Google (Firebase, Maps) : publiques par conception",
                "Google keys (Firebase, Maps): public by design"
            ),
        }
    }

    fn advice(self) -> &'static str {
        match self {
            Self::PublicVariable => tr!(
                "révoquer la clé, puis la garder côté serveur (nom sans préfixe NEXT_PUBLIC_, VITE_…)",
                "revoke the key, then keep it server-side (a name without NEXT_PUBLIC_, VITE_… prefix)"
            ),
            Self::GitTracked => tr!(
                "révoquer la clé (l'historique garde l'ancienne valeur), puis la retirer du fichier",
                "revoke the key (the history keeps the old value), then remove it from the file"
            ),
            Self::EnvNotIgnored => tr!(
                "ajouter .env* à .gitignore (en gardant .env.example)",
                "add .env* to .gitignore (keeping .env.example)"
            ),
            Self::AgentReadable => tr!(
                "les mettre au coffre (aestheris init, aestheris vault set …) : l'agent ne reçoit qu'un \
                 jeton fantôme. Dans aestheris run, les .env sont illisibles ; une clé écrite dans le \
                 code reste lisible : la retirer du code",
                "move them to the vault (aestheris init, aestheris vault set …): the agent only gets a \
                 phantom token. Under aestheris run, .env files are unreadable; a key written in the \
                 code stays readable: remove it from the code"
            ),
            Self::McpPlaintext => tr!(
                "remplacer la valeur par une variable d'environnement (${NOM} ou ${env:NOM} selon \
                 l'outil) et révoquer le jeton s'il a circulé",
                "replace the value with an environment variable (${NAME} or ${env:NAME} depending on \
                 the tool) and revoke the token if it has been shared"
            ),
            Self::EnvTracked => tr!(
                "git rm --cached <fichier>, l'ajouter à .gitignore, révoquer son contenu",
                "git rm --cached <file>, add it to .gitignore, revoke what it contained"
            ),
            Self::AgentSettings => tr!(
                "revenir aux validations par défaut, ou lancer l'agent dans aestheris run (bac à \
                 sable, politique et validations hors de l'agent)",
                "go back to the default approvals, or run the agent under aestheris run (sandbox, \
                 policy and approvals outside the agent)"
            ),
            Self::PublicByDesign => tr!(
                "vérifier qu'elles sont restreintes (domaines, API autorisées) dans la console Google Cloud",
                "check they are restricted (domains, allowed APIs) in the Google Cloud console"
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    /// Chemin relatif au projet, ou `~/…` dans le dossier personnel.
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Variable, serveur MCP ou réglage concerné (jamais la valeur).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kinds: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub root: String,
    pub files_scanned: usize,
    pub truncated: bool,
    pub git: bool,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    /// Emplacements de secrets du dossier personnel lisibles hors d'Aestheris.
    pub home_exposure: Vec<String>,
}

pub struct Options {
    pub root: PathBuf,
    /// Dossier personnel à inspecter (`None` : projet seul, par exemple en CI).
    pub home: Option<PathBuf>,
    /// Motifs de chemins à ignorer (`tests/**`).
    pub excludes: Vec<String>,
}

pub fn scan(opts: &Options) -> Result<Report> {
    let root = std::fs::canonicalize(&opts.root)?;
    let mut globs = GlobSetBuilder::new();
    // `.aestheris-ignore` : un motif par ligne (`#` pour les commentaires), versionné avec le projet.
    let ignored: Vec<String> = std::fs::read_to_string(root.join(IGNORE_FILE))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    for p in opts.excludes.iter().chain(&ignored) {
        globs.add(Glob::new(p).map_err(|e| {
            Error::Scan(tr!(fmt "motif --exclude « {p} » : {e}", "--exclude pattern “{p}”: {e}"))
        })?);
    }
    let excludes = globs
        .build()
        .map_err(|e| Error::Scan(tr!(fmt "motifs --exclude : {e}", "--exclude patterns: {e}")))?;
    let git = git_state(&root);
    let (files, truncated) = walk(&root, &excludes);

    let mut findings = Vec::new();
    for rel in &files {
        let Some(text) = read_text(&root.join(rel)) else {
            continue;
        };
        let tracked = git.as_ref().is_some_and(|g| g.tracked.contains(rel));
        if PROJECT_CONFIGS.contains(&rel.as_str()) {
            config_findings(rel, &text, tracked, &mut findings);
            continue;
        }
        let unignored = git.as_ref().is_some_and(|g| g.others.contains(rel));
        file_findings(rel, &text, tracked, unignored, &mut findings);
    }

    let mut home_exposure = Vec::new();
    if let Some(home) = opts
        .home
        .as_ref()
        .and_then(|h| std::fs::canonicalize(h).ok())
    {
        for rel in HOME_CONFIGS {
            let path = home.join(rel);
            if path.starts_with(&root) {
                continue; // déjà vu comme fichier du projet
            }
            if let Some(text) = read_text(&path) {
                config_findings(&format!("~/{rel}"), &text, false, &mut findings);
            }
        }
        home_exposure = crate::sandbox::HOME_SECRETS
            .iter()
            .filter(|rel| **rel != ".aestheris" && home.join(rel).exists())
            .map(|rel| format!("~/{rel}"))
            .collect();
    }

    findings.sort_by(|a, b| {
        (a.severity, a.category, &a.file, a.line).cmp(&(b.severity, b.category, &b.file, b.line))
    });
    let mut summary = Summary::default();
    for f in &findings {
        match f.severity {
            Severity::Critique => summary.critical += 1,
            Severity::Eleve => summary.high += 1,
            Severity::Moyen => summary.medium += 1,
        }
    }
    Ok(Report {
        root: root.display().to_string(),
        files_scanned: files.len(),
        truncated,
        git: git.is_some(),
        summary,
        findings,
        home_exposure,
    })
}

// ---------------------------------------------------------------------------------------------
// Fichiers du projet

fn walk(root: &Path, excludes: &GlobSet) -> (Vec<String>, bool) {
    let mut files = Vec::new();
    let mut truncated = false;
    let mut stack = vec![(root.to_path_buf(), String::new())];
    'outer: while let Some((dir, rel)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            // file_type ne suit pas les liens symboliques : ils sont ignorés.
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            let child = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if excludes.is_match(&child) {
                continue;
            }
            if ft.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push((e.path(), child));
                }
            } else if ft.is_file() && !SKIP_FILES.contains(&name.as_str()) {
                if files.len() >= MAX_FILES {
                    truncated = true;
                    break 'outer;
                }
                files.push(child);
            }
        }
    }
    files.sort();
    (files, truncated)
}

/// Contenu texte d'un fichier raisonnable (ni trop gros, ni binaire).
fn read_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SIZE {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.iter().take(8000).any(|b| *b == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn is_env_file(base: &str) -> bool {
    base == ".env" || base.starts_with(".env.") || base.ends_with(".env") || base == ".envrc"
}

fn is_example(base: &str) -> bool {
    let b = base.to_ascii_lowercase();
    ["example", "sample", "template", ".dist", "defaults"]
        .iter()
        .any(|w| b.contains(w))
}

fn file_findings(rel: &str, text: &str, tracked: bool, unignored: bool, out: &mut Vec<Finding>) {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let env = is_env_file(base);
    // Tri rapide : le fichier entier d'abord, ligne par ligne seulement s'il contient quelque chose.
    if !env && scan::detect(text).is_empty() {
        return;
    }
    let example = is_example(base);
    let before = out.len();
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().copied().enumerate() {
        if line.contains("aestheris:allow") || line.contains("gitleaks:allow") {
            continue;
        }
        let assign = if env { env_assignment(line) } else { None };
        let mut kinds = detect_in(line, lines.get(i + 1).copied());
        // Un fichier d'exemple contient des valeurs factices : seuls les formats reconnus comptent.
        if kinds.is_empty()
            && !example
            && let Some((name, value)) = assign
            && secret_name(name)
            && literal_secret(value)
        {
            kinds.push(PROBABLE.into());
        }
        if kinds.is_empty() {
            continue;
        }
        let public = assign.is_some_and(|(n, _)| PUBLIC_PREFIXES.iter().any(|p| n.starts_with(p)));
        let (severity, category) = if kinds.iter().all(|k| PUBLIC_BY_DESIGN.contains(&k.as_str())) {
            (Severity::Moyen, Category::PublicByDesign)
        } else if public {
            (Severity::Critique, Category::PublicVariable)
        } else if tracked {
            (Severity::Critique, Category::GitTracked)
        } else if env && unignored {
            (Severity::Critique, Category::EnvNotIgnored)
        } else {
            (Severity::Eleve, Category::AgentReadable)
        };
        out.push(Finding {
            severity,
            category,
            file: rel.to_string(),
            line: Some(i + 1),
            name: assign
                .map(|(n, _)| n.to_string())
                .or_else(|| name_hint(line)),
            kinds,
        });
    }
    if env && tracked && !example && out.len() == before {
        out.push(Finding {
            severity: Severity::Eleve,
            category: Category::EnvTracked,
            file: rel.to_string(),
            line: None,
            name: None,
            kinds: Vec::new(),
        });
    }
}

/// `NOM=valeur` (avec `export`, guillemets) dans un fichier .env.
fn env_assignment(line: &str) -> Option<(&str, &str)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$"#)
            .expect("motif")
    });
    let c = re.captures(line)?;
    let value = c.get(2)?.as_str();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
    Some((c.get(1)?.as_str(), value))
}

/// Nom de variable ou de clé en tête de ligne (`const X =`, `"x":`, `x:`), pour situer le constat.
fn name_hint(line: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]"#,
        )
        .expect("motif")
    })
    .captures(line)
    .map(|c| c[1].to_string())
}

/// Nom qui annonce un secret (`STRIPE_SECRET`, `DB_PASSWORD`, `API_KEY`…).
fn secret_name(name: &str) -> bool {
    static YES: OnceLock<Regex> = OnceLock::new();
    static NO: OnceLock<Regex> = OnceLock::new();
    let yes = YES.get_or_init(|| {
        Regex::new(
            r"(?i)(SECRET|PASSWORD|PASSWD|_PASS$|_PWD$|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|SERVICE_?ROLE|AUTHORIZATION|(^|_)PAT$)",
        )
        .expect("motif")
    });
    let no = NO.get_or_init(|| {
        Regex::new(
            r"(?i)(_URL|_URI|_ENDPOINT|_PATH|_FILE|_DIR|_ID|_NAME|_HOST|_PORT|_EXPIRES?(_IN|_AT)?|_EXPIRY|_TTL|_TYPE|_LENGTH)$",
        )
        .expect("motif")
    });
    yes.is_match(name) && !no.is_match(name)
}

/// Valeur écrite en dur (pas une référence, un exemple, un jeton fantôme ni une clé publique).
fn literal_secret(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 8 || v.contains(char::is_whitespace) && !v.starts_with("Bearer ") {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    let references = ["${", "{{", "$(", "op://", "vault:", "env:", "secret:"];
    let public = ["aes_ph_", "eyj", "pk_", "sb_publishable_"];
    let placeholders = [
        "your",
        "xxx",
        "changeme",
        "change_me",
        "example",
        "placeholder",
        "replace",
        "todo",
        "<",
        "insert",
        "dummy",
        "redacted",
        "****",
        "...",
        "password",
        "passwd",
        "secret",
        "token",
        "test",
        "fake",
        "mock",
        "sample",
    ];
    if v.starts_with('$')
        || references.iter().any(|r| lower.contains(r))
        || public.iter().any(|p| lower.starts_with(p))
        || placeholders.iter().any(|p| lower.contains(p))
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || v.chars().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    let first = v.chars().next();
    !v.chars().all(|c| Some(c) == first)
}

fn detect_str(s: &str) -> Vec<String> {
    detect_in(s, None)
}

/// Détection de secrets, JWT de Supabase compris (la clé `anon` est publique par conception, la
/// clé `service_role` donne tous les droits sur la base), puis tri des exemples de documentation.
/// `next` : ligne suivante (corps d'une clé privée).
fn detect_in(s: &str, next: Option<&str>) -> Vec<String> {
    let mut kinds: Vec<String> = scan::detect(s).into_iter().map(String::from).collect();
    if kinds.iter().any(|k| k == "JWT") {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"eyJ[A-Za-z0-9_\-]{10,}\.(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-]{10,}")
                .expect("motif")
        });
        let roles: Vec<Option<String>> = re.captures_iter(s).map(|c| jwt_role(&c[1])).collect();
        if roles.iter().any(|r| r.as_deref() == Some("service_role")) {
            for k in kinds.iter_mut().filter(|k| *k == "JWT") {
                *k = "SUPABASE_SERVICE_ROLE".into();
            }
        } else if !roles.is_empty() && roles.iter().all(|r| r.as_deref() == Some("anon")) {
            kinds.retain(|k| k != "JWT");
        }
    }
    if kinds.is_empty() {
        return kinds;
    }
    // Un type reconnu par nos motifs n'est gardé que si l'une de ses valeurs est vraisemblable.
    let found = scan::pattern_matches(s);
    kinds.retain(|k| {
        let kind = if k == "SUPABASE_SERVICE_ROLE" {
            "JWT"
        } else {
            k.as_str()
        };
        let mut values = found.iter().filter(|(fk, _)| *fk == kind).peekable();
        values.peek().is_none() || values.any(|(fk, r)| plausible(fk, s, r.clone(), next))
    });
    kinds
}

/// Valeur réelle plutôt qu'exemple : `AKIA…EXAMPLE`, `postgres://user:pass@`, `sk-test-mock-key`,
/// en-tête `BEGIN PRIVATE KEY` sans clé derrière, JWT à la signature factice.
fn plausible(kind: &str, text: &str, r: std::ops::Range<usize>, next: Option<&str>) -> bool {
    let value = &text[r.clone()];
    match kind {
        "AWS_ACCESS_KEY" => {
            // clé de la documentation d'AWS, ou fragment d'un bloc base64
            let before = text[..r.start].chars().next_back();
            let after = text[r.end..].chars().next();
            // identifiant factice, fragment de base64, ou identifiant d'une URL présignée
            // (X-Amz-Credential=ASIA…%2F… : sans le secret, qui n'y figure jamais)
            !["EXAMPLE", "FAKE", "TEST", "DUMMY", "SAMPLE", "XXXX"]
                .iter()
                .any(|w| value.contains(w))
                && !matches!(before, Some('+' | '/' | '='))
                && !matches!(after, Some('+' | '/' | '=' | '%'))
        }
        "DATABASE_URL_WITH_PASSWORD" => db_password_plausible(value),
        "PRIVATE_KEY" => key_body_follows(&text[r.end..], next),
        "JWT" => value.rsplit('.').next().is_some_and(|sig| sig.len() >= 32),
        "OPENAI_API_KEY" if value.starts_with("sk-ant-") => false,
        _ => random_body(value),
    }
}

/// Corps aléatoire (après le préfixe du fournisseur) : majuscules, minuscules et chiffres, sans
/// mot d'exemple ni suite évidente.
fn random_body(value: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "sk-ant-api03-",
        "sk-ant-admin01-",
        "sk-ant-oat01-",
        "sk-ant-",
        "sk-proj-",
        "sk-svcacct-",
        "sk-admin-",
        "sk-",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "rk_test_",
        "xoxa-",
        "xoxb-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "sb_secret_",
        "AIza",
    ];
    let body = PREFIXES
        .iter()
        .find_map(|p| value.strip_prefix(p))
        .unwrap_or(value);
    let lower = body.to_ascii_lowercase();
    let words = [
        "example",
        "test",
        "fake",
        "dummy",
        "mock",
        "sample",
        "your",
        "xxxx",
        "abcdef",
        "123456",
        "qwerty",
        "placeholder",
        "redacted",
        "should",
        "secret",
        "leak",
    ];
    body.chars().any(|c| c.is_ascii_uppercase())
        && body.chars().any(|c| c.is_ascii_lowercase())
        && body.chars().any(|c| c.is_ascii_digit())
        && !words.iter().any(|w| lower.contains(w))
}

fn db_password_plausible(url: &str) -> bool {
    let Some((user, password)) = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once(':'))
        .map(|(u, p)| (u, p.trim_end_matches('@')))
    else {
        return true;
    };
    // « s3cr3t », « p@ssw0rd » : les mêmes exemples, déguisés
    let lower: String = password
        .to_ascii_lowercase()
        .chars()
        .map(|c| match c {
            '3' => 'e',
            '0' => 'o',
            '1' => 'i',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            c => c,
        })
        .collect();
    let common = [
        "postgres", "root", "admin", "test", "guest", "user", "pass", "dev", "local", "mysql",
        "redis", "mongo", "rabbit", "pw", "password", "passwd", "secret", "changeme",
    ];
    password.len() >= 6
        && password != user
        && !password.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && !password.contains(['{', '}', '$', '<', '>', '*', '[', ']'])
        && !password.contains("%s")
        && !common.contains(&lower.as_str())
        && ![
            "password",
            "changeme",
            "example",
            "placeholder",
            "redacted",
            "secret",
            "xxx",
        ]
        .iter()
        .any(|w| lower.contains(w))
}

/// Une vraie clé privée : l'en-tête est suivi de son contenu base64 (même texte ou ligne suivante).
fn key_body_follows(rest: &str, next: Option<&str>) -> bool {
    let mut rest = rest;
    loop {
        let t = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        let t = t.strip_prefix("\\n").unwrap_or(t);
        if t.len() == rest.len() {
            break;
        }
        rest = t;
    }
    let body = if rest.is_empty() {
        next.unwrap_or("").trim()
    } else {
        rest
    };
    body.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .count()
        >= 40
}

fn jwt_role(payload: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("role")?.as_str().map(str::to_string)
}

// ---------------------------------------------------------------------------------------------
// Configurations d'agents et de serveurs MCP

fn config_findings(display: &str, text: &str, tracked: bool, out: &mut Vec<Finding>) {
    let parsed: Option<Value> = if display.ends_with(".toml") {
        toml::from_str::<toml::Table>(text)
            .ok()
            .and_then(|t| serde_json::to_value(t).ok())
    } else {
        serde_json::from_str(text).ok()
    };
    let Some(value) = parsed else {
        // JSON avec commentaires (VS Code) ou fichier invalide : ligne par ligne.
        file_findings(display, text, tracked, false, out);
        return;
    };
    let mut hits = Vec::new();
    walk_value(&value, &mut Vec::new(), &mut hits);
    for (path, kinds) in hits {
        let (name, server) = describe_path(&path);
        let (severity, category) = if kinds.iter().all(|k| PUBLIC_BY_DESIGN.contains(&k.as_str())) {
            (Severity::Moyen, Category::PublicByDesign)
        } else if tracked {
            (Severity::Critique, Category::GitTracked)
        } else if server {
            (Severity::Eleve, Category::McpPlaintext)
        } else {
            (Severity::Eleve, Category::AgentReadable)
        };
        out.push(Finding {
            severity,
            category,
            file: display.to_string(),
            line: None,
            name: Some(name),
            kinds,
        });
    }
    for setting in risky_settings(display, &value) {
        out.push(Finding {
            severity: Severity::Moyen,
            category: Category::AgentSettings,
            file: display.to_string(),
            line: None,
            name: Some(setting),
            kinds: Vec::new(),
        });
    }
}

type Hit = (Vec<String>, Vec<String>);

fn walk_value(v: &Value, path: &mut Vec<String>, hits: &mut Vec<Hit>) {
    match v {
        Value::Object(map) => {
            for (k, x) in map {
                path.push(k.clone());
                walk_value(x, path, hits);
                path.pop();
            }
        }
        Value::Array(items) => {
            if path.last().is_some_and(|l| l == "args") {
                args_hits(items, path, hits);
            }
            for x in items {
                walk_value(x, path, hits);
            }
        }
        Value::String(s) => {
            let key = path.last().map(String::as_str).unwrap_or("");
            let mut kinds = detect_str(s);
            if kinds.is_empty()
                && ((secret_scope(path) && secret_name(key) && literal_secret(s))
                    || (key == "url" && url_secret(s)))
            {
                kinds.push(PROBABLE.into());
            }
            if !kinds.is_empty() {
                hits.push((path.clone(), kinds));
            }
        }
        _ => {}
    }
}

/// Sous un serveur MCP ou un bloc de variables d'environnement.
fn secret_scope(path: &[String]) -> bool {
    path.iter().any(|s| {
        matches!(
            s.as_str(),
            "mcpServers" | "servers" | "mcp_servers" | "env" | "headers" | "http_headers"
        )
    })
}

/// `--token valeur` ou `--api-key=valeur` dans les arguments d'un serveur MCP.
fn args_hits(items: &[Value], path: &[String], hits: &mut Vec<Hit>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?i)^--?((?:[a-z0-9-]*[-_])?(?:token|key|secret|password|pat|api-?key))(?:=(.+))?$",
        )
        .expect("motif")
    });
    let args: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
    for (i, arg) in args.iter().enumerate() {
        let Some(c) = re.captures(arg) else { continue };
        let value = c
            .get(2)
            .map(|m| m.as_str())
            .or_else(|| args.get(i + 1).copied());
        if let Some(value) = value
            && !value.starts_with('-')
            && detect_str(value).is_empty()
            && literal_secret(value)
        {
            let mut p = path.to_vec();
            p.push(format!("--{}", &c[1]));
            hits.push((p, vec![PROBABLE.into()]));
        }
    }
}

/// Adresse qui porte un secret : `?api_key=…`, `?token=…` ou `https://utilisateur:motdepasse@…`.
fn url_secret(url: &str) -> bool {
    static PARAM: OnceLock<Regex> = OnceLock::new();
    static USERINFO: OnceLock<Regex> = OnceLock::new();
    let param = PARAM.get_or_init(|| {
        Regex::new(r"(?i)[?&](?:api[_-]?key|key|token|access[_-]?token|secret|auth)=([^&#\s]+)")
            .expect("motif")
    });
    let userinfo = USERINFO.get_or_init(|| {
        Regex::new(r"(?i)^[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]{6,}@").expect("motif")
    });
    userinfo.is_match(url)
        || param
            .captures_iter(url)
            .any(|c| literal_secret(c.get(1).map_or("", |m| m.as_str())))
}

/// « serveur « github » · env.GITHUB_TOKEN » plutôt qu'un chemin JSON complet.
fn describe_path(path: &[String]) -> (String, bool) {
    let server = path
        .iter()
        .rposition(|s| matches!(s.as_str(), "mcpServers" | "servers" | "mcp_servers"));
    match server {
        Some(i) if i + 1 < path.len() => {
            let rest = path[i + 2..].join(".");
            let server = tr!(fmt "serveur « {} »", "server “{}”", path[i + 1]);
            let name = if rest.is_empty() {
                server
            } else {
                format!("{server} · {rest}")
            };
            (name, true)
        }
        _ => (path.join("."), false),
    }
}

/// Réglages de Claude Code et de Codex qui retirent les validations ou le bac à sable.
fn risky_settings(display: &str, v: &Value) -> Vec<String> {
    let mut found = Vec::new();
    if display.ends_with(".claude/settings.json")
        || display.ends_with(".claude/settings.local.json")
    {
        if v.pointer("/permissions/defaultMode")
            .and_then(Value::as_str)
            == Some("bypassPermissions")
        {
            found.push(
                tr!(
                    "permissions.defaultMode = bypassPermissions : l'agent agit sans rien demander",
                    "permissions.defaultMode = bypassPermissions: the agent acts without asking"
                )
                .into(),
            );
        }
        if v.pointer("/permissions/allow")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .any(|r| matches!(r, "Bash" | "Bash(*)" | "Bash(:*)"))
            })
        {
            found.push(
                tr!(
                    "permissions.allow = Bash(*) : toutes les commandes sont autorisées",
                    "permissions.allow = Bash(*): every command is allowed"
                )
                .into(),
            );
        }
        if v.get("enableAllProjectMcpServers") == Some(&Value::Bool(true)) {
            found.push(
                tr!(
                    "enableAllProjectMcpServers = true : les serveurs MCP d'un dépôt cloné sont \
                     lancés sans validation",
                    "enableAllProjectMcpServers = true: MCP servers from a cloned repository start \
                     without approval"
                )
                .into(),
            );
        }
    }
    if display.ends_with(".codex/config.toml")
        && has_key_value(v, "sandbox_mode", "danger-full-access")
    {
        found.push(
            tr!(
                "sandbox_mode = danger-full-access : bac à sable de Codex désactivé",
                "sandbox_mode = danger-full-access: Codex sandbox disabled"
            )
            .into(),
        );
    }
    found
}

fn has_key_value(v: &Value, key: &str, expected: &str) -> bool {
    match v {
        Value::Object(map) => map.iter().any(|(k, x)| {
            (k == key && x.as_str() == Some(expected)) || has_key_value(x, key, expected)
        }),
        Value::Array(items) => items.iter().any(|x| has_key_value(x, key, expected)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------
// Git

struct Git {
    tracked: HashSet<String>,
    /// Fichiers ni suivis ni ignorés : le prochain `git add .` les publiera.
    others: HashSet<String>,
}

fn git_state(root: &Path) -> Option<Git> {
    let list = |extra: &[&str]| -> Option<HashSet<String>> {
        let out = Command::new("git")
            // un dépôt piégé pourrait définir core.fsmonitor = <commande> dans .git/config
            .args(["-c", "core.fsmonitor=false", "-C"])
            .arg(root)
            .args(["ls-files", "-z"])
            .args(extra)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status.success().then(|| {
            out.stdout
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect()
        })
    };
    Some(Git {
        tracked: list(&[])?,
        others: list(&["--others", "--exclude-standard"])?,
    })
}

// ---------------------------------------------------------------------------------------------
// Affichage

impl Severity {
    fn title(self) -> &'static str {
        match self {
            Self::Critique => tr!(
                "CRITIQUE — publié ou publiable",
                "CRITICAL — published or about to be"
            ),
            Self::Eleve => tr!(
                "ÉLEVÉ — lisible par vos agents",
                "HIGH — readable by your agents"
            ),
            Self::Moyen => tr!("MOYEN — à vérifier", "MEDIUM — to review"),
        }
    }
}

impl Finding {
    fn label(&self) -> String {
        let at = match self.line {
            Some(n) => format!("{}:{n}", self.file),
            None => self.file.clone(),
        };
        let kinds = self
            .kinds
            .iter()
            .map(|k| {
                if k == PROBABLE {
                    tr!(
                        "secret probable (d'après le nom)",
                        "likely secret (from its name)"
                    )
                    .to_string()
                } else {
                    k.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        match (&self.name, kinds.is_empty()) {
            (Some(n), false) if *n == kinds => format!("{at}  {n}"),
            (Some(n), false) => format!("{at}  {n} · {kinds}"),
            (Some(n), true) => format!("{at}  {n}"),
            (None, false) => format!("{at}  {kinds}"),
            (None, true) => at,
        }
    }
}

impl Report {
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let (root, files) = (&self.root, self.files_scanned);
        let limit = if self.truncated {
            tr!(" (limite atteinte)", " (limit reached)")
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "{}",
            tr!(fmt "Analyse Aestheris : {root} · {files} fichier(s){limit}",
                "Aestheris scan: {root} · {files} file(s){limit}")
        );
        let _ = writeln!(
            out,
            "  {}",
            if self.git {
                tr!(
                    "dépôt git : suivi et .gitignore vérifiés (historique non analysé)",
                    "git repository: tracking and .gitignore checked (history not scanned)"
                )
            } else {
                tr!(
                    "pas un dépôt git : suivi et .gitignore non vérifiés",
                    "not a git repository: tracking and .gitignore not checked"
                )
            }
        );
        for severity in [Severity::Critique, Severity::Eleve, Severity::Moyen] {
            let items: Vec<&Finding> = self
                .findings
                .iter()
                .filter(|f| f.severity == severity)
                .collect();
            if items.is_empty() {
                continue;
            }
            let _ = writeln!(out, "\n{}", severity.title());
            let mut categories: Vec<Category> = items.iter().map(|f| f.category).collect();
            categories.dedup();
            for category in categories {
                let _ = writeln!(out, "  {}", category.title());
                let listed: Vec<&&Finding> =
                    items.iter().filter(|f| f.category == category).collect();
                for f in listed.iter().take(MAX_LISTED) {
                    let _ = writeln!(out, "    {}", f.label());
                }
                if listed.len() > MAX_LISTED {
                    let more = listed.len() - MAX_LISTED;
                    let _ = writeln!(
                        out,
                        "    {}",
                        tr!(fmt "… et {more} autre(s) (--json pour la liste complète)",
                            "… and {more} more (--json for the full list)")
                    );
                }
                let _ = writeln!(out, "    → {}", category.advice());
            }
        }
        if !self.home_exposure.is_empty() {
            let n = self.home_exposure.len();
            let _ = writeln!(
                out,
                "\n{}",
                tr!(fmt "Lisibles par tout programme lancé sous votre compte, agents compris ({n}) :",
                    "Readable by any program running as you, agents included ({n}):")
            );
            let _ = writeln!(out, "    {}", self.home_exposure.join(", "));
            let _ = writeln!(
                out,
                "    → {}",
                tr!(
                    "dans aestheris run, ces emplacements sont illisibles pour l'agent et ses programmes",
                    "under aestheris run, these locations are unreadable for the agent and its programs"
                )
            );
        }
        let s = &self.summary;
        let _ = writeln!(out);
        if s.critical + s.high + s.medium == 0 {
            let _ = writeln!(
                out,
                "{}",
                tr!(
                    "Bilan : aucun secret exposé trouvé dans ce qui a été analysé.",
                    "Summary: no exposed secret found in what was scanned."
                )
            );
        } else {
            let (c, h, m) = (s.critical, s.high, s.medium);
            let _ = writeln!(
                out,
                "{}",
                tr!(fmt "Bilan : {c} critique(s) · {h} élevé(s) · {m} moyen(s)",
                    "Summary: {c} critical · {h} high · {m} medium")
            );
        }
        if s.critical + s.high > 0 || !self.home_exposure.is_empty() {
            let _ = writeln!(
                out,
                "{}",
                tr!(
                    "Protéger vos agents : aestheris init, puis aestheris run -- claude",
                    "Protect your agents: aestheris init, then aestheris run -- claude"
                )
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(role: &str) -> String {
        let b = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        format!(
            "{}.{}.{}",
            b(r#"{"alg":"HS256","typ":"JWT"}"#),
            b(&format!(
                r#"{{"iss":"supabase","ref":"abcdefgh","role":"{role}","iat":1700000000}}"#
            )),
            "Xq3vTgL0pWc8bHn2Rk5sYd7AeJf9UoMiZt4NxQ1yGhE"
        )
    }

    #[test]
    fn jwt_supabase_anon_ignore_service_role_signale() {
        assert!(detect_str(&format!("KEY={}", jwt("anon"))).is_empty());
        assert_eq!(
            detect_str(&format!("KEY={}", jwt("service_role"))),
            vec!["SUPABASE_SERVICE_ROLE"]
        );
    }

    #[test]
    fn affectations_et_noms() {
        assert_eq!(
            env_assignment(r#"export DB_PASSWORD="s3cr3t-valeur""#),
            Some(("DB_PASSWORD", "s3cr3t-valeur"))
        );
        assert_eq!(env_assignment("# commentaire"), None);
        for n in [
            "DB_PASSWORD",
            "JWT_SECRET",
            "OPENAI_API_KEY",
            "GITHUB_PAT",
            "SERVICE_ROLE_KEY",
        ] {
            assert!(secret_name(n), "{n}");
        }
        for n in [
            "NEXTAUTH_URL",
            "API_KEY_FILE",
            "AWS_ACCESS_KEY_ID",
            "TOKEN_EXPIRES_IN",
            "PORT",
        ] {
            assert!(!secret_name(n), "{n}");
        }
    }

    #[test]
    fn valeurs_litterales_seulement() {
        assert!(literal_secret("s3cr3t-tres-long"));
        for v in [
            "${DB_PASSWORD}",
            "your-api-key-here",
            "changeme123",
            "aes_ph_0123456789abcdef",
            "pk_live_abcdefgh12345678",
            "http://localhost:3000",
            "12345678",
            "xxxxxxxxxx",
            "op://coffre/stripe/cle",
            "court",
        ] {
            assert!(!literal_secret(v), "{v}");
        }
    }

    #[test]
    fn configuration_mcp() {
        let config = r#"{"mcpServers":{
            "github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"],
                      "env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"GH"}},
            "crm":{"command":"crm-mcp","args":["--api-key","CRM"]},
            "remote":{"url":"https://mcp.exemple.io/sse?token=URL"},
            "sur":{"command":"x","env":{"TOKEN":"${env:TOKEN}"}}}}"#
            // fausses valeurs assemblées ici : les scanners de secrets ne les voient pas entières
            .replace(
                "\"GH\"",
                concat!("\"ghp_", "R8kX2vQ9mLt4Wz7NbJ3hYc6FdG1eUaPs5oKi\""),
            )
            .replace("\"CRM\"", concat!("\"c3VwZXItc2Vj", "cmV0LWNybQ\""))
            .replace("=URL", concat!("=Zx81kL", "mQ0pWe7Rt"));
        let mut out = Vec::new();
        config_findings("~/.cursor/mcp.json", &config, false, &mut out);
        let names: Vec<String> = out.iter().map(|f| f.name.clone().unwrap()).collect();
        assert_eq!(out.len(), 3, "{names:?}");
        assert!(out.iter().all(|f| f.category == Category::McpPlaintext));
        assert!(names.contains(&"serveur « github » · env.GITHUB_PERSONAL_ACCESS_TOKEN".into()));
        assert!(names.contains(&"serveur « crm » · args.--api-key".into()));
        assert!(names.contains(&"serveur « remote » · url".into()));
    }

    #[test]
    fn exemples_de_documentation_ecartes() {
        for line in [
            concat!("aws = \"AKIA", "IOSFODNN7EXAMPLE\""),
            concat!("url = \"postgresql://user:", "pass@localhost:5432/db\""),
            "url = f\"postgresql://{user}:{password}@{host}/db\"",
            concat!("DATABASE_URL=postgres:", "//postgres:postgres@db:5432/app"),
            concat!("key = \"sk-", "test-mock-api-key-456\""),
            concat!("key = \"sk-", "live-SHOULD-NOT-APPEAR-anywhere\""),
            concat!(
                "headers = {\"x-api-key\": \"sk-ant-",
                "api03-test-anthropic-key\"}"
            ),
            concat!("placeholder=\"-----BEGIN PRIVATE", " KEY-----...\""),
            concat!("const header = \"-----BEGIN PRIVATE", " KEY-----\";"),
            concat!(
                "token = \"eyJhbGciOiJIUzI1NiJ9.",
                "eyJzdWIiOiJ1c2VyLTEifQ.idp-signature\""
            ),
            concat!("blob = \"iVBORw0KGgo+AKIA", "Z7Q3LMNOP4RSTUVW/8AAAA\""),
            concat!("aws_access_key_id=\"AKIA", "FAKEACCESSKEYID1\""),
            concat!(
                "https://b.s3.amazonaws.com/f.pdf?X-Amz-Credential=ASIA",
                "Z7Q3LMNOP4RSTUVW%2F20260101"
            ),
            concat!("url = \"postgresql://user:", "s3cr3t@db-host:5432/app\""),
            concat!("url = \"postgresql://app:", "app@localhost:5432/app\""),
            concat!("url = \"postgresql://app:", "WRITER_TOKEN@writer:5432/db\""),
        ] {
            assert!(
                detect_str(line).is_empty(),
                "{line} → {:?}",
                detect_str(line)
            );
        }
        for (line, kind) in [
            (
                concat!("aws = \"AKIA", "Z7Q3LMNOP4RSTUVW\""),
                "AWS_ACCESS_KEY",
            ),
            (
                concat!(
                    "DATABASE_URL=postgres://app:",
                    "Vq8rT2mLx9@db.prod:5432/app"
                ),
                "DATABASE_URL_WITH_PASSWORD",
            ),
            (
                concat!(
                    "OPENAI_API_KEY=sk-",
                    "proj-Q7vR2mXk9LpT4wZs8NbJ3hYc6FdG1eUa"
                ),
                "OPENAI_API_KEY",
            ),
            (
                concat!(
                    "k = \"-----BEGIN PRIVATE",
                    " KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\""
                ),
                "PRIVATE_KEY",
            ),
        ] {
            assert!(
                detect_str(line).contains(&kind.to_string()),
                "{line} → {:?}",
                detect_str(line)
            );
        }
        // clé privée sur plusieurs lignes : le corps est sur la ligne suivante
        assert_eq!(
            detect_in(
                concat!("-----BEGIN RSA PRIVATE", " KEY-----"),
                Some(concat!(
                    "MIIEpAIB",
                    "AAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi3Vx8Fp2Lk"
                ))
            ),
            vec!["PRIVATE_KEY"]
        );
    }

    #[test]
    fn reglages_risques() {
        let mut out = Vec::new();
        config_findings(
            ".claude/settings.local.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)"]},
                "enableAllProjectMcpServers":true}"#,
            false,
            &mut out,
        );
        config_findings(
            "~/.codex/config.toml",
            "[profiles.vite]\nsandbox_mode = \"danger-full-access\"\n",
            false,
            &mut out,
        );
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|f| f.category == Category::AgentSettings));
    }
}
