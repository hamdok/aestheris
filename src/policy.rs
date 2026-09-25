//! Politique de la passerelle (fichier YAML versionné dans Git).
//!
//! Un fichier, des actions simples, échec fermé : on **charge**, on **valide** tout au démarrage
//! (une politique douteuse empêche le démarrage), puis on **fait correspondre** chaque requête.
//!
//! Règles « fail secure » :
//! - une route sans règle qui corresponde → refus ;
//! - amont en `http://` → refusé, sauf boucle locale explicitement autorisée (tests) ;
//! - adresses de métadonnées cloud → toujours refusées (liste non modifiable).

use crate::error::{Error, Result};
use crate::tr;
use globset::{GlobBuilder, GlobMatcher};
use reqwest::Url;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

/* ------------------------------------------------------------------ */
/* Format du fichier                                                   */
/* ------------------------------------------------------------------ */

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    routes: BTreeMap<String, RouteFile>,
    #[serde(default)]
    content: ContentFile,
    #[serde(default)]
    network: NetworkFile,
    #[serde(default)]
    sandbox: SandboxFile,
    #[serde(default)]
    approval: ApprovalFile,
    #[serde(default)]
    agent: AgentFile,
    /// Bouclier de confidentialité (appliqué aux routes qui ont `privacy: true`).
    privacy: Option<PrivacyFile>,
    /// Disjoncteur : trop de tentatives suspectes → la session passe en validation humaine.
    guard: Option<GuardFile>,
    /// `enforce` (défaut) ou `observe` : rien n'est bloqué, tout ce qui l'aurait été est noté.
    #[serde(default)]
    mode: Mode,
}

/// Mode de la passerelle.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// La politique s'applique.
    #[default]
    Enforce,
    /// Rien n'est bloqué ni modifié par la politique : la passerelle note ce qu'elle aurait
    /// refusé, bloqué, demandé ou pseudonymisé (pour un premier déploiement et son rapport).
    /// Restent actifs : jeton de session (sans lui, pas de clé) et refus des adresses internes.
    Observe,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardFile {
    #[serde(default = "default_max_withheld")]
    max_withheld: u64,
    #[serde(default = "default_max_blocked")]
    max_blocked: u64,
    #[serde(default = "default_max_denied")]
    max_denied: u64,
    #[serde(default)]
    on_trip: OnTrip,
}

fn default_max_withheld() -> u64 {
    3
}
fn default_max_blocked() -> u64 {
    3
}
fn default_max_denied() -> u64 {
    20
}

/// Ce que fait le disjoncteur une fois déclenché.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnTrip {
    /// Chaque requête suivante attend la validation d'un humain.
    #[default]
    Ask,
    /// Plus rien ne passe jusqu'à la fin de la session.
    Stop,
}

/// Disjoncteur d'injection : seuils par session.
#[derive(Debug, Clone)]
pub struct GuardPolicy {
    /// Tentatives d'envoyer une donnée hors de ses destinations (données fantômes retenues).
    pub max_withheld: u64,
    /// Secrets en clair bloqués.
    pub max_blocked: u64,
    /// Refus de la politique.
    pub max_denied: u64,
    pub on_trip: OnTrip,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyFile {
    #[serde(default = "default_privacy_kinds")]
    pseudonymize: Vec<String>,
    /// Catégorie (ex. CLIENT, PROJET) → noms à ne jamais montrer au fournisseur.
    #[serde(default)]
    terms: BTreeMap<String, Vec<String>>,
    #[serde(default = "yes")]
    strip_metadata: bool,
    /// Nom d'utilisateur, nom de la machine, nom Git : pseudonymisés (défaut : oui).
    #[serde(default = "yes")]
    identity: bool,
    /// Données fantômes : catégorie (ou `*`) → où la vraie valeur peut réapparaître.
    #[serde(default)]
    release: BTreeMap<String, Vec<String>>,
    /// Provenance : source (route `phantom: true`) → où ses valeurs peuvent réapparaître.
    #[serde(default)]
    origins: BTreeMap<String, Vec<String>>,
}

fn default_privacy_kinds() -> Vec<String> {
    crate::privacy::BUILTIN
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Réglages de l'agent lancé par `aestheris run`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AgentFile {
    /// Variables non secrètes (ex. couper la télémétrie). Un secret n'a rien à faire ici : il va
    /// dans le coffre et passe par une route.
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// Validation humaine : délai de réponse (sans réponse → refus) et notification du poste.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalFile {
    #[serde(default = "default_approval_timeout")]
    timeout_secs: u64,
    #[serde(default = "yes")]
    notify: bool,
}

impl Default for ApprovalFile {
    fn default() -> Self {
        Self {
            timeout_secs: default_approval_timeout(),
            notify: true,
        }
    }
}

fn default_approval_timeout() -> u64 {
    120
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFile {
    upstream: String,
    secret: String,
    inject: InjectFile,
    env: Option<String>,
    base_url_env: Option<String>,
    #[serde(default)]
    rules: Vec<RuleFile>,
    /// Bouclier de confidentialité sur cette route (routes de modèles : Anthropic, OpenAI).
    #[serde(default)]
    privacy: bool,
    /// Source de données : ses réponses sont pseudonymisées avant d'atteindre l'agent, chaque
    /// valeur marquée de sa provenance (voir `privacy.origins`).
    #[serde(default)]
    phantom: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectFile {
    header: String,
    #[serde(default = "default_format")]
    format: String,
}

fn default_format() -> String {
    "{}".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    action: Action,
    #[serde(default)]
    methods: Vec<String>,
    path: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ContentFile {
    #[serde(default)]
    secrets: ContentAction,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NetworkFile {
    #[serde(default)]
    allow_insecure_loopback: bool,
    #[serde(default)]
    egress: Egress,
    #[serde(default)]
    allow_hosts: Vec<String>,
    #[serde(default = "default_ports")]
    allow_ports: Vec<u16>,
    /// Résolution DNS depuis le bac à sable quand la sortie est restreinte (fermée par défaut :
    /// le DNS est un canal d'exfiltration, et le proxy résout lui-même les noms).
    #[serde(default)]
    allow_dns: bool,
    /// Hôte hors liste blanche : demander à un humain au lieu de refuser.
    #[serde(default)]
    ask_unknown_hosts: bool,
}

fn default_ports() -> Vec<u16> {
    vec![443]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "yes")]
    deny_dotenv: bool,
    #[serde(default)]
    protect_paths: Vec<String>,
    #[serde(default = "default_allow_write")]
    allow_write: Vec<String>,
    #[serde(default)]
    allow_unix_sockets: Vec<String>,
    #[serde(default)]
    allow_local_binding: bool,
    #[serde(default)]
    allow_git_config: bool,
}

impl Default for SandboxFile {
    fn default() -> Self {
        Self {
            enabled: false,
            deny_dotenv: true,
            protect_paths: Vec::new(),
            allow_write: default_allow_write(),
            allow_unix_sockets: Vec::new(),
            allow_local_binding: false,
            allow_git_config: false,
        }
    }
}

/// Par défaut, l'agent n'écrit que dans le dossier où il est lancé (et les dossiers temporaires).
fn default_allow_write() -> Vec<String> {
    vec![".".into()]
}

fn yes() -> bool {
    true
}

/// Sortie réseau de l'agent (hors routes de la passerelle).
/// - `open` : non contrôlée (défaut, sans bac à sable) ;
/// - `allowlist` : uniquement les hôtes de `allow_hosts`, via le proxy HTTPS de la passerelle ;
/// - `none` : aucune, seules les routes de la passerelle sont joignables.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Egress {
    #[default]
    Open,
    Allowlist,
    None,
}

impl std::fmt::Display for Egress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Egress::Open => tr!("ouverte", "open"),
            Egress::Allowlist => tr!("liste blanche", "allowlist"),
            Egress::None => tr!("aucune (routes uniquement)", "none (routes only)"),
        })
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    /// Validation humaine avant l'envoi.
    Ask,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContentAction {
    #[default]
    Block,
    Allow,
}

/* ------------------------------------------------------------------ */
/* Politique validée                                                   */
/* ------------------------------------------------------------------ */

#[derive(Debug)]
pub struct Policy {
    pub routes: BTreeMap<String, Route>,
    pub content_secrets: ContentAction,
    pub egress: Egress,
    /// Hôtes joignables via le proxy de sortie : `exemple.com` ou `*.exemple.com`.
    pub allow_hosts: Vec<String>,
    pub allow_insecure_loopback: bool,
    /// Ports joignables via le proxy de sortie (443 par défaut).
    pub allow_ports: Vec<u16>,
    /// DNS permis dans le bac à sable malgré une sortie restreinte.
    pub allow_dns: bool,
    /// Hôte hors liste blanche : validation humaine au lieu d'un refus.
    pub ask_unknown_hosts: bool,
    pub sandbox: SandboxPolicy,
    pub approval: ApprovalPolicy,
    /// Variables non secrètes données à l'agent (`agent.env`).
    pub agent_env: BTreeMap<String, String>,
    /// Bouclier de confidentialité, présent si au moins une route l'active.
    pub privacy: Option<crate::privacy::Settings>,
    /// Disjoncteur d'injection (section `guard`).
    pub guard: Option<GuardPolicy>,
    pub mode: Mode,
}

#[derive(Debug, Clone)]
pub struct ApprovalPolicy {
    /// Sans réponse dans ce délai, la requête est refusée (fail secure).
    pub timeout: std::time::Duration,
    /// Notification du système quand une validation attend (macOS).
    pub notify: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SandboxPolicy {
    pub enabled: bool,
    /// Fichiers `.env` illisibles (défaut : oui).
    pub deny_dotenv: bool,
    /// Chemins illisibles et non modifiables, en plus des secrets usuels.
    pub protect_paths: Vec<String>,
    /// Seuls chemins modifiables (plus les dossiers temporaires) ; `.` = dossier de lancement.
    pub allow_write: Vec<String>,
    /// Sockets Unix joignables (ex. `/var/run/docker.sock`) : aucun par défaut.
    pub allow_unix_sockets: Vec<String>,
    /// Serveurs locaux (ports ouverts par l'agent, connexions vers `localhost`).
    pub allow_local_binding: bool,
    /// Autorise l'écriture de `.git/config` (nécessaire à `git init`, `git clone`, `git remote`).
    pub allow_git_config: bool,
}

#[derive(Debug)]
pub struct Route {
    pub name: String,
    pub upstream: Url,
    pub secret: String,
    pub inject_header: reqwest::header::HeaderName,
    pub inject_format: String,
    pub env: Option<String>,
    pub base_url_env: Option<String>,
    /// Pseudonymisation des requêtes et réponses de cette route.
    pub privacy: bool,
    /// Source de données : réponses pseudonymisées avant d'atteindre l'agent.
    pub phantom: bool,
    rules: Vec<Rule>,
}

#[derive(Debug)]
struct Rule {
    action: Action,
    methods: Vec<String>,
    path: Option<PathMatch>,
}

#[derive(Debug)]
struct PathMatch {
    text: String,
    main: GlobMatcher,
    /// Pour un motif en « /** » : la racine elle-même.
    base: Option<GlobMatcher>,
}

impl PathMatch {
    fn is_match(&self, path: &str) -> bool {
        self.main.is_match(path) || self.base.as_ref().is_some_and(|b| b.is_match(path))
    }
}

/// Résultat de la politique pour une requête.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Ask,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        self.verdict == Verdict::Allow
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::Policy(
                tr!(fmt "lecture de {} impossible : {e}", "cannot read {}: {e}", path.display()),
            )
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let file: PolicyFile = serde_yaml_ng::from_str(text)?;
        if file.version != 1 {
            return Err(Error::Policy(tr!(fmt
                "version {} non prise en charge (attendu : 1)", "version {} not supported (expected: 1)",
                file.version
            )));
        }
        if file.routes.is_empty() {
            return Err(Error::Policy(
                tr!("aucune route définie", "no route defined").into(),
            ));
        }
        let mut routes = BTreeMap::new();
        let mut envs: Vec<String> = Vec::new();
        for (name, r) in file.routes {
            let route = compile_route(&name, r, file.network.allow_insecure_loopback)?;
            for v in route.env.iter().chain(route.base_url_env.iter()) {
                if envs.contains(v) {
                    return Err(Error::Policy(tr!(fmt
                        "variable {v} utilisée par deux routes", "variable {v} used by two routes"
                    )));
                }
                envs.push(v.clone());
            }
            routes.insert(name, route);
        }
        let allow_hosts = file
            .network
            .allow_hosts
            .iter()
            .map(|h| validate_host_pattern(h))
            .collect::<Result<Vec<_>>>()?;
        if file.network.egress != Egress::Allowlist && !allow_hosts.is_empty() {
            return Err(Error::Policy(
                tr!(
                    "network.allow_hosts n'a d'effet qu'avec network.egress: allowlist",
                    "network.allow_hosts only takes effect with network.egress: allowlist"
                )
                .into(),
            ));
        }
        if file.network.ask_unknown_hosts && file.network.egress != Egress::Allowlist {
            return Err(Error::Policy(
                tr!(
                    "network.ask_unknown_hosts n'a de sens qu'avec network.egress: allowlist",
                    "network.ask_unknown_hosts only makes sense with network.egress: allowlist"
                )
                .into(),
            ));
        }
        if !(5..=3600).contains(&file.approval.timeout_secs) {
            return Err(Error::Policy(
                tr!(
                    "approval.timeout_secs doit être entre 5 et 3600 secondes",
                    "approval.timeout_secs must be between 5 and 3600 seconds"
                )
                .into(),
            ));
        }
        for (k, v) in &file.agent.env {
            validate_agent_env(k, v, &envs)?;
        }
        let privacy = validate_privacy(file.privacy, &routes)?;
        if file.network.egress != Egress::Open && !file.sandbox.enabled {
            return Err(Error::Policy(
                tr!("network.egress restreint exige sandbox.enabled: true (sinon l'agent pourrait contourner le proxy)", "a restricted network.egress requires sandbox.enabled: true (otherwise the agent could bypass the proxy)").into(),
            ));
        }
        Ok(Self {
            routes,
            content_secrets: file.content.secrets,
            egress: file.network.egress,
            allow_hosts,
            allow_insecure_loopback: file.network.allow_insecure_loopback,
            allow_ports: file.network.allow_ports,
            allow_dns: file.network.allow_dns,
            ask_unknown_hosts: file.network.ask_unknown_hosts,
            agent_env: file.agent.env,
            privacy,
            mode: file.mode,
            guard: file.guard.map(|g| GuardPolicy {
                max_withheld: g.max_withheld.max(1),
                max_blocked: g.max_blocked.max(1),
                max_denied: g.max_denied.max(1),
                on_trip: g.on_trip,
            }),
            approval: ApprovalPolicy {
                timeout: std::time::Duration::from_secs(file.approval.timeout_secs),
                notify: file.approval.notify,
            },
            sandbox: SandboxPolicy {
                enabled: file.sandbox.enabled,
                deny_dotenv: file.sandbox.deny_dotenv,
                protect_paths: file.sandbox.protect_paths,
                allow_write: file.sandbox.allow_write,
                allow_unix_sockets: file.sandbox.allow_unix_sockets,
                allow_local_binding: file.sandbox.allow_local_binding,
                allow_git_config: file.sandbox.allow_git_config,
            },
        })
    }
}

impl Route {
    /// Première règle qui correspond ; aucune → refus (fail secure).
    pub fn decide(&self, method: &str, path: &str) -> Decision {
        for (i, rule) in self.rules.iter().enumerate() {
            let method_ok = rule.methods.is_empty() || rule.methods.iter().any(|m| m == method);
            let path_ok = rule.path.as_ref().is_none_or(|m| m.is_match(path));
            if method_ok && path_ok {
                let what = describe(rule);
                let (verdict, verb) = match rule.action {
                    Action::Allow => (Verdict::Allow, tr!("autorise", "allows")),
                    Action::Deny => (Verdict::Deny, tr!("interdit", "denies")),
                    Action::Ask => (
                        Verdict::Ask,
                        tr!("soumet à validation humaine", "requires human approval"),
                    ),
                };
                return Decision {
                    verdict,
                    reason: tr!(fmt "règle {} {verb} {what}", "rule {} {verb} {what}", i + 1),
                };
            }
        }
        Decision {
            verdict: Verdict::Deny,
            reason: tr!(
                "aucune règle n'autorise cette requête (refus par défaut)",
                "no rule allows this request (denied by default)"
            )
            .into(),
        }
    }
}

impl Policy {
    /// La politique peut-elle demander une validation humaine ?
    pub fn uses_approval(&self) -> bool {
        self.mode == Mode::Enforce && self.uses_approval_rules()
    }

    /// La politique contient-elle des règles de validation (quel que soit le mode) ?
    fn uses_approval_rules(&self) -> bool {
        self.guard
            .as_ref()
            .is_some_and(|g| g.on_trip == OnTrip::Ask)
            || self.ask_unknown_hosts
            || self
                .routes
                .values()
                .any(|r| r.rules.iter().any(|rule| rule.action == Action::Ask))
    }
}

impl Route {
    /// Règles lisibles, dans l'ordre d'évaluation (pour `aestheris policy check`).
    pub fn describe_rules(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|r| {
                let verb = match r.action {
                    Action::Allow => tr!("autorise", "allow   "),
                    Action::Deny => tr!("interdit", "deny    "),
                    Action::Ask => tr!("demande ", "ask     "),
                };
                format!("{verb}  {}", describe(r))
            })
            .collect()
    }
}

fn describe(rule: &Rule) -> String {
    let m = if rule.methods.is_empty() {
        tr!("toute méthode", "any method").to_string()
    } else {
        rule.methods.join("/")
    };
    match &rule.path {
        Some(p) => tr!(fmt "{m} sur {}", "{m} on {}", p.text),
        None => m,
    }
}

fn compile_route(name: &str, r: RouteFile, allow_insecure_loopback: bool) -> Result<Route> {
    let bad =
        |msg: String| Error::Policy(tr!(fmt "route « {name} » : {msg}", "route “{name}”: {msg}"));

    if !(name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'))
    {
        return Err(bad(tr!(
            "nom invalide (minuscules, chiffres, - et _)",
            "invalid name (lowercase letters, digits, - and _)"
        )
        .into()));
    }

    let upstream = Url::parse(&r.upstream)
        .map_err(|e| bad(tr!(fmt "URL amont invalide : {e}", "invalid upstream URL: {e}")))?;
    validate_upstream(&upstream, allow_insecure_loopback).map_err(bad)?;
    crate::vault::validate_name(&r.secret).map_err(|e| bad(e.to_string()))?;

    let inject_header = reqwest::header::HeaderName::from_bytes(r.inject.header.as_bytes())
        .map_err(|_| {
            bad(tr!(fmt
                "en-tête d'injection invalide : {}", "invalid injection header: {}",
                r.inject.header
            ))
        })?;
    if r.inject.format.matches("{}").count() != 1 {
        return Err(bad(tr!(
            "le format d'injection doit contenir exactement un {}",
            "the injection format must contain exactly one {}"
        )
        .into()));
    }
    for v in r.env.iter().chain(r.base_url_env.iter()) {
        validate_env_name(v).map_err(&bad)?;
    }

    let mut rules = Vec::new();
    for rule in r.rules {
        let methods = rule
            .methods
            .iter()
            .map(|m| {
                let up = m.to_ascii_uppercase();
                if ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
                    .contains(&up.as_str())
                {
                    Ok(up)
                } else {
                    Err(bad(
                        tr!(fmt "méthode inconnue : {m}", "unknown method: {m}"),
                    ))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let path = match rule.path {
            Some(p) => {
                if !p.starts_with('/') {
                    return Err(bad(
                        tr!(fmt "le chemin doit commencer par / : {p}", "the path must start with /: {p}"),
                    ));
                }
                // `*` ne traverse pas les /, `**` oui.
                let compile = |pat: &str| {
                    GlobBuilder::new(pat)
                        .literal_separator(true)
                        .build()
                        .map(|g| g.compile_matcher())
                        .map_err(|e| bad(tr!(fmt "motif de chemin invalide {p} : {e}", "invalid path pattern {p}: {e}")))
                };
                // « /v1/refunds/** » couvre aussi « /v1/refunds » (comme dans un .gitignore) :
                // une règle qui interdit ou demande une validation ne laisse pas passer la racine.
                let base = match p.strip_suffix("/**") {
                    Some(b) if !b.is_empty() => Some(compile(b)?),
                    _ => None,
                };
                Some(PathMatch {
                    text: p.clone(),
                    main: compile(&p)?,
                    base,
                })
            }
            None => None,
        };
        rules.push(Rule {
            action: rule.action,
            methods,
            path,
        });
    }

    Ok(Route {
        name: name.to_string(),
        upstream,
        secret: r.secret,
        inject_header,
        inject_format: r.inject.format,
        env: r.env,
        base_url_env: r.base_url_env,
        privacy: r.privacy,
        phantom: r.phantom,
        rules,
    })
}

/// Hôtes de métadonnées cloud : toujours interdits (liste reprise d'un travail Apache-2.0, voir NOTICE).
const DENY_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
    "metadata.oraclecloud.com",
    "100.100.100.200",
    "fd00:ec2::254",
];

fn validate_upstream(url: &Url, allow_insecure_loopback: bool) -> std::result::Result<(), String> {
    let host = url
        .host_str()
        .ok_or(tr!("URL amont sans hôte", "upstream URL without a host"))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if !url.username().is_empty() || url.password().is_some() {
        return Err(tr!(
            "identifiants interdits dans l'URL amont",
            "credentials are not allowed in the upstream URL"
        )
        .into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(tr!(
            "l'URL amont ne doit pas contenir de paramètres ni de fragment",
            "the upstream URL must not contain query parameters or a fragment"
        )
        .into());
    }
    if DENY_HOSTS.contains(&host.as_str()) {
        return Err(tr!(fmt
            "{host} est une adresse de métadonnées cloud (toujours interdite)", "{host} is a cloud metadata address (always forbidden)"
        ));
    }
    let ip = host.parse::<IpAddr>().ok();
    if ip.is_some_and(|ip| is_link_local(&ip)) {
        return Err(tr!(fmt
            "{host} est une adresse lien-local (toujours interdite)", "{host} is a link-local address (always forbidden)"
        ));
    }
    let loopback = host == "localhost" || ip.is_some_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback && allow_insecure_loopback => Ok(()),
        "http" if loopback => Err(tr!("amont http:// local : ajoutez network.allow_insecure_loopback: true (tests uniquement)", "local http:// upstream: add network.allow_insecure_loopback: true (tests only)").into()),
        s => Err(tr!(fmt "schéma {s}:// refusé, seul https:// est autorisé", "scheme {s}:// refused, only https:// is allowed")),
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local())
        }
    }
}

/// Variables d'environnement données à l'agent : noms sûrs uniquement.
fn validate_env_name(v: &str) -> std::result::Result<(), String> {
    let shape = v
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && v.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !shape {
        return Err(tr!(fmt "nom de variable invalide : {v}", "invalid variable name: {v}"));
    }
    const FORBIDDEN: &[&str] = &[
        "PATH",
        "HOME",
        "SHELL",
        "USER",
        "PWD",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
    ];
    if FORBIDDEN.contains(&v) || v.starts_with("DYLD_") || v.starts_with("AESTHERIS_") {
        return Err(tr!(fmt "variable réservée : {v}", "reserved variable: {v}"));
    }
    Ok(())
}

/// Section `privacy` : catégories connues, noms déclarés raisonnables, destinations valides.
/// Le bouclier n'existe que si une route l'utilise (`privacy` ou `phantom`) ; réglages par
/// défaut si la section est absente.
fn validate_privacy(
    file: Option<PrivacyFile>,
    routes: &BTreeMap<String, Route>,
) -> Result<Option<crate::privacy::Settings>> {
    if let Some(r) = routes.values().find(|r| r.privacy && r.phantom) {
        return Err(Error::Policy(tr!(fmt
            "route {} : « privacy » (modèle) et « phantom » (source de données) s'excluent", "route {}: `privacy` (model) and `phantom` (data source) are mutually exclusive",
            r.name
        )));
    }
    let used = routes.values().any(|r| r.privacy || r.phantom);
    let bad = |m: String| Err(Error::Policy(tr!(fmt "privacy : {m}", "privacy: {m}")));
    let Some(f) = file else {
        return Ok(used.then(|| crate::privacy::Settings {
            kinds: default_privacy_kinds(),
            terms: BTreeMap::new(),
            strip_metadata: true,
            identity: true,
            release: BTreeMap::new(),
            origins: BTreeMap::new(),
        }));
    };
    if !used {
        return bad(tr!(
            "aucune route n'a « privacy: true » ni « phantom: true » : le bouclier ne \
                 s'appliquerait nulle part",
            "no route has `privacy: true` or `phantom: true`: the shield would apply nowhere"
        )
        .into());
    }
    for k in &f.pseudonymize {
        if !crate::privacy::BUILTIN.contains(&k.as_str()) {
            return bad(tr!(fmt
                "catégorie inconnue « {k} » (connues : {})", "unknown category “{k}” (known: {})",
                crate::privacy::BUILTIN.join(", ")
            ));
        }
    }
    for (cat, list) in &f.terms {
        let shape = !cat.is_empty()
            && cat.len() <= 20
            && cat.starts_with(|c: char| c.is_ascii_uppercase())
            && cat.chars().all(|c| c.is_ascii_uppercase() || c == '_');
        if !shape || ["EMAIL", "TEL", "IBAN", "CARTE", "IP"].contains(&cat.as_str()) {
            return bad(tr!(fmt
                "catégorie de termes invalide « {cat} » (ex. CLIENT, PROJET)", "invalid term category “{cat}” (e.g. CLIENT, PROJECT)"
            ));
        }
        if list.iter().any(|t| t.trim().is_empty() || t.len() > 200) {
            return bad(
                tr!(fmt "terme vide ou trop long dans {cat}", "empty or too long term in {cat}"),
            );
        }
    }
    // Données fantômes : catégories connues ; provenances = sources de données ; destinations
    // « human », « agent » ou une route qui n'est pas un modèle (libérer vers un modèle
    // annulerait le bouclier).
    const LABELS: &[&str] = &[
        "EMAIL",
        "TEL",
        "IBAN",
        "CARTE",
        "IP",
        "UTILISATEUR",
        "MACHINE",
        "NOM",
    ];
    for cat in f.release.keys() {
        if !(cat == "*" || LABELS.contains(&cat.as_str()) || f.terms.contains_key(cat)) {
            return bad(
                tr!(fmt "release : catégorie inconnue « {cat} »", "release: unknown category “{cat}”"),
            );
        }
    }
    for origin in f.origins.keys() {
        if !routes.get(origin).is_some_and(|r| r.phantom) {
            return bad(tr!(fmt
                "origins : « {origin} » n'est pas une route « phantom: true » (source de données)", "origins: “{origin}” is not a `phantom: true` route (data source)"
            ));
        }
    }
    for sink in f.release.values().chain(f.origins.values()).flatten() {
        let ok = match sink.strip_prefix("route:") {
            Some(r) => match routes.get(r) {
                Some(route) if route.privacy => {
                    return bad(tr!(fmt
                        "release : « {sink} » est une route de modèle protégée par le bouclier ; \
                         y libérer des valeurs réelles l'annulerait",
                        "release: “{sink}” is a model route protected by the shield; releasing \
                         real values to it would cancel the shield"
                    ));
                }
                Some(_) => true,
                None => false,
            },
            None => sink == "human" || sink == "agent",
        };
        if !ok {
            return bad(tr!(fmt
                "release : destination inconnue « {sink} » (human, agent ou route:<nom>)", "release: unknown destination “{sink}” (human, agent or route:<name>)"
            ));
        }
    }
    Ok(Some(crate::privacy::Settings {
        kinds: f.pseudonymize,
        terms: f.terms,
        strip_metadata: f.strip_metadata,
        identity: f.identity,
        release: f.release,
        origins: f.origins,
    }))
}

/// Variable de `agent.env` : nom sûr, jamais une variable que la passerelle gère (routes, proxy,
/// TMPDIR) ou qui charge du code, et jamais une valeur qui ressemble à un secret.
fn validate_agent_env(name: &str, value: &str, route_envs: &[String]) -> Result<()> {
    let bad = |why: &str| {
        Err(Error::Policy(
            tr!(fmt "agent.env.{name} : {why}", "agent.env.{name}: {why}"),
        ))
    };
    let shape = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !shape {
        return bad(tr!("nom de variable invalide", "invalid variable name"));
    }
    const MANAGED: &[&str] = &[
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_USE_ENV_PROXY",
        "TMPDIR",
    ];
    let upper = name.to_ascii_uppercase();
    if MANAGED.contains(&upper.as_str())
        || route_envs.iter().any(|r| r == name)
        || validate_env_name(&upper).is_err()
        || upper.starts_with("LD_")
    {
        return bad(tr!(
            "variable gérée par la passerelle ou réservée",
            "variable managed by the gateway or reserved"
        ));
    }
    if value.len() > 4096 || value.contains('\0') {
        return bad(tr!(
            "valeur trop longue ou invalide",
            "value too long or invalid"
        ));
    }
    let found = crate::scan::detect(value);
    if !found.is_empty() {
        return bad(&tr!(fmt
            "la valeur ressemble à un secret ({}) : rangez-la dans le coffre et passez par une route", "the value looks like a secret ({}): store it in the vault and go through a route",
            found.join(", ")
        ));
    }
    Ok(())
}

/// Motif d'hôte autorisé : `exemple.com` ou `*.exemple.com`, en minuscules, sans schéma ni port.
fn validate_host_pattern(p: &str) -> Result<String> {
    let h = p.trim().to_ascii_lowercase();
    let body = h.strip_prefix("*.").unwrap_or(&h);
    let ok = !body.is_empty()
        && body.len() <= 253
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':')
        && !body.starts_with('.')
        && !body.contains("..")
        && !body.contains('*');
    if !ok {
        return Err(Error::Policy(tr!(fmt
            "motif d'hôte invalide : « {p} » (ex. registry.npmjs.org ou *.github.com)", "invalid host pattern: “{p}” (e.g. registry.npmjs.org or *.github.com)"
        )));
    }
    if DENY_HOSTS.contains(&body) {
        return Err(Error::Policy(tr!(fmt
            "{body} est une adresse de métadonnées cloud (toujours interdite)", "{body} is a cloud metadata address (always forbidden)"
        )));
    }
    Ok(h)
}

impl Policy {
    /// L'hôte est-il autorisé en sortie ? (`*.exemple.com` couvre les sous-domaines, pas exemple.com)
    pub fn host_allowed(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.allow_hosts.iter().any(|p| match p.strip_prefix("*.") {
            Some(suffix) => host.ends_with(&format!(".{suffix}")),
            None => host == *p,
        })
    }

    /// Hôtes des routes : l'agent doit passer par la route (politique, injection), pas en direct.
    pub fn is_route_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.routes.values().any(|r| {
            r.upstream
                .host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&host))
        })
    }
}

/// Adresse interdite en sortie : métadonnées cloud, lien-local, et réseau interne ou boucle locale
/// (sauf boucle locale explicitement autorisée pour les tests). Vérifiée APRÈS résolution DNS,
/// sur chaque adresse, pour déjouer le « DNS rebinding ».
pub fn ip_forbidden(ip: &IpAddr, allow_loopback: bool) -> bool {
    if is_link_local(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (v4.is_loopback() && !allow_loopback)
                || v4.is_private()
                || v4.is_unspecified()
                || o[0] == 0 // 0.0.0.0/8 : joint le poste lui-même sur la plupart des systèmes
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 100 && (o[1] & 0xc0) == 64 // 100.64.0.0/10 (CGNAT, métadonnées Alibaba)
                || o[..3] == [192, 0, 0] // 192.0.0.0/24 (dont métadonnées Oracle 192.0.0.192)
                || o == [168, 63, 129, 16] // Azure WireServer (adresse publique !)
        }
        IpAddr::V6(v6) => {
            // Une adresse IPv6 qui transporte une IPv4 (mappée, compatible, NAT64, 6to4) est livrée
            // à cette IPv4 : on lui applique les mêmes interdictions.
            if let Some(v4) = embedded_ipv4(v6)
                && ip_forbidden(&IpAddr::V4(v4), allow_loopback)
            {
                return true;
            }
            (v6.is_loopback() && !allow_loopback)
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 (privées, métadonnées AWS/GCP IPv6)
        }
    }
}

/// Adresse attribuée à une interface de ce poste (hors boucle locale, régie par
/// `allow_insecure_loopback`) : un service qui écoute sur 0.0.0.0 y répond comme sur 127.0.0.1
/// Test sans dépendance : seul le poste peut se lier à ses adresses.
pub fn is_own_address(ip: &IpAddr) -> bool {
    !ip.is_loopback() && std::net::UdpSocket::bind((*ip, 0)).is_ok()
}

/// IPv4 transportée par une adresse IPv6 : mappée (`::ffff:a.b.c.d`), compatible (`::a.b.c.d`),
/// NAT64 (`64:ff9b::/96`) ou 6to4 (`2002:aabb:ccdd::/48`).
fn embedded_ipv4(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let g = v6.segments();
    let low =
        || std::net::Ipv4Addr::new((g[6] >> 8) as u8, g[6] as u8, (g[7] >> 8) as u8, g[7] as u8);
    if g[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            (g[1] >> 8) as u8,
            g[1] as u8,
            (g[2] >> 8) as u8,
            g[2] as u8,
        ));
    }
    if g[0] == 0x64 && g[1] == 0xff9b && g[2..6].iter().all(|&x| x == 0) {
        return Some(low());
    }
    if g[..5].iter().all(|&x| x == 0) && (g[5] == 0 || g[5] == 0xffff) && !(g[5] == 0 && g[6] == 0)
    {
        return Some(low());
    }
    None
}

/// Chemin de requête sûr : pas de segments `.`/`..`, pas de séparateurs encodés, pas de `\`.
/// Refuser plutôt que normaliser évite qu'une règle vue ici diffère de ce que comprend l'amont.
pub fn validate_request_path(path: &str) -> std::result::Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err(tr!("chemin relatif", "relative path"));
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
        || path.contains('\\')
    {
        return Err(tr!(
            "séparateur ou point encodé dans le chemin",
            "encoded separator or dot in the path"
        ));
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(tr!(
            "segment . ou .. dans le chemin",
            "`.` or `..` segment in the path"
        ));
    }
    if path.contains("//") {
        return Err(tr!(
            "double barre oblique dans le chemin",
            "double slash in the path"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
version: 1
routes:
  stripe:
    upstream: https://api.stripe.com
    secret: stripe/test
    inject: { header: Authorization, format: "Bearer {}" }
    env: STRIPE_API_KEY
    base_url_env: STRIPE_API_BASE
    rules:
      - { action: deny, methods: [DELETE] }
      - { action: allow, methods: [GET, POST], path: "/v1/**" }
"#;

    #[test]
    fn premiere_regle_qui_correspond() {
        let p = Policy::parse(BASE).unwrap();
        let r = &p.routes["stripe"];
        assert!(r.decide("POST", "/v1/charges").allowed());
        assert!(r.decide("GET", "/v1/customers/cus_1").allowed());
        assert!(!r.decide("DELETE", "/v1/customers/cus_1").allowed());
        assert!(
            !r.decide("POST", "/v2/admin").allowed(),
            "refus par défaut hors des règles"
        );
    }

    #[test]
    fn un_motif_en_double_etoile_couvre_sa_racine() {
        let yaml = BASE.replace(
            "      - { action: deny, methods: [DELETE] }",
            "      - { action: ask, methods: [POST], path: \"/v1/refunds/**\" }",
        );
        let p = Policy::parse(&yaml).unwrap();
        let r = &p.routes["stripe"];
        // création d'un remboursement chez Stripe : POST /v1/refunds
        assert_eq!(r.decide("POST", "/v1/refunds").verdict, Verdict::Ask);
        assert_eq!(
            r.decide("POST", "/v1/refunds/re_1/cancel").verdict,
            Verdict::Ask
        );
        assert_eq!(r.decide("POST", "/v1/refundsX").verdict, Verdict::Allow);
    }

    #[test]
    fn validation_humaine() {
        let yaml = BASE.replace(
            "      - { action: deny, methods: [DELETE] }",
            "      - { action: ask, methods: [POST], path: \"/v1/refunds/**\" }\n      - { action: deny, methods: [DELETE] }",
        );
        let p = Policy::parse(&yaml).unwrap();
        assert_eq!(
            p.routes["stripe"]
                .decide("POST", "/v1/refunds/re_1")
                .verdict,
            Verdict::Ask
        );
        assert!(p.routes["stripe"].decide("POST", "/v1/charges").allowed());
        assert!(p.uses_approval());
        assert!(!Policy::parse(BASE).unwrap().uses_approval());
        assert_eq!(p.approval.timeout.as_secs(), 120);
        // ask_unknown_hosts exige une liste blanche ; délai borné
        assert!(Policy::parse(&format!("{BASE}network:\n  ask_unknown_hosts: true\n")).is_err());
        assert!(Policy::parse(&format!("{BASE}approval:\n  timeout_secs: 1\n")).is_err());
    }

    #[test]
    fn variables_de_l_agent() {
        let ok = format!(
            "{BASE}agent:\n  env:\n    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: \"1\"\n    npm_config_fund: \"false\"\n"
        );
        let p = Policy::parse(&ok).unwrap();
        assert_eq!(p.agent_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1");
        for bad in [
            "    GITHUB_KEY: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n", // un secret
            "    LD_PRELOAD: /tmp/x.so\n",                                // injection de code
            "    DYLD_INSERT_LIBRARIES: /tmp/x.dylib\n",
            "    https_proxy: http://evil:8080\n", // détournement du proxy
            "    STRIPE_API_KEY: x\n",             // variable d'une route
            "    AESTHERIS_SESSION: x\n",
        ] {
            let err = Policy::parse(&format!("{BASE}agent:\n  env:\n{bad}")).unwrap_err();
            assert!(err.to_string().contains("agent.env"), "{bad} : {err}");
        }
    }

    #[test]
    fn provenance_et_disjoncteur_valides() {
        let source = BASE.replace(
            "    rules:\n      - { action: deny, methods: [DELETE] }",
            "    phantom: true\n    rules:\n      - { action: deny, methods: [DELETE] }",
        );
        let ok = format!(
            "{source}privacy:\n  origins:\n    stripe: [human]\nguard:\n  max_withheld: 2\n  on_trip: stop\n"
        );
        let p = Policy::parse(&ok).unwrap();
        assert!(p.routes["stripe"].phantom);
        let g = p.guard.unwrap();
        assert_eq!(
            (g.max_withheld, g.max_blocked, g.on_trip),
            (2, 3, OnTrip::Stop)
        );
        // une source de données active le bouclier même sans section « privacy »
        assert!(Policy::parse(&source).unwrap().privacy.is_some());
        // provenance d'une route qui n'est pas une source
        let err = Policy::parse(&format!(
            "{BASE}privacy:\n  origins:\n    stripe: [human]\n"
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("aucune route") || err.to_string().contains("phantom"),
            "{err}"
        );
        // modèle et source à la fois : refusé
        let both = BASE.replace(
            "    rules:\n      - { action: deny, methods: [DELETE] }",
            "    phantom: true\n    privacy: true\n    rules:\n      - { action: deny, methods: [DELETE] }",
        );
        assert!(
            Policy::parse(&both)
                .unwrap_err()
                .to_string()
                .contains("s'excluent")
        );
        // le disjoncteur en mode « ask » ouvre le canal de validation
        let ask = format!("{BASE}guard: {{}}\n");
        assert!(Policy::parse(&ask).unwrap().uses_approval());
    }

    #[test]
    fn donnees_fantomes_garde_fous() {
        let llm = BASE.replace(
            "    rules:\n      - { action: deny, methods: [DELETE] }",
            "    privacy: true\n    rules:\n      - { action: deny, methods: [DELETE] }",
        );
        let with = |release: &str| {
            format!("{llm}privacy:\n  terms: {{ CLIENT: [Dupont] }}\n  release:\n{release}")
        };
        assert!(Policy::parse(&with("    EMAIL: [human]\n    CLIENT: [human, agent]\n")).is_ok());
        for (bad, why) in [
            ("    EMAIL: [route:stripe]\n", "route de modèle"),
            ("    EMAIL: [route:inconnue]\n", "destination inconnue"),
            ("    EMAIL: [partout]\n", "destination inconnue"),
            ("    PROJET: [human]\n", "catégorie inconnue"),
        ] {
            let err = Policy::parse(&with(bad)).unwrap_err().to_string();
            assert!(err.contains(why), "{bad} : {err}");
        }
    }

    #[test]
    fn refuse_les_amonts_dangereux() {
        for up in [
            "http://api.stripe.com",
            "https://169.254.169.254",
            "https://metadata.google.internal",
            "ftp://x.com",
            "https://user:pw@x.com",
        ] {
            let yaml = BASE.replace("https://api.stripe.com", up);
            assert!(Policy::parse(&yaml).is_err(), "{up} aurait dû être refusé");
        }
        let local = BASE.replace("https://api.stripe.com", "http://127.0.0.1:9999");
        assert!(Policy::parse(&local).is_err());
        assert!(
            Policy::parse(&format!(
                "{local}network:\n  allow_insecure_loopback: true\n"
            ))
            .is_ok()
        );
    }

    #[test]
    fn refuse_les_variables_reservees() {
        assert!(Policy::parse(&BASE.replace("STRIPE_API_KEY", "LD_PRELOAD")).is_err());
        assert!(Policy::parse(&BASE.replace("STRIPE_API_KEY", "AESTHERIS_PASSWORD")).is_err());
    }

    #[test]
    fn hotes_autorises_et_adresses_internes() {
        let yaml = format!(
            "{BASE}network:\n  egress: allowlist\n  allow_hosts: [registry.npmjs.org, \"*.github.com\"]\nsandbox:\n  enabled: true\n"
        );
        let p = Policy::parse(&yaml).unwrap();
        assert!(p.host_allowed("registry.npmjs.org"));
        assert!(p.host_allowed("api.github.com"));
        assert!(!p.host_allowed("github.com.evil.io"));
        assert!(!p.host_allowed("evil.com"));
        assert!(p.is_route_host("api.stripe.com"));
        for ip in [
            "10.0.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "127.0.0.1",
            "100.100.100.200",
            "::1",
            "fd00::1",
            // multidiffusion, métadonnées hors lien local,
            // IPv4 cachées dans IPv6 (mappée, NAT64, 6to4)
            "224.0.0.251",
            "ff02::1",
            "0.1.2.3",
            "168.63.129.16",
            "192.0.0.192",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "2002:0a00:0001::1",
        ] {
            assert!(ip_forbidden(&ip.parse().unwrap(), false), "{ip}");
        }
        for ip in ["140.82.112.3", "2606:4700::1111", "64:ff9b::8c52:7003"] {
            assert!(!ip_forbidden(&ip.parse().unwrap(), false), "{ip}");
        }
        assert!(!ip_forbidden(&"127.0.0.1".parse().unwrap(), true));
        assert!(!ip_forbidden(&"::1".parse().unwrap(), true));
    }

    #[test]
    fn adresses_du_poste_lui_meme() {
        assert!(!is_own_address(&"8.8.8.8".parse().unwrap()));
        assert!(
            !is_own_address(&"127.0.0.1".parse().unwrap()),
            "boucle locale : régie à part"
        );
        // adresse de sortie du poste (aucun paquet envoyé) ; absente si le poste est hors ligne
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe.connect("192.0.2.1:9").is_ok() {
            let mine = probe.local_addr().unwrap().ip();
            if !mine.is_unspecified() {
                assert!(is_own_address(&mine), "{mine}");
            }
        }
    }

    #[test]
    fn sortie_restreinte_exige_le_bac_a_sable() {
        let yaml = format!("{BASE}network:\n  egress: none\n");
        assert!(Policy::parse(&yaml).is_err());
    }

    #[test]
    fn chemins_suspects() {
        assert!(validate_request_path("/v1/charges").is_ok());
        for p in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1%2fadmin",
            "/v1//x",
            "/v1/./x",
            "/v1\\x",
        ] {
            assert!(validate_request_path(p).is_err(), "{p}");
        }
    }
}
