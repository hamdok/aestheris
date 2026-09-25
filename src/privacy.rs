//! Bouclier de confidentialité : le fournisseur du modèle ne voit que des pseudonymes.
//!
//! ```text
//! agent ── « écris à marie@dupont.fr » ──▶ passerelle ── « écris à [EMAIL_1] » ──▶ fournisseur
//! agent ◀── outil : send(marie@dupont.fr) ── passerelle ◀── outil : send([EMAIL_1]) ── fournisseur
//! ```
//!
//! - **Requête** : chaque valeur sensible (courriel, téléphone, IBAN, carte, adresse IP, et les noms
//!   que l'entreprise déclare : clients, projets…) devient un pseudonyme typé et numéroté. La même
//!   valeur garde le même pseudonyme pendant toute la session (le modèle suit la conversation).
//! - **Réponse** : les pseudonymes redeviennent les vraies valeurs **sur la machine**, y compris
//!   dans les réponses diffusées en continu (SSE) et dans les arguments des appels d'outils : l'agent
//!   agit sur les vraies données, le fournisseur ne les a jamais vues.
//! - **Raisonnement du modèle** (`thinking`) : jamais modifié, ni à l'aller ni au retour. Il est
//!   signé par le fournisseur et ne contient de toute façon que des pseudonymes.
//! - **Métadonnées** : identifiants d'utilisateur et de session, informations sur le poste
//!   (`metadata.user_id`, `user`, en-têtes `x-stainless-*`) retirés.
//! - **Registre d'exposition** : chaque requête note les catégories pseudonymisées (jamais les
//!   valeurs) dans le journal d'audit.
//! - **Données fantômes** (`privacy.release`) : comme les jetons fantômes pour les clés, une
//!   valeur ne redevient réelle que là où la politique le permet : à l'écran (`human`), dans les
//!   actions de l'agent (`agent`), ou seulement à la sortie vers certains services
//!   (`route:crm`). Ailleurs, elle reste un pseudonyme : un agent détourné par une injection de
//!   prompt ne peut exfiltrer que des pseudonymes, sans modifier les agents existants.
//!
//! Formats pris en charge : API Messages d'Anthropic, Chat Completions et Responses d'OpenAI.

use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

/// Catégories détectées automatiquement.
pub const BUILTIN: &[&str] = &["email", "phone", "iban", "card", "ip"];

/// Clés dont la valeur n'est jamais modifiée : données binaires (images, documents), signatures.
const SKIP_KEYS: &[&str] = &["data", "signature"];

struct Detector {
    label: &'static str,
    re: Regex,
    valid: fn(&str) -> bool,
}

/// (catégorie de la politique, libellé du pseudonyme, motif, validation)
type DetectorDef = (&'static str, &'static str, &'static str, fn(&str) -> bool);

fn detectors(kinds: &[String]) -> Vec<Detector> {
    let all: [DetectorDef; 5] = [
        // IBAN et cartes avant les téléphones : des chiffres groupés qui se ressemblent
        (
            "iban",
            "IBAN",
            r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
            iban_ok,
        ),
        ("card", "CARTE", r"\b\d(?:[ -]?\d){12,18}\b", card_ok),
        (
            "email",
            "EMAIL",
            r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b",
            |_| true,
        ),
        (
            "phone",
            "TEL",
            r"(?:\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,5}|\b0[1-9](?:[ .-]?\d{2}){4})\b",
            phone_ok,
        ),
        (
            "ip",
            "IP",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            |s| !s.starts_with("127.") && s != "0.0.0.0",
        ),
    ];
    all.into_iter()
        .filter(|(k, ..)| kinds.iter().any(|x| x == k))
        .map(|(_, label, re, valid)| Detector {
            label,
            re: Regex::new(re).expect("motif de confidentialité valide"),
            valid,
        })
        .collect()
}

fn iban_ok(s: &str) -> bool {
    let c: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&c.len()) {
        return false;
    }
    let (head, tail) = c.split_at(4);
    let mut rem: u32 = 0;
    for ch in tail.chars().chain(head.chars()) {
        let v = match ch.to_digit(36) {
            Some(v) => v,
            None => return false,
        };
        for d in v.to_string().chars() {
            rem = (rem * 10 + d.to_digit(10).unwrap_or(0)) % 97;
        }
    }
    rem == 1
}

fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                if d * 2 > 9 { d * 2 - 9 } else { d * 2 }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Carte bancaire : clé de Luhn **et** préfixe d'un vrai réseau (sinon un horodatage de 13 chiffres
/// passerait une fois sur dix).
fn card_ok(s: &str) -> bool {
    let d: String = s.chars().filter(char::is_ascii_digit).collect();
    let n = d.len();
    let p2: u32 = d[..2].parse().unwrap_or(0);
    let p4: u32 = d[..4].parse().unwrap_or(0);
    let network = (d.starts_with('4') && [13, 16, 19].contains(&n)) // Visa
        || (((51..=55).contains(&p2) || (2221..=2720).contains(&p4)) && n == 16) // Mastercard
        || ((p2 == 34 || p2 == 37) && n == 15) // American Express
        || ((d.starts_with("6011") || p2 == 65) && (16..=19).contains(&n)) // Discover
        || ((3528..=3589).contains(&p4) && (16..=19).contains(&n)); // JCB
    network && luhn_ok(s)
}

fn phone_ok(s: &str) -> bool {
    (8..=15).contains(&s.chars().filter(char::is_ascii_digit).count())
}

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[([A-Z][A-Z_]*)_(\d+)\]").expect("motif valide"))
}

/// Début possible d'un pseudonyme en fin de fragment (« [EMA », « [EMAIL_1 ») : à retenir.
fn partial_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\[[A-Z_]*\d*$").expect("motif valide"))
}

#[derive(Default)]
struct Mapping {
    /// (catégorie, valeur normalisée) → pseudonyme
    to_token: HashMap<(String, String), String>,
    /// pseudonyme → valeur d'origine
    to_value: HashMap<String, String>,
    /// pseudonyme → service d'où vient la valeur (routes `phantom: true`)
    origin: HashMap<String, String>,
    counters: HashMap<String, u32>,
}

/// Réglages (issus de la politique).
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub kinds: Vec<String>,
    /// Catégorie (ex. CLIENT) → noms à ne jamais montrer au fournisseur.
    pub terms: BTreeMap<String, Vec<String>>,
    pub strip_metadata: bool,
    /// Identité du poste (nom d'utilisateur, nom de la machine, nom Git) : pseudonymisée.
    pub identity: bool,
    /// Données fantômes : catégorie (ou `*`) → où la vraie valeur peut réapparaître
    /// (`human`, `agent`, `route:<nom>`). Catégorie absente : `human` et `agent`.
    pub release: BTreeMap<String, Vec<String>>,
    /// Provenance : service source → où ses valeurs peuvent réapparaître (en plus de `release`).
    pub origins: BTreeMap<String, Vec<String>>,
}

/// Où une valeur rétablie va aller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink<'a> {
    /// Texte montré à l'humain.
    Human,
    /// Arguments des actions de l'agent (appels d'outils).
    Agent,
    /// Requête sortante vers une route de la passerelle.
    Route(&'a str),
}

impl Sink<'_> {
    fn matches(&self, rule: &str) -> bool {
        match self {
            Sink::Human => rule == "human",
            Sink::Agent => rule == "agent",
            Sink::Route(r) => rule.strip_prefix("route:") == Some(r),
        }
    }
}

/// Noms trop courants pour être pseudonymisés partout sans abîmer le texte.
const COMMON_NAMES: &[&str] = &[
    "user",
    "admin",
    "root",
    "test",
    "guest",
    "ubuntu",
    "runner",
    "debian",
    "ec2-user",
    "localhost",
    "home",
    "work",
    "main",
    "code",
    "agent",
];

/// Ce qui identifie le poste et la personne : nom d'utilisateur (visible dans chaque chemin,
/// `/Users/…`), nom de la machine (souvent le prénom : « MacBook-Air-de-… »), nom Git.
pub fn local_identity() -> BTreeMap<String, Vec<String>> {
    let keep = |s: &str| {
        let s = s.trim();
        s.chars().count() >= 4 && !COMMON_NAMES.contains(&s.to_lowercase().as_str())
    };
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let user = std::env::var("USER").ok().or_else(|| {
        dirs::home_dir().and_then(|h| h.file_name().map(|n| n.to_string_lossy().into_owned()))
    });
    if let Some(u) = user.filter(|u| keep(u)) {
        out.entry("UTILISATEUR".into()).or_default().push(u);
    }
    let mut buf = [0u8; 256];
    // SAFETY: tampon local, taille annoncée.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let host = String::from_utf8_lossy(&buf[..end]).into_owned();
        let short = host.trim_end_matches(".local").to_string();
        for h in [host, short] {
            if keep(&h) {
                out.entry("MACHINE".into()).or_default().push(h);
            }
        }
    }
    if let Ok(o) = std::process::Command::new("git")
        .args(["config", "--global", "user.name"])
        .output()
    {
        let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if o.status.success() && keep(&name) {
            out.entry("NOM".into()).or_default().push(name);
        }
    }
    out
}

/// Bouclier d'une session : ses pseudonymes sont stables d'une requête à l'autre.
pub struct Shield {
    detectors: Vec<Detector>,
    /// Termes de l'entreprise, du plus long au plus court : (catégorie, terme en minuscules, motif).
    terms: Vec<(String, Regex)>,
    strip_metadata: bool,
    release: BTreeMap<String, Vec<String>>,
    origins: BTreeMap<String, Vec<String>>,
    map: Mutex<Mapping>,
}

/// Catégories pseudonymisées dans une requête (pour le registre d'exposition).
pub type Counts = BTreeMap<String, u32>;

impl Shield {
    pub fn new(s: &Settings) -> Self {
        let mut all = s.terms.clone();
        if s.identity {
            for (cat, names) in local_identity() {
                all.entry(cat).or_default().extend(names);
            }
        }
        let mut terms: Vec<(String, String)> = all
            .iter()
            .flat_map(|(cat, list)| {
                list.iter()
                    .map(move |t| (cat.clone(), t.trim().to_string()))
            })
            .filter(|(_, t)| !t.is_empty())
            .collect();
        terms.sort_by_key(|(_, t)| std::cmp::Reverse(t.chars().count()));
        let terms = terms
            .into_iter()
            .map(|(cat, t)| {
                let re = Regex::new(&format!("(?i){}", regex::escape(&t))).expect("terme échappé");
                (cat, re)
            })
            .collect();
        Self {
            detectors: detectors(&s.kinds),
            terms,
            strip_metadata: s.strip_metadata,
            release: s.release.clone(),
            origins: s.origins.clone(),
            map: Mutex::new(Mapping::default()),
        }
    }

    /// La catégorie `label` peut-elle redevenir réelle vers `sink` ?
    pub fn allows(&self, label: &str, sink: Sink) -> bool {
        match self.release.get(label).or_else(|| self.release.get("*")) {
            Some(rules) => rules.iter().any(|r| sink.matches(r)),
            None => matches!(sink, Sink::Human | Sink::Agent),
        }
    }

    pub fn strips_metadata(&self) -> bool {
        self.strip_metadata
    }

    /// Pseudonyme d'une valeur. La première provenance connue est retenue : une valeur vue d'abord
    /// dans le CRM reste soumise aux règles du CRM, même si l'utilisateur la retape ensuite.
    fn token_for(&self, label: &str, value: &str, origin: Option<&str>) -> String {
        let mut m = self.map.lock().expect("verrou");
        let key = (label.to_string(), value.to_lowercase());
        if let Some(t) = m.to_token.get(&key) {
            return t.clone();
        }
        let n = m.counters.entry(label.to_string()).or_insert(0);
        *n += 1;
        let token = format!("[{label}_{n}]");
        m.to_token.insert(key, token.clone());
        m.to_value.insert(token.clone(), value.to_string());
        if let Some(o) = origin {
            m.origin.insert(token.clone(), o.to_string());
        }
        token
    }

    /// Provenance d'un pseudonyme (pour les tests et le journal).
    pub fn origin_of(&self, token: &str) -> Option<String> {
        self.map.lock().expect("verrou").origin.get(token).cloned()
    }

    /// Remplace les valeurs sensibles d'un texte par leurs pseudonymes. Les formats (courriel,
    /// IBAN…) passent d'abord, pour qu'un nom déclaré ne coupe pas une adresse
    /// (`jean@acme.io` → `[EMAIL_1]`, pas `jean@[CLIENT_1].io`) ; les noms ne touchent jamais
    /// l'intérieur d'un pseudonyme déjà posé.
    pub fn pseudonymize_text(&self, text: &str, counts: &mut Counts) -> String {
        self.pseudonymize_from(text, counts, None)
    }

    /// Comme `pseudonymize_text`, en notant la provenance des valeurs nouvelles.
    pub fn pseudonymize_from(
        &self,
        text: &str,
        counts: &mut Counts,
        origin: Option<&str>,
    ) -> String {
        let mut out = text.to_string();
        for d in &self.detectors {
            out =
                d.re.replace_all(&out, |c: &regex::Captures| {
                    let m = &c[0];
                    if (d.valid)(m) {
                        *counts.entry(d.label.to_string()).or_insert(0) += 1;
                        self.token_for(d.label, m, origin)
                    } else {
                        m.to_string()
                    }
                })
                .into_owned();
        }
        for (cat, re) in &self.terms {
            out = outside_tokens(&out, |segment| {
                replace_bounded(segment, re, |m| {
                    *counts.entry(cat.clone()).or_insert(0) += 1;
                    self.token_for(cat, m, origin)
                })
            });
        }
        out
    }

    /// Réponse du modèle : le texte va à l'humain, le JSON (arguments d'outils) à l'agent ;
    /// `json` : valeurs échappées pour être insérées dans du texte JSON.
    pub fn rehydrate_text(&self, text: &str, json: bool) -> String {
        let sink = if json { Sink::Agent } else { Sink::Human };
        self.rehydrate_for(
            text,
            sink,
            if json { Escape::Json } else { Escape::None },
            &mut Counts::new(),
            &mut Counts::new(),
        )
    }

    /// Rétablit les pseudonymes permis vers `sink` ; compte ce qui est libéré et ce qui est retenu.
    fn rehydrate_for(
        &self,
        text: &str,
        sink: Sink,
        escape: Escape,
        released: &mut Counts,
        withheld: &mut Counts,
    ) -> String {
        let m = self.map.lock().expect("verrou");
        let re = if escape == Escape::UrlEncodedToken {
            encoded_token_re()
        } else {
            token_re()
        };
        re.replace_all(text, |c: &regex::Captures| {
            let label = c[1].to_ascii_uppercase();
            let token = format!("[{label}_{}]", &c[2]);
            // La provenance décide pour les données venues d'une source ; une règle de catégorie
            // écrite explicitement restreint encore ; sinon, écran et agent seulement.
            let by_origin = m.origin.get(&token).and_then(|o| self.origins.get(o));
            let by_category = self.release.get(&label).or_else(|| self.release.get("*"));
            let ok = |rules: &Vec<String>| rules.iter().any(|r| sink.matches(r));
            let allowed = match (by_origin, by_category) {
                (Some(o), Some(c)) => ok(o) && ok(c),
                (Some(o), None) => ok(o),
                (None, Some(c)) => ok(c),
                (None, None) => matches!(sink, Sink::Human | Sink::Agent),
            };
            match m.to_value.get(&token) {
                Some(v) if allowed => {
                    *released.entry(label).or_insert(0) += 1;
                    match escape {
                        Escape::None => v.clone(),
                        Escape::Json => {
                            let quoted = serde_json::to_string(v).unwrap_or_default();
                            quoted[1..quoted.len().saturating_sub(1)].to_string()
                        }
                        Escape::Url | Escape::UrlEncodedToken => form_encode(v),
                    }
                }
                Some(_) => {
                    *withheld.entry(label).or_insert(0) += 1;
                    c[0].to_string()
                }
                None => c[0].to_string(),
            }
        })
        .into_owned()
    }

    /// Réponse d'une source de données (`phantom: true`) : toutes ses valeurs sensibles deviennent
    /// des pseudonymes marqués de leur provenance, avant d'atteindre l'agent. Contrairement aux
    /// requêtes des modèles, rien n'est ignoré (les API rangent souvent leurs listes sous `data`).
    /// `None` : contenu binaire, transmis tel quel.
    pub fn pseudonymize_data(
        &self,
        body: &[u8],
        content_type: &str,
        origin: &str,
    ) -> Option<(Vec<u8>, Counts)> {
        let mut counts = Counts::new();
        if content_type.contains("json")
            && let Ok(mut v) = serde_json::from_slice::<Value>(body)
        {
            fn all(v: &mut Value, f: &mut dyn FnMut(&mut String)) {
                match v {
                    Value::String(s) => f(s),
                    Value::Array(a) => a.iter_mut().for_each(|x| all(x, f)),
                    Value::Object(o) => o.values_mut().for_each(|x| all(x, f)),
                    _ => {}
                }
            }
            all(&mut v, &mut |s| {
                *s = self.pseudonymize_from(s, &mut counts, Some(origin))
            });
            return Some((serde_json::to_vec(&v).unwrap_or_default(), counts));
        }
        let text = std::str::from_utf8(body).ok()?;
        Some((
            self.pseudonymize_from(text, &mut counts, Some(origin))
                .into_bytes(),
            counts,
        ))
    }

    /// Requête sortante vers une route (hors routes de modèles) : les pseudonymes permis pour cette
    /// route redeviennent réels, les autres restent des pseudonymes. `None` : aucun pseudonyme.
    pub fn release_for_route(
        &self,
        body: &[u8],
        query: Option<&str>,
        content_type: &str,
        route: &str,
    ) -> Option<Released> {
        let text = String::from_utf8_lossy(body);
        let has = |s: &str| token_re().is_match(s) || encoded_token_re().is_match(s);
        if !has(&text) && !query.is_some_and(has) {
            return None;
        }
        let sink = Sink::Route(route);
        let (mut released, mut withheld) = (Counts::new(), Counts::new());
        let body = if content_type.contains("json") {
            match serde_json::from_slice::<Value>(body) {
                Ok(mut v) => {
                    self.walk(&mut v, &mut |s| {
                        *s = self.rehydrate_for(s, sink, Escape::None, &mut released, &mut withheld)
                    });
                    serde_json::to_vec(&v).unwrap_or_default()
                }
                Err(_) => body.to_vec(),
            }
        } else if content_type.contains("x-www-form-urlencoded") {
            // pseudonymes encodés (%5BEMAIL_1%5D) puis écrits en clair ([EMAIL_1]) : valeur encodée
            let t = self.rehydrate_for(
                &text,
                sink,
                Escape::UrlEncodedToken,
                &mut released,
                &mut withheld,
            );
            self.rehydrate_for(&t, sink, Escape::Url, &mut released, &mut withheld)
                .into_bytes()
        } else if std::str::from_utf8(body).is_ok() {
            self.rehydrate_for(&text, sink, Escape::None, &mut released, &mut withheld)
                .into_bytes()
        } else {
            body.to_vec()
        };
        let query = query.map(|q| {
            let t = self.rehydrate_for(
                q,
                sink,
                Escape::UrlEncodedToken,
                &mut released,
                &mut withheld,
            );
            self.rehydrate_for(&t, sink, Escape::Url, &mut released, &mut withheld)
        });
        Some(Released {
            body,
            query,
            released,
            withheld,
        })
    }

    /// Requête JSON : pseudonymise toutes les chaînes (sauf raisonnement, données binaires,
    /// signatures) et retire les métadonnées identifiantes.
    pub fn pseudonymize_request(&self, body: &mut Value) -> Counts {
        let mut counts = Counts::new();
        if self.strip_metadata
            && let Some(o) = body.as_object_mut()
        {
            o.remove("user"); // OpenAI : identifiant de l'utilisateur final
            if let Some(meta) = o.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.remove("user_id"); // Anthropic (Claude Code y met utilisateur et session)
            }
        }
        self.walk(body, &mut |s| *s = self.pseudonymize_text(s, &mut counts));
        counts
    }

    /// Réponse JSON complète : le texte va à l'humain, les appels d'outils (`input`,
    /// `arguments`) à l'agent.
    pub fn rehydrate_response(&self, body: &mut Value) {
        self.walk_sinks(body, Sink::Human);
    }

    fn walk_sinks(&self, v: &mut Value, sink: Sink) {
        match v {
            Value::String(s) => {
                let escape = Escape::None;
                *s = self.rehydrate_for(s, sink, escape, &mut Counts::new(), &mut Counts::new());
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.walk_sinks(x, sink)),
            Value::Object(o) => {
                let kind = o
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if kind == "thinking" || kind == "redacted_thinking" || kind == "reasoning" {
                    return;
                }
                let tool =
                    kind == "tool_use" || kind == "function_call" || o.contains_key("function");
                for (k, x) in o.iter_mut() {
                    if SKIP_KEYS.contains(&k.as_str()) {
                        continue;
                    }
                    let child = if tool || k == "input" || k == "arguments" || k == "tool_calls" {
                        Sink::Agent
                    } else {
                        sink
                    };
                    self.walk_sinks(x, child);
                }
            }
            _ => {}
        }
    }

    fn walk(&self, v: &mut Value, f: &mut dyn FnMut(&mut String)) {
        match v {
            Value::String(s) => f(s),
            Value::Array(a) => a.iter_mut().for_each(|x| self.walk(x, f)),
            Value::Object(o) => {
                let kind = o.get("type").and_then(Value::as_str).unwrap_or("");
                if kind == "thinking" || kind == "redacted_thinking" || kind == "reasoning" {
                    return;
                }
                for (k, x) in o.iter_mut() {
                    if !SKIP_KEYS.contains(&k.as_str()) {
                        self.walk(x, f);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Résultat de la libération vers une route.
pub struct Released {
    pub body: Vec<u8>,
    pub query: Option<String>,
    pub released: Counts,
    pub withheld: Counts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    Json,
    /// pseudonyme écrit en clair, valeur encodée pour un formulaire
    Url,
    /// pseudonyme lui-même encodé (%5BEMAIL_1%5D), valeur encodée
    UrlEncodedToken,
}

/// Pseudonyme encodé dans un formulaire ou une URL : `%5BEMAIL_1%5D`.
fn encoded_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)%5B([A-Z][A-Z_]*)_(\d+)%5D").expect("motif valide"))
}

/// Encodage `application/x-www-form-urlencoded`.
fn form_encode(v: &str) -> String {
    let mut out = String::new();
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Applique `f` aux morceaux de texte situés hors des pseudonymes.
fn outside_tokens(text: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in token_re().find_iter(text) {
        out.push_str(&f(&text[last..m.start()]));
        out.push_str(m.as_str());
        last = m.end();
    }
    out.push_str(&f(&text[last..]));
    out
}

/// Remplacement avec frontières de mots vérifiées à la main (un terme peut commencer ou finir
/// par un signe, ex. « Acme S.A. », que `\b` gérerait mal).
fn replace_bounded(text: &str, re: &Regex, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in re.find_iter(text) {
        let before = text[..m.start()].chars().next_back();
        let after = text[m.end()..].chars().next();
        let bounded = before.is_none_or(|c| !c.is_alphanumeric())
            && after.is_none_or(|c| !c.is_alphanumeric());
        if bounded {
            out.push_str(&text[last..m.start()]);
            out.push_str(&f(m.as_str()));
            last = m.end();
        }
    }
    out.push_str(&text[last..]);
    out
}

/* ------------------------------------------------------------------ */
/* Réponses diffusées en continu (SSE)                                 */
/* ------------------------------------------------------------------ */

/// Réécrit un flux SSE au fil de l'eau. Un pseudonyme peut être coupé entre deux fragments
/// (« [EMA » puis « IL_1] ») : la fin douteuse d'un fragment est retenue jusqu'au suivant, puis
/// rendue à la fin du bloc.
pub struct StreamRehydrator {
    shield: std::sync::Arc<Shield>,
    buf: Vec<u8>,
    /// clé du fragment (bloc, choix, appel d'outil) → texte retenu et nature (JSON ou texte)
    carry: BTreeMap<String, (String, bool)>,
}

impl StreamRehydrator {
    pub fn new(shield: std::sync::Arc<Shield>) -> Self {
        Self {
            shield,
            buf: Vec::new(),
            carry: BTreeMap::new(),
        }
    }

    /// Octets reçus du fournisseur → octets à transmettre à l'agent.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((end, sep)) = find_event_end(&self.buf) {
            let raw: Vec<u8> = self.buf.drain(..end + sep).collect();
            let text = String::from_utf8_lossy(&raw[..end]).into_owned();
            out.extend(self.event(&text).into_bytes());
        }
        out
    }

    /// Fin du flux : le reste est transmis tel quel.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    fn event(&mut self, raw: &str) -> String {
        let mut name = None;
        let mut data = String::new();
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("event:") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(v.strip_prefix(' ').unwrap_or(v));
            }
        }
        let emit = |name: &Option<String>, v: &Value| {
            let mut s = String::new();
            if let Some(n) = name {
                s.push_str(&format!("event: {n}\n"));
            }
            s.push_str(&format!(
                "data: {}\n\n",
                serde_json::to_string(v).unwrap_or_default()
            ));
            s
        };
        if data.trim() == "[DONE]" {
            return format!("{}{raw}\n\n", self.flush_openai_all());
        }
        let Ok(mut v) = serde_json::from_str::<Value>(&data) else {
            return format!("{raw}\n\n");
        };
        let kind = v
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut prefix = String::new();
        match kind.as_str() {
            // --- Anthropic
            "content_block_delta" => {
                let idx = v["index"].as_u64().unwrap_or(0);
                let dtype = v["delta"]["type"].as_str().unwrap_or("").to_string();
                let (field, json) = match dtype.as_str() {
                    "text_delta" => ("text", false),
                    "input_json_delta" => ("partial_json", true),
                    _ => return emit(&name, &v), // raisonnement, signature : intacts
                };
                let frag = v["delta"][field].as_str().unwrap_or("").to_string();
                let key = format!("a:{idx}");
                let text = self.process(&key, &frag, json);
                if text.is_empty() {
                    return String::new();
                }
                v["delta"][field] = Value::String(text);
            }
            "content_block_stop" => {
                let idx = v["index"].as_u64().unwrap_or(0);
                if let Some((rest, json)) = self.carry.remove(&format!("a:{idx}")) {
                    let (dtype, field) = if json {
                        ("input_json_delta", "partial_json")
                    } else {
                        ("text_delta", "text")
                    };
                    let flushed = self.shield.rehydrate_text(&rest, json);
                    let delta = serde_json::json!({
                        "type": "content_block_delta",
                        "index": idx,
                        "delta": { "type": dtype, field: flushed }
                    });
                    prefix = emit(&Some("content_block_delta".into()), &delta);
                }
            }
            // --- OpenAI Responses
            "response.output_text.delta" | "response.function_call_arguments.delta" => {
                let json = kind.starts_with("response.function_call");
                let key = format!(
                    "r:{}:{}",
                    v["item_id"].as_str().unwrap_or(""),
                    v["content_index"].as_u64().unwrap_or(0)
                );
                let frag = v["delta"].as_str().unwrap_or("").to_string();
                let text = self.process(&key, &frag, json);
                if text.is_empty() {
                    return String::new();
                }
                v["delta"] = Value::String(text);
            }
            "response.output_text.done" | "response.function_call_arguments.done" => {
                let json = kind.starts_with("response.function_call");
                let key = format!(
                    "r:{}:{}",
                    v["item_id"].as_str().unwrap_or(""),
                    v["content_index"].as_u64().unwrap_or(0)
                );
                if let Some((rest, _)) = self.carry.remove(&key) {
                    let mut delta = v.clone();
                    delta["type"] = Value::String(kind.replace(".done", ".delta"));
                    if let Some(o) = delta.as_object_mut() {
                        o.remove("text");
                        o.remove("arguments");
                    }
                    delta["delta"] = Value::String(self.shield.rehydrate_text(&rest, json));
                    prefix = emit(&name, &delta);
                }
                // le texte complet de clôture, lui, est entier
                for field in ["text", "arguments"] {
                    if let Some(s) = v[field].as_str() {
                        let full = self.shield.rehydrate_text(s, field == "arguments");
                        v[field] = Value::String(full);
                    }
                }
            }
            _ if v.get("choices").is_some() => self.openai_chat_chunk(&mut v),
            _ if kind.starts_with("response.") => self.shield.rehydrate_response(&mut v),
            _ => {}
        }
        prefix + &emit(&name, &v)
    }

    /// OpenAI Chat Completions : texte et arguments d'outils, par choix.
    fn openai_chat_chunk(&mut self, v: &mut Value) {
        let Some(choices) = v.get_mut("choices").and_then(Value::as_array_mut) else {
            return;
        };
        for choice in choices {
            let ci = choice["index"].as_u64().unwrap_or(0);
            let finished = !choice["finish_reason"].is_null();
            if let Some(frag) = choice["delta"]["content"].as_str().map(str::to_string) {
                let text = self.process(&format!("o:{ci}:c"), &frag, false);
                choice["delta"]["content"] = Value::String(text);
            }
            if let Some(calls) = choice["delta"]["tool_calls"].as_array_mut() {
                for call in calls {
                    let ti = call["index"].as_u64().unwrap_or(0);
                    if let Some(frag) = call["function"]["arguments"].as_str().map(str::to_string) {
                        let text = self.process(&format!("o:{ci}:t:{ti}"), &frag, true);
                        call["function"]["arguments"] = Value::String(text);
                    }
                }
            }
            if finished {
                self.flush_openai_choice(ci, choice);
            }
        }
    }

    fn flush_openai_choice(&mut self, ci: u64, choice: &mut Value) {
        let keys: Vec<String> = self
            .carry
            .keys()
            .filter(|k| k.starts_with(&format!("o:{ci}:")))
            .cloned()
            .collect();
        for key in keys {
            let (rest, json) = self.carry.remove(&key).unwrap_or_default();
            let flushed = self.shield.rehydrate_text(&rest, json);
            if key.ends_with(":c") {
                let before = choice["delta"]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                choice["delta"]["content"] = Value::String(before + &flushed);
            } else if let Some(ti) = key.rsplit(':').next().and_then(|t| t.parse::<u64>().ok()) {
                let call = serde_json::json!({ "index": ti, "function": { "arguments": flushed } });
                match choice["delta"]["tool_calls"].as_array_mut() {
                    Some(a) => a.push(call),
                    None => choice["delta"]["tool_calls"] = Value::Array(vec![call]),
                }
            }
        }
    }

    /// Avant `[DONE]` : ce qui reste retenu est rendu dans un fragment supplémentaire.
    fn flush_openai_all(&mut self) -> String {
        let keys: Vec<String> = self
            .carry
            .keys()
            .filter(|k| k.starts_with("o:"))
            .cloned()
            .collect();
        let mut out = String::new();
        for key in keys {
            let (rest, json) = self.carry.remove(&key).unwrap_or_default();
            let flushed = self.shield.rehydrate_text(&rest, json);
            let parts: Vec<&str> = key.split(':').collect();
            let ci: u64 = parts.get(1).and_then(|x| x.parse().ok()).unwrap_or(0);
            let delta = if key.ends_with(":c") {
                serde_json::json!({ "content": flushed })
            } else {
                let ti: u64 = parts.get(3).and_then(|x| x.parse().ok()).unwrap_or(0);
                serde_json::json!({ "tool_calls": [{ "index": ti, "function": { "arguments": flushed } }] })
            };
            let chunk = serde_json::json!({ "choices": [{ "index": ci, "delta": delta, "finish_reason": null }] });
            out.push_str(&format!("data: {}\n\n", chunk));
        }
        out
    }

    /// Ajoute le fragment au texte retenu, rend ce qui est sûr et retient une fin douteuse.
    fn process(&mut self, key: &str, fragment: &str, json: bool) -> String {
        let mut text = self.carry.remove(key).map(|(t, _)| t).unwrap_or_default();
        text.push_str(fragment);
        let hold_from = text
            .rfind('[')
            .filter(|&p| text.len() - p <= 40 && partial_token_re().is_match(&text[p..]));
        let (ready, held) = match hold_from {
            Some(p) => (text[..p].to_string(), text[p..].to_string()),
            None => (text, String::new()),
        };
        if !held.is_empty() {
            self.carry.insert(key.to_string(), (held, json));
        }
        self.shield.rehydrate_text(&ready, json)
    }
}

/// Fin d'un événement SSE : position et longueur du séparateur (« \n\n » ou « \r\n\r\n »).
fn find_event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2));
    let crlf = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn shield() -> Arc<Shield> {
        let mut terms = BTreeMap::new();
        terms.insert(
            "CLIENT".to_string(),
            vec!["Dupont SA".to_string(), "Acme".to_string()],
        );
        terms.insert("PROJET".to_string(), vec!["Phoenix".to_string()]);
        Arc::new(Shield::new(&Settings {
            kinds: BUILTIN.iter().map(|s| s.to_string()).collect(),
            terms,
            strip_metadata: true,
            identity: false,
            release: BTreeMap::new(),
            origins: BTreeMap::new(),
        }))
    }

    #[test]
    fn detecte_et_pseudonymise_de_facon_stable() {
        let s = shield();
        let mut c = Counts::new();
        let text = "Écris à marie.durand@dupont.fr (Dupont SA, projet phoenix), tél. +33 6 12 34 56 78, \
                    IBAN FR76 3000 6000 0112 3456 7890 189, carte 4111 1111 1111 1111, serveur 10.2.3.4.";
        let p = s.pseudonymize_text(text, &mut c);
        for secret in [
            "marie.durand",
            "Dupont SA",
            "phoenix",
            "12 34 56",
            "FR76",
            "4111",
            "10.2.3.4",
        ] {
            assert!(!p.contains(secret), "{secret} visible : {p}");
        }
        assert!(p.contains("[EMAIL_1]") && p.contains("[CLIENT_1]") && p.contains("[PROJET_1]"));
        assert!(
            p.contains("[TEL_1]")
                && p.contains("[IBAN_1]")
                && p.contains("[CARTE_1]")
                && p.contains("[IP_1]")
        );
        // même valeur → même pseudonyme, d'une requête à l'autre (et quelle que soit la casse)
        let again = s.pseudonymize_text(
            "Relance DUPONT SA et marie.durand@dupont.fr",
            &mut Counts::new(),
        );
        assert_eq!(again, "Relance [CLIENT_1] et [EMAIL_1]");
        assert_eq!(s.rehydrate_text(&p, false), text);
        assert_eq!(c["EMAIL"], 1);
    }

    #[test]
    fn ne_confond_pas_les_nombres_ordinaires() {
        let s = shield();
        let text =
            "version 1.2.3, horodatage 1790294748598, commande n°123456789, Acmeco, 127.0.0.1";
        assert_eq!(s.pseudonymize_text(text, &mut Counts::new()), text);
    }

    #[test]
    fn requete_json_raisonnement_et_metadonnees() {
        let s = shield();
        let mut body = serde_json::json!({
            "model": "claude-x",
            "metadata": { "user_id": "user_abc_account__session_123" },
            "messages": [
                { "role": "user", "content": [{ "type": "text", "text": "Facture pour Acme : jean@acme.io" }] },
                { "role": "assistant", "content": [
                    { "type": "thinking", "thinking": "Acme [EMAIL_1]", "signature": "sig" },
                    { "type": "tool_use", "id": "t1", "name": "send", "input": { "to": "jean@acme.io" } }
                ]},
                { "role": "user", "content": [{ "type": "image", "source": { "type": "base64", "data": "QWNtZQ==" } }] }
            ]
        });
        let counts = s.pseudonymize_request(&mut body);
        let text = body.to_string();
        assert!(!text.contains("jean@acme.io") && !text.contains("user_abc"));
        assert!(text.contains("Facture pour [CLIENT_1] : [EMAIL_1]"));
        assert_eq!(
            body["messages"][1]["content"][0]["thinking"], "Acme [EMAIL_1]",
            "raisonnement signé intact"
        );
        assert_eq!(
            body["messages"][1]["content"][1]["input"]["to"],
            "[EMAIL_1]"
        );
        assert_eq!(
            body["messages"][2]["content"][0]["source"]["data"],
            "QWNtZQ=="
        );
        assert_eq!(counts["EMAIL"], 2);
    }

    #[test]
    fn flux_anthropic_pseudonymes_coupes_et_appels_d_outils() {
        let s = shield();
        s.pseudonymize_text("jean@acme.io Dupont SA", &mut Counts::new()); // [EMAIL_1] [CLIENT_1]
        let mut r = StreamRehydrator::new(s.clone());
        let ev = |t: &str, delta: Value| {
            format!(
                "event: {t}\ndata: {}\n\n",
                serde_json::json!({ "type": t, "index": 0, "delta": delta })
            )
        };
        let stream = [
            ev("content_block_delta", serde_json::json!({"type":"text_delta","text":"Bonjour [CLI"})),
            ev("content_block_delta", serde_json::json!({"type":"text_delta","text":"ENT_1], j'écris à [EMAIL_"})),
            ev("content_block_delta", serde_json::json!({"type":"text_delta","text":"1] ["})),
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
            ev("content_block_delta", serde_json::json!({"type":"input_json_delta","partial_json":"{\"to\": \"[EMAIL_1"})),
            ev("content_block_delta", serde_json::json!({"type":"input_json_delta","partial_json":"]\", \"q\": \"O\\\"Neil\"}"})),
        ]
        .concat();
        // livré en morceaux arbitraires, coupés au milieu des événements
        let mut out = Vec::new();
        for chunk in stream.as_bytes().chunks(7) {
            out.extend(r.push(chunk));
        }
        out.extend(r.finish());
        let out = String::from_utf8(out).unwrap();
        let mut text = String::new();
        let mut json = String::new();
        for line in out.lines().filter_map(|l| l.strip_prefix("data: ")) {
            let v: Value = serde_json::from_str(line).unwrap();
            text.push_str(v["delta"]["text"].as_str().unwrap_or(""));
            json.push_str(v["delta"]["partial_json"].as_str().unwrap_or(""));
        }
        assert_eq!(text, "Bonjour Dupont SA, j'écris à jean@acme.io [");
        let args: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(args["to"], "jean@acme.io");
        assert_eq!(args["q"], "O\"Neil");
    }

    #[test]
    fn flux_openai_chat() {
        let s = shield();
        s.pseudonymize_text("jean@acme.io", &mut Counts::new());
        let mut r = StreamRehydrator::new(s.clone());
        let chunk = |content: &str, finish: Option<&str>| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"choices":[{"index":0,"delta":{"content":content},"finish_reason":finish}]})
            )
        };
        let stream = [
            chunk("à [EMA", None),
            chunk("IL_1] ok [", None),
            chunk("", Some("stop")),
            "data: [DONE]\n\n".into(),
        ]
        .concat();
        let out = String::from_utf8(r.push(stream.as_bytes())).unwrap();
        let text: String = out
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter(|l| *l != "[DONE]")
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["choices"][0]["delta"]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(text, "à jean@acme.io ok [");
        assert!(out.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn identite_du_poste_et_chemins() {
        let mut terms = BTreeMap::new();
        terms.insert("UTILISATEUR".to_string(), vec!["camille".to_string()]);
        terms.insert(
            "MACHINE".to_string(),
            vec!["MacBook-Air-de-Camille".to_string()],
        );
        let s = Shield::new(&Settings {
            kinds: vec![],
            terms,
            strip_metadata: true,
            identity: false,
            release: BTreeMap::new(),
            origins: BTreeMap::new(),
        });
        let p = s.pseudonymize_text(
            "cwd: /Users/camille/projet, dossier -Users-camille-Aetheris, hôte MacBook-Air-de-Camille",
            &mut Counts::new(),
        );
        assert_eq!(
            p,
            "cwd: /Users/[UTILISATEUR_1]/projet, dossier -Users-[UTILISATEUR_1]-Aetheris, hôte [MACHINE_1]"
        );
        // le modèle agit sur un chemin pseudonymisé : l'outil reçoit le vrai chemin
        assert_eq!(
            s.rehydrate_text("/Users/[UTILISATEUR_1]/projet/main.rs", false),
            "/Users/camille/projet/main.rs"
        );
        assert!(
            local_identity()
                .values()
                .flatten()
                .all(|n| n.chars().count() >= 4)
        );
    }

    #[test]
    fn donnees_fantomes_liberees_seulement_ou_la_politique_le_permet() {
        let mut terms = BTreeMap::new();
        terms.insert("CLIENT".to_string(), vec!["Dupont SA".to_string()]);
        let mut release = BTreeMap::new();
        release.insert(
            "EMAIL".to_string(),
            vec!["human".to_string(), "route:crm".to_string()],
        );
        release.insert(
            "CLIENT".to_string(),
            vec!["human".to_string(), "agent".to_string()],
        );
        release.insert("*".to_string(), vec!["human".to_string()]);
        let s = Shield::new(&Settings {
            kinds: BUILTIN.iter().map(|x| x.to_string()).collect(),
            terms,
            strip_metadata: true,
            identity: false,
            release,
            origins: BTreeMap::new(),
        });
        s.pseudonymize_text(
            "jean@acme.io Dupont SA FR76 3000 6000 0112 3456 7890 189",
            &mut Counts::new(),
        );
        // à l'écran : tout ; dans les actions de l'agent : seulement le client
        assert_eq!(
            s.rehydrate_text("[EMAIL_1] [CLIENT_1]", false),
            "jean@acme.io Dupont SA"
        );
        assert_eq!(
            s.rehydrate_text("[EMAIL_1] [CLIENT_1] [IBAN_1]", true),
            "[EMAIL_1] Dupont SA [IBAN_1]"
        );
        // réponse complète : texte → humain, appel d'outil → agent
        let mut v = serde_json::json!({ "content": [
            { "type": "text", "text": "Écrire à [EMAIL_1]" },
            { "type": "tool_use", "name": "send", "input": { "to": "[EMAIL_1]", "who": "[CLIENT_1]" } }
        ]});
        s.rehydrate_response(&mut v);
        assert_eq!(v["content"][0]["text"], "Écrire à jean@acme.io");
        assert_eq!(v["content"][1]["input"]["to"], "[EMAIL_1]");
        assert_eq!(v["content"][1]["input"]["who"], "Dupont SA");
        // sortie vers le CRM : le courriel redevient réel (JSON, formulaire, requête) ; vers un
        // autre service, il reste un pseudonyme
        let r = s
            .release_for_route(
                br#"{"to":"[EMAIL_1]","iban":"[IBAN_1]"}"#,
                None,
                "application/json",
                "crm",
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(r.body).unwrap(),
            r#"{"iban":"[IBAN_1]","to":"jean@acme.io"}"#
        );
        assert_eq!((r.released["EMAIL"], r.withheld["IBAN"]), (1, 1));
        let r = s
            .release_for_route(
                b"email=%5BEMAIL_1%5D&x=1",
                Some("q=%5BEMAIL_1%5D"),
                "application/x-www-form-urlencoded",
                "crm",
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(r.body).unwrap(),
            "email=jean%40acme.io&x=1"
        );
        assert_eq!(r.query.unwrap(), "q=jean%40acme.io");
        // pseudonyme écrit en clair dans un formulaire (curl -d) : valeur encodée, formulaire intact
        let r = s
            .release_for_route(
                b"email=[EMAIL_1]&a=1",
                None,
                "application/x-www-form-urlencoded",
                "crm",
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(r.body).unwrap(),
            "email=jean%40acme.io&a=1"
        );
        let r = s
            .release_for_route(br#"{"to":"[EMAIL_1]"}"#, None, "application/json", "pirate")
            .unwrap();
        assert!(String::from_utf8(r.body).unwrap().contains("[EMAIL_1]"));
        assert!(
            s.release_for_route(b"rien", None, "text/plain", "crm")
                .is_none()
        );
    }

    #[test]
    fn provenance_une_valeur_du_crm_ne_retourne_qu_aux_destinations_du_crm() {
        let mut origins = BTreeMap::new();
        origins.insert(
            "crm".to_string(),
            vec!["human".to_string(), "route:mail".to_string()],
        );
        let s = Shield::new(&Settings {
            kinds: BUILTIN.iter().map(|x| x.to_string()).collect(),
            terms: BTreeMap::new(),
            strip_metadata: true,
            identity: false,
            release: BTreeMap::new(),
            origins,
        });
        // réponse du CRM : pseudonymisée, même sous « data », avec sa provenance
        let body = br#"{"data":[{"email":"marie@dupont.fr","tel":"+33 6 12 34 56 78"}]}"#;
        let (out, counts) = s
            .pseudonymize_data(body, "application/json", "crm")
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("marie") && out.contains("[EMAIL_1]"), "{out}");
        assert_eq!(counts["EMAIL"], 1);
        assert_eq!(s.origin_of("[EMAIL_1]").as_deref(), Some("crm"));
        // valeur tapée par l'utilisateur : aucune provenance, règles ordinaires
        s.pseudonymize_text("autre@exemple.fr", &mut Counts::new());
        assert_eq!(s.origin_of("[EMAIL_2]"), None);
        // l'agent (outil) : le CRM ne l'autorise pas ; l'humain et le service mail : oui
        assert_eq!(
            s.rehydrate_text("[EMAIL_1] [EMAIL_2]", true),
            "[EMAIL_1] autre@exemple.fr"
        );
        assert_eq!(s.rehydrate_text("[EMAIL_1]", false), "marie@dupont.fr");
        let to = |route: &str| {
            let r = s
                .release_for_route(br#"{"to":"[EMAIL_1]"}"#, None, "application/json", route)
                .unwrap();
            String::from_utf8(r.body).unwrap()
        };
        assert!(
            to("webhook").contains("[EMAIL_1]"),
            "hors des destinations du CRM : retenu"
        );
        assert!(
            to("mail").contains("marie@dupont.fr"),
            "destination permise pour le CRM : libéré"
        );
        // binaire : transmis tel quel
        assert!(
            s.pseudonymize_data(&[0xff, 0xfe, 0x00], "application/octet-stream", "crm")
                .is_none()
        );
    }

    #[test]
    fn validations() {
        assert!(iban_ok("FR76 3000 6000 0112 3456 7890 189"));
        assert!(!iban_ok("FR76 3000 6000 0112 3456 7890 188"));
        assert!(card_ok("4111 1111 1111 1111"));
        assert!(!card_ok("4111 1111 1111 1112"));
        assert!(
            !card_ok("1790294748598"),
            "un horodatage n'est pas une carte"
        );
        // un client déclaré dans un domaine : l'adresse reste entière
        let s = shield();
        assert_eq!(
            s.pseudonymize_text("jean@acme.io pour Acme", &mut Counts::new()),
            "[EMAIL_1] pour [CLIENT_1]"
        );
        // un terme déclaré qui ressemble à un libellé ne casse pas un pseudonyme
        let mut t = BTreeMap::new();
        t.insert("MOT".to_string(), vec!["EMAIL".to_string()]);
        let s2 = Shield::new(&Settings {
            kinds: vec!["email".into()],
            terms: t,
            strip_metadata: false,
            identity: false,
            release: BTreeMap::new(),
            origins: BTreeMap::new(),
        });
        assert_eq!(
            s2.pseudonymize_text("a@b.fr EMAIL", &mut Counts::new()),
            "[EMAIL_1] [MOT_1]"
        );
    }
}
