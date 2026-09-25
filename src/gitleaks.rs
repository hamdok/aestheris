//! Règles de détection de gitleaks (MIT, `rules/gitleaks.toml`, 222 règles), appliquées comme
//! gitleaks les applique :
//!
//! 1. **mots-clés** : une règle n'est essayée que si l'un de ses mots-clés apparaît dans le texte
//!    (un seul passage Aho-Corasick pour toutes les règles) ;
//! 2. **expression régulière** : le secret est le groupe `secretGroup`, sinon le premier groupe
//!    non vide, sinon la correspondance entière ;
//! 3. **entropie** de Shannon du secret, au-dessus du seuil de la règle ;
//! 4. **exceptions** globales puis de la règle (motifs et mots vides : `EXAMPLE`, `${VAR}`…).
//!
//! Écartées : `generic-api-key` (fondée sur l'entropie seule, trop de faux positifs pour bloquer
//! une requête) et les règles qui ne portent que sur un nom de fichier (`path`).
//!
//! Les expressions sont compilées à la demande (la première fois qu'un mot-clé de la règle
//! apparaît) et, comme en Go, `\w`, `\s`, `\b` et `\d` y sont ASCII : c'est plus fidèle à gitleaks
//! et bien plus rapide à compiler.
//!
//! Mettre à jour les règles = remplacer `rules/gitleaks.toml` par la version de gitleaks.

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::sync::OnceLock;

const RULES_TOML: &str = include_str!("../rules/gitleaks.toml");

/// Règles écartées du blocage (voir l'en-tête).
const EXCLUDED: &[&str] = &["generic-api-key"];

/// Types déjà connus d'Aestheris : même nom dans le journal, quelle que soit la règle qui détecte.
const KIND_ALIASES: &[(&str, &str)] = &[
    ("aws-access-token", "AWS_ACCESS_KEY"),
    ("github-pat", "GITHUB_TOKEN"),
    ("github-fine-grained-pat", "GITHUB_TOKEN"),
    ("github-oauth", "GITHUB_TOKEN"),
    ("github-app-token", "GITHUB_TOKEN"),
    ("github-refresh-token", "GITHUB_TOKEN"),
    ("anthropic-api-key", "ANTHROPIC_API_KEY"),
    ("anthropic-admin-api-key", "ANTHROPIC_API_KEY"),
    ("openai-api-key", "OPENAI_API_KEY"),
    ("stripe-access-token", "STRIPE_SECRET_KEY"),
    ("gcp-api-key", "GOOGLE_API_KEY"),
    ("private-key", "PRIVATE_KEY"),
    ("jwt", "JWT"),
];

#[derive(Deserialize)]
struct File {
    allowlist: Option<AllowFile>,
    #[serde(default)]
    rules: Vec<RuleFile>,
}

#[derive(Deserialize)]
struct RuleFile {
    id: String,
    regex: Option<String>,
    #[serde(default)]
    entropy: f64,
    #[serde(default)]
    keywords: Vec<String>,
    path: Option<String>,
    #[serde(rename = "secretGroup", default)]
    secret_group: usize,
    #[serde(default)]
    allowlists: Vec<AllowFile>,
}

#[derive(Deserialize)]
struct AllowFile {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(rename = "regexTarget")]
    regex_target: Option<String>,
    condition: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
}

#[derive(Clone, Copy)]
enum Target {
    Secret,
    Match,
    Line,
}

struct Allow {
    re: Option<Regex>,
    stopwords: Vec<String>,
    target: Target,
}

struct Rule {
    #[cfg_attr(not(test), expect(dead_code))] // lu par les tests de mise à jour des règles
    id: String,
    kind: String,
    pattern: String,
    re: OnceLock<Option<Regex>>,
    entropy: f64,
    secret_group: usize,
    allow: Vec<Allow>,
}

pub(crate) struct Engine {
    rules: Vec<Rule>,
    global: Vec<Allow>,
    keywords: AhoCorasick,
    /// Pour chaque mot-clé (dans l'ordre de `keywords`), les règles qu'il déclenche.
    keyword_rules: Vec<Vec<usize>>,
    /// Règles sans mot-clé : toujours essayées.
    always: Vec<usize>,
}

pub(crate) fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| Engine::load(RULES_TOML).expect("rules/gitleaks.toml valide"))
}

impl Engine {
    fn load(text: &str) -> Result<Self, String> {
        let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
        let global = file.allowlist.iter().filter_map(compile_allow).collect();
        let mut rules = Vec::new();
        let mut words: Vec<String> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut always = Vec::new();
        for r in file.rules {
            let Some(pattern) = r.regex else { continue };
            if r.path.is_some() || EXCLUDED.contains(&r.id.as_str()) {
                continue;
            }
            let idx = rules.len();
            if r.keywords.is_empty() {
                always.push(idx);
            }
            for k in r.keywords {
                let k = k.to_lowercase();
                match words.iter().position(|w| *w == k) {
                    Some(i) => keyword_rules[i].push(idx),
                    None => {
                        words.push(k);
                        keyword_rules.push(vec![idx]);
                    }
                }
            }
            let kind = KIND_ALIASES
                .iter()
                .find(|(id, _)| *id == r.id)
                .map(|(_, k)| k.to_string())
                .unwrap_or_else(|| r.id.to_uppercase().replace('-', "_"));
            rules.push(Rule {
                id: r.id,
                kind,
                pattern,
                re: OnceLock::new(),
                entropy: r.entropy,
                secret_group: r.secret_group,
                allow: r.allowlists.iter().filter_map(compile_allow).collect(),
            });
        }
        let keywords = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&words)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            rules,
            global,
            keywords,
            keyword_rules,
            always,
        })
    }

    #[cfg(test)]
    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Compile toutes les règles et renvoie celles qui échouent (vérification des mises à jour).
    #[cfg(test)]
    pub(crate) fn uncompilable(&self) -> Vec<&str> {
        self.rules
            .iter()
            .filter(|r| r.regex().is_none())
            .map(|r| r.id.as_str())
            .collect()
    }

    /// Types de secrets trouvés (sans doublon).
    pub(crate) fn detect(&self, text: &str) -> Vec<&str> {
        let mut candidates: Vec<usize> = self.always.clone();
        for m in self.keywords.find_overlapping_iter(text) {
            candidates.extend(&self.keyword_rules[m.pattern().as_usize()]);
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut kinds: Vec<&str> = Vec::new();
        for i in candidates {
            let rule = &self.rules[i];
            if !kinds.contains(&rule.kind.as_str()) && self.rule_matches(rule, text) {
                kinds.push(&rule.kind);
            }
        }
        kinds
    }

    fn rule_matches(&self, rule: &Rule, text: &str) -> bool {
        // Règle illisible pour notre moteur : ignorée (signalée par les tests).
        let Some(re) = rule.regex() else { return false };
        for caps in re.captures_iter(text) {
            let whole = caps.get(0).expect("groupe 0");
            let matched = whole.as_str().trim_matches('\n');
            let secret = if rule.secret_group > 0 {
                caps.get(rule.secret_group).map(|m| m.as_str())
            } else {
                caps.iter()
                    .skip(1)
                    .flatten()
                    .map(|m| m.as_str())
                    .find(|s| !s.is_empty())
            }
            .unwrap_or(matched);
            if rule.entropy != 0.0 && shannon_entropy(secret) <= rule.entropy {
                continue;
            }
            let line = line_of(text, whole.start(), whole.end());
            let allowed = |a: &Allow| {
                let target = match a.target {
                    Target::Secret => secret,
                    Target::Match => matched,
                    Target::Line => line,
                };
                a.re.as_ref().is_some_and(|re| re.is_match(target)) || {
                    let lower = secret.to_lowercase();
                    a.stopwords.iter().any(|w| lower.contains(w.as_str()))
                }
            };
            if self.global.iter().any(allowed) || rule.allow.iter().any(allowed) {
                continue;
            }
            return true;
        }
        false
    }
}

impl Rule {
    fn regex(&self) -> Option<&Regex> {
        self.re.get_or_init(|| compile(&self.pattern)).as_ref()
    }
}

/// Compile en ASCII comme Go ; si le motif peut sortir de l'ASCII (`.`, `[^…]`), en Unicode.
fn compile(pattern: &str) -> Option<Regex> {
    let build = |p: &str| RegexBuilder::new(p).size_limit(64 << 20).build().ok();
    build(&format!("(?-u){pattern}")).or_else(|| build(pattern))
}

/// Exception applicable à un contenu : celles qui exigent (ET) un chemin de fichier ou un commit
/// ne peuvent jamais être satisfaites ici et sont ignorées.
fn compile_allow(a: &AllowFile) -> Option<Allow> {
    let and = a
        .condition
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case("and"));
    if and && (!a.paths.is_empty() || !a.commits.is_empty()) {
        return None;
    }
    if a.regexes.is_empty() && a.stopwords.is_empty() {
        return None;
    }
    let re = if a.regexes.is_empty() {
        None
    } else {
        let joined = a
            .regexes
            .iter()
            .map(|r| format!("(?:{r})"))
            .collect::<Vec<_>>()
            .join("|");
        Some(compile(&joined)?)
    };
    let target = match a.regex_target.as_deref() {
        Some("match") => Target::Match,
        Some("line") => Target::Line,
        _ => Target::Secret,
    };
    Some(Allow {
        re,
        stopwords: a.stopwords.iter().map(|w| w.to_lowercase()).collect(),
        target,
    })
}

/// Entropie de Shannon (bits par caractère), calculée comme gitleaks.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let inv = 1.0 / s.len() as f64;
    counts
        .values()
        .map(|&n| n as f64 * inv)
        .map(|f| -f * f.log2())
        .sum()
}

fn line_of(text: &str, start: usize, end: usize) -> &str {
    let from = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let to = text[end..].find('\n').map_or(text.len(), |i| end + i);
    &text[from..to]
}
