//! Détection de secrets en clair dans le contenu d'une requête.
//!
//! Deux sources : nos motifs rapides (clés AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, Google,
//! Supabase, clés privées, URL de bases avec mot de passe, JWT), puis ~220 règles au format
//! gitleaks (voir `gitleaks.rs` et NOTICE). On renvoie le **type** de secret, jamais sa valeur : c'est le
//! type qui va dans le journal d'audit.
//!
//! Le jeton fantôme d'Aestheris (`aes_ph_…`) ne correspond à aucun motif.

use regex::Regex;
use std::sync::OnceLock;

struct Pattern {
    kind: &'static str,
    re: Regex,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let defs: &[(&str, &str)] = &[
            ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
            ("GITHUB_TOKEN", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
            ("ANTHROPIC_API_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
            ("OPENAI_API_KEY", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"),
            ("STRIPE_SECRET_KEY", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
            ("SLACK_TOKEN", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
            ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            // nouvelles clés de Supabase (la clé « publishable » est publique par conception)
            ("SUPABASE_SECRET_KEY", r"\bsb_secret_[A-Za-z0-9_\-]{16,}"),
            ("PRIVATE_KEY", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
            (
                "DATABASE_URL_WITH_PASSWORD",
                r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@",
            ),
            ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        ];
        defs.iter()
            .map(|(kind, re)| Pattern { kind, re: Regex::new(re).expect("motif de détection valide") })
            .collect()
    })
}

/// Types de secrets trouvés dans `text` (sans doublon, dans l'ordre des motifs).
pub fn detect(text: &str) -> Vec<&'static str> {
    let mut kinds: Vec<&'static str> = Vec::new();
    for p in patterns() {
        if !kinds.contains(&p.kind) && p.re.is_match(text) {
            // sk-ant-… correspond aussi au motif OpenAI : on ne garde que le plus précis
            if p.kind == "OPENAI_API_KEY"
                && kinds.contains(&"ANTHROPIC_API_KEY")
                && !has_non_anthropic_sk(text)
            {
                continue;
            }
            kinds.push(p.kind);
        }
    }
    for k in crate::gitleaks::engine().detect(text) {
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    }
    kinds
}

/// Valeurs reconnues par nos motifs rapides, avec leur position. L'analyse de projets s'en sert
/// pour écarter les exemples de documentation ; la passerelle, elle, bloque sans nuance.
pub(crate) fn pattern_matches(text: &str) -> Vec<(&'static str, std::ops::Range<usize>)> {
    patterns()
        .iter()
        .flat_map(|p| p.re.find_iter(text).map(move |m| (p.kind, m.range())))
        .collect()
}

fn has_non_anthropic_sk(text: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}").expect("motif valide")
    })
    .find_iter(text)
    .any(|m| !m.as_str().starts_with("sk-ant-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecte_les_types_courants() {
        let cas = [
            ("ma clé AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
            (
                concat!("token ghp_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
                "GITHUB_TOKEN",
            ),
            (
                concat!("OPENAI_API_KEY=sk-", "proj-abc123def456ghi789jkl012"),
                "OPENAI_API_KEY",
            ),
            (
                concat!("sk-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWx"),
                "ANTHROPIC_API_KEY",
            ),
            (
                concat!("stripe sk_", "live_4eC39HqLyjWDarjtT1zdp7dc"),
                "STRIPE_SECRET_KEY",
            ),
            (
                concat!("-----BEGIN RSA PRIVATE", " KEY-----"),
                "PRIVATE_KEY",
            ),
            (
                concat!("DB_URL=postgres://admin:", "hunter2@prod.db:5432/app"),
                "DATABASE_URL_WITH_PASSWORD",
            ),
        ];
        for (texte, attendu) in cas {
            assert!(
                detect(texte).contains(&attendu),
                "{attendu} non détecté dans « {texte} »"
            );
        }
    }

    #[test]
    fn ne_confond_pas_anthropic_et_openai() {
        assert_eq!(
            detect(concat!("sk-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWx")),
            vec!["ANTHROPIC_API_KEY"]
        );
    }

    #[test]
    fn ignore_le_jeton_fantome_et_le_texte_normal() {
        let fantome = format!("aes_ph_{}", "0123456789abcdef".repeat(4));
        for texte in [
            format!("Authorization: Bearer {fantome}"),
            format!("{{\"api_key\": \"{fantome}\"}}"),
            "Crée un paiement de 20 € pour le client cus_123".to_string(),
            // requête typique d'un agent : du code qui parle de clés sans en contenir
            r#"{"model":"claude","messages":[{"role":"user","content":"const token = process.env.GITHUB_TOKEN; // lire la clé API\nfetch(url, { headers: { Authorization: `Bearer ${token}` } })"}]}"#.to_string(),
            "password = \"${DB_PASSWORD}\"\napi_key: {{ secrets.API_KEY }}".to_string(),
        ] {
            assert!(detect(&texte).is_empty(), "faux positif {:?} dans « {texte} »", detect(&texte));
        }
    }

    #[test]
    fn regles_gitleaks_chargees() {
        let t = std::time::Instant::now();
        let e = crate::gitleaks::engine();
        eprintln!("chargement : {:?}", t.elapsed());
        let corps = "lorem ipsum api key token secret password ".repeat(20_000);
        let t = std::time::Instant::now();
        let _ = e.detect(&corps);
        eprintln!("analyse de {} Kio : {:?}", corps.len() / 1024, t.elapsed());
        let t = std::time::Instant::now();
        assert!(
            e.uncompilable().is_empty(),
            "règles gitleaks non compilées : {:?}",
            e.uncompilable()
        );
        eprintln!("compilation de toutes les règles : {:?}", t.elapsed());
        assert!(e.rule_count() > 200, "{} règles seulement", e.rule_count());
    }

    #[test]
    fn detecte_les_fournisseurs_de_gitleaks() {
        let cas = [
            (
                concat!("HF_TOKEN=hf_", "QwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUi"),
                "HUGGINGFACE_ACCESS_TOKEN",
            ),
            (concat!("glpat-", "Xk3vR9mQ2pL7wZ4nT8yB"), "GITLAB_PAT"),
            (
                concat!("NPM_TOKEN=npm_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
                "NPM_ACCESS_TOKEN",
            ),
            (
                concat!(
                    "https://hooks.slack.com/services/",
                    "T0A1B2C3D/B4E5F6G7H/q8R9s0T1u2V3w4X5y6Z7a8B9"
                ),
                "SLACK_WEBHOOK_URL",
            ),
            (
                concat!(
                    "SENDGRID=SG.",
                    "aB3dE5gH7jK9mN1pQ3sT5v.wX7yZ9aB1cD3eF5gH7jK9mN1pQ3sT5vW7xY9zA1bC3d"
                ),
                "SENDGRID_API_TOKEN",
            ),
            (
                concat!("pplx-", "3fA9kQ7mZ2xW8vB4nR6tY1uJ5hG0dS3cL9pE7qK2wX4vN8rT"),
                "PERPLEXITY_API_KEY",
            ),
        ];
        for (texte, attendu) in cas {
            assert!(
                detect(texte).contains(&attendu),
                "{attendu} non détecté dans « {texte} » : {:?}",
                detect(texte)
            );
        }
    }

    #[test]
    fn exemples_de_documentation_ignores() {
        // gitleaks écarte les clés d'exemple (mots vides) : pas de blocage sur la documentation AWS.
        assert!(
            !crate::gitleaks::engine()
                .detect("AKIAIOSFODNN7EXAMPLE")
                .contains(&"AWS_ACCESS_KEY")
        );
    }
}
