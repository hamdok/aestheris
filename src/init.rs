//! `aestheris init` : politiques prêtes à l'emploi.
//!
//! Un modèle = un agent (ses besoins d'écriture, ses variables) + des services (une route chacun,
//! avec des règles raisonnables : lecture libre, écriture ciblée, actions irréversibles soumises à
//! validation humaine, suppressions interdites). Le texte produit est commenté : c'est un point de
//! départ que l'équipe relit et versionne.
//!
//! Faits vérifiés dans un vrai bac à sable : Claude Code attend un
//! jeton de passerelle dans `ANTHROPIC_AUTH_TOKEN` (envoyé en `Authorization: Bearer`) ; il écrit
//! dans `~/.claude`, `~/.claude.json` et le verrou `~/.claude.json.lock` ; sans
//! `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, il envoie de la télémétrie (Datadog).

use crate::error::{Error, Result};
use crate::tr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    ClaudeCode,
    Generic,
}

impl Agent {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "claude-code" | "claude" => Ok(Agent::ClaudeCode),
            "generic" | "generique" | "autre" => Ok(Agent::Generic),
            _ => Err(Error::Policy(tr!(fmt
                "agent inconnu : {s} (claude-code ou generic)",
                "unknown agent: {s} (claude-code or generic)"))),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Generic => tr!("agent générique", "generic agent"),
        }
    }

    /// Commande à lancer ensuite.
    pub fn command(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude",
            Agent::Generic => tr!("<votre agent>", "<your agent>"),
        }
    }
}

/// Service proposé : nom de la route, secret dans le coffre, variable d'où importer une clé déjà
/// présente dans le terminal.
pub struct Service {
    pub id: &'static str,
    pub label: &'static str,
    pub secret: &'static str,
    pub import_from: &'static [&'static str],
}

pub const SERVICES: &[Service] = &[
    Service {
        id: "anthropic",
        label: "Anthropic (Claude)",
        secret: "anthropic/api",
        import_from: &["ANTHROPIC_API_KEY"],
    },
    Service {
        id: "openai",
        label: "OpenAI",
        secret: "openai/api",
        import_from: &["OPENAI_API_KEY"],
    },
    Service {
        id: "github",
        label: "GitHub (API REST)",
        secret: "github/token",
        import_from: &["GITHUB_TOKEN", "GH_TOKEN"],
    },
    Service {
        id: "stripe",
        label: "Stripe",
        secret: "stripe/api",
        import_from: &["STRIPE_API_KEY", "STRIPE_SECRET_KEY"],
    },
];

pub fn service(id: &str) -> Result<&'static Service> {
    SERVICES.iter().find(|s| s.id == id).ok_or_else(|| {
        let ids: Vec<&str> = SERVICES.iter().map(|s| s.id).collect();
        let ids = ids.join(", ");
        Error::Policy(tr!(fmt "service inconnu : {id} (disponibles : {ids})",
            "unknown service: {id} (available: {ids})"))
    })
}

/// Hôtes des gestionnaires de paquets et de GitHub, ouverts par défaut en sortie ; tout autre hôte
/// est soumis à validation humaine.
const PACKAGE_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
];

fn route(id: &str, agent: Agent) -> String {
    match id {
        "anthropic" => {
            let env = match agent {
                // Claude Code n'accepte pas un jeton de passerelle dans ANTHROPIC_API_KEY
                Agent::ClaudeCode => "ANTHROPIC_AUTH_TOKEN",
                Agent::Generic => "ANTHROPIC_API_KEY",
            };
            let about = tr!(
                "Modèles Claude. Le SDK et Claude Code lisent ANTHROPIC_BASE_URL.",
                "Claude models. The SDK and Claude Code read ANTHROPIC_BASE_URL."
            );
            let shield = shield_comment();
            format!(
                r#"  # {about}
  anthropic:
    upstream: https://api.anthropic.com
    secret: anthropic/api
    inject: {{ header: x-api-key, format: "{{}}" }}
    env: {env}
    base_url_env: ANTHROPIC_BASE_URL
    privacy: true                       # {shield}
    rules:
      - {{ action: allow, methods: [POST], path: "/v1/messages" }}
      - {{ action: allow, methods: [POST], path: "/v1/messages/count_tokens" }}
      - {{ action: allow, methods: [GET], path: "/v1/models/**" }}
"#
            )
        }
        "openai" => format!(
            r#"  # {}
  openai:
    upstream: https://api.openai.com/v1
    secret: openai/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    env: OPENAI_API_KEY
    base_url_env: OPENAI_BASE_URL
    privacy: true                       # {}
    rules:
      - {{ action: allow, methods: [POST], path: "/chat/completions" }}
      - {{ action: allow, methods: [POST], path: "/responses" }}
      - {{ action: allow, methods: [POST], path: "/embeddings" }}
      - {{ action: allow, methods: [GET], path: "/models/**" }}
"#,
            tr!(
                "Modèles OpenAI. Les SDK attendent une URL de base qui contient /v1.",
                "OpenAI models. The SDKs expect a base URL that includes /v1."
            ),
            shield_comment()
        ),
        "github" => format!(
            r#"  # {}
  github:
    upstream: https://api.github.com
    secret: github/token
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    env: GITHUB_TOKEN
    base_url_env: GITHUB_API_URL
    rules:
      - {{ action: deny, methods: [DELETE] }}
      - {{ action: ask, methods: [PUT], path: "/repos/*/*/pulls/*/merge" }}   # {}
      - {{ action: allow, methods: [GET] }}
      - {{ action: allow, methods: [POST], path: "/repos/*/*/pulls" }}
      - {{ action: allow, methods: [POST], path: "/repos/*/*/issues" }}
      - {{ action: allow, methods: [POST], path: "/repos/*/*/issues/*/comments" }}
      - {{ action: allow, methods: [POST], path: "/repos/*/*/pulls/*/reviews" }}
"#,
            tr!(
                "API GitHub (Octokit, scripts, actions : GITHUB_API_URL). Le CLI « gh » ignore cette\n  \
                 # variable : il passerait par le proxy et serait refusé (hôte d'une route).",
                "GitHub API (Octokit, scripts, actions: GITHUB_API_URL). The `gh` CLI ignores this\n  \
                 # variable: it would go through the proxy and be denied (a route's host)."
            ),
            tr!("fusion : un humain décide", "merge: a human decides")
        ),
        "stripe" => format!(
            r#"  # {}
  stripe:
    upstream: https://api.stripe.com
    secret: stripe/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    env: STRIPE_API_KEY
    base_url_env: STRIPE_API_BASE
    rules:
      - {{ action: deny, methods: [DELETE] }}
      - {{ action: ask, methods: [POST], path: "/v1/refunds/**" }}     # {}
      - {{ action: ask, methods: [POST], path: "/v1/payouts/**" }}
      - {{ action: ask, methods: [POST], path: "/v1/transfers/**" }}
      - {{ action: allow, methods: [GET, POST], path: "/v1/**" }}
"#,
            tr!(
                "Stripe : lecture et création libres ; argent qui sort validé par un humain ; rien n'est supprimé.",
                "Stripe: reads and creations allowed; money going out approved by a human; nothing deleted."
            ),
            tr!("couvre aussi /v1/refunds", "also covers /v1/refunds")
        ),
        _ => String::new(),
    }
}

fn shield_comment() -> &'static str {
    tr!(
        "bouclier de confidentialité (voir « privacy » plus bas)",
        "privacy shield (see `privacy` below)"
    )
}

/// Politique en mode observation : rien n'est bloqué, tout est noté (`aestheris audit report`).
pub fn observe_mode(text: &str) -> String {
    let comment = tr!(
        "# Mode observation : rien n'est bloqué ni modifié, tout ce qui l'aurait été est noté.\n\
         # Bilan : aestheris audit report. Pour protéger : remplacer par « mode: enforce ».\n",
        "# Observe mode: nothing is blocked or modified; everything that would have been is recorded.\n\
         # Summary: aestheris audit report. To protect: replace with `mode: enforce`.\n"
    );
    text.replacen(
        "version: 1\n",
        &format!("version: 1\n\n{comment}mode: observe\n"),
        1,
    )
}

/// Texte complet de la politique. `protected` : noms propres à l'entreprise (société, clients,
/// projets) à ne jamais envoyer au fournisseur d'IA.
pub fn render(agent: Agent, services: &[&str], protected: &[String]) -> Result<String> {
    if services.is_empty() {
        return Err(Error::Policy(
            tr!(
                "choisissez au moins un service",
                "choose at least one service"
            )
            .into(),
        ));
    }
    let mut out = String::new();
    let label = agent.label();
    out.push_str(&tr!(fmt
        "# Politique Aestheris — {label}, générée par « aestheris init ».\n\
         # À relire et à versionner avec le projet. Règles : la première qui correspond gagne ;\n\
         # aucune ne correspond → refus. « ask » = un humain valide avec « aestheris approve ».\n\
         # Vérifier : aestheris policy check\n\n",
        "# Aestheris policy — {label}, generated by `aestheris init`.\n\
         # Review it and version it with the project. Rules: the first match wins;\n\
         # no match → deny. `ask` = a human approves with `aestheris approve`.\n\
         # Check: aestheris policy check\n\n"));
    out.push_str("version: 1\n\nroutes:\n");
    for id in services {
        service(id)?;
        out.push_str(&route(id, agent));
        out.push('\n');
    }
    out.push_str(tr!(
        "# Secrets en clair (clés AWS, jetons GitHub, clés privées… ~220 types) : requête bloquée.\n",
        "# Plaintext secrets (AWS keys, GitHub tokens, private keys… ~220 kinds): request blocked.\n"
    ));
    out.push_str("content:\n  secrets: block\n\n");
    if services.iter().any(|s| *s == "anthropic" || *s == "openai") {
        out.push_str(tr!(
            "# Bouclier de confidentialité (routes « privacy: true ») : le fournisseur d'IA ne reçoit que\n\
             # des pseudonymes ([EMAIL_1], [CLIENT_2]…) ; les vraies valeurs sont rétablies sur la machine,\n\
             # y compris dans les actions de l'agent. Détectés d'office : courriels, téléphones, IBAN,\n\
             # cartes, adresses IP, votre nom d'utilisateur, le nom de la machine, votre nom Git.\n\
             # Bilan : aestheris audit exposure\n",
            "# Privacy shield (routes with `privacy: true`): the AI provider only receives pseudonyms\n\
             # ([EMAIL_1], [CLIENT_2]…); real values are restored on the machine, including in the\n\
             # agent's actions. Detected by default: emails, phone numbers, IBANs, cards, IP addresses,\n\
             # your user name, the machine name, your Git name.\n\
             # Summary: aestheris audit exposure\n"
        ));
        out.push_str("privacy:\n");
        let names: Vec<String> = protected
            .iter()
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
            .map(|n| serde_json::to_string(n).unwrap_or_default())
            .collect();
        if names.is_empty() {
            out.push_str("  terms: {}\n");
        } else {
            out.push_str(&format!(
                "  terms:\n    {}: [{}]\n",
                tr!("CONFIDENTIEL", "CONFIDENTIAL"),
                names.join(", ")
            ));
        }
        out.push_str(tr!(
            "  # autres catégories, par exemple :\n  #   CLIENT: [\"Dupont SA\", \"Martin & Fils\"]\n  #   PROJET: [\"Phoenix\"]\n",
            "  # other categories, for example:\n  #   CLIENT: [\"Acme Corp\", \"Smith & Sons\"]\n  #   PROJECT: [\"Phoenix\"]\n"
        ));
        out.push_str(tr!(
            "  # Données fantômes : où une valeur peut redevenir réelle. Par défaut : à l'écran (human)\n  \
               # et dans les actions de l'agent (agent). Pour un agent qui agit sur vos services, limitez :\n  \
               # release:\n  \
               #   EMAIL: [human, route:crm]     # un agent détourné n'enverra ailleurs qu'un pseudonyme\n\n",
            "  # Phantom data: where a value may become real again. Default: on screen (human) and in\n  \
               # the agent's actions (agent). For an agent acting on your services, restrict it:\n  \
               # release:\n  \
               #   EMAIL: [human, route:crm]     # a hijacked agent only sends a pseudonym elsewhere\n\n"
        ));
    }
    out.push_str(tr!(
        "# Réseau hors routes : gestionnaires de paquets et GitHub ouverts ; tout autre hôte est\n\
         # soumis à validation humaine. Adresses internes et métadonnées cloud toujours refusées.\n",
        "# Network outside routes: package managers and GitHub open; any other host needs human\n\
         # approval. Internal addresses and cloud metadata are always denied.\n"
    ));
    out.push_str("network:\n  egress: allowlist\n  ask_unknown_hosts: true\n  allow_hosts:\n");
    for h in PACKAGE_HOSTS {
        out.push_str(&format!("    - {h}\n"));
    }
    out.push_str(tr!(
        "\n# Bac à sable : secrets du poste illisibles (~/.ssh, ~/.aws, .env, trousseau…), écriture\n\
         # limitée aux dossiers ci-dessous, aucune connexion directe hors de la passerelle.\n",
        "\n# Sandbox: the machine's secrets are unreadable (~/.ssh, ~/.aws, .env, keychain…), writes\n\
         # limited to the folders below, no direct connection outside the gateway.\n"
    ));
    out.push_str(&format!(
        "sandbox:\n  enabled: true\n  allow_write:\n    - .                         # {}\n",
        tr!("le dossier du projet", "the project folder")
    ));
    if agent == Agent::ClaudeCode {
        out.push_str(&format!(
            "    - ~/.claude                 # {}\n    - ~/.claude.json            # {}\n    - ~/.claude.json.lock\n",
            tr!("état de Claude Code", "Claude Code state"),
            tr!(
                "attention : contient aussi ses serveurs MCP",
                "careful: also holds its MCP servers"
            )
        ));
    }
    out.push_str(&format!(
        "\napproval:\n  timeout_secs: 120            # {}\n  notify: true\n",
        tr!("sans réponse → refus", "no answer → deny")
    ));
    out.push_str(tr!(
        "\n# Disjoncteur : trop de signes d'un agent détourné dans la session (données envoyées hors de\n\
         # leurs destinations, secrets en clair, refus répétés) → chaque action attend un humain.\n",
        "\n# Circuit breaker: too many signs of a hijacked agent in the session (data sent outside its\n\
         # destinations, plaintext secrets, repeated denials) → every action waits for a human.\n"
    ));
    out.push_str(&format!(
        "guard:\n  max_withheld: 3\n  max_blocked: 3\n  max_denied: 20\n  on_trip: ask                  # {}\n",
        tr!("ou stop : session suspendue", "or stop: session suspended")
    ));
    if agent == Agent::ClaudeCode {
        out.push_str(tr!(
            "\n# Variables non secrètes données à l'agent : pas de télémétrie ni de trafic non essentiel.\n",
            "\n# Non-secret variables given to the agent: no telemetry or non-essential traffic.\n"
        ));
        out.push_str("agent:\n  env:\n    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: \"1\"\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, Verdict};

    #[test]
    fn chaque_modele_est_une_politique_valide() {
        let all: Vec<&str> = SERVICES.iter().map(|s| s.id).collect();
        for agent in [Agent::ClaudeCode, Agent::Generic] {
            for n in 1..=all.len() {
                let text = render(agent, &all[..n], &[]).unwrap();
                Policy::parse(&text)
                    .unwrap_or_else(|e| panic!("{agent:?} {:?} : {e}\n{text}", &all[..n]));
            }
        }
    }

    #[test]
    fn claude_code_complet() {
        let text = render(
            Agent::ClaudeCode,
            &["anthropic", "github", "stripe"],
            &["Dupont SA".into(), "Projet \"Phoenix\"".into()],
        )
        .unwrap();
        let p = Policy::parse(&text).unwrap();
        assert_eq!(
            p.routes["anthropic"].env.as_deref(),
            Some("ANTHROPIC_AUTH_TOKEN")
        );
        assert_eq!(p.agent_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1");
        assert!(p.sandbox.enabled && p.ask_unknown_hosts);
        assert!(
            p.sandbox
                .allow_write
                .contains(&"~/.claude.json.lock".to_string())
        );
        assert!(p.guard.is_some(), "disjoncteur activé par défaut");
        let stripe = &p.routes["stripe"];
        assert_eq!(stripe.decide("POST", "/v1/refunds").verdict, Verdict::Ask);
        assert_eq!(stripe.decide("POST", "/v1/charges").verdict, Verdict::Allow);
        assert_eq!(
            stripe.decide("DELETE", "/v1/customers/cus_1").verdict,
            Verdict::Deny
        );
        let gh = &p.routes["github"];
        assert_eq!(
            gh.decide("PUT", "/repos/a/b/pulls/3/merge").verdict,
            Verdict::Ask
        );
        assert_eq!(gh.decide("DELETE", "/repos/a/b").verdict, Verdict::Deny);
        let anthropic = &p.routes["anthropic"];
        assert!(anthropic.privacy && !p.routes["github"].privacy);
        let terms = &p.privacy.as_ref().unwrap().terms["CONFIDENTIEL"];
        assert_eq!(
            terms,
            &vec!["Dupont SA".to_string(), "Projet \"Phoenix\"".to_string()]
        );
        assert!(anthropic.decide("GET", "/v1/models").allowed());
        assert!(anthropic.decide("POST", "/v1/messages").allowed());
        assert!(!anthropic.decide("POST", "/v1/files").allowed());
    }

    #[test]
    fn mode_observation() {
        let text = observe_mode(&render(Agent::ClaudeCode, &["anthropic"], &[]).unwrap());
        let p = Policy::parse(&text).unwrap();
        assert_eq!(p.mode, crate::policy::Mode::Observe);
        assert!(!p.uses_approval());
    }

    #[test]
    fn services_inconnus_refuses() {
        assert!(render(Agent::Generic, &["inconnu"], &[]).is_err());
        assert!(render(Agent::Generic, &[], &[]).is_err());
        // sans route de modèle, pas de section privacy (elle ne s'appliquerait nulle part)
        assert!(
            !render(Agent::Generic, &["stripe"], &[])
                .unwrap()
                .contains("privacy:")
        );
        assert!(Agent::parse("x").is_err());
    }
}
