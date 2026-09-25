//! `aestheris audit report` : le journal chaîné transformé en bilan lisible par une direction.
//!
//! Deux parties :
//! - **Protection** (mode `enforce`) : ce qu'Aestheris a refusé, bloqué, fait valider,
//!   pseudonymisé, retenu ;
//! - **Observation** (mode `observe`) : ce qu'il *aurait* fait, et surtout ce que les agents ont
//!   réellement transmis aux fournisseurs d'IA sans protection. C'est le rapport d'un premier
//!   déploiement : il montre le risque avec les données de l'entreprise elle-même.
//!
//! Le journal ne contient jamais de valeur sensible : le rapport non plus (catégories et nombres).

use crate::audit::Event;
use crate::tr;
use std::collections::BTreeMap;

type Tally = BTreeMap<String, u64>;

#[derive(Default)]
struct Totals {
    sessions: u64,
    first: Option<String>,
    last: Option<String>,
    per_route: Tally,
    denied: u64,
    blocked: u64,
    secret_types: Tally,
    approved: u64,
    rejected: u64,
    expired: u64,
    pseudonymized: Tally,
    source_pseudonymized: Tally,
    released: Tally,
    withheld: Tally,
    tripped: u64,
    // observation
    would_deny: u64,
    would_block: u64,
    would_secret_types: Tally,
    would_ask: u64,
    exposed: Tally,
    would_hosts: Tally,
    would_trip: u64,
}

/// Le journal est écrit dans la langue de l'interface : chaque repère existe en deux versions.
fn has(text: &str, markers: [&str; 2]) -> bool {
    markers.iter().any(|m| text.contains(m))
}

/// Extrait les « LIBELLÉ×n » qui suivent l'un des `markers` dans un détail du journal.
fn counts_after(text: &str, markers: [&str; 2], into: &mut Tally) {
    let Some((pos, marker)) = markers.iter().find_map(|m| text.find(m).map(|p| (p, *m))) else {
        return;
    };
    let rest = &text[pos + marker.len()..];
    let rest = rest.split(" · ").next().unwrap_or("");
    let rest = rest.split(" (").next().unwrap_or("");
    for part in rest.split(", ") {
        if let Some((label, n)) = part.trim().split_once('×') {
            *into.entry(label.to_string()).or_insert(0) += n.trim().parse::<u64>().unwrap_or(0);
        }
    }
}

fn add(t: &mut Tally, k: &str, n: u64) {
    *t.entry(k.to_string()).or_insert(0) += n;
}

fn tally(events: &[Event]) -> Totals {
    let mut t = Totals::default();
    for e in events {
        if t.first.is_none() {
            t.first = Some(e.ts.clone());
        }
        t.last = Some(e.ts.clone());
        match e.kind.as_str() {
            "session_start" => t.sessions += 1,
            "guard_tripped" => {
                if e.detail
                    .as_deref()
                    .is_some_and(|d| has(d, ["observation", "observe mode"]))
                {
                    t.would_trip += 1;
                } else {
                    t.tripped += 1;
                }
            }
            "request" => {
                let route = e.route.clone().unwrap_or_else(|| "?".into());
                let reason = e.reason.as_deref().unwrap_or("");
                let detail = e.detail.as_deref().unwrap_or("");
                add(&mut t.per_route, &route, 1);
                match e.decision.as_deref() {
                    Some("denied") => t.denied += 1,
                    Some("blocked") => {
                        t.blocked += 1;
                        for d in &e.detected {
                            add(&mut t.secret_types, d, 1);
                        }
                    }
                    Some("observed") => {
                        // « aurait refusé (…) » ; les sorties hors liste sont comptées à part
                        if has(reason, ["aurait refusé (", "would have denied ("]) {
                            t.would_deny += 1;
                        }
                        if has(reason, ["aurait bloqué un secret", "would have blocked a"]) {
                            t.would_block += 1;
                            for d in &e.detected {
                                add(&mut t.would_secret_types, d, 1);
                            }
                        }
                        if has(reason, ["aurait demandé", "would have asked"]) {
                            t.would_ask += 1;
                        }
                        if route == "sortie"
                            && has(reason, ["hors liste blanche", "outside the allowlist"])
                            && let Some(p) = &e.path
                        {
                            add(&mut t.would_hosts, p, 1);
                        }
                        counts_after(detail, ["exposition : ", "exposure: "], &mut t.exposed);
                        counts_after(detail, [" : exposé ", ": exposed "], &mut t.exposed);
                    }
                    _ => {}
                }
                if has(reason, ["approuvée par", "approved by"]) {
                    t.approved += 1;
                } else if has(reason, ["refusée par", "denied by"]) {
                    t.rejected += 1;
                } else if has(reason, ["sans réponse", "no answer"]) {
                    t.expired += 1;
                }
                counts_after(
                    detail,
                    ["confidentialité : ", "confidentiality: "],
                    &mut t.pseudonymized,
                );
                counts_after(detail, ["libéré ", "released "], &mut t.released);
                counts_after(detail, ["retenu ", "withheld "], &mut t.withheld);
                counts_after(
                    detail,
                    [" : pseudonymisé ", ": pseudonymized "],
                    &mut t.source_pseudonymized,
                );
            }
            _ => {}
        }
    }
    t
}

fn list(t: &Tally) -> String {
    let mut v: Vec<(&String, &u64)> = t.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    v.iter()
        .map(|(k, n)| format!("{k}×{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sum(t: &Tally) -> u64 {
    t.values().sum()
}

/// Rapport en texte (français), prêt à être lu ou transmis.
pub fn render(events: &[Event], journal: &str) -> String {
    let t = tally(events);
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    line(tr!("Rapport Aestheris", "Aestheris report").into());
    line(tr!(fmt "  journal  : {journal}", "  log      : {journal}"));
    line(tr!(fmt
        "  période  : {} → {} · {} session(s)", "  period   : {} → {} · {} session(s)",
        t.first.as_deref().unwrap_or("—"),
        t.last.as_deref().unwrap_or("—"),
        t.sessions
    ));
    let total = sum(&t.per_route);
    line(String::new());
    line(tr!(fmt
        "Activité des agents : {total} requête(s) relayée(s)", "Agent activity: {total} request(s) relayed"
    ));
    if total > 0 {
        let routes =
            list(&t.per_route).replace("sortie×", tr!("sortie réseau×", "network egress×"));
        line(tr!(fmt "  par service : {routes}", "  per service: {routes}"));
    }

    let protected = t.denied
        + t.blocked
        + t.approved
        + t.rejected
        + t.expired
        + t.tripped
        + sum(&t.pseudonymized)
        + sum(&t.source_pseudonymized)
        + sum(&t.withheld)
        + sum(&t.released);
    if protected > 0 {
        line(String::new());
        line("Protection".into());
        if t.denied > 0 {
            line(tr!(fmt
                "  refusées par la politique          : {}", "  denied by the policy               : {}",
                t.denied
            ));
        }
        if t.blocked > 0 {
            line(tr!(fmt
                "  secrets en clair bloqués           : {} ({})", "  plaintext secrets blocked          : {} ({})",
                t.blocked,
                list(&t.secret_types)
            ));
        }
        if t.approved + t.rejected + t.expired > 0 {
            line(tr!(fmt
                "  validations humaines               : {} approuvée(s) · {} refusée(s) · {} sans réponse", "  human approvals                    : {} approved · {} denied · {} unanswered",
                t.approved, t.rejected, t.expired
            ));
        }
        if !t.pseudonymized.is_empty() {
            line(tr!(fmt
                "  pseudonymisé vers les fournisseurs : {} ({} valeur(s) jamais transmise(s))", "  pseudonymized towards providers    : {} ({} value(s) never sent)",
                list(&t.pseudonymized),
                sum(&t.pseudonymized)
            ));
        }
        if !t.source_pseudonymized.is_empty() {
            line(tr!(fmt
                "  sources de données pseudonymisées  : {}", "  pseudonymized data sources         : {}",
                list(&t.source_pseudonymized)
            ));
        }
        if !t.released.is_empty() || !t.withheld.is_empty() {
            line(tr!(fmt
                "  données fantômes                   : {} libérée(s) · {} retenue(s) hors de leurs destinations", "  phantom data                       : {} released · {} withheld outside their destinations",
                sum(&t.released),
                sum(&t.withheld)
            ));
        }
        if t.tripped > 0 {
            line(tr!(fmt
                "  disjoncteur déclenché              : {} session(s)", "  circuit breaker tripped            : {} session(s)",
                t.tripped
            ));
        }
    }

    let observed = t.would_deny
        + t.would_block
        + t.would_ask
        + t.would_trip
        + sum(&t.exposed)
        + sum(&t.would_hosts);
    if observed > 0 {
        line(String::new());
        line(
            tr!(
                "Observation (rien n'a été bloqué)",
                "Observation (nothing was blocked)"
            )
            .into(),
        );
        if !t.exposed.is_empty() {
            line(tr!(fmt
                "  données sensibles transmises telles quelles aux fournisseurs : {} ({} au total)", "  sensitive data sent as is to providers : {} ({} in total)",
                list(&t.exposed),
                sum(&t.exposed)
            ));
        }
        if t.would_block > 0 {
            line(tr!(fmt
                "  secrets en clair qui auraient été bloqués : {} ({})", "  plaintext secrets that would have been blocked : {} ({})",
                t.would_block,
                list(&t.would_secret_types)
            ));
        }
        if t.would_deny > 0 {
            line(tr!(fmt
                "  requêtes qui auraient été refusées        : {}", "  requests that would have been denied  : {}",
                t.would_deny
            ));
        }
        if t.would_ask > 0 {
            line(tr!(fmt
                "  validations humaines qui auraient été demandées : {}", "  human approvals that would have been requested : {}",
                t.would_ask
            ));
        }
        if !t.would_hosts.is_empty() {
            line(tr!(fmt
                "  sorties réseau hors liste blanche         : {}", "  network egress outside the allowlist  : {}",
                list(&t.would_hosts)
            ));
        }
        if t.would_trip > 0 {
            line(tr!(fmt
                "  disjoncteur qui aurait sauté              : {} session(s)", "  circuit breaker that would have tripped : {} session(s)",
                t.would_trip
            ));
        }
        line(
            tr!(
                "  → passer en protection : mode: enforce dans la politique",
                "  → to protect: set mode: enforce in the policy"
            )
            .into(),
        );
    }
    if protected == 0 && observed == 0 && total > 0 {
        line(String::new());
        line(
            tr!(
                "Rien à signaler : aucune requête refusée, bloquée ni exposée.",
                "Nothing to report: no request denied, blocked or exposed."
            )
            .into(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, decision: Option<&str>, reason: &str, detail: &str) -> Event {
        Event {
            ts: "2026-09-25T10:00:00Z".into(),
            kind: kind.into(),
            route: Some("anthropic".into()),
            decision: decision.map(Into::into),
            reason: Some(reason.into()),
            detail: (!detail.is_empty()).then(|| detail.into()),
            ..Default::default()
        }
    }

    #[test]
    fn bilan_protection_et_observation() {
        let mut blocked = ev("request", Some("blocked"), "secret en clair", "");
        blocked.detected = vec!["AWS_ACCESS_KEY".into()];
        let mut egress = ev(
            "request",
            Some("observed"),
            "observation : aurait refusé ou soumis à validation (evil.io hors liste blanche)",
            "",
        );
        egress.route = Some("sortie".into());
        egress.path = Some("evil.io:443".into());
        let events = vec![
            ev("session_start", None, "", ""),
            ev(
                "request",
                Some("allowed"),
                "règle 1",
                "confidentialité : EMAIL×2, CLIENT×1",
            ),
            ev("request", Some("denied"), "règle 2 interdit DELETE", ""),
            blocked,
            ev(
                "request",
                Some("allowed"),
                "règle 1 soumet à validation humaine → approuvée par un humain",
                "",
            ),
            ev(
                "request",
                Some("allowed"),
                "règle 1",
                "données fantômes : libéré EMAIL×1 · retenu IBAN×2",
            ),
            ev(
                "request",
                Some("observed"),
                "observation : aurait pseudonymisé des données sensibles",
                "exposition : EMAIL×40, TEL×3 (transmis tel quel)",
            ),
            ev(
                "request",
                Some("observed"),
                "observation : aurait refusé (règle 2 interdit DELETE)",
                "",
            ),
            egress,
            ev(
                "guard_tripped",
                None,
                "1 tentative",
                "mode observation : aucun effet, noté pour le rapport",
            ),
        ];
        let r = render(&events, "audit.ndjson");
        assert!(r.contains("1 session(s)"));
        assert!(r.contains("refusées par la politique          : 1"));
        assert!(r.contains("secrets en clair bloqués           : 1 (AWS_ACCESS_KEY×1)"));
        assert!(r.contains("1 approuvée(s)"));
        assert!(r.contains("pseudonymisé vers les fournisseurs : EMAIL×2, CLIENT×1 (3 valeur(s)"));
        assert!(r.contains("1 libérée(s) · 2 retenue(s)"));
        assert!(r.contains(
            "transmises telles quelles aux fournisseurs : EMAIL×40, TEL×3 (43 au total)"
        ));
        assert!(r.contains("requêtes qui auraient été refusées        : 1"));
        assert!(r.contains("sorties réseau hors liste blanche         : evil.io:443×1"));
        assert!(r.contains("disjoncteur qui aurait sauté              : 1"));
    }
}
