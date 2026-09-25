//! Proxy inverse de la passerelle.
//!
//! L'agent appelle `http://127.0.0.1:PORT/<route>/<chemin>` avec son jeton fantôme. Pour chaque
//! requête, dans cet ordre (et en échouant fermé à chaque étape) :
//!
//! 1. route connue ?                               sinon 404
//! 2. jeton de session valide (temps constant) ?   sinon 401, la clé n'est jamais injectée
//! 3. chemin sain (pas de `..`, rien d'encodé) ?   sinon 400
//! 4. politique de la route (méthode, chemin) ?    sinon 403
//! 5. secret en clair dans le contenu ?            alors 403
//! 6. règle `ask` : validation humaine ?           sinon 403 (refus ou délai dépassé)
//! 7. route `privacy` : valeurs sensibles → pseudonymes ; métadonnées identifiantes retirées
//! 8. injection de la vraie clé, relais HTTPS vers l'amont, réponse relayée en flux (pseudonymes
//!    rétablis au passage sur les routes `privacy`)
//! 9. événement ajouté au journal chaîné
//!
//! La passerelle n'écoute que sur 127.0.0.1.

use crate::approval::{Broker, Outcome};
use crate::audit::{AuditLog, Event};
use crate::error::{Error, Result};
use crate::phantom::SessionToken;
use crate::policy::{
    ContentAction, Decision, Egress, Mode, OnTrip, Policy, Route, Verdict, ip_forbidden,
    is_own_address, validate_request_path,
};
use crate::privacy::{Shield, StreamRehydrator};
use crate::scan;
use crate::secret::{Secret, is_header_safe};
use crate::tr;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use reqwest::header::{HeaderMap, HeaderValue};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Taille maximale d'un corps de requête inspecté (10 Mio).
const MAX_BODY: usize = 10 * 1024 * 1024;

/// En-têtes « de saut » à ne jamais relayer (RFC 9110), plus ceux que la passerelle recalcule.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Compteurs de session (affichés à la fin de `aestheris run`).
#[derive(Default, Debug)]
pub struct Stats {
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    pub blocked: AtomicU64,
    pub unauthorized: AtomicU64,
    pub errors: AtomicU64,
    /// Dont autorisées par un humain (validation).
    pub approved: AtomicU64,
    /// Données fantômes retenues : tentatives d'envoyer une donnée hors de ses destinations.
    pub withheld: AtomicU64,
    /// Mode observation : requêtes qui auraient été refusées, bloquées ou modifiées.
    pub observed: AtomicU64,
    /// Mode observation : refus et blocages évités (pour le disjoncteur « qui aurait sauté »).
    pub would_denied: AtomicU64,
    pub would_blocked: AtomicU64,
}

pub struct Gateway {
    policy: Policy,
    secrets: HashMap<String, Secret>,
    token: SessionToken,
    audit: Arc<AuditLog>,
    session: String,
    client: reqwest::Client,
    pub stats: Stats,
    /// Demandes de validation humaine de la session.
    pub approvals: Arc<Broker>,
    /// Bouclier de confidentialité de la session (pseudonymes stables d'une requête à l'autre).
    privacy: Option<Arc<Shield>>,
    /// Disjoncteur déclenché (une fois pour toute la session).
    tripped: std::sync::atomic::AtomicBool,
}

impl Gateway {
    /// Prépare la passerelle. Chaque route doit avoir son secret, sûr pour un en-tête HTTP.
    pub fn new(
        policy: Policy,
        secrets: HashMap<String, Secret>,
        token: SessionToken,
        audit: Arc<AuditLog>,
        session: String,
    ) -> Result<Self> {
        for route in policy.routes.values() {
            let s = secrets
                .get(&route.name)
                .ok_or_else(|| Error::SecretMissing(route.secret.clone()))?;
            let rendered = route.inject_format.replace("{}", s.expose());
            if !is_header_safe(&rendered) || HeaderValue::from_str(&rendered).is_err() {
                return Err(Error::Policy(tr!(fmt
                    "le secret {} ne peut pas être injecté dans un en-tête", "the secret {} cannot be injected into a header",
                    route.secret
                )));
            }
        }
        let client = reqwest::Client::builder()
            // Pas de redirection automatique : une redirection vers un autre hôte pourrait emporter la clé.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| Error::Net(format!("client HTTP : {e}")))?;
        let approvals = Arc::new(Broker::new(
            session.clone(),
            policy.approval.timeout,
            policy.approval.notify,
        ));
        let privacy = policy.privacy.as_ref().map(|s| Arc::new(Shield::new(s)));
        Ok(Self {
            policy,
            secrets,
            token,
            audit,
            session,
            client,
            stats: Stats::default(),
            approvals,
            privacy,
            tripped: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn routes(&self) -> impl Iterator<Item = &Route> {
        self.policy.routes.values()
    }

    /// Jeton fantôme à donner à l'agent (seul endroit où il sort de la passerelle).
    pub fn token_for_agent(&self) -> &str {
        self.token.expose()
    }

    pub fn audit_log(&self) -> Arc<AuditLog> {
        self.audit.clone()
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Disjoncteur d'injection : trop de tentatives suspectes dans la session (données envoyées
    /// hors de leurs destinations, secrets en clair, refus) → il se déclenche une fois, le signale
    /// et le journalise ; ensuite chaque action attend un humain (`ask`) ou plus rien ne passe
    /// (`stop`). Aucun modèle n'est consulté : ce sont des faits observés par la passerelle.
    /// Mode observation : rien n'est bloqué par la politique, tout est noté.
    pub fn observing(&self) -> bool {
        self.policy.mode == Mode::Observe
    }

    pub fn guard_tripped(&self) -> Option<OnTrip> {
        let g = self.policy.guard.as_ref()?;
        if self.tripped.load(Ordering::SeqCst) {
            return (!self.observing()).then_some(g.on_trip);
        }
        let s = &self.stats;
        let (w, b, d) = if self.observing() {
            (
                0,
                s.would_blocked.load(Ordering::Relaxed),
                s.would_denied.load(Ordering::Relaxed),
            )
        } else {
            (
                s.withheld.load(Ordering::Relaxed),
                s.blocked.load(Ordering::Relaxed),
                s.denied.load(Ordering::Relaxed),
            )
        };
        let why = if w >= g.max_withheld {
            tr!(fmt "{w} tentative(s) d'envoyer une donnée hors de ses destinations", "{w} attempt(s) to send data outside its destinations")
        } else if b >= g.max_blocked {
            tr!(fmt "{b} secret(s) en clair bloqué(s)", "{b} plaintext secret(s) blocked")
        } else if d >= g.max_denied {
            tr!(fmt "{d} action(s) refusée(s) par la politique", "{d} action(s) denied by the policy")
        } else {
            return None;
        };
        if !self.tripped.swap(true, Ordering::SeqCst) {
            let effect = match (self.observing(), g.on_trip) {
                (true, _) => tr!(
                    "mode observation : aucun effet, noté pour le rapport",
                    "observe mode: no effect, recorded for the report"
                ),
                (false, OnTrip::Ask) => {
                    tr!(
                        "chaque action vers un service attend désormais une validation humaine",
                        "every action towards a service now waits for human approval"
                    )
                }
                (false, OnTrip::Stop) => tr!(
                    "plus aucune action ne passe jusqu'à la fin de la session",
                    "no action goes through until the end of the session"
                ),
            };
            eprintln!(
                "{}",
                tr!(fmt "aestheris ▸ ⚡ disjoncteur déclenché : {why} — {effect}",
                    "aestheris ▸ ⚡ circuit breaker tripped: {why} — {effect}")
            );
            record(
                self,
                Event {
                    session: self.session.clone(),
                    kind: "guard_tripped".into(),
                    reason: Some(why),
                    detail: Some(effect.into()),
                    ..Default::default()
                },
            );
        }
        (!self.observing()).then_some(g.on_trip)
    }
}

/// Passerelle démarrée : adresse locale et arrêt propre.
pub struct Running {
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

/// Démarre la passerelle sur 127.0.0.1:`port` (0 = port libre choisi par le système).
pub async fn start(gateway: Arc<Gateway>, port: u16) -> Result<Running> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(handle).with_state(gateway);
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    Ok(Running {
        addr,
        shutdown: Some(tx),
        task,
    })
}

async fn handle(State(gw): State<Arc<Gateway>>, req: Request) -> Response {
    // Proxy de sortie : tunnels HTTPS (CONNECT) vers les hôtes autorisés.
    if req.method() == axum::http::Method::CONNECT {
        return handle_connect(gw, req).await;
    }
    let started = Instant::now();
    // Requête de proxy HTTP en clair (`GET http://hôte/…`) : refusée, tout doit être chiffré.
    if req.uri().authority().is_some() {
        let event = Event {
            session: gw.session.clone(),
            kind: "request".into(),
            method: Some(req.method().to_string()),
            route: Some("sortie".into()),
            path: Some(req.uri().to_string()),
            decision: Some("denied".into()),
            reason: Some(
                tr!(
                    "HTTP en clair refusé en sortie",
                    "plaintext HTTP refused on egress"
                )
                .into(),
            ),
            ..Default::default()
        };
        return finish(
            &gw,
            event,
            started,
            403,
            tr!(
                "HTTP en clair refusé : utilisez HTTPS",
                "plaintext HTTP refused: use HTTPS"
            ),
        );
    }
    let method = req.method().as_str().to_string();
    let full_path = req.uri().path().to_string();
    let mut query = req.uri().query().map(str::to_string);

    let mut event = Event {
        session: gw.session.clone(),
        kind: "request".into(),
        method: Some(method.clone()),
        ..Default::default()
    };
    // Mode observation : ce que la passerelle aurait fait (la requête passe quand même).
    let observing = gw.observing();
    let mut would: Vec<String> = Vec::new();

    // 1. Route : premier segment du chemin.
    let trimmed = full_path.trim_start_matches('/');
    let (route_name, rest) = match trimmed.split_once('/') {
        Some((r, rest)) => (r.to_string(), format!("/{rest}")),
        None => (trimmed.to_string(), "/".to_string()),
    };
    event.path = Some(rest.clone());
    let Some(route) = gw.policy.routes.get(&route_name) else {
        event.decision = Some("denied".into());
        event.reason =
            Some(tr!(fmt "route inconnue : {route_name}", "unknown route: {route_name}"));
        return finish(
            &gw,
            event,
            started,
            404,
            &tr!(fmt "route inconnue : « {route_name} »", "unknown route: “{route_name}”"),
        );
    };
    event.route = Some(route.name.clone());

    // 2. Jeton de session : sans lui, la vraie clé n'est jamais injectée.
    if !has_valid_token(req.headers(), route, &gw.token) {
        event.decision = Some("unauthorized".into());
        event.reason = Some(
            tr!(
                "jeton de session absent ou invalide",
                "missing or invalid session token"
            )
            .into(),
        );
        return finish(
            &gw,
            event,
            started,
            401,
            tr!(
                "jeton de session Aestheris absent ou invalide",
                "missing or invalid Aestheris session token"
            ),
        );
    }

    // 3. Chemin sain.
    if let Err(why) = validate_request_path(&rest) {
        event.decision = Some("denied".into());
        event.reason = Some(tr!(fmt "chemin refusé : {why}", "path refused: {why}"));
        return finish(
            &gw,
            event,
            started,
            400,
            &tr!(fmt "chemin refusé : {why}", "path refused: {why}"),
        );
    }

    // 4. Politique de la route (une règle `ask` est traitée après l'inspection du contenu :
    //    on ne dérange pas un humain pour une requête qui serait bloquée de toute façon).
    let mut decision = route.decide(&method, &rest);
    // Disjoncteur déclenché : plus rien (stop) ou validation humaine (ask). Les appels au modèle
    // restent libres en mode ask : il ne voit que des pseudonymes, ce sont les actions qui comptent.
    if decision.verdict != Verdict::Deny {
        match gw.guard_tripped() {
            Some(OnTrip::Stop) => {
                event.decision = Some("denied".into());
                event.reason = Some(
                    tr!(
                        "disjoncteur déclenché : session suspendue",
                        "circuit breaker tripped: session suspended"
                    )
                    .into(),
                );
                return finish(
                    &gw,
                    event,
                    started,
                    403,
                    tr!(
                        "session suspendue par le disjoncteur d'Aestheris (activité suspecte)",
                        "session suspended by the Aestheris circuit breaker (suspicious activity)"
                    ),
                );
            }
            Some(OnTrip::Ask) if !route.privacy => {
                decision = Decision {
                    verdict: Verdict::Ask,
                    reason: tr!(fmt
                        "{} ; disjoncteur déclenché : validation humaine exigée", "{}; circuit breaker tripped: human approval required",
                        decision.reason
                    ),
                };
            }
            _ => {}
        }
    }
    if decision.verdict == Verdict::Deny && observing {
        would.push(tr!(fmt "aurait refusé ({})", "would have denied ({})", decision.reason));
        gw.stats.would_denied.fetch_add(1, Ordering::Relaxed);
        decision.verdict = Verdict::Allow;
    }
    if decision.verdict == Verdict::Deny {
        event.decision = Some("denied".into());
        event.reason = Some(decision.reason.clone());
        return finish(
            &gw,
            event,
            started,
            403,
            &format!("interdit par la politique : {}", decision.reason),
        );
    }

    // 5. Contenu : lu en entier (borné) pour être inspecté avant tout envoi.
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            event.decision = Some("denied".into());
            event.reason = Some("corps trop volumineux".into());
            return finish(
                &gw,
                event,
                started,
                413,
                tr!(
                    "corps de requête trop volumineux (10 Mio maximum)",
                    "request body too large (10 MiB maximum)"
                ),
            );
        }
    };
    if gw.policy.content_secrets == ContentAction::Block {
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        if let Some(q) = &query {
            text.push('\n');
            text.push_str(q);
        }
        let found = scan::detect(&text);
        if !found.is_empty() && observing {
            would.push(tr!(fmt
                "aurait bloqué un secret en clair ({})", "would have blocked a plaintext secret ({})",
                found.join(", ")
            ));
            gw.stats.would_blocked.fetch_add(1, Ordering::Relaxed);
            event.detected = found.iter().map(|s| s.to_string()).collect();
        } else if !found.is_empty() {
            event.decision = Some("blocked".into());
            event.reason = Some(
                tr!(
                    "secret en clair dans le contenu",
                    "plaintext secret in the content"
                )
                .into(),
            );
            event.detected = found.iter().map(|s| s.to_string()).collect();
            return finish(
                &gw,
                event,
                started,
                403,
                &tr!(fmt
                    "secret en clair détecté dans la requête : {}", "plaintext secret detected in the request: {}",
                    found.join(", ")
                ),
            );
        }
    }

    // 6. Données fantômes : vers un service (hors modèle), les pseudonymes que la politique
    //    autorise pour cette route redeviennent réels ; les autres restent des pseudonymes. Avant
    //    la validation humaine : l'humain voit ce qui partira vraiment.
    let mut bytes = bytes;
    if !route.privacy
        && let Some(sh) = &gw.privacy
    {
        let content_type = parts
            .headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if let Some(r) = sh.release_for_route(&bytes, query.as_deref(), &content_type, &route.name)
        {
            let withheld: u32 = r.withheld.values().sum();
            gw.stats
                .withheld
                .fetch_add(u64::from(withheld), Ordering::Relaxed);
            bytes = r.body.into();
            query = r.query;
            event.detail = Some(describe_release(&r.released, &r.withheld));
        }
    }

    // 7. Validation humaine.
    let mut reason = decision.reason.clone();
    if decision.verdict == Verdict::Ask && observing {
        would.push(tr!(fmt
            "aurait demandé une validation humaine ({})", "would have asked for human approval ({})",
            decision.reason
        ));
    } else if decision.verdict == Verdict::Ask {
        let shown = match &query {
            Some(q) => format!("{rest}?{q}"),
            None => rest.clone(),
        };
        let outcome = gw
            .approvals
            .ask(
                format!("route:{}:{method}:{rest}", route.name),
                tr!("requête API", "API request"),
                tr!(fmt "{} : {method} {shown}", "{}: {method} {shown}", route.name),
                format!("{}\n{}", decision.reason, excerpt(&bytes)),
            )
            .await;
        reason = format!(
            "{} → {}",
            decision.reason,
            outcome.describe(gw.approvals.timeout())
        );
        if !matches!(outcome, Outcome::Approved { .. }) {
            event.decision = Some("denied".into());
            event.reason = Some(reason);
            let msg = match outcome {
                Outcome::Expired => tr!(
                    "validation humaine sans réponse : requête refusée",
                    "no answer to the approval request: request denied"
                ),
                _ => tr!("requête refusée par un humain", "request denied by a human"),
            };
            return finish(&gw, event, started, 403, msg);
        }
        gw.stats.approved.fetch_add(1, Ordering::Relaxed);
    }

    // 8. Bouclier de confidentialité (routes de modèles). En observation : on mesure ce qui
    //    aurait été pseudonymisé, sans rien modifier (ni la requête, ni la réponse).
    let shield = if route.privacy {
        gw.privacy.clone()
    } else {
        None
    };
    if observing
        && let Some(sh) = &shield
        && let Ok(mut copy) = serde_json::from_slice::<serde_json::Value>(&bytes)
    {
        let counts = sh.pseudonymize_request(&mut copy);
        if !counts.is_empty() {
            let exposed = counts_list(&counts);
            event.detail = Some(
                tr!(fmt "exposition : {exposed} (transmis tel quel)", "exposure: {exposed} (sent as is)"),
            );
            would.push(
                tr!(
                    "aurait pseudonymisé des données sensibles",
                    "would have pseudonymized sensitive data"
                )
                .into(),
            );
        }
    }
    let shield = if observing { None } else { shield };
    if let Some(sh) = &shield
        && !bytes.is_empty()
    {
        let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            event.decision = Some("blocked".into());
            event.reason = Some(
                tr!(
                    "contenu non JSON sur une route confidentielle",
                    "non-JSON content on a confidential route"
                )
                .into(),
            );
            return finish(
                &gw,
                event,
                started,
                403,
                tr!(
                    "contenu non JSON : le bouclier de confidentialité ne peut pas le protéger",
                    "non-JSON content: the privacy shield cannot protect it"
                ),
            );
        };
        let counts = sh.pseudonymize_request(&mut json);
        bytes = serde_json::to_vec(&json).unwrap_or_default().into();
        event.detail = Some(describe_counts(&counts));
    }

    // 9. Injection et relais.
    let mut url = route.upstream.clone();
    let base = url.path().trim_end_matches('/').to_string();
    url.set_path(&format!("{base}{rest}"));
    url.set_query(query.as_deref());

    let mut headers = filtered_headers(&parts.headers);
    // Les en-têtes qui ont pu porter le jeton fantôme ne partent jamais vers l'amont.
    headers.remove(reqwest::header::AUTHORIZATION);
    headers.remove("x-api-key");
    headers.remove(&route.inject_header);
    if route.phantom {
        // réponse non compressée : elle doit pouvoir être pseudonymisée au passage
        headers.remove(reqwest::header::ACCEPT_ENCODING);
    }
    if let Some(sh) = &shield {
        // réponse non compressée : les pseudonymes doivent pouvoir être rétablis au passage
        headers.remove(reqwest::header::ACCEPT_ENCODING);
        if sh.strips_metadata() {
            let identifying: Vec<_> = headers
                .keys()
                .filter(|k| k.as_str().starts_with("x-stainless-"))
                .cloned()
                .collect();
            for k in identifying {
                headers.remove(k);
            }
            headers.insert(
                reqwest::header::USER_AGENT,
                HeaderValue::from_static("aestheris"),
            );
        }
    }
    let secret = &gw.secrets[&route.name];
    let value = route.inject_format.replace("{}", secret.expose());
    match HeaderValue::from_str(&value) {
        Ok(mut v) => {
            v.set_sensitive(true);
            headers.insert(route.inject_header.clone(), v);
        }
        Err(_) => {
            event.decision = Some("error".into());
            event.reason = Some(tr!("injection impossible", "injection failed").into());
            return finish(
                &gw,
                event,
                started,
                500,
                tr!("injection de la clé impossible", "key injection failed"),
            );
        }
    }

    let upstream = gw
        .client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(bytes)
        .send()
        .await;
    let resp = match upstream {
        Ok(r) => r,
        Err(e) => {
            event.decision = Some("error".into());
            event.reason = Some(
                tr!(fmt "amont injoignable : {}", "upstream unreachable: {}", redact_error(&e)),
            );
            return finish(
                &gw,
                event,
                started,
                502,
                tr!("amont injoignable", "upstream unreachable"),
            );
        }
    };

    let status = resp.status().as_u16();
    let mut builder = Response::builder().status(status);
    for (name, value) in resp.headers() {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            builder = builder.header(name, value);
        }
    }
    builder = builder.header("x-aestheris-decision", "allowed");

    // Réponse : source de données → pseudonymisée avant d'atteindre l'agent ; modèle protégé →
    // pseudonymes rétablis ; sinon relayée en flux (SSE, streaming) sans mise en mémoire tampon.
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = if route.phantom
        && observing
        && let Some(sh) = gw.privacy.clone()
    {
        // Observation : la réponse de la source passe telle quelle ; on note ce qu'elle expose.
        let raw = resp.bytes().await.unwrap_or_default();
        if let Some((_, counts)) = sh.pseudonymize_data(&raw, &content_type, &route.name)
            && !counts.is_empty()
        {
            let exposed = counts_list(&counts);
            event.detail = Some(tr!(fmt
                "source {} : exposé {exposed} (transmis tel quel)", "source {}: exposed {exposed} (sent as is)",
                route.name
            ));
            would.push(
                tr!(
                    "aurait pseudonymisé la réponse de la source",
                    "would have pseudonymized the source's response"
                )
                .into(),
            );
        }
        Body::from(raw)
    } else if route.phantom
        && let Some(sh) = gw.privacy.clone()
    {
        let raw = resp.bytes().await.unwrap_or_default();
        match sh.pseudonymize_data(&raw, &content_type, &route.name) {
            Some((b, counts)) => {
                let note = tr!(fmt
                    "source {} : {}", "source {}: {}",
                    route.name,
                    {
                        let l = counts_list(&counts);
                        tr!(fmt "pseudonymisé {l}", "pseudonymized {l}")
                    }
                );
                event.detail = Some(match event.detail.take() {
                    Some(d) => format!("{d} · {note}"),
                    None => note,
                });
                Body::from(b)
            }
            None => Body::from(raw),
        }
    } else if let Some(sh) = shield {
        rehydrated_body(resp, sh).await
    } else {
        Body::from_stream(resp.bytes_stream())
    };

    event.status = Some(status);
    event.duration_ms = Some(started.elapsed().as_millis() as u64);
    if would.is_empty() {
        event.decision = Some("allowed".into());
        event.reason = Some(reason);
        gw.stats.allowed.fetch_add(1, Ordering::Relaxed);
    } else {
        event.decision = Some("observed".into());
        event.reason = Some(
            tr!(fmt "observation : {} · {reason}", "observation: {} · {reason}", would.join(" · ")),
        );
        gw.stats.observed.fetch_add(1, Ordering::Relaxed);
    }
    record(&gw, event);
    builder.body(body).unwrap_or_else(|_| {
        plain(
            502,
            tr!("réponse amont invalide", "invalid upstream response"),
        )
    })
}

/// Réponse d'une route confidentielle : pseudonymes rétablis, en flux pour les SSE.
async fn rehydrated_body(resp: reqwest::Response, shield: Arc<Shield>) -> Body {
    use futures_util::StreamExt;
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.starts_with("text/event-stream") {
        let state = (resp.bytes_stream(), StreamRehydrator::new(shield), false);
        let stream = futures_util::stream::unfold(state, |(mut up, mut r, done)| async move {
            if done {
                return None;
            }
            match up.next().await {
                Some(Ok(chunk)) => Some((Ok(bytes::Bytes::from(r.push(&chunk))), (up, r, false))),
                Some(Err(e)) => Some((Err(std::io::Error::other(e)), (up, r, true))),
                None => Some((Ok(bytes::Bytes::from(r.finish())), (up, r, true))),
            }
        });
        return Body::from_stream(stream);
    }
    match resp.bytes().await {
        Ok(raw) if content_type.contains("json") => {
            match serde_json::from_slice::<serde_json::Value>(&raw) {
                Ok(mut v) => {
                    shield.rehydrate_response(&mut v);
                    Body::from(serde_json::to_vec(&v).unwrap_or_default())
                }
                Err(_) => Body::from(raw),
            }
        }
        Ok(raw) => Body::from(raw),
        Err(_) => Body::from(tr!(
            "réponse amont interrompue",
            "upstream response interrupted"
        )),
    }
}

/// « données fantômes : libéré EMAIL×1 · retenu IBAN×1 » pour le journal.
fn describe_release(
    released: &crate::privacy::Counts,
    withheld: &crate::privacy::Counts,
) -> String {
    let mut parts = Vec::new();
    if !released.is_empty() {
        let l = counts_list(released);
        parts.push(tr!(fmt "libéré {l}", "released {l}"));
    }
    if !withheld.is_empty() {
        let l = counts_list(withheld);
        parts.push(tr!(fmt "retenu {l}", "withheld {l}"));
    }
    let parts = parts.join(" · ");
    tr!(fmt "données fantômes : {parts}", "phantom data: {parts}")
}

/// « EMAIL×2, CLIENT×1 » (jamais les valeurs).
fn counts_list(c: &crate::privacy::Counts) -> String {
    c.iter()
        .map(|(k, n)| format!("{k}×{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// « confidentialité : EMAIL×2, CLIENT×1 » pour le journal (jamais les valeurs).
pub fn describe_counts(c: &crate::privacy::Counts) -> String {
    if c.is_empty() {
        return tr!(
            "confidentialité : rien à pseudonymiser",
            "confidentiality: nothing to pseudonymize"
        )
        .into();
    }
    let l = counts_list(c);
    tr!(fmt "confidentialité : {l}", "confidentiality: {l}")
}

/* ------------------------------------------------------------------ */
/* Proxy de sortie (CONNECT)                                           */
/* ------------------------------------------------------------------ */

/// Tunnel HTTPS vers un hôte autorisé.
///
/// 1. jeton de session dans `Proxy-Authorization` (Basic ou Bearer)  sinon 407
/// 2. politique de sortie : `none` refuse tout, `allowlist` exige un hôte listé
/// 3. port autorisé (443 par défaut), et jamais l'hôte d'une route (il faut passer par la route)
/// 4. résolution DNS, puis refus si UNE adresse est interne, lien-local ou de métadonnées cloud
/// 5. connexion à l'adresse vérifiée elle-même (pas de nouvelle résolution : anti « DNS rebinding »)
async fn handle_connect(gw: Arc<Gateway>, req: Request) -> Response {
    let started = Instant::now();
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let mut event = Event {
        session: gw.session.clone(),
        kind: "request".into(),
        method: Some("CONNECT".into()),
        route: Some("sortie".into()),
        path: Some(target.clone()),
        ..Default::default()
    };

    if !proxy_auth_ok(req.headers(), &gw.token) {
        event.decision = Some("unauthorized".into());
        event.reason = Some(
            tr!(
                "jeton de session absent du proxy",
                "session token missing from the proxy request"
            )
            .into(),
        );
        let mut r = finish(
            &gw,
            event,
            started,
            407,
            tr!(
                "authentification du proxy Aestheris requise",
                "Aestheris proxy authentication required"
            ),
        );
        r.headers_mut().insert(
            "proxy-authenticate",
            HeaderValue::from_static("Basic realm=\"aestheris\""),
        );
        return r;
    }

    let deny = |mut event: Event, reason: String| {
        event.decision = Some("denied".into());
        event.reason = Some(reason.clone());
        finish(&gw, event, started, 403, &reason)
    };

    // Disjoncteur déclenché : sortie refusée (stop) ou soumise à un humain (ask).
    match gw.guard_tripped() {
        Some(OnTrip::Stop) => {
            return deny(
                event,
                tr!(
                    "disjoncteur déclenché : session suspendue",
                    "circuit breaker tripped: session suspended"
                )
                .into(),
            );
        }
        Some(OnTrip::Ask) => {
            let outcome = gw
                .approvals
                .ask(
                    format!("guard:{target}"),
                    tr!("sortie réseau", "network egress"),
                    tr!(fmt "connexion à {target} (disjoncteur déclenché)", "connection to {target} (circuit breaker tripped)"),
                    tr!("activité suspecte dans la session : validation humaine exigée", "suspicious activity in the session: human approval required").into(),
                )
                .await;
            if !matches!(outcome, Outcome::Approved { .. }) {
                let why = outcome.describe(gw.approvals.timeout());
                return deny(
                    event,
                    tr!(fmt "disjoncteur : {why}", "circuit breaker: {why}"),
                );
            }
        }
        None => {}
    }

    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            p.parse::<u16>().unwrap_or(0),
        ),
        None => (target.clone(), 443),
    };
    // Mode observation : la politique de sortie est notée, pas appliquée (le refus des adresses
    // internes, plus bas, reste toujours actif).
    let observing = gw.observing();
    let mut would: Vec<String> = Vec::new();
    let mut policy_refusal = |why: String| -> Option<String> {
        if observing {
            would.push(tr!(fmt "aurait refusé ({why})", "would have denied ({why})"));
            gw.stats.would_denied.fetch_add(1, Ordering::Relaxed);
            None
        } else {
            Some(why)
        }
    };
    if !gw.policy.allow_ports.contains(&port)
        && let Some(why) = policy_refusal(tr!(fmt
            "port {port} refusé en sortie (network.allow_ports)", "port {port} refused on egress (network.allow_ports)"
        ))
    {
        return deny(event, why);
    }
    if gw.policy.egress == Egress::None
        && let Some(why) = policy_refusal(
            tr!(
                "aucune sortie réseau autorisée par la politique",
                "no network egress allowed by the policy"
            )
            .into(),
        )
    {
        return deny(event, why);
    }
    if gw.policy.is_route_host(&host)
        && let Some(why) = policy_refusal(tr!(fmt
            "{host} est servi par une route : utilisez son URL de base (politique et clé)", "{host} is served by a route: use its base URL (policy and key)"
        ))
    {
        return deny(event, why);
    }
    let mut reason = tr!(
        "tunnel HTTPS vers un hôte autorisé",
        "HTTPS tunnel to an allowed host"
    )
    .to_string();
    if gw.policy.egress == Egress::Allowlist && !gw.policy.host_allowed(&host) && observing {
        would.push(tr!(fmt
            "aurait refusé ou soumis à validation ({host} hors liste blanche)", "would have denied or asked for approval ({host} outside the allowlist)"
        ));
    } else if gw.policy.egress == Egress::Allowlist && !gw.policy.host_allowed(&host) {
        if !gw.policy.ask_unknown_hosts {
            return deny(
                event,
                tr!(fmt "{host} n'est pas dans network.allow_hosts", "{host} is not in network.allow_hosts"),
            );
        }
        // Hôte inconnu : un humain décide. L'approbation ne dispense pas du contrôle des adresses.
        let outcome = gw
            .approvals
            .ask(
                format!("host:{host}:{port}"),
                tr!("sortie réseau", "network egress"),
                tr!(fmt "connexion à {host}:{port}", "connection to {host}:{port}"),
                tr!(fmt "{host} n'est pas dans network.allow_hosts", "{host} is not in network.allow_hosts"),
            )
            .await;
        let what = tr!(fmt
            "{host} hors liste blanche → {}", "{host} outside the allowlist → {}",
            outcome.describe(gw.approvals.timeout())
        );
        if !matches!(outcome, Outcome::Approved { .. }) {
            return deny(event, what);
        }
        gw.stats.approved.fetch_add(1, Ordering::Relaxed);
        reason = what;
    }

    let addrs: Vec<SocketAddr> = match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(a)) => a.collect(),
        _ => Vec::new(),
    };
    if addrs.is_empty() {
        event.decision = Some("error".into());
        event.reason =
            Some(tr!(fmt "résolution DNS impossible : {host}", "DNS resolution failed: {host}"));
        return finish(
            &gw,
            event,
            started,
            502,
            tr!("hôte introuvable", "host not found"),
        );
    }
    if let Some(bad) = addrs.iter().find(|a| {
        ip_forbidden(&a.ip(), gw.policy.allow_insecure_loopback) || is_own_address(&a.ip())
    }) {
        return deny(
            event,
            tr!(fmt
                "{host} résout vers une adresse interne interdite ({})", "{host} resolves to a forbidden internal address ({})",
                bad.ip()
            ),
        );
    }

    let upstream = match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(addrs[0]),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            event.decision = Some("error".into());
            event.reason =
                Some(tr!(fmt "connexion impossible : {host}", "connection failed: {host}"));
            return finish(
                &gw,
                event,
                started,
                502,
                tr!("amont injoignable", "upstream unreachable"),
            );
        }
    };

    event.status = Some(200);
    event.duration_ms = Some(started.elapsed().as_millis() as u64);
    if would.is_empty() {
        event.decision = Some("allowed".into());
        event.reason = Some(reason);
        gw.stats.allowed.fetch_add(1, Ordering::Relaxed);
    } else {
        event.decision = Some("observed".into());
        event.reason = Some(
            tr!(fmt "observation : {} · {reason}", "observation: {} · {reason}", would.join(" · ")),
        );
        gw.stats.observed.fetch_add(1, Ordering::Relaxed);
    }
    record(&gw, event);

    // Le tunnel s'ouvre une fois la réponse 200 envoyée au client.
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(req).await {
            let mut client = hyper_util::rt::TokioIo::new(upgraded);
            let mut upstream = upstream;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    });
    Response::new(Body::empty())
}

/// `Proxy-Authorization: Basic base64(utilisateur:jeton)` ou `Bearer jeton`.
fn proxy_auth_ok(headers: &HeaderMap, token: &SessionToken) -> bool {
    use base64::Engine as _;
    let Some(value) = headers
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let value = value.trim();
    if let Some(b) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    {
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b.trim()) else {
            return false;
        };
        let Ok(text) = String::from_utf8(raw) else {
            return false;
        };
        return text
            .split_once(':')
            .is_some_and(|(_, pass)| token.matches(pass));
    }
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .is_some_and(|t| token.matches(t.trim()))
}

/// Cherche le jeton fantôme dans les en-têtes usuels des SDK : `Authorization: Bearer …`,
/// `x-api-key: …`, ou l'en-tête d'injection de la route (avec son format).
fn has_valid_token(headers: &HeaderMap, route: &Route, token: &SessionToken) -> bool {
    let mut candidates: Vec<String> = Vec::new();
    for name in [
        reqwest::header::AUTHORIZATION.as_str(),
        "x-api-key",
        route.inject_header.as_str(),
    ] {
        for v in headers.get_all(name).iter() {
            if let Ok(s) = v.to_str() {
                let s = s.trim();
                candidates.push(s.to_string());
                if let Some(rest) = s
                    .strip_prefix("Bearer ")
                    .or_else(|| s.strip_prefix("bearer "))
                {
                    candidates.push(rest.trim().to_string());
                }
                // format de la route, ex. « Bearer {} » ou « Token {} »
                if let Some((pre, post)) = route.inject_format.split_once("{}")
                    && let Some(inner) = s.strip_prefix(pre).and_then(|x| x.strip_suffix(post))
                {
                    candidates.push(inner.to_string());
                }
            }
        }
    }
    // On évalue tous les candidats (pas d'arrêt anticipé) pour garder un temps constant par candidat.
    candidates.iter().fold(false, |ok, c| token.matches(c) | ok)
}

fn filtered_headers(input: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in input {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Début du contenu montré à l'humain qui valide (300 caractères, sans caractères de contrôle).
fn excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out: String = text
        .chars()
        .take(300)
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    if text.chars().count() > 300 {
        out.push('…');
    }
    out
}

/// Message d'erreur réseau sans URL complète (qui pourrait contenir des paramètres sensibles).
fn redact_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        tr!("délai dépassé", "timed out").into()
    } else if e.is_connect() {
        tr!("connexion refusée", "connection refused").into()
    } else {
        tr!("erreur de transport", "transport error").into()
    }
}

fn record(gw: &Gateway, event: Event) {
    if let Err(e) = gw.audit.append(event) {
        eprintln!(
            "{}",
            tr!(fmt "aestheris : écriture du journal d'audit impossible : {e}",
                "aestheris: cannot write the audit log: {e}")
        );
    }
}

fn finish(
    gw: &Gateway,
    mut event: Event,
    started: Instant,
    status: u16,
    message: &str,
) -> Response {
    event.status = Some(status);
    event.duration_ms = Some(started.elapsed().as_millis() as u64);
    let counter = match event.decision.as_deref() {
        Some("blocked") => &gw.stats.blocked,
        Some("unauthorized") => &gw.stats.unauthorized,
        Some("error") => &gw.stats.errors,
        _ => &gw.stats.denied,
    };
    counter.fetch_add(1, Ordering::Relaxed);
    let decision = event.decision.clone().unwrap_or_default();
    let route = event.route.clone();
    record(gw, event);
    let body = serde_json::json!({
        "error": { "type": "aestheris", "decision": decision, "route": route, "message": message }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-aestheris-decision", decision)
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| plain(status, message))
}

fn plain(status: u16, message: &str) -> Response {
    let mut r = Response::new(Body::from(message.to_string()));
    *r.status_mut() =
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    r
}
