//! Mode observation : rien n'est bloqué ni modifié par la politique, tout est noté, et le rapport
//! montre ce qu'Aestheris aurait fait. Les protections vitales restent actives.

use aestheris::proxy;
use aestheris::run;
use aestheris::vault::{KdfParams, Vault};
use axum::extract::{Request, State};
use base64::Engine as _;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "mot de passe de test solide";

/// Service qui note ce qu'il reçoit et répond comme un modèle (JSON).
async fn recorder() -> (u16, Arc<Mutex<Vec<String>>>) {
    let got: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    async fn handle(
        State(got): State<Arc<Mutex<Vec<String>>>>,
        req: Request,
    ) -> axum::Json<serde_json::Value> {
        let line = format!("{} {}", req.method(), req.uri().path());
        let body = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap();
        got.lock()
            .unwrap()
            .push(format!("{line} {}", String::from_utf8_lossy(&body)));
        axum::Json(serde_json::json!({ "content": [{ "type": "text", "text": "ok" }] }))
    }
    let app = axum::Router::new().fallback(handle).with_state(got.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, got)
}

async fn echo_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 64];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn connect(gw: std::net::SocketAddr, target: &str, token: &str) -> String {
    let mut s = TcpStream::connect(gw).await.unwrap();
    let b = base64::engine::general_purpose::STANDARD.encode(format!("aestheris:{token}"));
    s.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {b}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).await.unwrap() == 1 {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).to_string()
}

#[tokio::test]
async fn observation_rien_n_est_bloque_tout_est_note() {
    let dir = tempfile::tempdir().unwrap();
    let (api_port, api) = recorder().await;
    let (llm_port, llm) = recorder().await;
    let echo = echo_port().await;
    let vault = dir.path().join("vault.json");
    let mut v = Vault::create(&vault, PASSWORD, KdfParams::insecure_for_tests()).unwrap();
    v.set("api/key", "valeur-api-factice").unwrap();
    v.set(
        "llm/key",
        concat!("sk-ant-", "api03-CleDeTest0123456789abcdef"),
    )
    .unwrap();
    let policy = dir.path().join("aestheris.yaml");
    std::fs::write(
        &policy,
        format!(
            r#"version: 1
mode: observe
routes:
  api:
    upstream: http://localhost:{api_port}
    secret: api/key
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules:
      - {{ action: deny, methods: [DELETE] }}
      - {{ action: ask, methods: [PUT] }}
      - {{ action: allow, methods: [GET, POST] }}
  llm:
    upstream: http://localhost:{llm_port}
    secret: llm/key
    inject: {{ header: x-api-key, format: "{{}}" }}
    privacy: true
    rules: [ {{ action: allow, methods: [POST], path: "/v1/messages" }} ]
network:
  allow_insecure_loopback: true
  egress: allowlist
  allow_ports: [443, {echo}]
sandbox:
  enabled: true
guard:
  max_denied: 1
"#
        ),
    )
    .unwrap();
    let audit = dir.path().join("audit.ndjson");
    let (gw, _) = run::prepare(&policy, &vault, &audit, PASSWORD).unwrap();
    assert!(
        !gw.policy().uses_approval(),
        "en observation, aucun canal de validation n'est ouvert"
    );
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let base = format!("http://{}", running.addr);
    let token = gw.token_for_agent().to_string();
    let http = reqwest::Client::new();
    let call = |method: reqwest::Method, path: &str, body: &str| {
        http.request(method, format!("{base}/{path}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };

    // Tout passe : suppression interdite, secret en clair, action à valider (sans attendre).
    assert_eq!(
        call(reqwest::Method::DELETE, "api/clients/1", "")
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        call(
            reqwest::Method::POST,
            "api/notes",
            r#"{"n":"AKIAIOSFODNN7EXAMPLE"}"#
        )
        .await
        .unwrap()
        .status(),
        200
    );
    assert_eq!(
        call(reqwest::Method::PUT, "api/clients/1", "{}")
            .await
            .unwrap()
            .status(),
        200
    );
    // Le modèle reçoit les données telles quelles ; l'exposition est mesurée.
    let r = call(
        reqwest::Method::POST,
        "llm/v1/messages",
        r#"{"messages":[{"role":"user","content":"Relance marie@dupont.fr"}]}"#,
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 200);
    // Sortie hors liste blanche : passe ; adresse interne : toujours refusée.
    assert!(
        connect(running.addr, &format!("127.0.0.1:{echo}"), &token)
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        connect(running.addr, "10.1.2.3:443", &token)
            .await
            .starts_with("HTTP/1.1 403")
    );
    running.stop().await;

    assert_eq!(api.lock().unwrap().len(), 3, "l'API a tout reçu");
    assert!(
        llm.lock().unwrap()[0].contains("marie@dupont.fr"),
        "en observation, rien n'est modifié"
    );

    let events = aestheris::audit::tail(&audit, usize::MAX).unwrap();
    let report = aestheris::report::render(&events, "audit.ndjson");
    for expected in [
        "Observation (rien n'a été bloqué)",
        "données sensibles transmises telles quelles aux fournisseurs : EMAIL×1",
        "secrets en clair qui auraient été bloqués : 1 (AWS_ACCESS_KEY",
        "requêtes qui auraient été refusées        : 1",
        "validations humaines qui auraient été demandées : 1",
        "sorties réseau hors liste blanche         : 127.0.0.1:",
        "disjoncteur qui aurait sauté              : 1",
    ] {
        assert!(
            report.contains(expected),
            "« {expected} » absent du rapport :\n{report}"
        );
    }
    assert!(aestheris::audit::verify(&audit).unwrap().ok);
}
