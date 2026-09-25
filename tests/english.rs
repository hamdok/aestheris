//! Interface en anglais : journal et rapport d'une vraie session, et rapport d'un journal écrit
//! en français (les repères des deux langues sont reconnus).

use aestheris::i18n::{self, Lang};
use aestheris::proxy;
use aestheris::run;
use aestheris::vault::{KdfParams, Vault};
use tokio::net::TcpListener;

const PASSWORD: &str = "mot de passe de test solide";

async fn upstream() -> u16 {
    async fn handle() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({ "content": [{ "type": "text", "text": "ok" }] }))
    }
    let app = axum::Router::new().fallback(handle);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

#[tokio::test]
async fn session_observee_journal_et_rapport_en_anglais() {
    i18n::set(Lang::En);
    let dir = tempfile::tempdir().unwrap();
    let port = upstream().await;
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
    upstream: http://localhost:{port}
    secret: api/key
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules:
      - {{ action: deny, methods: [DELETE] }}
      - {{ action: allow, methods: [GET, POST] }}
  llm:
    upstream: http://localhost:{port}
    secret: llm/key
    inject: {{ header: x-api-key, format: "{{}}" }}
    privacy: true
    rules: [ {{ action: allow, methods: [POST], path: "/v1/messages" }} ]
network:
  allow_insecure_loopback: true
  egress: open
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
    for (method, path, body) in [
        (reqwest::Method::DELETE, "api/clients/1", ""),
        (
            reqwest::Method::POST,
            "llm/v1/messages",
            r#"{"messages":[{"role":"user","content":"Follow up with jane@acme.io"}]}"#,
        ),
    ] {
        let r = http
            .request(method, format!("{base}/{path}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    running.stop().await;

    let events = aestheris::audit::tail(&audit, usize::MAX).unwrap();
    let reasons: Vec<String> = events.iter().filter_map(|e| e.reason.clone()).collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("would have denied (rule 1 denies DELETE)")),
        "{reasons:?}"
    );
    let report = aestheris::report::render(&events, "audit.ndjson");
    for expected in [
        "Aestheris report",
        "Agent activity: 2 request(s) relayed",
        "Observation (nothing was blocked)",
        "sensitive data sent as is to providers : EMAIL×1",
        "requests that would have been denied  : 1",
        "→ to protect: set mode: enforce in the policy",
    ] {
        assert!(
            report.contains(expected),
            "« {expected} » absent :\n{report}"
        );
    }

    // Un journal écrit en français reste lisible par l'interface anglaise.
    let french = aestheris::audit::Event {
        kind: "request".into(),
        route: Some("anthropic".into()),
        decision: Some("allowed".into()),
        reason: Some("règle 1 autorise POST sur /v1/messages".into()),
        detail: Some("confidentialité : EMAIL×2, CLIENT×1".into()),
        ..Default::default()
    };
    let report = aestheris::report::render(&[french], "ancien.ndjson");
    assert!(
        report.contains("pseudonymized towards providers    : EMAIL×2, CLIENT×1"),
        "{report}"
    );
}
