//! Tests de bout en bout : une fausse API locale enregistre tout ce qu'elle reçoit, et l'on vérifie
//! que la passerelle injecte la vraie clé, refuse ce qu'elle doit refuser et journalise tout.

use aestheris::audit;
use aestheris::proxy;
use aestheris::run;
use aestheris::vault::{KdfParams, Vault};
use axum::Router;
use axum::extract::{Request, State};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const REAL_SECRET: &str = concat!("sk_test_", "VraieCleUltraSecrete123456");
const PASSWORD: &str = "mot de passe de test solide";

#[derive(Debug, Clone)]
struct Received {
    method: String,
    path: String,
    authorization: Option<String>,
    headers_dump: String,
}

type Log = Arc<Mutex<Vec<Received>>>;

/// Fausse API (joue le rôle de api.stripe.com) : note chaque requête reçue.
async fn mock_upstream() -> (String, Log) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    async fn record(State(log): State<Log>, req: Request) -> axum::Json<serde_json::Value> {
        let headers_dump = format!("{:?}", req.headers());
        let authorization = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let r = Received {
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            authorization,
            headers_dump,
        };
        log.lock().unwrap().push(r.clone());
        axum::Json(serde_json::json!({ "ok": true, "path": r.path }))
    }
    let app = Router::new().fallback(record).with_state(log.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), log)
}

fn setup(dir: &Path, upstream: &str) -> (PathBuf, PathBuf, PathBuf) {
    let vault_path = dir.join("vault.json");
    let mut v = Vault::create(&vault_path, PASSWORD, KdfParams::insecure_for_tests()).unwrap();
    v.set("stripe/test", REAL_SECRET).unwrap();

    let policy_path = dir.join("aestheris.yaml");
    std::fs::write(
        &policy_path,
        format!(
            r#"version: 1
routes:
  stripe:
    upstream: {upstream}
    secret: stripe/test
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    env: STRIPE_API_KEY
    base_url_env: STRIPE_API_BASE
    rules:
      - {{ action: deny, methods: [DELETE] }}
      - {{ action: allow, methods: [GET, POST], path: "/v1/**" }}
content:
  secrets: block
network:
  allow_insecure_loopback: true
"#
        ),
    )
    .unwrap();
    (policy_path, vault_path, dir.join("audit.ndjson"))
}

#[tokio::test]
async fn la_passerelle_injecte_filtre_et_journalise() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = mock_upstream().await;
    let (policy, vault, audit_path) = setup(dir.path(), &upstream);

    let (gw, _session) = run::prepare(&policy, &vault, &audit_path, PASSWORD).unwrap();
    let phantom = gw.token_for_agent().to_string();
    assert!(phantom.starts_with("aes_ph_"));
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let base = format!("http://{}/stripe", running.addr);
    let http = reqwest::Client::new();
    let count = || received.lock().unwrap().len();

    // 1. Requête autorisée : l'API reçoit la VRAIE clé, jamais le jeton fantôme.
    let r = http
        .post(format!("{base}/v1/charges"))
        .bearer_auth(&phantom)
        .body("amount=2000&currency=eur")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-aestheris-decision"], "allowed");
    let got = received.lock().unwrap()[0].clone();
    assert_eq!(got.method, "POST");
    assert_eq!(got.path, "/v1/charges");
    assert_eq!(
        got.authorization.as_deref(),
        Some(format!("Bearer {REAL_SECRET}").as_str())
    );
    assert!(
        !got.headers_dump.contains(&phantom),
        "le jeton fantôme ne doit jamais atteindre l'API"
    );

    // 2. Sans jeton : 401 et l'API n'est jamais appelée.
    let r = http
        .post(format!("{base}/v1/charges"))
        .body("amount=1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // 3. Mauvais jeton : 401.
    let r = http
        .post(format!("{base}/v1/charges"))
        .bearer_auth("aes_ph_faux")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // 4. Méthode interdite par la politique : 403.
    let r = http
        .delete(format!("{base}/v1/customers/cus_1"))
        .bearer_auth(&phantom)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // 5. Chemin hors des règles : refus par défaut.
    let r = http
        .get(format!("{base}/v2/admin"))
        .bearer_auth(&phantom)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // 6. Secret en clair dans le contenu : bloqué.
    let r = http
        .post(format!("{base}/v1/notes"))
        .bearer_auth(&phantom)
        .body("voici ma clé AWS AKIAIOSFODNN7EXAMPLE")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(r.headers()["x-aestheris-decision"], "blocked");
    // 7. Tentative de remontée de chemin encodée : 400. Envoyée « brute » car un client HTTP
    //    normal réécrirait lui-même `%2e%2e` avant l'envoi.
    let raw = format!(
        "GET /stripe/v1/%2e%2e/admin HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {phantom}\r\nConnection: close\r\n\r\n",
        addr = running.addr
    );
    let mut sock = tokio::net::TcpStream::connect(running.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    sock.write_all(raw.as_bytes()).await.unwrap();
    let mut answer = String::new();
    sock.read_to_string(&mut answer).await.unwrap();
    assert!(
        answer.starts_with("HTTP/1.1 400"),
        "réponse : {}",
        answer.lines().next().unwrap_or("")
    );
    // 8. Route inconnue : 404.
    let r = http
        .get(format!("http://{}/github/user", running.addr))
        .bearer_auth(&phantom)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    assert_eq!(count(), 1, "seule la requête autorisée a atteint l'API");
    running.stop().await;

    // Journal : chaîne intacte, 1 ouverture + 8 requêtes, aucune valeur secrète.
    let report = audit::verify(&audit_path).unwrap();
    assert!(report.ok);
    assert_eq!(report.count, 9);
    let raw = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        !raw.contains(REAL_SECRET)
            && !raw.contains(&phantom)
            && !raw.contains("AKIAIOSFODNN7EXAMPLE")
    );
    assert!(
        raw.contains("AWS_ACCESS_KEY"),
        "le type de secret détecté est journalisé"
    );
}

#[tokio::test]
async fn aestheris_run_donne_un_fantome_a_l_agent() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = mock_upstream().await;
    let (policy, vault, audit_path) = setup(dir.path(), &upstream);
    let seen = dir.path().join("vu-par-l-agent.txt");
    let resp = dir.path().join("reponse.json");

    // L'« agent » : un script qui lit sa variable de clé et appelle l'API via la passerelle.
    let script = format!(
        r#"printf '%s' "$STRIPE_API_KEY" > '{seen}' && curl -s -X POST -H "Authorization: Bearer $STRIPE_API_KEY" -d amount=100 "$STRIPE_API_BASE/v1/charges" > '{resp}'"#,
        seen = seen.display(),
        resp = resp.display()
    );
    let command = vec!["sh".to_string(), "-c".to_string(), script];
    let code = run::run(run::RunOptions {
        policy: &policy,
        vault: &vault,
        audit: &audit_path,
        password: PASSWORD,
        command: &command,
        run_dir: &std::env::temp_dir().join(format!("aestheris-test-run-{}", std::process::id())),
        sandbox_init: Some(std::path::Path::new(env!("CARGO_BIN_EXE_aestheris"))),
    })
    .await
    .unwrap();
    assert_eq!(code, 0);

    let agent_saw = std::fs::read_to_string(&seen).unwrap();
    assert!(
        agent_saw.starts_with("aes_ph_"),
        "l'agent n'a reçu qu'un jeton fantôme"
    );
    assert!(!agent_saw.contains(REAL_SECRET));
    assert!(
        std::fs::read_to_string(&resp)
            .unwrap()
            .contains("\"ok\":true")
    );
    let got = received.lock().unwrap()[0].clone();
    assert_eq!(
        got.authorization.as_deref(),
        Some(format!("Bearer {REAL_SECRET}").as_str())
    );

    let report = audit::verify(&audit_path).unwrap();
    assert!(report.ok);
    assert_eq!(report.count, 3, "ouverture, requête, fermeture de session");
}
