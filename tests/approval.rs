//! Validation humaine de bout en bout : une règle `ask` retient la requête jusqu'à la réponse d'un
//! humain (par le canal local), l'agent ne peut pas répondre lui-même, et le journal consigne qui a
//! décidé.

use aestheris::approval::{self, Message, Pending, Scope};
use aestheris::proxy;
use aestheris::run;
use aestheris::vault::{KdfParams, Vault};
use base64::Engine as _;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "mot de passe de test solide";
const REAL_SECRET: &str = concat!("sk_test_", "VraieCleUltraSecrete123456");

/// Fausse API : compte les requêtes et vérifie que la vraie clé arrive.
async fn upstream() -> (u16, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let h = h.clone();
        async move {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert_eq!(
                auth,
                format!("Bearer {REAL_SECRET}"),
                "la vraie clé doit être injectée"
            );
            h.fetch_add(1, Ordering::SeqCst);
            axum::Json(serde_json::json!({ "ok": true }))
        }
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, hits)
}

async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn raw_connect(gateway: std::net::SocketAddr, target: String, token: String) -> String {
    let mut s = TcpStream::connect(gateway).await.unwrap();
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

/// Prochaine demande encore jamais vue (le canal peut annoncer deux fois la même).
async fn next_pending(human: &mut approval::Client, seen: &mut HashSet<u64>) -> Pending {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), human.next())
            .await
            .expect("une demande de validation doit arriver")
            .unwrap()
            .expect("canal ouvert");
        if let Message::Pending { item } = m
            && seen.insert(item.id)
        {
            return item;
        }
    }
}

#[tokio::test]
async fn validation_humaine_de_bout_en_bout() {
    let dir = tempfile::tempdir().unwrap();
    let (api_port, hits) = upstream().await;
    let echo_port = echo_server().await;

    let vault = dir.path().join("vault.json");
    Vault::create(&vault, PASSWORD, KdfParams::insecure_for_tests())
        .unwrap()
        .set("stripe/test", REAL_SECRET)
        .unwrap();
    let policy = dir.path().join("aestheris.yaml");
    std::fs::write(
        &policy,
        format!(
            r#"version: 1
routes:
  stripe:
    upstream: http://localhost:{api_port}
    secret: stripe/test
    inject: {{ header: Authorization, format: "Bearer {{}}" }}
    rules:
      - {{ action: ask, methods: [POST], path: "/v1/refunds/**" }}
      - {{ action: allow, methods: [GET, POST], path: "/v1/**" }}
network:
  allow_insecure_loopback: true
  egress: allowlist
  ask_unknown_hosts: true
  allow_ports: [443, {echo_port}]
sandbox:
  enabled: true
approval:
  timeout_secs: 5
  notify: false
"#
        ),
    )
    .unwrap();
    let audit = dir.path().join("audit.ndjson");

    let (gw, _) = run::prepare(&policy, &vault, &audit, PASSWORD).unwrap();
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let admin = approval::serve(gw.approvals.clone(), &dir.path().join("run")).unwrap();
    let base = format!("http://{}/stripe", running.addr);
    let token = gw.token_for_agent().to_string();
    let http = reqwest::Client::new();
    let refund = |id: &str| {
        let req = http
            .post(format!("{base}/v1/refunds/{id}"))
            .bearer_auth(&token)
            .body("amount=500&reason=duplicate");
        tokio::spawn(async move { req.send().await.unwrap() })
    };

    let mut human = approval::Client::connect(admin.path()).await.unwrap();
    human.watch().await.unwrap();
    let mut seen = HashSet::new();

    // 1. Approuvée une fois : l'humain voit ce qu'il autorise, la requête part avec la vraie clé.
    let pending_req = refund("re_1");
    let item = next_pending(&mut human, &mut seen).await;
    assert_eq!(item.kind, "requête API");
    assert!(
        item.summary.contains("POST /v1/refunds/re_1"),
        "{}",
        item.summary
    );
    assert!(item.detail.contains("amount=500"), "{}", item.detail);
    human.decide(item.id, true, Scope::Once).await.unwrap();
    assert_eq!(pending_req.await.unwrap().status(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // un remboursement ordinaire n'est pas concerné
    let charge = http
        .post(format!("{base}/v1/charges"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(charge.status(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // 2. Refusée : rien ne part.
    let pending_req = refund("re_2");
    let item = next_pending(&mut human, &mut seen).await;
    human.decide(item.id, false, Scope::Once).await.unwrap();
    let r = pending_req.await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("refusée par un humain"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // 3. Approuvée pour la session : la même requête repasse sans nouvelle demande.
    let pending_req = refund("re_3");
    let item = next_pending(&mut human, &mut seen).await;
    human.decide(item.id, true, Scope::Session).await.unwrap();
    assert_eq!(pending_req.await.unwrap().status(), 200);
    let again = refund("re_3").await.unwrap();
    assert_eq!(again.status(), 200);
    assert!(gw.approvals.pending().is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 4);

    // 4. Sortie réseau vers un hôte hors liste blanche : un humain décide, puis le tunnel s'ouvre.
    let target = format!("127.0.0.1:{echo_port}");
    let tunnel = tokio::spawn(raw_connect(running.addr, target.clone(), token.clone()));
    let item = next_pending(&mut human, &mut seen).await;
    assert_eq!(item.kind, "sortie réseau");
    assert!(item.summary.contains(&target));
    human.decide(item.id, true, Scope::Once).await.unwrap();
    assert!(tunnel.await.unwrap().starts_with("HTTP/1.1 200"));

    // 5. L'agent (ici : ce processus et ses descendants) ne peut pas répondre à sa propre demande.
    gw.approvals.set_agent_pid(std::process::id());
    let mut agent = approval::Client::connect(admin.path()).await.unwrap();
    agent.list().await.unwrap();
    match agent.next().await.unwrap() {
        Some(Message::Error { message }) => assert!(message.contains("l'agent ne peut pas")),
        other => panic!("l'agent a obtenu une réponse du canal : {other:?}"),
    }

    // 6. Sans réponse dans le délai : refus (fail secure).
    let started = Instant::now();
    let r = refund("re_4").await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("sans réponse"));
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert_eq!(hits.load(Ordering::SeqCst), 4);

    running.stop().await;
    drop(admin);

    // Journal : intact, chaque décision et son auteur consignés, jamais la clé.
    assert!(aestheris::audit::verify(&audit).unwrap().ok);
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("approuvée par un humain"));
    assert!(log.contains("(pour la session)"));
    assert!(log.contains("refusée par un humain"));
    assert!(log.contains("sans réponse en 5 s"));
    assert!(!log.contains(REAL_SECRET));
    assert!(
        !dir.path()
            .join("run")
            .join(format!("{}.sock", gw.session()))
            .exists(),
        "canal retiré"
    );
}

/// Un dossier très profond dépasse la limite d'adresse des sockets Unix : le canal passe par un
/// lien vers /tmp/aestheris-<uid>, et le client le suit.
#[tokio::test]
async fn canal_dans_un_dossier_tres_profond() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir
        .path()
        .join("a".repeat(60))
        .join("b".repeat(60))
        .join("run");
    let broker = Arc::new(approval::Broker::new(
        "profond0123456789".into(),
        Duration::from_secs(5),
        false,
    ));
    let admin = approval::serve(broker, &deep).unwrap();
    assert!(admin.path().as_os_str().len() > 104);
    let mut c = approval::Client::connect(admin.path()).await.unwrap();
    c.list().await.unwrap();
    assert!(matches!(c.next().await.unwrap(), Some(Message::List { items }) if items.is_empty()));
    let real = std::fs::canonicalize(admin.path()).unwrap();
    drop(admin);
    assert!(!real.exists(), "socket réel retiré à l'arrêt");
}
