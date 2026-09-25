//! Tests réels du proxy de sortie et du bac à sable macOS.

use aestheris::proxy;
use aestheris::run;
use aestheris::vault::{KdfParams, Vault};
use base64::Engine as _;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "mot de passe de test solide";
const REAL_SECRET: &str = concat!("sk_test_", "VraieCleUltraSecrete123456");

/// Serveur « écho » TCP : renvoie tout ce qu'il reçoit (joue un site externe derrière un tunnel).
async fn echo_server(bind: &str) -> u16 {
    let l = TcpListener::bind(bind).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
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

/// Petit serveur HTTP qui répond toujours 200 {"ok":true} (joue l'API derrière une route).
async fn http_ok(bind: &str) -> u16 {
    let l = TcpListener::bind(bind).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app =
        axum::Router::new().fallback(|| async { axum::Json(serde_json::json!({ "ok": true })) });
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

fn write_policy(dir: &Path, route_port: u16, extra: &str) -> (PathBuf, PathBuf, PathBuf) {
    let vault = dir.join("vault.json");
    Vault::create(&vault, PASSWORD, KdfParams::insecure_for_tests())
        .unwrap()
        .set("stripe/test", REAL_SECRET)
        .unwrap();
    let policy = dir.join("aestheris.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
routes:
  stripe:
    upstream: http://localhost:{route_port}
    secret: stripe/test
    inject: {{ header: Authorization, format: \"Bearer {{}}\" }}
    env: STRIPE_API_KEY
    base_url_env: STRIPE_API_BASE
    rules:
      - {{ action: allow, methods: [GET, POST], path: \"/v1/**\" }}
{extra}"
        ),
    )
    .unwrap();
    (policy, vault, dir.join("audit.ndjson"))
}

async fn raw_connect(
    gateway: std::net::SocketAddr,
    target: &str,
    auth: Option<&str>,
) -> (String, TcpStream) {
    let mut s = TcpStream::connect(gateway).await.unwrap();
    let auth_line = auth
        .map(|t| {
            let b = base64::engine::general_purpose::STANDARD.encode(format!("aestheris:{t}"));
            format!("Proxy-Authorization: Basic {b}\r\n")
        })
        .unwrap_or_default();
    s.write_all(
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth_line}\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).await.unwrap() == 1 {
        head.push(byte[0]);
    }
    (String::from_utf8_lossy(&head).to_string(), s)
}

#[tokio::test]
async fn proxy_de_sortie_liste_blanche_et_anti_ssrf() {
    let dir = tempfile::tempdir().unwrap();
    let echo_port = echo_server("127.0.0.1:0").await;
    let extra = format!(
        "network:
  allow_insecure_loopback: true
  egress: allowlist
  allow_hosts: [\"127.0.0.1\", \"10.1.2.3\"]
  allow_ports: [443, {echo_port}]
sandbox:
  enabled: true
"
    );
    let (policy, vault, audit) = write_policy(dir.path(), 9, &extra);
    let (gw, _) = run::prepare(&policy, &vault, &audit, PASSWORD).unwrap();
    let token = gw.token_for_agent().to_string();
    let running = proxy::start(gw.clone(), 0).await.unwrap();
    let target = format!("127.0.0.1:{echo_port}");

    // Tunnel autorisé : les octets font l'aller-retour.
    let (head, mut s) = raw_connect(running.addr, &target, Some(&token)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    s.write_all(b"bonjour").await.unwrap();
    let mut buf = [0u8; 7];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"bonjour");

    // Sans jeton : 407.
    let (head, _) = raw_connect(running.addr, &target, None).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    // Hôte hors liste : 403.
    let (head, _) = raw_connect(running.addr, "example.com:443", Some(&token)).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    // Hôte listé mais adresse interne (réseau privé) : 403 sans tentative de connexion.
    let (head, _) = raw_connect(running.addr, "10.1.2.3:443", Some(&token)).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    // Port non autorisé : 403.
    let (head, _) = raw_connect(running.addr, "127.0.0.1:22", Some(&token)).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");

    running.stop().await;
    assert!(aestheris::audit::verify(&audit).unwrap().ok);
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn bac_a_sable_macos_protege_les_secrets_et_coupe_le_reseau() {
    // Variable secrète présente dans le terminal : elle ne doit pas atteindre l'agent.
    // SAFETY : ce fichier de test ne lance qu'un seul test à la fois pour cette variable.
    unsafe {
        std::env::set_var(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
    };

    let config = tempfile::tempdir().unwrap(); // coffre, politique, journal
    let secrets = tempfile::tempdir().unwrap(); // dossier sensible protégé
    let projet = tempfile::tempdir().unwrap(); // projet de l'agent (contient un .env)
    let out = tempfile::tempdir().unwrap(); // résultats écrits par l'agent

    std::fs::write(secrets.path().join("credentials.txt"), "mot-de-passe-prod").unwrap();
    std::fs::write(projet.path().join(".env"), "DB_PASSWORD=hunter2").unwrap();
    std::fs::create_dir_all(projet.path().join(".git/hooks")).unwrap();
    // Service local hors passerelle (socket Unix, comme Docker ou l'agent SSH).
    let ext_sock = config.path().join("service.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&ext_sock).unwrap();
    let home_probe = dirs::home_dir()
        .unwrap()
        .join(format!(".aestheris-sonde-{}", std::process::id()));

    let route_port = http_ok("127.0.0.1:0").await;

    let extra = format!(
        "network:
  allow_insecure_loopback: true
  egress: none
sandbox:
  enabled: true
  protect_paths: [\"{}\"]
",
        secrets.path().display()
    );
    let (policy, vault, audit) = write_policy(config.path(), route_port, &extra);

    let o = out.path().display();
    // Réseau direct : 192.0.2.1 (adresse réservée, jamais routée). Dans le bac à sable, le refus est
    // immédiat (curl code 7) ; sans bac à sable, la connexion attendrait jusqu'à expiration (code 28).
    // Remarque : pour Seatbelt, « localhost » couvre toutes les adresses de la machine elle-même.
    let net_cmd = format!(
        "curl -s --noproxy '*' --max-time 3 http://192.0.2.1/ >/dev/null 2>&1; echo $? > {o}/net_code;"
    );
    let p = projet.path().display();
    let evasions = format!(
        "osascript -e 'tell application \"Finder\" to get (count of windows)' >/dev/null 2>&1; echo $? > {o}/applescript_code;
         open -g -j -a Finder >/dev/null 2>&1; echo $? > {o}/open_code;
         python3 -c 'import socket;socket.socket(socket.AF_UNIX).connect(\"{sock}\")' 2>/dev/null; echo $? > {o}/socket_code;
         python3 -c 'import socket,os;p=os.environ[\"TMPDIR\"]+\"/s.sock\";a=socket.socket(socket.AF_UNIX);a.bind(p);a.listen();b=socket.socket(socket.AF_UNIX);b.connect(p)' 2>/dev/null; echo $? > {o}/own_socket_code;
         curl -s --noproxy '*' --max-time 3 http://127.0.0.1:{route_port}/ >/dev/null 2>&1; echo $? > {o}/local_service_code;
         (echo x > '{home_probe}') 2>/dev/null; echo $? > {o}/home_write_code;
         (echo x > {p}/.git/hooks/pre-commit) 2>/dev/null; echo $? > {o}/hook_code;
         (echo x > {p}/.git/hooks/pre-commit.sample) 2>/dev/null; echo $? > {o}/sample_code;
         mv {p}/.git {p}/.git2 2>/dev/null; echo $? > {o}/rename_code;
         (echo x > {p}/.zshrc) 2>/dev/null; echo $? > {o}/zshrc_code;
         (mkdir -p {p}/.vscode && echo x > {p}/.vscode/tasks.json) 2>/dev/null; echo $? > {o}/vscode_code;
         (mkdir -p {p}/.cursor2 && echo '{{}}' > {p}/.cursor2/mcp.json) 2>/dev/null; echo $? > {o}/mcp_code;
         (echo ok > \"$TMPDIR/f\" && mktemp >/dev/null && echo \"$TMPDIR\") > {o}/tmp_out 2>/dev/null;",
        sock = ext_sock.display(),
        home_probe = home_probe.display(),
    );
    let script = format!(
        "{evasions}
         cat '{secret}' > /dev/null 2>&1; echo $? > {o}/secret_code;
         cat '{dotenv}' > /dev/null 2>&1; echo $? > {o}/env_code;
         cat '{vault}' > /dev/null 2>&1; echo $? > {o}/vault_code;
         (echo 'routes: {{}}' >> '{policy}') 2>/dev/null; echo $? > {o}/policy_code;
         echo ok > {o}/normal;
         {net_cmd}
         curl -s -X POST -H \"Authorization: Bearer $STRIPE_API_KEY\" \"$STRIPE_API_BASE/v1/charges\" > {o}/route_out;
         env > {o}/env_dump",
        secret = secrets.path().join("credentials.txt").display(),
        dotenv = projet.path().join(".env").display(),
        vault = vault.display(),
        policy = policy.display(),
    );
    let command = vec!["sh".to_string(), "-c".to_string(), script];
    let code = run::run(run::RunOptions {
        policy: &policy,
        vault: &vault,
        audit: &audit,
        password: PASSWORD,
        command: &command,
        run_dir: &std::env::temp_dir().join(format!("aestheris-test-run-{}", std::process::id())),
        sandbox_init: Some(std::path::Path::new(env!("CARGO_BIN_EXE_aestheris"))),
    })
    .await
    .unwrap();
    assert_eq!(code, 0);

    let read = |f: &str| {
        std::fs::read_to_string(out.path().join(f))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    assert_ne!(read("secret_code"), "0", "dossier protégé lisible");
    assert_ne!(read("env_code"), "0", "fichier .env lisible");
    assert_ne!(read("vault_code"), "0", "coffre lisible");
    assert_ne!(read("policy_code"), "0", "politique modifiable par l'agent");
    assert_eq!(
        read("normal"),
        "ok",
        "les écritures ordinaires doivent rester possibles"
    );
    assert_eq!(
        read("net_code"),
        "7",
        "la connexion directe au réseau doit être refusée immédiatement"
    );
    assert!(
        read("route_out").contains("\"ok\":true"),
        "la route de la passerelle doit fonctionner"
    );
    let env = read("env_dump");
    assert!(
        !env.contains("wJalrXUtnFEMI"),
        "variable secrète transmise à l'agent"
    );
    assert!(!env.contains("AESTHERIS_PASSWORD"));
    assert!(env.contains("STRIPE_API_KEY=aes_ph_"));
    assert!(
        env.contains("npm_config_cache=") && env.contains("aestheris-agent"),
        "caches des agents"
    );

    // v0.3 : évasions fermées par le profil « tout interdit »
    let home_written = home_probe.exists();
    let _ = std::fs::remove_file(&home_probe);
    assert_ne!(
        read("applescript_code"),
        "0",
        "AppleScript pilote une application hors du bac à sable"
    );
    assert_ne!(
        read("open_code"),
        "0",
        "`open` lance une application hors du bac à sable"
    );
    assert_ne!(
        read("socket_code"),
        "0",
        "socket Unix extérieur joignable (Docker, agent SSH…)"
    );
    assert_eq!(
        read("own_socket_code"),
        "0",
        "les sockets du dossier de session doivent fonctionner"
    );
    assert_eq!(
        read("local_service_code"),
        "7",
        "service local hors passerelle joignable"
    );
    assert!(
        !home_written && read("home_write_code") != "0",
        "écriture hors des dossiers autorisés"
    );
    assert_ne!(read("hook_code"), "0", "hook Git modifiable");
    assert_eq!(
        read("sample_code"),
        "0",
        "les modèles .sample de git init doivent rester possibles"
    );
    assert_ne!(
        read("rename_code"),
        "0",
        ".git renommable (contournement des interdictions)"
    );
    assert_ne!(read("zshrc_code"), "0", ".zshrc modifiable");
    assert_ne!(read("vscode_code"), "0", ".vscode modifiable");
    assert_ne!(
        read("mcp_code"),
        "0",
        "configuration MCP modifiable (commande lancée hors bac à sable)"
    );
    assert!(
        read("tmp_out").contains("aestheris-"),
        "TMPDIR de session attendu : {}",
        read("tmp_out")
    );
    assert!(
        std::fs::read_to_string(&policy)
            .unwrap()
            .matches("routes:")
            .count()
            == 1,
        "politique altérée"
    );
}

/// Linux : bubblewrap + seccomp. Les dossiers du test sont créés dans le dossier personnel, car le
/// `/tmp` de l'hôte est de toute façon invisible dans le bac à sable.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn bac_a_sable_linux_protege_les_secrets_et_coupe_le_reseau() {
    // SAFETY : ce fichier de test ne lance qu'un seul test à la fois pour cette variable.
    unsafe {
        std::env::set_var(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
    };
    let home = dirs::home_dir().unwrap();
    let config = tempfile::tempdir_in(&home).unwrap(); // coffre, journal (≈ ~/.aestheris)
    let secrets = tempfile::tempdir_in(&home).unwrap(); // dossier sensible protégé
    let projet = tempfile::tempdir_in(&home).unwrap(); // projet de l'agent (modifiable)
    let out = tempfile::tempdir_in(&home).unwrap(); // résultats écrits par l'agent

    std::fs::write(secrets.path().join("credentials.txt"), "mot-de-passe-prod").unwrap();
    std::fs::write(projet.path().join(".env"), "DB_PASSWORD=hunter2").unwrap();
    std::fs::write(projet.path().join(".envrc"), "export OK=1").unwrap();
    std::fs::create_dir_all(projet.path().join(".git/hooks")).unwrap();
    let host_tmp = std::env::temp_dir().join(format!("aestheris-hote-{}", std::process::id()));
    std::fs::write(&host_tmp, "fichier temporaire de l'hôte").unwrap();
    let ext_sock = config.path().join("service.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&ext_sock).unwrap();

    let route_port = http_ok("127.0.0.1:0").await;
    let (_, vault, audit) = write_policy(config.path(), route_port, "");
    // Politique dans le projet (cas réel) : l'agent pourrait l'écrire, elle doit rester figée.
    let policy = projet.path().join("aestheris.yaml");
    let base = std::fs::read_to_string(config.path().join("aestheris.yaml")).unwrap();
    std::fs::write(
        &policy,
        format!(
            "{base}network:\n  allow_insecure_loopback: true\n  egress: none\nsandbox:\n  enabled: true\n  protect_paths: [\"{}\"]\n  allow_write: [\"{}\", \"{}\"]\n",
            secrets.path().display(),
            projet.path().display(),
            out.path().display()
        ),
    )
    .unwrap();

    let o = out.path().display();
    let p = projet.path().display();
    let script = format!(
        "cat '{secret}' > {o}/secret 2>/dev/null; echo $? > {o}/secret_code;
         cat {p}/.env > {o}/dotenv 2>/dev/null;
         cat '{vault}' > {o}/vault 2>/dev/null;
         cat '{host_tmp}' > {o}/host_tmp 2>/dev/null; echo $? > {o}/host_tmp_code;
         (echo 'routes: {{}}' >> '{policy}') 2>/dev/null; echo $? > {o}/policy_code;
         (echo x > {p}/.git/hooks/pre-commit) 2>/dev/null; echo $? > {o}/hook_code;
         (echo x >> {p}/.envrc) 2>/dev/null; echo $? > {o}/envrc_code;
         (echo x > $HOME/.aestheris-sonde) 2>/dev/null; echo $? > {o}/home_code;
         echo ok > {p}/travail.txt && echo ok > {o}/normal;
         (echo ok > \"$TMPDIR/f\" && mktemp >/dev/null && echo \"$TMPDIR\") > {o}/tmp_out 2>/dev/null;
         curl -s --noproxy '*' --max-time 3 http://192.0.2.1/ >/dev/null 2>&1; echo $? > {o}/net_code;
         curl -s --noproxy '*' --max-time 3 http://127.0.0.1:{route_port}/ >/dev/null 2>&1; echo $? > {o}/local_code;
         python3 -c 'import socket;socket.socket(socket.AF_UNIX).connect(\"{sock}\")' 2>{o}/socket_err; echo $? > {o}/socket_code;
         python3 -c 'import fcntl,termios;fcntl.ioctl(0,termios.TIOCSTI,b\"x\")' 2>{o}/tiocsti_err;
         curl -s -X POST -H \"Authorization: Bearer $STRIPE_API_KEY\" \"$STRIPE_API_BASE/v1/charges\" > {o}/route_out;
         env > {o}/env_dump",
        secret = secrets.path().join("credentials.txt").display(),
        vault = vault.display(),
        host_tmp = host_tmp.display(),
        policy = policy.display(),
        sock = ext_sock.display(),
    );
    let command = vec!["sh".to_string(), "-c".to_string(), script];
    let code = run::run(run::RunOptions {
        policy: &policy,
        vault: &vault,
        audit: &audit,
        password: PASSWORD,
        command: &command,
        run_dir: &config.path().join("run"),
        sandbox_init: Some(std::path::Path::new(env!("CARGO_BIN_EXE_aestheris"))),
    })
    .await
    .unwrap();
    let _ = std::fs::remove_file(&host_tmp);
    let home_written = home.join(".aestheris-sonde").exists();
    let _ = std::fs::remove_file(home.join(".aestheris-sonde"));
    assert_eq!(code, 0);

    let read = |f: &str| {
        std::fs::read_to_string(out.path().join(f))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    assert!(
        !read("secret").contains("mot-de-passe-prod"),
        "dossier protégé lisible"
    );
    assert!(!read("dotenv").contains("hunter2"), "fichier .env lisible");
    assert!(!read("vault").contains('{'), "coffre lisible");
    assert_ne!(
        read("host_tmp_code"),
        "0",
        "le /tmp de l'hôte doit être invisible"
    );
    assert_ne!(read("policy_code"), "0", "politique modifiable par l'agent");
    assert_ne!(read("hook_code"), "0", "hook Git modifiable");
    assert_ne!(read("envrc_code"), "0", ".envrc modifiable");
    assert!(
        !home_written && read("home_code") != "0",
        "écriture hors des dossiers autorisés"
    );
    assert_eq!(
        read("normal"),
        "ok",
        "le projet et la sortie doivent rester modifiables"
    );
    assert!(projet.path().join("travail.txt").exists());
    assert!(
        read("tmp_out").contains("aestheris-"),
        "TMPDIR de session : {}",
        read("tmp_out")
    );
    assert_eq!(read("net_code"), "7", "Internet joignable directement");
    assert_eq!(read("local_code"), "7", "service local de l'hôte joignable");
    assert_ne!(
        read("socket_code"),
        "0",
        "socket Unix joignable (Docker, agent SSH…)"
    );
    assert!(
        read("socket_err").contains("Operation not permitted"),
        "{}",
        read("socket_err")
    );
    assert!(
        read("tiocsti_err").contains("Operation not permitted"),
        "injection de frappes : {}",
        read("tiocsti_err")
    );
    assert!(
        read("route_out").contains("\"ok\":true"),
        "la route de la passerelle doit fonctionner : {}",
        read("route_out")
    );
    let env = read("env_dump");
    assert!(
        !env.contains("wJalrXUtnFEMI"),
        "variable secrète transmise à l'agent"
    );
    assert!(env.contains("STRIPE_API_KEY=aes_ph_"));
    assert!(
        std::fs::read_to_string(&policy)
            .unwrap()
            .matches("routes:")
            .count()
            == 1,
        "politique altérée"
    );
}
