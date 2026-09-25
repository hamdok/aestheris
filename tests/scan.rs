//! `aestheris scan` sur un projet « vibe codé » réaliste : ce qui est publié, publiable, lisible
//! par les agents ; sans jamais afficher une valeur.

use base64::Engine as _;
use std::path::Path;
use std::process::Command;

const OPENAI: &str = concat!("sk-", "proj-Q7vR2mXk9LpT4wZs8NbJ3hYc6FdG1eUa");
const STRIPE: &str = concat!("sk_", "live_51HqLyjWDarjtT1zdp7dcXyZ");
const AWS: &str = concat!("AKIA", "Z7Q3LMNOP4RSTUVW");
const GITHUB: &str = concat!("ghp_", "R8kX2vQ9mLt4Wz7NbJ3hYc6FdG1eUaPs5oKi");
const SLACK: &str = concat!(
    "xox",
    "b-740283915562-2918374650192-Qm7Rt2Vx9LkP4sWz8NbJ3hYc"
);
const DB_PASSWORD: &str = "Tr0ub4dor-maison-42";
const GOOGLE: &str = concat!("AIza", "SyB7kQ2mX9vL4tW8zN3bJ6hY1cF5dG0eUaR");

fn jwt(role: &str) -> String {
    let b = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
    format!(
        "{}.{}.Xq3vTgL0pWc8bHn2Rk5sYd7AeJf9UoMiZt4NxQ1yGhE",
        b(r#"{"alg":"HS256","typ":"JWT"}"#),
        b(&format!(
            r#"{{"iss":"supabase","ref":"abcdefgh","role":"{role}","iat":1700000000}}"#
        ))
    )
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .output()
        .expect("git installé")
        .status
        .success();
    assert!(ok, "git {args:?}");
}

fn scan(home: &Path, project: &Path, extra: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_aestheris"))
        .current_dir(project)
        .env("HOME", home)
        .arg("scan")
        .args(extra)
        .output()
        .unwrap();
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// (catégorie, fichier, nom) de chaque constat.
fn findings(json: &str) -> Vec<(String, String, String)> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["category"].as_str().unwrap().to_string(),
                f["file"].as_str().unwrap().to_string(),
                f["name"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn has(found: &[(String, String, String)], category: &str, file: &str, name: &str) -> bool {
    found
        .iter()
        .any(|(c, f, n)| c == category && f == file && n.contains(name))
}

#[test]
fn projet_vibe_code_publie_publiable_lisible() {
    let dir = tempfile::tempdir().unwrap();
    let (home, p) = (dir.path().join("home"), dir.path().join("app"));
    write(&p.join(".gitignore"), ".env\nnode_modules\n");
    write(
        &p.join(".env"),
        &format!(
            "OPENAI_API_KEY={OPENAI}\n\
             NEXT_PUBLIC_SUPABASE_ANON_KEY={}\n\
             NEXT_PUBLIC_SUPABASE_SERVICE_KEY={}\n\
             DB_PASSWORD=\"{DB_PASSWORD}\"\n\
             NEXTAUTH_URL=http://localhost:3000\n\
             NEXT_PUBLIC_FIREBASE_API_KEY={GOOGLE}\n",
            jwt("anon"),
            jwt("service_role")
        ),
    );
    write(
        &p.join(".env.local"),
        &format!("STRIPE_SECRET_KEY={STRIPE}\n"),
    );
    write(&p.join(".env.production"), "FEATURE_FLAG=on\n");
    write(&p.join(".env.example"), "OPENAI_API_KEY=your-key-here\n");
    write(
        &p.join("src/config.js"),
        &format!("export const awsKey = \"{AWS}\";\n"),
    );
    write(
        &p.join("src/fixtures.js"),
        &format!("const k = \"{GITHUB}\"; // aestheris:allow\n"),
    );
    write(
        &p.join("node_modules/pkg/index.js"),
        &format!("const k = \"{AWS}\";"),
    );
    let mut png = b"\x89PNG\x00\x00".to_vec();
    png.extend_from_slice(AWS.as_bytes());
    std::fs::write(p.join("logo.png"), png).unwrap();
    write(
        &p.join(".mcp.json"),
        &format!(
            r#"{{"mcpServers":{{"github":{{"command":"npx","env":{{"GITHUB_PERSONAL_ACCESS_TOKEN":"{GITHUB}"}}}}}}}}"#
        ),
    );
    write(
        &p.join(".claude/settings.local.json"),
        r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
    );
    git(&p, &["init", "-q"]);
    git(
        &p,
        &[
            "add",
            ".gitignore",
            "src",
            ".env.production",
            ".env.example",
        ],
    );

    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    write(&home.join(".aws/credentials"), "[default]\n");
    write(
        &home.join(".cursor/mcp.json"),
        &format!(
            r#"{{"mcpServers":{{"slack":{{"command":"slack-mcp","env":{{"SLACK_BOT_TOKEN":"{SLACK}"}}}}}}}}"#
        ),
    );
    write(
        &home.join(".codex/config.toml"),
        "sandbox_mode = \"danger-full-access\"\n",
    );

    let (code, json) = scan(&home, &p, &["--json"]);
    assert_eq!(code, 1, "un constat critique donne le code 1");
    let found = findings(&json);
    for (category, file, name) in [
        (
            "public_variable",
            ".env",
            "NEXT_PUBLIC_SUPABASE_SERVICE_KEY",
        ),
        ("git_tracked", "src/config.js", "awsKey"),
        ("env_not_ignored", ".env.local", "STRIPE_SECRET_KEY"),
        ("agent_readable", ".env", "OPENAI_API_KEY"),
        ("agent_readable", ".env", "DB_PASSWORD"),
        (
            "mcp_plaintext",
            ".mcp.json",
            "serveur « github » · env.GITHUB_PERSONAL_ACCESS_TOKEN",
        ),
        (
            "mcp_plaintext",
            "~/.cursor/mcp.json",
            "serveur « slack » · env.SLACK_BOT_TOKEN",
        ),
        ("env_tracked", ".env.production", ""),
        (
            "agent_settings",
            ".claude/settings.local.json",
            "bypassPermissions",
        ),
        (
            "agent_settings",
            "~/.codex/config.toml",
            "danger-full-access",
        ),
        ("public_by_design", ".env", "NEXT_PUBLIC_FIREBASE_API_KEY"),
    ] {
        assert!(
            has(&found, category, file, name),
            "{category} {file} {name} absent : {found:#?}"
        );
    }
    assert_eq!(found.len(), 11, "constats en trop : {found:#?}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["summary"]["critical"], 3);
    assert_eq!(v["summary"]["high"], 5);
    assert_eq!(v["summary"]["medium"], 3);
    let exposure = v["home_exposure"].to_string();
    assert!(exposure.contains("~/.ssh") && exposure.contains("~/.aws"));
    assert!(json.contains("SUPABASE_SERVICE_ROLE"));

    let (_, text) = scan(&home, &p, &[]);
    for expected in [
        "CRITIQUE — publié ou publiable",
        "src/config.js:1  awsKey · AWS_ACCESS_KEY",
        ".env:3  NEXT_PUBLIC_SUPABASE_SERVICE_KEY · SUPABASE_SERVICE_ROLE",
        ".env:4  DB_PASSWORD · secret probable (d'après le nom)",
        "Bilan : 3 critique(s) · 5 élevé(s) · 3 moyen(s)",
        "Protéger vos agents : aestheris init",
    ] {
        assert!(text.contains(expected), "« {expected} » absent :\n{text}");
    }

    // Jamais une valeur, ni en texte ni en JSON.
    let (service, anon) = (jwt("service_role"), jwt("anon"));
    for secret in [
        OPENAI,
        STRIPE,
        AWS,
        GITHUB,
        SLACK,
        DB_PASSWORD,
        GOOGLE,
        &service,
        &anon,
    ] {
        assert!(
            !text.contains(secret) && !json.contains(secret),
            "valeur affichée"
        );
    }

    // CI : projet seul, chemins exclus.
    let (_, json) = scan(&home, &p, &["--json", "--no-home", "--exclude", "src/**"]);
    let found = findings(&json);
    assert!(found.iter().all(|(_, f, _)| !f.starts_with('~')));
    assert!(!has(&found, "git_tracked", "src/config.js", ""));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v["home_exposure"].as_array().unwrap().is_empty());
}

#[test]
fn projet_propre_code_zero() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("app");
    write(&p.join("README.md"), "# Mon app\n");
    write(
        &p.join(".env.example"),
        "STRIPE_SECRET_KEY=\nDB_PASSWORD=changeme\n",
    );
    write(
        &p.join("src/api.ts"),
        "const key = process.env.STRIPE_SECRET_KEY;\n",
    );
    write(&p.join(".aestheris-ignore"), "# motifs\nvendor-copie/**\n");
    write(
        &p.join("vendor-copie/cle.js"),
        concat!("k = \"AKIA", "Z7Q3LMNOP4RSTUVW\""),
    );
    let (code, text) = scan(dir.path(), &p, &["--no-home"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("pas un dépôt git"), "{text}");
    assert!(text.contains("aucun secret exposé"), "{text}");
}

#[test]
fn interface_en_anglais() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("app");
    write(
        &p.join(".env"),
        concat!(
            "OPENAI_API_KEY=sk-",
            "proj-Q7vR2mXk9LpT4wZs8NbJ3hYc6FdG1eUa\n"
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_aestheris"))
        .args(["scan", "--no-home"])
        .arg(&p)
        .env("AESTHERIS_LANG", "en")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    for expected in [
        "Aestheris scan:",
        "HIGH — readable by your agents",
        "Secrets your agents can read",
        "Summary: 0 critical · 1 high · 0 medium",
    ] {
        assert!(text.contains(expected), "« {expected} » absent :\n{text}");
    }
}
