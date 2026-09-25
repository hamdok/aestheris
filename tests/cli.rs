//! Ligne de commande : `aestheris init` prépare un projet sans interaction (CI, scripts).

use std::process::Command;

fn aestheris(home: &std::path::Path, cwd: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aestheris"));
    c.current_dir(cwd)
        .env("AESTHERIS_HOME", home)
        .env("AESTHERIS_PASSWORD", "mot de passe de test solide")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("STRIPE_API_KEY");
    c
}

#[test]
fn init_prepare_coffre_et_politique() {
    let dir = tempfile::tempdir().unwrap();
    let (home, projet) = (dir.path().join(".aestheris"), dir.path().join("projet"));
    std::fs::create_dir_all(&projet).unwrap();

    let out = aestheris(&home, &projet)
        .args(["init", "--agent", "claude-code", "--service", "stripe"])
        .env(
            "ANTHROPIC_API_KEY",
            "sk-ant-api03-FAUSSEcleDeTest0123456789abcdefghijKLMN",
        )
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("clé rangée dans le coffre (anthropic/api)"),
        "{text}"
    );
    assert!(text.contains("aestheris vault set stripe/api"), "{text}");

    // La clé est dans le coffre (chiffrée), pas dans la politique.
    let policy = std::fs::read_to_string(projet.join("aestheris.yaml")).unwrap();
    assert!(!policy.contains("FAUSSEcle"));
    assert!(policy.contains("ANTHROPIC_AUTH_TOKEN"));
    let vault = std::fs::read_to_string(home.join("vault.json")).unwrap();
    assert!(!vault.contains("FAUSSEcle"));
    let list = aestheris(&home, &projet)
        .args(["vault", "list"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&list.stdout).contains("anthropic/api"));

    // Politique relue avec succès ; pas d'écrasement sans --force.
    let check = aestheris(&home, &projet)
        .args(["policy", "check"])
        .output()
        .unwrap();
    assert!(check.status.success());
    let again = aestheris(&home, &projet)
        .args(["init", "--agent", "generic", "--service", "openai"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("--force"));
}
