//! Erreurs d'Aestheris.
//!
//! Règle : aucune erreur ne doit contenir la valeur d'un secret. Les messages
//! nomment le secret (ex. `stripe/test`) mais jamais son contenu.

use crate::tr;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    VaultMissing(PathBuf),
    VaultExists(PathBuf),
    BadPassword,
    Vault(String),
    SecretMissing(String),
    Policy(String),
    Audit(String),
    Crypto(String),
    Net(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    Scan(String),
    Yaml(serde_yaml_ng::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::VaultMissing(p) => {
                let p = p.display();
                tr!(fmt "coffre introuvable : {p} (créez-le avec `aestheris vault init`)",
                    "vault not found: {p} (create it with `aestheris vault init`)")
            }
            Self::VaultExists(p) => {
                let p = p.display();
                tr!(fmt "un coffre existe déjà : {p}", "a vault already exists: {p}")
            }
            Self::BadPassword => tr!(
                "mot de passe incorrect, ou coffre modifié en dehors d'Aestheris",
                "wrong password, or vault modified outside Aestheris"
            )
            .to_string(),
            Self::Vault(m) => tr!(fmt "coffre : {m}", "vault: {m}"),
            Self::SecretMissing(n) => tr!(fmt
                "secret introuvable dans le coffre : {n} (ajoutez-le : aestheris vault set {n})",
                "secret not found in the vault: {n} (add it: aestheris vault set {n})"),
            Self::Policy(m) => tr!(fmt "politique : {m}", "policy: {m}"),
            Self::Audit(m) => tr!(fmt "journal d'audit : {m}", "audit log: {m}"),
            Self::Crypto(m) => tr!(fmt "cryptographie : {m}", "cryptography: {m}"),
            Self::Net(m) => tr!(fmt "réseau : {m}", "network: {m}"),
            Self::Io(e) => tr!(fmt "entrée/sortie : {e}", "I/O: {e}"),
            Self::Json(e) => tr!(fmt "JSON : {e}", "JSON: {e}"),
            Self::Scan(m) => tr!(fmt "analyse : {m}", "scan: {m}"),
            Self::Yaml(e) => tr!(fmt "YAML : {e}", "YAML: {e}"),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Yaml(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<serde_yaml_ng::Error> for Error {
    fn from(e: serde_yaml_ng::Error) -> Self {
        Self::Yaml(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
