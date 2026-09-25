//! Coffre chiffré local.
//!
//! Chiffrement en enveloppe à deux niveaux :
//!
//! ```text
//! mot de passe ──Argon2id──▶ KEK (clé de chiffrement de clé, jamais stockée)
//!                               │ XChaCha20-Poly1305
//!                               ▼
//!                             DEK (clé de données, stockée chiffrée)
//!                               │ XChaCha20-Poly1305, données associées = nom du secret
//!                               ▼
//!                             secrets (stockés chiffrés)
//! ```
//!
//! - Changer le mot de passe ne rechiffre que la DEK. Plus tard, la KEK pourra venir du trousseau
//!   du système, d'un KMS ou d'un HSM sans toucher aux secrets.
//! - XChaCha20-Poly1305 : chiffrement authentifié (toute modification est détectée) avec un nonce
//!   de 24 octets tiré au hasard à chaque écriture, donc sans risque de réutilisation.
//! - Le nom du secret est lié à son contenu chiffré (données associées) : échanger deux blocs dans
//!   le fichier fait échouer le déchiffrement.
//! - Format d'un bloc : `nonce ‖ texte chiffré ‖ tag`, encodé en base64.
//! - Fichier en 0600, écrit de façon atomique (fichier temporaire puis renommage).

use crate::error::{Error, Result};
use crate::secret::{Secret, is_header_safe};
use crate::tr;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const FORMAT: &str = "aestheris-vault/1";
const AAD_DEK: &[u8] = b"aestheris/dek/v1";
const AAD_SECRET_PREFIX: &[u8] = b"aestheris/secret/v1\n";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const MAX_SECRET_LEN: usize = 64 * 1024;

/// Paramètres Argon2id enregistrés dans le coffre (pour pouvoir les renforcer plus tard).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 Mio, 3 passes, 1 voie : second profil recommandé par la RFC 9106, adapté à un poste.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Paramètres volontairement faibles, réservés aux tests automatisés (rapides).
    pub fn insecure_for_tests() -> Self {
        Self {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct KdfRecord {
    algorithm: String,
    #[serde(flatten)]
    params: KdfParams,
    salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SecretRecord {
    blob: String,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    kdf: KdfRecord,
    wrapped_dek: String,
    secrets: BTreeMap<String, SecretRecord>,
}

/// Coffre déverrouillé : la DEK est en mémoire (effacée à la libération), les secrets restent
/// chiffrés et ne sont déchiffrés qu'à la demande.
pub struct Vault {
    path: PathBuf,
    file: VaultFile,
    dek: Zeroizing<[u8; KEY_LEN]>,
}

impl Vault {
    /// Crée un nouveau coffre protégé par `password`. Refuse d'écraser un coffre existant.
    pub fn create(path: &Path, password: &str, params: KdfParams) -> Result<Self> {
        if path.exists() {
            return Err(Error::VaultExists(path.to_path_buf()));
        }
        if password.chars().count() < 12 {
            return Err(Error::Vault(
                tr!(
                    "le mot de passe doit contenir au moins 12 caractères",
                    "the password must be at least 12 characters long"
                )
                .into(),
            ));
        }
        let salt = random::<SALT_LEN>()?;
        let kek = derive_kek(password, salt.as_ref(), params)?;
        let dek = Zeroizing::new(*random::<KEY_LEN>()?);
        let wrapped = seal(&kek, dek.as_ref(), AAD_DEK)?;

        let vault = Self {
            path: path.to_path_buf(),
            file: VaultFile {
                format: FORMAT.into(),
                kdf: KdfRecord {
                    algorithm: "argon2id".into(),
                    params,
                    salt: B64.encode(salt.as_ref()),
                },
                wrapped_dek: B64.encode(wrapped),
                secrets: BTreeMap::new(),
            },
            dek,
        };
        vault.save()?;
        Ok(vault)
    }

    /// Ouvre et déverrouille un coffre existant.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        if !path.exists() {
            return Err(Error::VaultMissing(path.to_path_buf()));
        }
        let file: VaultFile = serde_json::from_slice(&fs::read(path)?)?;
        if file.format != FORMAT || file.kdf.algorithm != "argon2id" {
            return Err(Error::Vault(format!(
                "format non reconnu : {}",
                file.format
            )));
        }
        let salt = B64
            .decode(&file.kdf.salt)
            .map_err(|_| Error::Vault("sel illisible".into()))?;
        let kek = derive_kek(password, &salt, file.kdf.params)?;
        let wrapped = B64.decode(&file.wrapped_dek).map_err(|_| {
            Error::Vault(tr!("clé de données illisible", "unreadable data key").into())
        })?;
        // Un mauvais mot de passe donne une mauvaise KEK : l'authentification de la DEK échoue.
        let dek_bytes = open_sealed(&kek, &wrapped, AAD_DEK).map_err(|_| Error::BadPassword)?;
        if dek_bytes.len() != KEY_LEN {
            return Err(Error::BadPassword);
        }
        let mut dek = Zeroizing::new([0u8; KEY_LEN]);
        dek.copy_from_slice(&dek_bytes);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            dek,
        })
    }

    /// Ajoute ou remplace un secret.
    pub fn set(&mut self, name: &str, value: &str) -> Result<()> {
        validate_name(name)?;
        if value.is_empty() || value.len() > MAX_SECRET_LEN {
            return Err(Error::Vault(
                "secret vide ou trop long (64 Kio maximum)".into(),
            ));
        }
        if !is_header_safe(value) {
            return Err(Error::Vault(
                tr!("le secret contient un retour à la ligne ou un caractère nul (interdit pour l'injection HTTP)", "the secret contains a line break or a NUL character (not allowed for HTTP injection)").into(),
            ));
        }
        let blob = seal(&self.dek, value.as_bytes(), &secret_aad(name))?;
        let now = chrono::Utc::now().to_rfc3339();
        let created_at = self
            .file
            .secrets
            .get(name)
            .map(|r| r.created_at.clone())
            .unwrap_or_else(|| now.clone());
        self.file.secrets.insert(
            name.to_string(),
            SecretRecord {
                blob: B64.encode(blob),
                created_at,
                updated_at: now,
            },
        );
        self.save()
    }

    /// Déchiffre un secret en mémoire.
    pub fn get(&self, name: &str) -> Result<Secret> {
        let record = self
            .file
            .secrets
            .get(name)
            .ok_or_else(|| Error::SecretMissing(name.to_string()))?;
        let blob = B64.decode(&record.blob).map_err(|_| {
            Error::Vault(tr!(fmt "bloc illisible : {name}", "unreadable block: {name}"))
        })?;
        let plain = open_sealed(&self.dek, &blob, &secret_aad(name)).map_err(|_| {
            Error::Vault(tr!(fmt
                "le secret {name} a été modifié ou déplacé dans le fichier", "the secret {name} was modified or moved in the file"
            ))
        })?;
        let text = String::from_utf8(plain.to_vec())
            .map_err(|_| Error::Vault(format!("secret non UTF-8 : {name}")))?;
        Ok(Secret::new(text))
    }

    pub fn remove(&mut self, name: &str) -> Result<bool> {
        let removed = self.file.secrets.remove(name).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Noms des secrets (jamais leurs valeurs).
    pub fn names(&self) -> Vec<String> {
        self.file.secrets.keys().cloned().collect()
    }

    /// Change le mot de passe : seule la DEK est rechiffrée, avec un nouveau sel.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.chars().count() < 12 {
            return Err(Error::Vault(
                tr!(
                    "le mot de passe doit contenir au moins 12 caractères",
                    "the password must be at least 12 characters long"
                )
                .into(),
            ));
        }
        let salt = random::<SALT_LEN>()?;
        let kek = derive_kek(new_password, salt.as_ref(), self.file.kdf.params)?;
        self.file.wrapped_dek = B64.encode(seal(&kek, self.dek.as_ref(), AAD_DEK)?);
        self.file.kdf.salt = B64.encode(salt.as_ref());
        self.save()
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = open_private(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(&self.file)?)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    getrandom::fill(out.as_mut()).map_err(|e| {
        Error::Crypto(tr!(fmt "aléa indisponible : {e}", "randomness unavailable: {e}"))
    })?;
    Ok(out)
}

fn derive_kek(password: &str, salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(KEY_LEN)).map_err(|e| {
        Error::Crypto(
            tr!(fmt "paramètres Argon2 invalides : {e}", "invalid Argon2 parameters: {e}"),
        )
    })?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| Error::Crypto(format!("Argon2 : {e}")))?;
    Ok(out)
}

/// Chiffre : renvoie `nonce ‖ texte chiffré ‖ tag`.
fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce_bytes = random::<NONCE_LEN>()?;
    let nonce = XNonce::from(*nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto(tr!("chiffrement impossible", "encryption failed").into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce_bytes.as_ref());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Déchiffre et vérifie un bloc produit par [`seal`].
fn open_sealed(key: &[u8; KEY_LEN], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(Error::Crypto("bloc trop court".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(&XNonce::from(n), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto(tr!("authentification échouée", "authentication failed").into()))
}

fn secret_aad(name: &str) -> Vec<u8> {
    let mut aad = AAD_SECRET_PREFIX.to_vec();
    aad.extend_from_slice(name.as_bytes());
    aad
}

/// Noms de secrets : minuscules, chiffres, `. _ / -`, 128 caractères maximum (ex. `stripe/test`).
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-')
        })
        && !name.contains("..");
    if ok {
        Ok(())
    } else {
        Err(Error::Vault(tr!(fmt
            "nom de secret invalide : « {name} » (minuscules, chiffres et . _ / - uniquement)", "invalid secret name: “{name}” (lowercase letters, digits and . _ / - only)"
        )))
    }
}

#[cfg(unix)]
fn open_private(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_vault(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("vault.json")
    }

    #[test]
    fn aller_retour_et_mauvais_mot_de_passe() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_vault(&dir);
        let mut v = Vault::create(
            &path,
            "correct horse battery",
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        v.set("stripe/test", "sk_test_123456").unwrap();

        let v2 = Vault::open(&path, "correct horse battery").unwrap();
        assert_eq!(v2.get("stripe/test").unwrap().expose(), "sk_test_123456");
        assert!(matches!(
            Vault::open(&path, "mauvais mot de passe"),
            Err(Error::BadPassword)
        ));
    }

    #[test]
    fn le_fichier_ne_contient_aucune_valeur_en_clair() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_vault(&dir);
        let mut v = Vault::create(
            &path,
            "correct horse battery",
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        v.set("github/token", "ghp_valeur_ultra_secrete").unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("ghp_valeur_ultra_secrete"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn echanger_deux_blocs_est_detecte() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_vault(&dir);
        let mut v = Vault::create(
            &path,
            "correct horse battery",
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        v.set("a/key", "valeur-a").unwrap();
        v.set("b/key", "valeur-b").unwrap();
        // on échange les blocs chiffrés de a et b directement dans le fichier
        let mut file: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let a = file["secrets"]["a/key"]["blob"].clone();
        file["secrets"]["a/key"]["blob"] = file["secrets"]["b/key"]["blob"].clone();
        file["secrets"]["b/key"]["blob"] = a;
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let v2 = Vault::open(&path, "correct horse battery").unwrap();
        assert!(v2.get("a/key").is_err());
    }

    #[test]
    fn changement_de_mot_de_passe() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_vault(&dir);
        let mut v = Vault::create(
            &path,
            "ancien mot de passe",
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        v.set("x/y", "valeur").unwrap();
        v.change_password("nouveau mot de passe").unwrap();
        assert!(Vault::open(&path, "ancien mot de passe").is_err());
        assert_eq!(
            Vault::open(&path, "nouveau mot de passe")
                .unwrap()
                .get("x/y")
                .unwrap()
                .expose(),
            "valeur"
        );
    }

    #[test]
    fn refuse_les_valeurs_dangereuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(
            &tmp_vault(&dir),
            "correct horse battery",
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        assert!(v.set("x/y", "abc\r\nX-Evil: 1").is_err());
        assert!(v.set("../evasion", "abc").is_err());
        assert!(v.set("Majuscule", "abc").is_err());
    }
}
