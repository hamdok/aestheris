//! Journal d'audit chaîné (append-only).
//!
//! Un événement par ligne (NDJSON) ; chaque ligne porte le hachage de la précédente et le sien :
//!
//! ```text
//! hash_n = SHA-256( "aestheris.audit.v1\n" ‖ hash_{n-1} ‖ JSON(événement_n) )
//! ```
//!
//! Modifier, supprimer ou insérer une ligne casse la chaîne : `aestheris audit verify` le détecte.
//! Le journal contient le **type** d'un secret détecté, jamais sa valeur.

use crate::error::{Error, Result};
use crate::tr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const DOMAIN: &[u8] = b"aestheris.audit.v1\n";
const GENESIS: [u8; 32] = [0u8; 32];

/// Contenu d'un événement (ce qui est haché). L'ordre des champs est fixe, donc la sérialisation
/// est reproductible à la vérification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Event {
    pub seq: u64,
    pub ts: String,
    pub session: String,
    /// `session_start`, `request`, `session_end`
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,
    /// `allowed`, `denied` (politique), `blocked` (contenu), `unauthorized`, `error`
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub detected: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    #[serde(flatten)]
    event: Event,
    prev: String,
    hash: String,
}

fn chain_hash(prev: &[u8; 32], event: &Event) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(prev);
    h.update(serde_json::to_vec(event)?);
    Ok(h.finalize().into())
}

struct State {
    file: File,
    seq: u64,
    head: [u8; 32],
}

pub struct AuditLog {
    path: PathBuf,
    state: Mutex<State>,
}

impl AuditLog {
    /// Ouvre (ou crée) le journal. Refuse de continuer une chaîne déjà cassée.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let (seq, head) = if path.exists() {
            let report = verify(path)?;
            if !report.ok {
                return Err(Error::Audit(tr!(fmt
                    "chaîne cassée à la ligne {} : {} (archivez ce fichier avant de continuer)", "chain broken at line {}: {} (archive this file before continuing)",
                    report.broken_at.unwrap_or(0),
                    report.problem.unwrap_or_default()
                )));
            }
            (report.count, report.head)
        } else {
            (0, GENESIS)
        };
        let file = open_append(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(State { file, seq, head }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Ajoute un événement ; `seq`, `ts`, `prev` et `hash` sont remplis ici.
    pub fn append(&self, mut event: Event) -> Result<Event> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| Error::Audit(tr!("verrou empoisonné", "poisoned lock").into()))?;
        event.seq = st.seq + 1;
        if event.ts.is_empty() {
            event.ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        }
        let hash = chain_hash(&st.head, &event)?;
        let record = Record {
            event: event.clone(),
            prev: hex::encode(st.head),
            hash: hex::encode(hash),
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        st.file.write_all(&line)?;
        st.file.flush()?;
        st.seq = event.seq;
        st.head = hash;
        Ok(event)
    }

    /// Hachage de tête actuel (scelle tout le journal).
    pub fn head(&self) -> String {
        self.state
            .lock()
            .map(|s| hex::encode(s.head))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: bool,
    pub count: u64,
    pub head: [u8; 32],
    pub broken_at: Option<u64>,
    pub problem: Option<String>,
}

/// Recalcule toute la chaîne.
pub fn verify(path: &Path) -> Result<VerifyReport> {
    let reader = BufReader::new(File::open(path)?);
    let mut prev = GENESIS;
    let mut count = 0u64;
    for (i, line) in reader.lines().enumerate() {
        let line_no = i as u64 + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let fail = |problem: String| VerifyReport {
            ok: false,
            count,
            head: prev,
            broken_at: Some(line_no),
            problem: Some(problem),
        };
        let record: Record = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => return Ok(fail(format!("ligne illisible : {e}"))),
        };
        if record.event.seq != count + 1 {
            return Ok(fail(tr!(fmt
                "numéro {} attendu, {} trouvé (ligne supprimée ou insérée ?)", "number {} expected, {} found (line deleted or inserted?)",
                count + 1,
                record.event.seq
            )));
        }
        if record.prev != hex::encode(prev) {
            return Ok(fail(
                tr!(
                    "le lien vers la ligne précédente ne correspond pas",
                    "the link to the previous line does not match"
                )
                .into(),
            ));
        }
        let expected = chain_hash(&prev, &record.event)?;
        if record.hash != hex::encode(expected) {
            return Ok(fail(
                tr!(
                    "contenu modifié après écriture",
                    "content modified after writing"
                )
                .into(),
            ));
        }
        prev = expected;
        count += 1;
    }
    Ok(VerifyReport {
        ok: true,
        count,
        head: prev,
        broken_at: None,
        problem: None,
    })
}

/// Lit les `last` derniers événements (pour `aestheris audit show`).
pub fn tail(path: &Path, last: usize) -> Result<Vec<Event>> {
    let reader = BufReader::new(File::open(path)?);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Ok(r) = serde_json::from_str::<Record>(&line) {
            events.push(r.event);
        }
    }
    let start = events.len().saturating_sub(last);
    Ok(events.split_off(start))
}

#[cfg(unix)]
fn open_append(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_append(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().create(true).append(true).open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str) -> Event {
        Event {
            session: "s1".into(),
            kind: kind.into(),
            ..Default::default()
        }
    }

    fn remplir(path: &Path) {
        let log = AuditLog::open(path).unwrap();
        log.append(ev("session_start")).unwrap();
        log.append(Event {
            decision: Some("allowed".into()),
            ..ev("request")
        })
        .unwrap();
        log.append(ev("session_end")).unwrap();
    }

    #[test]
    fn chaine_intacte_et_reprise() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");
        remplir(&path);
        let r = verify(&path).unwrap();
        assert!(r.ok && r.count == 3);
        // réouverture : la chaîne continue au numéro 4
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(log.append(ev("session_start")).unwrap().seq, 4);
        assert!(verify(&path).unwrap().ok);
    }

    #[test]
    fn modification_detectee() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");
        remplir(&path);
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("\"allowed\"", "\"denied\"");
        fs::write(&path, text).unwrap();
        let r = verify(&path).unwrap();
        assert!(!r.ok);
        assert_eq!(r.broken_at, Some(2));
    }

    #[test]
    fn suppression_detectee() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");
        remplir(&path);
        let lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(!verify(&path).unwrap().ok);
        assert!(
            AuditLog::open(&path).is_err(),
            "on ne prolonge pas une chaîne cassée"
        );
    }
}
