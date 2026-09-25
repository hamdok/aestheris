//! Validation humaine : une requête soumise à `action: ask` attend qu'un humain l'autorise.
//!
//! ```text
//! agent ──requête──▶ passerelle ──(file d'attente)──▶ canal local ◀── `aestheris approve` (humain)
//!                        │  sans réponse avant `approval.timeout_secs` → refus (fail secure)
//! ```
//!
//! Principe : aucune action critique sans validation humaine. Garanties :
//! - **l'agent ne peut pas s'approuver lui-même** : le canal est un socket Unix dans
//!   `~/.aestheris/run/` (0600), que le bac à sable rend illisible et injoignable ; en plus, toute
//!   connexion venant du processus de l'agent ou de l'un de ses descendants est refusée ;
//! - une approbation vaut **une fois** par défaut, ou pour la session si l'humain le choisit
//!   (même route, même méthode, même chemin ; ou même hôte et port pour la sortie réseau) ;
//! - chaque décision, et qui l'a prise, va dans le journal chaîné (par l'appelant).
//!
//! Protocole du canal : une ligne JSON par message, dans les deux sens.

use crate::error::{Error, Result};
use crate::tr;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};

/// Demande en attente, telle que la voit l'humain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pending {
    pub id: u64,
    pub session: String,
    /// « requête API » ou « sortie réseau ».
    pub kind: String,
    /// Ex. « stripe : POST /v1/refunds/re_1 ».
    pub summary: String,
    /// Règle concernée, extrait du contenu.
    pub detail: String,
    /// Secondes restantes avant refus automatique (au moment de l'envoi).
    pub expires_in: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Once,
    Session,
}

/// Issue d'une demande.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Approved { scope: Scope, by: String },
    Denied { by: String },
    Expired,
}

impl Outcome {
    /// Phrase pour le journal d'audit.
    pub fn describe(&self, timeout: Duration) -> String {
        match self {
            Outcome::Approved {
                scope: Scope::Once,
                by,
            } => tr!(fmt "approuvée par {by} (une fois)", "approved by {by} (once)"),
            Outcome::Approved {
                scope: Scope::Session,
                by,
            } => {
                tr!(fmt "approuvée par {by} (pour la session)", "approved by {by} (for the session)")
            }
            Outcome::Denied { by } => tr!(fmt "refusée par {by}", "denied by {by}"),
            Outcome::Expired => {
                let secs = timeout.as_secs();
                tr!(fmt "sans réponse en {secs} s : refusée", "no answer within {secs} s: denied")
            }
        }
    }
}

struct Answer {
    approve: bool,
    scope: Scope,
    by: String,
}

struct Waiting {
    view: Pending,
    deadline: Instant,
    reply: oneshot::Sender<Answer>,
}

/// File des demandes d'une session.
pub struct Broker {
    session: String,
    timeout: Duration,
    notify: bool,
    next_id: AtomicU64,
    waiting: Mutex<BTreeMap<u64, Waiting>>,
    /// Clés approuvées « pour la session ».
    grants: Mutex<HashSet<String>>,
    announcements: broadcast::Sender<Pending>,
    /// Processus de l'agent (0 = inconnu, par ex. avec `aestheris serve`).
    agent_pid: AtomicU32,
}

impl Broker {
    pub fn new(session: String, timeout: Duration, notify: bool) -> Self {
        Self {
            session,
            timeout,
            notify,
            next_id: AtomicU64::new(1),
            waiting: Mutex::new(BTreeMap::new()),
            grants: Mutex::new(HashSet::new()),
            announcements: broadcast::channel(64).0,
            agent_pid: AtomicU32::new(0),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Déclare le processus de l'agent : ni lui ni ses descendants ne pourront répondre.
    pub fn set_agent_pid(&self, pid: u32) {
        self.agent_pid.store(pid, Ordering::Relaxed);
    }

    /// Demande une validation et attend la réponse (ou le délai). `key` identifie ce qui est
    /// approuvé « pour la session ».
    pub async fn ask(&self, key: String, kind: &str, summary: String, detail: String) -> Outcome {
        if self.grants.lock().expect("verrou").contains(&key) {
            return Outcome::Approved {
                scope: Scope::Session,
                by: tr!("une validation précédente", "an earlier approval").into(),
            };
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let view = Pending {
            id,
            session: self.session.clone(),
            kind: kind.into(),
            summary,
            detail,
            expires_in: self.timeout.as_secs(),
        };
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().expect("verrou").insert(
            id,
            Waiting {
                view: view.clone(),
                deadline: Instant::now() + self.timeout,
                reply: tx,
            },
        );
        let _ = self.announcements.send(view.clone());
        self.announce(&view);

        let answer = tokio::time::timeout(self.timeout, rx).await;
        self.waiting.lock().expect("verrou").remove(&id);
        match answer {
            Ok(Ok(a)) if a.approve => {
                if a.scope == Scope::Session {
                    self.grants.lock().expect("verrou").insert(key);
                }
                Outcome::Approved {
                    scope: a.scope,
                    by: a.by,
                }
            }
            Ok(Ok(a)) => Outcome::Denied { by: a.by },
            _ => Outcome::Expired,
        }
    }

    /// Réponse d'un humain à la demande `id`.
    pub fn decide(
        &self,
        id: u64,
        approve: bool,
        scope: Scope,
        by: &str,
    ) -> std::result::Result<(), String> {
        let w = self
            .waiting
            .lock()
            .expect("verrou")
            .remove(&id)
            .ok_or_else(|| {
                tr!(fmt "demande #{id} introuvable : déjà traitée ou expirée",
                    "request #{id} not found: already handled or expired")
            })?;
        w.reply
            .send(Answer {
                approve,
                scope,
                by: by.into(),
            })
            .map_err(|_| tr!(fmt "demande #{id} expirée", "request #{id} expired"))?;
        Ok(())
    }

    /// Demandes en attente, avec le temps restant à jour.
    pub fn pending(&self) -> Vec<Pending> {
        let now = Instant::now();
        self.waiting
            .lock()
            .expect("verrou")
            .values()
            .map(|w| Pending {
                expires_in: w.deadline.saturating_duration_since(now).as_secs(),
                ..w.view.clone()
            })
            .collect()
    }

    /// Prévient l'humain : ligne dans le terminal de `aestheris run`, notification macOS.
    fn announce(&self, p: &Pending) {
        let (id, summary, left) = (p.id, &p.summary, p.expires_in);
        eprintln!(
            "{}",
            tr!(fmt "aestheris ▸ ⏸ validation #{id} demandée : {summary} — répondez avec « aestheris approve » ({left} s)",
                "aestheris ▸ ⏸ approval #{id} requested: {summary} — answer with `aestheris approve` ({left} s)")
        );
        if self.notify && cfg!(target_os = "macos") {
            // Texte passé en argument (jamais dans le script) : aucune injection AppleScript.
            // tokio récupère le processus terminé (pas de zombie).
            let _ = tokio::process::Command::new("/usr/bin/osascript")
                .args([
                    "-e",
                    "on run argv",
                    "-e",
                    "display notification (item 2 of argv) with title \"Aestheris\" subtitle (item 1 of argv)",
                    "-e",
                    "end run",
                    &tr!(fmt "Validation #{id} demandée", "Approval #{id} requested"),
                    &p.summary,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    }

    /// Le processus `pid` est-il l'agent ou l'un de ses descendants ?
    fn is_agent(&self, pid: Option<i32>) -> bool {
        let agent = self.agent_pid.load(Ordering::Relaxed);
        match (agent, pid) {
            (0, _) => false,
            // pid inconnu alors qu'un agent tourne : on refuse (fail secure)
            (_, None) => true,
            (agent, Some(pid)) => is_descendant_or_self(pid, agent as i32),
        }
    }
}

/* ------------------------------------------------------------------ */
/* Canal local (socket Unix)                                           */
/* ------------------------------------------------------------------ */

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
enum Command {
    List,
    Watch,
    Decide {
        id: u64,
        approve: bool,
        #[serde(default = "once")]
        scope: Scope,
    },
}

fn once() -> Scope {
    Scope::Once
}

/// Message du canal vers le client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Message {
    Pending { item: Pending },
    List { items: Vec<Pending> },
    Result { id: u64, ok: bool, message: String },
    Error { message: String },
}

/// Canal ouvert ; le fichier du socket (et son lien éventuel) est retiré à l'arrêt.
pub struct AdminSocket {
    path: PathBuf,
    /// Socket réel quand `path` n'est qu'un lien (chemin trop long pour un socket Unix).
    real: Option<PathBuf>,
    task: tokio::task::JoinHandle<()>,
}

impl AdminSocket {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AdminSocket {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
        if let Some(r) = &self.real {
            let _ = std::fs::remove_file(r);
        }
    }
}

/// Ouvre le canal de validation de la session dans `dir` (créé en 0700, socket en 0600).
pub fn serve(broker: std::sync::Arc<Broker>, dir: &Path) -> Result<AdminSocket> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::Policy(format!("dossier du canal de validation : {e}")))?;
    remove_dead_channels(dir);
    let path = dir.join(format!("{}.sock", broker.session));
    let _ = std::fs::remove_file(&path);
    // Un socket Unix a une adresse limitée (104 octets sur macOS) : si le chemin est trop long,
    // le socket va dans /tmp/aestheris-<uid> (0700, à nous) et `path` devient un lien vers lui.
    let real = (path.as_os_str().len() >= MAX_SOCKET_PATH)
        .then(|| short_dir().map(|d| d.join(format!("{}.sock", broker.session))))
        .transpose()?;
    let bound = real.clone().unwrap_or_else(|| path.clone());
    let _ = std::fs::remove_file(&bound);
    let listener = UnixListener::bind(&bound)
        .map_err(|e| Error::Policy(format!("canal de validation {} : {e}", bound.display())))?;
    std::fs::set_permissions(&bound, std::fs::Permissions::from_mode(0o600))?;
    if let Some(r) = &real {
        std::os::unix::fs::symlink(r, &path)?;
    }
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(connection(broker.clone(), stream));
        }
    });
    Ok(AdminSocket { path, real, task })
}

/// Canaux laissés par une session interrompue brutalement (plus personne n'écoute) : retirés,
/// ainsi que leur socket réel s'ils n'étaient qu'un lien.
fn remove_dead_channels(dir: &Path) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = entry.path();
        if p.extension().is_none_or(|x| x != "sock") {
            continue;
        }
        let target = std::fs::canonicalize(&p).ok();
        let alive = target
            .as_deref()
            .is_some_and(|t| std::os::unix::net::UnixStream::connect(t).is_ok());
        if !alive {
            if let Some(t) = &target
                && t != &p
            {
                let _ = std::fs::remove_file(t);
            }
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Marge sous la limite des adresses de sockets Unix (104 octets sur macOS, 108 sur Linux).
const MAX_SOCKET_PATH: usize = 100;

/// `/tmp/aestheris-<uid>` : créé en 0700, refusé s'il appartient à un autre utilisateur ou
/// s'il est ouvert aux autres (quelqu'un pourrait l'avoir préparé pour intercepter le canal).
fn short_dir() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    // SAFETY: getuid ne peut pas échouer.
    let uid = unsafe { libc::getuid() };
    let dir = PathBuf::from(format!("/tmp/aestheris-{uid}"));
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
    let meta = std::fs::symlink_metadata(&dir)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        let d = dir.display();
        return Err(Error::Policy(tr!(fmt
            "{d} n'est pas un dossier privé à cet utilisateur : canal de validation refusé",
            "{d} is not a folder private to this user: approval channel refused")));
    }
    Ok(dir)
}

async fn connection(broker: std::sync::Arc<Broker>, stream: UnixStream) {
    let cred = stream.peer_cred().ok();
    // SAFETY: getuid ne peut pas échouer.
    let same_user = cred.is_some_and(|c| c.uid() == unsafe { libc::getuid() });
    let pid = cred.and_then(|c| c.pid());
    let (read, mut write) = stream.into_split();
    if !same_user || broker.is_agent(pid) {
        let refusal = Message::Error {
            message: tr!(
                "refusé : l'agent ne peut pas répondre à ses propres demandes de validation",
                "denied: the agent cannot answer its own approval requests"
            )
            .into(),
        };
        let _ = write.write_all(line(&refusal).as_bytes()).await;
        return;
    }
    let by = match pid {
        Some(p) => tr!(fmt "un humain (terminal, pid {p})", "a human (terminal, pid {p})"),
        None => tr!("un humain (terminal)", "a human (terminal)").into(),
    };

    let (tx, mut rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if write.write_all(line(&m).as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let mut watcher: Option<tokio::task::JoinHandle<()>> = None;
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(l)) = lines.next_line().await {
        let reply = match serde_json::from_str::<Command>(&l) {
            Err(_) => Message::Error {
                message: "commande illisible".into(),
            },
            Ok(Command::List) => Message::List {
                items: broker.pending(),
            },
            Ok(Command::Watch) => {
                // Abonnement d'abord, puis l'existant : rien ne se perd (un doublon est possible).
                let mut sub = broker.announcements.subscribe();
                for item in broker.pending() {
                    let _ = tx.send(Message::Pending { item }).await;
                }
                let tx2 = tx.clone();
                if let Some(w) = watcher.take() {
                    w.abort();
                }
                watcher = Some(tokio::spawn(async move {
                    loop {
                        match sub.recv().await {
                            Ok(item) => {
                                if tx2.send(Message::Pending { item }).await.is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        }
                    }
                }));
                continue;
            }
            Ok(Command::Decide { id, approve, scope }) => {
                match broker.decide(id, approve, scope, &by) {
                    Ok(()) => Message::Result {
                        id,
                        ok: true,
                        message: if approve {
                            tr!("autorisée", "allowed").into()
                        } else {
                            tr!("refusée", "denied").into()
                        },
                    },
                    Err(message) => Message::Result {
                        id,
                        ok: false,
                        message,
                    },
                }
            }
        };
        if tx.send(reply).await.is_err() {
            break;
        }
    }
    if let Some(w) = watcher {
        w.abort();
    }
    drop(tx);
    let _ = writer.await;
}

fn line(m: &Message) -> String {
    let mut s = serde_json::to_string(m).unwrap_or_default();
    s.push('\n');
    s
}

/* ------------------------------------------------------------------ */
/* Client (utilisé par `aestheris approve` et les tests)               */
/* ------------------------------------------------------------------ */

pub struct Client {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    write: tokio::net::unix::OwnedWriteHalf,
}

impl Client {
    pub async fn connect(path: &Path) -> Result<Self> {
        // Le canal peut être un lien vers un chemin court (voir `serve`).
        let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let stream = UnixStream::connect(&target)
            .await
            .map_err(|e| Error::Policy(format!("canal de validation {} : {e}", path.display())))?;
        let (read, write) = stream.into_split();
        Ok(Self {
            lines: BufReader::new(read).lines(),
            write,
        })
    }

    async fn send(&mut self, c: &Command) -> Result<()> {
        let mut s = serde_json::to_string(c).map_err(|e| Error::Policy(e.to_string()))?;
        s.push('\n');
        self.write.write_all(s.as_bytes()).await?;
        Ok(())
    }

    /// Prochain message du canal (`None` : la session est terminée).
    pub async fn next(&mut self) -> Result<Option<Message>> {
        match self.lines.next_line().await? {
            None => Ok(None),
            Some(l) => serde_json::from_str(&l)
                .map(Some)
                .map_err(|e| Error::Policy(format!("message illisible : {e}"))),
        }
    }

    pub async fn watch(&mut self) -> Result<()> {
        self.send(&Command::Watch).await
    }

    pub async fn list(&mut self) -> Result<()> {
        self.send(&Command::List).await
    }

    pub async fn decide(&mut self, id: u64, approve: bool, scope: Scope) -> Result<()> {
        self.send(&Command::Decide { id, approve, scope }).await
    }
}

/// Canaux ouverts dans `dir`, du plus récent au plus ancien.
pub fn sockets(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sock"))
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .collect();
    found.sort_by_key(|a| std::cmp::Reverse(a.0));
    found.into_iter().map(|(_, p)| p).collect()
}

/* ------------------------------------------------------------------ */
/* Filiation des processus                                             */
/* ------------------------------------------------------------------ */

/// `pid` est-il `ancestor` ou l'un de ses descendants ? (remonte au plus 64 parents)
fn is_descendant_or_self(mut pid: i32, ancestor: i32) -> bool {
    for _ in 0..64 {
        if pid == ancestor {
            return true;
        }
        match parent_pid(pid) {
            Some(p) if p > 1 && p != pid => pid = p,
            _ => return false,
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: i32) -> Option<i32> {
    // SAFETY: structure C de simples entiers et tableaux d'octets : l'état tout à zéro est valide.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: tampon local de la taille annoncée.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (n == size).then_some(info.pbi_ppid as i32)
}

#[cfg(target_os = "linux")]
fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // « pid (nom) état ppid … » : le nom peut contenir des espaces, on part de la dernière « ) ».
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn parent_pid(_pid: i32) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filiation_des_processus() {
        let me = std::process::id() as i32;
        let parent = parent_pid(me).expect("parent du processus de test");
        assert!(is_descendant_or_self(me, me));
        assert!(
            is_descendant_or_self(me, parent),
            "le test descend de son parent"
        );
        assert!(
            !is_descendant_or_self(parent, me),
            "le parent ne descend pas du test"
        );
    }

    #[tokio::test]
    async fn approbation_pour_la_session_puis_expiration() {
        let b = std::sync::Arc::new(Broker::new("s".into(), Duration::from_millis(300), false));
        let b2 = b.clone();
        let waiter = tokio::spawn(async move {
            b2.ask("k".into(), "requête API", "x".into(), String::new())
                .await
        });
        // attendre que la demande soit enregistrée
        let id = loop {
            if let Some(p) = b.pending().first() {
                break p.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        b.decide(id, true, Scope::Session, "test").unwrap();
        assert!(matches!(
            waiter.await.unwrap(),
            Outcome::Approved {
                scope: Scope::Session,
                ..
            }
        ));
        // même clé : accordée sans nouvelle demande ; autre clé : expire
        assert!(matches!(
            b.ask("k".into(), "", String::new(), String::new()).await,
            Outcome::Approved { .. }
        ));
        assert_eq!(
            b.ask("autre".into(), "", String::new(), String::new())
                .await,
            Outcome::Expired
        );
        assert!(b.decide(999, true, Scope::Once, "test").is_err());
    }
}
