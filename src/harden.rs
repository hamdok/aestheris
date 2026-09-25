//! Durcissement du processus de la passerelle, qui détient les vrais secrets en mémoire.
//!
//! Portions adaptées d'un travail sous licence Apache-2.0 (voir NOTICE) :
//! - aucun débogueur ne peut s'attacher (`PT_DENY_ATTACH` sur macOS, `PR_SET_DUMPABLE` sur Linux :
//!   un autre processus du même utilisateur ne peut pas lire la mémoire de la passerelle) ;
//! - aucun fichier d'image mémoire (core dump) en cas de plantage (il contiendrait les secrets) ;
//! - refus de démarrer si une bibliothèque a pu être injectée au lancement (`DYLD_INSERT_LIBRARIES`,
//!   `LD_PRELOAD`…) ; ces variables ne sont pas non plus transmises à l'agent.
//!
//! Chaque échec empêche le démarrage (fail secure).

use crate::error::{Error, Result};
use crate::tr;

/// Variables qui font charger du code arbitraire dans un processus au lancement. (Les chemins de
/// recherche `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH`, courants et légitimes, ne sont pas refusés.)
pub const INJECTION_ENV: &[&str] = &["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "LD_AUDIT"];

pub fn harden_process() -> Result<()> {
    if let Some(v) = INJECTION_ENV.iter().find(|v| std::env::var_os(v).is_some()) {
        return Err(Error::Policy(tr!(fmt
            "variable {v} présente : une bibliothèque a pu être injectée dans la passerelle, \
             lancement refusé (retirez-la de l'environnement)",
            "variable {v} is set: a library may have been injected into the gateway, refusing \
             to start (remove it from the environment)")));
    }
    deny_debugger()?;
    disable_core_dumps()
}

#[cfg(target_os = "macos")]
fn deny_debugger() -> Result<()> {
    // SAFETY: appel système sans pointeur valide requis pour PT_DENY_ATTACH.
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc == -1 {
        return Err(Error::Policy(format!(
            "ptrace(PT_DENY_ATTACH) : {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn deny_debugger() -> Result<()> {
    // SAFETY: prctl avec des entiers uniquement.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        return Err(Error::Policy(format!(
            "prctl(PR_SET_DUMPABLE) : {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn deny_debugger() -> Result<()> {
    Ok(())
}

pub fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: pointeur vers une structure locale valide.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(Error::Policy(format!(
            "setrlimit(RLIMIT_CORE) : {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn plus_de_core_dump() {
        super::disable_core_dumps().unwrap();
        let mut l = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: pointeur vers une structure locale valide.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut l) }, 0);
        assert_eq!((l.rlim_cur, l.rlim_max), (0, 0));
    }
}
