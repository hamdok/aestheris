//! Jeton fantôme de session.
//!
//! Chaque session tire 32 octets aléatoires
//! (256 bits) auprès du système, encodés en hexadécimal et préfixés `aes_ph_`. L'agent reçoit ce
//! jeton à la place de sa vraie clé (ex. `STRIPE_API_KEY=aes_ph_…`). Hors de la passerelle, il ne
//! vaut rien ; dans la passerelle, il prouve que la requête vient bien de l'agent lancé par nous
//! (un autre processus local ne le connaît pas).
//!
//! La comparaison se fait en temps constant (`subtle`) pour ne rien révéler par chronométrage.

use crate::error::{Error, Result};
use crate::tr;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const PREFIX: &str = "aes_ph_";
const TOKEN_BYTES: usize = 32;

pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|e| {
            Error::Crypto(tr!(fmt "aléa indisponible : {e}", "randomness unavailable: {e}"))
        })?;
        Ok(Self(Zeroizing::new(format!(
            "{PREFIX}{}",
            hex::encode(bytes.as_ref())
        ))))
    }

    /// Valeur à transmettre à l'agent (variables d'environnement).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Vrai si `candidate` est exactement ce jeton, comparé en temps constant.
    pub fn matches(&self, candidate: &str) -> bool {
        let a = self.0.as_bytes();
        let b = candidate.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(«masqué»)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jetons_uniques_et_bien_formes() {
        let a = SessionToken::generate().unwrap();
        let b = SessionToken::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert!(a.expose().starts_with(PREFIX));
        assert_eq!(a.expose().len(), PREFIX.len() + 64);
    }

    #[test]
    fn comparaison() {
        let t = SessionToken::generate().unwrap();
        assert!(t.matches(t.expose()));
        assert!(!t.matches("aes_ph_faux"));
        assert!(!t.matches(""));
    }
}
