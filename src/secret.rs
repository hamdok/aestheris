//! Valeur secrète en mémoire.
//!
//! Enveloppe `Zeroizing<String>` : la mémoire est effacée quand la valeur est libérée.
//! `Debug` n'affiche jamais le contenu, pour qu'un secret ne puisse pas finir dans un journal ou
//! un message d'erreur par accident.

use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Accès explicite au contenu. Le nom rappelle, à chaque appel, qu'on manipule un secret.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(«masqué»)")
    }
}

/// Un secret destiné à un en-tête HTTP ne doit contenir ni retour chariot, ni saut de ligne,
/// ni caractère nul : sinon il pourrait couper la requête et en forger une autre.
pub fn is_header_safe(value: &str) -> bool {
    !value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_ne_montre_jamais_la_valeur() {
        let s = Secret::new("sk_live_tres_secret".into());
        assert!(!format!("{s:?}").contains("sk_live"));
    }

    #[test]
    fn refuse_les_caracteres_de_coupure() {
        assert!(is_header_safe("sk_test_abc"));
        assert!(!is_header_safe("abc\r\nX-Evil: 1"));
        assert!(!is_header_safe("abc\0"));
    }
}
