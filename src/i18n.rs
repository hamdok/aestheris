//! Langue de l'interface : anglais ou français.
//!
//! Choisie une fois par processus : `AESTHERIS_LANG` (`fr`, `en`), sinon la langue du système
//! (`LC_ALL`, `LC_MESSAGES`, `LANG`) ; français si elle commence par `fr`, anglais sinon.
//! Les tests unitaires de la bibliothèque sont écrits contre le texte français.
//!
//! Dans le code : `tr!("texte", "text")`, ou `tr!("{n} fichier(s)", "{n} file(s)")` pour un texte
//! mis en forme (renvoie alors une `String`).

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Fr,
    En,
}

static LANG: OnceLock<Lang> = OnceLock::new();

/// Langue du processus (déterminée au premier appel).
pub fn lang() -> Lang {
    *LANG.get_or_init(|| {
        if cfg!(test) {
            Lang::Fr
        } else {
            from_env(|k| std::env::var(k).ok())
        }
    })
}

/// Fixe la langue avant tout affichage (tests d'intégration). Sans effet si elle est déjà choisie.
pub fn set(lang: Lang) {
    let _ = LANG.set(lang);
}

pub fn fr() -> bool {
    lang() == Lang::Fr
}

/// Langue d'après l'environnement, lu par `get`.
pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Lang {
    let pick = |v: &str| {
        if v.trim().to_ascii_lowercase().starts_with("fr") {
            Lang::Fr
        } else {
            Lang::En
        }
    };
    if let Some(v) = get("AESTHERIS_LANG").filter(|v| !v.trim().is_empty()) {
        return pick(&v);
    }
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(v) = get(key).filter(|v| !v.trim().is_empty() && v != "C" && v != "POSIX") {
            return pick(&v);
        }
    }
    Lang::En
}

/// Texte selon la langue : `tr!("fr", "en")` → `&'static str` ;
/// `tr!("fr {x}", "en {x}", …)` ou avec des variables capturées → `String`.
#[macro_export]
macro_rules! tr {
    ($fr:literal, $en:literal $(,)?) => {
        if $crate::i18n::fr() { $fr } else { $en }
    };
    (fmt $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::i18n::fr() { format!($fr $(, $arg)*) } else { format!($en $(, $arg)*) }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn choix_de_la_langue() {
        assert_eq!(from_env(env(&[])), Lang::En);
        assert_eq!(from_env(env(&[("LANG", "fr_FR.UTF-8")])), Lang::Fr);
        assert_eq!(from_env(env(&[("LANG", "en_US.UTF-8")])), Lang::En);
        assert_eq!(
            from_env(env(&[("LC_ALL", "C"), ("LANG", "fr_CA.UTF-8")])),
            Lang::Fr
        );
        assert_eq!(
            from_env(env(&[("AESTHERIS_LANG", "en"), ("LANG", "fr_FR.UTF-8")])),
            Lang::En
        );
        assert_eq!(from_env(env(&[("AESTHERIS_LANG", "fr")])), Lang::Fr);
    }

    #[test]
    fn traduction_avec_variables_capturees() {
        let n = 3;
        assert_eq!(crate::tr!("bonjour", "hello"), "bonjour");
        assert_eq!(
            crate::tr!(fmt "{n} fichier(s)", "{n} file(s)"),
            "3 fichier(s)"
        );
        assert_eq!(crate::tr!(fmt "{} et {}", "{} and {}", 1, 2), "1 et 2");
    }
}
