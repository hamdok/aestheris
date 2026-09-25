//! Aestheris Gateway : la passerelle de confiance entre les agents IA et vos API.
//!
//! Voir `docs/DESIGN.md` pour l'architecture et le modèle de menaces.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod approval;
pub mod audit;
pub mod error;
mod gitleaks;
pub mod harden;
pub mod i18n;
pub mod init;
pub mod phantom;
pub mod policy;
pub mod privacy;
pub mod project_scan;
pub mod proxy;
pub mod report;
pub mod run;
pub mod sandbox;
pub mod sandbox_linux;
pub mod scan;
pub mod secret;
pub mod vault;

pub use error::{Error, Result};
