//! `mauvelyd`, the Mauvely OS device agent.
//!
//! It enrols the device, checks in on a timer, and reconciles system Flatpak
//! remotes and apps and the bootc image against what the server asks for.
//! The wire format is brief 19's agent API v1.

pub mod agent;
pub mod api;
pub mod bootc;
pub mod command;
pub mod creds;
pub mod facts;
pub mod flatpak;
pub mod reconcile;
pub mod schedule;
pub mod signing;
pub mod state;

#[cfg(test)]
mod fake;

use std::path::PathBuf;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{program}: {detail}")]
    Command { program: String, detail: String },
    #[error("{what}: {source}")]
    Json {
        what: String,
        source: serde_json::Error,
    },
    #[error("{0}")]
    Http(String),
    #[error("random: {0}")]
    Random(String),
    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn json(what: impl Into<String>, source: serde_json::Error) -> Self {
        Error::Json {
            what: what.into(),
            source,
        }
    }
}
