//! Shared types, errors, and constants for the Aegyra workspace.

pub mod client;
pub mod ipc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AegyraError {
    #[error("TPM error: {0}")]
    Tpm(String),
    #[error("biometrics error: {0}")]
    Biometrics(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(String),
}

pub type Result<T> = std::result::Result<T, AegyraError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    Full,
    Medium,
    Basic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootMode {
    Uki,
    Grub,
    Unknown,
}

pub const SOCKET_PATH: &str = "/run/aegyra.sock";
pub const CONFIG_ROOT: &str = "/etc/aegyra";
