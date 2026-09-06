//! Central error type shared across all StreamGuard crates.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("routing error: {0}")]
    Routing(String),
    #[error("platform error: {0}")]
    Platform(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::Transport(msg.into())
    }
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
    pub fn routing(msg: impl Into<String>) -> Self {
        Self::Routing(msg.into())
    }
    pub fn platform(msg: impl Into<String>) -> Self {
        Self::Platform(msg.into())
    }
}