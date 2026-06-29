use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("protocol error: {0}")]
    Proto(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("db error: {0}")]
    Db(String),
    #[error("serde error: {0}")]
    Serde(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("not found")]
    NotFound,
    #[error("already registered")]
    AlreadyRegistered,
    #[error("already in filter")]
    AlreadyInFilter,
    #[error("not in filter")]
    NotInFilter,
    #[error("filter not set")]
    FilterNotSet,
    #[error("blocked by filter")]
    Blocked,
    #[error("network not found")]
    NetworkNotFound,
    #[error("network already exists")]
    NetworkExists,
    #[error("not in network")]
    NotInNetwork,
    #[error("host refused join")]
    JoinRefused,
    #[error("host not responding")]
    HostTimeout,
    #[error("timeout")]
    Timeout,
    #[error("packet expired")]
    Expired,
    #[error("silk failed")]
    SilkFailed,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
impl From<sled::Error> for Error {
    fn from(e: sled::Error) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Self::Serde(e.to_string())
    }
}
