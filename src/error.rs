use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("ordinary reboot required: {0}")]
    NeedsReboot(String),
    #[error("I/O {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ZIP: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("external catalog does not belong to this xpad2 release")]
    CatalogReleaseMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn msg(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

pub fn needs_reboot(message: impl Into<String>) -> Error {
    Error::NeedsReboot(message.into())
}

impl Error {
    pub fn requires_reboot(&self) -> bool {
        matches!(self, Self::NeedsReboot(_))
    }
}

pub trait IoContext<T> {
    fn at(self, path: impl Into<PathBuf>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn at(self, path: impl Into<PathBuf>) -> Result<T> {
        let path = path.into();
        self.map_err(|source| Error::Io { path, source })
    }
}
