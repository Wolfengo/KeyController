pub mod agent;
pub mod client;
pub mod keys;
pub mod locale;
pub mod platform;
pub mod process;
pub mod protocol;
pub mod server;
pub mod state;
pub mod worker;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("io_error")
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid_json")
    }
}
impl From<zbus::Error> for Error {
    fn from(_: zbus::Error) -> Self {
        Self("session_unavailable")
    }
}
