use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const API: u32 = 1;
pub const MAX_MESSAGE: usize = 64 * 1024;
pub const REQUEST_SECONDS: u64 = 120;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub api_version: u32,
    pub action: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub interactive: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub value: Value,
}
impl Command {
    pub fn new(action: &str) -> Self {
        Self {
            api_version: API,
            action: action.into(),
            key: None,
            request_id: None,
            interactive: false,
            reason: String::new(),
            value: Value::Null,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.api_version != API {
            return Err(Error("api_mismatch"));
        }
        if self.reason.chars().count() > 240 || self.reason.chars().any(char::is_control) {
            return Err(Error("invalid_reason"));
        }
        Ok(())
    }
}
pub fn response(
    state: &str,
    key: Option<&str>,
    request: Option<&str>,
    expiry: Option<u64>,
    code: Option<&str>,
) -> Value {
    json!({"api_version": API, "state":state, "key_id":key,"request_id":request,"expires_at":expiry,"error_code":code})
}
pub fn error(code: &str) -> Value {
    response("error", None, None, None, Some(code))
}
