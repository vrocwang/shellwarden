use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 统一错误结构，对应文档 §17.3。
/// `code` 稳定可检索，文案与 code 分离以便 i18n。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Value,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_action: Option<String>,
}

impl AppError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            details: Value::Null,
            retryable: false,
            user_action: None,
        }
    }

    pub fn with_details(mut self, details: impl Serialize) -> Self {
        self.details = serde_json::to_value(details).unwrap_or(Value::Null);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.user_action = Some(action.into());
        self
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

pub type Result<T> = std::result::Result<T, AppError>;

/// 稳定错误码。新增时遵循 `<域>.<子域>.<原因>`。
pub mod codes {
    pub const DIGEST_FAILED: &str = "digest.failed";

    pub const AUDIT_INTEGRITY: &str = "audit.integrity";
}
