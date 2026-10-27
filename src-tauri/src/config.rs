use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
pub const DEFAULT_MODEL: &str = "gpt-4o-mini";
pub const DEFAULT_TASK_HISTORY_KEEP_DAYS: i64 = 30;
pub const DEFAULT_TASK_HISTORY_MAX_TERMINAL: i64 = 200;
pub const MAX_TASK_HISTORY_KEEP_DAYS: i64 = 3650;
pub const MAX_TASK_HISTORY_MAX_TERMINAL: i64 = 10_000;

/// 用户可编辑配置。只放非秘密设置；API key 仍由 `SecretBox` 加密保存。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub model: ModelFile,
    #[serde(default)]
    pub shortcuts: ShortcutsConfig,
    #[serde(default)]
    pub tasks: TaskHistoryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskHistoryConfig {
    /// 终态任务保留天数；0 表示不按时间清理。
    #[serde(default = "default_task_history_keep_days")]
    pub history_keep_days: i64,
    /// 每个范围内最多保留的终态任务数；0 表示不按数量清理。
    #[serde(default = "default_task_history_max_terminal")]
    pub history_max_terminal: i64,
}

impl Default for TaskHistoryConfig {
    fn default() -> Self {
        Self {
            history_keep_days: DEFAULT_TASK_HISTORY_KEEP_DAYS,
            history_max_terminal: DEFAULT_TASK_HISTORY_MAX_TERMINAL,
        }
    }
}

fn default_task_history_keep_days() -> i64 {
    DEFAULT_TASK_HISTORY_KEEP_DAYS
}

fn default_task_history_max_terminal() -> i64 {
    DEFAULT_TASK_HISTORY_MAX_TERMINAL
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShortcutsConfig {
    /// 例：Cmd+C / Ctrl+Shift+C / Shift+Insert。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paste: Option<String>,
}

pub fn default_shortcuts() -> (String, String) {
    if cfg!(target_os = "macos") {
        ("Cmd+C".into(), "Cmd+V".into())
    } else {
        ("Ctrl+Shift+C".into(), "Ctrl+Shift+V".into())
    }
}

impl AppConfig {
    pub fn shortcut_copy(&self) -> String {
        self.shortcuts
            .copy
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| default_shortcuts().0)
    }

    pub fn shortcut_paste(&self) -> String {
        self.shortcuts
            .paste
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| default_shortcuts().1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    /// 绝对路径，或相对于 config.toml 所在目录的路径。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    /// 上次实际使用的数据目录（应用维护，用于把已有数据迁移到新目录）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_data_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|error| format!("读取配置 {} 失败: {error}", path.display()))?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        toml::from_str(raw).map_err(|error| format!("配置不是合法 TOML: {error}"))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("创建配置目录 {} 失败: {error}", parent.display()))?;
        }
        let raw =
            toml::to_string_pretty(self).map_err(|error| format!("序列化配置失败: {error}"))?;
        std::fs::write(path, raw)
            .map_err(|error| format!("写入配置 {} 失败: {error}", path.display()))
    }

    /// 补齐默认模型设置；返回是否发生了修改。
    pub fn ensure_defaults(&mut self) -> bool {
        let mut changed = false;
        if self
            .model
            .base_url
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            self.model.base_url = Some(DEFAULT_BASE_URL.into());
            changed = true;
        }
        if self.model.model.as_deref().unwrap_or("").trim().is_empty() {
            self.model.model = Some(DEFAULT_MODEL.into());
            changed = true;
        }
        changed
    }

    /// 配置中的 data_dir：绝对路径直接用；相对路径相对于 config.toml 所在目录。
    pub fn resolved_data_dir(&self, config_path: &Path) -> Option<PathBuf> {
        let raw = self.storage.data_dir.as_deref()?.trim();
        if raw.is_empty() {
            return None;
        }
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            Some(path)
        } else {
            config_path.parent().map(|parent| parent.join(path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_storage_and_model() {
        let config = AppConfig::parse(
            r#"
[storage]
data_dir = "./data"

[model]
base_url = "http://127.0.0.1:11434/v1"
model = "qwen"
"#,
        )
        .unwrap();
        assert_eq!(config.storage.data_dir.as_deref(), Some("./data"));
        assert_eq!(config.storage.last_data_dir, None);
        assert_eq!(config.model.model.as_deref(), Some("qwen"));
    }

    #[test]
    fn relative_data_dir_is_config_relative() {
        let config = AppConfig::parse("[storage]\ndata_dir = \"data\"\n").unwrap();
        let path = config
            .resolved_data_dir(Path::new("/tmp/shellwarden/config.toml"))
            .unwrap();
        assert_eq!(path, PathBuf::from("/tmp/shellwarden/data"));
    }

    #[test]
    fn shortcuts_parse_and_default() {
        let config = AppConfig::parse("[shortcuts]\ncopy = \"Ctrl+Alt+C\"\n").unwrap();
        assert_eq!(config.shortcut_copy(), "Ctrl+Alt+C");
        let default = AppConfig::default();
        assert_eq!(default.shortcut_copy(), default_shortcuts().0);
        assert_eq!(default.shortcut_paste(), default_shortcuts().1);
    }

    #[test]
    fn task_history_policy_defaults_and_parse() {
        let default = AppConfig::default();
        assert_eq!(
            default.tasks.history_keep_days,
            DEFAULT_TASK_HISTORY_KEEP_DAYS
        );
        assert_eq!(
            default.tasks.history_max_terminal,
            DEFAULT_TASK_HISTORY_MAX_TERMINAL
        );
        let config = AppConfig::parse(
            "[tasks]
history_keep_days = 7
",
        )
        .unwrap();
        assert_eq!(config.tasks.history_keep_days, 7);
        assert_eq!(
            config.tasks.history_max_terminal,
            DEFAULT_TASK_HISTORY_MAX_TERMINAL
        );
    }

    #[test]
    fn defaults_are_filled_without_overwriting() {
        let mut config = AppConfig::parse("[model]\nmodel = \"custom\"\n").unwrap();
        assert!(config.ensure_defaults());
        assert_eq!(config.model.model.as_deref(), Some("custom"));
        assert_eq!(config.model.base_url.as_deref(), Some(DEFAULT_BASE_URL));
    }
}
