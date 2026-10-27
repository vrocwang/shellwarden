use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// 终端尺寸。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySize {
    pub cols: u32,
    pub rows: u32,
}

impl Default for PtySize {
    fn default() -> Self {
        Self {
            cols: 120,
            rows: 32,
        }
    }
}

/// 主机公钥信息。`fingerprint` 形如 `SHA256:...`，与 `ssh-keygen -lf` 一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyInfo {
    pub algorithm: String,
    pub fingerprint: String,
}

/// 已知主机文件的判定结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TrustState {
    Unknown,
    Trusted,
    /// 指纹与已记录值不一致：必须阻断，交由用户处理。
    Changed {
        known: HostKeyInfo,
    },
}

#[derive(Clone)]
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
    /// 直接粘贴的私钥内容（PEM/OpenSSH 格式），不必落盘成文件。
    PrivateKeyPem {
        pem: String,
        passphrase: Option<String>,
    },
    Agent,
    KeyboardInteractive,
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password(_) => f.write_str("Password(<redacted>)"),
            AuthMethod::PrivateKey { path, passphrase } => f
                .debug_struct("PrivateKey")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
            AuthMethod::PrivateKeyPem { pem, passphrase } => f
                .debug_struct("PrivateKeyPem")
                .field("pem_len", &pem.len())
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
            AuthMethod::Agent => f.write_str("Agent"),
            AuthMethod::KeyboardInteractive => f.write_str("KeyboardInteractive"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub timeout: Duration,
    pub auth: AuthMethod,
    /// 期望的主机指纹；`None` 仅用于「探测」（不发送任何凭证）。
    pub expected_host_key: Option<HostKeyInfo>,
}

impl ConnectConfig {
    pub fn new(host: impl Into<String>, port: u16, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            timeout: Duration::from_secs(20),
            auth: AuthMethod::Agent,
            expected_host_key: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("host 不能为空".into());
        }
        if self.port == 0 {
            return Err("port 必须在 1-65535 之间".into());
        }
        if self.timeout.is_zero() {
            return Err("timeout 必须大于 0".into());
        }
        Ok(())
    }
}

/// 终端输出出口。由宿主（Tauri）实现，核心不依赖具体 UI。
pub trait OutputSink: Send + Sync + 'static {
    fn on_data(&self, session_id: &str, data: &[u8]);
    fn on_closed(&self, session_id: &str, exit_code: Option<u32>);
    fn on_error(&self, session_id: &str, message: &str);
}

/// 无副作用的空实现，便于测试与 exec 场景。
pub struct NullSink;

impl OutputSink for NullSink {
    fn on_data(&self, _session_id: &str, _data: &[u8]) {}
    fn on_closed(&self, _session_id: &str, _exit_code: Option<u32>) {}
    fn on_error(&self, _session_id: &str, _message: &str) {}
}

pub type SharedSink = Arc<dyn OutputSink>;

/// 单次 exec 的结果（对应文档 §8.4）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: Option<u32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub truncated: bool,
}

/// PTY 会话的输入命令。
#[derive(Debug)]
pub enum PtyCommand {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Close,
}

/// 已打开的 PTY 会话句柄。写入走 channel，读取由后台任务推送 sink。
#[derive(Debug)]
pub struct PtySession {
    pub id: String,
    pub host_key: HostKeyInfo,
    pub commands: tokio::sync::mpsc::Sender<PtyCommand>,
    /// 最近一段输出。UI 挂载晚于会话建立时，用它补回丢失的初始提示符。
    pub backlog: Arc<std::sync::Mutex<Vec<u8>>>,
    /// UI 是否已挂载。只有未挂载时才缓冲，避免切回时重复回放。
    pub attached: Arc<AtomicBool>,
}

impl PtySession {
    pub async fn write(&self, data: Vec<u8>) -> Result<(), String> {
        self.commands
            .send(PtyCommand::Data(data))
            .await
            .map_err(|_| "会话已关闭".to_string())
    }

    pub async fn resize(&self, cols: u32, rows: u32) -> Result<(), String> {
        self.commands
            .send(PtyCommand::Resize { cols, rows })
            .await
            .map_err(|_| "会话已关闭".to_string())
    }

    /// 标记 UI 已挂载，并取走挂载前的输出。
    ///
    /// 置位与 drain 必须在同一把 backlog 锁内完成，否则会与写入线程竞态：
    /// 先置位、后 drain 时，窗口内到达的字节既不会进缓冲，也不会补回。
    pub fn attach(&self) -> Vec<u8> {
        match self.backlog.lock() {
            Ok(mut buffer) => {
                self.attached.store(true, Ordering::SeqCst);
                std::mem::take(&mut *buffer)
            }
            Err(_) => {
                self.attached.store(true, Ordering::SeqCst);
                Vec::new()
            }
        }
    }

    /// UI 卸载（切换到别的会话）：此后输出重新进入回放缓冲。
    pub fn detach(&self) {
        if let Ok(_buffer) = self.backlog.lock() {
            self.attached.store(false, Ordering::SeqCst);
        }
    }

    pub fn backlog(&self) -> Vec<u8> {
        self.backlog
            .lock()
            .map(|buf| buf.clone())
            .unwrap_or_default()
    }

    /// 取走已缓冲输出（UI 挂载后调用一次，避免重复回放）。
    pub fn take_backlog(&self) -> Vec<u8> {
        match self.backlog.lock() {
            Ok(mut buf) => std::mem::take(&mut *buf),
            Err(_) => Vec::new(),
        }
    }

    pub async fn close(&self) -> Result<(), String> {
        self.commands
            .send(PtyCommand::Close)
            .await
            .map_err(|_| "会话已关闭".to_string())
    }
}

#[cfg(test)]
mod attach_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[tokio::test]
    async fn attach_drains_backlog_and_marks_attached() {
        let backlog = Arc::new(std::sync::Mutex::new(b"ops@host:~$ ".to_vec()));
        let attached = Arc::new(AtomicBool::new(false));
        let (commands, _rx) = tokio::sync::mpsc::channel(1);
        let session = PtySession {
            id: "sess".into(),
            host_key: HostKeyInfo {
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:test".into(),
            },
            commands,
            backlog: backlog.clone(),
            attached: attached.clone(),
        };

        assert_eq!(session.attach(), b"ops@host:~$ ");
        assert!(attached.load(Ordering::SeqCst));
        assert!(backlog.lock().unwrap().is_empty());

        session.detach();
        assert!(!attached.load(Ordering::SeqCst));
    }
}
