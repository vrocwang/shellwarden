use async_trait::async_trait;

use shellwarden_core::error::{AppError, Result};

use crate::config::{ConnectConfig, ExecResult, HostKeyInfo, PtySize, SharedSink};

/// 统一 SSH 后端接口（文档 §8.2 的 Rust 版）。
///
/// 约束：主机密钥在校验通过前不发送任何凭证。`open_pty` / `exec` 要求调用方
/// 传入 `expected_host_key`（`ConnectConfig` 中），指纹不符时直接失败。
#[async_trait]
pub trait SshBackend: Send + Sync {
    /// 只探测主机公钥，不发送凭证。
    async fn probe_host_key(&self, config: &ConnectConfig) -> Result<HostKeyInfo>;

    /// 建立会话并申请 PTY，返回可写入的句柄；输出经 sink 推送。
    async fn open_pty(
        &self,
        config: &ConnectConfig,
        size: PtySize,
        sink: SharedSink,
    ) -> Result<crate::config::PtySession>;

    /// 执行单条命令并收集结果（AI 只读工具走这条路径）。
    async fn exec(
        &self,
        config: &ConnectConfig,
        command: &str,
        output_limit_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<ExecResult>;
}

pub fn ssh_error(code: &str, message: impl Into<String>) -> AppError {
    AppError::new(code, message)
}

pub mod codes {
    pub const CONNECT_TIMEOUT: &str = "ssh.connect.timeout";
    pub const CONNECT_FAILED: &str = "ssh.connect.failed";
    pub const HOST_KEY_CHANGED: &str = "ssh.host_key.changed";
    pub const HOST_KEY_UNKNOWN: &str = "ssh.host_key.unknown";
    pub const HOST_KEY_UNSUPPORTED: &str = "ssh.host_key.unsupported";
    pub const AUTH_FAILED: &str = "ssh.auth.failed";
    pub const AUTH_UNSUPPORTED: &str = "ssh.auth.unsupported";
    pub const PTY_FAILED: &str = "ssh.pty.failed";
    pub const EXEC_FAILED: &str = "ssh.exec.failed";
    pub const SESSION_NOT_FOUND: &str = "ssh.session.not_found";
}
