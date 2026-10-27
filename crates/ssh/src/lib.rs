//! ShellWarden SSH 传输层。
//!
//! - `config`：连接配置、主机密钥信息、PTY/exec 数据类型；
//! - `known_hosts`：应用自管的指纹存储（与系统 known_hosts 分离）；
//! - `backend`：`SshBackend` 接口与稳定错误码；
//! - `russh_backend`：基于 russh 的实现（先验密钥、后发凭证）。

pub mod backend;
pub mod config;
pub mod known_hosts;
pub mod russh_backend;

pub use backend::{codes, SshBackend};
pub use config::{
    AuthMethod, ConnectConfig, ExecResult, HostKeyInfo, NullSink, OutputSink, PtyCommand,
    PtySession, PtySize, SharedSink, TrustState,
};
pub use known_hosts::{KnownHostEntry, KnownHostsStore};
pub use russh_backend::RusshBackend;
