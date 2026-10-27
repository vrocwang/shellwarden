use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use shellwarden_core::audit::AuditChain;
use shellwarden_ssh::{
    ConnectConfig, HostKeyInfo, KnownHostsStore, PtySession, RusshBackend, SshBackend,
};
use shellwarden_store::Db;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::AppConfig;
use crate::secret::SecretBox;

pub struct AppState {
    pub db: Mutex<Db>,
    pub secrets: SecretBox,
    pub ssh: SshState,
    /// 审计哈希链；启动时从数据库恢复。
    pub audit: Mutex<AuditChain>,
    /// 启动验链失败后 fail-closed，阻止继续写审计。
    pub audit_ok: AtomicBool,
    /// 配置来源与数据目录，供设置页展示和“修改位置”提示。
    pub config_path: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    pub config: Mutex<AppConfig>,
    /// 每个任务最近一次 `task_revise` 模型调用的取消通知。
    /// 用户取消任务时唤醒 `tokio::select!`，丢弃未完成的模型请求。
    pub revise_cancels: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
}

#[derive(Debug, Clone)]
pub struct ProbeRecord {
    /// 一次探测的标识；用户确认信任时必须回传，避免“看到 A 的指纹、
    /// 后端信任了后来被覆盖的 B 的指纹”。
    pub probe_id: String,
    pub hostname: String,
    pub port: u16,
    pub info: HostKeyInfo,
}

pub struct SshState {
    /// 可注入的 SSH 后端：生产是 russh，测试可以替换为 fake backend。
    pub backend: Arc<dyn SshBackend>,
    pub known_hosts: AsyncMutex<KnownHostsStore>,
    /// 最近一次服务端探测到的指纹；信任只接受这里的结果，不接受前端传入。
    /// 记录 hostname/port，主机编辑后旧探测自动失效。
    pub probes: AsyncMutex<HashMap<String, ProbeRecord>>,
    pub sessions: AsyncMutex<HashMap<String, PtySession>>,
    /// 每个活动会话的连接参数，用于 `command -v` 探测（不落盘）。
    pub configs: AsyncMutex<HashMap<String, ConnectConfig>>,
    /// `command -v` 结果缓存：host@port:user#token -> 是否存在。
    pub command_cache: AsyncMutex<HashMap<String, bool>>,
}

impl SshState {
    pub fn new(known_hosts: KnownHostsStore) -> Self {
        Self::with_backend(known_hosts, Arc::new(RusshBackend::new()))
    }

    /// 测试/联调注入后端；生产使用 `new()`。
    pub fn with_backend(known_hosts: KnownHostsStore, backend: Arc<dyn SshBackend>) -> Self {
        Self {
            backend,
            known_hosts: AsyncMutex::new(known_hosts),
            probes: AsyncMutex::new(HashMap::new()),
            sessions: AsyncMutex::new(HashMap::new()),
            configs: AsyncMutex::new(HashMap::new()),
            command_cache: AsyncMutex::new(HashMap::new()),
        }
    }
}
