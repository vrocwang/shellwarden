use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use russh::client::{self, Handle};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use shellwarden_core::error::{AppError, Result};
use shellwarden_core::ids::new_id;
use tokio::sync::mpsc;

use crate::backend::{codes, ssh_error, SshBackend};
use crate::config::{
    AuthMethod, ConnectConfig, ExecResult, HostKeyInfo, OutputSink, PtyCommand, PtySession,
    PtySize, SharedSink,
};

/// 握手阶段捕获服务端公钥，并与期望值比对。
///
/// 安全顺序：先校验密钥，再认证。`expected = None` 只用于探测，绝不发送凭证。
struct KeyCapture {
    expected: Option<HostKeyInfo>,
    observed: Arc<Mutex<Option<HostKeyInfo>>>,
}

fn host_key_info(key: &PublicKeyOrCertificate) -> Option<HostKeyInfo> {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => Some(HostKeyInfo {
            algorithm: key.algorithm().as_str().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        }),
        // 主机证书：M1 明确不支持（PoC 矩阵中单列），不允许静默降级。
        PublicKeyOrCertificate::Certificate(_) => None,
    }
}

impl client::Handler for KeyCapture {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let info = host_key_info(server_public_key);
        *self.observed.lock().expect("host key lock poisoned") = info.clone();

        match (&self.expected, info) {
            (None, _) => Ok(true),
            (Some(expected), Some(observed)) => Ok(expected == &observed),
            (Some(_), None) => Ok(false),
        }
    }
}

/// 保留最近一段输出，解决「UI 挂载晚于会话建立」导致初始提示符丢失的问题。
struct BufferedSink {
    inner: SharedSink,
    backlog: Arc<Mutex<Vec<u8>>>,
    attached: Arc<std::sync::atomic::AtomicBool>,
    limit: usize,
}

impl OutputSink for BufferedSink {
    fn on_data(&self, session_id: &str, data: &[u8]) {
        // 只缓冲「UI 未挂载」期间的输出；挂载中已实时渲染，无需回放。
        // attached 的检查必须在 backlog 锁内，与 attach() 的 drain+置位原子化，
        // 否则会在这个窗口丢掉恰好到达的初始提示符。
        //
        // 未挂载时只写入 backlog、不推事件：否则“监听器已注册但 attach 未完成”
        // 的窗口里，同一段输出会既实时打印、又随 backlog 再打印一次。
        if let Ok(mut buffer) = self.backlog.lock() {
            if !self.attached.load(std::sync::atomic::Ordering::SeqCst) {
                buffer.extend_from_slice(data);
                if buffer.len() > self.limit {
                    let overflow = buffer.len() - self.limit;
                    buffer.drain(..overflow);
                }
                return;
            }
        }
        self.inner.on_data(session_id, data);
    }

    fn on_closed(&self, session_id: &str, exit_code: Option<u32>) {
        self.inner.on_closed(session_id, exit_code);
    }

    fn on_error(&self, session_id: &str, message: &str) {
        self.inner.on_error(session_id, message);
    }
}

#[derive(Default)]
pub struct RusshBackend;

impl RusshBackend {
    pub fn new() -> Self {
        Self
    }
}

async fn connect_raw(
    config: &ConnectConfig,
    expected: Option<HostKeyInfo>,
) -> Result<(Handle<KeyCapture>, HostKeyInfo)> {
    config
        .validate()
        .map_err(|e| ssh_error(codes::CONNECT_FAILED, e))?;

    let observed = Arc::new(Mutex::new(None));
    let handler = KeyCapture {
        expected: expected.clone(),
        observed: observed.clone(),
    };
    let ssh_config = Arc::new(client::Config {
        // 交互会话可能长时间无输出；不要用连接超时当空闲超时。
        inactivity_timeout: None,
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    });

    let fut = client::connect(ssh_config, (config.host.as_str(), config.port), handler);

    let handle = match tokio::time::timeout(config.timeout, fut).await {
        Err(_) => {
            return Err(ssh_error(
                codes::CONNECT_TIMEOUT,
                format!(
                    "连接 {}:{} 超时（{}s）",
                    config.host,
                    config.port,
                    config.timeout.as_secs()
                ),
            ))
        }
        Ok(Err(error)) => {
            let got = observed.lock().expect("host key lock poisoned").clone();
            if let (Some(expected), Some(observed)) = (&expected, &got) {
                if expected != observed {
                    return Err(ssh_error(
                        codes::HOST_KEY_CHANGED,
                        format!(
                            "主机指纹已变化：已记录 {}，本次 {}",
                            expected.fingerprint, observed.fingerprint
                        ),
                    )
                    .with_details(serde_json::json!({
                        "expected": expected,
                        "observed": observed,
                    }))
                    .with_action("确认主机是否被重装或遭遇中间人；如确认无误，重新信任新指纹"));
                }
            }
            return Err(ssh_error(
                codes::CONNECT_FAILED,
                format!("连接 {}:{} 失败: {error}", config.host, config.port),
            ));
        }
        Ok(Ok(handle)) => handle,
    };

    let info = observed
        .lock()
        .expect("host key lock poisoned")
        .clone()
        .ok_or_else(|| {
            ssh_error(
                codes::HOST_KEY_UNSUPPORTED,
                "服务端使用 SSH 主机证书，当前版本尚未支持",
            )
            .with_action("在 PoC 矩阵中补上证书校验后再启用该主机")
        })?;
    Ok((handle, info))
}

async fn authenticate(handle: &mut Handle<KeyCapture>, config: &ConnectConfig) -> Result<()> {
    tokio::time::timeout(config.timeout, authenticate_inner(handle, config))
        .await
        .map_err(|_| ssh_error(codes::AUTH_FAILED, "认证超时"))?
}

async fn authenticate_inner(handle: &mut Handle<KeyCapture>, config: &ConnectConfig) -> Result<()> {
    match &config.auth {
        AuthMethod::Password(password) => {
            let result = handle
                .authenticate_password(config.username.clone(), password.clone())
                .await
                .map_err(|e| ssh_error(codes::AUTH_FAILED, format!("密码认证失败: {e}")))?;
            if result.success() {
                Ok(())
            } else {
                Err(ssh_error(
                    codes::AUTH_FAILED,
                    "认证被拒绝：用户名或密码错误",
                ))
            }
        }
        AuthMethod::PrivateKeyPem { pem, passphrase } => {
            let key = russh::keys::decode_secret_key(pem, passphrase.as_deref()).map_err(|e| {
                ssh_error(codes::AUTH_FAILED, format!("解析私钥内容失败: {e}"))
                    .with_action("确认粘贴的是完整私钥（含 BEGIN/END 行）")
            })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| ssh_error(codes::AUTH_FAILED, e.to_string()))?
                .flatten();
            let result = handle
                .authenticate_publickey(
                    config.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| ssh_error(codes::AUTH_FAILED, format!("公钥认证失败: {e}")))?;
            if result.success() {
                Ok(())
            } else {
                Err(ssh_error(
                    codes::AUTH_FAILED,
                    "认证被拒绝：粘贴的私钥不被接受",
                ))
            }
        }
        AuthMethod::PrivateKey { path, passphrase } => {
            let key = load_secret_key(path, passphrase.as_deref()).map_err(|e| {
                ssh_error(codes::AUTH_FAILED, format!("读取私钥失败: {e}"))
                    .with_action("检查私钥路径、权限与口令")
            })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| ssh_error(codes::AUTH_FAILED, e.to_string()))?
                .flatten();
            let result = handle
                .authenticate_publickey(
                    config.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| ssh_error(codes::AUTH_FAILED, format!("公钥认证失败: {e}")))?;
            if result.success() {
                Ok(())
            } else {
                Err(ssh_error(codes::AUTH_FAILED, "认证被拒绝：公钥不被接受"))
            }
        }
        AuthMethod::Agent => Err(ssh_error(
            codes::AUTH_UNSUPPORTED,
            "SSH Agent 认证尚未接入（M1 后续补）",
        )),
        AuthMethod::KeyboardInteractive => Err(ssh_error(
            codes::AUTH_UNSUPPORTED,
            "键盘交互（OTP/2FA）尚未接入（M1 后续补）",
        )),
    }
}

#[async_trait]
impl SshBackend for RusshBackend {
    async fn probe_host_key(&self, config: &ConnectConfig) -> Result<HostKeyInfo> {
        let (handle, info) = connect_raw(config, None).await?;
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        Ok(info)
    }

    async fn open_pty(
        &self,
        config: &ConnectConfig,
        size: PtySize,
        sink: SharedSink,
    ) -> Result<PtySession> {
        let expected = config.expected_host_key.clone().ok_or_else(|| {
            ssh_error(codes::HOST_KEY_UNKNOWN, "尚未确认主机指纹，拒绝建立会话")
                .with_action("先探测并确认主机指纹，再建立连接")
        })?;
        let (handle, info) = connect_raw(config, Some(expected)).await?;
        let mut handle = handle;
        authenticate(&mut handle, config).await?;

        let channel = tokio::time::timeout(config.timeout, handle.channel_open_session())
            .await
            .map_err(|_| ssh_error(codes::PTY_FAILED, "打开会话通道超时"))?
            .map_err(|e| ssh_error(codes::PTY_FAILED, format!("打开会话通道失败: {e}")))?;
        tokio::time::timeout(
            config.timeout,
            channel.request_pty(true, "xterm-256color", size.cols, size.rows, 0, 0, &[]),
        )
        .await
        .map_err(|_| ssh_error(codes::PTY_FAILED, "申请 PTY 超时"))?
        .map_err(|e| ssh_error(codes::PTY_FAILED, format!("申请 PTY 失败: {e}")))?;
        tokio::time::timeout(config.timeout, channel.request_shell(true))
            .await
            .map_err(|_| ssh_error(codes::PTY_FAILED, "启动远端 shell 超时"))?
            .map_err(|e| ssh_error(codes::PTY_FAILED, format!("启动远端 shell 失败: {e}")))?;

        let session_id = new_id("sess");
        let backlog = Arc::new(Mutex::new(Vec::new()));
        let attached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink: SharedSink = Arc::new(BufferedSink {
            inner: sink,
            backlog: backlog.clone(),
            attached: attached.clone(),
            limit: 256 * 1024,
        });
        let (tx, mut rx) = mpsc::channel::<PtyCommand>(64);
        let (mut reader, writer) = channel.split();
        let sid = session_id.clone();

        tokio::spawn(async move {
            let mut exit_code: Option<u32> = None;
            let mut got_data = false;
            let mut request_rejected = false;
            loop {
                tokio::select! {
                    command = rx.recv() => {
                        match command {
                            Some(PtyCommand::Data(data)) => {
                                if writer.data_bytes(data).await.is_err() {
                                    break;
                                }
                            }
                            Some(PtyCommand::Resize { cols, rows }) => {
                                if writer.window_change(cols, rows, 0, 0).await.is_err() {
                                    break;
                                }
                            }
                            Some(PtyCommand::Close) | None => {
                                let _ = writer.eof().await;
                                break;
                            }
                        }
                    }
                    message = reader.wait() => {
                        match message {
                            Some(ChannelMsg::Data { data }) => {
                                got_data = true;
                                sink.on_data(&sid, &data);
                            }
                            Some(ChannelMsg::ExtendedData { data, .. }) => {
                                got_data = true;
                                sink.on_data(&sid, &data);
                            }
                            Some(ChannelMsg::ExitStatus { exit_status }) => exit_code = Some(exit_status),
                            Some(ChannelMsg::Success) => {}
                            Some(ChannelMsg::Failure) => {
                                request_rejected = true;
                                sink.on_error(&sid, "远端拒绝了 PTY 或 shell 请求");
                            }
                            Some(ChannelMsg::Eof) | None => break,
                            Some(_) => {}
                        }
                    }
                }
            }
            tracing::info!(session_id = %sid, exit = ?exit_code, data = got_data, "pty closed");
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            if exit_code.is_none() && !got_data && !request_rejected {
                sink.on_error(
                    &sid,
                    "远端在返回任何输出前关闭了会话：可能是登录 shell 启动失败、账户受限或服务器策略终止",
                );
            }
            sink.on_closed(&sid, exit_code);
        });

        tracing::info!(session_id = %session_id, host = %config.host, "pty opened");
        Ok(PtySession {
            id: session_id,
            host_key: info,
            commands: tx,
            backlog,
            attached,
        })
    }

    async fn exec(
        &self,
        config: &ConnectConfig,
        command: &str,
        output_limit_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<ExecResult> {
        let expected = config
            .expected_host_key
            .clone()
            .ok_or_else(|| ssh_error(codes::HOST_KEY_UNKNOWN, "尚未确认主机指纹，拒绝执行命令"))?;
        let (handle, _info) = connect_raw(config, Some(expected)).await?;
        let mut handle = handle;
        authenticate(&mut handle, config).await?;

        let mut channel = tokio::time::timeout(config.timeout, handle.channel_open_session())
            .await
            .map_err(|_| ssh_error(codes::EXEC_FAILED, "打开执行通道超时"))?
            .map_err(|e| ssh_error(codes::EXEC_FAILED, format!("打开执行通道失败: {e}")))?;
        tokio::time::timeout(
            config.timeout,
            channel.exec(true, command.as_bytes().to_vec()),
        )
        .await
        .map_err(|_| ssh_error(codes::EXEC_FAILED, "下发命令超时"))?
        .map_err(|e| ssh_error(codes::EXEC_FAILED, format!("下发命令失败: {e}")))?;

        let started = Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;
        let mut truncated = false;
        let mut saw_eof = false;

        let collect = async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        push_limited(&mut stdout, &data, output_limit_bytes, &mut truncated);
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        push_limited(&mut stderr, &data, output_limit_bytes, &mut truncated);
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status);
                        if saw_eof {
                            break;
                        }
                    }
                    ChannelMsg::Eof => {
                        saw_eof = true;
                        // 某些服务端把 exit-status 放在 EOF 之后；不要立刻
                        // 退出，否则会把成功命令误判为 exit_code=None。
                        if exit_code.is_some() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        };

        let timed_out = tokio::time::timeout(timeout, collect).await.is_err();
        if timed_out {
            let _ = channel.close().await;
        }
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;

        Ok(ExecResult {
            exit_code,
            stdout,
            stderr,
            duration_ms: started.elapsed().as_millis() as u64,
            timed_out,
            truncated,
        })
    }
}

fn push_limited(target: &mut Vec<u8>, data: &[u8], limit: usize, truncated: &mut bool) {
    if target.len() >= limit {
        *truncated = true;
        return;
    }
    let remaining = limit - target.len();
    if data.len() > remaining {
        target.extend_from_slice(&data[..remaining]);
        *truncated = true;
    } else {
        target.extend_from_slice(data);
    }
}

pub fn map_backend_error(error: AppError) -> AppError {
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rejects_empty_host() {
        let cfg = ConnectConfig::new("", 22, "ops");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_port() {
        let cfg = ConnectConfig::new("10.0.0.1", 0, "ops");
        assert!(cfg.validate().is_err());
    }

    struct CountingSink;
    impl OutputSink for CountingSink {
        fn on_data(&self, _session_id: &str, _data: &[u8]) {}
        fn on_closed(&self, _session_id: &str, _exit_code: Option<u32>) {}
        fn on_error(&self, _session_id: &str, _message: &str) {}
    }

    #[test]
    fn backlog_buffers_only_while_detached() {
        let backlog = Arc::new(Mutex::new(Vec::new()));
        let attached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = BufferedSink {
            inner: Arc::new(CountingSink),
            backlog: backlog.clone(),
            attached: attached.clone(),
            limit: 1024,
        };

        sink.on_data("s", b"a"); // 未挂载：缓冲
        attached.store(true, std::sync::atomic::Ordering::SeqCst);
        sink.on_data("s", b"b"); // 已挂载：不缓冲
        attached.store(false, std::sync::atomic::Ordering::SeqCst);
        sink.on_data("s", b"c"); // 又切走：缓冲

        assert_eq!(backlog.lock().unwrap().as_slice(), b"ac");
    }

    #[test]
    fn push_limited_truncates() {
        let mut buf = Vec::new();
        let mut truncated = false;
        push_limited(&mut buf, b"abcdef", 4, &mut truncated);
        assert_eq!(buf, b"abcd");
        assert!(truncated);
        push_limited(&mut buf, b"zzz", 4, &mut truncated);
        assert_eq!(buf, b"abcd");
    }

    #[tokio::test]
    async fn probe_to_closed_port_fails_fast() {
        let mut cfg = ConnectConfig::new("127.0.0.1", 1, "ops");
        cfg.timeout = Duration::from_millis(800);
        let err = RusshBackend::new().probe_host_key(&cfg).await.unwrap_err();
        assert!(
            err.code == codes::CONNECT_FAILED || err.code == codes::CONNECT_TIMEOUT,
            "unexpected: {err:?}"
        );
    }
}
