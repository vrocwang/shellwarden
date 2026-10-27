use chrono::Utc;

use serde::Serialize;
use serde_json::json;
use tauri::State;

use crate::config::{DEFAULT_BASE_URL, DEFAULT_MODEL};
use shellwarden_core::audit::{AuditChain, AuditEvent};
use shellwarden_core::digest::{digest_of, sha256_hex};
use shellwarden_core::error::Result;
use shellwarden_core::APP_VERSION;
use shellwarden_store::{
    task_elapsed_secs, Host, NewHost, NewTask, NewTaskBatch, NewTaskStep, TaskBatchRow,
    TaskPruneReport, TaskRow, TaskStepEdit, TaskStepRow, TaskWithSteps, TASK_TIMEOUT_SECS,
};

use crate::state::AppState;

#[derive(Serialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub db_schema: i64,
    pub host_count: i64,
    pub config_path: String,
    pub data_dir: String,
    pub shortcut_copy: String,
    pub shortcut_paste: String,
}

#[tauri::command]
pub fn open_config_dir(state: State<'_, AppState>) -> Result<()> {
    let dir = state
        .config_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut command = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("explorer")
    } else {
        std::process::Command::new("xdg-open")
    };
    command.arg(&dir).spawn().map_err(|error| {
        shellwarden_core::AppError::new(
            "config.open_failed",
            format!("打开配置目录 {} 失败: {error}", dir.display()),
        )
    })?;
    Ok(())
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> Result<AppInfo> {
    reload_config(&state)?;
    let (shortcut_copy, shortcut_paste) = {
        let config = state
            .config
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?;
        (config.shortcut_copy(), config.shortcut_paste())
    };
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    let hosts = db.list_hosts()?;
    Ok(AppInfo {
        name: "ShellWarden".into(),
        version: APP_VERSION.into(),
        db_schema: db.schema_version()?,
        host_count: hosts.len() as i64,
        config_path: state.config_path.display().to_string(),
        data_dir: state.data_dir.display().to_string(),
        shortcut_copy,
        shortcut_paste,
    })
}

#[tauri::command]
pub fn save_shortcuts(copy: String, paste: String, state: State<'_, AppState>) -> Result<()> {
    let copy = copy.trim().to_string();
    let paste = paste.trim().to_string();
    if copy.is_empty() || paste.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "config.shortcut_empty",
            "复制/粘贴快捷键不能为空",
        ));
    }
    let normalized = |value: &str| {
        value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    if normalized(&copy) == normalized(&paste) {
        return Err(shellwarden_core::AppError::new(
            "config.shortcut_duplicate",
            "复制和粘贴不能使用同一个快捷键",
        ));
    }
    if normalized(&copy) == "ctrl+c" || normalized(&paste) == "ctrl+c" {
        return Err(shellwarden_core::AppError::new(
            "config.shortcut_reserved",
            "Ctrl+C 保留为终端中断，不能分配给复制/粘贴",
        ));
    }
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?;
        config.shortcuts.copy = Some(copy);
        config.shortcuts.paste = Some(paste);
    }
    save_config(&state)?;
    Ok(())
}

#[tauri::command]
pub fn list_hosts(state: State<'_, AppState>) -> Result<Vec<Host>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.list_hosts()
}

#[tauri::command]
pub fn create_host(input: NewHost, state: State<'_, AppState>) -> Result<Host> {
    let host = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.create_host(input)?
    };
    append_audit_links(
        &state,
        "host.created",
        serde_json::json!({
            "host_id": host.id,
            "hostname": host.hostname,
            "port": host.port,
            "user": host.default_username,
        }),
        &AuditLinks {
            host_id: Some(host.id.clone()),
            ..Default::default()
        },
    )?;
    Ok(host)
}

#[tauri::command]
pub async fn delete_host(id: String, state: State<'_, AppState>) -> Result<bool> {
    let host = load_host(&state, &id)?;
    let removed = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.delete_host(&id)?
    };
    if !removed {
        return Ok(false);
    }
    // 删除主机也要忘掉已知指纹与探测缓存，避免重新添加同名主机时继承旧信任。
    let _ = state
        .ssh
        .known_hosts
        .lock()
        .await
        .forget(&host.hostname, host.port);
    state.ssh.probes.lock().await.remove(&id);
    let prefix = format!("{}@{}:", host.hostname, host.port);
    state
        .ssh
        .command_cache
        .lock()
        .await
        .retain(|key, _| !key.starts_with(&prefix));
    // DB 删除后，IPC 层也要把仍然活着的 PTY 与内存连接配置收掉；
    // 否则已删除主机还能继续 exec，密码/私钥也仍留在内存里。
    let session_ids: Vec<String> = {
        let configs = state.ssh.configs.lock().await;
        configs
            .iter()
            .filter(|(_, config)| config.host == host.hostname && config.port == host.port)
            .map(|(session_id, _)| session_id.clone())
            .collect()
    };
    {
        let mut configs = state.ssh.configs.lock().await;
        for session_id in &session_ids {
            configs.remove(session_id);
        }
    }
    let sessions_to_close = {
        let mut sessions = state.ssh.sessions.lock().await;
        session_ids
            .iter()
            .filter_map(|session_id| sessions.remove(session_id))
            .collect::<Vec<_>>()
    };
    for session in sessions_to_close {
        // 关闭通道是尽力而为；不能让一个卡住的 PTY 拖住删除。
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.close()).await;
    }
    append_audit_links(
        &state,
        "host.deleted",
        serde_json::json!({
            "host_id": host.id,
            "hostname": host.hostname,
            "port": host.port,
        }),
        &AuditLinks {
            host_id: Some(host.id.clone()),
            ..Default::default()
        },
    )?;
    Ok(true)
}

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct SelfCheck {
    pub passed: bool,
    pub checks: Vec<Check>,
}

/// 运行期自检：不需要 SSH，检查摘要稳定性与审计链完整性。
#[tauri::command]
pub fn self_check(state: State<'_, AppState>) -> Result<SelfCheck> {
    let mut checks = Vec::new();

    let a = digest_of(&json!({ "b": 2, "a": 1 }))?;
    let b = digest_of(&json!({ "a": 1, "b": 2 }))?;
    let c = digest_of(&json!({ "a": 1, "b": 3 }))?;
    checks.push(Check {
        name: "canonical digest 稳定".into(),
        passed: a == b && a != c,
        detail: format!("键序无关={}, 值变更敏感={}", a == b, a != c),
    });

    let mut chain = AuditChain::new(100);
    chain.append("check.a", "self-check", json!({"i": 1}), Utc::now())?;
    chain.append("check.b", "self-check", json!({"i": 2}), Utc::now())?;
    let clean = chain.verify();
    let detected = chain.events().first().is_some_and(|event| {
        let mut forged = AuditChain::new(100);
        let _ = forged.append("check.a", "self-check", json!({"i": 999}), Utc::now());
        forged.events()[0].event_hash != event.event_hash
    });
    checks.push(Check {
        name: "审计链可检测篡改".into(),
        passed: clean.valid && detected,
        detail: format!("clean={}, tamper_detected={}", clean.valid, detected),
    });

    let report = state
        .audit
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "审计链锁被污染"))?
        .verify();
    checks.push(Check {
        name: "持久化审计链完整".into(),
        passed: report.valid,
        detail: format!(
            "checked={}, broken_at={:?}, reason={:?}",
            report.checked, report.broken_at, report.reason
        ),
    });

    let passed = checks.iter().all(|c| c.passed);
    Ok(SelfCheck { passed, checks })
}

// ---- SSH：探测、信任、PTY 会话 -------------------------------------------

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager};

use shellwarden_ssh::{
    codes as ssh_codes, AuthMethod, ConnectConfig, HostKeyInfo, OutputSink, PtySize, SharedSink,
    TrustState,
};

struct EventSink {
    app: AppHandle,
}

impl OutputSink for EventSink {
    fn on_data(&self, session_id: &str, data: &[u8]) {
        let _ = self.app.emit(
            "session:data",
            serde_json::json!({
                "session_id": session_id,
                "encoding": "base64",
                "data": BASE64.encode(data),
            }),
        );
    }

    fn on_closed(&self, session_id: &str, exit_code: Option<u32>) {
        // 远端断开也要落审计；用户主动关闭时 end_session 已先写入，这里不会重复。
        if let Some(state) = self.app.try_state::<AppState>() {
            let ended = chrono::Utc::now().to_rfc3339();
            let updated = state
                .db
                .lock()
                .map(|db| {
                    db.end_session(session_id, "remote_closed", &ended)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if updated {
                let _ = append_audit_links(
                    &state,
                    "session.closed",
                    serde_json::json!({
                        "session_id": session_id,
                        "exit_code": exit_code,
                        "reason": "remote_closed",
                    }),
                    &AuditLinks {
                        session_id: Some(session_id.to_string()),
                        ..Default::default()
                    },
                );
            }
        }
        let _ = self.app.emit(
            "session:closed",
            serde_json::json!({ "session_id": session_id, "exit_code": exit_code }),
        );
        // 远端断开时清理内存中的会话与连接配置（手动关闭时已被移除）。
        let app = self.app.clone();
        let sid = session_id.to_string();
        tauri::async_runtime::spawn(async move {
            if let Some(state) = app.try_state::<AppState>() {
                state.ssh.sessions.lock().await.remove(&sid);
                state.ssh.configs.lock().await.remove(&sid);
            }
        });
    }

    fn on_error(&self, session_id: &str, message: &str) {
        let _ = self.app.emit(
            "session:error",
            serde_json::json!({ "session_id": session_id, "message": message }),
        );
    }
}

#[derive(Serialize)]
pub struct ProbeResult {
    pub probe_id: String,
    pub host_key: HostKeyInfo,
    pub trust: TrustState,
}

fn load_host(state: &AppState, host_id: &str) -> Result<Host> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.get_host(host_id)?
        .ok_or_else(|| shellwarden_core::AppError::new("host.not_found", "主机不存在"))
}

#[tauri::command]
pub async fn probe_host(host_id: String, state: State<'_, AppState>) -> Result<ProbeResult> {
    let host = load_host(&state, &host_id)?;
    let mut config = ConnectConfig::new(
        host.hostname.clone(),
        host.port,
        host.default_username.clone(),
    );
    config.auth = AuthMethod::Agent;
    config.expected_host_key = None;

    let host_key = state.ssh.backend.probe_host_key(&config).await?;
    let store = state.ssh.known_hosts.lock().await;
    let trust = store.verify(&host.hostname, host.port, &host_key);
    drop(store);
    let probe_id = new_id("probe");
    state.ssh.probes.lock().await.insert(
        host.id.clone(),
        crate::state::ProbeRecord {
            probe_id: probe_id.clone(),
            hostname: host.hostname.clone(),
            port: host.port,
            info: host_key.clone(),
        },
    );
    Ok(ProbeResult {
        probe_id,
        host_key,
        trust,
    })
}

/// 用户确认指纹后写入信任。信任值只接受服务端最近一次 probe 的结果，
/// 不接受前端传入的指纹（防止 WebView 被注入后改写信任目标）。
#[tauri::command]
pub async fn trust_host(
    host_id: String,
    probe_id: String,
    state: State<'_, AppState>,
) -> Result<()> {
    let host = load_host(&state, &host_id)?;
    let record = state
        .ssh
        .probes
        .lock()
        .await
        .get(&host_id)
        .cloned()
        .ok_or_else(|| {
            shellwarden_core::AppError::new(
                "ssh.host_key.probe_required",
                "信任前必须先由服务端探测主机指纹",
            )
            .with_action("点击重新探测指纹，再确认")
        })?;
    if record.probe_id != probe_id {
        return Err(shellwarden_core::AppError::new(
            "ssh.host_key.probe_stale",
            "确认的指纹与当前探测结果不是同一次；请重新探测后再确认",
        )
        .with_action("重新探测指纹后再确认"));
    }
    if record.hostname != host.hostname || record.port != host.port {
        return Err(shellwarden_core::AppError::new(
            "ssh.host_key.probe_stale",
            "主机地址或端口已变化，旧的探测结果不能用于信任",
        )
        .with_action("重新探测指纹后再确认"));
    }
    let info = record.info;
    {
        let mut store = state.ssh.known_hosts.lock().await;
        store
            .trust(&host.hostname, host.port, &info, chrono::Utc::now())
            .map_err(|e| shellwarden_core::AppError::new("ssh.known_hosts.write_failed", e))?;
    }
    let db_error = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.upsert_host_key(&host.id, &info.algorithm, &info.fingerprint)
            .err()
    };
    if let Some(error) = db_error {
        // 回滚刚刚写入的 known_hosts，避免 DB 与文件状态分叉。
        let _ = state
            .ssh
            .known_hosts
            .lock()
            .await
            .forget(&host.hostname, host.port);
        return Err(error);
    }
    append_audit_links(
        &state,
        "host_key.trusted",
        serde_json::json!({
            "host_id": host.id,
            "hostname": host.hostname,
            "port": host.port,
            "algorithm": info.algorithm,
            "fingerprint": info.fingerprint,
        }),
        &AuditLinks {
            host_id: Some(host.id.clone()),
            ..Default::default()
        },
    )?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct OpenSessionInput {
    pub host_id: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub remember_password: bool,
    #[serde(default)]
    pub remember_key: bool,
    #[serde(default)]
    pub cols: Option<u32>,
    #[serde(default)]
    pub rows: Option<u32>,
}

#[derive(Serialize)]
pub struct OpenSessionResult {
    pub session_id: String,
    pub host_key: HostKeyInfo,
}

#[tauri::command]
pub async fn open_session(
    input: OpenSessionInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<OpenSessionResult> {
    let host = load_host(&state, &input.host_id)?;
    let username = input
        .username
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| host.default_username.clone());
    if username.trim().is_empty() {
        return Err(shellwarden_core::AppError::new(
            "ssh.auth.missing_username",
            "缺少登录用户名",
        ));
    }

    let password_to_save = input.password.clone().filter(|value| !value.is_empty());
    let key_to_save = input
        .key_pem
        .clone()
        .filter(|value| !value.trim().is_empty());
    let key_path_to_save = input
        .key_path
        .clone()
        .filter(|value| !value.trim().is_empty());
    let passphrase_to_save = input.passphrase.clone();
    let auth = resolve_auth(
        &state,
        &host.id,
        input.password,
        input.key_pem,
        input.key_path,
        input.passphrase,
        false,
    )?;

    let expected = {
        let store = state.ssh.known_hosts.lock().await;
        store.get(&host.hostname, host.port).ok_or_else(|| {
            shellwarden_core::AppError::new(
                ssh_codes::HOST_KEY_UNKNOWN,
                format!("尚未信任主机 {}:{} 的指纹", host.hostname, host.port),
            )
            .with_action("先探测主机指纹并确认")
        })?
    };

    let mut config = ConnectConfig::new(host.hostname.clone(), host.port, username.clone());
    config.auth = auth;
    config.expected_host_key = Some(expected);

    let size = PtySize {
        cols: input.cols.unwrap_or(120).clamp(20, 500),
        rows: input.rows.unwrap_or(32).clamp(5, 300),
    };
    let sink: SharedSink = std::sync::Arc::new(EventSink { app });

    let session = match state.ssh.backend.open_pty(&config, size, sink).await {
        Ok(session) => session,
        Err(error) => {
            // 认证/密钥/PTY 失败都留痕，便于事后排查「为什么连不上」。
            let _ = append_audit_links(
                &state,
                "session.failed",
                serde_json::json!({
                    "host_id": host.id,
                    "code": error.code,
                    "message": error.message,
                    "user": username,
                }),
                &AuditLinks {
                    host_id: Some(host.id.clone()),
                    ..Default::default()
                },
            );
            return Err(error);
        }
    };
    let session_id = session.id.clone();
    let host_key = session.host_key.clone();
    let started = chrono::Utc::now().to_rfc3339();
    let inserted = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.insert_session(&session_id, &host.id, None, "russh", &started)
    };
    if let Err(error) = inserted {
        let _ = session.close().await;
        return Err(error);
    }
    if let Err(error) = append_audit_links(
        &state,
        "session.opened",
        serde_json::json!({
            "session_id": session_id,
            "host_id": host.id,
            "user": username,
            "fingerprint": host_key.fingerprint,
        }),
        &AuditLinks {
            host_id: Some(host.id.clone()),
            session_id: Some(session_id.clone()),
            ..Default::default()
        },
    ) {
        let _ = session.close().await;
        if let Ok(db) = state.db.lock() {
            let ended = chrono::Utc::now().to_rfc3339();
            let _ = db.end_session(&session_id, "audit_failed", &ended);
        }
        return Err(error);
    }
    // 只在认证与会话建立成功后才保存密码。此前 resolve_auth 提前落库，
    // 一个密码 typo 会覆盖原本可用的凭据。
    if input.remember_password {
        if let Some(password) = password_to_save.as_deref() {
            if let Err(error) = save_password(&state, &host.id, password) {
                tracing::warn!(error = %error, "failed to persist password after successful auth");
            }
        }
    }
    if input.remember_key {
        if let Some(pem) = key_to_save.as_deref() {
            if let Err(error) = save_private_key(&state, &host.id, pem, None) {
                tracing::warn!(error = %error, "failed to persist private key after successful auth");
            } else if let Err(error) =
                save_key_auth(&state, &host.id, "pem", None, passphrase_to_save.as_deref())
            {
                tracing::warn!(error = %error, "failed to persist private key auth after successful auth");
            }
        } else if let Some(path) = key_path_to_save.as_deref() {
            if let Err(error) = save_key_auth(
                &state,
                &host.id,
                "file",
                Some(path),
                passphrase_to_save.as_deref(),
            ) {
                tracing::warn!(error = %error, "failed to persist private key path after successful auth");
            }
        }
    }
    state
        .ssh
        .configs
        .lock()
        .await
        .insert(session_id.clone(), config.clone());
    state
        .ssh
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), session);
    Ok(OpenSessionResult {
        session_id,
        host_key,
    })
}

/// 用户显式对当前会话启用 bash/zsh OSC 133 集成。不会自动注入。
#[tauri::command]
pub async fn enable_shell_integration(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<()> {
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        if let Some(task) = db.active_task_for_session(&session_id)? {
            if matches!(task.status.as_str(), "running" | "paused_interactive") {
                return Err(shellwarden_core::AppError::new(
                    "task.step_running",
                    "任务步骤正在执行或等待人工接管；先处理完，再启用命令审计",
                ));
            }
        }
    }
    // 只克隆输入 channel：睡眠期间不持有 sessions 锁。
    let sender = {
        let sessions = state.ssh.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(|| {
            shellwarden_core::AppError::new(ssh_codes::SESSION_NOT_FOUND, "会话不存在或已结束")
        })?;
        session.commands.clone()
    };
    sender
        .send(shellwarden_ssh::PtyCommand::Data(
            crate::shell_integration::install_prelude(),
        ))
        .await
        .map_err(|_| shellwarden_core::AppError::new("ssh.session.write_failed", "会话已关闭"))?;
    // 等远端 shell 执行 stty -echo；否则 heredoc 仍会在关闭回显前被 PTY 回显。
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    if sender
        .send(shellwarden_ssh::PtyCommand::Data(
            crate::shell_integration::install_body(),
        ))
        .await
        .is_err()
    {
        // 尽力恢复回显；会话若已关闭则无副作用。
        let _ = sender
            .send(shellwarden_ssh::PtyCommand::Data(b"stty echo\r".to_vec()))
            .await;
        return Err(shellwarden_core::AppError::new(
            "ssh.session.write_failed",
            "会话已关闭，shell integration 未写入",
        ));
    }
    append_audit_links(
        &state,
        "terminal.integration_enabled",
        serde_json::json!({ "session_id": session_id }),
        &AuditLinks {
            session_id: Some(session_id),
            ..Default::default()
        },
    )?;
    Ok(())
}

#[tauri::command]
pub async fn write_session(
    session_id: String,
    data: String,
    state: State<'_, AppState>,
) -> Result<()> {
    if data.len() > 512 * 1024 {
        return Err(shellwarden_core::AppError::new(
            "ssh.input.too_large",
            "单次写入超过 512 KiB 上限",
        ));
    }
    let bytes = BASE64.decode(data.as_bytes()).map_err(|e| {
        shellwarden_core::AppError::new("ssh.input.invalid", format!("输入不是合法 base64: {e}"))
    })?;
    let sessions = state.ssh.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(|| {
        shellwarden_core::AppError::new(ssh_codes::SESSION_NOT_FOUND, "会话不存在或已结束")
    })?;
    session
        .write(bytes)
        .await
        .map_err(|e| shellwarden_core::AppError::new("ssh.session.write_failed", e))
}

#[tauri::command]
pub async fn resize_session(
    session_id: String,
    cols: u32,
    rows: u32,
    state: State<'_, AppState>,
) -> Result<()> {
    let cols = cols.clamp(20, 500);
    let rows = rows.clamp(5, 300);
    let sessions = state.ssh.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(|| {
        shellwarden_core::AppError::new(ssh_codes::SESSION_NOT_FOUND, "会话不存在或已结束")
    })?;
    session
        .resize(cols, rows)
        .await
        .map_err(|e| shellwarden_core::AppError::new("ssh.session.resize_failed", e))
}

/// UI 挂载后调用：取走会话建立到挂载之间的输出（初始提示符），避免空白终端。
#[tauri::command]
pub async fn session_attach(session_id: String, state: State<'_, AppState>) -> Result<String> {
    let sessions = state.ssh.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(|| {
        shellwarden_core::AppError::new(ssh_codes::SESSION_NOT_FOUND, "会话不存在或已结束")
    })?;
    Ok(BASE64.encode(session.attach()))
}

/// 终端卸载（切换主机）时调用：之后输出重新进入回放缓冲。
#[tauri::command]
pub async fn session_detach(session_id: String, state: State<'_, AppState>) -> Result<()> {
    let sessions = state.ssh.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        session.detach();
    }
    Ok(())
}

#[tauri::command]
pub async fn close_session(session_id: String, state: State<'_, AppState>) -> Result<()> {
    let mut sessions = state.ssh.sessions.lock().await;
    let session = sessions.remove(&session_id).ok_or_else(|| {
        shellwarden_core::AppError::new(ssh_codes::SESSION_NOT_FOUND, "会话不存在或已结束")
    })?;
    let close_result =
        tokio::time::timeout(std::time::Duration::from_secs(2), session.close()).await;
    match close_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "closing PTY failed");
        }
        Err(_) => {
            tracing::warn!("closing PTY timed out");
        }
    }
    drop(sessions);
    state.ssh.configs.lock().await.remove(&session_id);

    let ended = chrono::Utc::now().to_rfc3339();
    let updated = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.end_session(&session_id, "user_closed", &ended)?
    };
    if updated {
        append_audit_links(
            &state,
            "session.closed",
            serde_json::json!({
                "session_id": session_id,
                "reason": "user_closed",
            }),
            &AuditLinks {
                session_id: Some(session_id.clone()),
                ..Default::default()
            },
        )?;
    }
    Ok(())
}

/// 审计链已损坏时 fail-closed：破坏性/状态变更操作在写库前就应拒绝，
/// 避免出现“状态已变、审计没写”的不可追溯路径。
fn ensure_audit_ok(state: &AppState) -> Result<()> {
    if state.audit_ok.load(std::sync::atomic::Ordering::SeqCst) {
        Ok(())
    } else {
        Err(shellwarden_core::AppError::new(
            "audit.integrity",
            "审计链完整性校验失败，已停止写入；请先修复或导出审计数据",
        ))
    }
}

/// 审计写入：链与数据库必须同时成功；数据库失败时回滚内存链，避免哈希链与落库不一致。
fn append_audit(state: &AppState, event_type: &str, payload: serde_json::Value) -> Result<u64> {
    append_audit_links(state, event_type, payload, &AuditLinks::default())
}

#[derive(Default, Clone)]
struct AuditLinks {
    host_id: Option<String>,
    session_id: Option<String>,
    task_id: Option<String>,
    step_id: Option<String>,
    /// 事件产生者；默认 local-user。
    actor: Option<String>,
}

/// 把关联列镜像进 payload，让哈希链覆盖“这条事件属于哪个任务/会话/审批”。
/// 列仍然保留用于查询；payload 里的 `_links` 是哈希覆盖的权威副本。
fn payload_with_links(mut payload: serde_json::Value, links: &AuditLinks) -> serde_json::Value {
    if let Some(map) = payload.as_object_mut() {
        map.insert(
            "_links".into(),
            serde_json::json!({
                "host_id": &links.host_id,
                "session_id": &links.session_id,
                "task_id": &links.task_id,
                "step_id": &links.step_id,
            }),
        );
    }
    payload
}

/// 事件产生者的默认归属；显式的 `AuditLinks.actor` 优先。
/// 之前所有事件都写 diagnosis-engine，导致无法从 actor 区分用户动作与执行器。
fn actor_for(event_type: &str) -> &'static str {
    if event_type.starts_with("host.") || event_type.starts_with("ai.") {
        "local-user"
    } else if event_type.starts_with("session.") || event_type.starts_with("terminal.") {
        "session-manager"
    } else if event_type.starts_with("probe.") {
        "probe-engine"
    } else if event_type.starts_with("model.") {
        "model-adapter"
    } else {
        "local-user"
    }
}

fn append_audit_with_persist<F>(
    state: &AppState,
    event_type: &str,
    payload: serde_json::Value,
    links: &AuditLinks,
    persist: F,
) -> Result<u64>
where
    F: FnOnce(&shellwarden_store::Db, &AuditEvent) -> Result<()>,
{
    if !state.audit_ok.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(shellwarden_core::AppError::new(
            "audit.integrity",
            "审计链完整性校验失败，已停止写入；请先修复或导出审计数据",
        ));
    }

    // 持有审计链锁跨越落库：失败时回滚的一定是本线程刚追加的事件，
    // 不会误删并发线程已成功落库的事件（v2 审查 P1 并发回滚竞态）。
    let mut chain = state
        .audit
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "审计链锁被污染"))?;
    let payload = payload_with_links(payload, links);
    let event = chain
        .append(
            event_type,
            links
                .actor
                .as_deref()
                .unwrap_or_else(|| actor_for(event_type)),
            payload,
            chrono::Utc::now(),
        )?
        .clone();

    let persisted = match state.db.lock() {
        Ok(db) => persist(&db, &event),
        Err(_) => Err(shellwarden_core::AppError::new(
            "app.lock",
            "数据库锁被污染",
        )),
    };
    match persisted {
        Ok(()) => Ok(event.seq),
        Err(error) => {
            chain.rollback_last();
            Err(shellwarden_core::AppError::new(
                "audit.unavailable",
                format!("审计写入失败，操作已中止: {}", error.message),
            ))
        }
    }
}

fn append_audit_links(
    state: &AppState,
    event_type: &str,
    payload: serde_json::Value,
    links: &AuditLinks,
) -> Result<u64> {
    append_audit_with_persist(state, event_type, payload, links, |db, event| {
        db.insert_audit_event_linked(
            event,
            links.host_id.as_deref(),
            links.session_id.as_deref(),
            links.task_id.as_deref(),
            links.step_id.as_deref(),
        )
    })
}

#[derive(Debug, Deserialize)]
pub struct TerminalCommandInput {
    pub session_id: String,
    pub command: String,
    pub exit_code: Option<i32>,
    /// 前端在 OSC 133 C 收到的本地时间（RFC3339）。
    pub started_at: String,
}

#[tauri::command]
pub async fn record_terminal_command(
    input: TerminalCommandInput,
    state: State<'_, AppState>,
) -> Result<()> {
    record_terminal_command_inner(input, &state).await
}

async fn record_terminal_command_inner(
    input: TerminalCommandInput,
    state: &AppState,
) -> Result<()> {
    let command = redact_request(input.command.trim());
    if command.is_empty() {
        return Ok(());
    }
    let started = chrono::DateTime::parse_from_rfc3339(&input.started_at)
        .map_err(|error| {
            shellwarden_core::AppError::new(
                "terminal.invalid_timestamp",
                format!("命令开始时间不是合法 RFC3339: {error}"),
            )
        })?
        .with_timezone(&Utc);
    let finished = Utc::now();
    let duration_ms = (finished - started).num_milliseconds().clamp(0, 86_400_000);
    let host_id = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.session_host_id(&input.session_id)?.ok_or_else(|| {
            shellwarden_core::AppError::new("session.not_found", "会话不存在或已结束")
        })?
    };
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.insert_terminal_command(
            &input.session_id,
            Some(&host_id),
            &command,
            input.exit_code.map(i64::from),
            &started.to_rfc3339(),
            &finished.to_rfc3339(),
            duration_ms,
        )?;
    }
    append_audit_links(
        state,
        "terminal.command",
        serde_json::json!({
            "session_id": input.session_id,
            "command_redacted": command,
            "exit_code": input.exit_code,
            "duration_ms": duration_ms,
        }),
        &AuditLinks {
            host_id: Some(host_id),
            session_id: Some(input.session_id),
            ..Default::default()
        },
    )?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AuditAiCommandInput {
    pub session_id: String,
    pub command: String,
    pub risk: String,
}

/// 通用命令模式在写入 PTY 前落审计；失败则调用方不得执行。
#[tauri::command]
pub async fn audit_ai_command(
    input: AuditAiCommandInput,
    state: State<'_, AppState>,
) -> Result<()> {
    let command = redact_request(input.command.trim());
    if command.is_empty() {
        return Err(shellwarden_core::AppError::new("command.empty", "命令为空"));
    }
    let host_id = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.session_host_id(&input.session_id)?
    };
    append_audit_links(
        &state,
        "ai.command_confirmed",
        serde_json::json!({
            "session_id": input.session_id,
            "command_redacted": command,
            "risk": input.risk,
        }),
        &AuditLinks {
            host_id,
            session_id: Some(input.session_id),
            ..Default::default()
        },
    )?;
    Ok(())
}

#[tauri::command]
pub fn terminal_commands(
    session_id: String,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<shellwarden_store::TerminalCommandRow>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.terminal_commands_for_session(&session_id, limit.unwrap_or(200).clamp(1, 1000))
}

/// 会话级审计时间线（连接、探测、授权等与任务无关的事件）。
#[tauri::command]
pub fn session_audit(
    session_id: String,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<shellwarden_core::audit::AuditEvent>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.audit_events_for_session(&session_id, limit.unwrap_or(200).clamp(1, 1000))
}

/// 落库前对请求做最小脱敏：常见 `key=value` 形态与超长文本。
/// 自然语言里的“我的密码是…”无法可靠识别，仍需用户避免在请求中写秘密（§15.2）。
fn sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "api_key",
        "apikey",
        "credential",
        "pwd",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || [
            "密码",
            "口令",
            "パスワード",
            "비밀번호",
            "пароль",
            "contraseña",
            "mot de passe",
            "كلمة المرور",
            "पासवर्ड",
            "senha",
            "passwort",
            "wachtwoord",
            "şifre",
            "رمز",
        ]
        .iter()
        .any(|needle| key.contains(needle))
}

/// 把一行文本里的凭据替换成 `***`，返回（脱敏文本, 是否发现凭据）。
///
/// 覆盖 `key=value`、`key: value`、`--password value`、`Bearer token`、
/// `-----BEGIN ... PRIVATE KEY-----` 以及中/日/韩/俄等语言的键名。
fn mask_credentials(text: &str) -> (String, bool) {
    let mut output: Vec<String> = Vec::new();
    let mut mask_next = false;
    let mut found = false;
    let mut in_pem = false;
    let mut after_authorization = false;

    for token in text.split_whitespace() {
        if in_pem {
            output.push("***".into());
            found = true;
            if token.contains("-----END") {
                in_pem = false;
            }
            continue;
        }
        if mask_next {
            // `password = hunter2`：中间的分隔符保留，继续等真正的值。
            // `password = hunter2` / `my password is hunter2`：中间的分隔符
            // 或系动词保留，继续等真正的值。
            if matches!(
                token.to_ascii_lowercase().as_str(),
                "=" | ":" | "：" | "is" | "are" | "是" | "为"
            ) {
                output.push(token.to_string());
                continue;
            }
            output.push("***".into());
            mask_next = false;
            found = true;
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if lower == "authorization" || lower == "authorization:" {
            output.push(token.to_string());
            after_authorization = true;
            continue;
        }
        if after_authorization && matches!(lower.as_str(), "basic" | "digest" | "bearer") {
            output.push(token.to_string());
            mask_next = true;
            after_authorization = false;
            found = true;
            continue;
        }
        if lower == "bearer" {
            output.push(token.to_string());
            mask_next = true;
            found = true;
            continue;
        }
        if token.starts_with("-----BEGIN") {
            output.push("***".into());
            in_pem = true;
            found = true;
            continue;
        }
        if lower.starts_with("--password")
            || lower.starts_with("--passwd")
            || lower.starts_with("--passphrase")
            || lower.starts_with("--token")
            || lower.starts_with("--secret")
            || lower.starts_with("--api-key")
        {
            if let Some((key, value)) = token.split_once('=') {
                output.push(format!("{key}=***"));
                let _ = value;
            } else {
                output.push(token.to_string());
                mask_next = true;
            }
            found = true;
            continue;
        }
        if let Some((key, _value)) = token.split_once('=') {
            if sensitive_key(key) {
                output.push(format!("{key}=***"));
                found = true;
                continue;
            }
        }
        // URL 内嵌凭据：scheme://user:pass@host
        if token.contains("://") {
            if let Some(at) = token.find('@') {
                if let Some((scheme, userinfo)) = token[..at].split_once("://") {
                    if let Some((user, _password)) = userinfo.split_once(':') {
                        output.push(format!("{scheme}://{user}:***@{}", &token[at + 1..]));
                        found = true;
                        continue;
                    }
                }
            }
        }
        // 空格分隔的敏感词：`password hunter2`、`密码 hunter2`、
        // “我的密码是 hunter2”。只设 mask_next，真正遮蔽下一个词时才算 found，
        // 这样 “如何重置密码” 这类正常请求不会被误拒。
        if !token.contains('=')
            && !token.contains(':')
            && !token.contains('：')
            && sensitive_key(&lower)
        {
            output.push(token.to_string());
            mask_next = true;
            continue;
        }
        // key:value / key：value（避免把 URL 的 scheme 当成键）
        if let Some((key, value)) = token.split_once(':').or_else(|| token.split_once('：')) {
            if !key.contains("://") && sensitive_key(key) {
                if value.is_empty() {
                    // `密码：` 后面跟空格分隔的值。
                    output.push(token.to_string());
                    mask_next = true;
                } else {
                    output.push(format!("{key}=***"));
                    if matches!(
                        value.to_ascii_lowercase().as_str(),
                        "bearer" | "basic" | "token" | "digest"
                    ) {
                        mask_next = true;
                    }
                }
                found = true;
                continue;
            }
        }
        after_authorization = false;
        output.push(token.to_string());
    }

    (output.join(" "), found)
}

/// 空格分隔的秘密值：过短/纯英文单词（如 “expired”“reset”）不按凭据拒绝，
/// 避免把“my password is expired”这类正常运维请求误判。真正的口令通常
/// 含数字/符号，或足够长；无冒号的自定义提示仍由前端 prompt 启发式兜底。
fn looks_like_secret_value(token: &str) -> bool {
    let len = token.chars().count();
    let digits = token.chars().filter(|c| c.is_ascii_digit()).count();
    len >= 12 || (len >= 5 && digits >= 1)
}

/// 高置信度的凭据形态判定；与 `mask_credentials`（宽进、用于脱敏）分开，
/// 避免为了“不漏”而把正常请求也拒掉（PRD §19.4 不误伤）。
fn contains_credential_like(text: &str) -> bool {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut after_authorization = false;
    for (index, token) in tokens.iter().enumerate() {
        let lower = token.to_ascii_lowercase();
        if token.starts_with("-----BEGIN") {
            return true;
        }
        if lower.starts_with("--password")
            || lower.starts_with("--passwd")
            || lower.starts_with("--passphrase")
            || lower.starts_with("--token")
            || lower.starts_with("--secret")
            || lower.starts_with("--api-key")
        {
            return true;
        }
        if lower == "authorization" || lower == "authorization:" {
            after_authorization = true;
            continue;
        }
        if after_authorization && matches!(lower.as_str(), "bearer" | "basic" | "digest") {
            return true;
        }
        after_authorization = false;
        if let Some((key, _value)) = token.split_once('=') {
            if sensitive_key(key) {
                return true;
            }
        }
        if let Some((key, value)) = token.split_once(':').or_else(|| token.split_once('：')) {
            if !key.contains("://")
                && sensitive_key(key)
                && (!value.is_empty() || tokens.get(index + 1).is_some())
            {
                return true;
            }
        }
        if token.contains("://") {
            if let Some(at) = token.find('@') {
                if token[..at].split_once(':').is_some() {
                    return true;
                }
            }
        }
        if sensitive_key(&lower)
            && !token.contains('=')
            && !token.contains(':')
            && !token.contains('：')
        {
            let mut next = index + 1;
            if tokens
                .get(next)
                .map(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "is" | "are" | "是" | "为" | "=" | ":" | "："
                    )
                })
                .unwrap_or(false)
            {
                next += 1;
            }
            if tokens
                .get(next)
                .map(|value| looks_like_secret_value(value))
                .unwrap_or(false)
            {
                return true;
            }
        }
        if lower == "bearer" {
            return true;
        }
    }
    false
}

fn redact_request(text: &str) -> String {
    const MAX_CHARS: usize = 2000;
    let (masked, _) = mask_credentials(text);
    masked.chars().take(MAX_CHARS).collect()
}

fn record_audit(state: &AppState, event_type: &str, payload: serde_json::Value) -> Result<u64> {
    append_audit(state, event_type, payload)
}

struct SavedKeyAuth {
    mode: String,
    key_path: Option<String>,
    passphrase: Option<String>,
}

fn load_saved_key_auth(state: &AppState, host_id: &str) -> Option<SavedKeyAuth> {
    let row = {
        let db = state.db.lock().ok()?;
        db.load_key_auth(host_id).ok()??
    };
    let passphrase = match (row.passphrase_ciphertext, row.passphrase_nonce) {
        (Some(ct), Some(nonce)) => state.secrets.decrypt(&ct, &nonce).ok(),
        _ => None,
    };
    Some(SavedKeyAuth {
        mode: row.mode,
        key_path: row.key_path,
        passphrase,
    })
}

fn save_key_auth(
    state: &AppState,
    host_id: &str,
    mode: &str,
    key_path: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    let pass = match passphrase.filter(|value| !value.is_empty()) {
        Some(value) => {
            let (ct, nonce) = state.secrets.encrypt(value)?;
            Some((ct, nonce))
        }
        None => None,
    };
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.save_key_auth(
        host_id,
        mode,
        key_path,
        pass.as_ref()
            .map(|(ct, nonce)| (ct.as_slice(), nonce.as_slice())),
    )
}

fn resolve_auth(
    state: &AppState,
    host_id: &str,
    password: Option<String>,
    key_pem: Option<String>,
    key_path: Option<String>,
    passphrase: Option<String>,
    remember_password: bool,
) -> Result<AuthMethod> {
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        if remember_password {
            save_password(state, host_id, &password)?;
        }
        return Ok(AuthMethod::Password(password));
    }
    let saved_auth = load_saved_key_auth(state, host_id);
    if let Some(pem) = key_pem.filter(|p| !p.trim().is_empty()) {
        let saved_pass = saved_auth
            .as_ref()
            .filter(|auth| auth.mode == "pem")
            .and_then(|auth| auth.passphrase.clone());
        return Ok(AuthMethod::PrivateKeyPem {
            pem,
            passphrase: passphrase.or(saved_pass),
        });
    }
    if let Some(path) = key_path.filter(|p| !p.trim().is_empty()) {
        let saved_pass = saved_auth
            .as_ref()
            .filter(|auth| auth.mode == "file")
            .and_then(|auth| auth.passphrase.clone());
        return Ok(AuthMethod::PrivateKey {
            path: std::path::PathBuf::from(path),
            passphrase: passphrase.or(saved_pass),
        });
    }
    if let Some(auth) = saved_auth {
        if auth.mode == "file" {
            if let Some(path) = auth.key_path.filter(|path| !path.trim().is_empty()) {
                return Ok(AuthMethod::PrivateKey {
                    path: std::path::PathBuf::from(path),
                    passphrase: passphrase.or(auth.passphrase),
                });
            }
        }
        if auth.mode == "pem" {
            if let Some((pem, saved_passphrase)) = load_saved_private_key(state, host_id) {
                return Ok(AuthMethod::PrivateKeyPem {
                    pem,
                    passphrase: passphrase.or(auth.passphrase).or(saved_passphrase),
                });
            }
        }
    }
    if let Some((pem, saved_passphrase)) = load_saved_private_key(state, host_id) {
        return Ok(AuthMethod::PrivateKeyPem {
            pem,
            passphrase: passphrase.or(saved_passphrase),
        });
    }
    if let Some(saved) = load_saved_password(state, host_id) {
        return Ok(AuthMethod::Password(saved));
    }
    Ok(AuthMethod::Agent)
}

fn save_password(state: &AppState, host_id: &str, password: &str) -> Result<()> {
    let (ciphertext, nonce) = state.secrets.encrypt(password)?;
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.save_credential(host_id, &ciphertext, &nonce)
}

fn load_saved_password(state: &AppState, host_id: &str) -> Option<String> {
    let stored = {
        let db = state.db.lock().ok()?;
        db.load_credential(host_id).ok()??
    };
    state.secrets.decrypt(&stored.0, &stored.1).ok()
}

fn save_private_key(
    state: &AppState,
    host_id: &str,
    pem: &str,
    passphrase: Option<&str>,
) -> Result<()> {
    let (ciphertext, nonce) = state.secrets.encrypt(pem)?;
    let pass = match passphrase.filter(|p| !p.is_empty()) {
        Some(pass) => {
            let (ct, nonce) = state.secrets.encrypt(pass)?;
            Some((ct, nonce))
        }
        None => None,
    };
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.save_private_key(
        host_id,
        &ciphertext,
        &nonce,
        pass.as_ref()
            .map(|(ct, nonce)| (ct.as_slice(), nonce.as_slice())),
    )
}

fn load_saved_private_key(state: &AppState, host_id: &str) -> Option<(String, Option<String>)> {
    let stored = {
        let db = state.db.lock().ok()?;
        db.load_private_key(host_id).ok()??
    };
    let pem = state.secrets.decrypt(&stored.0, &stored.1).ok()?;
    let passphrase = match (stored.2, stored.3) {
        (Some(ct), Some(nonce)) => state.secrets.decrypt(&ct, &nonce).ok(),
        _ => None,
    };
    Some((pem, passphrase))
}

#[tauri::command]
pub fn host_private_key_status(host_id: String, state: State<'_, AppState>) -> bool {
    state
        .db
        .lock()
        .ok()
        .and_then(|db| db.load_private_key(&host_id).ok().flatten())
        .is_some()
}

#[derive(Serialize)]
pub struct HostKeyAuthStatus {
    pub mode: Option<String>,
    pub key_path: Option<String>,
    pub has_passphrase: bool,
    pub has_private_key: bool,
}

#[tauri::command]
pub fn host_key_auth_status(host_id: String, state: State<'_, AppState>) -> HostKeyAuthStatus {
    let row = state
        .db
        .lock()
        .ok()
        .and_then(|db| db.load_key_auth(&host_id).ok().flatten());
    let has_private_key = state
        .db
        .lock()
        .ok()
        .and_then(|db| db.load_private_key(&host_id).ok().flatten())
        .is_some();
    HostKeyAuthStatus {
        mode: row.as_ref().map(|row| row.mode.clone()),
        key_path: row.as_ref().and_then(|row| row.key_path.clone()),
        has_passphrase: row
            .as_ref()
            .is_some_and(|row| row.passphrase_ciphertext.is_some()),
        has_private_key,
    }
}

#[tauri::command]
pub fn save_host_key_file(
    host_id: String,
    key_path: String,
    passphrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<()> {
    let _ = load_host(&state, &host_id)?;
    let path = key_path.trim();
    if path.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "ssh.key.path_missing",
            "私钥文件路径不能为空",
        ));
    }
    save_key_auth(&state, &host_id, "file", Some(path), passphrase.as_deref())
}

#[tauri::command]
pub fn save_host_private_key(
    host_id: String,
    key_pem: String,
    passphrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<()> {
    let _ = load_host(&state, &host_id)?;
    if key_pem.trim().is_empty() {
        return Err(shellwarden_core::AppError::new(
            "ssh.key.pem_missing",
            "私钥内容不能为空",
        ));
    }
    save_private_key(&state, &host_id, &key_pem, None)?;
    save_key_auth(&state, &host_id, "pem", None, passphrase.as_deref())
}

#[tauri::command]
pub async fn delete_host_key_auth(host_id: String, state: State<'_, AppState>) -> Result<()> {
    let host = load_host(&state, &host_id).ok();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.delete_key_auth(&host_id)?;
        db.delete_private_key(&host_id)?;
    }
    if let Some(host) = host {
        let mut configs = state.ssh.configs.lock().await;
        configs.retain(|_, config| !(config.host == host.hostname && config.port == host.port));
    }
    Ok(())
}

#[tauri::command]
pub async fn delete_host_private_key(host_id: String, state: State<'_, AppState>) -> Result<()> {
    let host = load_host(&state, &host_id).ok();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.delete_private_key(&host_id)?;
    }
    if let Some(host) = host {
        let mut configs = state.ssh.configs.lock().await;
        configs.retain(|_, config| !(config.host == host.hostname && config.port == host.port));
    }
    Ok(())
}

#[tauri::command]
pub fn save_host_password(
    host_id: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<()> {
    let _ = load_host(&state, &host_id)?;
    save_password(&state, &host_id, &password)
}

#[tauri::command]
pub async fn delete_host_password(host_id: String, state: State<'_, AppState>) -> Result<()> {
    let host = load_host(&state, &host_id).ok();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.delete_credential(&host_id)?;
    }
    // 活跃会话的内存 ConnectConfig 里还留着旧密码；清掉对应配置，
    // 让 command_exists 等后续 exec 不再使用已被用户删除的凭据。
    if let Some(host) = host {
        let mut configs = state.ssh.configs.lock().await;
        configs.retain(|_, config| !(config.host == host.hostname && config.port == host.port));
    }
    Ok(())
}

#[tauri::command]
pub fn host_credentials_status(host_id: String, state: State<'_, AppState>) -> bool {
    load_saved_password(&state, &host_id).is_some()
}

#[tauri::command]
pub async fn host_trust(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<Option<HostKeyInfo>> {
    let host = load_host(&state, &host_id)?;
    let store = state.ssh.known_hosts.lock().await;
    Ok(store.get(&host.hostname, host.port))
}

// ---- 模型起草计划（M3） --------------------------------------------------

use shellwarden_model::{
    draft_command as draft_command_with_model, draft_task as draft_task_with_model,
    is_loopback_base_url, revise_task as revise_task_with_model, truncate_output_tail,
    validate_task_step_command, HttpTransport, ModelConfig, ReviseDecision, TaskStepDraft,
    TaskStepResult, MAX_OUTPUT_TAIL_CHARS, MAX_OUTPUT_TAIL_LINES, MAX_TASK_STEPS,
    MAX_TASK_STEP_BUDGET, REVISE_PROMPT_VERSION, TASK_PROMPT_VERSION,
};

#[derive(Debug, Deserialize)]
pub struct DraftCommandInput {
    pub host_id: String,
    pub request: String,
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Serialize)]
pub struct DraftCommandOption {
    pub command: String,
    pub explanation: String,
    pub risk: String,
    pub manual_only: bool,
}

#[derive(Serialize)]
pub struct DraftCommandResult {
    pub commands: Vec<DraftCommandOption>,
    pub model: String,
    pub prompt_version: String,
}

fn dangerous_ai_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let compact: String = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    [
        "rm -rf /",
        "rm -fr /",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "init 0",
        "chmod -r 777 /",
        "> /dev/sd",
        ":(){",
    ]
    .iter()
    .any(|pattern| compact.contains(pattern))
        || compact.contains("sudo ")
        || (compact.contains("curl") && compact.contains("| sh"))
        || (compact.contains("wget") && compact.contains("| sh"))
}

fn segment_risk(segment: &str) -> &'static str {
    let lower = segment.trim().to_ascii_lowercase();
    let read_only = [
        "date",
        "uptime",
        "df",
        "free",
        "ps ",
        "top -b",
        "cat ",
        "ls ",
        "pwd",
        "whoami",
        "uname",
        "systemctl status",
        "journalctl",
        "ss ",
        "netstat",
        "ip ",
        "head ",
        "tail ",
        "grep ",
    ];
    if read_only.iter().any(|pattern| lower.starts_with(pattern)) {
        return "R0";
    }
    let mutating = [
        "rm ",
        "mv ",
        "cp ",
        "chmod",
        "chown",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "systemctl reload",
        "service nginx restart",
        "service nginx stop",
        "service nginx start",
        "service nginx reload",
        "nginx -s",
        "kill ",
        "killall",
        "pkill",
        "truncate",
        "tee ",
        "sed -i",
        "apt ",
        "apt-get ",
        "yum ",
        "dnf ",
        "pip install",
        "npm install",
        "git reset",
        "git clean",
        "docker restart",
        "docker stop",
        "kubectl delete",
        "kubectl apply",
    ];
    if mutating.iter().any(|pattern| lower.contains(pattern)) || lower.contains('>') {
        "R2"
    } else {
        "R1"
    }
}

fn ai_command_risk(command: &str) -> &'static str {
    // 复合命令按段取最高风险：`date && rm -f x` 不能被当成 R0。
    // 用保守切分；引号内的 |/; 会被误切，但只会让风险偏高，不会放行变更。
    let normalized = command
        .replace("&&", "\n")
        .replace("||", "\n")
        .replace([';', '|'], "\n");
    let mut risk = "R0";
    for segment in normalized.split('\n') {
        let next = segment_risk(segment);
        if next == "R2" {
            return "R2";
        }
        if next == "R1" {
            risk = "R1";
        }
    }
    risk
}

/// 一次分类同时得到风险等级和是否需要手动输入，避免同一命令重复跑规则。
fn assess_command(command: &str) -> (&'static str, bool) {
    if dangerous_ai_command(command) {
        return ("R3", true);
    }
    let risk = ai_command_risk(command);
    (risk, risk == "R2")
}

/// 统一解析模型配置：空 api_key 表示使用已保存密钥；空 base_url/model 使用设置值。
/// 所有模型调用（单命令 / 任务计划 / 任务推进）共用这一入口。
fn resolve_model_config(
    state: &AppState,
    api_key: &str,
    base_url: &str,
    model: &str,
    timeout_secs: Option<u64>,
    max_tokens: Option<u32>,
) -> Result<ModelConfig> {
    let using_saved_key = api_key.trim().is_empty();
    let api_key = if using_saved_key {
        saved_api_key(state).ok_or_else(|| {
            shellwarden_core::AppError::new("model.config_invalid", "尚未配置 API Key")
                .with_action("在设置中填写并保存模型密钥")
        })?
    } else {
        api_key.to_string()
    };
    let base_url = if using_saved_key || base_url.trim().is_empty() {
        model_base_url(state)
    } else {
        base_url.to_string()
    };
    let model = if model.trim().is_empty() {
        model_name(state)
    } else {
        model.to_string()
    };
    Ok(ModelConfig {
        base_url,
        model,
        api_key,
        timeout: std::time::Duration::from_secs(timeout_secs.unwrap_or(30).clamp(5, 120)),
        max_tokens: max_tokens.unwrap_or(512).clamp(64, 4096),
        temperature: 0.0,
    })
}

/// 通用命令模式：模型只生成一条单行命令，服务端做危险模式拦截后交给用户确认。
#[tauri::command]
pub async fn draft_command(
    input: DraftCommandInput,
    state: State<'_, AppState>,
) -> Result<DraftCommandResult> {
    reload_config(&state)?;
    let host = load_host(&state, &input.host_id)?;
    let config = resolve_model_config(
        &state,
        &input.api_key,
        &input.base_url,
        &input.model,
        input.timeout_secs,
        input.max_tokens,
    )?;
    if input.request.trim().is_empty() {
        return Err(shellwarden_core::AppError::new(
            "model.empty_request",
            "请求不能为空",
        ));
    }
    if input.request.chars().count() > 2000 {
        return Err(shellwarden_core::AppError::new(
            "model.request_too_long",
            "请求超过 2000 字符，请拆分",
        ));
    }
    if contains_credential_like(&input.request) {
        return Err(shellwarden_core::AppError::new(
            "model.secret_input",
            "输入疑似包含凭据，已拒绝发送到模型",
        ));
    }
    let transport = HttpTransport::new();
    let draft =
        draft_command_with_model(&transport, &config, &host.name, input.request.trim()).await?;
    let commands = draft
        .candidates
        .into_iter()
        .map(|candidate| {
            let (risk, manual_only) = assess_command(&candidate.command);
            DraftCommandOption {
                command: candidate.command,
                explanation: candidate.explanation,
                risk: risk.to_string(),
                manual_only,
            }
        })
        .collect();
    Ok(DraftCommandResult {
        commands,
        model: draft.model,
        prompt_version: draft.prompt_version,
    })
}

// ---- 任务模式（阶段 1/2） ------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DraftTaskInput {
    pub host_id: String,
    pub request: String,
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Serialize)]
pub struct TaskStepOption {
    pub command: String,
    pub purpose: String,
    /// 服务端 `assess_command` 复核后的风险，不是模型自报值。
    pub risk: String,
    /// 模型自报的风险，仅用于对照显示。
    pub risk_hint: String,
    /// R2/R3 或需要交互：只显示命令，不提供自动执行按钮。
    pub manual_only: bool,
    pub interactive_hint: bool,
}

#[derive(Serialize)]
pub struct DraftTaskResult {
    pub title: String,
    pub summary: String,
    pub steps: Vec<TaskStepOption>,
    pub model: String,
    pub prompt_version: String,
    pub step_limit: usize,
}

#[derive(Debug, Deserialize)]
pub struct CreateTaskStepInput {
    pub command: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub risk_hint: String,
    #[serde(default)]
    pub interactive_hint: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateTaskInput {
    pub host_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub batch_id: Option<String>,
    pub goal: String,
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub step_limit: Option<i64>,
    pub steps: Vec<CreateTaskStepInput>,
}

#[derive(Debug, Deserialize)]
pub struct TaskStepFinishedInput {
    pub task_id: String,
    pub step_id: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub output_tail: String,
    /// sent / manual / skipped；缺省按 exit_code 推断 succeeded/failed/sent。
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TaskReviseInput {
    pub task_id: String,
    #[serde(default)]
    pub user_note: Option<String>,
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Serialize)]
pub struct TaskReviseResult {
    pub task: TaskWithSteps,
    pub decision: String,
    pub message: String,
}

fn normalize_task_goal(raw: &str) -> Result<&str> {
    let goal = raw.trim();
    if goal.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "model.empty_request",
            "任务目标不能为空",
        ));
    }
    if goal.chars().count() > 2000 {
        return Err(shellwarden_core::AppError::new(
            "model.request_too_long",
            "任务目标超过 2000 字符，请拆分",
        ));
    }
    if contains_credential_like(goal) {
        return Err(shellwarden_core::AppError::new(
            "model.secret_input",
            "任务目标疑似包含凭据，已拒绝发送到模型",
        ));
    }
    Ok(goal)
}

fn task_links(task: &TaskRow, step: Option<&TaskStepRow>) -> AuditLinks {
    AuditLinks {
        host_id: Some(task.host_id.clone()),
        session_id: task.session_id.clone(),
        task_id: Some(task.id.clone()),
        step_id: step.map(|step| step.id.clone()),
        actor: None,
    }
}

fn attach_step_audit(state: &AppState, task_id: &str, step_id: &str, audit_seq: u64) {
    if let Ok(db) = state.db.lock() {
        let _ = db.set_step_audit_seq(task_id, step_id, audit_seq as i64);
    }
}

fn load_task_record(state: &AppState, task_id: &str) -> Result<TaskWithSteps> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.get_task(task_id)?
        .ok_or_else(|| shellwarden_core::AppError::new("task.not_found", "任务不存在"))
}

/// R2/R3 或模型声明需要交互的步骤不允许自动执行（计划 §4.4 / §5.2）。
fn task_step_manual_only(step: &TaskStepRow) -> bool {
    matches!(step.risk.as_str(), "R2" | "R3") || step.interactive_hint
}

fn guard_task_timeout(state: &AppState, task: &TaskRow) -> Result<()> {
    let elapsed = task_elapsed_secs(&task.created_at);
    if elapsed <= TASK_TIMEOUT_SECS {
        return Ok(());
    }
    if let Ok(db) = state.db.lock() {
        let _ = db.fail_task(&task.id, "任务超过 10 分钟上限，已自动停止");
    }
    let _ = append_audit_links(
        state,
        "task.failed",
        serde_json::json!({
            "task_id": task.id,
            "reason": "timeout",
            "elapsed_secs": elapsed,
        }),
        &task_links(task, None),
    );
    Err(
        shellwarden_core::AppError::new("task.timeout", "任务超过 10 分钟上限，已自动停止")
            .with_action("重新创建任务，或直接在终端手动处理"),
    )
}

/// 输出尾部脱敏：逐行遮掉凭据，跨行 PEM 正文整段遮蔽，再按行/字符截断。
fn redact_output_tail(raw: &str) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }
    let mut lines = Vec::new();
    let mut in_pem = false;
    for line in raw.lines() {
        if in_pem {
            lines.push("***".to_string());
            if line.contains("-----END") {
                in_pem = false;
            }
            continue;
        }
        if line.contains("-----BEGIN") {
            in_pem = true;
            lines.push("***".to_string());
            continue;
        }
        // 只有真的发现凭据才替换整行，保留正常输出的空格/对齐。
        let (masked, found) = mask_credentials(line);
        lines.push(if found { masked } else { line.to_string() });
    }
    truncate_output_tail(
        &lines.join("\n"),
        MAX_OUTPUT_TAIL_LINES,
        MAX_OUTPUT_TAIL_CHARS,
    )
}

fn build_created_steps(steps: Vec<CreateTaskStepInput>, limit: usize) -> Result<Vec<NewTaskStep>> {
    if steps.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "task.empty_plan",
            "任务至少需要 1 个步骤",
        ));
    }
    if steps.len() > limit.min(MAX_TASK_STEPS) {
        return Err(shellwarden_core::AppError::new(
            "task.step_limit",
            format!(
                "计划 {} 步，超过上限 {}",
                steps.len(),
                limit.min(MAX_TASK_STEPS)
            ),
        ));
    }
    let mut planned = Vec::with_capacity(steps.len());
    for (index, step) in steps.into_iter().enumerate() {
        let command = validate_task_step_command(&step.command)?;
        if contains_credential_like(&command) {
            return Err(shellwarden_core::AppError::new(
                "task.secret_step",
                "任务步骤疑似包含凭据，已拒绝",
            )
            .with_action("把秘密留在终端里手动输入，不要写进任务步骤"));
        }
        // 模型给的 risk 只是提示；服务端必须重新计算。
        let _ = step.risk_hint;
        let (risk, _manual) = assess_command(&command);
        let mut planned_step = NewTaskStep::new(redact_request(&command), step.purpose, risk)
            .with_interactive(step.interactive_hint);
        if index == 0 {
            planned_step = planned_step.with_status("ready");
        }
        planned.push(planned_step);
    }
    Ok(planned)
}

fn build_revised_steps(steps: Vec<TaskStepDraft>, remaining: usize) -> Result<Vec<NewTaskStep>> {
    if steps.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "model.invalid_output",
            "模型没有给出下一步",
        ));
    }
    if steps.len() > remaining.min(MAX_TASK_STEPS) {
        return Err(shellwarden_core::AppError::new(
            "task.step_limit",
            format!(
                "模型追加 {} 步，超过剩余预算 {}",
                steps.len(),
                remaining.min(MAX_TASK_STEPS)
            ),
        ));
    }
    let mut planned = Vec::with_capacity(steps.len());
    for (index, step) in steps.into_iter().enumerate() {
        let command = validate_task_step_command(&step.command)?;
        if contains_credential_like(&command) {
            return Err(shellwarden_core::AppError::new(
                "task.secret_step",
                "模型建议的下一步疑似包含凭据，已拒绝",
            ));
        }
        let (risk, _manual) = assess_command(&command);
        let mut planned_step = NewTaskStep::new(redact_request(&command), step.purpose, risk)
            .with_interactive(step.interactive_hint);
        if index == 0 {
            planned_step = planned_step.with_status("ready");
        }
        planned.push(planned_step);
    }
    Ok(planned)
}

/// 首次任务计划：模型只给草案，服务端重新分级风险。
#[tauri::command]
pub async fn draft_task(
    input: DraftTaskInput,
    state: State<'_, AppState>,
) -> Result<DraftTaskResult> {
    reload_config(&state)?;
    let host = load_host(&state, &input.host_id)?;
    let config = resolve_model_config(
        &state,
        &input.api_key,
        &input.base_url,
        &input.model,
        input.timeout_secs,
        input.max_tokens,
    )?;
    let request = normalize_task_goal(&input.request)?;
    let transport = HttpTransport::new();
    let draft = draft_task_with_model(&transport, &config, &host.name, request).await?;
    let steps = draft
        .steps
        .into_iter()
        .map(|step| {
            let (risk, manual_only) = assess_command(&step.command);
            TaskStepOption {
                command: step.command,
                purpose: step.purpose,
                risk: risk.to_string(),
                risk_hint: step.risk_hint,
                manual_only: manual_only || step.interactive_hint,
                interactive_hint: step.interactive_hint,
            }
        })
        .collect();
    Ok(DraftTaskResult {
        title: draft.title,
        summary: draft.summary,
        steps,
        model: draft.model,
        prompt_version: draft.prompt_version,
        step_limit: MAX_TASK_STEP_BUDGET,
    })
}

#[tauri::command]
pub fn create_task(input: CreateTaskInput, state: State<'_, AppState>) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let host = load_host(&state, &input.host_id)?;
    let goal = normalize_task_goal(&input.goal)?;
    let title = input.title.trim();
    if title.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_title",
            "任务标题不能为空",
        ));
    }
    let step_limit = input
        .step_limit
        .unwrap_or(MAX_TASK_STEP_BUDGET as i64)
        .clamp(1, MAX_TASK_STEP_BUDGET as i64);
    let steps = build_created_steps(input.steps, step_limit as usize)?;
    let session_id = input
        .session_id
        .filter(|session| !session.trim().is_empty());
    if let Some(session) = session_id.as_deref() {
        let owner = {
            let db = state
                .db
                .lock()
                .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
            db.session_host_id(session)?
        };
        match owner {
            Some(owner) if owner == host.id => {}
            Some(_) => {
                return Err(shellwarden_core::AppError::new(
                    "task.session_mismatch",
                    "会话与任务主机不一致",
                ))
            }
            None => {
                return Err(shellwarden_core::AppError::new(
                    "task.session_not_found",
                    "会话不存在或已结束；请重新连接后再创建任务",
                ))
            }
        }
    }

    if let Some(batch_id) = input.batch_id.as_deref() {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        let batch = db
            .get_task_batch(batch_id)?
            .ok_or_else(|| shellwarden_core::AppError::new("task.batch_missing", "批次不存在"))?;
        if !batch.host_ids.iter().any(|id| id == &host.id) {
            return Err(shellwarden_core::AppError::new(
                "task.batch_host_mismatch",
                "主机不属于该批次",
            ));
        }
    }
    let task = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.create_task(NewTask {
            host_id: host.id.clone(),
            session_id: session_id.clone(),
            batch_id: input.batch_id,
            goal_redacted: redact_request(goal),
            title: title.to_string(),
            summary: input.summary.trim().to_string(),
            step_limit,
            steps,
        })?
    };
    let links = task_links(&task.task, None);
    append_audit_links(
        &state,
        "task.created",
        serde_json::json!({
            "task_id": task.task.id,
            "host_id": host.id,
            "session_id": session_id,
            "title": task.task.title,
            "goal_redacted": task.task.goal_redacted,
            "step_count": task.steps.len(),
            "step_limit": task.task.step_limit,
            "prompt_version": TASK_PROMPT_VERSION,
        }),
        &links,
    )?;
    append_audit_links(
        &state,
        "task.plan_ready",
        serde_json::json!({
            "task_id": task.task.id,
            "steps": task
                .steps
                .iter()
                .map(|step| serde_json::json!({
                    "step_id": step.id,
                    "ordinal": step.ordinal,
                    "risk": step.risk,
                    "command_redacted": step.command_redacted,
                }))
                .collect::<Vec<_>>(),
        }),
        &links,
    )?;
    Ok(task)
}

#[derive(Debug, Deserialize)]
pub struct CreateTaskBatchInput {
    pub goal: String,
    pub title: String,
    pub host_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTaskBatchInput {
    pub id: String,
    pub status: String,
    pub current_index: i64,
}

#[tauri::command]
pub fn create_task_batch(
    input: CreateTaskBatchInput,
    state: State<'_, AppState>,
) -> Result<TaskBatchRow> {
    let goal = normalize_task_goal(&input.goal)?;
    let title = input.title.trim();
    if title.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_title",
            "批次标题不能为空",
        ));
    }
    let mut host_ids = Vec::new();
    for host_id in input.host_ids {
        if !host_ids.contains(&host_id) {
            host_ids.push(host_id);
        }
    }
    if host_ids.is_empty() || host_ids.len() > 20 {
        return Err(shellwarden_core::AppError::new(
            "task.batch_size",
            "批次主机数量必须在 1-20 台之间",
        ));
    }
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    for host_id in &host_ids {
        if db.get_host(host_id)?.is_none() {
            return Err(shellwarden_core::AppError::new(
                "host.not_found",
                format!("批次主机不存在: {host_id}"),
            ));
        }
    }
    let batch = db.create_task_batch(NewTaskBatch {
        goal_redacted: redact_request(goal),
        title: title.to_string(),
        host_ids,
    })?;
    drop(db);
    append_audit_links(
        &state,
        "task.batch_created",
        serde_json::json!({
            "batch_id": batch.id,
            "title": batch.title,
            "goal_redacted": batch.goal_redacted,
            "host_count": batch.host_ids.len(),
            "host_ids": batch.host_ids,
        }),
        &AuditLinks::default(),
    )?;
    Ok(batch)
}

#[tauri::command]
pub fn task_batch_get(
    batch_id: String,
    state: State<'_, AppState>,
) -> Result<Option<TaskBatchRow>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.get_task_batch(&batch_id)
}

#[tauri::command]
pub fn task_batch_list_active(
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<TaskBatchRow>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.list_active_task_batches(limit.unwrap_or(10).clamp(1, 50))
}

#[tauri::command]
pub fn task_batch_update(input: UpdateTaskBatchInput, state: State<'_, AppState>) -> Result<()> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    if db.get_task_batch(&input.id)?.is_none() {
        return Err(shellwarden_core::AppError::new(
            "task.batch_missing",
            "批次不存在",
        ));
    }
    db.update_task_batch(&input.id, &input.status, input.current_index)?;
    drop(db);
    append_audit_links(
        &state,
        "task.batch_updated",
        serde_json::json!({
            "batch_id": input.id,
            "status": input.status,
            "current_index": input.current_index,
        }),
        &AuditLinks::default(),
    )?;
    Ok(())
}

/// 批次恢复：把任务重新绑定到当前会话，避免旧 session_id 让任务无法继续。
#[tauri::command]
pub async fn task_bind_session(
    task_id: String,
    session_id: String,
    host_id: String,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.get_task(&task_id)?
            .ok_or_else(|| shellwarden_core::AppError::new("task.missing", "任务不存在"))?
    };
    if record.task.host_id != host_id {
        return Err(shellwarden_core::AppError::new(
            "task.host_mismatch",
            "任务不属于该主机，拒绝重新绑定会话",
        ));
    }
    {
        let sessions = state.ssh.sessions.lock().await;
        if !sessions.contains_key(&session_id) {
            return Err(shellwarden_core::AppError::new(
                ssh_codes::SESSION_NOT_FOUND,
                "会话不存在或已结束",
            ));
        }
    }
    let from_session = record.task.session_id.clone();
    let updated = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.rebind_task_session(&task_id, &session_id)?
    };
    append_audit_links(
        &state,
        "task.session_rebound",
        serde_json::json!({
            "task_id": updated.task.id,
            "host_id": updated.task.host_id,
            "from_session_id": from_session,
            "to_session_id": session_id,
        }),
        &AuditLinks {
            host_id: Some(updated.task.host_id.clone()),
            session_id: Some(session_id),
            task_id: Some(updated.task.id.clone()),
            step_id: None,
            actor: None,
        },
    )?;
    Ok(updated)
}

#[tauri::command]
pub fn task_batch_tasks(batch_id: String, state: State<'_, AppState>) -> Result<Vec<TaskRow>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.tasks_for_batch(&batch_id)
}

#[tauri::command]
pub fn task_get(task_id: String, state: State<'_, AppState>) -> Result<Option<TaskWithSteps>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.get_task(&task_id)
}

#[tauri::command]
pub fn task_list(
    host_id: Option<String>,
    session_id: Option<String>,
    batch_id: Option<String>,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<TaskRow>> {
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    if let Some(batch_id) = batch_id.as_deref() {
        db.list_tasks_for_batch(batch_id, limit.unwrap_or(50).clamp(1, 200))
    } else {
        db.list_tasks(
            host_id.as_deref(),
            session_id.as_deref(),
            limit.unwrap_or(50).clamp(1, 200),
        )
    }
}

/// 用户确认执行某一步：写 `task.step_confirmed` 审计后才允许写 PTY。
#[tauri::command]
pub fn task_step_started(
    task_id: String,
    step_id: String,
    auto: Option<bool>,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    let auto = auto.unwrap_or(false);
    let record = load_task_record(&state, &task_id)?;
    if !matches!(
        record.task.status.as_str(),
        "completed" | "failed" | "cancelled"
    ) {
        guard_task_timeout(&state, &record.task)?;
    }
    if !matches!(
        record.task.status.as_str(),
        "plan_ready" | "waiting_user" | "running"
    ) {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_transition",
            "当前任务状态不能开始执行步骤",
        )
        .with_action("等待模型判断结束，或先处理/继续当前步骤"));
    }
    let step = record
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    if task_step_manual_only(&step) {
        return Err(shellwarden_core::AppError::new(
            "task.manual_step",
            format!("步骤风险为 {} 或需要交互，只能在终端手动执行", step.risk),
        )
        .with_action("在终端手动输入该命令；完成后点击「标记完成」"));
    }
    if step.status == "running" {
        return Ok(record);
    }
    // 预检与 store 内的最终校验一致：先拒绝再写审计，避免留下
    // “已确认但从未开始”的误导性事件。
    if record.steps.iter().any(|candidate| {
        candidate.ordinal < step.ordinal
            && !matches!(
                candidate.status.as_str(),
                "succeeded" | "skipped" | "manual" | "sent"
            )
    }) {
        return Err(shellwarden_core::AppError::new(
            "task.out_of_order",
            "请先处理前面的步骤，再执行这一步",
        ));
    }
    if record
        .steps
        .iter()
        .any(|candidate| candidate.status == "running" && candidate.id != step.id)
    {
        return Err(shellwarden_core::AppError::new(
            "task.step_running",
            "同一任务同时只能执行一个步骤",
        ));
    }
    let links = task_links(&record.task, Some(&step));
    let audit_seq = append_audit_links(
        &state,
        "task.step_confirmed",
        serde_json::json!({
            "task_id": task_id,
            "step_id": step_id,
            "command_redacted": step.command_redacted,
            "risk": step.risk,
            "auto": auto,
        }),
        &links,
    )?;
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.start_step(&task_id, &step_id, Some(audit_seq as i64))?;
    }
    let started_seq = append_audit_links(
        &state,
        "task.step_started",
        serde_json::json!({
            "task_id": task_id,
            "step_id": step_id,
            "command_redacted": step.command_redacted,
            "risk": step.risk,
            "audit_seq": audit_seq,
            "auto": auto,
        }),
        &links,
    )?;
    attach_step_audit(&state, &task_id, &step_id, started_seq);
    load_task_record(&state, &task_id)
}

#[tauri::command]
pub fn task_step_finished(
    input: TaskStepFinishedInput,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &input.task_id)?;
    let step = record
        .steps
        .iter()
        .find(|step| step.id == input.step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    // 退出码是权威信号：显式 succeeded/failed 不能覆盖真实 exit code。
    let step_status = match input.status.as_deref() {
        Some(status @ ("sent" | "manual" | "skipped" | "failed")) => status,
        Some("succeeded") => match input.exit_code {
            None => "manual",
            Some(0) => "succeeded",
            Some(_) => "failed",
        },
        None => match input.exit_code {
            Some(0) => "succeeded",
            Some(_) => "failed",
            None => "sent",
        },
        Some(other) => {
            return Err(shellwarden_core::AppError::new(
                "task.invalid_result",
                format!("未知的步骤结果: {other}"),
            ))
        }
    };
    if step_status == "skipped" && !matches!(step.risk.as_str(), "R0" | "R1") {
        return Err(shellwarden_core::AppError::new(
            "task.skip_not_allowed",
            "只有 R0/R1 步骤可以跳过",
        ));
    }
    let output = redact_output_tail(&input.output_tail);
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.finish_step(
            &input.task_id,
            &input.step_id,
            step_status,
            input.exit_code.map(i64::from),
            &output,
            None,
        )?;
    }
    let links = task_links(&record.task, Some(&step));
    let event_type = if step_status == "failed" {
        "task.step_failed"
    } else {
        "task.step_finished"
    };
    let audit = append_audit_links(
        &state,
        event_type,
        serde_json::json!({
            "task_id": input.task_id,
            "step_id": input.step_id,
            "status": step_status,
            "exit_code": input.exit_code,
            "risk": step.risk,
            "output_sha256": sha256_hex(output.as_bytes()),
            "output_chars": output.chars().count(),
            "output_lines": output.lines().count(),
        }),
        &links,
    );
    if let Ok(seq) = &audit {
        attach_step_audit(&state, &input.task_id, &input.step_id, *seq);
    }
    let updated = load_task_record(&state, &input.task_id)?;
    if updated.task.status == "failed" {
        append_audit_links(
            &state,
            "task.failed",
            serde_json::json!({
                "task_id": updated.task.id,
                "reason": "consecutive_failures",
                "failure_count": updated.task.failure_count,
            }),
            &task_links(&updated.task, None),
        )?;
    }
    audit.map_err(|error| error.with_action("步骤结果已保存；审计写入失败，请检查审计链完整性"))?;
    Ok(updated)
}

/// 交互提示 / REPL / 全屏程序：暂停任务，交还用户。
#[tauri::command]
pub fn task_step_interactive(
    task_id: String,
    step_id: String,
    reason: Option<String>,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &task_id)?;
    if record.task.status == "paused_interactive" {
        return Ok(record);
    }
    let step = record
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    if step.status != "running" {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_step",
            "只有正在执行的步骤可以暂停",
        ));
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.pause_task(&task_id, "paused_interactive")?;
    }
    let reason = redact_request(reason.unwrap_or_default().as_str())
        .chars()
        .take(300)
        .collect::<String>();
    let audit_seq = append_audit_links(
        &state,
        "task.step_interactive",
        serde_json::json!({
            "task_id": task_id,
            "step_id": step_id,
            "reason": reason,
        }),
        &task_links(&record.task, Some(&step)),
    )?;
    attach_step_audit(&state, &task_id, &step_id, audit_seq);
    load_task_record(&state, &task_id)
}

#[tauri::command]
pub fn task_step_skip(
    task_id: String,
    step_id: String,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &task_id)?;
    let step = record
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    if !matches!(step.risk.as_str(), "R0" | "R1") {
        return Err(shellwarden_core::AppError::new(
            "task.skip_not_allowed",
            "只有 R0/R1 步骤可以跳过；变更步骤必须显式处理",
        ));
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.finish_step(&task_id, &step_id, "skipped", None, "", None)?;
    }
    let audit_seq = append_audit_links(
        &state,
        "task.step_skipped",
        serde_json::json!({
            "task_id": task_id,
            "step_id": step_id,
            "risk": step.risk,
        }),
        &task_links(&record.task, Some(&step)),
    )?;
    attach_step_audit(&state, &task_id, &step_id, audit_seq);
    load_task_record(&state, &task_id)
}

/// 失败步骤重试：回到 ready，仍需用户再次确认执行（不自动重跑）。
#[tauri::command]
pub fn task_step_retry(
    task_id: String,
    step_id: String,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &task_id)?;
    let step = record
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.retry_step(&task_id, &step_id, None)?;
    }
    let audit_seq = append_audit_links(
        &state,
        "task.step_retried",
        serde_json::json!({
            "task_id": task_id,
            "step_id": step_id,
            "risk": step.risk,
        }),
        &task_links(&record.task, Some(&step)),
    )?;
    attach_step_audit(&state, &task_id, &step_id, audit_seq);
    load_task_record(&state, &task_id)
}

/// 让模型根据真实结果决定继续 / 结束 / 请求人工。
#[tauri::command]
pub async fn task_revise(
    input: TaskReviseInput,
    state: State<'_, AppState>,
) -> Result<TaskReviseResult> {
    ensure_audit_ok(&state)?;
    reload_config(&state)?;
    let record = load_task_record(&state, &input.task_id)?;
    if !matches!(
        record.task.status.as_str(),
        "completed" | "failed" | "cancelled"
    ) {
        guard_task_timeout(&state, &record.task)?;
    }
    if !matches!(
        record.task.status.as_str(),
        "waiting_user" | "paused_failed"
    ) {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_transition",
            "只有等待确认或失败暂停的任务可以让模型判断下一步",
        ));
    }
    // 预算为 0 时仍允许请求模型判断 done / needs_user；追加步骤会被拒绝。
    let remaining = (record.task.step_limit - record.steps.len() as i64).max(0) as usize;
    let executed = record
        .steps
        .iter()
        .filter(|step| {
            matches!(
                step.status.as_str(),
                "succeeded" | "failed" | "sent" | "manual"
            )
        })
        .collect::<Vec<_>>();
    if executed.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "task.no_result",
            "还没有可用的执行结果，不能请求模型判断下一步",
        ));
    }
    let mut results = executed
        .iter()
        .map(|step| TaskStepResult {
            command: step.command_redacted.clone(),
            exit_code: step.exit_code.and_then(|code| i32::try_from(code).ok()),
            output_tail: step.output_tail_redacted.clone(),
        })
        .collect::<Vec<_>>();
    let last = results.pop();
    let user_note = input
        .user_note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
        .map(str::to_string);
    if let Some(note) = user_note.as_deref() {
        if note.chars().count() > 500 {
            return Err(shellwarden_core::AppError::new(
                "model.request_too_long",
                "补充说明超过 500 字符",
            ));
        }
        if contains_credential_like(note) {
            return Err(shellwarden_core::AppError::new(
                "model.secret_input",
                "补充说明疑似包含凭据，已拒绝发送到模型",
            ));
        }
    }
    let config = resolve_model_config(
        &state,
        &input.api_key,
        &input.base_url,
        &input.model,
        input.timeout_secs,
        input.max_tokens,
    )?;
    let previous_status = record.task.status.clone();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.set_task_status(&input.task_id, "revising")?;
    }
    let host = load_host(&state, &record.task.host_id)?;
    // 注册取消令牌：task_cancel 会 notify_one；select 会丢弃未完成的 HTTP 请求。
    let cancel_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    {
        let mut cancels = state
            .revise_cancels
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "模型取消锁被污染"))?;
        cancels.insert(input.task_id.clone(), cancel_notify.clone());
    }
    // 注册与设置 revising 之间可能已被取消；不要在没有任务的情况下启动模型调用。
    if load_task_record(&state, &input.task_id)?.task.status != "revising" {
        if let Ok(mut cancels) = state.revise_cancels.lock() {
            cancels.remove(&input.task_id);
        }
        return Err(shellwarden_core::AppError::new(
            "task.cancelled",
            "任务在模型判断开始前已被取消",
        ));
    }
    let transport = HttpTransport::new();
    let model_future = revise_task_with_model(
        &transport,
        &config,
        &host.name,
        &record.task.goal_redacted,
        &results,
        last.as_ref(),
        remaining,
        user_note.as_deref(),
    );
    tokio::pin!(model_future);
    let decision = tokio::select! {
        result = &mut model_future => result,
        _ = cancel_notify.notified() => Err(shellwarden_core::AppError::new(
            "task.cancelled",
            "任务已取消，模型判断已中断",
        )),
    };
    if let Ok(mut cancels) = state.revise_cancels.lock() {
        cancels.remove(&input.task_id);
    }
    let decision = match decision {
        Ok(decision) => decision,
        Err(error) => {
            if let Ok(db) = state.db.lock() {
                let _ = db.set_task_status(&input.task_id, &previous_status);
            }
            return Err(error);
        }
    };
    // 模型调用期间用户可能取消或补记了结果；不要把过期决策写到已变化的任务上。
    if load_task_record(&state, &input.task_id)?.task.status != "revising" {
        return Err(shellwarden_core::AppError::new(
            "task.stale",
            "任务状态在模型判断期间已变化；请刷新后重试",
        ));
    }
    let links = task_links(&record.task, None);
    match decision {
        ReviseDecision::Continue { steps } => {
            let planned = match build_revised_steps(steps, remaining) {
                Ok(planned) => planned,
                Err(error) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = db.set_task_status(&input.task_id, &previous_status);
                    }
                    return Err(error);
                }
            };
            let planned_count = planned.len();
            let updated = {
                let db = state
                    .db
                    .lock()
                    .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
                match db.append_task_steps(&input.task_id, planned, "waiting_user", None) {
                    Ok(updated) => updated,
                    Err(error) => {
                        let _ = db.set_task_status(&input.task_id, &previous_status);
                        return Err(error);
                    }
                }
            };
            append_audit_links(
                &state,
                "task.revised",
                serde_json::json!({
                    "task_id": input.task_id,
                    "decision": "continue",
                    "added_steps": planned_count,
                    "remaining_budget": remaining - planned_count,
                    "prompt_version": REVISE_PROMPT_VERSION,
                }),
                &links,
            )?;
            Ok(TaskReviseResult {
                task: updated,
                decision: "continue".into(),
                message: format!("模型追加了 {planned_count} 步，等待你确认"),
            })
        }
        ReviseDecision::Done { summary } => {
            let summary = if summary.trim().is_empty() {
                "模型判定目标已达成"
            } else {
                summary.trim()
            };
            {
                let db = state
                    .db
                    .lock()
                    .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
                db.complete_task(&input.task_id, summary)?;
            }
            append_audit_links(
                &state,
                "task.revised",
                serde_json::json!({
                    "task_id": input.task_id,
                    "decision": "done",
                    "summary": summary,
                    "prompt_version": REVISE_PROMPT_VERSION,
                }),
                &links,
            )?;
            append_audit_links(
                &state,
                "task.completed",
                serde_json::json!({
                    "task_id": input.task_id,
                    "summary": summary,
                }),
                &links,
            )?;
            Ok(TaskReviseResult {
                task: load_task_record(&state, &input.task_id)?,
                decision: "done".into(),
                message: summary.to_string(),
            })
        }
        ReviseDecision::NeedsUser { reason } => {
            {
                let db = state
                    .db
                    .lock()
                    .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
                db.set_task_status(&input.task_id, "waiting_user")?;
            }
            append_audit_links(
                &state,
                "task.revised",
                serde_json::json!({
                    "task_id": input.task_id,
                    "decision": "needs_user",
                    "reason": reason,
                    "prompt_version": REVISE_PROMPT_VERSION,
                }),
                &links,
            )?;
            Ok(TaskReviseResult {
                task: load_task_record(&state, &input.task_id)?,
                decision: "needs_user".into(),
                message: if reason.is_empty() {
                    "模型需要你确认下一步；请手动处理或补充说明".into()
                } else {
                    reason
                },
            })
        }
    }
}

#[tauri::command]
pub fn task_cancel(task_id: String, state: State<'_, AppState>) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &task_id)?;
    // 先唤醒可能在等待的模型判断；task_revise 的 select 会丢弃请求。
    if let Ok(cancels) = state.revise_cancels.lock() {
        if let Some(notify) = cancels.get(&task_id) {
            notify.notify_one();
        }
    }
    if record.task.status == "cancelled" {
        return Ok(record);
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.cancel_task(&task_id, None)?;
    }
    append_audit_links(
        &state,
        "task.cancelled",
        serde_json::json!({
            "task_id": task_id,
            "previous_status": record.task.status,
        }),
        &task_links(&record.task, None),
    )?;
    load_task_record(&state, &task_id)
}

/// 恢复卡在 `revising` 的任务（模型调用被中断/应用退出）；只回到等待用户。
#[tauri::command]
pub fn task_resume(task_id: String, state: State<'_, AppState>) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &task_id)?;
    let has_running_step = record.steps.iter().any(|step| step.status == "running");
    let recoverable =
        record.task.status == "revising" || (record.task.status == "running" && !has_running_step);
    if !recoverable {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_transition",
            "只有模型判断中或执行状态已中断的任务需要恢复",
        ));
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.set_task_status(&task_id, "waiting_user")?;
    }
    append_audit_links(
        &state,
        "task.revised",
        serde_json::json!({
            "task_id": task_id,
            "decision": "resumed",
        }),
        &task_links(&record.task, None),
    )?;
    load_task_record(&state, &task_id)
}

// ---- 任务步骤编辑 / 删除 / 导出 -----------------------------------------

#[derive(Debug, Deserialize)]
pub struct TaskStepUpdateInput {
    pub task_id: String,
    pub step_id: String,
    pub command: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub interactive_hint: Option<bool>,
}

/// 编辑尚未执行的步骤：命令重新校验、风险由服务端重新计算。
#[tauri::command]
pub fn task_step_update(
    input: TaskStepUpdateInput,
    state: State<'_, AppState>,
) -> Result<TaskWithSteps> {
    ensure_audit_ok(&state)?;
    let record = load_task_record(&state, &input.task_id)?;
    if !matches!(
        record.task.status.as_str(),
        "draft" | "plan_ready" | "waiting_user" | "paused_failed"
    ) {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_transition",
            "当前任务状态不能编辑步骤",
        ));
    }
    let step = record
        .steps
        .iter()
        .find(|step| step.id == input.step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    if !matches!(step.status.as_str(), "pending" | "ready") {
        return Err(shellwarden_core::AppError::new(
            "task.invalid_step",
            "只有尚未执行的 pending/ready 步骤可以编辑",
        ));
    }
    let command = validate_task_step_command(&input.command)?;
    if contains_credential_like(&command) {
        return Err(shellwarden_core::AppError::new(
            "task.secret_step",
            "编辑后的命令疑似包含凭据，已拒绝",
        ));
    }
    // 风险永远由服务端计算，不接受前端传入。
    let (risk, _manual) = assess_command(&command);
    let purpose = input.purpose.unwrap_or_else(|| step.purpose.clone());
    // 只能把步骤标成需要人工接管，不能通过编辑清除已有的交互标记。
    let interactive_hint = step.interactive_hint || input.interactive_hint.unwrap_or(false);
    let command_redacted = redact_request(&command);
    let updated = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.update_step(
            &input.task_id,
            &input.step_id,
            &TaskStepEdit {
                command_redacted: command_redacted.clone(),
                purpose: purpose.clone(),
                risk: risk.to_string(),
                interactive_hint,
            },
            None,
        )?
    };
    let updated_step = updated
        .steps
        .iter()
        .find(|step| step.id == input.step_id)
        .cloned()
        .ok_or_else(|| shellwarden_core::AppError::new("task.step_not_found", "任务步骤不存在"))?;
    let audit = append_audit_links(
        &state,
        "task.step_edited",
        serde_json::json!({
            "task_id": input.task_id,
            "step_id": input.step_id,
            "before_sha256": sha256_hex(step.command_redacted.as_bytes()),
            "after_sha256": sha256_hex(command_redacted.as_bytes()),
            "before_risk": step.risk,
            "after_risk": risk,
            "command_redacted": command_redacted,
            "interactive_hint": interactive_hint,
        }),
        &task_links(&updated.task, Some(&updated_step)),
    );
    if let Ok(seq) = &audit {
        attach_step_audit(&state, &input.task_id, &input.step_id, *seq);
    }
    audit.map_err(|error| error.with_action("步骤已更新；审计写入失败，请检查审计链完整性"))?;
    load_task_record(&state, &input.task_id)
}

/// 删除终态任务；审计事件保留。
#[tauri::command]
pub fn task_delete(task_id: String, state: State<'_, AppState>) -> Result<()> {
    let record = load_task_record(&state, &task_id)?;
    if !matches!(
        record.task.status.as_str(),
        "completed" | "failed" | "cancelled"
    ) {
        return Err(shellwarden_core::AppError::new(
            "task.delete_active",
            "进行中的任务不能删除；请先取消任务",
        )
        .with_action("先取消任务，再删除"));
    }
    append_audit_links(
        &state,
        "task.deleted",
        serde_json::json!({
            "task_id": record.task.id,
            "title": record.task.title,
            "status": record.task.status,
            "host_id": record.task.host_id,
            "session_id": record.task.session_id,
            "step_count": record.steps.len(),
        }),
        &task_links(&record.task, None),
    )?;
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
    db.delete_task(&task_id)
}

fn task_status_label(status: &str) -> &'static str {
    match status {
        "draft" => "草案",
        "plan_ready" => "计划就绪",
        "waiting_user" => "等待确认",
        "running" => "执行中",
        "revising" => "模型判断中",
        "paused_failed" => "失败暂停",
        "paused_interactive" => "等待人工接管",
        "completed" => "已完成",
        "failed" => "已停止",
        "cancelled" => "已取消",
        _ => "未知",
    }
}

fn step_status_label(status: &str) -> &'static str {
    match status {
        "pending" => "等待上一步",
        "ready" => "待确认",
        "running" => "执行中",
        "succeeded" => "已完成",
        "failed" => "失败",
        "sent" => "已发送（结果未知）",
        "skipped" => "已跳过",
        "manual" => "人工完成",
        _ => "未知",
    }
}

/// Markdown 代码块用 4 空格缩进，避免命令/输出里的反引号破坏文档结构。
fn indent_markdown_block(text: &str) -> String {
    if text.trim().is_empty() {
        return "    （空）".to_string();
    }
    text.lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_task_markdown(task: &TaskWithSteps, host: &Host, audit: &[AuditEvent]) -> String {
    let mut out = String::new();
    out.push_str(&format!("# 任务：{}\n\n", task.task.title));
    out.push_str(&format!(
        "- 状态：{}（{}）\n",
        task.task.status,
        task_status_label(&task.task.status)
    ));
    out.push_str(&format!("- 主机：{}（{}）\n", host.name, task.task.host_id));
    if let Some(session_id) = task.task.session_id.as_deref() {
        out.push_str(&format!("- 会话：{session_id}\n"));
    }
    out.push_str(&format!("- 创建：{}\n", task.task.created_at));
    out.push_str(&format!("- 更新：{}\n", task.task.updated_at));
    if let Some(completed_at) = task.task.completed_at.as_deref() {
        out.push_str(&format!("- 结束：{completed_at}\n"));
    }
    out.push_str(&format!(
        "- 预算：{} / {} 步；连续失败：{}\n",
        task.steps.len(),
        task.task.step_limit,
        task.task.failure_count
    ));
    out.push_str("\n## 目标（已脱敏）\n\n");
    out.push_str(&indent_markdown_block(&task.task.goal_redacted));
    out.push('\n');
    if !task.task.summary.trim().is_empty() {
        out.push_str("\n## 计划摘要\n\n");
        out.push_str(&indent_markdown_block(&task.task.summary));
        out.push('\n');
    }
    if !task.task.outcome_summary.trim().is_empty() {
        out.push_str("\n## 结果\n\n");
        out.push_str(&indent_markdown_block(&task.task.outcome_summary));
        out.push('\n');
    }
    out.push_str("\n## 步骤\n\n");
    for step in &task.steps {
        out.push_str(&format!("### 步骤 {}\n\n", step.ordinal));
        out.push_str(&format!(
            "- 状态：{}（{}）\n",
            step.status,
            step_status_label(&step.status)
        ));
        out.push_str(&format!("- 风险：{}\n", step.risk));
        if let Some(exit_code) = step.exit_code {
            out.push_str(&format!("- 退出码：{exit_code}\n"));
        }
        if step.interactive_hint {
            out.push_str("- 交互：需要人工接管\n");
        }
        if let Some(audit_seq) = step.audit_seq {
            out.push_str(&format!("- 审计：#{audit_seq}\n"));
        }
        if !step.purpose.trim().is_empty() {
            out.push_str(&format!("- 目的：{}\n", step.purpose));
        }
        out.push_str("- 命令（已脱敏）：\n\n");
        out.push_str(&indent_markdown_block(&step.command_redacted));
        out.push('\n');
        if !step.output_tail_redacted.trim().is_empty() {
            out.push_str("\n输出摘要（已脱敏，仅尾部）：\n\n");
            out.push_str(&indent_markdown_block(&step.output_tail_redacted));
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str("## 审计事件\n\n");
    if audit.is_empty() {
        out.push_str("（无）\n");
    } else {
        out.push_str("| seq | 时间 | 事件 | actor |\n|---|---|---|---|\n");
        for event in audit {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                event.seq,
                event.timestamp.to_rfc3339(),
                event.event_type,
                event.actor
            ));
        }
    }
    out.push_str(
        "\n> 本导出只包含任务表中已脱敏的命令与输出尾部；完整输出、密码与密钥不会写入。\n",
    );
    out
}

fn export_task_content(state: &AppState, task_id: &str) -> Result<String> {
    let record = load_task_record(state, task_id)?;
    let host = load_host(state, &record.task.host_id)?;
    let audit = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.audit_events_for_task(task_id, 500)?
    };
    Ok(render_task_markdown(&record, &host, &audit))
}

#[tauri::command]
pub fn task_export_markdown(task_id: String, state: State<'_, AppState>) -> Result<String> {
    export_task_content(&state, &task_id)
}

#[tauri::command]
pub fn save_task_export(
    task_id: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<String> {
    let target = std::path::Path::new(&path);
    let extension = target
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "md" | "markdown" | "txt") {
        return Err(shellwarden_core::AppError::new(
            "task.export_invalid_path",
            "导出文件扩展名必须是 .md / .markdown / .txt",
        ));
    }
    if target.file_name().is_none() || target.is_dir() {
        return Err(shellwarden_core::AppError::new(
            "task.export_invalid_path",
            "导出路径必须是文件",
        ));
    }
    let content = export_task_content(&state, &task_id)?;
    std::fs::write(target, content.as_bytes()).map_err(|error| {
        shellwarden_core::AppError::new("task.export_failed", format!("写入导出文件失败: {error}"))
            .with_action("检查目标目录是否存在、是否有写权限")
    })?;
    Ok(path)
}

#[tauri::command]
pub fn save_batch_export(
    batch_id: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<String> {
    let target = std::path::Path::new(&path);
    let extension = target
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "md" | "markdown" | "txt") {
        return Err(shellwarden_core::AppError::new(
            "task.export_invalid_path",
            "导出文件扩展名必须是 .md / .markdown / .txt",
        ));
    }
    if target.file_name().is_none() || target.is_dir() {
        return Err(shellwarden_core::AppError::new(
            "task.export_invalid_path",
            "导出路径必须是文件",
        ));
    }
    let (batch, task_rows) = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        let batch = db
            .get_task_batch(&batch_id)?
            .ok_or_else(|| shellwarden_core::AppError::new("task.batch_missing", "批次不存在"))?;
        let rows = db.tasks_for_batch(&batch_id)?;
        (batch, rows)
    };
    let mut out = format!(
        "# 批量任务：{}\n\n- 批次：{}\n- 目标：{}\n- 主机数：{}\n- 状态：{}\n- 生成时间：{}\n\n",
        batch.title,
        batch.id,
        batch.goal_redacted,
        batch.host_ids.len(),
        batch.status,
        Utc::now().to_rfc3339()
    );
    out.push_str("## 汇总\n\n| 主机 | 任务 | 状态 | 步骤 |\n|---|---|---|---|\n");
    for row in &task_rows {
        let host_name = load_host(&state, &row.host_id)
            .map(|host| host.name)
            .unwrap_or_else(|_| row.host_id.clone());
        let steps = {
            let db = state
                .db
                .lock()
                .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
            db.get_task(&row.id)?
                .map(|task| task.steps.len())
                .unwrap_or(0)
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            host_name.replace('|', "\\|"),
            row.id,
            row.status,
            steps
        ));
    }
    for row in &task_rows {
        out.push_str("\n---\n\n");
        out.push_str(&export_task_content(&state, &row.id)?);
    }
    out.push_str(
        "\n> 本导出只包含任务表中已脱敏的命令与输出尾部；完整输出、密码与密钥不会写入。\n",
    );
    std::fs::write(target, out.as_bytes()).map_err(|error| {
        shellwarden_core::AppError::new("task.export_failed", format!("写入导出文件失败: {error}"))
            .with_action("检查目标目录是否存在、是否有写权限")
    })?;
    Ok(path)
}

// ---- 任务历史保留 / 清理 ------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskHistorySettings {
    pub keep_days: i64,
    pub max_terminal: i64,
}

fn clamp_task_history_policy(keep_days: i64, max_terminal: i64) -> (i64, i64) {
    (
        keep_days.clamp(0, crate::config::MAX_TASK_HISTORY_KEEP_DAYS),
        max_terminal.clamp(0, crate::config::MAX_TASK_HISTORY_MAX_TERMINAL),
    )
}

#[tauri::command]
pub fn load_task_history_settings(state: State<'_, AppState>) -> Result<TaskHistorySettings> {
    reload_config(&state)?;
    let config = state
        .config
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?;
    let (keep_days, max_terminal) = clamp_task_history_policy(
        config.tasks.history_keep_days,
        config.tasks.history_max_terminal,
    );
    Ok(TaskHistorySettings {
        keep_days,
        max_terminal,
    })
}

#[tauri::command]
pub fn save_task_history_settings(
    keep_days: i64,
    max_terminal: i64,
    state: State<'_, AppState>,
) -> Result<TaskHistorySettings> {
    ensure_audit_ok(&state)?;
    if !(0..=crate::config::MAX_TASK_HISTORY_KEEP_DAYS).contains(&keep_days) {
        return Err(shellwarden_core::AppError::new(
            "config.task_history_invalid",
            format!(
                "任务历史保留天数必须在 0-{} 之间（0 表示不按时间清理）",
                crate::config::MAX_TASK_HISTORY_KEEP_DAYS
            ),
        ));
    }
    if !(0..=crate::config::MAX_TASK_HISTORY_MAX_TERMINAL).contains(&max_terminal) {
        return Err(shellwarden_core::AppError::new(
            "config.task_history_invalid",
            format!(
                "任务历史保留条数必须在 0-{} 之间（0 表示不按数量清理）",
                crate::config::MAX_TASK_HISTORY_MAX_TERMINAL
            ),
        ));
    }
    reload_config(&state)?;
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?;
        config.tasks.history_keep_days = keep_days;
        config.tasks.history_max_terminal = max_terminal;
    }
    save_config(&state)?;
    record_audit(
        &state,
        "settings.task_history_updated",
        serde_json::json!({
            "keep_days": keep_days,
            "max_terminal": max_terminal,
        }),
    )?;
    Ok(TaskHistorySettings {
        keep_days,
        max_terminal,
    })
}

/// 按配置（或显式覆盖）清理终态任务；进行中任务永不清理，审计事件保留。
#[tauri::command]
pub fn task_history_prune(
    host_id: Option<String>,
    keep_days: Option<i64>,
    max_terminal: Option<i64>,
    state: State<'_, AppState>,
) -> Result<TaskPruneReport> {
    reload_config(&state)?;
    let (config_keep, config_max) = {
        let config = state
            .config
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?;
        (
            config.tasks.history_keep_days,
            config.tasks.history_max_terminal,
        )
    };
    let (keep_days, max_terminal) = clamp_task_history_policy(
        keep_days.unwrap_or(config_keep),
        max_terminal.unwrap_or(config_max),
    );
    // 清理是破坏性操作；审计链已损坏时不要先删再报错。
    if !state.audit_ok.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(shellwarden_core::AppError::new(
            "audit.integrity",
            "审计链完整性校验失败，已停止清理；请先修复或导出审计数据",
        ));
    }
    let report = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.prune_tasks(host_id.as_deref(), keep_days, max_terminal)?
    };
    if report.deleted > 0 {
        append_audit_links(
            &state,
            "task.history_pruned",
            serde_json::json!({
                "host_id": host_id,
                "deleted": report.deleted,
                "remaining_terminal": report.remaining_terminal,
                "keep_days": keep_days,
                "max_terminal": max_terminal,
                "age_cutoff": report.age_cutoff,
            }),
            &AuditLinks {
                host_id: host_id.clone(),
                ..Default::default()
            },
        )
        .map_err(|error| error.with_action("任务历史已清理；审计写入失败，请检查审计链完整性"))?;
    }
    Ok(report)
}

use shellwarden_core::ids::new_id;

// ---- 配置修改：主机、模型提供方 -----------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpdateHostInput {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    #[serde(default)]
    pub default_username: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_ssh_backend")]
    pub ssh_backend: String,
    #[serde(default)]
    pub group_name: String,
}

fn default_ssh_backend() -> String {
    "auto".into()
}

#[tauri::command]
pub async fn update_host(input: UpdateHostInput, state: State<'_, AppState>) -> Result<Host> {
    let before = load_host(&state, &input.id)?;
    let updated = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.update_host(
            &input.id,
            &shellwarden_store::NewHost {
                name: input.name,
                hostname: input.hostname,
                port: input.port,
                default_username: input.default_username,
                tags: input.tags,
                ssh_backend: input.ssh_backend,
                group_name: input.group_name,
            },
        )?
    };
    // 只有地址/端口变化才需要重新探测；改名字/标签不应使已有信任失效。
    let address_changed = before.hostname != updated.hostname || before.port != updated.port;
    if address_changed {
        state.ssh.probes.lock().await.remove(&input.id);
        // 旧地址的信任不能留在 known_hosts 里：否则以后改回旧地址会
        // 跳过探测直接复用旧指纹。
        let _ = state
            .ssh
            .known_hosts
            .lock()
            .await
            .forget(&before.hostname, before.port);
    }
    if address_changed || before.default_username != updated.default_username {
        let old_prefix = format!("{}@{}:", before.hostname, before.port);
        let new_prefix = format!("{}@{}:", updated.hostname, updated.port);
        state
            .ssh
            .command_cache
            .lock()
            .await
            .retain(|key, _| !key.starts_with(&old_prefix) && !key.starts_with(&new_prefix));
    }
    append_audit_links(
        &state,
        "host.updated",
        serde_json::json!({
            "host_id": updated.id,
            "before": {
                "hostname": before.hostname,
                "port": before.port,
                "user": before.default_username,
            },
            "after": {
                "hostname": updated.hostname,
                "port": updated.port,
                "user": updated.default_username,
            },
        }),
        &AuditLinks {
            host_id: Some(updated.id.clone()),
            ..Default::default()
        },
    )?;
    Ok(updated)
}

#[derive(Serialize)]
pub struct ModelProviderInfo {
    pub base_url: String,
    pub model: String,
    /// 只告知是否已保存密钥，不把明文回传给前端。
    pub has_key: bool,
}

/// 每次模型调用前重新读 config.toml，外部编辑无需重启。
fn reload_config(state: &AppState) -> Result<()> {
    let loaded = crate::config::AppConfig::load(&state.config_path)
        .map_err(|error| shellwarden_core::AppError::new("config.read_failed", error))?;
    let mut config = state
        .config
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?;
    *config = loaded;
    if config.ensure_defaults() {
        config
            .save(&state.config_path)
            .map_err(|error| shellwarden_core::AppError::new("config.write_failed", error))?;
    }
    Ok(())
}

fn saved_api_key(state: &AppState) -> Option<String> {
    let payload = {
        let db = state.db.lock().ok()?;
        db.get_setting("model.api_key").ok()??
    };
    let ciphertext = BASE64.decode(payload.get("ciphertext")?.as_str()?).ok()?;
    let nonce = BASE64.decode(payload.get("nonce")?.as_str()?).ok()?;
    state.secrets.decrypt(&ciphertext, &nonce).ok()
}

fn model_base_url(state: &AppState) -> String {
    state
        .config
        .lock()
        .ok()
        .and_then(|config| config.model.base_url.clone())
        .unwrap_or_else(|| DEFAULT_BASE_URL.into())
}

fn model_name(state: &AppState) -> String {
    state
        .config
        .lock()
        .ok()
        .and_then(|config| config.model.model.clone())
        .unwrap_or_else(|| DEFAULT_MODEL.into())
}

fn save_config(state: &AppState) -> Result<()> {
    let config = state
        .config
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?
        .clone();
    config
        .save(&state.config_path)
        .map_err(|error| shellwarden_core::AppError::new("config.write_failed", error))
}

#[tauri::command]
pub fn load_model_provider(state: State<'_, AppState>) -> Result<ModelProviderInfo> {
    reload_config(&state)?;
    let base_url = model_base_url(&state);
    let model = model_name(&state);
    let db = state
        .db
        .lock()
        .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;

    let has_key = db
        .get_setting("model.api_key")
        .ok()
        .flatten()
        .and_then(|value| {
            let ciphertext = BASE64.decode(value.get("ciphertext")?.as_str()?).ok()?;
            let nonce = BASE64.decode(value.get("nonce")?.as_str()?).ok()?;
            state.secrets.decrypt(&ciphertext, &nonce).ok()
        })
        .is_some();

    Ok(ModelProviderInfo {
        base_url,
        model,
        has_key,
    })
}

#[tauri::command]
pub fn save_model_provider(
    base_url: String,
    model: String,
    api_key: Option<String>,
    remember_key: bool,
    state: State<'_, AppState>,
) -> Result<()> {
    let base_url = base_url.trim().to_string();
    let model = model.trim().to_string();
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return Err(shellwarden_core::AppError::new(
            "model.config_invalid",
            "Base URL 必须是 http(s) 地址",
        ));
    }
    if base_url.starts_with("http://") && !is_loopback_base_url(&base_url) {
        return Err(shellwarden_core::AppError::new(
            "model.config_invalid",
            "远程模型地址必须使用 https；http 仅允许 localhost/127.0.0.1/[::1]",
        ));
    }
    if model.is_empty() {
        return Err(shellwarden_core::AppError::new(
            "model.config_invalid",
            "模型名不能为空",
        ));
    }

    {
        state
            .config
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?
            .model
            .base_url = Some(base_url.clone());
        state
            .config
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "配置锁被污染"))?
            .model
            .model = Some(model.clone());
        save_config(&state)?;

        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        match api_key.filter(|key| !key.is_empty()) {
            Some(key) if remember_key => {
                let (ciphertext, nonce) = state.secrets.encrypt(&key)?;
                db.set_setting(
                    "model.api_key",
                    &serde_json::json!({
                        "ciphertext": BASE64.encode(ciphertext),
                        "nonce": BASE64.encode(nonce),
                    }),
                )?;
            }
            Some(_) => {
                db.delete_setting("model.api_key")?;
            }
            None if !remember_key => {
                // 显式“不保存”且没有新密钥：清除旧密钥。
                db.delete_setting("model.api_key")?;
            }
            None => {}
        }
    }

    record_audit(
        &state,
        "settings.model_updated",
        serde_json::json!({ "base_url": base_url, "model": model, "key_saved": remember_key }),
    )?;
    Ok(())
}

#[derive(Serialize)]
pub struct ClassifyInputResult {
    pub intent: String,
    pub text: String,
    pub probe: Option<String>,
}

#[tauri::command]
pub fn classify_input(input: String) -> ClassifyInputResult {
    let result = nlsh::classify(&input);
    ClassifyInputResult {
        intent: result.intent.as_str().into(),
        text: result.text,
        probe: result.probe,
    }
}

fn is_probe_token(command: &str) -> bool {
    if command.is_empty() || command.len() > 64 {
        return false;
    }
    command
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && command
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// 内部只读探针：只接受简单命令名，用于歧义输入的一次 `command -v` 复核。
#[tauri::command]
pub async fn command_exists(
    session_id: String,
    command: String,
    state: State<'_, AppState>,
) -> Result<bool> {
    if !is_probe_token(&command) {
        return Ok(false);
    }
    let config = state.ssh.configs.lock().await.get(&session_id).cloned();
    let Some(config) = config else {
        return Ok(false);
    };

    let key = format!(
        "{}@{}:{}#{}",
        config.host, config.port, config.username, command
    );
    if let Some(exists) = state.ssh.command_cache.lock().await.get(&key) {
        return Ok(*exists);
    }

    let host_id = {
        let db = state
            .db
            .lock()
            .map_err(|_| shellwarden_core::AppError::new("app.lock", "数据库锁被污染"))?;
        db.list_hosts().ok().and_then(|hosts| {
            hosts
                .into_iter()
                .find(|host| host.hostname == config.host && host.port == config.port)
                .map(|host| host.id)
        })
    };
    append_audit_links(
        &state,
        "probe.started",
        serde_json::json!({
            "session_id": session_id,
            "host": config.host,
            "command": command,
        }),
        &AuditLinks {
            host_id: host_id.clone(),
            session_id: Some(session_id.clone()),
            ..Default::default()
        },
    )?;

    let result = state
        .ssh
        .backend
        .exec(
            &config,
            &format!("command -v {command}"),
            4096,
            std::time::Duration::from_secs(10),
        )
        .await;
    let exists = match result {
        Ok(output) => output.exit_code == Some(0) && !output.stdout.is_empty(),
        Err(error) => {
            // 探测失败不是“命令不存在”。不要缓存 false，否则这次失败会让
            // 该命令在主机编辑前一直被误判成 AI 输入。
            let _ = append_audit_links(
                &state,
                "probe.failed",
                serde_json::json!({
                    "session_id": session_id,
                    "host": config.host,
                    "command": command,
                    "code": error.code,
                }),
                &AuditLinks {
                    host_id: host_id.clone(),
                    session_id: Some(session_id.clone()),
                    ..Default::default()
                },
            );
            return Ok(false);
        }
    };
    append_audit_links(
        &state,
        "probe.completed",
        serde_json::json!({
            "session_id": session_id,
            "host": config.host,
            "command": command,
            "exists": exists,
        }),
        &AuditLinks {
            host_id: host_id.clone(),
            session_id: Some(session_id.clone()),
            ..Default::default()
        },
    )?;
    state.ssh.command_cache.lock().await.insert(key, exists);
    Ok(exists)
}

#[cfg(test)]
mod classify_input_tests {
    use super::*;

    #[test]
    fn classify_input_uses_nlsh_for_all_languages() {
        assert_eq!(classify_input("git status".into()).intent, "shell");
        assert_eq!(classify_input("现在几点了".into()).intent, "ai");
        assert_eq!(classify_input("Привет".into()).intent, "ai");
        assert_eq!(classify_input("sl".into()).intent, "ambiguous");
        let custom = classify_input("deploy prod".into());
        assert_eq!(custom.intent, "ai");
        assert_eq!(custom.probe, None);
        // 服务动词是请求，不是合法子命令；真正的 shell 写法是 -s reload。
        assert_eq!(classify_input("nginx reload".into()).intent, "ai");
        assert_eq!(classify_input("nginx -s reload".into()).intent, "shell");

        // nlsh v0.5 的关键边界：命令 + 散文参数、话题式提问、子命令。
        assert_eq!(classify_input("git commit the changes".into()).intent, "ai");
        assert_eq!(classify_input("tail the logs".into()).intent, "ai");
        assert_eq!(classify_input("kubectl get pods".into()).intent, "shell");
        assert_eq!(classify_input("git hooks".into()).intent, "ai");
        assert_eq!(classify_input("npm install hangs".into()).intent, "ai");
        assert_eq!(classify_input("cat 中文.txt".into()).intent, "shell");
        let history = classify_input("!!".into());
        assert_eq!(history.intent, "shell");
        assert_eq!(history.text, "!!");
    }
}

#[cfg(test)]
mod command_risk_tests {
    use super::{ai_command_risk, assess_command};

    #[test]
    fn compound_and_nginx_reload_are_high_risk() {
        assert_eq!(ai_command_risk("date"), "R0");
        assert_eq!(ai_command_risk("df -h | grep root"), "R0");
        assert_eq!(ai_command_risk("nginx -t"), "R1");
        assert_eq!(ai_command_risk("nginx -t && nginx -s reload"), "R2");
        assert_eq!(ai_command_risk("date && rm -f /tmp/x"), "R2");
        assert_eq!(ai_command_risk("systemctl reload nginx"), "R2");
        assert!(!assess_command("date").1);
        assert!(!assess_command("nginx -t").1);
        assert!(assess_command("nginx -t && nginx -s reload").1);
        assert!(assess_command("systemctl reload nginx").1);
        assert!(assess_command("rm -rf /").1);
    }
}

#[cfg(test)]
mod task_mode_tests {
    use super::{
        build_created_steps, build_revised_steps, redact_output_tail, task_step_manual_only,
        CreateTaskStepInput,
    };
    use shellwarden_model::TaskStepDraft;
    use shellwarden_store::TaskStepRow;

    fn step(command: &str, risk_hint: &str) -> CreateTaskStepInput {
        CreateTaskStepInput {
            command: command.into(),
            purpose: "purpose".into(),
            risk_hint: risk_hint.into(),
            interactive_hint: false,
        }
    }

    fn step_row(risk: &str, interactive_hint: bool) -> TaskStepRow {
        TaskStepRow {
            id: "tstep_1".into(),
            task_id: "task_1".into(),
            ordinal: 1,
            command_redacted: "date".into(),
            purpose: String::new(),
            risk: risk.into(),
            status: "ready".into(),
            exit_code: None,
            output_tail_redacted: String::new(),
            interactive_hint,
            started_at: None,
            finished_at: None,
            audit_seq: None,
        }
    }

    #[test]
    fn create_steps_reassess_risk_and_mark_first_ready() {
        let planned = build_created_steps(
            vec![
                step("rm -f /tmp/x", "R0"),
                step("nginx -t", "R3"),
                step("sudo systemctl restart nginx", "R0"),
            ],
            8,
        )
        .unwrap();
        assert_eq!(planned[0].risk, "R2");
        assert_eq!(planned[0].status, "ready");
        assert_eq!(planned[1].risk, "R1");
        assert_eq!(planned[1].status, "pending");
        assert_eq!(planned[2].risk, "R3");
    }

    #[test]
    fn create_steps_reject_secrets_multiline_and_over_budget() {
        let err = build_created_steps(vec![step("mysql --password=hunter2", "R0")], 8).unwrap_err();
        assert_eq!(err.code, "task.secret_step");
        let err = build_created_steps(vec![step("echo a\necho b", "R0")], 8).unwrap_err();
        assert_eq!(err.code, "task.invalid_step");
        let err = build_created_steps(
            (0..6).map(|i| step(&format!("echo {i}"), "R0")).collect(),
            8,
        )
        .unwrap_err();
        assert_eq!(err.code, "task.step_limit");
    }

    #[test]
    fn interactive_and_high_risk_steps_are_manual_only() {
        assert!(task_step_manual_only(&step_row("R2", false)));
        assert!(task_step_manual_only(&step_row("R3", false)));
        assert!(task_step_manual_only(&step_row("R1", true)));
        assert!(!task_step_manual_only(&step_row("R0", false)));
        assert!(!task_step_manual_only(&step_row("R1", false)));
    }

    #[test]
    fn revised_steps_respect_remaining_budget() {
        let draft = |command: &str| TaskStepDraft {
            command: command.into(),
            purpose: String::new(),
            risk_hint: "R0".into(),
            interactive_hint: false,
        };
        let planned = build_revised_steps(vec![draft("journalctl -u nginx -n 20")], 2).unwrap();
        assert_eq!(planned[0].status, "ready");
        assert_eq!(planned[0].risk, "R0");
        let err = build_revised_steps(vec![draft("date"), draft("uptime"), draft("free -m")], 2)
            .unwrap_err();
        assert_eq!(err.code, "task.step_limit");
    }

    #[test]
    fn output_tail_redacts_credentials_and_pem_bodies() {
        let raw = "nginx: ok\npassword=hunter2\n-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYBODY\n-----END OPENSSH PRIVATE KEY-----\ntail";
        let redacted = redact_output_tail(raw);
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(!redacted.contains("SECRETKEYBODY"), "{redacted}");
        assert!(redacted.contains("tail"));
        assert!(redacted.contains("nginx: ok"));
        let long = (1..=100)
            .map(|index| format!("line{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(redact_output_tail(&long).lines().count(), 80);
        assert_eq!(redact_output_tail("   "), "");
    }
}

#[cfg(test)]
mod probe_tests {
    use super::{contains_credential_like, is_probe_token, redact_request};

    #[test]
    fn probe_token_rejects_injection() {
        assert!(is_probe_token("deploy"));
        assert!(is_probe_token("my-script.sh"));
        assert!(!is_probe_token("deploy; rm -rf /"));
        assert!(!is_probe_token("-rf"));
        assert!(!is_probe_token(""));
        assert!(!is_probe_token("a b"));
    }

    #[test]
    fn request_redaction_masks_key_value_secrets() {
        assert_eq!(
            redact_request("重启 nginx password=hunter2 token=abc"),
            "重启 nginx password=*** token=***"
        );
        assert_eq!(redact_request("普通描述"), "普通描述");
        assert_eq!(
            redact_request("ssh host --password hunter2"),
            "ssh host --password ***"
        );
        assert_eq!(redact_request("密码：hunter2"), "密码=***");
        assert_eq!(redact_request("密码： hunter2"), "密码： ***");
        assert_eq!(
            redact_request("Authorization: Bearer abc.def"),
            "Authorization: Bearer ***"
        );
        assert_eq!(
            redact_request("https://user:hunter2@example.com/x"),
            "https://user:***@example.com/x"
        );
        assert!(contains_credential_like("password=hunter2"));
        assert!(contains_credential_like("密码：hunter2"));
        assert!(!contains_credential_like("如何重置密码"));
    }

    #[test]
    fn space_separated_secrets_are_masked() {
        assert_eq!(redact_request("password hunter2"), "password ***");
        assert_eq!(redact_request("密码 hunter2"), "密码 ***");
        assert_eq!(redact_request("我的密码是 hunter2"), "我的密码是 ***");
        assert_eq!(
            redact_request("my password is hunter2"),
            "my password is ***"
        );
        assert!(contains_credential_like("password hunter2"));
        assert!(contains_credential_like("密码 hunter2"));
        assert!(contains_credential_like("my password is hunter2"));
        assert!(
            !contains_credential_like("basic check"),
            "普通英文 'basic' 不应触发凭据拒绝"
        );
        assert!(
            !contains_credential_like("my password is expired"),
            "正常运维描述不应因为含 password 被拒绝"
        );
        assert!(
            !contains_credential_like("my password reset failed"),
            "正常运维描述不应因为含 password 被拒绝"
        );
    }

    #[test]
    fn basic_auth_and_pem_body_are_masked() {
        assert_eq!(
            redact_request("Authorization: Basic dXNlcjpwYXNz"),
            "Authorization: Basic ***"
        );
        let pem = redact_request(
            "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk -----END OPENSSH PRIVATE KEY-----",
        );
        assert!(!pem.contains("b3BlbnNzaC1rZXk"), "{pem}");
        assert!(contains_credential_like(
            "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk"
        ));
    }
}

#[cfg(test)]
mod task_ipc_tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::secret::SecretBox;
    use crate::state::{AppState, SshState};
    use shellwarden_core::audit::AuditChain;
    use shellwarden_store::{now, Db, Host, NewHost};
    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;
    use tauri::Manager;

    fn test_state(dir: &std::path::Path) -> AppState {
        let db = Db::open(dir.join("shellwarden.db")).unwrap();
        let secrets = SecretBox::load_or_create(dir).unwrap();
        let known_hosts =
            shellwarden_ssh::KnownHostsStore::load(dir.join("known_hosts.json")).unwrap();
        AppState {
            db: Mutex::new(db),
            secrets,
            ssh: SshState::new(known_hosts),
            audit: Mutex::new(AuditChain::new(1000)),
            audit_ok: AtomicBool::new(true),
            config_path: dir.join("config.toml"),
            data_dir: dir.to_path_buf(),
            config: Mutex::new(AppConfig::default()),
            revise_cancels: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn make_host(state: &AppState, name: &str) -> Host {
        state
            .db
            .lock()
            .unwrap()
            .create_host(NewHost {
                name: name.into(),
                hostname: "127.0.0.1".into(),
                port: 22,
                default_username: "ops".into(),
                tags: vec![],
                ssh_backend: "auto".into(),
                group_name: "test".into(),
            })
            .unwrap()
    }

    fn make_session(state: &AppState, session_id: &str, host_id: &str) {
        state
            .db
            .lock()
            .unwrap()
            .insert_session(session_id, host_id, None, "auto", &now())
            .unwrap();
    }

    fn step_input(command: &str) -> CreateTaskStepInput {
        CreateTaskStepInput {
            command: command.into(),
            purpose: "purpose".into(),
            risk_hint: "R0".into(),
            interactive_hint: false,
        }
    }

    fn task_input(
        host_id: &str,
        session_id: &str,
        steps: Vec<CreateTaskStepInput>,
    ) -> CreateTaskInput {
        CreateTaskInput {
            host_id: host_id.into(),
            session_id: Some(session_id.into()),
            batch_id: None,
            goal: "检查并重载 nginx".into(),
            title: "检查并重载 nginx".into(),
            summary: "只读检查后平滑重载".into(),
            step_limit: Some(8),
            steps,
        }
    }

    fn audit_types_for(state: &AppState, task_id: &str) -> Vec<String> {
        let events = state.db.lock().unwrap().audit_events_all().unwrap();
        events
            .iter()
            .filter(|event| {
                event
                    .payload
                    .pointer("/_links/task_id")
                    .and_then(|value| value.as_str())
                    == Some(task_id)
            })
            .map(|event| event.event_type.clone())
            .collect()
    }

    #[test]
    fn task_ipc_lifecycle_audit_and_guards() {
        let dir = tempfile::tempdir().unwrap();
        let app = tauri::test::mock_builder()
            .manage(test_state(dir.path()))
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let state = app.state::<AppState>();

        let host = make_host(&state, "web-ipc");
        make_session(&state, "sess_ipc_1", &host.id);
        let task = create_task(
            task_input(
                &host.id,
                "sess_ipc_1",
                vec![
                    step_input("nginx -t"),
                    step_input("curl -I http://127.0.0.1"),
                    step_input("systemctl reload nginx"),
                ],
            ),
            state.clone(),
        )
        .unwrap();
        assert_eq!(task.task.status, "plan_ready");
        assert_eq!(task.steps[0].status, "ready");
        assert_eq!(task.steps[1].status, "pending");
        assert_eq!(task.steps[2].risk, "R2");

        // 编辑未执行步骤：重算风险；改成 R2 后不能再自动执行。
        let edited_high = task_step_update(
            TaskStepUpdateInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[0].id.clone(),
                command: "systemctl reload nginx".into(),
                purpose: Some("编辑后的重载".into()),
                interactive_hint: None,
            },
            state.clone(),
        )
        .unwrap();
        assert_eq!(edited_high.steps[0].risk, "R2");
        let err = task_step_started(
            task.task.id.clone(),
            task.steps[0].id.clone(),
            None,
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.manual_step");

        let restored = task_step_update(
            TaskStepUpdateInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[0].id.clone(),
                command: "nginx -t".into(),
                purpose: Some("验证配置".into()),
                interactive_hint: None,
            },
            state.clone(),
        )
        .unwrap();
        assert_eq!(restored.steps[0].risk, "R1");
        let err = task_step_update(
            TaskStepUpdateInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[0].id.clone(),
                command: "mysql --password=hunter2".into(),
                purpose: None,
                interactive_hint: None,
            },
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.secret_step");

        // 进行中的任务不能删除。
        let err = task_delete(task.task.id.clone(), state.clone()).unwrap_err();
        assert_eq!(err.code, "task.delete_active");

        // 同一会话只允许一个进行中任务。
        let err = create_task(
            task_input(&host.id, "sess_ipc_1", vec![step_input("uptime")]),
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.session_busy");

        // R2 步骤只能手动执行。
        let err = task_step_started(
            task.task.id.clone(),
            task.steps[2].id.clone(),
            None,
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.manual_step");

        let running = task_step_started(
            task.task.id.clone(),
            task.steps[0].id.clone(),
            Some(true),
            state.clone(),
        )
        .unwrap();
        assert_eq!(running.task.status, "running");
        assert_eq!(running.steps[0].status, "running");
        assert!(running.steps[0].audit_seq.is_some());
        let err = task_step_update(
            TaskStepUpdateInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[0].id.clone(),
                command: "date".into(),
                purpose: None,
                interactive_hint: None,
            },
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");

        // 前一步运行中，不能启动后面的步骤。
        let err = task_step_started(
            task.task.id.clone(),
            task.steps[1].id.clone(),
            None,
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.out_of_order");

        let finished = task_step_finished(
            TaskStepFinishedInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[0].id.clone(),
                exit_code: Some(0),
                output_tail: "nginx: configuration test is successful\npassword=hunter2".into(),
                status: None,
            },
            state.clone(),
        )
        .unwrap();
        assert_eq!(finished.task.status, "waiting_user");
        assert_eq!(finished.steps[0].status, "succeeded");
        assert!(!finished.steps[0].output_tail_redacted.contains("hunter2"));
        assert!(finished.steps[0]
            .output_tail_redacted
            .contains("successful"));

        task_step_started(
            task.task.id.clone(),
            task.steps[1].id.clone(),
            None,
            state.clone(),
        )
        .unwrap();
        let failed = task_step_finished(
            TaskStepFinishedInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[1].id.clone(),
                exit_code: Some(7),
                output_tail: "curl: (7) Failed to connect".into(),
                status: None,
            },
            state.clone(),
        )
        .unwrap();
        assert_eq!(failed.task.status, "paused_failed");
        assert_eq!(failed.task.failure_count, 1);

        let retried = task_step_retry(
            task.task.id.clone(),
            task.steps[1].id.clone(),
            state.clone(),
        )
        .unwrap();
        assert_eq!(retried.task.status, "waiting_user");
        assert_eq!(retried.steps[1].status, "ready");

        let skipped = task_step_skip(
            task.task.id.clone(),
            task.steps[1].id.clone(),
            state.clone(),
        )
        .unwrap();
        assert_eq!(skipped.task.status, "waiting_user");
        assert_eq!(skipped.steps[1].status, "skipped");

        // R2 步骤仍然只能人工完成。
        let manual = task_step_finished(
            TaskStepFinishedInput {
                task_id: task.task.id.clone(),
                step_id: task.steps[2].id.clone(),
                exit_code: None,
                output_tail: String::new(),
                status: Some("manual".into()),
            },
            state.clone(),
        )
        .unwrap();
        assert_eq!(manual.task.status, "waiting_user");
        assert_eq!(manual.steps[2].status, "manual");

        // Markdown 导出：包含脱敏命令/输出，不包含密码。
        let markdown = task_export_markdown(task.task.id.clone(), state.clone()).unwrap();
        assert!(markdown.contains("# 任务：检查并重载 nginx"));
        assert!(markdown.contains("nginx -t"));
        assert!(markdown.contains("configuration test is successful"));
        assert!(!markdown.contains("hunter2"));
        let export_path = dir.path().join("task-export.md");
        let export_path_string = export_path.to_string_lossy().to_string();
        assert_eq!(
            save_task_export(
                task.task.id.clone(),
                export_path_string.clone(),
                state.clone()
            )
            .unwrap(),
            export_path_string
        );
        assert_eq!(std::fs::read_to_string(&export_path).unwrap(), markdown);
        let err = save_task_export(
            task.task.id.clone(),
            dir.path().join("task.exe").to_string_lossy().to_string(),
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.export_invalid_path");
        let err = task_export_markdown("task_missing".into(), state.clone()).unwrap_err();
        assert_eq!(err.code, "task.not_found");

        let cancelled = task_cancel(task.task.id.clone(), state.clone()).unwrap();
        assert_eq!(cancelled.task.status, "cancelled");
        assert_eq!(
            task_get(task.task.id.clone(), state.clone())
                .unwrap()
                .unwrap(),
            cancelled
        );
        let listed = task_list(
            Some(host.id.clone()),
            Some("sess_ipc_1".into()),
            None,
            Some(10),
            state.clone(),
        )
        .unwrap();
        assert_eq!(listed.len(), 1);

        // 审计：事件类型齐全、步骤事件带 step_id、payload 不含原始密码。
        let types = audit_types_for(&state, &task.task.id);
        let type_set: HashSet<&str> = types.iter().map(String::as_str).collect();
        for expected in [
            "task.created",
            "task.plan_ready",
            "task.step_confirmed",
            "task.step_started",
            "task.step_finished",
            "task.step_failed",
            "task.step_retried",
            "task.step_skipped",
            "task.step_edited",
            "task.cancelled",
        ] {
            assert!(
                type_set.contains(expected),
                "missing audit event {expected}"
            );
        }
        let events = state.db.lock().unwrap().audit_events_all().unwrap();
        let task_events: Vec<_> = events
            .iter()
            .filter(|event| {
                event
                    .payload
                    .pointer("/_links/task_id")
                    .and_then(|value| value.as_str())
                    == Some(task.task.id.as_str())
            })
            .collect();
        for event in &task_events {
            if event.event_type.starts_with("task.step_") {
                assert!(
                    event
                        .payload
                        .pointer("/_links/step_id")
                        .and_then(|value| value.as_str())
                        .is_some(),
                    "step event missing step_id: {}",
                    event.event_type
                );
            }
        }
        assert!(
            task_events.iter().any(|event| {
                event.event_type == "task.step_confirmed"
                    && event.payload.get("auto").and_then(|value| value.as_bool()) == Some(true)
            }),
            "automatic step confirmation missing auto=true"
        );
        let serialized = serde_json::to_string(&task_events).unwrap();
        assert!(!serialized.contains("hunter2"), "audit leaked the secret");
        assert!(
            !serialized.contains("configuration test"),
            "audit stored raw output"
        );

        // 删除终态任务：任务/步骤消失，审计事件保留。
        task_delete(task.task.id.clone(), state.clone()).unwrap();
        assert!(task_get(task.task.id.clone(), state.clone())
            .unwrap()
            .is_none());
        assert!(task_list(
            Some(host.id.clone()),
            Some("sess_ipc_1".into()),
            None,
            Some(10),
            state.clone(),
        )
        .unwrap()
        .is_empty());
        let deleted_audit = state
            .db
            .lock()
            .unwrap()
            .audit_events_for_task(&task.task.id, 100)
            .unwrap();
        assert!(deleted_audit
            .iter()
            .any(|event| event.event_type == "task.deleted"));

        // 交互暂停 → 记为结果未知；再模拟中断恢复。
        make_session(&state, "sess_ipc_2", &host.id);
        let second = create_task(
            task_input(&host.id, "sess_ipc_2", vec![step_input("uptime")]),
            state.clone(),
        )
        .unwrap();
        task_step_started(
            second.task.id.clone(),
            second.steps[0].id.clone(),
            None,
            state.clone(),
        )
        .unwrap();
        let paused = task_step_interactive(
            second.task.id.clone(),
            second.steps[0].id.clone(),
            Some("password prompt".into()),
            state.clone(),
        )
        .unwrap();
        assert_eq!(paused.task.status, "paused_interactive");
        let unknown = task_step_finished(
            TaskStepFinishedInput {
                task_id: second.task.id.clone(),
                step_id: second.steps[0].id.clone(),
                exit_code: None,
                output_tail: String::new(),
                status: None,
            },
            state.clone(),
        )
        .unwrap();
        assert_eq!(unknown.task.status, "waiting_user");
        assert_eq!(unknown.steps[0].status, "sent");

        // running 但无 running step：属于“中断”，task_resume 应回到等待确认。
        state
            .db
            .lock()
            .unwrap()
            .set_task_status(&second.task.id, "running")
            .unwrap();
        let resumed = task_resume(second.task.id.clone(), state.clone()).unwrap();
        assert_eq!(resumed.task.status, "waiting_user");
        let err = task_delete(second.task.id.clone(), state.clone()).unwrap_err();
        assert_eq!(err.code, "task.delete_active");

        // 取消会唤醒等待中的模型判断（task_revise 的 select）。
        state
            .db
            .lock()
            .unwrap()
            .set_task_status(&second.task.id, "revising")
            .unwrap();
        let notify = std::sync::Arc::new(tokio::sync::Notify::new());
        state
            .revise_cancels
            .lock()
            .unwrap()
            .insert(second.task.id.clone(), notify.clone());
        task_cancel(second.task.id.clone(), state.clone()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(200), notify.notified())
                .await
                .expect("task_cancel must notify the revise waiter");
        });
        assert_eq!(
            task_get(second.task.id.clone(), state.clone())
                .unwrap()
                .unwrap()
                .task
                .status,
            "cancelled"
        );

        // 任务历史策略：保存/读取，再按数量清理两条终态任务中的一条。
        let defaults = load_task_history_settings(state.clone()).unwrap();
        assert_eq!(
            defaults.keep_days,
            crate::config::DEFAULT_TASK_HISTORY_KEEP_DAYS
        );
        assert_eq!(
            defaults.max_terminal,
            crate::config::DEFAULT_TASK_HISTORY_MAX_TERMINAL
        );
        let saved = save_task_history_settings(7, 50, state.clone()).unwrap();
        assert_eq!(saved.keep_days, 7);
        assert_eq!(
            load_task_history_settings(state.clone())
                .unwrap()
                .max_terminal,
            50
        );
        let err = save_task_history_settings(-1, 50, state.clone()).unwrap_err();
        assert_eq!(err.code, "config.task_history_invalid");

        make_session(&state, "sess_ipc_3", &host.id);
        let third = create_task(
            task_input(&host.id, "sess_ipc_3", vec![step_input("uptime")]),
            state.clone(),
        )
        .unwrap();
        task_cancel(third.task.id.clone(), state.clone()).unwrap();
        let report = task_history_prune(None, Some(0), Some(1), state.clone()).unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(report.remaining_terminal, 1);
        assert!(report.age_cutoff.is_none());
        assert!(task_get(second.task.id.clone(), state.clone())
            .unwrap()
            .is_none());
        assert!(task_get(third.task.id.clone(), state.clone())
            .unwrap()
            .is_some());
        let events = state.db.lock().unwrap().audit_events_all().unwrap();
        assert!(events
            .iter()
            .any(|event| event.event_type == "task.history_pruned"));

        // 审计链损坏时任务变更必须 fail-closed，不能先改状态再报错。
        state
            .audit_ok
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let err = task_cancel(third.task.id.clone(), state.clone()).unwrap_err();
        assert_eq!(err.code, "audit.integrity");
        state
            .audit_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // 主机/会话归属与不存在对象的错误路径。
        let other_host = make_host(&state, "db-ipc");
        let err = create_task(
            task_input(&other_host.id, "sess_ipc_1", vec![step_input("uptime")]),
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.session_mismatch");
        let err = create_task(
            task_input(&other_host.id, "sess_missing", vec![step_input("uptime")]),
            state.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code, "task.session_not_found");
        assert!(task_get("task_missing".into(), state.clone())
            .unwrap()
            .is_none());
        let err = task_cancel("task_missing".into(), state.clone()).unwrap_err();
        assert_eq!(err.code, "task.not_found");
    }
}
