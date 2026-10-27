mod commands;
mod config;
mod data_dir;
mod secret;
mod shell_integration;
mod state;

use std::sync::Mutex;

use tauri::Manager;
use tracing_subscriber::EnvFilter;

use shellwarden_ssh::KnownHostsStore;
use shellwarden_store::Db;
use state::{AppState, SshState};

struct ConfigLocation {
    path: std::path::PathBuf,
    portable: bool,
}

fn dir_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".shellwarden-write-test");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn exe_dir() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
}

/// 配置优先级：SHELLWARDEN_CONFIG > exe 同目录 config.toml >
/// 当前目录 config.toml > 已有 OS app_config_dir > portable exe 目录 > OS app_config_dir。
///
/// 新装/便携启动时优先把 config.toml 放到可写的 exe 目录；macOS .app 包、
/// Program Files 等不可写位置会回退到系统配置目录。
fn resolve_config_path(
    app: &tauri::AppHandle,
) -> Result<ConfigLocation, Box<dyn std::error::Error>> {
    if let Some(path) = std::env::var_os("SHELLWARDEN_CONFIG") {
        return Ok(ConfigLocation {
            path: std::path::PathBuf::from(path),
            portable: false,
        });
    }
    let app_config = app.path().app_config_dir()?.join("config.toml");
    if let Some(dir) = exe_dir() {
        let candidate = dir.join("config.toml");
        if candidate.exists() {
            return Ok(ConfigLocation {
                path: candidate,
                portable: true,
            });
        }
    }
    let cwd = std::path::PathBuf::from("config.toml");
    if cwd.exists() {
        return Ok(ConfigLocation {
            path: cwd,
            portable: true,
        });
    }
    if app_config.exists() {
        return Ok(ConfigLocation {
            path: app_config,
            portable: false,
        });
    }
    if let Some(dir) = exe_dir() {
        let is_macos_bundle =
            cfg!(target_os = "macos") && dir.to_string_lossy().contains(".app/Contents/MacOS");
        if !is_macos_bundle && dir_writable(&dir) {
            return Ok(ConfigLocation {
                path: dir.join("config.toml"),
                portable: true,
            });
        }
    }
    Ok(ConfigLocation {
        path: app_config,
        portable: false,
    })
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,shellwarden=debug")),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // 配置入口：SHELLWARDEN_CONFIG / portable config.toml / OS config dir。
            // 数据目录：SHELLWARDEN_DATA_DIR > config.storage.data_dir > OS app_data_dir。
            let location = resolve_config_path(app.handle())?;
            let config_path = location.path;
            let mut config =
                crate::config::AppConfig::load(&config_path).map_err(std::io::Error::other)?;
            let default_data_dir = app.path().app_data_dir()?;
            let env_data_dir = std::env::var_os("SHELLWARDEN_DATA_DIR");
            let data_dir = crate::data_dir::absolute(&match env_data_dir.as_ref() {
                Some(path) => std::path::PathBuf::from(path),
                None => config.resolved_data_dir(&config_path).unwrap_or_else(|| {
                    if location.portable {
                        config_path
                            .parent()
                            .map(crate::data_dir::absolute)
                            .unwrap_or(default_data_dir.clone())
                    } else {
                        default_data_dir.clone()
                    }
                }),
            });
            // 改了 config.toml 的 data_dir 后，把旧目录的 DB/密钥/known_hosts
            // 一起复制到新目录；source 保留作为备份。只有目标已有完整数据时才跳过。
            let previous = config
                .storage
                .last_data_dir
                .as_deref()
                .map(|path| crate::data_dir::absolute(std::path::Path::new(path)));
            let source = previous
                .or_else(|| (data_dir != default_data_dir).then_some(default_data_dir.clone()));
            if let Some(source) = source {
                if source != data_dir
                    && crate::data_dir::migrate_data_dir(&source, &data_dir)
                        .map_err(std::io::Error::other)?
                {
                    tracing::info!(
                        from = %source.display(),
                        to = %data_dir.display(),
                        "migrated local data directory"
                    );
                }
            }
            std::fs::create_dir_all(&data_dir)?;
            if env_data_dir.is_none() {
                let current = data_dir.to_string_lossy().to_string();
                if config.storage.last_data_dir.as_deref() != Some(current.as_str()) {
                    config.storage.last_data_dir = Some(current);
                }
            }

            let db_path = data_dir.join("shellwarden.db");
            tracing::info!(
                config = %config_path.display(),
                data = %data_dir.display(),
                db = %db_path.display(),
                "opening local configuration and database"
            );
            let db = Db::open(&db_path)?;
            // 旧版本把 model.base_url/model 写在 settings 表；一次性迁到配置。
            for (key, field) in [
                ("model.base_url", &mut config.model.base_url),
                ("model.model", &mut config.model.model),
            ] {
                if field.is_none() {
                    if let Some(value) = db
                        .get_setting(key)
                        .ok()
                        .flatten()
                        .and_then(|v| v.as_str().map(str::to_string))
                    {
                        *field = Some(value);
                    }
                }
                let _ = db.delete_setting(key);
            }
            config.ensure_defaults();
            config.save(&config_path).map_err(std::io::Error::other)?;

            let secrets = crate::secret::SecretBox::load_or_create(&data_dir)?;
            let known_hosts_path = data_dir.join("known_hosts.json");
            let known_hosts =
                KnownHostsStore::load(&known_hosts_path).map_err(std::io::Error::other)?;

            let existing = db.audit_events_all()?;
            let audit = shellwarden_core::audit::AuditChain::from_events(existing, 1000);
            let audit_ok = audit.verify().valid;
            if !audit_ok {
                tracing::error!(
                    "audit chain failed verification at startup; audit writes are now blocked"
                );
            }

            app.manage(AppState {
                db: Mutex::new(db),
                secrets,
                ssh: SshState::new(known_hosts),
                audit: Mutex::new(audit),
                audit_ok: std::sync::atomic::AtomicBool::new(audit_ok),
                config_path,
                data_dir,
                config: Mutex::new(config),
                revise_cancels: Mutex::new(std::collections::HashMap::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::open_config_dir,
            commands::save_shortcuts,
            commands::list_hosts,
            commands::create_host,
            commands::delete_host,
            commands::self_check,
            commands::probe_host,
            commands::trust_host,
            commands::open_session,
            commands::write_session,
            commands::enable_shell_integration,
            commands::resize_session,
            commands::close_session,
            commands::session_attach,
            commands::session_detach,
            commands::host_trust,
            commands::save_host_password,
            commands::delete_host_password,
            commands::host_private_key_status,
            commands::host_key_auth_status,
            commands::save_host_key_file,
            commands::save_host_private_key,
            commands::delete_host_key_auth,
            commands::delete_host_private_key,
            commands::host_credentials_status,
            commands::draft_command,
            commands::draft_task,
            commands::create_task,
            commands::task_get,
            commands::task_list,
            commands::create_task_batch,
            commands::task_batch_get,
            commands::task_batch_list_active,
            commands::task_batch_update,
            commands::task_batch_tasks,
            commands::task_bind_session,
            commands::save_batch_export,
            commands::task_step_started,
            commands::task_step_finished,
            commands::task_step_interactive,
            commands::task_step_skip,
            commands::task_step_retry,
            commands::task_revise,
            commands::task_resume,
            commands::task_cancel,
            commands::task_step_update,
            commands::task_delete,
            commands::task_export_markdown,
            commands::save_task_export,
            commands::task_history_prune,
            commands::load_task_history_settings,
            commands::save_task_history_settings,
            commands::audit_ai_command,
            commands::session_audit,
            commands::record_terminal_command,
            commands::terminal_commands,
            commands::update_host,
            commands::load_model_provider,
            commands::save_model_provider,
            commands::classify_input,
            commands::command_exists,
        ])
        .run(tauri::generate_context!())
        .expect("ShellWarden failed to start");
}
