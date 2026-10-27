//! ShellWarden 本地存储层：SQLite schema、迁移与仓储。
//!
//! 通用命令模式保留主机、会话、审计、终端命令、凭据与设置；
//! 任务模式增加 `tasks` / `task_steps` 两张表与状态机。

mod task;
pub use task::{
    is_active_task_status, is_terminal_task_status, step_transition_allowed, task_elapsed_secs,
    task_transition_allowed, valid_step_status, valid_task_status, NewTask, NewTaskBatch,
    NewTaskStep, TaskBatchRow, TaskPruneReport, TaskRow, TaskStepEdit, TaskStepRow, TaskWithSteps,
    ACTIVE_TASK_STATUSES, DEFAULT_STEP_LIMIT, MAX_TASK_STEPS, STEP_STATUSES, TASK_STATUSES,
    TASK_TIMEOUT_SECS,
};

use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use shellwarden_core::audit::AuditEvent;
use shellwarden_core::digest::sha256_hex;
use shellwarden_core::error::{AppError, Result};
use shellwarden_core::ids::new_id;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_credentials.sql")),
    (3, include_str!("../migrations/0003_approval_lifecycle.sql")),
    (4, include_str!("../migrations/0004_reauth.sql")),
    (5, include_str!("../migrations/0005_terminal_commands.sql")),
    (6, include_str!("../migrations/0006_drop_legacy.sql")),
    (
        7,
        include_str!("../migrations/0007_drop_unused_host_column.sql"),
    ),
    (
        8,
        include_str!("../migrations/0008_private_keys_and_groups.sql"),
    ),
    (9, include_str!("../migrations/0009_host_key_auth.sql")),
    (10, include_str!("../migrations/0010_task_mode.sql")),
    (11, include_str!("../migrations/0011_task_batches.sql")),
];

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub default_username: String,
    pub tags: Vec<String>,
    pub ssh_backend: String,
    pub group_name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NewHost {
    pub name: String,
    pub hostname: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub default_username: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_backend")]
    pub ssh_backend: String,
    #[serde(default)]
    pub group_name: String,
}

fn default_port() -> u16 {
    22
}

fn default_backend() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct TerminalCommandRow {
    pub id: String,
    pub session_id: String,
    pub host_id: Option<String>,
    pub command_redacted: String,
    pub exit_code: Option<i64>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: i64,
    pub state_unknown: bool,
}

pub type StoredPrivateKey = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);

#[derive(Debug, Clone)]
pub struct KeyAuthRow {
    pub mode: String,
    pub key_path: Option<String>,
    pub passphrase_ciphertext: Option<Vec<u8>>,
    pub passphrase_nonce: Option<Vec<u8>>,
}

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(sql_err)?;
        Self::finish(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(sql_err)?;
        Self::finish(conn)
    }

    fn finish(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(sql_err)?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn migrate(&mut self) -> Result<()> {
        let current: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql_err)?;

        if current > 0 {
            self.verify_migration_checksums()?;
        }

        for (version, sql) in MIGRATIONS {
            if *version <= current {
                continue;
            }
            let tx = self.conn.transaction().map_err(sql_err)?;
            tx.execute_batch(sql).map_err(sql_err)?;
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_at, checksum) VALUES (?1, ?2, ?3)",
                params![version, now(), sha256_hex(sql.as_bytes())],
            )
            .map_err(sql_err)?;
            tx.pragma_update(None, "user_version", version)
                .map_err(sql_err)?;
            tx.commit().map_err(sql_err)?;
            tracing::info!(version, "applied migration");
        }

        self.verify_migration_checksums()?;
        Ok(())
    }

    fn verify_migration_checksums(&self) -> Result<()> {
        for (version, sql) in MIGRATIONS {
            let stored: Option<String> = self
                .conn
                .query_row(
                    "SELECT checksum FROM schema_migrations WHERE version = ?1",
                    params![version],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            if let Some(stored) = stored {
                let actual = sha256_hex(sql.as_bytes());
                if stored != actual {
                    return Err(AppError::new(
                        "store.migration_checksum",
                        format!("迁移 {version} 的校验和不匹配：数据库可能来自不同版本"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql_err)
    }

    // ---- hosts -----------------------------------------------------------

    pub fn create_host(&self, input: NewHost) -> Result<Host> {
        let name = input.name.trim();
        let hostname = input.hostname.trim();
        if name.is_empty() {
            return Err(invalid_input("主机名（显示名）不能为空"));
        }
        if hostname.is_empty() {
            return Err(invalid_input("hostname 不能为空"));
        }
        if input.port == 0 {
            return Err(invalid_input("端口必须在 1-65535 之间"));
        }
        let exists: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM hosts WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if exists.is_some() {
            return Err(AppError::new(
                "store.host.duplicate",
                format!("主机显示名已存在: {name}"),
            ));
        }

        let id = new_id("host");
        let ts = now();
        let tags = serde_json::to_string(&input.tags).unwrap_or_else(|_| "[]".into());
        self.conn
            .execute(
                "INSERT INTO hosts
                   (id, name, hostname, port, default_username, tags_json, ssh_backend,
                    group_name, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    id,
                    name,
                    hostname,
                    input.port,
                    input.default_username.trim(),
                    tags,
                    input.ssh_backend,
                    input.group_name.trim(),
                    ts
                ],
            )
            .map_err(sql_err)?;
        self.get_host(&id)?
            .ok_or_else(|| AppError::new("store.host.missing", "刚创建的主机读不回来"))
    }

    pub fn update_host(&self, id: &str, input: &NewHost) -> Result<Host> {
        let name = input.name.trim();
        let hostname = input.hostname.trim();
        if name.is_empty() {
            return Err(invalid_input("主机名（显示名）不能为空"));
        }
        if hostname.is_empty() {
            return Err(invalid_input("hostname 不能为空"));
        }
        if input.port == 0 {
            return Err(invalid_input("端口必须在 1-65535 之间"));
        }
        if self.get_host(id)?.is_none() {
            return Err(AppError::new("store.host.missing", "主机不存在"));
        }
        let conflict: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM hosts WHERE name = ?1 AND id != ?2",
                params![name, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if conflict.is_some() {
            return Err(AppError::new(
                "store.host.duplicate",
                format!("主机显示名已存在: {name}"),
            ));
        }

        let tags = serde_json::to_string(&input.tags).unwrap_or_else(|_| "[]".into());
        self.conn
            .execute(
                "UPDATE hosts SET
                   name = ?2, hostname = ?3, port = ?4, default_username = ?5, tags_json = ?6,
                   ssh_backend = ?7, group_name = ?8, updated_at = ?9
                 WHERE id = ?1",
                params![
                    id,
                    name,
                    hostname,
                    input.port,
                    input.default_username.trim(),
                    tags,
                    input.ssh_backend,
                    input.group_name.trim(),
                    now()
                ],
            )
            .map_err(sql_err)?;
        self.get_host(id)?
            .ok_or_else(|| AppError::new("store.host.missing", "更新后主机读不回来"))
    }

    pub fn list_hosts(&self) -> Result<Vec<Host>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, hostname, port, default_username, tags_json, ssh_backend,
                        group_name, created_at, updated_at
                 FROM hosts ORDER BY group_name COLLATE NOCASE, name COLLATE NOCASE",
            )
            .map_err(sql_err)?;
        let rows = stmt.query_map([], host_from_row).map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    pub fn get_host(&self, id: &str) -> Result<Option<Host>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, hostname, port, default_username, tags_json, ssh_backend,
                        group_name, created_at, updated_at
                 FROM hosts WHERE id = ?1",
            )
            .map_err(sql_err)?;
        stmt.query_row(params![id], host_from_row)
            .optional()
            .map_err(sql_err)
    }

    pub fn delete_host(&self, id: &str) -> Result<bool> {
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "DELETE FROM terminal_commands WHERE session_id IN
                (SELECT id FROM sessions WHERE host_id = ?1)",
            params![id],
        )
        .map_err(sql_err)?;
        tx.execute("DELETE FROM sessions WHERE host_id = ?1", params![id])
            .map_err(sql_err)?;
        let affected = tx
            .execute("DELETE FROM hosts WHERE id = ?1", params![id])
            .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(affected > 0)
    }

    // ---- audit -----------------------------------------------------------

    pub fn insert_audit_event(&self, event: &AuditEvent) -> Result<()> {
        self.insert_audit_event_linked(event, None, None, None, None)
    }

    pub fn insert_audit_event_linked(
        &self,
        event: &AuditEvent,
        host_id: Option<&str>,
        session_id: Option<&str>,
        task_id: Option<&str>,
        step_id: Option<&str>,
    ) -> Result<()> {
        let payload = serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".into());
        self.conn
            .execute(
                "INSERT INTO audit_events
                   (id, seq, event_type, timestamp, chain_segment, host_id, session_id, task_id,
                    step_id, approval_id, policy_version, tool_version, context_id, plan_digest,
                    actor, payload_redacted_json, previous_hash, event_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                         ?17, ?18)",
                params![
                    event.event_id,
                    event.seq as i64,
                    event.event_type,
                    event.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
                    event.chain_segment,
                    host_id,
                    session_id,
                    task_id,
                    step_id,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    event.actor,
                    payload,
                    event.previous_hash,
                    event.event_hash
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn count_audit_events(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .map_err(sql_err)
    }

    pub fn audit_events(&self, limit: u32) -> Result<Vec<AuditEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, seq, event_type, timestamp, chain_segment, actor,
                        payload_redacted_json, previous_hash, event_hash
                 FROM audit_events ORDER BY seq ASC LIMIT ?1",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![limit], audit_event_from_row)
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    pub fn audit_events_for_session(
        &self,
        session_id: &str,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, seq, event_type, timestamp, chain_segment, actor,
                        payload_redacted_json, previous_hash, event_hash
                 FROM audit_events WHERE session_id = ?1 ORDER BY seq ASC LIMIT ?2",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![session_id, limit], audit_event_from_row)
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    /// 任务相关审计（按 task_id 列；任务删除后事件仍保留）。
    pub fn audit_events_for_task(&self, task_id: &str, limit: u32) -> Result<Vec<AuditEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, seq, event_type, timestamp, chain_segment, actor,
                        payload_redacted_json, previous_hash, event_hash
                 FROM audit_events WHERE task_id = ?1 ORDER BY seq ASC LIMIT ?2",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![task_id, limit], audit_event_from_row)
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    pub fn audit_events_all(&self) -> Result<Vec<AuditEvent>> {
        self.audit_events(u32::MAX)
    }

    // ---- settings --------------------------------------------------------

    pub fn set_setting(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![key, serde_json::to_string(value).unwrap(), now()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn delete_setting(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", params![key])
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub fn table_count(&self) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(sql_err)
    }

    // ---- host keys -------------------------------------------------------

    pub fn upsert_host_key(&self, host_id: &str, algorithm: &str, fingerprint: &str) -> Result<()> {
        let ts = now();
        self.conn
            .execute(
                "INSERT INTO host_keys
                   (id, host_id, hop_index, algorithm, fingerprint, first_seen_at, last_seen_at, trust_state)
                 VALUES (?1, ?2, 0, ?3, ?4, ?5, ?5, 'trusted')
                 ON CONFLICT(host_id, hop_index, algorithm, fingerprint) DO UPDATE SET
                   last_seen_at = excluded.last_seen_at,
                   trust_state = excluded.trust_state",
                params![new_id("hk"), host_id, algorithm, fingerprint, ts],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    // ---- sessions --------------------------------------------------------

    pub fn insert_session(
        &self,
        id: &str,
        host_id: &str,
        identity_id: Option<&str>,
        backend: &str,
        started_at: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO sessions(id, host_id, identity_id, backend, started_at, recording_enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![id, host_id, identity_id, backend, started_at],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn end_session(&self, id: &str, reason: &str, ended_at: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute(
                "UPDATE sessions SET ended_at = ?2, disconnect_reason = ?3
                 WHERE id = ?1 AND ended_at IS NULL",
                params![id, ended_at, reason],
            )
            .map_err(sql_err)?;
        Ok(affected > 0)
    }

    pub fn session_host_id(&self, session_id: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT host_id FROM sessions WHERE id = ?1",
                params![session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sql_err)
    }

    // ---- terminal commands ----------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn insert_terminal_command(
        &self,
        session_id: &str,
        host_id: Option<&str>,
        command_redacted: &str,
        exit_code: Option<i64>,
        started_at: &str,
        finished_at: &str,
        duration_ms: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO terminal_commands
                   (id, session_id, host_id, command_redacted, exit_code,
                    started_at, finished_at, duration_ms, state_unknown)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                params![
                    new_id("tcmd"),
                    session_id,
                    host_id,
                    command_redacted,
                    exit_code,
                    started_at,
                    finished_at,
                    duration_ms
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn terminal_commands_for_session(
        &self,
        session_id: &str,
        limit: u32,
    ) -> Result<Vec<TerminalCommandRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, session_id, host_id, command_redacted, exit_code,
                        started_at, finished_at, duration_ms, state_unknown
                 FROM terminal_commands WHERE session_id = ?1
                 ORDER BY started_at ASC LIMIT ?2",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![session_id, limit], |row| {
                Ok(TerminalCommandRow {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    host_id: row.get(2)?,
                    command_redacted: row.get(3)?,
                    exit_code: row.get(4)?,
                    started_at: row.get(5)?,
                    finished_at: row.get(6)?,
                    duration_ms: row.get(7)?,
                    state_unknown: row.get::<_, i64>(8)? != 0,
                })
            })
            .map_err(sql_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)?;
        Ok(rows)
    }

    // ---- key auth (path/passphrase) -------------------------------------

    pub fn save_key_auth(
        &self,
        host_id: &str,
        mode: &str,
        key_path: Option<&str>,
        passphrase: Option<(&[u8], &[u8])>,
    ) -> Result<()> {
        if mode != "file" && mode != "pem" {
            return Err(AppError::new("store.invalid_input", "未知私钥凭据模式"));
        }
        let (pass_ct, pass_nonce) = match passphrase {
            Some((ct, nonce)) => (Some(ct), Some(nonce)),
            None => (None, None),
        };
        self.conn
            .execute(
                "INSERT INTO host_key_auth
                   (host_id, mode, key_path, passphrase_ciphertext, passphrase_nonce, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(host_id) DO UPDATE SET
                   mode = excluded.mode,
                   key_path = excluded.key_path,
                   passphrase_ciphertext = excluded.passphrase_ciphertext,
                   passphrase_nonce = excluded.passphrase_nonce,
                   updated_at = excluded.updated_at",
                params![host_id, mode, key_path, pass_ct, pass_nonce, now()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn load_key_auth(&self, host_id: &str) -> Result<Option<KeyAuthRow>> {
        self.conn
            .query_row(
                "SELECT mode, key_path, passphrase_ciphertext, passphrase_nonce
                 FROM host_key_auth WHERE host_id = ?1",
                params![host_id],
                |row| {
                    Ok(KeyAuthRow {
                        mode: row.get(0)?,
                        key_path: row.get(1)?,
                        passphrase_ciphertext: row.get(2)?,
                        passphrase_nonce: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(sql_err)
    }

    pub fn delete_key_auth(&self, host_id: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM host_key_auth WHERE host_id = ?1",
                params![host_id],
            )
            .map_err(sql_err)?;
        Ok(affected > 0)
    }

    // ---- private keys ---------------------------------------------------

    pub fn save_private_key(
        &self,
        host_id: &str,
        ciphertext: &[u8],
        nonce: &[u8],
        passphrase: Option<(&[u8], &[u8])>,
    ) -> Result<()> {
        let (pass_ct, pass_nonce) = match passphrase {
            Some((ct, nonce)) => (Some(ct), Some(nonce)),
            None => (None, None),
        };
        self.conn
            .execute(
                "INSERT INTO host_private_keys
                   (host_id, ciphertext, nonce, passphrase_ciphertext, passphrase_nonce, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(host_id) DO UPDATE SET
                   ciphertext = excluded.ciphertext,
                   nonce = excluded.nonce,
                   passphrase_ciphertext = excluded.passphrase_ciphertext,
                   passphrase_nonce = excluded.passphrase_nonce,
                   updated_at = excluded.updated_at",
                params![host_id, ciphertext, nonce, pass_ct, pass_nonce, now()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn load_private_key(&self, host_id: &str) -> Result<Option<StoredPrivateKey>> {
        self.conn
            .query_row(
                "SELECT ciphertext, nonce, passphrase_ciphertext, passphrase_nonce
                 FROM host_private_keys WHERE host_id = ?1",
                params![host_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sql_err)
    }

    pub fn delete_private_key(&self, host_id: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM host_private_keys WHERE host_id = ?1",
                params![host_id],
            )
            .map_err(sql_err)?;
        Ok(affected > 0)
    }

    // ---- credentials -----------------------------------------------------

    pub fn save_credential(&self, host_id: &str, ciphertext: &[u8], nonce: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO host_credentials(host_id, ciphertext, nonce, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(host_id) DO UPDATE SET
                   ciphertext = excluded.ciphertext,
                   nonce = excluded.nonce,
                   updated_at = excluded.updated_at",
                params![host_id, ciphertext, nonce, now()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn load_credential(&self, host_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.conn
            .query_row(
                "SELECT ciphertext, nonce FROM host_credentials WHERE host_id = ?1",
                params![host_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(sql_err)
    }

    pub fn delete_credential(&self, host_id: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM host_credentials WHERE host_id = ?1",
                params![host_id],
            )
            .map_err(sql_err)?;
        Ok(affected > 0)
    }
}

fn host_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Host> {
    let tags_json: String = row.get(5)?;
    Ok(Host {
        id: row.get(0)?,
        name: row.get(1)?,
        hostname: row.get(2)?,
        port: row.get(3)?,
        default_username: row.get(4)?,
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        ssh_backend: row.get(6)?,
        group_name: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn audit_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
    let payload: String = row.get(6)?;
    let ts: String = row.get(3)?;
    let timestamp = DateTime::parse_from_rfc3339(&ts)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    Ok(AuditEvent {
        event_id: row.get(0)?,
        seq: row.get::<_, i64>(1)? as u64,
        event_type: row.get(2)?,
        timestamp,
        chain_segment: row.get::<_, i64>(4)? as u32,
        actor: row.get(5)?,
        payload: serde_json::from_str(&payload).unwrap_or_default(),
        previous_hash: row.get(7)?,
        event_hash: row.get(8)?,
    })
}

fn invalid_input(message: impl Into<String>) -> AppError {
    AppError::new("store.invalid_input", message)
}

fn sql_err(error: rusqlite::Error) -> AppError {
    AppError::new("store.sqlite", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> NewHost {
        NewHost {
            name: name.into(),
            hostname: "127.0.0.1".into(),
            port: 22,
            default_username: "ops".into(),
            tags: vec!["test".into()],
            ssh_backend: "auto".into(),
            group_name: "test".into(),
        }
    }

    #[test]
    fn host_crud_and_terminal_commands() {
        let db = Db::open_in_memory().unwrap();
        let created = db.create_host(host("web")).unwrap();
        assert_eq!(db.list_hosts().unwrap().len(), 1);
        db.insert_session("sess_1", &created.id, None, "auto", &now())
            .unwrap();
        db.insert_terminal_command(
            "sess_1",
            Some(&created.id),
            "date",
            Some(0),
            &now(),
            &now(),
            1,
        )
        .unwrap();
        assert_eq!(
            db.terminal_commands_for_session("sess_1", 10)
                .unwrap()
                .len(),
            1
        );
        assert!(db.delete_host(&created.id).unwrap());
        assert!(db.list_hosts().unwrap().is_empty());
    }

    #[test]
    fn private_key_and_group_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let created = db.create_host(host("web")).unwrap();
        assert_eq!(created.group_name, "test");
        db.save_private_key(
            &created.id,
            b"ciphertext",
            b"nonce",
            Some((b"pass-ciphertext".as_slice(), b"pass-nonce".as_slice())),
        )
        .unwrap();
        let (ct, nonce, pass_ct, pass_nonce) = db.load_private_key(&created.id).unwrap().unwrap();
        assert_eq!(ct, b"ciphertext");
        assert_eq!(nonce, b"nonce");
        assert_eq!(pass_ct.unwrap(), b"pass-ciphertext");
        assert_eq!(pass_nonce.unwrap(), b"pass-nonce");
        assert!(db.delete_private_key(&created.id).unwrap());
        assert!(db.load_private_key(&created.id).unwrap().is_none());
    }

    #[test]
    fn key_auth_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let created = db.create_host(host("web")).unwrap();
        db.save_key_auth(
            &created.id,
            "file",
            Some("/home/ops/.ssh/id_ed25519"),
            Some((b"pass-ciphertext".as_slice(), b"pass-nonce".as_slice())),
        )
        .unwrap();
        let row = db.load_key_auth(&created.id).unwrap().unwrap();
        assert_eq!(row.mode, "file");
        assert_eq!(row.key_path.as_deref(), Some("/home/ops/.ssh/id_ed25519"));
        assert_eq!(row.passphrase_ciphertext.unwrap(), b"pass-ciphertext");
        assert!(db.delete_key_auth(&created.id).unwrap());
        assert!(db.load_key_auth(&created.id).unwrap().is_none());
    }

    #[test]
    fn legacy_tables_are_dropped() {
        let db = Db::open_in_memory().unwrap();
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
                 ('ai_tasks','approvals','grants','policy_profiles','tools')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
