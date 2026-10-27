//! 任务与步骤仓储 + 状态机（任务模式阶段 1/2）。
//!
//! 设计要点：
//! - 状态转移只在这里校验，IPC 层不重复实现；
//! - 任务的步骤数受 `step_limit` 与 `MAX_TASK_STEPS` 双重约束；
//! - 命令与输出只存脱敏文本，输出只存尾部；
//! - `finish_step` 同时更新步骤与任务，避免中途失败留下“步骤已结束、任务仍在跑”。

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use shellwarden_core::error::{AppError, Result};
use shellwarden_core::ids::new_id;

use crate::{now, sql_err, Db};

/// 任务总步数上限（计划建议 8）。
pub const MAX_TASK_STEPS: i64 = 8;
pub const DEFAULT_STEP_LIMIT: i64 = 8;
/// 任务总时长上限（计划建议 10 分钟）。
pub const TASK_TIMEOUT_SECS: i64 = 600;
const MAX_STEP_COMMAND_CHARS: usize = 2_000;
const MAX_OUTPUT_TAIL_CHARS: usize = 16_000;

pub const TASK_STATUSES: &[&str] = &[
    "draft",
    "plan_ready",
    "waiting_user",
    "running",
    "revising",
    "paused_failed",
    "paused_interactive",
    "completed",
    "failed",
    "cancelled",
];

pub const STEP_STATUSES: &[&str] = &[
    "pending",
    "ready",
    "running",
    "succeeded",
    "failed",
    "sent",
    "skipped",
    "manual",
];

pub const ACTIVE_TASK_STATUSES: &[&str] = &[
    "draft",
    "plan_ready",
    "waiting_user",
    "running",
    "revising",
    "paused_failed",
    "paused_interactive",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskRow {
    pub id: String,
    pub host_id: String,
    pub session_id: Option<String>,
    pub batch_id: Option<String>,
    pub goal_redacted: String,
    pub title: String,
    pub summary: String,
    pub outcome_summary: String,
    pub status: String,
    pub step_limit: i64,
    /// 连续失败次数；任一步成功即清零。达到 2 时任务直接 failed。
    pub failure_count: i64,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskStepRow {
    pub id: String,
    pub task_id: String,
    pub ordinal: i64,
    pub command_redacted: String,
    pub purpose: String,
    pub risk: String,
    pub status: String,
    pub exit_code: Option<i64>,
    pub output_tail_redacted: String,
    pub interactive_hint: bool,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub audit_seq: Option<i64>,
}

/// 任务详情：任务字段平铺 + 按 ordinal 排序的步骤。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskWithSteps {
    #[serde(flatten)]
    pub task: TaskRow,
    pub steps: Vec<TaskStepRow>,
}

#[derive(Debug, Clone)]
pub struct NewTaskStep {
    pub command_redacted: String,
    pub purpose: String,
    pub risk: String,
    pub status: String,
    pub interactive_hint: bool,
}

impl NewTaskStep {
    pub fn new(
        command_redacted: impl Into<String>,
        purpose: impl Into<String>,
        risk: &str,
    ) -> Self {
        Self {
            command_redacted: command_redacted.into(),
            purpose: purpose.into(),
            risk: risk.to_string(),
            status: "pending".into(),
            interactive_hint: false,
        }
    }

    pub fn with_status(mut self, status: &str) -> Self {
        self.status = status.to_string();
        self
    }

    pub fn with_interactive(mut self, interactive: bool) -> Self {
        self.interactive_hint = interactive;
        self
    }
}

#[derive(Debug, Clone)]
pub struct NewTask {
    pub host_id: String,
    pub session_id: Option<String>,
    pub batch_id: Option<String>,
    pub goal_redacted: String,
    pub title: String,
    pub summary: String,
    pub step_limit: i64,
    pub steps: Vec<NewTaskStep>,
}

/// 编辑未执行步骤时由 IPC 重新评估后写入的字段。
#[derive(Debug, Clone)]
pub struct TaskStepEdit {
    pub command_redacted: String,
    pub purpose: String,
    pub risk: String,
    pub interactive_hint: bool,
}

/// 批量任务批次；每台主机对应一条独立 `tasks`。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskBatchRow {
    pub id: String,
    pub goal_redacted: String,
    pub title: String,
    pub host_ids: Vec<String>,
    pub status: String,
    pub current_index: i64,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewTaskBatch {
    pub goal_redacted: String,
    pub title: String,
    pub host_ids: Vec<String>,
}

/// 任务历史清理结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskPruneReport {
    pub deleted: i64,
    pub remaining_terminal: i64,
    /// 按时间清理时的截止时间；仅按数量清理时为 None。
    pub age_cutoff: Option<String>,
}

pub fn valid_task_status(status: &str) -> bool {
    TASK_STATUSES.contains(&status)
}

pub fn valid_step_status(status: &str) -> bool {
    STEP_STATUSES.contains(&status)
}

pub fn is_terminal_task_status(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

pub fn is_active_task_status(status: &str) -> bool {
    ACTIVE_TASK_STATUSES.contains(&status)
}

pub fn task_transition_allowed(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    match from {
        "draft" => matches!(to, "plan_ready" | "cancelled"),
        "plan_ready" => matches!(
            to,
            "waiting_user" | "running" | "completed" | "cancelled" | "failed"
        ),
        "waiting_user" => matches!(
            to,
            "running" | "revising" | "completed" | "cancelled" | "failed"
        ),
        "running" => matches!(
            to,
            "waiting_user"
                | "revising"
                | "paused_failed"
                | "paused_interactive"
                | "completed"
                | "failed"
                | "cancelled"
        ),
        "revising" => matches!(
            to,
            "waiting_user"
                | "running"
                | "completed"
                | "paused_failed"
                | "paused_interactive"
                | "cancelled"
                | "failed"
        ),
        "paused_failed" => matches!(
            to,
            "running" | "revising" | "waiting_user" | "cancelled" | "failed"
        ),
        "paused_interactive" => matches!(to, "running" | "waiting_user" | "cancelled" | "failed"),
        _ => false,
    }
}

pub fn step_transition_allowed(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    match from {
        "pending" => matches!(to, "ready" | "running" | "skipped" | "manual"),
        "ready" => matches!(to, "running" | "skipped" | "manual"),
        "running" => matches!(to, "succeeded" | "failed" | "sent" | "skipped" | "manual"),
        "sent" => matches!(to, "succeeded" | "failed" | "skipped" | "manual"),
        "failed" => matches!(to, "ready" | "running" | "skipped"),
        _ => false,
    }
}

/// 任务创建后经过的秒数；时间戳异常时返回 0（不阻止用户操作）。
pub fn task_elapsed_secs(created_at: &str) -> i64 {
    DateTime::parse_from_rfc3339(created_at)
        .map(|start| {
            (Utc::now() - start.with_timezone(&Utc))
                .num_seconds()
                .max(0)
        })
        .unwrap_or(0)
}

fn ensure_task_transition(from: &str, to: &str) -> Result<()> {
    if task_transition_allowed(from, to) {
        return Ok(());
    }
    Err(AppError::new(
        "task.invalid_transition",
        format!("任务状态不能从 {from} 转到 {to}"),
    ))
}

fn ensure_step_transition(from: &str, to: &str) -> Result<()> {
    if step_transition_allowed(from, to) {
        return Ok(());
    }
    Err(AppError::new(
        "task.invalid_transition",
        format!("任务步骤不能从 {from} 转到 {to}"),
    ))
}

fn validate_task_step(step: &NewTaskStep) -> Result<()> {
    let command = step.command_redacted.trim();
    if command.is_empty() {
        return Err(invalid("任务步骤命令不能为空"));
    }
    if command.chars().count() > MAX_STEP_COMMAND_CHARS {
        return Err(invalid(format!(
            "任务步骤命令超过 {MAX_STEP_COMMAND_CHARS} 字符"
        )));
    }
    if command.contains('\n') || command.contains('\r') {
        return Err(invalid("任务步骤必须是单行命令"));
    }
    if !matches!(step.risk.as_str(), "R0" | "R1" | "R2" | "R3") {
        return Err(invalid(format!("未知风险等级: {}", step.risk)));
    }
    if !valid_step_status(&step.status) {
        return Err(invalid(format!("未知步骤状态: {}", step.status)));
    }
    if step.risk != "R0" && step.risk != "R1" && step.status == "skipped" {
        return Err(AppError::new(
            "task.skip_not_allowed",
            "只有 R0/R1 步骤可以跳过",
        ));
    }
    if step.purpose.chars().count() > 400 {
        return Err(invalid("任务步骤说明超过 400 字符"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::new("store.invalid_input", message)
}

impl Db {
    pub fn create_task(&self, input: NewTask) -> Result<TaskWithSteps> {
        let title = input.title.trim();
        let goal = input.goal_redacted.trim();
        let summary = input.summary.trim();
        if title.is_empty() {
            return Err(invalid("任务标题不能为空"));
        }
        if goal.is_empty() {
            return Err(invalid("任务目标不能为空"));
        }
        if title.chars().count() > 200 {
            return Err(invalid("任务标题超过 200 字符"));
        }
        if !(1..=MAX_TASK_STEPS).contains(&input.step_limit) {
            return Err(invalid(format!(
                "step_limit 必须在 1-{MAX_TASK_STEPS} 之间"
            )));
        }
        if input.steps.is_empty() {
            return Err(invalid("任务至少需要 1 个步骤"));
        }
        if input.steps.len() as i64 > input.step_limit {
            return Err(AppError::new(
                "task.step_limit",
                format!(
                    "任务计划 {} 步，超过预算 {}",
                    input.steps.len(),
                    input.step_limit
                ),
            ));
        }
        for step in &input.steps {
            validate_task_step(step)?;
        }
        if let Some(session_id) = input
            .session_id
            .as_deref()
            .filter(|session| !session.is_empty())
        {
            if let Some(active) = self.active_task_for_session(session_id)? {
                return Err(AppError::new(
                    "task.session_busy",
                    format!("该会话已有进行中的任务 {}", active.id),
                )
                .with_action("先完成或取消当前任务，再创建新任务"));
            }
        }

        let id = new_id("task");
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "INSERT INTO tasks
               (id, host_id, session_id, batch_id, goal_redacted, title, summary, outcome_summary,
                status, step_limit, created_at, updated_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', 'plan_ready', ?8, ?9, ?9, NULL)",
            params![
                id,
                input.host_id,
                input.session_id,
                input.batch_id,
                goal,
                title,
                summary,
                input.step_limit,
                ts
            ],
        )
        .map_err(sql_err)?;
        for (index, step) in input.steps.iter().enumerate() {
            tx.execute(
                "INSERT INTO task_steps
                   (id, task_id, ordinal, command_redacted, purpose, risk, status,
                    exit_code, output_tail_redacted, interactive_hint, started_at, finished_at, audit_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, '', ?8, NULL, NULL, NULL)",
                params![
                    new_id("tstep"),
                    id,
                    index as i64 + 1,
                    step.command_redacted.trim(),
                    step.purpose.trim(),
                    step.risk,
                    step.status,
                    i64::from(step.interactive_hint)
                ],
            )
            .map_err(sql_err)?;
        }
        tx.commit().map_err(sql_err)?;
        self.get_task(&id)?
            .ok_or_else(|| AppError::new("store.task.missing", "刚创建的任务读不回来"))
    }

    /// 任务与步骤在同一事务快照中读取，避免并发写入时返回半新半旧的视图。
    pub fn get_task(&self, task_id: &str) -> Result<Option<TaskWithSteps>> {
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        let Some(task) = task_row_optional_on(&tx, task_id)? else {
            return Ok(None);
        };
        let steps = task_steps_on(&tx, task_id)?;
        tx.commit().map_err(sql_err)?;
        Ok(Some(TaskWithSteps { task, steps }))
    }

    pub fn list_tasks(
        &self,
        host_id: Option<&str>,
        session_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<TaskRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, host_id, session_id, batch_id, goal_redacted, title, summary, outcome_summary,
                        status, step_limit, failure_count, created_at, updated_at, completed_at
                 FROM tasks
                 WHERE (?1 IS NULL OR host_id = ?1)
                   AND (?2 IS NULL OR session_id = ?2)
                 ORDER BY created_at DESC
                 LIMIT ?3",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(
                params![host_id, session_id, limit.clamp(1, 500) as i64],
                task_from_row,
            )
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    /// 同一会话只允许一个进行中的任务（计划 §9）。
    pub fn active_task_for_session(&self, session_id: &str) -> Result<Option<TaskRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, host_id, session_id, batch_id, goal_redacted, title, summary, outcome_summary,
                        status, step_limit, failure_count, created_at, updated_at, completed_at
                 FROM tasks
                 WHERE session_id = ?1
                   AND status IN ('draft', 'plan_ready', 'waiting_user', 'running', 'revising',
                                  'paused_failed', 'paused_interactive')
                 ORDER BY created_at DESC
                 LIMIT 1",
            )
            .map_err(sql_err)?;
        stmt.query_row(params![session_id], task_from_row)
            .optional()
            .map_err(sql_err)
    }

    /// 用户确认执行某一步：步骤进入 running，任务进入 running。
    pub fn start_step(&self, task_id: &str, step_id: &str, audit_seq: Option<i64>) -> Result<()> {
        let task = self.require_task(task_id)?;
        let step = self.require_step(task_id, step_id)?;
        if matches!(task.status.as_str(), "revising" | "paused_interactive") {
            return Err(AppError::new(
                "task.invalid_transition",
                "模型判断中或等待人工接管的步骤不能开始执行",
            ));
        }
        ensure_task_transition(&task.status, "running")?;
        ensure_step_transition(&step.status, "running")?;
        // 后面的步骤不能越过前面的 pending/ready/running 步骤。
        let earlier_open: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM task_steps
                 WHERE task_id = ?1 AND ordinal < ?2
                   AND status NOT IN ('succeeded', 'skipped', 'manual', 'sent')
                 LIMIT 1",
                params![task_id, step.ordinal],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if earlier_open.is_some() {
            return Err(AppError::new(
                "task.out_of_order",
                "请先处理前面的步骤，再执行这一步",
            ));
        }
        // 计划 §5.2：running 时只允许一个 step。IPC 调用之间没有共享锁，
        // 必须在这里用一次查询兜住并发双击。
        let other_running: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM task_steps
                 WHERE task_id = ?1 AND status = 'running' AND id != ?2 LIMIT 1",
                params![task_id, step_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if other_running.is_some() {
            return Err(AppError::new(
                "task.step_running",
                "同一任务同时只能执行一个步骤",
            ));
        }
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'running', exit_code = NULL, output_tail_redacted = '',
                 started_at = ?3, finished_at = NULL, audit_seq = ?4
             WHERE id = ?1 AND task_id = ?2",
            params![step_id, task_id, ts, audit_seq],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks SET status = 'running', updated_at = ?2 WHERE id = ?1",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    /// 完成/失败/已发送（结果未知）/跳过/人工完成一步，并同步任务状态。
    ///
    /// 连续两步 `failed` 时任务直接进入终态 `failed`（计划 §5.8：连续失败 2 次自动停止）。
    pub fn finish_step(
        &self,
        task_id: &str,
        step_id: &str,
        step_status: &str,
        exit_code: Option<i64>,
        output_tail_redacted: &str,
        audit_seq: Option<i64>,
    ) -> Result<()> {
        if !matches!(
            step_status,
            "succeeded" | "failed" | "sent" | "skipped" | "manual"
        ) {
            return Err(invalid(format!("不能把步骤结束为 {step_status}")));
        }
        if output_tail_redacted.chars().count() > MAX_OUTPUT_TAIL_CHARS {
            return Err(invalid(format!(
                "输出尾部超过 {MAX_OUTPUT_TAIL_CHARS} 字符"
            )));
        }
        let task = self.require_task(task_id)?;
        let step = self.require_step(task_id, step_id)?;
        ensure_step_transition(&step.status, step_status)?;

        // 成功/人工完成/跳过也必须按顺序：不能用一个“标记完成”越过失败或未执行的前一步。
        if matches!(step_status, "succeeded" | "manual" | "skipped") {
            let earlier_open: Option<String> = self
                .conn
                .query_row(
                    "SELECT id FROM task_steps
                     WHERE task_id = ?1 AND ordinal < ?2
                       AND status NOT IN ('succeeded', 'skipped', 'manual', 'sent')
                     LIMIT 1",
                    params![task_id, step.ordinal],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            if earlier_open.is_some() {
                return Err(AppError::new(
                    "task.out_of_order",
                    "请先处理前面的步骤，再结束这一步",
                ));
            }
        }

        let failure_count = if step_status == "failed" {
            task.failure_count + 1
        } else if matches!(step_status, "succeeded" | "manual") {
            0
        } else {
            // sent / skipped 不是成功证据，不能重置连续失败计数。
            task.failure_count
        };
        let task_status = if step_status == "failed" {
            if failure_count >= 2 {
                "failed"
            } else {
                "paused_failed"
            }
        } else {
            "waiting_user"
        };
        ensure_task_transition(&task.status, task_status)?;

        let ts = now();
        let completed_at = is_terminal_task_status(task_status).then_some(ts.clone());
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = ?3, exit_code = ?4, output_tail_redacted = ?5,
                 finished_at = ?6, audit_seq = ?7
             WHERE id = ?1 AND task_id = ?2",
            params![
                step_id,
                task_id,
                step_status,
                exit_code,
                output_tail_redacted,
                ts,
                audit_seq
            ],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks
             SET status = ?2, failure_count = ?3, updated_at = ?4,
                 completed_at = COALESCE(?5, completed_at)
             WHERE id = ?1",
            params![task_id, task_status, failure_count, ts, completed_at],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    /// 回填步骤最近一次审计事件（started / finished / skipped / retried / interactive）。
    pub fn set_step_audit_seq(&self, task_id: &str, step_id: &str, audit_seq: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE task_steps SET audit_seq = ?3 WHERE id = ?1 AND task_id = ?2",
                params![step_id, task_id, audit_seq],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// 编辑一个尚未执行的步骤；风险必须由调用方重新评估后传入。
    pub fn update_step(
        &self,
        task_id: &str,
        step_id: &str,
        edit: &TaskStepEdit,
        audit_seq: Option<i64>,
    ) -> Result<TaskWithSteps> {
        let task = self.require_task(task_id)?;
        if !matches!(
            task.status.as_str(),
            "draft" | "plan_ready" | "waiting_user" | "paused_failed"
        ) {
            return Err(AppError::new(
                "task.invalid_transition",
                "当前任务状态不能编辑步骤（执行中/模型判断中/已结束）",
            ));
        }
        let step = self.require_step(task_id, step_id)?;
        if !matches!(step.status.as_str(), "pending" | "ready") {
            return Err(AppError::new(
                "task.invalid_step",
                "只有尚未执行的 pending/ready 步骤可以编辑",
            ));
        }
        let command = edit.command_redacted.trim();
        if command.is_empty() {
            return Err(invalid("任务步骤命令不能为空"));
        }
        if command.chars().count() > MAX_STEP_COMMAND_CHARS {
            return Err(invalid(format!(
                "任务步骤命令超过 {MAX_STEP_COMMAND_CHARS} 字符"
            )));
        }
        if command.contains('\n') || command.contains('\r') {
            return Err(invalid("任务步骤必须是单行命令"));
        }
        if command.chars().any(|c| c.is_control() && c != '\t') {
            return Err(invalid("任务步骤命令包含控制字符"));
        }
        if !matches!(edit.risk.as_str(), "R0" | "R1" | "R2" | "R3") {
            return Err(invalid(format!("未知风险等级: {}", edit.risk)));
        }
        if edit.purpose.chars().count() > 400 {
            return Err(invalid("任务步骤说明超过 400 字符"));
        }
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET command_redacted = ?3, purpose = ?4, risk = ?5,
                 interactive_hint = ?6, audit_seq = ?7
             WHERE id = ?1 AND task_id = ?2",
            params![
                step_id,
                task_id,
                command,
                edit.purpose.trim(),
                edit.risk,
                i64::from(edit.interactive_hint),
                audit_seq
            ],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks SET updated_at = ?2 WHERE id = ?1",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        self.get_task(task_id)?
            .ok_or_else(|| AppError::new("store.task.missing", "编辑后任务读不回来"))
    }

    /// 按保留策略清理终态任务；进行中/草案任务永不清理。
    ///
    /// - `keep_days > 0`：删除 `COALESCE(completed_at, updated_at)` 早于截止时间的终态任务；
    /// - `max_terminal > 0`：每个主机只保留最新的 N 个终态任务（按完成时间倒序）；
    /// - `host_id` 为 None 时清理全部主机，否则只清理指定主机。
    pub fn prune_tasks(
        &self,
        host_id: Option<&str>,
        keep_days: i64,
        max_terminal: i64,
    ) -> Result<TaskPruneReport> {
        if !(0..=3650).contains(&keep_days) {
            return Err(invalid("任务历史保留天数必须在 0-3650 之间"));
        }
        if !(0..=10_000).contains(&max_terminal) {
            return Err(invalid("任务历史保留条数必须在 0-10000 之间"));
        }
        let age_cutoff = if keep_days > 0 {
            let delta = chrono::TimeDelta::try_days(keep_days)
                .ok_or_else(|| invalid("任务历史保留天数超出范围"))?;
            Some((Utc::now() - delta).to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        } else {
            None
        };
        let terminal = "status IN ('completed', 'failed', 'cancelled')";
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        let mut deleted = 0i64;
        if let Some(cutoff) = age_cutoff.as_deref() {
            deleted += tx
                .execute(
                    &format!(
                        "DELETE FROM tasks
                         WHERE {terminal}
                           AND (?1 IS NULL OR host_id = ?1)
                           AND COALESCE(completed_at, updated_at) < ?2"
                    ),
                    params![host_id, cutoff],
                )
                .map_err(sql_err)? as i64;
        }
        if max_terminal > 0 {
            // 每个 host_id 独立计数：一个主机的高频任务不能挤掉另一个主机的历史。
            deleted += tx
                .execute(
                    &format!(
                        "DELETE FROM tasks
                         WHERE id IN (
                             SELECT id FROM (
                                 SELECT id,
                                        ROW_NUMBER() OVER (
                                            PARTITION BY host_id
                                            ORDER BY COALESCE(completed_at, updated_at) DESC,
                                                     created_at DESC, id DESC
                                        ) AS rn
                                 FROM tasks
                                 WHERE {terminal}
                                   AND (?1 IS NULL OR host_id = ?1)
                             ) WHERE rn > ?2
                         )"
                    ),
                    params![host_id, max_terminal],
                )
                .map_err(sql_err)? as i64;
        }
        let remaining_terminal: i64 = tx
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM tasks
                     WHERE {terminal} AND (?1 IS NULL OR host_id = ?1)"
                ),
                params![host_id],
                |row| row.get(0),
            )
            .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(TaskPruneReport {
            deleted,
            remaining_terminal,
            age_cutoff,
        })
    }

    /// 只允许删除已完成/失败/取消的任务；进行中的任务必须先取消。
    pub fn delete_task(&self, task_id: &str) -> Result<()> {
        let task = self.require_task(task_id)?;
        if !is_terminal_task_status(&task.status) {
            return Err(AppError::new(
                "task.delete_active",
                "进行中的任务不能删除；请先取消任务",
            ));
        }
        let affected = self
            .conn
            .execute("DELETE FROM tasks WHERE id = ?1", params![task_id])
            .map_err(sql_err)?;
        if affected == 0 {
            return Err(AppError::new("task.not_found", "任务不存在"));
        }
        Ok(())
    }

    /// 通用状态推进（revising / 回退）；仍走同一张状态转移表。
    pub fn set_task_status(&self, task_id: &str, status: &str) -> Result<()> {
        if !valid_task_status(status) {
            return Err(invalid(format!("未知任务状态: {status}")));
        }
        let task = self.require_task(task_id)?;
        ensure_task_transition(&task.status, status)?;
        let ts = now();
        let completed_at = is_terminal_task_status(status).then_some(ts.clone());
        self.conn
            .execute(
                "UPDATE tasks
                 SET status = ?2, updated_at = ?3, completed_at = COALESCE(?4, completed_at)
                 WHERE id = ?1",
                params![task_id, status, ts, completed_at],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// 把非终态任务重新绑定到新会话（批次恢复/重连后继续执行）。
    ///
    /// 只改 `tasks.session_id`，不改步骤状态；目标会话若已有其他进行中任务则拒绝。
    pub fn rebind_task_session(&self, task_id: &str, session_id: &str) -> Result<TaskWithSteps> {
        let Some(current) = self.get_task(task_id)? else {
            return Err(AppError::new("task.missing", "任务不存在"));
        };
        if matches!(
            current.task.status.as_str(),
            "completed" | "failed" | "cancelled"
        ) {
            return Err(AppError::new("task.terminal", "终态任务不能重新绑定会话"));
        }
        if current.task.session_id.as_deref() == Some(session_id) {
            return Ok(current);
        }
        if let Some(active) = self.active_task_for_session(session_id)? {
            if active.id != task_id {
                return Err(AppError::new(
                    "task.session_busy",
                    format!("目标会话已有进行中的任务 {}", active.id),
                )
                .with_action("先完成或取消目标会话中的任务，再恢复批次"));
            }
        }
        let ts = now();
        self.conn
            .execute(
                "UPDATE tasks SET session_id = ?2, updated_at = ?3 WHERE id = ?1",
                params![task_id, session_id, ts],
            )
            .map_err(sql_err)?;
        self.get_task(task_id)?
            .ok_or_else(|| AppError::new("store.task.missing", "重新绑定后任务读不回来"))
    }

    /// 暂停任务（失败或交互），步骤保持原状，等待用户处理。
    pub fn pause_task(&self, task_id: &str, status: &str) -> Result<()> {
        if !matches!(status, "paused_failed" | "paused_interactive") {
            return Err(invalid(
                "pause_task 只接受 paused_failed / paused_interactive",
            ));
        }
        let task = self.require_task(task_id)?;
        ensure_task_transition(&task.status, status)?;
        let ts = now();
        self.conn
            .execute(
                "UPDATE tasks SET status = ?2, updated_at = ?3 WHERE id = ?1",
                params![task_id, status, ts],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// 失败步骤重试：回到 ready，任务回到 waiting_user，等待用户再次确认执行。
    pub fn retry_step(&self, task_id: &str, step_id: &str, audit_seq: Option<i64>) -> Result<()> {
        let task = self.require_task(task_id)?;
        let step = self.require_step(task_id, step_id)?;
        if step.status != "failed" {
            return Err(AppError::new("task.invalid_step", "只有失败的步骤可以重试"));
        }
        ensure_step_transition(&step.status, "ready")?;
        ensure_task_transition(&task.status, "waiting_user")?;
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'ready', exit_code = NULL, output_tail_redacted = '',
                 started_at = NULL, finished_at = NULL, audit_seq = ?3
             WHERE id = ?1 AND task_id = ?2",
            params![step_id, task_id, audit_seq],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks SET status = 'waiting_user', updated_at = ?2 WHERE id = ?1",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    /// 进度推进：由模型追加新步骤（仍在预算内）。
    pub fn append_task_steps(
        &self,
        task_id: &str,
        steps: Vec<NewTaskStep>,
        next_status: &str,
        audit_seq: Option<i64>,
    ) -> Result<TaskWithSteps> {
        if steps.is_empty() {
            return Err(invalid("追加步骤不能为空"));
        }
        let task = self.require_task(task_id)?;
        if is_terminal_task_status(&task.status) {
            return Err(AppError::new(
                "task.invalid_transition",
                "已完成/失败/取消的任务不能追加步骤",
            ));
        }
        let existing = self.task_steps(task_id)?;
        let total = existing.len() as i64 + steps.len() as i64;
        if total > task.step_limit {
            return Err(AppError::new(
                "task.step_limit",
                format!("追加后共 {total} 步，超过任务预算 {}", task.step_limit),
            ));
        }
        if total > MAX_TASK_STEPS {
            return Err(AppError::new(
                "task.step_limit",
                format!("追加后超过总步数上限 {MAX_TASK_STEPS}"),
            ));
        }
        if !valid_task_status(next_status) {
            return Err(invalid(format!("未知任务状态: {next_status}")));
        }
        ensure_task_transition(&task.status, next_status)?;
        for step in &steps {
            validate_task_step(step)?;
        }
        let next_ordinal = existing.iter().map(|s| s.ordinal).max().unwrap_or(0) + 1;
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        for (offset, step) in steps.iter().enumerate() {
            tx.execute(
                "INSERT INTO task_steps
                   (id, task_id, ordinal, command_redacted, purpose, risk, status,
                    exit_code, output_tail_redacted, interactive_hint, started_at, finished_at, audit_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, '', ?8, NULL, NULL, ?9)",
                params![
                    new_id("tstep"),
                    task_id,
                    next_ordinal + offset as i64,
                    step.command_redacted.trim(),
                    step.purpose.trim(),
                    step.risk,
                    step.status,
                    i64::from(step.interactive_hint),
                    audit_seq
                ],
            )
            .map_err(sql_err)?;
        }
        tx.execute(
            "UPDATE tasks SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![task_id, next_status, ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        self.get_task(task_id)?
            .ok_or_else(|| AppError::new("store.task.missing", "追加步骤后任务读不回来"))
    }

    /// 模型判定完成：写入完成摘要，未执行的步骤统一标记 skipped。
    pub fn complete_task(&self, task_id: &str, outcome_summary: &str) -> Result<()> {
        let task = self.require_task(task_id)?;
        ensure_task_transition(&task.status, "completed")?;
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'skipped', finished_at = ?2
             WHERE task_id = ?1 AND status IN ('pending', 'ready')",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks
             SET status = 'completed', outcome_summary = ?2, updated_at = ?3, completed_at = ?3
             WHERE id = ?1",
            params![task_id, outcome_summary.trim(), ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    /// 终止任务（超时 / 连续失败 / 人工停止），正在运行的步骤标记为结果未知。
    pub fn fail_task(&self, task_id: &str, reason: &str) -> Result<()> {
        let task = self.require_task(task_id)?;
        if task.status == "cancelled" {
            return Err(AppError::new(
                "task.invalid_transition",
                "任务已取消，不能再标记失败",
            ));
        }
        ensure_task_transition(&task.status, "failed")?;
        self.close_task(task_id, "failed", reason)
    }

    pub fn cancel_task(&self, task_id: &str, audit_seq: Option<i64>) -> Result<()> {
        let task = self.require_task(task_id)?;
        if task.status == "cancelled" {
            return Ok(());
        }
        ensure_task_transition(&task.status, "cancelled")?;
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'sent', finished_at = ?2, exit_code = NULL, audit_seq = COALESCE(?3, audit_seq)
             WHERE task_id = ?1 AND status = 'running'",
            params![task_id, ts, audit_seq],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'skipped', finished_at = ?2
             WHERE task_id = ?1 AND status IN ('pending', 'ready')",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks SET status = 'cancelled', updated_at = ?2, completed_at = ?2
             WHERE id = ?1",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    fn close_task(&self, task_id: &str, status: &str, reason: &str) -> Result<()> {
        let ts = now();
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'sent', finished_at = ?2, exit_code = NULL
             WHERE task_id = ?1 AND status = 'running'",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE task_steps
             SET status = 'skipped', finished_at = ?2
             WHERE task_id = ?1 AND status IN ('pending', 'ready')",
            params![task_id, ts],
        )
        .map_err(sql_err)?;
        tx.execute(
            "UPDATE tasks
             SET status = ?2, outcome_summary = ?3, updated_at = ?4, completed_at = ?4
             WHERE id = ?1",
            params![task_id, status, reason.trim(), ts],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    fn task_steps(&self, task_id: &str) -> Result<Vec<TaskStepRow>> {
        task_steps_on(&self.conn, task_id)
    }

    fn require_task(&self, task_id: &str) -> Result<TaskRow> {
        self.require_task_optional(task_id)?.ok_or_else(|| {
            AppError::new("task.not_found", "任务不存在").with_action("刷新任务列表后重试")
        })
    }

    fn require_task_optional(&self, task_id: &str) -> Result<Option<TaskRow>> {
        task_row_optional_on(&self.conn, task_id)
    }

    fn require_step(&self, task_id: &str, step_id: &str) -> Result<TaskStepRow> {
        self.conn
            .query_row(
                "SELECT id, task_id, ordinal, command_redacted, purpose, risk, status,
                        exit_code, output_tail_redacted, interactive_hint, started_at,
                        finished_at, audit_seq
                 FROM task_steps WHERE id = ?1 AND task_id = ?2",
                params![step_id, task_id],
                step_from_row,
            )
            .optional()
            .map_err(sql_err)?
            .ok_or_else(|| AppError::new("task.step_not_found", "任务步骤不存在"))
    }
}

fn task_row_optional_on(conn: &rusqlite::Connection, task_id: &str) -> Result<Option<TaskRow>> {
    conn.query_row(
        "SELECT id, host_id, session_id, batch_id, goal_redacted, title, summary, outcome_summary,
                status, step_limit, failure_count, created_at, updated_at, completed_at
         FROM tasks WHERE id = ?1",
        params![task_id],
        task_from_row,
    )
    .optional()
    .map_err(sql_err)
}

impl Db {
    pub fn create_task_batch(&self, input: NewTaskBatch) -> Result<TaskBatchRow> {
        if input.host_ids.is_empty() {
            return Err(invalid("批次至少需要一台主机"));
        }
        if input.title.trim().is_empty() {
            return Err(invalid("批次标题不能为空"));
        }
        let id = new_id("batch");
        let ts = now();
        let host_ids = serde_json::to_string(&input.host_ids).unwrap_or_else(|_| "[]".into());
        self.conn
            .execute(
                "INSERT INTO task_batches
                   (id, goal_redacted, title, host_ids_json, status, current_index,
                    created_at, updated_at, completed_at)
                 VALUES (?1, ?2, ?3, ?4, 'running', 0, ?5, ?5, NULL)",
                params![
                    id,
                    input.goal_redacted.trim(),
                    input.title.trim(),
                    host_ids,
                    ts
                ],
            )
            .map_err(sql_err)?;
        self.get_task_batch(&id)?
            .ok_or_else(|| AppError::new("store.batch.missing", "刚创建的批次读不回来"))
    }

    pub fn get_task_batch(&self, id: &str) -> Result<Option<TaskBatchRow>> {
        self.conn
            .query_row(
                "SELECT id, goal_redacted, title, host_ids_json, status, current_index,
                        created_at, updated_at, completed_at
                 FROM task_batches WHERE id = ?1",
                params![id],
                batch_from_row,
            )
            .optional()
            .map_err(sql_err)
    }

    pub fn list_active_task_batches(&self, limit: u32) -> Result<Vec<TaskBatchRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, goal_redacted, title, host_ids_json, status, current_index,
                        created_at, updated_at, completed_at
                 FROM task_batches
                 WHERE status IN ('running', 'paused')
                 ORDER BY created_at DESC LIMIT ?1",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 50) as i64], batch_from_row)
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    pub fn update_task_batch(&self, id: &str, status: &str, current_index: i64) -> Result<()> {
        if !matches!(status, "running" | "paused" | "done" | "cancelled") {
            return Err(invalid(format!("未知批次状态: {status}")));
        }
        let completed = matches!(status, "done" | "cancelled");
        self.conn
            .execute(
                "UPDATE task_batches
                 SET status = ?2, current_index = ?3, updated_at = ?4,
                     completed_at = CASE WHEN ?5 THEN ?4 ELSE completed_at END
                 WHERE id = ?1",
                params![id, status, current_index.max(0), now(), completed],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn list_tasks_for_batch(&self, batch_id: &str, limit: u32) -> Result<Vec<TaskRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, host_id, session_id, batch_id, goal_redacted, title, summary,
                        outcome_summary, status, step_limit, failure_count, created_at,
                        updated_at, completed_at
                 FROM tasks WHERE batch_id = ?1 ORDER BY created_at DESC
                 LIMIT ?2",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![batch_id, limit.clamp(1, 200) as i64], task_from_row)
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    pub fn tasks_for_batch(&self, batch_id: &str) -> Result<Vec<TaskRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, host_id, session_id, batch_id, goal_redacted, title, summary,
                        outcome_summary, status, step_limit, failure_count, created_at,
                        updated_at, completed_at
                 FROM tasks WHERE batch_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![batch_id], task_from_row)
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }
}

fn batch_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskBatchRow> {
    let host_ids_json: String = row.get(3)?;
    Ok(TaskBatchRow {
        id: row.get(0)?,
        goal_redacted: row.get(1)?,
        title: row.get(2)?,
        host_ids: serde_json::from_str(&host_ids_json).unwrap_or_default(),
        status: row.get(4)?,
        current_index: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        completed_at: row.get(8)?,
    })
}

fn task_steps_on(conn: &rusqlite::Connection, task_id: &str) -> Result<Vec<TaskStepRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, task_id, ordinal, command_redacted, purpose, risk, status,
                    exit_code, output_tail_redacted, interactive_hint, started_at,
                    finished_at, audit_seq
             FROM task_steps WHERE task_id = ?1 ORDER BY ordinal ASC",
        )
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![task_id], step_from_row)
        .map_err(sql_err)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(sql_err)
}

fn task_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRow> {
    Ok(TaskRow {
        id: row.get(0)?,
        host_id: row.get(1)?,
        session_id: row.get(2)?,
        batch_id: row.get(3)?,
        goal_redacted: row.get(4)?,
        title: row.get(5)?,
        summary: row.get(6)?,
        outcome_summary: row.get(7)?,
        status: row.get(8)?,
        step_limit: row.get(9)?,
        failure_count: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
        completed_at: row.get(13)?,
    })
}

fn step_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskStepRow> {
    Ok(TaskStepRow {
        id: row.get(0)?,
        task_id: row.get(1)?,
        ordinal: row.get(2)?,
        command_redacted: row.get(3)?,
        purpose: row.get(4)?,
        risk: row.get(5)?,
        status: row.get(6)?,
        exit_code: row.get(7)?,
        output_tail_redacted: row.get(8)?,
        interactive_hint: row.get::<_, i64>(9)? != 0,
        started_at: row.get(10)?,
        finished_at: row.get(11)?,
        audit_seq: row.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Db, NewHost};

    fn host() -> NewHost {
        NewHost {
            name: "web".into(),
            hostname: "127.0.0.1".into(),
            port: 22,
            default_username: "ops".into(),
            tags: vec![],
            ssh_backend: "auto".into(),
            group_name: "".into(),
        }
    }

    fn task_input(host_id: &str, steps: Vec<NewTaskStep>) -> NewTask {
        NewTask {
            host_id: host_id.into(),
            session_id: Some("sess_1".into()),
            batch_id: None,
            goal_redacted: "检查并重载 nginx".into(),
            title: "检查并重载 nginx".into(),
            summary: "只读检查后平滑重载".into(),
            step_limit: DEFAULT_STEP_LIMIT,
            steps,
        }
    }

    fn create(db: &Db, host_id: &str) -> TaskWithSteps {
        db.create_task(task_input(
            host_id,
            vec![
                NewTaskStep::new("nginx -t", "验证配置", "R1").with_status("ready"),
                NewTaskStep::new("systemctl reload nginx", "平滑重载", "R2"),
            ],
        ))
        .unwrap()
    }

    #[test]
    fn create_get_list_and_ordinals() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        assert_eq!(task.task.status, "plan_ready");
        assert_eq!(task.steps.len(), 2);
        assert_eq!(task.steps[0].ordinal, 1);
        assert_eq!(task.steps[1].ordinal, 2);
        assert_eq!(task.steps[0].status, "ready");
        assert_eq!(db.get_task(&task.task.id).unwrap().unwrap(), task);
        assert_eq!(db.list_tasks(Some(&host.id), None, 10).unwrap().len(), 1);
        assert_eq!(
            db.active_task_for_session("sess_1").unwrap().unwrap().id,
            task.task.id
        );
    }

    #[test]
    fn batch_persists_and_links_tasks() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let batch = db
            .create_task_batch(NewTaskBatch {
                goal_redacted: "检查 nginx".into(),
                title: "检查 nginx".into(),
                host_ids: vec![host.id.clone()],
            })
            .unwrap();
        assert_eq!(db.list_active_task_batches(10).unwrap().len(), 1);
        let mut input = task_input(
            &host.id,
            vec![NewTaskStep::new("nginx -t", "验证配置", "R1")],
        );
        input.batch_id = Some(batch.id.clone());
        let task = db.create_task(input).unwrap();
        assert_eq!(task.task.batch_id.as_deref(), Some(batch.id.as_str()));
        let rows = db.tasks_for_batch(&batch.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, task.task.id);
        db.update_task_batch(&batch.id, "paused", 0).unwrap();
        assert_eq!(
            db.get_task_batch(&batch.id).unwrap().unwrap().status,
            "paused"
        );
        db.update_task_batch(&batch.id, "done", 0).unwrap();
        assert_eq!(db.list_active_task_batches(10).unwrap().len(), 0);
    }

    #[test]
    fn rejects_over_budget_and_invalid_steps() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let mut input = task_input(
            &host.id,
            (0..6)
                .map(|i| NewTaskStep::new(format!("echo {i}"), "", "R0"))
                .collect(),
        );
        input.step_limit = 5;
        let err = db.create_task(input).unwrap_err();
        assert_eq!(err.code, "task.step_limit");

        let mut input = task_input(&host.id, vec![NewTaskStep::new("echo a\necho b", "", "R0")]);
        input.session_id = None;
        assert!(db.create_task(input).is_err());

        let mut input = task_input(&host.id, vec![NewTaskStep::new("echo a", "", "R9")]);
        input.session_id = None;
        assert!(db.create_task(input).is_err());
    }

    #[test]
    fn one_active_task_per_session() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let _task = create(&db, &host.id);
        let err = db
            .create_task(task_input(
                &host.id,
                vec![NewTaskStep::new("uptime", "", "R0")],
            ))
            .unwrap_err();
        assert_eq!(err.code, "task.session_busy");
    }

    #[test]
    fn start_and_finish_step_updates_task() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        db.start_step(&task.task.id, &task.steps[0].id, Some(7))
            .unwrap();
        let running = db.get_task(&task.task.id).unwrap().unwrap();
        assert_eq!(running.task.status, "running");
        assert_eq!(running.steps[0].status, "running");
        assert_eq!(running.steps[0].audit_seq, Some(7));
        db.finish_step(
            &task.task.id,
            &task.steps[0].id,
            "succeeded",
            Some(0),
            "nginx: configuration file test is successful",
            Some(8),
        )
        .unwrap();
        let done = db.get_task(&task.task.id).unwrap().unwrap();
        assert_eq!(done.task.status, "waiting_user");
        assert_eq!(done.steps[0].status, "succeeded");
        assert_eq!(done.steps[0].exit_code, Some(0));
        assert!(done.steps[0].finished_at.is_some());
        assert!(done.steps[1].command_redacted.contains("systemctl"));
    }

    #[test]
    fn second_consecutive_failure_stops_task() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        db.start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        db.finish_step(
            &task.task.id,
            &task.steps[0].id,
            "failed",
            Some(1),
            "err",
            None,
        )
        .unwrap();
        let first = db.get_task(&task.task.id).unwrap().unwrap();
        assert_eq!(first.task.status, "paused_failed");
        db.retry_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        db.start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        db.finish_step(
            &task.task.id,
            &task.steps[0].id,
            "failed",
            Some(1),
            "err2",
            None,
        )
        .unwrap();
        let second = db.get_task(&task.task.id).unwrap().unwrap();
        assert_eq!(second.task.status, "failed");
        assert!(second.task.completed_at.is_some());
    }

    #[test]
    fn cannot_start_later_step_before_earlier_done() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        let err = db
            .start_step(&task.task.id, &task.steps[1].id, None)
            .unwrap_err();
        assert_eq!(err.code, "task.out_of_order");
        db.start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        db.finish_step(
            &task.task.id,
            &task.steps[0].id,
            "succeeded",
            Some(0),
            "",
            None,
        )
        .unwrap();
        db.start_step(&task.task.id, &task.steps[1].id, None)
            .unwrap();
    }

    #[test]
    fn cannot_finish_later_step_before_earlier_done() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        let err = db
            .finish_step(&task.task.id, &task.steps[1].id, "manual", None, "", None)
            .unwrap_err();
        assert_eq!(err.code, "task.out_of_order");
    }

    #[test]
    fn cannot_start_while_revising_or_waiting_interactive() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        db.set_task_status(&task.task.id, "waiting_user").unwrap();
        db.set_task_status(&task.task.id, "revising").unwrap();
        let err = db
            .start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");
        db.set_task_status(&task.task.id, "waiting_user").unwrap();
        db.start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        db.pause_task(&task.task.id, "paused_interactive").unwrap();
        let err = db
            .start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        // pending 步骤不能直接成功
        let err = db
            .finish_step(
                &task.task.id,
                &task.steps[1].id,
                "succeeded",
                Some(0),
                "",
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");
        db.cancel_task(&task.task.id, None).unwrap();
        let err = db
            .start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");
    }

    #[test]
    fn cancel_marks_running_and_pending_steps_closed() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        db.start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        db.cancel_task(&task.task.id, None).unwrap();
        let cancelled = db.get_task(&task.task.id).unwrap().unwrap();
        assert_eq!(cancelled.task.status, "cancelled");
        assert_eq!(cancelled.steps[0].status, "sent");
        assert_eq!(cancelled.steps[1].status, "skipped");
        assert!(db.active_task_for_session("sess_1").unwrap().is_none());
    }

    #[test]
    fn append_steps_respects_budget_and_updates_status() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        let appended = db
            .append_task_steps(
                &task.task.id,
                vec![
                    NewTaskStep::new("journalctl -u nginx -n 50", "看日志", "R0")
                        .with_status("ready"),
                ],
                "waiting_user",
                Some(9),
            )
            .unwrap();
        assert_eq!(appended.steps.len(), 3);
        assert_eq!(appended.steps[2].ordinal, 3);
        assert_eq!(appended.task.status, "waiting_user");

        let mut error = None;
        for index in 3..=8 {
            match db.append_task_steps(
                &task.task.id,
                vec![NewTaskStep::new(format!("echo {index}"), "", "R0")],
                "waiting_user",
                None,
            ) {
                Ok(_) => {}
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
        let err = error.expect("must hit the step budget");
        assert_eq!(err.code, "task.step_limit");
    }

    #[test]
    fn complete_and_fail_close_pending_steps() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        db.complete_task(&task.task.id, "目标已达成").unwrap();
        let done = db.get_task(&task.task.id).unwrap().unwrap();
        assert_eq!(done.task.status, "completed");
        assert_eq!(done.task.outcome_summary, "目标已达成");
        assert!(done.steps.iter().all(|step| step.status == "skipped"));

        let second = db
            .create_task(NewTask {
                session_id: Some("sess_2".into()),
                ..task_input(&host.id, vec![NewTaskStep::new("uptime", "", "R0")])
            })
            .unwrap();
        db.fail_task(&second.task.id, "超时").unwrap();
        let failed = db.get_task(&second.task.id).unwrap().unwrap();
        assert_eq!(failed.task.status, "failed");
        assert_eq!(failed.task.outcome_summary, "超时");
    }

    #[test]
    fn task_progress_survives_database_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shellwarden.db");
        let task_id;
        {
            let db = Db::open(&path).unwrap();
            let host = db.create_host(host()).unwrap();
            let task = create(&db, &host.id);
            task_id = task.task.id.clone();
            db.start_step(&task.task.id, &task.steps[0].id, None)
                .unwrap();
            db.finish_step(
                &task.task.id,
                &task.steps[0].id,
                "succeeded",
                Some(0),
                "nginx: configuration file test is successful",
                None,
            )
            .unwrap();
            // 模拟任务在模型判断中退出：重启后必须还能读出同一状态。
            db.set_task_status(&task.task.id, "revising").unwrap();
        }
        {
            let db = Db::open(&path).unwrap();
            let recovered = db.get_task(&task_id).unwrap().unwrap();
            assert_eq!(recovered.task.status, "revising");
            assert_eq!(recovered.steps[0].status, "succeeded");
            assert_eq!(recovered.steps[0].exit_code, Some(0));
            assert!(recovered.steps[0]
                .output_tail_redacted
                .contains("successful"));
            db.set_task_status(&task_id, "waiting_user").unwrap();
            assert_eq!(
                db.get_task(&task_id).unwrap().unwrap().task.status,
                "waiting_user"
            );
        }
    }

    #[test]
    fn rebinds_task_session_for_batch_restore() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        assert_eq!(task.task.session_id.as_deref(), Some("sess_1"));

        let rebound = db.rebind_task_session(&task.task.id, "sess_2").unwrap();
        assert_eq!(rebound.task.session_id.as_deref(), Some("sess_2"));
        assert_eq!(
            db.active_task_for_session("sess_2")
                .unwrap()
                .expect("rebound task should be active")
                .id,
            task.task.id
        );

        // 目标会话已有进行中任务时拒绝。
        let other = create(&db, &host.id);
        assert!(db.rebind_task_session(&other.task.id, "sess_2").is_err());

        // 终态任务拒绝。
        db.cancel_task(&task.task.id, None).unwrap();
        assert!(db.rebind_task_session(&task.task.id, "sess_3").is_err());
    }

    #[test]
    fn edit_only_unexecuted_steps_and_reassess_fields() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        let edited = db
            .update_step(
                &task.task.id,
                &task.steps[1].id,
                &TaskStepEdit {
                    command_redacted: "systemctl restart nginx".into(),
                    purpose: "重启而不是平滑重载".into(),
                    risk: "R2".into(),
                    interactive_hint: true,
                },
                None,
            )
            .unwrap();
        assert_eq!(edited.steps[1].command_redacted, "systemctl restart nginx");
        assert_eq!(edited.steps[1].risk, "R2");
        assert!(edited.steps[1].interactive_hint);

        // 执行中的步骤不可编辑。
        db.start_step(&task.task.id, &task.steps[0].id, None)
            .unwrap();
        let err = db
            .update_step(
                &task.task.id,
                &task.steps[0].id,
                &TaskStepEdit {
                    command_redacted: "date".into(),
                    purpose: String::new(),
                    risk: "R0".into(),
                    interactive_hint: false,
                },
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");

        // 终态任务不可编辑。
        db.complete_task(&task.task.id, "完成").unwrap();
        let err = db
            .update_step(
                &task.task.id,
                &task.steps[1].id,
                &TaskStepEdit {
                    command_redacted: "date".into(),
                    purpose: String::new(),
                    risk: "R0".into(),
                    interactive_hint: false,
                },
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, "task.invalid_transition");
    }

    #[test]
    fn delete_only_terminal_tasks() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        let err = db.delete_task(&task.task.id).unwrap_err();
        assert_eq!(err.code, "task.delete_active");
        db.cancel_task(&task.task.id, None).unwrap();
        db.delete_task(&task.task.id).unwrap();
        assert!(db.get_task(&task.task.id).unwrap().is_none());
        assert!(db.list_tasks(None, None, 10).unwrap().is_empty());
    }

    fn terminal_task(db: &Db, host_id: &str, title: &str) -> TaskWithSteps {
        let mut input = task_input(host_id, vec![NewTaskStep::new("uptime", "", "R0")]);
        input.session_id = None;
        input.title = title.into();
        let task = db.create_task(input).unwrap();
        db.cancel_task(&task.task.id, None).unwrap();
        task
    }

    fn set_completed_at(db: &Db, task_id: &str, value: &str) {
        db.conn
            .execute(
                "UPDATE tasks SET completed_at = ?2, updated_at = ?2 WHERE id = ?1",
                params![task_id, value],
            )
            .unwrap();
    }

    #[test]
    fn prune_tasks_by_age_keeps_active_and_cascades_steps() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let old = terminal_task(&db, &host.id, "old");
        set_completed_at(&db, &old.task.id, "2020-01-01T00:00:00.000Z");
        let fresh = terminal_task(&db, &host.id, "fresh");
        let mut active_input = task_input(&host.id, vec![NewTaskStep::new("uptime", "", "R0")]);
        active_input.session_id = None;
        active_input.title = "active".into();
        let active = db.create_task(active_input).unwrap();

        let report = db.prune_tasks(Some(&host.id), 30, 0).unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(report.remaining_terminal, 1);
        assert!(report.age_cutoff.is_some());
        assert!(db.get_task(&old.task.id).unwrap().is_none());
        assert!(db.get_task(&fresh.task.id).unwrap().is_some());
        assert!(db.get_task(&active.task.id).unwrap().is_some());
        let steps: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM task_steps WHERE task_id = ?1",
                params![old.task.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(steps, 0);
    }

    #[test]
    fn prune_tasks_by_count_and_host_scope() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let a = terminal_task(&db, &host.id, "a");
        set_completed_at(&db, &a.task.id, "2026-01-01T00:00:00.000Z");
        let b = terminal_task(&db, &host.id, "b");
        set_completed_at(&db, &b.task.id, "2026-01-02T00:00:00.000Z");
        let c = terminal_task(&db, &host.id, "c");
        set_completed_at(&db, &c.task.id, "2026-01-03T00:00:00.000Z");
        let other_host = db
            .create_host(NewHost {
                name: "other".into(),
                hostname: "127.0.0.1".into(),
                port: 22,
                default_username: "ops".into(),
                tags: vec![],
                ssh_backend: "auto".into(),
                group_name: "test".into(),
            })
            .unwrap();
        let other = terminal_task(&db, &other_host.id, "other");

        let report = db.prune_tasks(Some(&host.id), 0, 2).unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(report.remaining_terminal, 2);
        assert!(report.age_cutoff.is_none());
        assert!(db.get_task(&a.task.id).unwrap().is_none());
        assert!(db.get_task(&b.task.id).unwrap().is_some());
        assert!(db.get_task(&c.task.id).unwrap().is_some());
        assert!(db.get_task(&other.task.id).unwrap().is_some());

        // 全局清理也按 host 分区：host1 保留最新 1 条，host2 的 1 条保留。
        let global = db.prune_tasks(None, 0, 1).unwrap();
        assert_eq!(global.deleted, 1);
        assert_eq!(global.remaining_terminal, 2);
        assert!(db.get_task(&b.task.id).unwrap().is_none());
        assert!(db.get_task(&c.task.id).unwrap().is_some());
        assert!(db.get_task(&other.task.id).unwrap().is_some());

        let disabled = db.prune_tasks(None, 0, 0).unwrap();
        assert_eq!(disabled.deleted, 0);
        assert!(disabled.remaining_terminal >= 2);
    }

    #[test]
    fn prune_rejects_out_of_range_policy() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.prune_tasks(None, -1, 0).is_err());
        assert!(db.prune_tasks(None, 0, 10_001).is_err());
    }

    #[test]
    fn deleting_host_cascades_tasks() {
        let db = Db::open_in_memory().unwrap();
        let host = db.create_host(host()).unwrap();
        let task = create(&db, &host.id);
        assert!(db.delete_host(&host.id).unwrap());
        assert!(db.get_task(&task.task.id).unwrap().is_none());
        assert!(db.list_tasks(None, None, 10).unwrap().is_empty());
    }

    #[test]
    fn state_machine_tables_are_consistent() {
        for status in TASK_STATUSES {
            assert!(task_transition_allowed(status, status));
            assert!(valid_task_status(status));
        }
        assert!(task_transition_allowed("plan_ready", "running"));
        assert!(!task_transition_allowed("completed", "running"));
        assert!(!task_transition_allowed("cancelled", "waiting_user"));
        assert!(step_transition_allowed("running", "sent"));
        assert!(!step_transition_allowed("succeeded", "running"));
        assert_eq!(task_elapsed_secs("not-a-date"), 0);
    }
}
