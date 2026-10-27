-- 任务模式（阶段 1/2）：多命令清单 + 半自动多步任务。
-- 约定：
--   * 命令、输出都只存脱敏后的文本；
--   * 输出只保留尾部，完整输出不入库；
--   * 不存 API Key、密码或原始文件内容；
--   * session_id 不设外键：会话结束/删除后任务仍可作为历史查看。

CREATE TABLE IF NOT EXISTS tasks (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    session_id      TEXT,
    goal_redacted   TEXT NOT NULL,
    title           TEXT NOT NULL,
    summary         TEXT NOT NULL DEFAULT '',
    outcome_summary TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    step_limit      INTEGER NOT NULL DEFAULT 8,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_tasks_host ON tasks(host_id, created_at);
CREATE INDEX IF NOT EXISTS ix_tasks_session ON tasks(session_id);
CREATE INDEX IF NOT EXISTS ix_tasks_status ON tasks(status);

CREATE TABLE IF NOT EXISTS task_steps (
    id                   TEXT PRIMARY KEY,
    task_id              TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    ordinal              INTEGER NOT NULL,
    command_redacted     TEXT NOT NULL,
    purpose              TEXT NOT NULL DEFAULT '',
    risk                 TEXT NOT NULL,
    status               TEXT NOT NULL,
    exit_code            INTEGER,
    output_tail_redacted TEXT NOT NULL DEFAULT '',
    interactive_hint     INTEGER NOT NULL DEFAULT 0,
    started_at           TEXT,
    finished_at          TEXT,
    audit_seq            INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_task_steps_task_ordinal
    ON task_steps(task_id, ordinal);
