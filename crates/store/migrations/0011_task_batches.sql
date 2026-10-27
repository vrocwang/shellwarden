-- 批量任务批次：按标签选择主机后，每台独立任务，串行推进。
CREATE TABLE IF NOT EXISTS task_batches (
    id              TEXT PRIMARY KEY,
    goal_redacted   TEXT NOT NULL,
    title           TEXT NOT NULL,
    host_ids_json   TEXT NOT NULL,
    status          TEXT NOT NULL,
    current_index   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_task_batches_status ON task_batches(status, created_at);

ALTER TABLE tasks ADD COLUMN batch_id TEXT REFERENCES task_batches(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS ix_tasks_batch ON tasks(batch_id, created_at);
