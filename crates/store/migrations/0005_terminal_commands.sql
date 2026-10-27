-- 终端命令级审计（§14.1）。只存脱敏后的命令，不存原始输出。
CREATE TABLE IF NOT EXISTS terminal_commands (
    id               TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    host_id          TEXT,
    command_redacted TEXT NOT NULL,
    exit_code        INTEGER,
    started_at       TEXT NOT NULL,
    finished_at      TEXT NOT NULL,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    state_unknown    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_terminal_commands_session
    ON terminal_commands(session_id, started_at);
