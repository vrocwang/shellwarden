-- ShellWarden schema v1（对应设计文档 §12.2）
-- 约定：
--   * 时间统一存 UTC RFC3339 文本；
--   * 秘密只存引用（credential_ref），不存明文；
--   * 大输出/录制只存引用与哈希，正文走文件；
--   * 后置能力（P2）也建表，避免后续改主键与关联。

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    checksum   TEXT NOT NULL
);

-- 主机与连接 ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS hosts (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    hostname             TEXT NOT NULL,
    port                 INTEGER NOT NULL DEFAULT 22,
    default_username     TEXT NOT NULL DEFAULT '',
    group_id             TEXT,
    tags_json            TEXT NOT NULL DEFAULT '[]',
    ssh_backend          TEXT NOT NULL DEFAULT 'auto',
    connection_options_json TEXT NOT NULL DEFAULT '{}',
    ai_policy_profile_id TEXT,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_hosts_name ON hosts(name);
CREATE INDEX IF NOT EXISTS ix_hosts_hostname ON hosts(hostname);

CREATE TABLE IF NOT EXISTS identities (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    auth_type      TEXT NOT NULL,
    credential_ref TEXT,
    ssh_agent_ref  TEXT,
    cert_ref       TEXT,
    otp_required   INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identities_name ON identities(name);

CREATE TABLE IF NOT EXISTS host_keys (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    hop_index   INTEGER NOT NULL DEFAULT 0,
    algorithm   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    trust_state   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_host_keys ON host_keys(host_id, hop_index, algorithm, fingerprint);

CREATE TABLE IF NOT EXISTS host_capabilities (
    id                 TEXT PRIMARY KEY,
    host_id            TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    probed_at          TEXT NOT NULL,
    ssh_algorithms_json TEXT NOT NULL DEFAULT '[]',
    auth_methods_json  TEXT NOT NULL DEFAULT '[]',
    sudo_capability    TEXT NOT NULL DEFAULT 'unknown',
    locale             TEXT,
    command_set_json   TEXT NOT NULL DEFAULT '[]',
    pty_ok             INTEGER NOT NULL DEFAULT 0,
    sftp_ok            INTEGER NOT NULL DEFAULT 0,
    forward_ok         INTEGER NOT NULL DEFAULT 0,
    notes              TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    host_id          TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    identity_id      TEXT REFERENCES identities(id),
    backend          TEXT NOT NULL DEFAULT 'auto',
    started_at       TEXT NOT NULL,
    ended_at         TEXT,
    disconnect_reason TEXT,
    recording_ref    TEXT,
    recording_enabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS session_recordings (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    format          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    encrypted       INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    paused_intervals_json TEXT NOT NULL DEFAULT '[]',
    deleted_at      TEXT
);

-- 策略与授权 ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS policy_profiles (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    mode       TEXT NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id          TEXT PRIMARY KEY,
    profile_id  TEXT NOT NULL REFERENCES policy_profiles(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL DEFAULT 1,
    priority    INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    match_json  TEXT NOT NULL DEFAULT '{}',
    cel         TEXT,
    effect      TEXT NOT NULL,
    approval    TEXT NOT NULL DEFAULT 'none',
    max_risk    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_policy_rules_profile ON policy_rules(profile_id);

CREATE TABLE IF NOT EXISTS policy_versions (
    id           TEXT PRIMARY KEY,
    profile_id   TEXT NOT NULL REFERENCES policy_profiles(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL,
    digest       TEXT NOT NULL,
    published_at TEXT NOT NULL,
    published_by TEXT,
    notes        TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_policy_versions ON policy_versions(profile_id, version);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id             TEXT PRIMARY KEY,
    task_id        TEXT,
    step_id        TEXT,
    plan_version   INTEGER,
    inputs_digest  TEXT NOT NULL,
    decision       TEXT NOT NULL,
    risk           TEXT NOT NULL,
    unknown        INTEGER NOT NULL DEFAULT 0,
    rule_ids_json  TEXT NOT NULL DEFAULT '[]',
    reason         TEXT NOT NULL DEFAULT '',
    policy_version TEXT NOT NULL,
    policy_digest  TEXT NOT NULL,
    decided_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_policy_decisions_task ON policy_decisions(task_id);

CREATE TABLE IF NOT EXISTS grants (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    identity_id TEXT NOT NULL REFERENCES identities(id),
    tools_json  TEXT NOT NULL,
    max_risk    TEXT NOT NULL DEFAULT 'R0',
    valid_from  TEXT NOT NULL,
    valid_to    TEXT NOT NULL,
    max_calls   INTEGER NOT NULL DEFAULT 20,
    used_calls  INTEGER NOT NULL DEFAULT 0,
    revoked_at  TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- 工具 ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tools (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    version               TEXT NOT NULL,
    schema_json           TEXT NOT NULL DEFAULT '{}',
    output_schema_json    TEXT NOT NULL DEFAULT '{}',
    risk_floor            TEXT NOT NULL,
    read_only             INTEGER NOT NULL DEFAULT 1,
    output_mode           TEXT NOT NULL DEFAULT 'structured_only',
    model_visible_fields_json TEXT NOT NULL DEFAULT '[]',
    enabled               INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tools_name_version ON tools(name, version);

CREATE TABLE IF NOT EXISTS tool_versions (
    id         TEXT PRIMARY KEY,
    tool_id    TEXT NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    version    TEXT NOT NULL,
    digest     TEXT NOT NULL,
    integrity  TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_permissions (
    id               TEXT PRIMARY KEY,
    host_id          TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tool_id          TEXT NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    constraints_json TEXT NOT NULL DEFAULT '{}',
    enabled          INTEGER NOT NULL DEFAULT 1,
    granted_at       TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tool_permissions ON tool_permissions(host_id, tool_id);

-- 任务、计划、审批 ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS ai_tasks (
    id                  TEXT PRIMARY KEY,
    host_id             TEXT NOT NULL REFERENCES hosts(id),
    identity_id         TEXT REFERENCES identities(id),
    request_text_redacted TEXT NOT NULL DEFAULT '',
    model_provider      TEXT,
    model_name          TEXT,
    prompt_version      TEXT,
    schema_version      TEXT NOT NULL DEFAULT '2.0',
    status              TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    finished_at         TEXT,
    summary             TEXT,
    plan_digest         TEXT,
    token_usage_json    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_ai_tasks_host ON ai_tasks(host_id, created_at);

CREATE TABLE IF NOT EXISTS plans (
    id             TEXT PRIMARY KEY,
    task_id        TEXT NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL,
    schema_version TEXT NOT NULL,
    plan_json      TEXT NOT NULL,
    digest         TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    invalidated_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_plans_version ON plans(task_id, version);

CREATE TABLE IF NOT EXISTS execution_contexts (
    id           TEXT PRIMARY KEY,
    task_id      TEXT,
    step_id      TEXT,
    context_json TEXT NOT NULL,
    digest       TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_steps (
    id                     TEXT PRIMARY KEY,
    task_id                TEXT NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
    plan_id                TEXT REFERENCES plans(id),
    plan_version           INTEGER,
    step_key               TEXT NOT NULL,
    tool_name              TEXT NOT NULL,
    tool_version           TEXT,
    arguments_redacted_json TEXT NOT NULL DEFAULT '{}',
    argument_provenance_json TEXT NOT NULL DEFAULT '{}',
    reversible             TEXT,
    status                 TEXT NOT NULL,
    exit_code              INTEGER,
    stdout_ref             TEXT,
    stderr_ref             TEXT,
    started_at             TEXT,
    finished_at            TEXT,
    duration_ms            INTEGER,
    timed_out              INTEGER NOT NULL DEFAULT 0,
    truncated              INTEGER NOT NULL DEFAULT 0,
    state_unknown          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_task_steps_task ON task_steps(task_id, plan_version);

CREATE TABLE IF NOT EXISTS preconditions (
    id          TEXT PRIMARY KEY,
    approval_id TEXT,
    step_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,
    target      TEXT NOT NULL,
    expected    TEXT NOT NULL,
    observed    TEXT,
    observed_at TEXT,
    checked_at  TEXT,
    result      TEXT
);

CREATE TABLE IF NOT EXISTS verifications (
    id          TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
    step_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,
    params_json TEXT NOT NULL DEFAULT '{}',
    result      TEXT,
    observed_json TEXT NOT NULL DEFAULT '{}',
    checked_at  TEXT,
    asserted_by TEXT NOT NULL DEFAULT 'executor'
);

CREATE TABLE IF NOT EXISTS approvals (
    id                       TEXT PRIMARY KEY,
    task_id                  TEXT NOT NULL,
    plan_id                  TEXT NOT NULL,
    plan_version             INTEGER NOT NULL,
    plan_digest              TEXT NOT NULL,
    schema_version           TEXT NOT NULL,
    policy_version           TEXT NOT NULL,
    policy_digest            TEXT NOT NULL,
    tool_versions_json       TEXT NOT NULL DEFAULT '{}',
    host_id                  TEXT NOT NULL,
    identity_id              TEXT NOT NULL,
    execution_context_digest TEXT NOT NULL,
    scope_json               TEXT NOT NULL DEFAULT '{}',
    preconditions_json       TEXT NOT NULL DEFAULT '[]',
    risk_summary_json        TEXT NOT NULL DEFAULT '{}',
    decision                 TEXT NOT NULL,
    decided_by               TEXT,
    decided_at               TEXT,
    expires_at               TEXT NOT NULL,
    revoked_at               TEXT,
    reauth_evidence_id       TEXT
);
CREATE INDEX IF NOT EXISTS ix_approvals_task ON approvals(task_id, plan_version);

CREATE TABLE IF NOT EXISTS reauth_evidence (
    id         TEXT PRIMARY KEY,
    method     TEXT NOT NULL,
    scope      TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    result     TEXT NOT NULL
);

-- 审计与可观测 -------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT PRIMARY KEY,
    seq             INTEGER NOT NULL UNIQUE,
    event_type      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    chain_segment   INTEGER NOT NULL,
    host_id         TEXT,
    session_id      TEXT,
    task_id         TEXT,
    step_id         TEXT,
    approval_id     TEXT,
    policy_version  TEXT,
    tool_version    TEXT,
    context_id      TEXT,
    plan_digest     TEXT,
    actor           TEXT NOT NULL,
    payload_redacted_json TEXT NOT NULL DEFAULT '{}',
    previous_hash   TEXT NOT NULL,
    event_hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_events_time ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_events_task ON audit_events(task_id);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id           TEXT PRIMARY KEY,
    chain_segment INTEGER NOT NULL,
    range_start  INTEGER NOT NULL,
    range_end    INTEGER NOT NULL,
    hash         TEXT NOT NULL,
    exported_at  TEXT,
    target       TEXT
);

CREATE TABLE IF NOT EXISTS file_operations (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    task_id     TEXT,
    operation   TEXT NOT NULL,
    path        TEXT NOT NULL,
    direction   TEXT,
    result      TEXT,
    bytes       INTEGER,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS model_contexts (
    id                    TEXT PRIMARY KEY,
    task_id               TEXT NOT NULL,
    call_index            INTEGER NOT NULL,
    provider              TEXT,
    model                 TEXT,
    prompt_version        TEXT,
    context_digest        TEXT NOT NULL,
    context_summary_redacted TEXT NOT NULL DEFAULT '',
    token_in              INTEGER NOT NULL DEFAULT 0,
    token_out             INTEGER NOT NULL DEFAULT 0,
    redaction_rules_version TEXT,
    created_at            TEXT NOT NULL
);

-- 配置与迁移 ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS model_providers (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    base_url        TEXT,
    model           TEXT,
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS prompt_versions (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    version        INTEGER NOT NULL,
    content_digest TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    active         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS redaction_rules (
    id         TEXT PRIMARY KEY,
    version    INTEGER NOT NULL,
    rules_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    read_at      TEXT,
    created_at   TEXT NOT NULL
);

-- P2 能力（表先建，接口后置） ---------------------------------------------

CREATE TABLE IF NOT EXISTS automation_templates (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    version            INTEGER NOT NULL DEFAULT 1,
    params_schema_json TEXT NOT NULL DEFAULT '{}',
    steps_json         TEXT NOT NULL DEFAULT '[]',
    approval_scope_json TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id         TEXT PRIMARY KEY,
    template_id TEXT NOT NULL REFERENCES automation_templates(id) ON DELETE CASCADE,
    host_id    TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    schedule   TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 0,
    last_run_at TEXT
);

CREATE TABLE IF NOT EXISTS knowledge_docs (
    id         TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    digest     TEXT NOT NULL,
    indexed_at TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id         TEXT PRIMARY KEY,
    doc_id     TEXT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
    chunk_no   INTEGER NOT NULL,
    text_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugins (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    version        TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    signature      TEXT,
    installed_at   TEXT,
    state          TEXT NOT NULL DEFAULT 'installed'
);
