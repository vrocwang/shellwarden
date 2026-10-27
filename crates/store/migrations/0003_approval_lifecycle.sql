-- 审批绑定的完整生命周期字段（v2 审查 P0-2）。
-- issued_at 用于审计“何时签发”；strength 记录绑定要求的最低强度。
ALTER TABLE approvals ADD COLUMN issued_at TEXT;
ALTER TABLE approvals ADD COLUMN strength TEXT NOT NULL DEFAULT 'optional';
ALTER TABLE approvals ADD COLUMN policy_digests_json TEXT NOT NULL DEFAULT '{}';

-- 同一 task + plan_version 只允许一个有效绑定，防止重复批准。
CREATE UNIQUE INDEX IF NOT EXISTS ux_approvals_active
    ON approvals(task_id, plan_version)
    WHERE decision != 'revoked';
