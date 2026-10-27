-- 审批的重新认证证据（§6.11）：需要完整往返 method/evidence_id/at。
ALTER TABLE approvals ADD COLUMN reauth_method TEXT;
ALTER TABLE approvals ADD COLUMN reauth_at TEXT;
