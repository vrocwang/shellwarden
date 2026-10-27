-- 工具/Grant/任务计划路径已删除；本迁移清理旧表。
-- 保留：hosts、identities、host_keys、sessions、audit_events、terminal_commands、
--       host_credentials、settings、schema_migrations。
DROP TABLE IF EXISTS task_steps;
DROP TABLE IF EXISTS verifications;
DROP TABLE IF EXISTS preconditions;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS plans;
DROP TABLE IF EXISTS execution_contexts;
DROP TABLE IF EXISTS model_contexts;
DROP TABLE IF EXISTS policy_decisions;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS policy_versions;
DROP TABLE IF EXISTS policy_profiles;
DROP TABLE IF EXISTS tool_permissions;
DROP TABLE IF EXISTS tool_versions;
DROP TABLE IF EXISTS tools;
DROP TABLE IF EXISTS ai_tasks;
DROP TABLE IF EXISTS reauth_evidence;
DROP TABLE IF EXISTS session_recordings;
DROP TABLE IF EXISTS file_operations;
DROP TABLE IF EXISTS audit_checkpoints;
DROP TABLE IF EXISTS host_capabilities;
DROP TABLE IF EXISTS model_providers;
DROP TABLE IF EXISTS prompt_versions;
DROP TABLE IF EXISTS redaction_rules;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS scheduled_tasks;
DROP TABLE IF EXISTS automation_templates;
DROP TABLE IF EXISTS knowledge_chunks;
DROP TABLE IF EXISTS knowledge_docs;
DROP TABLE IF EXISTS plugins;
