import { invoke } from "@tauri-apps/api/core";

export interface AppInfo {
  name: string;
  version: string;
  db_schema: number;
  host_count: number;
  config_path: string;
  data_dir: string;
  shortcut_copy: string;
  shortcut_paste: string;
}

export interface ShortcutsConfig {
  copy: string;
  paste: string;
}

export interface Host {
  id: string;
  name: string;
  hostname: string;
  port: number;
  default_username: string;
  tags: string[];
  ssh_backend: string;
  group_name: string;
  created_at: string;
  updated_at: string;
}

export interface NewHost {
  name: string;
  hostname: string;
  port: number;
  default_username: string;
  tags: string[];
  ssh_backend: string;
  group_name: string;
}

export interface Check {
  name: string;
  passed: boolean;
  detail: string;
}

export interface SelfCheck {
  passed: boolean;
  checks: Check[];
}

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function openConfigDir(): Promise<void> {
  return invoke<void>("open_config_dir");
}

export function getAppInfo(): Promise<AppInfo> {
  return invoke<AppInfo>("app_info");
}

export function saveShortcuts(copy: string, paste: string): Promise<void> {
  return invoke<void>("save_shortcuts", { copy, paste });
}

export function listHosts(): Promise<Host[]> {
  return invoke<Host[]>("list_hosts");
}

export function createHost(input: NewHost): Promise<Host> {
  return invoke<Host>("create_host", { input });
}

export function deleteHost(id: string): Promise<boolean> {
  return invoke<boolean>("delete_host", { id });
}

export function runSelfCheck(): Promise<SelfCheck> {
  return invoke<SelfCheck>("self_check");
}

export function describeError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && "message" in error) {
    const withCode = error as { code?: string; message?: string };
    return withCode.code ? `${withCode.code}: ${withCode.message ?? ""}` : String(withCode.message);
  }
  return String(error);
}

// ---- SSH ----------------------------------------------------------------

export interface HostKeyInfo {
  algorithm: string;
  fingerprint: string;
}

export type TrustState =
  | { state: "unknown" }
  | { state: "trusted" }
  | { state: "changed"; known: HostKeyInfo };

export interface ProbeResult {
  probe_id: string;
  host_key: HostKeyInfo;
  trust: TrustState;
}

export interface OpenSessionInput {
  host_id: string;
  username?: string;
  password?: string;
  key_path?: string;
  key_pem?: string;
  passphrase?: string;
  remember_password?: boolean;
  remember_key?: boolean;
  cols?: number;
  rows?: number;
}

export interface OpenSessionResult {
  session_id: string;
  host_key: HostKeyInfo;
}

export interface SessionDataEvent {
  session_id: string;
  encoding: string;
  data: string;
}

export interface SessionClosedEvent {
  session_id: string;
  exit_code: number | null;
}

export interface SessionErrorEvent {
  session_id: string;
  message: string;
}

export function probeHost(hostId: string): Promise<ProbeResult> {
  return invoke<ProbeResult>("probe_host", { hostId });
}

export function trustHost(hostId: string, probeId: string): Promise<void> {
  return invoke<void>("trust_host", { hostId, probeId });
}

export function openSession(input: OpenSessionInput): Promise<OpenSessionResult> {
  return invoke<OpenSessionResult>("open_session", { input });
}

export function writeSession(sessionId: string, dataBase64: string): Promise<void> {
  return invoke<void>("write_session", { sessionId, data: dataBase64 });
}

export function resizeSession(sessionId: string, cols: number, rows: number): Promise<void> {
  return invoke<void>("resize_session", { sessionId, cols, rows });
}

export function sessionDetach(sessionId: string): Promise<void> {
  return invoke<void>("session_detach", { sessionId });
}

export function sessionAttach(sessionId: string): Promise<string> {
  return invoke<string>("session_attach", { sessionId });
}

export function closeSession(sessionId: string): Promise<void> {
  return invoke<void>("close_session", { sessionId });
}

export function encodeBase64(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...Array.from(bytes.subarray(i, i + chunk)));
  }
  return btoa(binary);
}

export function decodeBase64(data: string): Uint8Array {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export interface DraftCommandInput {
  host_id: string;
  request: string;
  base_url: string;
  model: string;
  api_key: string;
  timeout_secs?: number;
  max_tokens?: number;
}

export interface CommandOption {
  command: string;
  explanation: string;
  risk: string;
  manual_only: boolean;
}

export interface DraftCommandResult {
  commands: CommandOption[];
  model: string;
  prompt_version: string;
}

export function auditAiCommand(input: {
  session_id: string;
  command: string;
  risk: string;
}): Promise<void> {
  return invoke<void>("audit_ai_command", { input });
}

export function draftCommand(input: DraftCommandInput): Promise<DraftCommandResult> {
  return invoke<DraftCommandResult>("draft_command", { input });
}

// ---- 任务模式（阶段 1/2） ------------------------------------------------

export type TaskStatus =
  | "draft"
  | "plan_ready"
  | "waiting_user"
  | "running"
  | "revising"
  | "paused_failed"
  | "paused_interactive"
  | "completed"
  | "failed"
  | "cancelled";

export type TaskStepStatus =
  | "pending"
  | "ready"
  | "running"
  | "succeeded"
  | "failed"
  | "sent"
  | "skipped"
  | "manual";

export interface TaskStep {
  id: string;
  task_id: string;
  ordinal: number;
  command_redacted: string;
  purpose: string;
  risk: string;
  status: TaskStepStatus;
  exit_code: number | null;
  output_tail_redacted: string;
  interactive_hint: boolean;
  started_at: string | null;
  finished_at: string | null;
  audit_seq: number | null;
}

export interface TaskRecord {
  id: string;
  host_id: string;
  session_id: string | null;
  batch_id: string | null;
  goal_redacted: string;
  title: string;
  summary: string;
  outcome_summary: string;
  status: TaskStatus;
  step_limit: number;
  failure_count: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  steps: TaskStep[];
}

export type TaskSummary = Omit<TaskRecord, "steps">;

export interface DraftTaskStepOption {
  command: string;
  purpose: string;
  risk: string;
  risk_hint: string;
  manual_only: boolean;
  interactive_hint: boolean;
}

export interface DraftTaskResult {
  title: string;
  summary: string;
  steps: DraftTaskStepOption[];
  model: string;
  prompt_version: string;
  step_limit: number;
}

export interface DraftTaskInput {
  host_id: string;
  request: string;
  base_url: string;
  model: string;
  api_key: string;
  timeout_secs?: number;
  max_tokens?: number;
}

export interface CreateTaskStepInput {
  command: string;
  purpose: string;
  risk_hint: string;
  interactive_hint: boolean;
}

export interface CreateTaskInput {
  host_id: string;
  session_id?: string;
  batch_id?: string;
  goal: string;
  title: string;
  summary: string;
  step_limit: number;
  steps: CreateTaskStepInput[];
}

export interface TaskBatch {
  id: string;
  goal_redacted: string;
  title: string;
  host_ids: string[];
  status: "running" | "paused" | "done" | "cancelled";
  current_index: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export interface CreateTaskBatchInput {
  goal: string;
  title: string;
  host_ids: string[];
}

export function createTaskBatch(input: CreateTaskBatchInput): Promise<TaskBatch> {
  return invoke<TaskBatch>("create_task_batch", { input });
}

export function taskBatchGet(batchId: string): Promise<TaskBatch | null> {
  return invoke<TaskBatch | null>("task_batch_get", { batchId });
}

export function taskBatchListActive(limit = 10): Promise<TaskBatch[]> {
  return invoke<TaskBatch[]>("task_batch_list_active", { limit });
}

export function taskBatchUpdate(
  id: string,
  status: TaskBatch["status"],
  currentIndex: number
): Promise<void> {
  return invoke<void>("task_batch_update", {
    input: { id, status, current_index: currentIndex }
  });
}

export function taskBatchTasks(batchId: string): Promise<TaskSummary[]> {
  return invoke<TaskSummary[]>("task_batch_tasks", { batchId });
}

/** 批次恢复：把任务绑定到重连后的新会话。 */
export function taskBindSession(
  taskId: string,
  sessionId: string,
  hostId: string
): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_bind_session", { taskId, sessionId, hostId });
}

export interface TaskStepFinishedInput {
  task_id: string;
  step_id: string;
  exit_code: number | null;
  output_tail: string;
  status?: "sent" | "manual" | "skipped" | "failed" | "succeeded";
}

export interface TaskReviseResult {
  task: TaskRecord;
  decision: "continue" | "done" | "needs_user";
  message: string;
}

export function draftTask(input: DraftTaskInput): Promise<DraftTaskResult> {
  return invoke<DraftTaskResult>("draft_task", { input });
}

export function createTask(input: CreateTaskInput): Promise<TaskRecord> {
  return invoke<TaskRecord>("create_task", { input });
}

export function taskGet(taskId: string): Promise<TaskRecord | null> {
  return invoke<TaskRecord | null>("task_get", { taskId });
}

export function taskList(params: {
  host_id?: string;
  session_id?: string;
  batch_id?: string;
  limit?: number;
}): Promise<TaskSummary[]> {
  return invoke<TaskSummary[]>("task_list", {
    hostId: params.host_id,
    sessionId: params.session_id,
    batchId: params.batch_id,
    limit: params.limit
  });
}

export function taskStepStarted(
  taskId: string,
  stepId: string,
  auto = false
): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_step_started", { taskId, stepId, auto });
}

export function taskStepFinished(input: TaskStepFinishedInput): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_step_finished", { input });
}

export function taskStepInteractive(
  taskId: string,
  stepId: string,
  reason?: string
): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_step_interactive", { taskId, stepId, reason });
}

export function taskStepSkip(taskId: string, stepId: string): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_step_skip", { taskId, stepId });
}

export function taskStepRetry(taskId: string, stepId: string): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_step_retry", { taskId, stepId });
}

export interface TaskStepUpdateInput {
  task_id: string;
  step_id: string;
  command: string;
  purpose?: string;
  interactive_hint?: boolean;
}

export function taskStepUpdate(input: TaskStepUpdateInput): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_step_update", { input });
}

export function taskDelete(taskId: string): Promise<void> {
  return invoke<void>("task_delete", { taskId });
}

export function taskExportMarkdown(taskId: string): Promise<string> {
  return invoke<string>("task_export_markdown", { taskId });
}

export function saveTaskExport(taskId: string, path: string): Promise<string> {
  return invoke<string>("save_task_export", { taskId, path });
}

export function saveBatchExport(batchId: string, path: string): Promise<string> {
  return invoke<string>("save_batch_export", { batchId, path });
}

export interface TaskPruneReport {
  deleted: number;
  remaining_terminal: number;
  age_cutoff: string | null;
}

export interface TaskHistorySettings {
  keep_days: number;
  max_terminal: number;
}

export function taskHistoryPrune(params?: {
  host_id?: string;
  keep_days?: number;
  max_terminal?: number;
}): Promise<TaskPruneReport> {
  return invoke<TaskPruneReport>("task_history_prune", {
    hostId: params?.host_id,
    keepDays: params?.keep_days,
    maxTerminal: params?.max_terminal
  });
}

export function loadTaskHistorySettings(): Promise<TaskHistorySettings> {
  return invoke<TaskHistorySettings>("load_task_history_settings");
}

export function saveTaskHistorySettings(
  keepDays: number,
  maxTerminal: number
): Promise<TaskHistorySettings> {
  return invoke<TaskHistorySettings>("save_task_history_settings", {
    keepDays,
    maxTerminal
  });
}

export function taskRevise(input: {
  task_id: string;
  user_note?: string;
  base_url: string;
  model: string;
  api_key: string;
  timeout_secs?: number;
  max_tokens?: number;
}): Promise<TaskReviseResult> {
  return invoke<TaskReviseResult>("task_revise", { input });
}

export function taskResume(taskId: string): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_resume", { taskId });
}

export function taskCancel(taskId: string): Promise<TaskRecord> {
  return invoke<TaskRecord>("task_cancel", { taskId });
}

export function isTerminalTaskStatus(status: TaskStatus): boolean {
  return status === "completed" || status === "failed" || status === "cancelled";
}

export function isManualOnlyStep(step: TaskStep): boolean {
  return step.risk === "R2" || step.risk === "R3" || step.interactive_hint;
}

// ---- 凭证与已信任指纹 ----------------------------------------------------

export function hostTrust(hostId: string): Promise<HostKeyInfo | null> {
  return invoke<HostKeyInfo | null>("host_trust", { hostId });
}

export function hostCredentialsStatus(hostId: string): Promise<boolean> {
  return invoke<boolean>("host_credentials_status", { hostId });
}

export function saveHostPassword(hostId: string, password: string): Promise<void> {
  return invoke<void>("save_host_password", { hostId, password });
}

export function deleteHostPassword(hostId: string): Promise<void> {
  return invoke<void>("delete_host_password", { hostId });
}

export interface HostKeyAuthStatus {
  mode: "file" | "pem" | null;
  key_path: string | null;
  has_passphrase: boolean;
  has_private_key: boolean;
}

export function hostKeyAuthStatus(hostId: string): Promise<HostKeyAuthStatus> {
  return invoke<HostKeyAuthStatus>("host_key_auth_status", { hostId });
}

export function saveHostKeyFile(
  hostId: string,
  keyPath: string,
  passphrase?: string
): Promise<void> {
  return invoke<void>("save_host_key_file", {
    hostId,
    keyPath,
    passphrase
  });
}

export function saveHostPrivateKey(
  hostId: string,
  keyPem: string,
  passphrase?: string
): Promise<void> {
  return invoke<void>("save_host_private_key", {
    hostId,
    keyPem,
    passphrase
  });
}

export function deleteHostKeyAuth(hostId: string): Promise<void> {
  return invoke<void>("delete_host_key_auth", { hostId });
}

export function hostPrivateKeyStatus(hostId: string): Promise<boolean> {
  return invoke<boolean>("host_private_key_status", { hostId });
}

export function deleteHostPrivateKey(hostId: string): Promise<void> {
  return invoke<void>("delete_host_private_key", { hostId });
}

export interface ProviderConfig {
  baseUrl: string;
  model: string;
  apiKey: string;
  /** 服务端是否已保存密钥（前端拿不到明文）。 */
  hasKey: boolean;
}

export interface SessionAuditEvent {
  seq: number;
  event_type: string;
  timestamp: string;
  actor: string;
  payload: unknown;
}

export function enableShellIntegration(sessionId: string): Promise<void> {
  return invoke<void>("enable_shell_integration", { sessionId });
}

export function sessionAudit(sessionId: string, limit = 200): Promise<SessionAuditEvent[]> {
  return invoke<SessionAuditEvent[]>("session_audit", { sessionId, limit });
}

export interface TerminalCommandRow {
  id: string;
  session_id: string;
  host_id: string | null;
  command_redacted: string;
  exit_code: number | null;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  state_unknown: boolean;
}

export function terminalCommands(
  sessionId: string,
  limit = 200
): Promise<TerminalCommandRow[]> {
  return invoke<TerminalCommandRow[]>("terminal_commands", { sessionId, limit });
}

export function recordTerminalCommand(input: {
  session_id: string;
  command: string;
  exit_code: number | null;
  started_at: string;
}): Promise<void> {
  return invoke<void>("record_terminal_command", { input });
}

// ---- 配置修改 ------------------------------------------------------------

export interface UpdateHostInput {
  id: string;
  name: string;
  hostname: string;
  port: number;
  default_username: string;
  tags: string[];
  ssh_backend: string;
  group_name: string;
}

export function updateHost(input: UpdateHostInput): Promise<Host> {
  return invoke<Host>("update_host", { input });
}

export interface StoredProvider {
  base_url: string;
  model: string;
  has_key: boolean;
}

export function loadModelProvider(): Promise<StoredProvider> {
  return invoke<StoredProvider>("load_model_provider");
}

export interface SaveProviderInput {
  base_url: string;
  model: string;
  api_key?: string;
  remember_key: boolean;
}

export function saveModelProvider(input: SaveProviderInput): Promise<void> {
  return invoke<void>("save_model_provider", {
    baseUrl: input.base_url,
    model: input.model,
    apiKey: input.api_key,
    rememberKey: input.remember_key
  });
}

// ---- 输入意图 ------------------------------------------------------------

export interface ClassifyInputResult {
  intent: "shell" | "ai" | "ambiguous";
  text: string;
  probe: string | null;
}

export function classifyInput(input: string): Promise<ClassifyInputResult> {
  return invoke<ClassifyInputResult>("classify_input", { input });
}

export function commandExists(sessionId: string, command: string): Promise<boolean> {
  return invoke<boolean>("command_exists", { sessionId, command });
}
