import { useEffect, useRef, useState, type FormEvent } from "react";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  describeError,
  isManualOnlyStep,
  isTerminalTaskStatus,
  type TaskRecord,
  type TaskStatus,
  type TaskStep,
  type TaskStepStatus
} from "./api";
import type { TaskRunner } from "./useTaskRunner";

interface Props {
  open: boolean;
  hostName: string | null;
  sessionId: string | null;
  integrationEnabled: boolean;
  /** 终端在全屏程序中：禁止执行任务步骤，避免按键写进 vim/tmux。 */
  terminalFullscreen: boolean;
  /** 终端在密码/REPL/确认提示符：禁止发送任务命令。 */
  unsafePrompt: boolean;
  runner: TaskRunner;
  onClose: () => void;
  onEnableIntegration: () => void;
}

const TASK_STATUS_LABEL: Record<TaskStatus, string> = {
  draft: "草案",
  plan_ready: "计划就绪",
  waiting_user: "等待确认",
  running: "执行中",
  revising: "模型判断中",
  paused_failed: "失败暂停",
  paused_interactive: "等待人工接管",
  completed: "已完成",
  failed: "已停止",
  cancelled: "已取消"
};

const STEP_STATUS_LABEL: Record<TaskStepStatus, string> = {
  pending: "等待上一步",
  ready: "待确认",
  running: "执行中",
  succeeded: "已完成",
  failed: "失败",
  sent: "已发送 · 结果未知",
  skipped: "已跳过",
  manual: "人工完成"
};

const CLOSED_STEP_STATUSES: TaskStepStatus[] = [
  "succeeded",
  "failed",
  "skipped",
  "manual",
  "sent"
];

/** 前一步处于这些状态才算“已处置”；failed 仍然阻塞后面的步骤。 */
const SETTLED_STEP_STATUSES: TaskStepStatus[] = [
  "succeeded",
  "skipped",
  "manual",
  "sent"
];

function stepIcon(status: TaskStepStatus): string {
  switch (status) {
    case "succeeded":
      return "✓";
    case "failed":
      return "✕";
    case "running":
    case "ready":
      return "▶";
    case "manual":
      return "✎";
    case "sent":
      return "·";
    case "skipped":
      return "–";
    default:
      return "○";
  }
}

function shortTime(value: string): string {
  return value.replace("T", " ").slice(0, 16);
}

function statusHint(task: TaskRecord): string {
  switch (task.status) {
    case "plan_ready":
      return "计划已生成。逐条确认执行；R2/R3 与交互步骤只显示命令，需要你在终端手动输入。";
    case "waiting_user":
      return "等待你确认下一步。上一步结果已写回任务。";
    case "running":
      return "步骤执行中；命令输出只取脱敏尾部，成功后才允许下一步。";
    case "revising":
      return "模型正在根据真实结果判断下一步；不会自动执行它给出的命令。";
    case "paused_failed":
      return task.failure_count >= 2
        ? "连续失败 2 次，任务已停止；请取消后重新规划，或手动处理。"
        : "上一步失败，任务已暂停。可重试、跳过（仅 R0/R1）、让 AI 诊断或取消。";
    case "paused_interactive":
      return "当前步骤需要人工接管（密码 / REPL / 全屏程序）。处理完后点「我已处理完，继续」。";
    case "completed":
      return task.outcome_summary || "任务已完成。";
    case "failed":
      return task.outcome_summary || "任务已停止。";
    case "cancelled":
      return "任务已取消；不会再发送任何步骤命令。";
    default:
      return "任务草案。";
  }
}

export function TaskPanel({
  open,
  hostName,
  sessionId,
  integrationEnabled,
  terminalFullscreen,
  unsafePrompt,
  runner,
  onClose,
  onEnableIntegration
}: Props) {
  const [goal, setGoal] = useState("");
  const [note, setNote] = useState("");
  const [editingStepId, setEditingStepId] = useState<string | null>(null);
  const [editCommand, setEditCommand] = useState("");
  const [editPurpose, setEditPurpose] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [confirmPrune, setConfirmPrune] = useState(false);
  const [confirmAuto, setConfirmAuto] = useState(false);
  const autoEnableAttemptedRef = useRef<Record<string, boolean>>({});
  const { task } = runner;

  useEffect(() => {
    if (task) setGoal("");
    setEditingStepId(null);
    setConfirmDelete(false);
    setConfirmCancel(false);
    setConfirmAuto(false);
  }, [task?.id]);

  useEffect(() => {
    setConfirmPrune(false);
  }, [sessionId]);

  useEffect(() => {
    if (!task && runner.goalDraft) setGoal(runner.goalDraft);
  }, [runner.goalDraft, task]);

  // 外部完成/刷新后任务已是终态：确保自动推进不会残留在“开启”状态。
  useEffect(() => {
    if (task && isTerminalTaskStatus(task.status) && runner.autoRun) {
      runner.setAutoRun(false);
    }
  }, [task, runner.autoRun, runner.setAutoRun]);

  // 任务模式不再要求用户先点“启用命令审计”：有任务且终端可写时自动尝试一次。
  useEffect(() => {
    if (!open || !task || integrationEnabled || !sessionId) return;
    if (isTerminalTaskStatus(task.status)) return;
    if (task.session_id && task.session_id !== sessionId) return;
    if (task.status === "running" || task.status === "paused_interactive") return;
    if (terminalFullscreen || unsafePrompt || runner.busy) return;
    if (
      runner.pendingStepId ||
      task.steps.some((step) => step.status === "running")
    ) {
      return;
    }
    if (autoEnableAttemptedRef.current[sessionId]) return;
    autoEnableAttemptedRef.current[sessionId] = true;
    onEnableIntegration();
  }, [
    open,
    sessionId,
    task,
    integrationEnabled,
    terminalFullscreen,
    unsafePrompt,
    runner.busy,
    runner.pendingStepId,
    onEnableIntegration
  ]);

  if (!open) return null;

  const submitted = task
    ? task.steps.filter((step) => CLOSED_STEP_STATUSES.includes(step.status)).length
    : 0;
  const executed = task
    ? task.steps.filter((step) =>
        ["succeeded", "failed", "sent", "manual"].includes(step.status)
      ).length
    : 0;
  const sameSession = !task?.session_id || task.session_id === sessionId;
  const blockedInTerminal = terminalFullscreen || unsafePrompt;
  const terminalBusy =
    Boolean(runner.pendingStepId) ||
    Boolean(task?.steps.some((step) => step.status === "running"));
  const canRevise =
    Boolean(task) &&
    (task?.status === "waiting_user" || task?.status === "paused_failed") &&
    executed > 0 &&
    !runner.busy;
  const interrupted =
    task?.status === "running" &&
    !task.steps.some((step) => step.status === "running") &&
    !runner.pendingStepId;
  const canEdit =
    Boolean(task) &&
    !runner.busy &&
    ["plan_ready", "waiting_user", "paused_failed"].includes(task?.status ?? "");
  const canStartAuto =
    task !== null &&
    !isTerminalTaskStatus(task.status) &&
    sameSession &&
    integrationEnabled &&
    !blockedInTerminal &&
    !terminalBusy &&
    !runner.busy;

  function startEdit(step: TaskStep) {
    setEditingStepId(step.id);
    setEditCommand(step.command_redacted);
    setEditPurpose(step.purpose);
  }

  async function saveEdit(step: TaskStep) {
    const command = editCommand.trim();
    if (!command) return;
    const ok = await runner.updateStep(step.id, command, editPurpose.trim());
    if (ok) setEditingStepId(null);
  }

  async function handleExport() {
    if (!task) return;
    try {
      const selected = await saveDialog({
        defaultPath: `shellwarden-task-${task.id}.md`,
        filters: [{ name: "Markdown", extensions: ["md"] }]
      });
      if (!selected) return;
      const target = /\.[a-z0-9]+$/i.test(selected) ? selected : `${selected}.md`;
      await runner.exportTask(target);
    } catch (err) {
      runner.notifyError(describeError(err));
    }
  }

  function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = goal.trim();
    if (!value || !sessionId) return;
    void runner.createFromGoal(value);
  }

  function renderStepActions(step: TaskStep) {
    if (!task) return null;
    if (isTerminalTaskStatus(task.status) || task.status === "cancelled") return null;
    // 模型判断中不要并行修改步骤，避免和 revise 的结果互相覆盖。
    if (task.status === "revising") return null;
    const manual = isManualOnlyStep(step);
    const earlierOpen = task.steps.some(
      (candidate) =>
        candidate.ordinal < step.ordinal &&
        !SETTLED_STEP_STATUSES.includes(candidate.status)
    );

    if (step.status === "running") {
      return (
        <div className="task-step-actions">
          <button
            type="button"
            className="secondary"
            disabled={runner.busy}
            onClick={() => void runner.markStep(step.id, "manual")}
          >
            标记完成（结果未知）
          </button>
          <button
            type="button"
            className="ghost"
            disabled={runner.busy}
            onClick={() => void runner.markStep(step.id, "failed")}
          >
            标记失败
          </button>
        </div>
      );
    }

    if (step.status === "failed") {
      return (
        <div className="task-step-actions">
          <button
            type="button"
            disabled={runner.busy}
            onClick={() => void runner.retryStep(step.id)}
          >
            重试
          </button>
          {(step.risk === "R0" || step.risk === "R1") && (
            <button
              type="button"
              className="ghost"
              disabled={runner.busy}
              onClick={() => void runner.skipStep(step.id)}
            >
              跳过
            </button>
          )}
        </div>
      );
    }

    if (step.status === "sent" || step.status === "manual") {
      return (
        <div className="task-step-actions">
          <button
            type="button"
            className="ghost"
            disabled={runner.busy}
            onClick={() => void runner.markStep(step.id, "failed")}
          >
            标记失败
          </button>
        </div>
      );
    }

    if (step.status === "pending" && earlierOpen) {
      if (!canEdit) return null;
      return (
        <div className="task-step-actions">
          <button
            type="button"
            className="ghost"
            disabled={runner.busy}
            onClick={() => startEdit(step)}
          >
            编辑
          </button>
        </div>
      );
    }

    if (step.status === "ready" || step.status === "pending") {
      return (
        <div className="task-step-actions">
          {manual ? (
            <button
              type="button"
              disabled={runner.busy || blockedInTerminal}
              title={
                terminalFullscreen
                  ? "终端在全屏程序（vim/tmux/less）中，请先退出"
                  : unsafePrompt
                    ? "终端在密码/REPL/确认提示符，请先处理完"
                    : undefined
              }
              onClick={() => void runner.markStep(step.id, "manual")}
            >
              已手动执行 · 标记完成
            </button>
          ) : (
            <button
              type="button"
              disabled={
                runner.busy ||
                !sameSession ||
                blockedInTerminal ||
                !["plan_ready", "waiting_user"].includes(task.status)
              }
              title={
                terminalFullscreen
                  ? "终端在全屏程序（vim/tmux/less）中，请先退出"
                  : unsafePrompt
                    ? "终端在密码/REPL/确认提示符，请先处理完"
                    : sameSession
                      ? undefined
                      : "任务属于另一个会话，不能在这里执行"
              }
              onClick={() => void runner.startStep(step.id)}
            >
              执行
            </button>
          )}
          {(step.risk === "R0" || step.risk === "R1") && (
            <button
              type="button"
              className="ghost"
              disabled={runner.busy}
              onClick={() => void runner.skipStep(step.id)}
            >
              跳过
            </button>
          )}
          {canEdit && (
            <button
              type="button"
              className="ghost"
              disabled={runner.busy}
              onClick={() => startEdit(step)}
            >
              编辑
            </button>
          )}
          {manual && (
            <span className="muted small">请先在终端手动输入完整命令</span>
          )}
        </div>
      );
    }

    return null;
  }

  return (
    <aside className="task-drawer" aria-label="任务模式">
      <header className="task-drawer-header">
        <div>
          <h3>任务模式</h3>
          <p className="muted small">
            {hostName ? `${hostName} · 逐条确认 · 失败停止` : "逐条确认 · 失败停止"}
          </p>
        </div>
        <div className="task-drawer-actions">
          {task && isTerminalTaskStatus(task.status) && (
            <button
              type="button"
              className="primary"
              disabled={runner.busy}
              title="回到新建任务，旧任务保留在任务历史"
              onClick={runner.clearTask}
            >
              新建任务
            </button>
          )}
          <button type="button" className="ghost" onClick={onClose} aria-label="关闭任务面板">
            ×
          </button>
        </div>
      </header>

      {!integrationEnabled ? (
        <div className="task-integration">
          <p className="small">
            未检测到 bash/zsh 命令审计（OSC 133）。任务模式会自动尝试启用；若未生效，任务仍可执行，
            但步骤成功/失败需要手动标记。
          </p>
          <button
            type="button"
            className="ghost"
            onClick={onEnableIntegration}
            disabled={!sessionId || blockedInTerminal || terminalBusy || runner.busy}
            title={
              terminalBusy
                ? "任务步骤正在执行；先等待完成或取消后再启用"
                : runner.busy
                  ? "当前有任务操作进行中；稍后再启用"
                  : blockedInTerminal
                    ? "终端在全屏程序或密码/REPL 提示符，先处理完再写入集成脚本"
                    : undefined
            }
          >
            启用命令审计
          </button>
        </div>
      ) : (
        <p className="task-integration ok small">命令审计已启用：可自动读取退出码与输出尾部。</p>
      )}

      {runner.error && <div className="error task-error">{runner.error}</div>}
      {runner.message && (
        <div className="notice task-message">
          <span>{runner.message}</span>
          <button type="button" className="ghost" onClick={runner.clearNotice}>
            知道了
          </button>
        </div>
      )}

      {!sessionId ? (
        <p className="muted">连接主机并打开终端后才能创建任务。</p>
      ) : !task ? (
        <form className="task-goal-form" onSubmit={handleCreate}>
          <label>
            描述一个需要多步完成的目标
            <textarea
              rows={3}
              value={goal}
              onChange={(event) => setGoal(event.target.value)}
              placeholder="例如：检查 nginx 配置并重载，确认本地端口可访问"
              maxLength={2000}
            />
          </label>
          <button type="submit" disabled={runner.busy || goal.trim().length === 0}>
            {runner.busy ? "生成中…" : "生成任务计划"}
          </button>
          <p className="muted small">
            模型只生成 1–5 步草案；服务端会重新分级风险。R2/R3 不会出现自动执行按钮。
          </p>
        </form>
      ) : (
        <section className="task-detail">
          <header className="task-detail-header">
            <div>
              <h4>{task.title}</h4>
              <p className="muted small">{task.summary}</p>
            </div>
            <span className={`task-status-badge ${task.status}`}>
              {TASK_STATUS_LABEL[task.status]}
            </span>
          </header>
          <div className="task-detail-tools">
            <button
              type="button"
              className="ghost"
              disabled={runner.busy}
              onClick={() => void runner.refresh()}
            >
              刷新
            </button>
            <button
              type="button"
              className="ghost"
              disabled={runner.busy}
              onClick={() => void handleExport()}
            >
              导出
            </button>
            {isTerminalTaskStatus(task.status) && (
              <>
                <button
                  type="button"
                  className="ghost"
                  disabled={runner.busy}
                  onClick={() => setConfirmDelete(true)}
                >
                  删除
                </button>
              </>
            )}
          </div>
          {confirmDelete && (
            <div className="task-confirm">
              <span>删除这个任务？任务与步骤不可恢复；审计事件会保留。</span>
              <button
                type="button"
                disabled={runner.busy}
                onClick={() => {
                  setConfirmDelete(false);
                  void runner.deleteTask();
                }}
              >
                确认删除
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => setConfirmDelete(false)}
              >
                取消
              </button>
            </div>
          )}

          {!sameSession && (
            <p className="task-warn small">
              该任务属于另一个终端会话；这里只能查看、标记结果或取消，不能执行命令。
            </p>
          )}
          <p className="task-progress small">
            进度 {submitted}/{task.steps.length} · 预算 {task.steps.length}/{task.step_limit}
            {task.failure_count > 0 ? ` · 连续失败 ${task.failure_count}` : ""}
          </p>
          <p className="task-hint small">{statusHint(task)}</p>
          {task.status === "waiting_user" &&
            !task.steps.some(
              (step) => step.status === "pending" || step.status === "ready"
            ) && (
              <p className="task-hint small">
                计划中的步骤已全部处理；点「让 AI 判断下一步」确认是否完成，或取消任务。
              </p>
            )}

          {terminalFullscreen && (
            <p className="task-warn small">
              终端当前在全屏程序（vim/tmux/less）中，任务步骤已禁止执行；请先退出该程序。
            </p>
          )}
          {unsafePrompt && (
            <p className="task-warn small">
              终端当前在密码/REPL/确认提示符；为避免把命令或 Ctrl-U 打进提示符，任务步骤已暂停执行。
            </p>
          )}

          {interrupted && (
            <p className="task-warn small">
              任务可能已中断（应用刷新或命令没有产生结束信号）。请在下方标记该步骤完成/失败，
              或恢复任务后重新确认。
            </p>
          )}

          {!isTerminalTaskStatus(task.status) && (
            <div className="task-auto">
              <label className="task-auto-toggle">
              <input
                type="checkbox"
                checked={runner.autoRun}
                disabled={!runner.autoRun && !canStartAuto}
                onChange={(event) => {
                  if (event.target.checked) {
                    setConfirmAuto(true);
                  } else {
                    runner.setAutoRun(false);
                  }
                }}
              />
              <span>自动推进（仅 R0/R1）</span>
            </label>
            <p className="muted small">
              自动执行只读步骤并让 AI 判断下一步；R2/R3、交互、失败、结果未知时暂停。
            </p>
            {!integrationEnabled && (
              <p className="muted small">
                自动推进需要命令审计；任务模式会自动尝试启用，未生效时可手动点击上方
                「启用命令审计」。
              </p>
            )}
              {runner.autoRun && (
                <p className="task-hint small">
                  自动推进已开启；遇到需要人工的步骤会暂停，完成/跳过/重试后继续。
                </p>
              )}
            </div>
          )}
          {confirmAuto && !isTerminalTaskStatus(task.status) && (
            <div className="task-confirm">
              <span>
                自动推进只会自动执行 R0/R1 步骤；风险分类不是完整 shell 分析，仍可能执行
                非预期命令。R2/R3、交互、失败、结果未知时会暂停。确认开启？
              </span>
              <button
                type="button"
                onClick={() => {
                  setConfirmAuto(false);
                  runner.setAutoRun(true);
                }}
              >
                开启自动推进
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => setConfirmAuto(false)}
              >
                取消
              </button>
            </div>
          )}

          {(task.status === "waiting_user" || task.status === "paused_failed") && (
            <label className="task-note">
              补充说明（可选，脱敏后发给模型）
              <textarea
                rows={2}
                value={note}
                onChange={(event) => setNote(event.target.value)}
                placeholder="例如：我刚改过配置；或某个服务本来就停着"
                maxLength={500}
              />
            </label>
          )}

          <div className="task-actions">
            {(task.status === "paused_interactive" || interrupted) && (
              <button
                type="button"
                disabled={runner.busy}
                onClick={() => void runner.resumeInterrupted()}
              >
                {interrupted ? "恢复任务" : "我已处理完，继续"}
              </button>
            )}
            {task.status === "revising" && (
              <button
                type="button"
                disabled={runner.busy}
                onClick={() => void runner.resumeRevising()}
              >
                恢复
              </button>
            )}
            {canRevise && (
              <button
                type="button"
                disabled={runner.busy}
                onClick={() => void runner.revise(note)}
              >
                {runner.busy ? "判断中…" : "让 AI 判断下一步"}
              </button>
            )}
            {task.status !== "cancelled" && !isTerminalTaskStatus(task.status) &&
              (confirmCancel ? (
                <>
                  <button
                    type="button"
                    disabled={runner.busy && task.status !== "revising"}
                    onClick={() => {
                      setConfirmCancel(false);
                      void runner.cancel();
                    }}
                  >
                    确认取消
                  </button>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => setConfirmCancel(false)}
                  >
                    保持任务
                  </button>
                  <span className="muted small">
                    取消后不再发送后续步骤
                    {task.status === "running" ? "；当前正在运行的命令可能继续" : ""}
                    {task.status === "revising" ? "；模型判断会中断" : ""}
                    。
                  </span>
                </>
              ) : (
                <button
                  type="button"
                  className="ghost"
                  onClick={() => setConfirmCancel(true)}
                >
                  {task.status === "revising"
                    ? "取消任务（中断模型判断）"
                    : task.status === "running"
                      ? "取消任务（不中断当前命令）"
                      : "取消任务"}
                </button>
              ))}
          </div>

          <ol className="task-steps">
            {task.steps.map((step) => (
              <li key={step.id} className={`task-step ${step.status}`}>
                <div className="task-step-head">
                  <span className={`task-step-icon ${step.status}`}>{stepIcon(step.status)}</span>
                  <span className="task-step-ordinal">{step.ordinal}.</span>
                  <code className="task-step-command" title={step.command_redacted}>
                    {step.command_redacted}
                  </code>
                  <span className={`risk-badge ${step.risk.toLowerCase()}`}>{step.risk}</span>
                  <span className={`task-step-status ${step.status}`}>
                    {STEP_STATUS_LABEL[step.status]}
                  </span>
                </div>
                {editingStepId === step.id ? (
                  <div className="task-step-editor">
                    <label>
                      命令
                      <input
                        value={editCommand}
                        onChange={(event) => setEditCommand(event.target.value)}
                        maxLength={2000}
                        autoFocus
                      />
                    </label>
                    <label>
                      目的（可选）
                      <input
                        value={editPurpose}
                        onChange={(event) => setEditPurpose(event.target.value)}
                        maxLength={400}
                      />
                    </label>
                    <div className="task-step-actions">
                      <button
                        type="button"
                        disabled={runner.busy || editCommand.trim().length === 0}
                        onClick={() => void saveEdit(step)}
                      >
                        保存
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => setEditingStepId(null)}
                      >
                        取消
                      </button>
                    </div>
                    <p className="muted small">
                      保存后服务端会重新分级风险；改成 R2/R3 会变成手动步骤，命令仍必须逐条确认。
                    </p>
                  </div>
                ) : (
                  <>
                    {step.purpose && (
                      <p className="task-step-purpose small">{step.purpose}</p>
                    )}
                    {step.interactive_hint && (
                      <p className="task-step-note small">需要交互：不会自动执行。</p>
                    )}
                    {step.status === "running" && (
                      <p className="task-step-note small">
                        执行中… 输出不会实时回传模型；结束后只回灌脱敏尾部。
                      </p>
                    )}
                    {step.exit_code !== null && (
                      <p className="task-step-note small">exit {step.exit_code}</p>
                    )}
                    {step.audit_seq !== null && (
                      <p className="task-step-note small">审计 #{step.audit_seq}</p>
                    )}
                    {step.output_tail_redacted && (
                      <details className="task-output">
                        <summary>
                          输出摘要（已脱敏 · 最近{" "}
                          {step.output_tail_redacted.split("\n").length} 行）
                        </summary>
                        <pre>{step.output_tail_redacted}</pre>
                      </details>
                    )}
                    {renderStepActions(step)}
                  </>
                )}
              </li>
            ))}
          </ol>

          <details className="task-goal">
            <summary>原始目标（已脱敏）</summary>
            <pre>{task.goal_redacted}</pre>
          </details>
        </section>
      )}

      <details className="task-history" open={Boolean(task) && runner.history.length > 1}>
        <summary>任务历史（{runner.history.length}）</summary>
        <div className="task-history-tools">
          {confirmPrune ? (
            <>
              <span className="muted small">
                按当前策略清理本机终态任务？审计事件保留。
              </span>
              <button
                type="button"
                disabled={runner.busy}
                onClick={() => {
                  setConfirmPrune(false);
                  void runner.pruneHistory();
                }}
              >
                确认清理
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => setConfirmPrune(false)}
              >
                取消
              </button>
            </>
          ) : (
            <button
              type="button"
              className="ghost"
              disabled={runner.busy || runner.history.length === 0}
              onClick={() => setConfirmPrune(true)}
            >
              清理历史
            </button>
          )}
        </div>
        {runner.history.length === 0 ? (
          <p className="muted small">还没有任务记录。</p>
        ) : (
          <ul className="task-history-list">
            {runner.history.map((row) => (
              <li key={row.id} className={task?.id === row.id ? "active" : undefined}>
                <button
                  type="button"
                  className="task-history-main"
                  disabled={runner.busy}
                  onClick={() => void runner.loadTask(row.id)}
                >
                  <strong>{row.title}</strong>
                  <span>
                    {TASK_STATUS_LABEL[row.status]} · {shortTime(row.created_at)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </details>
    </aside>
  );
}
