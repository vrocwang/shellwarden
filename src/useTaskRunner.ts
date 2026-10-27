import { useCallback, useEffect, useRef, useState } from "react";
import {
  createTask,
  describeError,
  draftTask,
  isManualOnlyStep,
  isTerminalTaskStatus,
  saveTaskExport,
  taskCancel,
  taskHistoryPrune,
  taskDelete,
  taskGet,
  taskList,
  taskResume,
  taskRevise,
  taskStepFinished,
  taskStepInteractive,
  taskStepRetry,
  taskStepSkip,
  taskStepStarted,
  taskStepUpdate,
  type ProviderConfig,
  type TaskRecord,
  type TaskStep,
  type TaskStepStatus,
  type TaskSummary
} from "./api";

/** 单步等待上限：超时后暂停，宁可让用户接管，也不自动继续。 */
export const STEP_TIMEOUT_MS = 120_000;

export interface TaskCommandFinished {
  sessionId: string;
  command: string;
  exitCode: number | null;
  durationMs: number;
  outputTail: string;
}

export interface TaskRunnerOptions {
  hostId: string | null;
  sessionId: string | null;
  provider: ProviderConfig;
  /** 由 App 提供：必须走 writeSession，不在这里拼 shell 命令。 */
  sendCommand: (sessionId: string, command: string) => Promise<void>;
  /** 发送前检查终端状态（例如全屏程序）；返回原因则拒绝执行。 */
  beforeSend?: (sessionId: string) => string | null;
  /** 当前会话是否已观察到 OSC 133；自动推进必须在能拿到退出码时运行。 */
  integrationEnabled: boolean;
  onModelRequired?: () => void;
}

export interface TaskRunner {
  task: TaskRecord | null;
  history: TaskSummary[];
  busy: boolean;
  error: string | null;
  message: string | null;
  pendingStepId: string | null;
  /** 最近一次尝试生成失败的目标，用于回填输入框。 */
  goalDraft: string | null;
  /** 自动推进：只自动执行 R0/R1，并自动让 AI 判断下一步。 */
  autoRun: boolean;
  setAutoRun: (enabled: boolean) => void;
  createFromGoal: (goal: string) => Promise<void>;
  startStep: (stepId: string) => Promise<void>;
  markStep: (stepId: string, outcome: "manual" | "failed") => Promise<void>;
  skipStep: (stepId: string) => Promise<void>;
  retryStep: (stepId: string) => Promise<void>;
  updateStep: (stepId: string, command: string, purpose: string) => Promise<boolean>;
  deleteTask: () => Promise<void>;
  exportTask: (path: string) => Promise<void>;
  pruneHistory: () => Promise<void>;
  notifyError: (message: string) => void;
  revise: (note?: string) => Promise<void>;
  resumeInterrupted: () => Promise<void>;
  resumeRevising: () => Promise<void>;
  cancel: () => Promise<void>;
  loadTask: (taskId: string) => Promise<void>;
  refresh: () => Promise<void>;
  clearTask: () => void;
  handleCommandFinished: (event: TaskCommandFinished) => void;
  handleInteractive: (sessionId: string, reason: string) => void;
  clearNotice: () => void;
}

const AUTO_SETTLED_STATUSES: TaskStepStatus[] = ["succeeded", "skipped", "manual"];

/** 找到下一个可执行的步骤；前面有未成功/跳过/人工完成的步骤时不越过。 */
function nextAutoStep(task: TaskRecord): TaskStep | null {
  const ordered = [...task.steps].sort((a, b) => a.ordinal - b.ordinal);
  for (const step of ordered) {
    if (step.status !== "pending" && step.status !== "ready") continue;
    const earlierOpen = task.steps.some(
      (candidate) =>
        candidate.ordinal < step.ordinal &&
        !AUTO_SETTLED_STATUSES.includes(candidate.status)
    );
    if (earlierOpen) return null;
    return step;
  }
  return null;
}

function normalizeCommand(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function errorCode(error: unknown): string | undefined {
  if (error && typeof error === "object" && "code" in error) {
    return (error as { code?: string }).code;
  }
  return undefined;
}

/**
 * 任务控制器：状态机在服务端，这里只负责
 * 创建 / 确认执行 / 等 OSC 结束 / 回灌 / 恢复。
 *
 * 不变量：
 * - 每次只跟踪一个 pending step；
 * - 命令写入失败或超时都降级为“结果未知”，不自动重试；
 * - 交互提示、全屏程序立即暂停任务，交还用户；
 * - 只把 OSC 133 D 的输出尾部交给服务端脱敏后回灌模型。
 */
export function useTaskRunner(options: TaskRunnerOptions): TaskRunner {
  const [task, setTask] = useState<TaskRecord | null>(null);
  const [history, setHistory] = useState<TaskSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [pendingStepId, setPendingStepId] = useState<string | null>(null);
  const [goalDraft, setGoalDraft] = useState<string | null>(null);
  const [autoRun, setAutoRunState] = useState(false);

  const optionsRef = useRef(options);
  optionsRef.current = options;
  const taskRef = useRef<TaskRecord | null>(null);
  taskRef.current = task;
  const pendingRef = useRef<string | null>(null);
  const timerRef = useRef<number | null>(null);
  const busyRef = useRef(false);
  /** 已提交过结果的 step id：防止重复 OSC 事件重复写库。 */
  const finishedStepsRef = useRef<Set<string>>(new Set());
  const autoRunRef = useRef(false);
  autoRunRef.current = autoRun;
  /** advanceAuto 在 revise/startTimer 之前定义会形成循环；用 ref 延迟取最新实现。 */
  const advanceRef = useRef<() => void>(() => undefined);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const clearPending = useCallback(() => {
    pendingRef.current = null;
    setPendingStepId(null);
    clearTimer();
  }, [clearTimer]);

  const resetAutoRun = useCallback(() => {
    autoRunRef.current = false;
    setAutoRunState(false);
  }, []);

  const stopAutoRun = useCallback((reason: string) => {
    autoRunRef.current = false;
    setAutoRunState(false);
    setMessage(reason);
  }, []);

  const pauseAutoRun = useCallback((reason: string) => {
    if (autoRunRef.current) setMessage(reason);
  }, []);

  const fail = useCallback((caught: unknown) => {
    if (errorCode(caught) === "model.config_invalid") {
      optionsRef.current.onModelRequired?.();
    }
    setError(describeError(caught));
  }, []);

  const refreshHistory = useCallback(async () => {
    const { hostId } = optionsRef.current;
    if (!hostId) {
      setHistory([]);
      return;
    }
    try {
      setHistory(await taskList({ host_id: hostId, limit: 30 }));
    } catch {
      // 历史刷新失败不影响当前任务状态。
    }
  }, []);

  const withBusy = useCallback(async (action: () => Promise<void>): Promise<boolean> => {
    if (busyRef.current) return false;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await action();
      return true;
    } catch (caught) {
      const code = errorCode(caught);
      // 用户在 revising 期间取消后，模型调用会以 task.cancelled/task.stale 返回；
      // 任务已经不是 revising，忽略这条迟到的错误，保留“已取消”提示。
      if (
        (code === "task.cancelled" || code === "task.stale") &&
        taskRef.current?.status !== "revising"
      ) {
        return false;
      }
      if (code === "model.config_invalid") {
        optionsRef.current.onModelRequired?.();
      }
      setError(describeError(caught));
      return false;
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, []);

  const startTimer = useCallback(
    (taskId: string, stepId: string) => {
      clearTimer();
      timerRef.current = window.setTimeout(() => {
        if (pendingRef.current !== stepId) return;
        pendingRef.current = null;
        setPendingStepId(null);
        void taskStepInteractive(
          taskId,
          stepId,
          "120 秒内没有收到命令结束信号（可能仍在运行，或未启用 OSC 133）"
        )
          .then((updated) => {
            setTask(updated);
            if (autoRunRef.current) {
              stopAutoRun("当前步骤超时未返回；自动推进已暂停。");
            } else {
              setMessage("当前步骤超时未返回；任务已暂停，请人工确认结果。");
            }
            void refreshHistory();
          })
          .catch((caught) => {
            if (autoRunRef.current) {
              stopAutoRun("当前步骤超时处理失败；自动推进已暂停。");
            }
            fail(caught);
          });
      }, STEP_TIMEOUT_MS);
    },
    [clearTimer, fail, refreshHistory, stopAutoRun]
  );

  // 会话/主机切换时从库里恢复进行中的任务；找不到就回到空状态。
  useEffect(() => {
    let cancelled = false;
    clearPending();
    resetAutoRun();
    finishedStepsRef.current = new Set();
    setError(null);
    setMessage(null);
    if (!options.hostId) {
      setTask(null);
      setHistory([]);
      return;
    }
    void (async () => {
      try {
        const rows = await taskList({ host_id: options.hostId ?? undefined, limit: 30 });
        if (cancelled) return;
        setHistory(rows);
        // 只恢复当前会话的任务：任务步骤必须写回它绑定的那个 PTY。
        // 其他会话的任务仍会出现在历史里，但只能查看/标记，不能在这里执行。
        const active = rows.find((row) => row.session_id === options.sessionId);
        if (!active) {
          setTask(null);
          return;
        }
        const detail = await taskGet(active.id);
        if (cancelled || !detail) return;
        setTask(detail);
        if (detail.status === "revising") {
          setMessage("上次「让 AI 判断下一步」被中断；可点「恢复」回到等待确认。");
        } else if (
          detail.status === "running" &&
          !detail.steps.some((step) => step.status === "running")
        ) {
          setMessage("任务状态为执行中，但没有正在运行的步骤；可能已中断，请标记结果或恢复。");
        } else if (detail.steps.some((step) => step.status === "running")) {
          setMessage("任务有步骤正在执行；如果是刷新后恢复，请人工确认结果。");
        }
      } catch (caught) {
        if (!cancelled) fail(caught);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [options.hostId, options.sessionId, clearPending, fail, resetAutoRun]);

  useEffect(() => () => clearTimer(), [clearTimer]);

  const createFromGoal = useCallback(
    async (goal: string) => {
      resetAutoRun();
      const { hostId, sessionId, provider } = optionsRef.current;
      if (!hostId || !sessionId) {
        setError("请先连接主机并打开终端，再创建任务。");
        return;
      }
      const existing = taskRef.current;
      if (existing && !isTerminalTaskStatus(existing.status)) {
        setError("当前会话已有进行中的任务；先完成或取消它，再创建新任务。");
        return;
      }
      setGoalDraft(goal);
      await withBusy(async () => {
        const draft = await draftTask({
          host_id: hostId,
          request: goal,
          base_url: provider.baseUrl,
          model: provider.model,
          api_key: provider.apiKey,
          // 任务计划/推进比单命令慢，30 秒默认值容易误杀推理模型。
          timeout_secs: 60
        });
        const created = await createTask({
          host_id: hostId,
          session_id: sessionId,
          goal,
          title: draft.title,
          summary: draft.summary,
          step_limit: draft.step_limit,
          steps: draft.steps.map((step) => ({
            command: step.command,
            purpose: step.purpose,
            risk_hint: step.risk_hint,
            interactive_hint: step.interactive_hint
          }))
        });
        setTask(created);
        setGoalDraft(null);
        setMessage("任务计划已生成。每一步都需要你确认后才执行。");
        await refreshHistory();
      });
    },
    [refreshHistory, resetAutoRun, withBusy]
  );

  const startStep = useCallback(
    async (stepId: string, auto = false) => {
      const current = taskRef.current;
      if (!current) return;
      const step = current.steps.find((candidate) => candidate.id === stepId);
      if (!step) return;
      const { sessionId } = optionsRef.current;
      if (!sessionId) {
        const reason = "没有活动终端会话，无法执行任务步骤。";
        setError(reason);
        if (auto) stopAutoRun(`${reason}自动推进已暂停。`);
        return;
      }
      if (step.risk === "R2" || step.risk === "R3" || step.interactive_hint) {
        const reason = "该步骤需要手动执行：请在终端输入完整命令，再标记完成。";
        setError(reason);
        if (auto) pauseAutoRun(`${reason}自动推进已暂停。`);
        return;
      }
      if (step.status === "running") return;
      // 重新执行同一步骤（含失败重试）时，清掉上一次的防重复事件标记；
      // 否则新一次 OSC 结果会被当成重复事件丢弃。
      finishedStepsRef.current.delete(stepId);
      if (current.session_id && current.session_id !== sessionId) {
        const reason = "该任务属于另一个会话；请切回对应终端，或只做标记/取消。";
        setError(reason);
        if (auto) stopAutoRun(`${reason}自动推进已暂停。`);
        return;
      }
      const blocked = optionsRef.current.beforeSend?.(sessionId);
      if (blocked) {
        setError(blocked);
        if (auto) stopAutoRun(`${blocked}；自动推进已暂停。`);
        return;
      }
      const ok = await withBusy(async () => {
        const updated = await taskStepStarted(current.id, stepId, auto);
        taskRef.current = updated;
        setTask(updated);
        pendingRef.current = stepId;
        setPendingStepId(stepId);
        // 先启动超时：write_session 若卡住，也要能暂停而不是一直 busy。
        startTimer(current.id, stepId);
        try {
          await optionsRef.current.sendCommand(sessionId, step.command_redacted);
        } catch (caught) {
          clearPending();
          setError(`命令没有写入终端：${describeError(caught)}`);
          if (auto) {
            stopAutoRun("命令没有写入终端；自动推进已暂停。");
          }
          try {
            setTask(
              await taskStepFinished({
                task_id: current.id,
                step_id: stepId,
                exit_code: null,
                output_tail: "",
                status: "sent"
              })
            );
          } catch {
            // 保留“命令没有写入终端”的原始错误。
          }
        }
      });
      if (!ok && auto) {
        stopAutoRun("步骤启动失败；自动推进已暂停。");
      }
    },
    [clearPending, pauseAutoRun, startTimer, stopAutoRun, withBusy]
  );

  const markStep = useCallback(
    async (stepId: string, outcome: "manual" | "failed") => {
      const current = taskRef.current;
      if (!current) return;
      if (finishedStepsRef.current.has(stepId)) return;
      clearPending();
      finishedStepsRef.current.add(stepId);
      const ok = await withBusy(async () => {
        const updated = await taskStepFinished({
          task_id: current.id,
          step_id: stepId,
          exit_code: null,
          output_tail: "",
          status: outcome
        });
        taskRef.current = updated;
        setTask(updated);
        setMessage(
          outcome === "failed"
            ? "已把该步骤标记为失败；任务已暂停。"
            : "已标记为完成（结果未通过退出码校验）。"
        );
        await refreshHistory();
        if (autoRunRef.current) {
          if (outcome === "failed") {
            pauseAutoRun("步骤被标记失败；自动推进已暂停，重试/跳过后可继续。");
          } else {
            window.setTimeout(() => advanceRef.current(), 0);
          }
        }
      });
      if (!ok) finishedStepsRef.current.delete(stepId);
    },
    [clearPending, pauseAutoRun, refreshHistory, withBusy]
  );

  const skipStep = useCallback(
    async (stepId: string) => {
      const current = taskRef.current;
      if (!current) return;
      await withBusy(async () => {
        const updated = await taskStepSkip(current.id, stepId);
        taskRef.current = updated;
        setTask(updated);
        setMessage("已跳过该只读步骤。");
        await refreshHistory();
        if (autoRunRef.current) {
          window.setTimeout(() => advanceRef.current(), 0);
        }
      });
    },
    [refreshHistory, withBusy]
  );

  const retryStep = useCallback(
    async (stepId: string) => {
      const current = taskRef.current;
      if (!current) return;
      finishedStepsRef.current.delete(stepId);
      await withBusy(async () => {
        const updated = await taskStepRetry(current.id, stepId);
        taskRef.current = updated;
        setTask(updated);
        setMessage("步骤已回到待确认状态；不会自动重跑。");
        await refreshHistory();
        if (autoRunRef.current) {
          window.setTimeout(() => advanceRef.current(), 0);
        }
      });
    },
    [refreshHistory, withBusy]
  );

  const updateStep = useCallback(
    async (stepId: string, command: string, purpose: string): Promise<boolean> => {
      const current = taskRef.current;
      if (!current) return false;
      return withBusy(async () => {
        const updated = await taskStepUpdate({
          task_id: current.id,
          step_id: stepId,
          command,
          purpose: purpose.trim() || undefined
        });
        setTask(updated);
        setMessage("步骤已更新；服务端已重新计算风险。");
        await refreshHistory();
      });
    },
    [refreshHistory, withBusy]
  );

  const deleteTask = useCallback(async () => {
    const current = taskRef.current;
    if (!current) return;
    resetAutoRun();
    clearPending();
    await withBusy(async () => {
      await taskDelete(current.id);
      setTask(null);
      setMessage("任务已删除；审计事件仍保留。");
      await refreshHistory();
    });
  }, [clearPending, refreshHistory, resetAutoRun, withBusy]);

  const exportTask = useCallback(
    async (path: string) => {
      const current = taskRef.current;
      if (!current) return;
      await withBusy(async () => {
        const written = await saveTaskExport(current.id, path);
        setMessage(`任务已导出：${written}`);
      });
    },
    [withBusy]
  );

  const pruneHistory = useCallback(async () => {
    const { hostId } = optionsRef.current;
    if (!hostId) return;
    await withBusy(async () => {
      const report = await taskHistoryPrune({ host_id: hostId });
      // 当前展示的任务可能刚好被清理掉；以库为准回到创建态。
      const current = taskRef.current;
      if (current) {
        const detail = await taskGet(current.id);
        taskRef.current = detail;
        setTask(detail);
        if (!detail) resetAutoRun();
      }
      setMessage(
        report.deleted > 0
          ? `已按策略清理 ${report.deleted} 条终态任务；审计事件保留。`
          : "没有符合条件的旧任务需要清理。"
      );
      await refreshHistory();
    });
  }, [refreshHistory, resetAutoRun, withBusy]);

  const notifyError = useCallback((message: string) => {
    setError(message);
  }, []);

  const revise = useCallback(
    async (note?: string) => {
      const current = taskRef.current;
      if (!current) return;
      const { provider } = optionsRef.current;
      const ok = await withBusy(async () => {
        if (taskRef.current?.id !== current.id) return;
        // 乐观进入 revising：模型返回前用户就能看到并中断本次判断。
        const optimistic: TaskRecord = { ...current, status: "revising" };
        taskRef.current = optimistic;
        setTask(optimistic);
        const result = await taskRevise({
          task_id: current.id,
          user_note: note?.trim() || undefined,
          base_url: provider.baseUrl,
          model: provider.model,
          api_key: provider.apiKey,
          timeout_secs: 60
        });
        if (taskRef.current?.id !== current.id) return;
        taskRef.current = result.task;
        setTask(result.task);
        setMessage(result.message);
        await refreshHistory();
        if (autoRunRef.current) {
          if (result.decision === "continue") {
            window.setTimeout(() => advanceRef.current(), 0);
          } else if (result.decision === "done") {
            stopAutoRun("任务已完成，自动推进停止。");
          } else {
            pauseAutoRun(result.message || "模型请求人工处理；自动推进已暂停。");
          }
        }
      });
      if (!ok) {
        const detail = await taskGet(current.id).catch(() => null);
        if (detail && taskRef.current?.id === current.id) {
          taskRef.current = detail;
          setTask(detail);
          if (detail.status === "cancelled") setError(null);
        }
        if (autoRunRef.current) {
          stopAutoRun("模型判断失败，自动推进已暂停。");
        }
      }
    },
    [pauseAutoRun, refreshHistory, stopAutoRun, withBusy]
  );

  const advanceAuto = useCallback(async () => {
    if (!autoRunRef.current || busyRef.current) return;
    const task = taskRef.current;
    const { sessionId, integrationEnabled } = optionsRef.current;
    if (!task) {
      stopAutoRun("没有任务，自动推进停止。");
      return;
    }
    if (isTerminalTaskStatus(task.status) || task.status === "cancelled") {
      stopAutoRun("任务已结束，自动推进停止。");
      return;
    }
    if (task.status === "paused_failed") {
      pauseAutoRun("上一步失败，自动推进已暂停；重试/跳过或让 AI 诊断后继续。");
      return;
    }
    if (task.status === "paused_interactive") {
      stopAutoRun("当前步骤需要人工接管，自动推进已暂停。");
      return;
    }
    if (task.status === "running" || task.status === "revising") return;
    if (task.status !== "waiting_user" && task.status !== "plan_ready") return;
    if (!sessionId) {
      stopAutoRun("没有活动会话，自动推进停止。");
      return;
    }
    if (!integrationEnabled) {
      stopAutoRun("命令审计未生效，自动推进已暂停；请先启用命令审计。");
      return;
    }
    const blocked = optionsRef.current.beforeSend?.(sessionId);
    if (blocked) {
      stopAutoRun(`${blocked}；自动推进已暂停。`);
      return;
    }
    if (task.steps.some((step) => step.status === "sent")) {
      pauseAutoRun("有步骤结果未知，自动推进已暂停；请先处理该步骤。");
      return;
    }
    const next = nextAutoStep(task);
    if (next) {
      if (isManualOnlyStep(next)) {
        pauseAutoRun("下一步需要手动执行；完成后自动推进继续。");
        return;
      }
      if (next.risk !== "R0" && next.risk !== "R1") {
        pauseAutoRun("下一步不是只读步骤；处理后自动推进继续。");
        return;
      }
      await startStep(next.id, true);
      return;
    }
    const executed = task.steps.filter((step) =>
      ["succeeded", "failed", "sent", "manual"].includes(step.status)
    ).length;
    const remaining = task.step_limit - task.steps.length;
    if (executed === 0) {
      stopAutoRun("没有可执行的步骤，自动推进停止。");
      return;
    }
    if (remaining <= 0) {
      stopAutoRun("步数预算已用完，自动推进停止；可让 AI 判断是否完成。");
      return;
    }
    await revise(undefined);
  }, [pauseAutoRun, revise, startStep, stopAutoRun]);

  // 延迟取最新实现：startStep/revise 完成时通过 ref 回到自动推进循环。
  advanceRef.current = () => {
    void advanceAuto();
  };

  const setAutoRun = useCallback((enabled: boolean) => {
    if (!enabled) {
      autoRunRef.current = false;
      setAutoRunState(false);
      setMessage("自动推进已暂停。");
      return;
    }
    autoRunRef.current = true;
    setAutoRunState(true);
    setMessage("自动推进已开启：仅自动执行 R0/R1；R2/R3、交互、失败或结果未知时暂停。");
    window.setTimeout(() => advanceRef.current(), 0);
  }, []);

  const resumeInterrupted = useCallback(async () => {
    const current = taskRef.current;
    if (!current) return;
    resetAutoRun();
    const running = current.steps.find((step) => step.status === "running");
    await withBusy(async () => {
      if (running && current.status === "paused_interactive") {
        setTask(
          await taskStepFinished({
            task_id: current.id,
            step_id: running.id,
            exit_code: null,
            output_tail: "",
            status: "sent"
          })
        );
        setMessage("已继续任务；刚才的步骤记为“已发送（结果未知）”。");
      } else {
        setTask(await taskResume(current.id));
        setMessage("任务已恢复，等待你确认下一步。");
      }
      await refreshHistory();
    });
  }, [refreshHistory, resetAutoRun, withBusy]);

  const resumeRevising = useCallback(async () => {
    const current = taskRef.current;
    if (!current) return;
    resetAutoRun();
    await withBusy(async () => {
      setTask(await taskResume(current.id));
      setMessage("已恢复被中断的模型判断；任务回到等待确认。");
      await refreshHistory();
    });
  }, [refreshHistory, resetAutoRun, withBusy]);

  const cancel = useCallback(async () => {
    const current = taskRef.current;
    if (!current) return;
    resetAutoRun();
    clearPending();
    if (current.status === "revising") {
      // 允许打断进行中的模型判断：不走 withBusy，避免和 revise 的 busy 守卫互相覆盖。
      // 后端 task_cancel 会 notify 取消令牌，task_revise 丢弃 HTTP 请求。
      setError(null);
      try {
        const updated = await taskCancel(current.id);
        if (taskRef.current?.id === current.id) {
          setTask(updated);
          setMessage("任务已取消；模型判断已中断。");
          await refreshHistory();
        }
      } catch (caught) {
        setError(describeError(caught));
      }
      return;
    }
    await withBusy(async () => {
      const updated = await taskCancel(current.id);
      if (taskRef.current?.id === current.id) {
        setTask(updated);
        setMessage("任务已取消；不会再发送任何步骤命令。");
        await refreshHistory();
      }
    });
  }, [clearPending, refreshHistory, resetAutoRun, withBusy]);

  const loadTask = useCallback(
    async (taskId: string) => {
      resetAutoRun();
      await withBusy(async () => {
        const detail = await taskGet(taskId);
        if (!detail) {
          setError("任务不存在或已被删除。");
          return;
        }
        clearPending();
        taskRef.current = detail;
        setTask(detail);
        setMessage(null);
        if (detail.status === "running") {
          setMessage("这是历史/进行中的任务；如果是刷新后恢复，请人工确认正在运行的步骤结果。");
        }
      });
    },
    [clearPending, resetAutoRun, withBusy]
  );

  const refresh = useCallback(async () => {
    const current = taskRef.current;
    await withBusy(async () => {
      if (current) {
        // 任务可能已被历史清理删除；此时回到创建态。
        const detail = await taskGet(current.id);
        taskRef.current = detail;
        setTask(detail);
        if (!detail || isTerminalTaskStatus(detail.status)) {
          resetAutoRun();
        }
      }
      await refreshHistory();
    });
  }, [refreshHistory, resetAutoRun, withBusy]);

  const clearTask = useCallback(() => {
    resetAutoRun();
    clearPending();
    finishedStepsRef.current = new Set();
    setTask(null);
    setError(null);
    setMessage(null);
  }, [clearPending, resetAutoRun]);

  const handleCommandFinished = useCallback(
    (event: TaskCommandFinished) => {
      const current = taskRef.current;
      if (!current || event.sessionId !== optionsRef.current.sessionId) return;
      const pending = pendingRef.current;
      const running = current.steps.find((step) => step.status === "running");
      if (!pending) {
        // 没有待确认步骤时，只有“唯一 running 步骤 + 命令完全一致”才认领，
        // 避免把用户手敲的无关命令记到任务上。
        if (!running || !event.command) return;
        if (normalizeCommand(event.command) !== normalizeCommand(running.command_redacted)) {
          return;
        }
      }
      const step = pending
        ? current.steps.find((candidate) => candidate.id === pending)
        : running;
      if (!step || step.status !== "running") return;
      if (finishedStepsRef.current.has(step.id)) return;
      if (
        event.command &&
        normalizeCommand(event.command) !== normalizeCommand(step.command_redacted)
      ) {
        return;
      }
      clearPending();
      finishedStepsRef.current.add(step.id);
      void taskStepFinished({
        task_id: current.id,
        step_id: step.id,
        exit_code: event.exitCode,
        output_tail: event.outputTail
      })
        .then((updated) => {
          if (taskRef.current?.id !== current.id) return;
          taskRef.current = updated;
          setTask(updated);
          const resultStep = updated.steps.find((candidate) => candidate.id === step.id);
          const succeeded =
            resultStep?.status === "succeeded" && resultStep.exit_code === 0;
          if (succeeded) {
            setMessage(null);
            if (autoRunRef.current) {
              window.setTimeout(() => advanceRef.current(), 0);
            }
          } else if (updated.status === "paused_failed") {
            setMessage("步骤失败，任务已暂停；不会自动重试。");
            if (autoRunRef.current) {
              pauseAutoRun("步骤失败；自动推进已暂停，重试/跳过后可继续。");
            }
          } else if (isTerminalTaskStatus(updated.status)) {
            setMessage("任务已停止；不会自动重试。");
            if (autoRunRef.current) {
              stopAutoRun("任务已停止，自动推进结束。");
            }
          } else {
            setMessage("步骤结果未知；请人工确认。");
            if (autoRunRef.current) {
              stopAutoRun("步骤结果未知，自动推进已暂停。");
            }
          }
          void refreshHistory();
        })
        .catch((caught) => {
          finishedStepsRef.current.delete(step.id);
          if (taskRef.current?.id !== current.id) return;
          // 审计失败时步骤状态可能已经落库；先刷新，避免 UI 一直显示 running。
          void taskGet(current.id)
            .then((detail) => {
              if (detail) setTask(detail);
            })
            .catch(() => undefined);
          fail(caught);
        });
    },
    [clearPending, fail, pauseAutoRun, refreshHistory, stopAutoRun]
  );

  const handleInteractive = useCallback(
    (sessionId: string, reason: string) => {
      const current = taskRef.current;
      if (!current || sessionId !== optionsRef.current.sessionId) return;
      const pending = pendingRef.current;
      if (!pending) return;
      const step = current.steps.find((candidate) => candidate.id === pending);
      if (!step || step.status !== "running") return;
      clearPending();
      void taskStepInteractive(current.id, step.id, reason)
        .then((updated) => {
          if (taskRef.current?.id !== current.id) return;
          taskRef.current = updated;
          setTask(updated);
          setMessage("当前步骤需要人工接管（密码/REPL/全屏）。处理完后点「我已处理完，继续」。");
          if (autoRunRef.current) {
            stopAutoRun("当前步骤需要人工接管；自动推进已暂停。");
          }
          void refreshHistory();
        })
        .catch((caught) => {
          finishedStepsRef.current.delete(step.id);
          if (taskRef.current?.id !== current.id) return;
          // 审计失败时步骤状态可能已经落库；先刷新，避免 UI 一直显示 running。
          void taskGet(current.id)
            .then((detail) => {
              if (detail) setTask(detail);
            })
            .catch(() => undefined);
          fail(caught);
        });
    },
    [clearPending, fail, refreshHistory, stopAutoRun]
  );

  const clearNotice = useCallback(() => {
    setError(null);
    setMessage(null);
  }, []);

  return {
    task,
    history,
    busy,
    error,
    message,
    pendingStepId,
    goalDraft,
    autoRun,
    setAutoRun,
    createFromGoal,
    startStep,
    markStep,
    skipStep,
    retryStep,
    updateStep,
    deleteTask,
    exportTask,
    pruneHistory,
    notifyError,
    revise,
    resumeInterrupted,
    resumeRevising,
    cancel,
    loadTask,
    refresh,
    clearTask,
    handleCommandFinished,
    handleInteractive,
    clearNotice
  };
}
