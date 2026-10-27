import { useEffect, useMemo, useState } from "react";
import type { Host } from "./api";

export type BatchStatus = "running" | "paused" | "done" | "cancelled";

export interface BatchState {
  id: string;
  goal: string;
  hostIds: string[];
  taskIds: Record<string, string>;
  statuses: Record<string, string>;
  index: number;
  status: BatchStatus;
  /** 客户端批次级自动推进；不持久化，重启恢复后默认关闭。 */
  autoRun: boolean;
}

interface Props {
  open: boolean;
  hosts: Host[];
  connectedHostIds: Set<string>;
  tags: string[];
  batch: BatchState | null;
  busy: boolean;
  error: string | null;
  onStart: (goal: string, hostIds: string[], autoRun: boolean) => void;
  onToggleAuto: (enabled: boolean) => void;
  onContinueCurrent: () => void;
  onResume: () => void;
  onStop: () => void;
  onExport: () => void;
  onNew: () => void;
  onClose: () => void;
}

const TASK_STATUS_LABEL: Record<string, string> = {
  draft: "草案",
  plan_ready: "计划就绪",
  waiting_user: "等待确认",
  running: "执行中",
  revising: "判断中",
  paused_failed: "失败暂停",
  paused_interactive: "等待人工",
  completed: "完成",
  failed: "失败",
  cancelled: "已取消",
  sent: "结果未知",
  skipped: "已跳过",
  manual: "人工完成"
};

export function BatchTaskPanel({
  open,
  hosts,
  connectedHostIds,
  tags,
  batch,
  busy,
  error,
  onStart,
  onToggleAuto,
  onContinueCurrent,
  onResume,
  onStop,
  onExport,
  onNew,
  onClose
}: Props) {
  const [goal, setGoal] = useState("");
  const [tag, setTag] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [auto, setAuto] = useState(false);

  useEffect(() => {
    if (!open) return;
    setGoal("");
    setTag("");
    setSelected([]);
    setAuto(false);
  }, [open, batch?.goal]);

  const filtered = useMemo(() => {
    const list = tag ? hosts.filter((host) => host.tags.includes(tag)) : hosts;
    return [...list].sort((a, b) => a.name.localeCompare(b.name, "zh-CN"));
  }, [hosts, tag]);

  if (!open) return null;

  const activeHost = batch ? hosts.find((host) => host.id === batch.hostIds[batch.index]) : null;

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-card batch-panel">
        <div className="batch-panel-head">
          <h3>按标签批量任务</h3>
          <div className="row">
            {batch &&
              (batch.status === "done" || batch.status === "cancelled") && (
                <button type="button" className="primary" onClick={onNew}>
                  新建批次
                </button>
              )}
            {batch && batch.status !== "done" && batch.status !== "cancelled" && (
              <button type="button" className="secondary" onClick={onStop}>
                停止批次
              </button>
            )}
            <button type="button" className="ghost" onClick={onClose} aria-label="关闭批次面板">
              ×
            </button>
          </div>
        </div>
        {batch ? (
          <>
            <p className="muted small">
              目标：{batch.goal} · 第 {batch.index + 1}/{batch.hostIds.length} 台
              {activeHost ? ` · 当前 ${activeHost.name}` : ""}
            </p>
            <ul className="batch-queue">
              {batch.hostIds.map((hostId, index) => {
                const host = hosts.find((item) => item.id === hostId);
                const status = batch.statuses[hostId];
                const state =
                  (status ? TASK_STATUS_LABEL[status] ?? status : undefined) ??
                  (index < batch.index
                    ? "已完成/跳过"
                    : index === batch.index
                      ? batch.status === "paused"
                        ? "暂停"
                        : batch.status === "done"
                          ? "完成"
                          : "当前"
                      : "等待");
                return (
                  <li key={hostId} className={index === batch.index ? "active" : undefined}>
                    <span>{host?.name ?? hostId}</span>
                    <em>{state}</em>
                  </li>
                );
              })}
            </ul>
            <label className="confirm">
              <input
                type="checkbox"
                checked={batch.autoRun}
                disabled={batch.status === "done" || batch.status === "cancelled"}
                onChange={(event) => onToggleAuto(event.target.checked)}
              />
              <span>自动推进每台任务（仅 R0/R1）</span>
            </label>
            <p className="muted small">
              每台任务只读步骤自动执行并自动让 AI 判断下一步；R2/R3、交互、失败或结果未知时暂停。
              批次级开关不持久化，重启恢复后需重新开启。
            </p>
            <div className="row">
              {batch.status === "paused" && (
                <>
                  <button type="button" onClick={onContinueCurrent}>
                    继续当前
                  </button>
                  <button type="button" className="secondary" onClick={onResume}>
                    跳过当前
                  </button>
                </>
              )}
              <button type="button" className="secondary" onClick={onExport}>
                导出汇总
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              先选一个标签，再勾选主机；每台会创建一个独立任务，按顺序执行。
              未连接的主机会在创建时用已保存的密码/私钥自动连接。
            </p>
            <div className="tag-chips batch-tags">
              <button
                type="button"
                className={tag === "" ? "tag-chip active" : "tag-chip"}
                onClick={() => {
                  setTag("");
                  setSelected([]);
                }}
              >
                全部
              </button>
              {tags.map((item) => (
                <button
                  type="button"
                  key={item}
                  className={tag === item ? "tag-chip active" : "tag-chip"}
                  onClick={() => {
                    setTag(item);
                    setSelected([]);
                  }}
                >
                  {item}
                </button>
              ))}
            </div>
            <ul className="batch-hosts">
              {filtered.map((host) => {
                const online = connectedHostIds.has(host.id);
                const checked = selected.includes(host.id);
                return (
                  <li key={host.id}>
                    <label className="confirm">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(event) => {
                          setSelected((prev) =>
                            event.target.checked
                              ? [...prev, host.id]
                              : prev.filter((id) => id !== host.id)
                          );
                        }}
                      />
                      <span>
                        {host.name} · {host.hostname}:{host.port}
                        {host.tags.length > 0 ? ` · ${host.tags.join(", ")}` : ""}
                      </span>
                      <em>{online ? "已连接" : "未连接 · 将自动连接"}</em>
                    </label>
                  </li>
                );
              })}
            </ul>
            {filtered.length === 0 && (
              <p className="error">当前筛选下没有主机。</p>
            )}
            {selected.length > 20 && (
              <p className="error">单批最多 20 台主机。</p>
            )}
            <label>
              任务目标
              <textarea
                rows={3}
                value={goal}
                onChange={(event) => setGoal(event.target.value)}
                placeholder="例如：检查 nginx 配置并重载"
              />
            </label>
            <label className="confirm">
              <input
                type="checkbox"
                checked={auto}
                onChange={(event) => setAuto(event.target.checked)}
              />
              <span>自动推进每台任务（仅 R0/R1）</span>
            </label>
            {auto && (
              <p className="muted small">
                每台任务只读步骤自动执行并自动让 AI 判断下一步；R2/R3、交互、失败或结果未知时暂停。
                风险分类不是完整 shell 分析，请确认批次目标适合自动执行只读命令。
              </p>
            )}
            {error && <p className="error">{error}</p>}
            <div className="row">
              <button
                type="button"
                disabled={
                  busy || !goal.trim() || selected.length === 0 || selected.length > 20
                }
                onClick={() => onStart(goal.trim(), selected, auto)}
              >
                {busy ? "创建中…" : `创建批次（${selected.length} 台）`}
              </button>
              <button type="button" className="ghost" onClick={onClose}>
                取消
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
