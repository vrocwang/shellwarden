import { useCallback, useEffect, useState } from "react";
import {
  describeError,
  enableShellIntegration,
  sessionAudit,
  terminalCommands,
  type SessionAuditEvent,
  type TerminalCommandRow
} from "./api";

export function SessionAuditPanel({
  sessionId,
  terminalBlocked = false
}: {
  sessionId: string;
  /** 全屏程序或密码/REPL 提示符中：禁止向 PTY 写入集成脚本。 */
  terminalBlocked?: boolean;
}) {
  const [events, setEvents] = useState<SessionAuditEvent[]>([]);
  const [commands, setCommands] = useState<TerminalCommandRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextEvents, nextCommands] = await Promise.all([
        sessionAudit(sessionId, 200),
        terminalCommands(sessionId, 200)
      ]);
      setEvents(nextEvents);
      setCommands(nextCommands);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleEnableIntegration() {
    setError(null);
    try {
      await enableShellIntegration(sessionId);
      setCommands([]);
    } catch (err) {
      setError(describeError(err));
    }
  }

  return (
    <article className="card wide">
      <h3>
        本次会话审计
        <button
          type="button"
          className="ghost"
          disabled={terminalBlocked}
          title={
            terminalBlocked
              ? "终端在全屏程序、密码/REPL 提示符中，或任务步骤正在执行；先处理完再启用"
              : undefined
          }
          onClick={() => void handleEnableIntegration()}
        >
          启用命令审计（bash/zsh）
        </button>
        <button type="button" className="ghost" onClick={() => void refresh()} disabled={loading}>
          {loading ? "刷新中…" : "刷新"}
        </button>
      </h3>
      {error && <div className="error">{error}</div>}
      <p className="muted small">
        命令审计需要 shell integration（仅 bash/zsh）；未启用时只记录连接事件。
      </p>
      {terminalBlocked && (
        <p className="muted small">
          终端当前在全屏程序、密码/REPL 提示符中，或任务步骤正在执行；请先处理完再启用命令审计。
        </p>
      )}
      {commands.length > 0 && (
        <section>
          <h4>命令历史</h4>
          <ol className="audit-list">
            {commands.map((item) => (
              <li key={item.id}>
                <code>{item.exit_code ?? "—"}</code>
                <span>{item.command_redacted}</span>
                <em>
                  {item.started_at.replace("T", " ").slice(0, 19)} · {item.duration_ms}ms
                </em>
              </li>
            ))}
          </ol>
        </section>
      )}
      {events.length === 0 ? (
        <p className="muted small">还没有会话事件。</p>
      ) : (
        <ol className="audit-list">
          {events.map((event) => (
            <li key={event.seq}>
              <code>#{event.seq}</code>
              <span>{event.event_type}</span>
              <em>
                {event.timestamp.replace("T", " ").slice(0, 19)} · {event.actor}
              </em>
              <pre>{JSON.stringify(event.payload)}</pre>
            </li>
          ))}
        </ol>
      )}
    </article>
  );
}
