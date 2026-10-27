import type {
  ProviderConfig,
  ShortcutsConfig,
  TaskHistorySettings
} from "./api";
import { ModelConfigForm } from "./ModelConfigForm";

interface Props {
  provider: ProviderConfig;
  onProviderChange: (provider: ProviderConfig) => void;
  rememberKey: boolean;
  onRememberKeyChange: (value: boolean) => void;
  saving: boolean;
  onSave: () => void;
  onClearKey: () => void;
  shortcuts: ShortcutsConfig;
  onShortcutsChange: (shortcuts: ShortcutsConfig) => void;
  onSaveShortcuts: () => void;
  taskHistory: TaskHistorySettings;
  onTaskHistoryChange: (settings: TaskHistorySettings) => void;
  taskHistorySaving: boolean;
  onSaveTaskHistory: () => void;
}

export function SettingsView({
  provider,
  onProviderChange,
  rememberKey,
  onRememberKeyChange,
  saving,
  onSave,
  onClearKey,
  shortcuts,
  onShortcutsChange,
  onSaveShortcuts,
  taskHistory,
  onTaskHistoryChange,
  taskHistorySaving,
  onSaveTaskHistory
}: Props) {
  return (
    <section className="page">
      <article className="card">
        <h3>
          模型配置
          <span className={provider.hasKey ? "badge ok" : "badge"}>
            {provider.hasKey ? "已保存密钥" : "未保存密钥"}
          </span>
        </h3>
        <ModelConfigForm
          provider={provider}
          onProviderChange={onProviderChange}
          rememberKey={rememberKey}
          onRememberKeyChange={onRememberKeyChange}
          saving={saving}
          onSave={onSave}
          onClearKey={onClearKey}
        />
        <p className="muted small">
          保存后 AI 命令生成会复用；密钥按本机密钥文件加密，换机需同时迁移数据库与 secret.key。
        </p>
      </article>

      <article className="card">
        <h3>终端快捷键</h3>
        <div className="host-form">
          <label>
            复制
            <input
              value={shortcuts.copy}
              onChange={(event) =>
                onShortcutsChange({ ...shortcuts, copy: event.target.value })
              }
              placeholder="Cmd+C / Ctrl+Shift+C"
            />
          </label>
          <label>
            粘贴
            <input
              value={shortcuts.paste}
              onChange={(event) =>
                onShortcutsChange({ ...shortcuts, paste: event.target.value })
              }
              placeholder="Cmd+V / Ctrl+Shift+V"
            />
          </label>
          <p className="muted small">
            格式：修饰键 + 键名，例如 Cmd+C、Ctrl+Shift+V、Shift+Insert。
            Ctrl+C 始终保持终端中断，不会被复制占用。
          </p>
          <button type="button" onClick={onSaveShortcuts}>
            保存快捷键
          </button>
        </div>
      </article>

      <article className="card">
        <h3>任务历史</h3>
        <div className="host-form">
          <label>
            保留天数（0 = 不按时间清理）
            <input
              type="number"
              min={0}
              max={3650}
              value={taskHistory.keep_days}
              onChange={(event) => {
                const next = Number(event.target.value);
                onTaskHistoryChange({
                  ...taskHistory,
                  keep_days: Number.isFinite(next) ? next : 0
                });
              }}
            />
          </label>
          <label>
            每个主机最多保留终态任务（0 = 不按数量清理）
            <input
              type="number"
              min={0}
              max={10000}
              value={taskHistory.max_terminal}
              onChange={(event) => {
                const next = Number(event.target.value);
                onTaskHistoryChange({
                  ...taskHistory,
                  max_terminal: Number.isFinite(next) ? next : 0
                });
              }}
            />
          </label>
          <p className="muted small">
            只清理已完成/失败/取消的任务，进行中任务永不清理；审计事件保留。应用启动时自动
            按策略清理，任务抽屉可手动清理当前主机历史。
          </p>
          <button
            type="button"
            disabled={taskHistorySaving}
            onClick={onSaveTaskHistory}
          >
            {taskHistorySaving ? "保存中…" : "保存历史策略"}
          </button>
        </div>
      </article>

      <article className="card">
        <h3>输入路由</h3>
        <dl className="kv">
          <div>
            <dt>命令直通</dt>
            <dd>已知命令、路径、管道、重定向、赋值直接发给远端，不确认。</dd>
          </div>
          <div>
            <dt>自然语言</dt>
            <dd>AI 识别开启、回车时才分类；疑问句、口语、未知多词会清行后显示完整命令，再回车执行。补全/历史/全屏程序保持原生，且这些情况下的回车不再走 AI 分类。</dd>
          </div>
          <div>
            <dt>强制前缀</dt>
            <dd><code>!cmd</code> 强制 Shell；<code>@...</code> 或 <code>/ai ...</code> 强制 AI。</dd>
          </div>
        </dl>
      </article>
    </section>
  );
}
