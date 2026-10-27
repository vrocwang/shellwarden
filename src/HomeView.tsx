interface Props {
  hostCount: number;
  onSettings: () => void;
  onHelp: () => void;
  onAbout: () => void;
}

export function HomeView({ hostCount, onSettings, onHelp, onAbout }: Props) {
  return (
    <section className="welcome">
      <div className="welcome-mark">SW</div>
      <h1>ShellWarden</h1>
      <p className="welcome-lead">
        面向 AI 运维的安全终端。命令直接执行，自然语言先出完整命令，确认后才落地。
      </p>

      <div className="welcome-steps">
        <div>
          <strong>1</strong>
          <span>在左侧选择已保存的主机，或添加一台新主机。</span>
        </div>
        <div>
          <strong>2</strong>
          <span>
            首次使用先到 <button type="button" className="link" onClick={onSettings}>设置</button>{" "}
            填写模型 Base URL 与密钥。
          </span>
        </div>
        <div>
          <strong>3</strong>
          <span>
            连接后在终端里输入命令、自然语言，或用顶栏「任务」/ <code>/task</code> 描述多步目标。
          </span>
        </div>
      </div>

      <div className="welcome-actions">
        <button type="button" onClick={onSettings}>模型设置</button>
        <button type="button" className="secondary" onClick={onHelp}>帮助与自检</button>
        <button type="button" className="ghost" onClick={onAbout}>关于</button>
      </div>

      <p className="muted small">
        {hostCount === 0
          ? "还没有主机。用左侧「添加主机」开始。"
          : `已有 ${hostCount} 台主机。`}
      </p>
    </section>
  );
}
