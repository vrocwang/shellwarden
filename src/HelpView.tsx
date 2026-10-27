import type { SelfCheck } from "./api";

interface Props {
  check: SelfCheck | null;
  onRefresh: () => void;
}

export function HelpView({ check, onRefresh }: Props) {
  return (
    <section className="page">
      <article className="card">
        <h3>
          安全核心自检
          <span className={check?.passed ? "badge ok" : "badge bad"}>
            {check ? (check.passed ? "全部通过" : "有失败项") : "未运行"}
          </span>
        </h3>
        <ul className="checks">
          {(check?.checks ?? []).map((item) => (
            <li key={item.name} className={item.passed ? "ok" : "bad"}>
              <span className="dot" />
              <div>
                <strong>{item.name}</strong>
                <code>{item.detail}</code>
              </div>
            </li>
          ))}
        </ul>
        <button type="button" className="secondary" onClick={onRefresh}>
          重新自检
        </button>
      </article>

      <article className="card">
        <h3>快捷键与输入</h3>
        <ul className="help-list">
          <li>
            模型给 2–3 条候选：↑/↓ 或数字键切换，<code>Enter</code> 执行选中的 R0/R1
            命令；<code>e</code> 把选中命令放进当前行编辑，<code>r</code> 恢复原始描述
            重新生成，<code>Esc</code> 取消。
          </li>
          <li>
            <code>Esc</code> 取消本次命令生成或命令确认；执行中按 <code>Esc</code> 请求取消
            （远端进程可能继续，状态未知）。
          </li>
          <li><code>!deploy prod</code> 强制按 Shell 执行（去掉 <code>!</code>）；不想走模型的命令都可加 <code>!</code>。</li>
          <li>
            终端复制/粘贴：macOS <code>Cmd+C</code> / <code>Cmd+V</code>；
            Windows/Linux <code>Ctrl+Shift+C</code> / <code>Ctrl+Shift+V</code>。
            <code>Ctrl+C</code> 仍是中断信号。
          </li>
          <li>自然语言会调用模型生成命令；首次未配置模型会弹出配置表单，保存后回车重试。模型失败时 Enter 执行原文、<code>a</code> 重试、Esc 取消。</li>
          <li><code>@fix the bug</code> / <code>/ai why is it slow</code> 强制交给 AI。</li>
          <li>AI 识别开启时，Tab 补全、方向键历史、Ctrl-R 仍由远端原生处理；这些情况下回车按原生执行，不再用本地片段做 AI 分类。</li>
          <li>tmux/vim/less 等全屏程序内 AI 识别暂停，所有按键原样透传给远端；退出全屏后自动恢复，退出后的第一次输入也可正常走 AI。</li>
          <li>
            回车时才分类：自然语言会先让 AI 生成一条单行命令，显示命令/风险/说明，
            确认后才清行写入当前 shell；生成失败不会自动执行原文。
          </li>
          <li><code>cat 中文.txt</code> 这类以命令开头的输入，回车仍按命令直通。</li>
          <li>密码/sudo/passphrase 提示、Python/MySQL/SQLite/redis/psql 等 REPL、here-doc 正文会尽量纯透传；自定义无冒号提示仍可能漏判，建议在提示出现后再输入或关闭 AI 识别。</li>
          <li>
            AI 生成的命令会在执行前写 <code>ai.command_confirmed</code> 审计；手敲的交互命令
            默认不入结构化审计，开启 bash/zsh 命令审计集成后才逐条记录。
          </li>
        </ul>
      </article>

      <article className="card">
        <h3>任务模式</h3>
        <ul className="help-list">
          <li>
            连接主机后点顶栏 <code>任务</code> 打开右侧抽屉，描述一个多步目标；也可以直接在终端
            输入 <code>/task 检查并重载 nginx</code>（或 <code>@task ...</code>）打开面板并生成计划。
            模型只给 1–5 步草案。默认每步都要点 <code>执行</code>；开启「自动推进」后只读步骤
            （R0/R1）会自动执行，R2/R3、交互步骤仍要手动。
          </li>
          <li>
            <code>R2/R3</code> 与需要交互的步骤只显示命令，不提供自动执行按钮；请在终端手动输入，
            再点 <code>已手动执行 · 标记完成</code>。只有 R0/R1 可以跳过。
          </li>
          <li>
            启用 bash/zsh 命令审计（OSC 133）后自动读取退出码与输出尾部；任务模式会自动尝试启用，
            未生效时面板会提示，步骤成功/失败需要手动标记。
          </li>
          <li>
            未执行的步骤（pending/ready）可以「编辑」命令；保存后服务端会重新分级风险，改成 R2/R3
            会变成手动步骤，已有的“需要交互”标记不会被清掉。
          </li>
          <li>
            「自动推进」只自动执行 R0/R1，并自动让 AI 判断下一步；R2/R3、交互、失败、结果未知、
            命令审计未生效或终端不可写时会暂停。开启前有一次风险确认；失败不会自动重试。
          </li>
          <li>
            按标签批量任务会给每台主机建独立任务并串行执行；批次创建表单或批次面板可开启
            「自动推进每台任务」（仅 R0/R1）。批次级开关不持久化，重启恢复后需重新开启。
          </li>
          <li>
            任务抽屉和批次面板顶部都有「新建任务 / 新建批次」主按钮；打开已结束的任务/批次时
            可以直接回到首次创建表单，旧记录仍保留在历史/汇总中。
          </li>
          <li>
            上一步失败会暂停任务，不会自动重试；可重试、跳过（仅 R0/R1）、让 AI 判断下一步或取消。
            连续失败 2 次、超过 8 步或超过 10 分钟会停止。
          </li>
          <li>
            已完成/失败/取消的任务可以「导出」Markdown（任务、步骤、脱敏输出尾部与审计事件），或
            「删除」任务与步骤。删除前会二次确认；审计事件保留。进行中的任务必须先取消才能删除。
          </li>
          <li>
            取消任务会二次确认；正在运行的远端命令可能继续。模型判断中取消会中断本次判断（客户端
            丢弃未完成请求），不会再应用模型返回的结果。
          </li>
          <li>
            任务历史默认保留 30 天、每个主机最多 200 条终态任务；设置页可改策略，启动时自动清理，
            任务抽屉「清理历史」可按当前主机手动清理。只删除终态任务，审计事件保留。
          </li>
          <li>
            「让 AI 判断下一步」只发送目标、已完成命令、退出码与最近 80 行脱敏输出；密码/密钥不会
            发送。模型给出的新步骤仍然逐条确认，不会自动执行。
          </li>
          <li>
            密码/sudo/passphrase、REPL、vim/tmux/less 全屏程序或 120 秒无结束信号会让任务暂停，
            交还用户处理；处理完点「我已处理完，继续」。
          </li>
          <li>
            任务绑定创建它的终端会话；切换会话只能查看、标记结果或取消，不能把命令写到别的 PTY。
            所有确认、执行、失败、取消都写任务审计。
          </li>
        </ul>
      </article>

      <article className="card">
        <h3>安全边界</h3>
        <p className="muted small">
          AI 自然语言生成一条单行 shell 命令，显示完整命令与风险；已知危险模式
          （sudo、rm -rf /、mkfs、dd、shutdown、curl|sh 等）以及 R2 变更命令只打印、
          不执行，退出 AI 确认流程，需用户手动重新输入；R0/R1 只读命令由用户 Enter 确认、
          Esc 取消，执行前写
          <code>ai.command_confirmed</code> 审计。用户手敲命令不受此限制。
          任务模式的每条步骤同样先写 <code>task.step_confirmed</code>；R2/R3 与交互步骤由服务端
          拒绝自动执行，没有“自动批准”“自动重试”“全自动跑完”的路径。
        </p>
      </article>
    </section>
  );
}
