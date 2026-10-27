import { openConfigDir, type AppInfo } from "./api";

export function AboutView({ info }: { info: AppInfo | null }) {
  return (
    <section className="page">
      <article className="card">
        <h3>ShellWarden</h3>
        <p className="muted small">
          面向 AI 运维的安全终端：真实 SSH PTY + 通用 AI 命令 + 本地审计。
        </p>
        <dl className="kv">
          <div><dt>应用版本</dt><dd>{info?.version ?? "—"}</dd></div>
          <div><dt>数据库 schema</dt><dd>{info ? `v${info.db_schema}` : "—"}</dd></div>
          <div>
            <dt>配置文件</dt>
            <dd>
              {info?.config_path ?? "—"}{" "}
              <button type="button" className="ghost" onClick={() => void openConfigDir()}>
                打开配置目录
              </button>
            </dd>
          </div>
          <div><dt>数据目录</dt><dd>{info?.data_dir ?? "—"}</dd></div>
          <div><dt>迁移数据</dt><dd>编辑 config.toml 的 [storage] data_dir 后重启，应用会复制数据库、secret.key 与 known_hosts 到新目录，旧目录保留为备份</dd></div>
          <div><dt>本机主机数</dt><dd>{info?.host_count ?? 0}</dd></div>
        </dl>
      </article>

      <article className="card">
        <h3>数据与隐私</h3>
        <ul className="help-list">
          <li>主机密码、私钥、模型密钥用 AES-256-GCM 加密，密钥是本机 <code>secret.key</code>。</li>
          <li><code>secret.key</code> 是 32 字节随机二进制密钥，不是文本；文本编辑器打开乱码是正常的，不要编辑或只迁移数据库而不迁移它。</li>
          <li>主机私钥可选择加密保存到本地数据库；路径方式直接读取本机文件。</li>
          <li>审计事件写入本地 SQLite，带哈希链；不上传云端。</li>
          <li>
            单命令模式只发送用户描述与主机别名；任务推进模式额外发送已完成步骤的命令、退出码与最近
            80 行脱敏输出尾部。完整输出、密码与密钥不会发送；结构化凭据（如{" "}
            <code>password=</code>、Bearer）会被拒绝或脱敏。<strong>自定义提示符</strong>仍可能漏判，
            输入口令前请确认提示符已被识别或关闭 AI 识别。
          </li>
        </ul>
      </article>
    </section>
  );
}
