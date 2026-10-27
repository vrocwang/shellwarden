<p align="center"><img src="src-tauri/icons/128x128.png" width="112" alt="ShellWarden" /></p>

<h1 align="center">ShellWarden</h1>

<p align="center">本地优先的 AI SSH 运维终端。自然语言描述目标，模型只负责建议；命令、变更与多步任务默认都要你确认。</p>

> **状态：早期项目。** 真实 OpenSSH 发行版、2FA/跳板机、真实模型提供方与高吞吐场景尚未完成验收；请勿直接用于无人值守的生产环境。

## 特性

- **终端 + 自然语言**：同一个输入框里，Shell 命令直接透传；中文/英文描述交给模型生成单行命令。`!cmd` 强制 Shell，`@...` 或 `/ai ...` 强制 AI。
- **风险分级**：命令按 R0（只读）→ R3（破坏性）展示；R2/R3 与已知危险模式只打印、不自动执行，需要你手动重敲。执行前写审计。
- **任务模式**：把多步目标拆成 1–5 步草案；每步显示完整命令、用途和风险，默认逐条确认。失败暂停、不自动重试；连续失败或超时停止。
- **可选自动推进**：只自动执行 R0/R1 且非交互的步骤；R2/R3、交互、失败、结果未知、超时、审计未生效时暂停。开启前有一次风险确认。
- **批量任务**：按标签选择主机，每台生成独立任务并串行执行；支持失败暂停、刷新/重启恢复、批次汇总导出。可为每台任务开启自动推进。
- **命令审计**：opt-in 的 bash/zsh OSC 133 集成可记录命令、退出码、时长与脱敏输出尾部；审计事件使用哈希链，可检测篡改。
- **主机与凭据**：密码或私钥用 AES-256-GCM 加密保存在本地 SQLite；主机指纹首次确认后固定，指纹变化会阻断连接。
- **本地优先**：没有云端后端；数据库、密钥、审计与任务历史都在本机。

## 快速开始

前置：Rust stable（≥1.85）、Node.js 20+、npm，以及 Tauri 2 对应平台依赖（macOS：Xcode Command Line Tools；Linux：WebKitGTK 等；Windows：WebView2）。

```bash
git clone https://github.com/vrocwang/shellwarden.git
cd shellwarden
npm install
npm run tauri dev
```

常用命令：

```bash
npm run build            # 前端类型检查 + 构建
cargo test --workspace   # Rust 测试
./scripts/check.sh       # fmt + schema + clippy + 测试 + 前端构建
npm run tauri -- build   # 打包桌面应用
```

## 使用

### 终端

- 普通命令直接回车执行。
- 自然语言会先被分类，再显示模型生成的命令、风险与说明；确认后才写入当前 shell。
- `!` 前缀强制走 Shell；`/ai` 或 `@` 强制走 AI。
- vim、tmux、less 等全屏程序内暂停 AI 识别；密码、REPL、here-doc 等敏感输入尽量纯透传。

### 任务模式

顶栏「任务」打开右侧抽屉，输入目标，例如：

```text
检查 nginx 配置并重载，确认本地端口可访问
```

也可以直接在终端输入 `/task 检查并重载 nginx`。

模型生成计划后：

- 每步都要点「执行」确认；
- R2/R3 与交互步骤只显示命令，需要你在终端手动输入后标记完成；
- 失败会暂停，可重试、跳过、让 AI 诊断或取消；
- 任务抽屉可开启「自动推进（仅 R0/R1）」；开启前会提示风险；
- 任务绑定创建它的终端会话，切换会话只能查看/标记。

### 批量任务

- 侧栏按标签筛选主机，选择主机后创建批次；
- 每台主机独立生成计划，串行执行；
- 批次面板可开启「自动推进每台任务（仅 R0/R1）」；批次级开关不持久化；
- 刷新/重启后可恢复，任务会重新绑定到新会话；
- 批次汇总可导出 Markdown。

### 命令审计

在会话审计面板或任务抽屉启用 bash/zsh 命令审计。启用后，终端命令的退出码与输出尾部会进入任务状态机与审计记录；未启用时任务步骤需要手动标记成功/失败。

## 安全模型

ShellWarden 的目标不是“让 AI 直接操作服务器”，而是把 AI 建议、风险提示、人工确认和可检测审计放在同一条链路里。

- **默认人工确认**：单命令与任务步骤都需要确认；R2/R3 永远需要手动执行。
- **自动推进是 opt-in**：只自动执行 R0/R1，R2/R3、交互、失败、未知结果立即暂停；不自动重试。
- **凭据**：密码/私钥用 AES-256-GCM 加密；密钥文件 `secret.key` 默认 Unix 0600。它能防止数据库被单独拷走，但不能防止能读取该文件的本机用户。
- **主机指纹**：首次连接必须确认指纹；已记录指纹变化会阻断连接。
- **模型输入**：单命令模式发送用户描述与主机别名；任务推进额外发送已完成步骤的命令、退出码与最近一段脱敏输出尾部。完整输出、密码与密钥不会发送。
- **审计**：关键操作写哈希链审计；任务步骤的 `task.step_confirmed`/`task.step_started` 带 `auto` 标记，区分自动与手动确认。

### 诚实边界

- 风险分级是启发式规则，不是完整的 shell 语义分析；R1 仍可能包含非预期命令。
- 输出脱敏是启发式；不含 `key=value` 形态的秘密仍可能出现在尾部。
- 审计哈希链只承诺“可检测篡改”，不承诺“不可抵赖”；能改数据库与密钥的本机用户仍可重写。
- 前端是可信执行器；后端保证任务状态机、风险、顺序、预算与审计，不防被完全控制的 WebView 绕过 UI。
- 真实主机、真实模型、2FA/跳板机、高吞吐与发布打包仍需验收。

## 架构

```text
crates/core/      审计链、摘要、错误、ID
crates/store/     SQLite schema、迁移、主机/审计/设置/任务仓储
crates/ssh/       SSH 后端接口、known_hosts、russh PTY
crates/model/     OpenAI 兼容模型适配、命令/任务提示词与解析
src-tauri/        Tauri 2 应用、IPC、任务审计与脱敏
src/              React + TypeScript + xterm.js 前端
schemas/          JSON schema
scripts/          检查与 shell integration 脚本
```

技术栈：Tauri 2、Rust、React 19、TypeScript、Vite、xterm.js、rusqlite、russh。

## 配置与数据

- 非秘密配置在 `config.toml`；默认放在系统应用数据目录，便携模式优先放在可写的可执行文件同目录。
- `SHELLWARDEN_CONFIG`、`SHELLWARDEN_DATA_DIR` 可显式覆盖配置/数据目录。
- 数据库、`secret.key`、`known_hosts.json` 属于本地运行数据，不要提交到仓库。
- 模型 Base URL、模型名与 API Key 在设置页配置；任务历史保留策略在设置页或 `[tasks]` 配置。
- 任务历史默认保留 30 天、每个主机最多 200 条终态任务；只删除终态任务，审计事件保留。

## 开发

```bash
npm install
npm run tauri dev
npm run build
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/check.sh
```

提交前请至少运行 `./scripts/check.sh`。

## 已知限制

- 真实 OpenSSH 发行版、跳板机、2FA/SSH Agent 的兼容矩阵未完整验证。
- 终端数据仍走 base64 JSON 事件，未改为原始字节通道；高吞吐/背压未验收。
- 交互态识别基于 alternate-screen 与提示符启发式；自定义提示符、复杂 here-doc 可能误判。
- 任务自动推进与批次自动推进是客户端状态机，暂无前端自动化测试。
- 自动化仅覆盖 R0/R1；R2/R3 仍需要人工执行。

## License

MIT，见 [LICENSE](LICENSE)。

---

如果这个项目对你有帮助，欢迎提 Issue 或 PR。使用前请先在非生产环境验证。
