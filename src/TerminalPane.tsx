import { useEffect, useRef, useState } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { readText as readClipboardText, writeText as writeClipboardText } from "@tauri-apps/plugin-clipboard-manager";
import "@xterm/xterm/css/xterm.css";
import { createOsc133Parser } from "./osc";

import {
  auditAiCommand,
  classifyInput,
  commandExists,
  decodeBase64,
  describeError,
  encodeBase64,
  recordTerminalCommand,
  resizeSession,
  sessionAttach,
  sessionDetach,
  writeSession,
  type CommandOption,
  type DraftCommandResult,
  type ShortcutsConfig,
  type SessionClosedEvent,
  type SessionDataEvent,
  type SessionErrorEvent
} from "./api";

interface Props {
  sessionId: string;
  title: string;
  /** 当前可见（用于 fit/尺寸）；不可见时保持挂载但暂停 resize。 */
  visible?: boolean;
  /** 当前键盘焦点；同一时刻只应有一个。 */
  active?: boolean;
  onFocus?: () => void;
  onClose?: () => void;
  onExit: (sessionId: string, message: string) => void;
  /** 自然语言 → 一条 shell 命令（终端里的通用命令模式）。 */
  onCommand: (text: string) => Promise<DraftCommandResult>;
  /** 首次自然语言调用发现模型未配置时，打开配置表单。 */
  onModelRequired?: () => void;
  /** 终端复制/粘贴快捷键。 */
  shortcuts?: ShortcutsConfig;
  /** OSC 133 命令结束：退出码 + 本次输出尾部（任务模式用）。 */
  onCommandFinished?: (event: {
    sessionId: string;
    command: string;
    exitCode: number | null;
    durationMs: number;
    outputTail: string;
  }) => void;
  /** 检测到密码/REPL/全屏等交互信号（任务模式用）。 */
  onInteractivePrompt?: (sessionId: string, reason: string) => void;
  /** 收到任意 OSC 133 事件，说明 shell integration 已生效。 */
  onShellIntegration?: (sessionId: string) => void;
  /** 全屏程序（vim/tmux/less）进入/退出；任务面板据此阻止执行。 */
  onInteractiveState?: (sessionId: string, interactive: boolean) => void;
  /** `/task ...` 或 `@task ...`：交给任务模式生成计划。 */
  onTaskRequest?: (text: string) => void;
  /** 当前终端处于密码/REPL/yes-no 等不安全提示；任务执行据此阻止。 */
  onUnsafePrompt?: (sessionId: string, unsafe: boolean, detail: string) => void;
}

const CTRL_U = "\x15";

/** 最后一行非空输出（去掉 ANSI），用于识别密码 / REPL 提示符。 */
function lastNonEmptyLine(raw: string): string {
  const lines = raw.split(/\r?\n/);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index].trim();
    if (line.length > 0) return line;
  }
  return "";
}

function stripAnsi(raw: string): string {
  // CSI / OSC / 常见单字符转义；只用于提示符识别，不参与渲染。
  return raw
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
}

interface ParsedShortcut {
  ctrl: boolean;
  meta: boolean;
  alt: boolean;
  shift: boolean;
  key: string;
}

function parseShortcut(raw: string, fallback: string): ParsedShortcut {
  const text = (raw || fallback).trim();
  const parts = text.split("+").map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0) return parseShortcut(fallback, "Ctrl+Shift+C");
  const key = parts.pop()?.toLowerCase() ?? "";
  const parsed: ParsedShortcut = {
    ctrl: false,
    meta: false,
    alt: false,
    shift: false,
    key: key === "space" ? " " : key
  };
  for (const part of parts) {
    const mod = part.toLowerCase();
    if (mod === "ctrl" || mod === "control") parsed.ctrl = true;
    else if (mod === "cmd" || mod === "meta" || mod === "super") parsed.meta = true;
    else if (mod === "alt" || mod === "option") parsed.alt = true;
    else if (mod === "shift") parsed.shift = true;
  }
  return parsed;
}

function matchesShortcut(
  event: KeyboardEvent,
  raw: string,
  fallback: string
): boolean {
  const parsed = parseShortcut(raw, fallback);
  // Ctrl+C 永远保留为终端中断，不能被自定义快捷键覆盖。
  if (parsed.ctrl && !parsed.meta && !parsed.alt && !parsed.shift && parsed.key === "c") {
    return false;
  }
  return (
    event.ctrlKey === parsed.ctrl &&
    event.metaKey === parsed.meta &&
    event.altKey === parsed.alt &&
    event.shiftKey === parsed.shift &&
    event.key.toLowerCase() === parsed.key
  );
}

/** 读取终端当前行中提示符之后的文本；仅用于方向键历史召回。 */
function currentInputLine(term: Terminal): string {
  const buffer = term.buffer.active;
  const line = buffer.getLine(buffer.baseY + buffer.cursorY);
  if (!line) return "";
  const raw = line.translateToString(true);
  const visible = raw.slice(0, Math.max(0, buffer.cursorX));
  // 常见 shell 提示符以 "$ "、"# "、"❯ " 等结尾；取第一个提示符之后。
  const prompt = /^.*?[$#%❯>]\s/.exec(visible);
  return (prompt ? visible.slice(prompt[0].length) : visible).trimEnd();
}

async function copyToClipboard(text: string): Promise<void> {
  try {
    await writeClipboardText(text);
  } catch {
    await navigator.clipboard.writeText(text);
  }
}

async function pasteFromClipboard(): Promise<string> {
  try {
    return await readClipboardText();
  } catch {
    return navigator.clipboard.readText();
  }
}

/** 密码、sudo、passphrase、read -s 等提示：整行透传，绝不交给 AI。 */
function isSecretPromptLine(line: string): boolean {
  const trimmed = line.trimEnd();
  if (!trimmed) return false;
  // 跨语言的强结构信号：短提示行以冒号/问号结尾（Password:、密码：、
  // Contraseña:、Пароль:、パスワード：、PIN? 等）。宁可多判为秘密输入，
  // 也不要把口令送进模型。
  if (trimmed.length <= 160 && /[:：?？]\s*$/.test(trimmed)) {
    return true;
  }
  // 常见秘密词的多语言兜底（没有冒号的自定义提示）。
  return /(password|passwd|passphrase|passcode|pin|otp|verification code|secret|credential|密码|口令|パスワード|비밀번호|пароль|contraseña|mot de passe|كلمة المرور|पासवर्ड|senha|passwort|wachtwoord|şifre|رمز)\s*[:：?？]?\s*$/iu.test(
    trimmed
  );
}

/** 常见 REPL 提示符：这些输入必须原样透传（PRD §9.4）。 */
function isReplPromptLine(line: string): boolean {
  // 除了 `>>>`/`mysql>`/`sqlite>` 这类裸提示符，还要覆盖真实客户端：
  // redis-cli 的 `127.0.0.1:6379>`、psql 的 `postgres=#`、mariadb 的
  // `mariadb [(none)]>`。注意不要匹配 `root@host:~#` 这种普通 shell 提示符。
  return /^(>>>|\.\.\.|In \[\d+\]:|Out\[\d+\]:|irb\(|pry\(|node>|julia>|R>|>|mariadb \[[^\]]*\]>|[\w.-]+(:\d+)?[=>#]+)\s*$/.test(
    line
  );
}

function isUnsafeInputPrompt(raw: string): boolean {
  const line = lastNonEmptyLine(raw);
  return isSecretPromptLine(line) || isReplPromptLine(line);
}

/** 任务模式下更窄的交互信号：只认密码/口令与 REPL 提示符。 */
function taskInteractiveReason(raw: string): string | null {
  const line = lastNonEmptyLine(raw);
  if (!line) return null;
  if (isSecretPromptLine(line)) return `检测到密码/口令提示：${line.slice(0, 160)}`;
  if (isReplPromptLine(line)) return `检测到 REPL 提示符：${line.slice(0, 160)}`;
  return null;
}

function heredocTerminator(line: string): string | null {
  const match = /<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/.exec(line);
  return match ? match[1] : null;
}

export function TerminalPane({
  sessionId,
  title,
  visible = true,
  active = true,
  onFocus,
  onClose,
  onExit,
  onCommand,
  onModelRequired,
  shortcuts,
  onCommandFinished,
  onInteractivePrompt,
  onShellIntegration,
  onInteractiveState,
  onTaskRequest,
  onUnsafePrompt
}: Props) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const visibleRef = useRef(visible);
  const [aiInput, setAiInput] = useState(true);
  const aiInputRef = useRef(true);
  const [fullscreen, setFullscreen] = useState(false);

  const commandRef = useRef(onCommand);
  const modelRequiredRef = useRef(onModelRequired);
  const shortcutsRef = useRef(shortcuts);
  const commandFinishedRef = useRef(onCommandFinished);
  const interactivePromptRef = useRef(onInteractivePrompt);
  const shellIntegrationRef = useRef(onShellIntegration);
  const interactiveStateRef = useRef(onInteractiveState);
  const taskRequestRef = useRef(onTaskRequest);
  const unsafePromptRef = useRef(onUnsafePrompt);

  useEffect(() => {
    commandRef.current = onCommand;
    modelRequiredRef.current = onModelRequired;
    shortcutsRef.current = shortcuts;
    commandFinishedRef.current = onCommandFinished;
    interactivePromptRef.current = onInteractivePrompt;
    shellIntegrationRef.current = onShellIntegration;
    interactiveStateRef.current = onInteractiveState;
    taskRequestRef.current = onTaskRequest;
    unsafePromptRef.current = onUnsafePrompt;
  }, [onCommand, onModelRequired, shortcuts, onCommandFinished, onInteractivePrompt, onShellIntegration, onInteractiveState, onTaskRequest, onUnsafePrompt]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.3,
      scrollback: 5000,
      theme: {
        background: "#080b10",
        foreground: "#d8dee9",
        cursor: "#4dd4c0",
        selectionBackground: "#1f4f49",
        black: "#1c2430",
        red: "#ff6b6b",
        green: "#5fd38a",
        yellow: "#e6c07b",
        blue: "#6aa9ff",
        magenta: "#c792ea",
        cyan: "#4dd4c0",
        white: "#d8dee9"
      }
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    const isMac = navigator.userAgent.includes("Mac");
    const defaultCopy = isMac ? "Cmd+C" : "Ctrl+Shift+C";
    const defaultPaste = isMac ? "Cmd+V" : "Ctrl+Shift+V";
    term.attachCustomKeyEventHandler((event) => {
      if (event.type !== "keydown") return true;
      const copyCombo = matchesShortcut(
        event,
        shortcutsRef.current?.copy ?? defaultCopy,
        defaultCopy
      );
      const pasteCombo = matchesShortcut(
        event,
        shortcutsRef.current?.paste ?? defaultPaste,
        defaultPaste
      );
      if (copyCombo) {
        const selection = term.getSelection();
        if (selection) void copyToClipboard(selection).catch(() => undefined);
        event.preventDefault();
        return false;
      }
      if (pasteCombo) {
        event.preventDefault();
        void pasteFromClipboard()
          .then((text) => {
            if (text) term.paste(text);
          })
          .catch(() => undefined);
        return false;
      }
      return true;
    });
    termRef.current = term;
    fitRef.current = fit;
    if (visibleRef.current) {
      fit.fit();
      if (active) term.focus();
    }

    type Phase = "idle" | "classifying" | "ambiguous" | "analyzing" | "confirm";
    let phase: Phase = "idle";
    let pendingOptions: CommandOption[] = [];
    let selectedOption = 0;
    let renderedOptionRows = 0;
    let pendingRequest = "";
    let lastSubmittedCommand = "";
    let pendingOscCommand = "";
    let commandStartedAt = 0;
    let commandActive = false;
    let commandOutput = "";
    let interactivePromptReported = false;
    let integrationReported = false;
    const osc = createOsc133Parser();
    const reportInteractive = (reason: string) => {
      if (interactivePromptReported) return;
      interactivePromptReported = true;
      interactivePromptRef.current?.(sessionId, reason);
    };
    const handleOsc = (bytes: Uint8Array) => {
      for (const event of osc(bytes)) {
        if (!integrationReported) {
          integrationReported = true;
          shellIntegrationRef.current?.(sessionId);
        }
        if (event.type === "command") {
          pendingOscCommand = event.command;
        } else if (event.type === "command-start") {
          commandStartedAt = Date.now();
          commandActive = true;
          commandOutput = "";
          interactivePromptReported = false;
          // 命令已提交：本地行缓冲一定过期。任务面板直接写 PTY 时也走这里，
          // 避免用户残留的半截输入在下一次回车被重新分类/重放。
          resetLineState();
        } else if (event.type === "command-end") {
          const command = pendingOscCommand || lastSubmittedCommand;
          const started = commandStartedAt || Date.now();
          const durationMs = Math.max(0, Date.now() - started);
          const outputTail = stripAnsi(commandOutput).slice(-16000);
          const finished = commandActive;
          commandActive = false;
          commandOutput = "";
          interactivePromptReported = false;
          if (command.trim()) {
            void recordTerminalCommand({
              session_id: sessionId,
              command,
              exit_code: event.exitCode,
              started_at: new Date(started).toISOString()
            }).catch(() => undefined);
          }
          if (finished) {
            commandFinishedRef.current?.({
              sessionId,
              command,
              exitCode: event.exitCode,
              durationMs,
              outputTail
            });
          }
          pendingOscCommand = "";
          lastSubmittedCommand = "";
          commandStartedAt = 0;
        }
      }
    };
    let pendingText = "";
    let job = 0;
    let line = "";
    // 本地 line 是否仍与远端真实行一致。任何可能改写远端行的按键
    // （Tab/方向键/全屏程序/粘贴/截断）都会把它置 false；回车时只发原生 \r，
    // 绝不再用一个不可信的片段去分类或 Ctrl-U。
    let lineTrusted = true;
    let historyRecall = false;
    let wasInteractive = term.buffer.active.type === "alternate";
    // tmux/vim/less 切回普通缓冲时，必须清掉全屏期间留下的不可信行标记；
    // 否则退出 tmux 后的第一次自然语言会被当成普通命令原样回车。
    const syncInteractive = (next: boolean) => {
      if (next === wasInteractive) return;
      if (wasInteractive && !next) {
        line = "";
        lineTrusted = true;
        lineUnsafe = false;
        heredocEnd = null;
        // 全屏程序的退出画面不能参与下一条命令的密码/REPL 判断。
        outputTail = "";
      }
      wasInteractive = next;
      setFullscreen(next);
      interactiveStateRef.current?.(sessionId, next);
      if (next && commandActive) {
        reportInteractive("检测到全屏程序（vim/less/tmux）");
      }
    };
    let sawData = false;
    let userTyped = false;
    // 当前输入是否起于密码 / REPL 提示符；起于这些提示时绝不走 AI。
    let lineUnsafe = false;
    // 正在这里的 here-doc 终止符；期间所有输入原样透传。
    let heredocEnd: string | null = null;
    // 分类期间用户继续输入的按键：Shell 路径会补发，避免静默丢键。
    let deferredInput = "";
    let outputTail = "";
    let unsafePrompt = false;
    // 只在状态翻转时上报：密码/REPL/yes-no 提示期间禁止任务面板发命令，
    // 避免把 Ctrl-U + 命令打进 sudo 密码或 REPL。
    const reportUnsafePrompt = () => {
      const next = isUnsafeInputPrompt(outputTail);
      if (next === unsafePrompt) return;
      unsafePrompt = next;
      unsafePromptRef.current?.(
        sessionId,
        next,
        next ? lastNonEmptyLine(outputTail).slice(0, 160) : ""
      );
    };
    const decoder = new TextDecoder();

    const resetLineState = () => {
      line = "";
      lineTrusted = true;
      lineUnsafe = false;
      heredocEnd = null;
      historyRecall = false;
    };
    const resetPendingState = () => {
      pendingOptions = [];
      selectedOption = 0;
      pendingRequest = "";
      pendingText = "";
      deferredInput = "";
      renderedOptionRows = 0;
    };

    const refreshPrompt = () => {
      resetLineState();
      // 让远端 shell 重新打印一次提示符，接在本地输出之后。
      void writeSession(sessionId, encodeBase64("\r")).catch(() => undefined);
    };

    const renderCommand = (options: CommandOption[], selected: number) => {
      const active = options[selected];
      if (!active) return;
      // 清除上一帧候选块并原位重绘，避免方向键切换时不断往 scrollback 追加。
      if (renderedOptionRows > 0) {
        term.write(`\x1b[${renderedOptionRows}A\r\x1b[0J`);
      }
      const width = Math.max(20, term.cols);
      const displayWidth = (text: string) =>
        Array.from(text).reduce(
          (sum, char) => sum + (/[\u1100-\uffff]/.test(char) ? 2 : 1),
          0
        );
      const rowsFor = (text: string) =>
        Math.max(1, Math.ceil(displayWidth(text) / width));
      let rows = 0;
      const writeLine = (ansi: string, plain: string) => {
        rows += rowsFor(plain);
        term.write(`${ansi}\r\n`);
      };

      writeLine(
        "\x1b[36m── AI 命令（选择要执行的版本）─────────\x1b[0m",
        "── AI 命令（选择要执行的版本）─────────"
      );
      options.forEach((option, index) => {
        const isSelected = index === selected;
        const riskColor =
          option.risk === "R3" || option.risk === "R2" ? "\x1b[31m" : "\x1b[36m";
        const marker = isSelected ? "\x1b[7m▶" : " ";
        const riskPlain = `${isSelected ? "▶" : " "} [${index + 1}] ${option.risk} · ${
          option.explanation || "无说明"
        }`;
        if (isSelected) {
          writeLine(
            `\x1b[7m${marker} [${index + 1}] ${riskColor}${option.risk} · ${
              option.explanation || "无说明"
            }\x1b[0m`,
            riskPlain
          );
        } else {
          writeLine(
            `${marker} [${index + 1}] ${riskColor}${option.risk}\x1b[0m · ${
              option.explanation || "无说明"
            }`,
            riskPlain
          );
        }
        const commandPlain = `      $ ${option.command}`;
        const commandAnsi = isSelected
          ? `\x1b[7m${commandPlain}\x1b[0m`
          : `      \x1b[37m$ ${option.command}\x1b[0m`;
        writeLine(commandAnsi, commandPlain);
      });
      if (active.manual_only) {
        writeLine(
          "\x1b[31m此候选为高风险，不会执行；↑/↓ 或数字切换 · e 编辑 · r 重新描述 · Esc 取消\x1b[0m",
          "此候选为高风险，不会执行；↑/↓ 或数字切换 · e 编辑 · r 重新描述 · Esc 取消"
        );
      } else {
        writeLine(
          "\x1b[90m↑/↓ 选择 · 数字选择 · Enter 执行 · e 编辑 · r 重新描述 · Esc 取消\x1b[0m",
          "↑/↓ 选择 · 数字选择 · Enter 执行 · e 编辑 · r 重新描述 · Esc 取消"
        );
      }
      renderedOptionRows = rows;
    };

    const cancel = (message: string) => {
      job += 1;
      phase = "idle";
      resetPendingState();
      resetLineState();
      term.write(`\r\x1b[2K\r\n\x1b[90m${message}\x1b[0m\r\n`);
      refreshPrompt();
    };

    const runAnalysis = async (value: string) => {
      const current = ++job;
      phase = "analyzing";
      term.write(`\r\n\x1b[90m◐ 生成命令：${value}\x1b[0m`);
      try {
        const proposal = await commandRef.current(value);
        if (current !== job) return;
        if (proposal.commands.length === 0) {
          throw new Error("模型没有返回命令候选");
        }
        // 必须先确认远端原行已清空，再刷新提示符；否则高风险路径里
        // 立即发送的 \r 可能抢在 Ctrl-U 前到达，把自然语言原文执行掉。
        try {
          await writeSession(sessionId, encodeBase64(CTRL_U));
        } catch (err) {
          phase = "idle";
          pendingOptions = [];
          term.write(
            `\r\n\x1b[31m无法清空远端输入行，AI 命令未执行：${describeError(err)}\x1b[0m\r\n`
          );
          return;
        }
        term.write("\r\x1b[2K");
        pendingOptions = proposal.commands;
        selectedOption = 0;
        pendingRequest = value;
        const allManual = pendingOptions.every((option) => option.manual_only);
        if (allManual) {
          renderCommand(pendingOptions, 0);
          resetPendingState();
          phase = "idle";
          refreshPrompt();
          return;
        }
        phase = "confirm";
        renderCommand(pendingOptions, selectedOption);
      } catch (err) {
        if (current !== job) return;
        const code =
          err && typeof err === "object" && "code" in err
            ? (err as { code?: string }).code
            : undefined;
        if (code === "model.config_invalid" && modelRequiredRef.current) {
          // 保留远端自然语言行；配置完成后用户直接回车即可重试。
          phase = "idle";
          pendingText = "";
          line = value;
          lineTrusted = true;
          lineUnsafe = false;
          term.write(
            "\r\n\x1b[33m尚未配置大模型，已打开配置表单。\x1b[0m\r\n\x1b[90m保存后回到终端按 Enter 重试。\x1b[0m\r\n"
          );
          modelRequiredRef.current();
          return;
        }
        // 失败后不再让回车再次自动请求模型。
        phase = "ambiguous";
        pendingText = value;
        line = value;
        term.write(
          `\r\n\x1b[31m生成命令失败：${describeError(err)}\x1b[0m\r\n\x1b[90m输入仍保留在远端命令行：Enter 执行原命令 · a 重试 AI · Esc 取消\x1b[0m\r\n`
        );
      }
    };

    const classifyAndRoute = async (text: string) => {
      // 显式任务入口：/task 或 @task。优先于 shell/AI 分类，但仍在
      // “密码/REPL/全屏/不可信行”检查之后，不会把秘密送进任务模式。
      const taskGoal = /^(?:\/task|@task)\s+([\s\S]+)$/i.exec(text.trim())?.[1]?.trim();
      if (taskGoal) {
        phase = "idle";
        deferredInput = "";
        try {
          // 清掉远端已回显的 /task 原文，避免它留在命令行里。
          await writeSession(sessionId, encodeBase64(CTRL_U));
        } catch (err) {
          line = text;
          term.write(
            `\r\n\x1b[31m无法清空远端输入行，任务模式未启动：${describeError(err)}\x1b[0m\r\n`
          );
          return;
        }
        term.write(`\r\n\x1b[90m▶ 任务模式：${taskGoal}\x1b[0m\r\n`);
        taskRequestRef.current?.(taskGoal);
        refreshPrompt();
        return;
      }
      phase = "classifying";
      try {
        const result = await classifyInput(text);
        let intent = result.intent;
        // nlsh 0.5 的契约：probe 只用于 Ambiguous；明确 AI 不得被
        // “首词存在”覆盖（nginx reload 的 nginx 存在，但整行是请求）。
        if (intent === "ambiguous" && result.probe) {
          term.write(`\r\n\x1b[90m◐ 检查命令 ${result.probe}…\x1b[0m`);
          const exists = await commandExists(sessionId, result.probe).catch(() => false);
          term.write("\r\x1b[2K");
          if (exists) intent = "shell";
        }
        if (intent === "ai") {
          deferredInput = "";
          void runAnalysis(result.text);
          return;
        }
        if (intent === "ambiguous") {
          deferredInput = "";
          pendingText = result.text;
          phase = "ambiguous";
          term.write(
            "\r\n\x1b[90m? 可能是命令：Enter 执行 · a 交给 AI · Esc 取消\x1b[0m\r\n"
          );
          return;
        }
        phase = "idle";
        lastSubmittedCommand = result.text;
        if (result.text !== text) {
          // 强制前缀（!cmd）需要先清掉远端已回显的原行。
          void writeSession(sessionId, encodeBase64(CTRL_U + result.text + "\r"));
        } else {
          void writeSession(sessionId, encodeBase64("\r"));
        }
        // 分类期间暂存的按键补发到远端；避免用户打字被静默吞掉。
        if (deferredInput) {
          const deferred = deferredInput;
          deferredInput = "";
          line += deferred;
          void writeSession(sessionId, encodeBase64(deferred));
        }
      } catch (err) {
        phase = "idle";
        line = text;
        deferredInput = "";
        // 分类失败不得降级为直接执行（PRD §5.2）。
        term.write(
          `\r\n\x1b[31m分类失败：${describeError(err)}\x1b[0m\r\n\x1b[90m输入未执行；可继续编辑或回车重试\x1b[0m\r\n`
        );
      }
    };

    const input = term.onData((data) => {
      userTyped = true;
      if (phase === "confirm") {
        if (pendingOptions.length > 0) {
          const option = pendingOptions[selectedOption];
          if (data === "\x1b[A" || data === "\x1bOA") {
            selectedOption =
              (selectedOption - 1 + pendingOptions.length) % pendingOptions.length;
            renderCommand(pendingOptions, selectedOption);
            return;
          }
          if (data === "\x1b[B" || data === "\x1bOB") {
            selectedOption = (selectedOption + 1) % pendingOptions.length;
            renderCommand(pendingOptions, selectedOption);
            return;
          }
          if (/^[1-9]$/.test(data)) {
            const index = Number(data) - 1;
            if (index < pendingOptions.length) {
              selectedOption = index;
              renderCommand(pendingOptions, selectedOption);
            }
            return;
          }
          if (data === "\r" && option) {
            if (option.manual_only) {
              resetPendingState();
              phase = "idle";
              term.write(
                "\r\n\x1b[31m该候选为高风险，未执行；请手动输入。\x1b[0m\r\n"
              );
              refreshPrompt();
              return;
            }
            resetPendingState();
            phase = "idle";
            void (async () => {
              try {
                await auditAiCommand({
                  session_id: sessionId,
                  command: option.command,
                  risk: option.risk
                });
              } catch (err) {
                line = option.command;
                term.write(
                  `\r\n\x1b[31m审计写入失败，命令未执行：${describeError(err)}\x1b[0m\r\n`
                );
                return;
              }
              lastSubmittedCommand = option.command;
              void writeSession(sessionId, encodeBase64(CTRL_U + option.command + "\r"));
              term.write("\r\n\x1b[90m▶ 执行 AI 命令…\x1b[0m\r\n");
            })();
          } else if ((data === "e" || data === "E") && option) {
            const command = option.command;
            resetPendingState();
            phase = "idle";
            lastSubmittedCommand = command;
            line = command;
            lineTrusted = true;
            lineUnsafe = false;
            void writeSession(sessionId, encodeBase64(CTRL_U + command));
            term.write(
              "\r\n\x1b[90m已放入命令行：可修改后回车执行，AI 流程已结束\x1b[0m\r\n"
            );
          } else if (data === "r" || data === "R") {
            const request = pendingRequest;
            resetPendingState();
            phase = "idle";
            line = request;
            lineTrusted = true;
            lineUnsafe = false;
            if (request) {
              void writeSession(sessionId, encodeBase64(CTRL_U + request));
              term.write(
                "\r\n\x1b[90m已恢复原始描述：修改后回车重新生成，Esc 取消\x1b[0m\r\n"
              );
            } else {
              refreshPrompt();
            }
          } else if (data === "\x1b" || data === "\x03") {
            cancel("已取消 AI 命令");
          }
          return;
        }
        return;
      }
      if (phase === "analyzing") {
        if (data === "\x1b" || data === "\x03") {
          // 远端命令行仍保留原文，取消时清掉。
          void writeSession(sessionId, encodeBase64(CTRL_U)).catch(() => undefined);
          cancel("已取消生成");
        }
        return;
      }
      if (phase === "classifying") {
        if (data === "\x03") {
          job += 1;
          phase = "idle";
          deferredInput = "";
          line = "";
          lineTrusted = true;
          lineUnsafe = false;
          void writeSession(sessionId, encodeBase64("\x03")).catch(() => undefined);
          return;
        }
        // 先暂存；Shell 路径完成后补发，AI 路径明确丢弃。
        deferredInput += data;
        return;
      }
      if (phase === "ambiguous") {
        if (data === "\r") {
          lastSubmittedCommand = pendingText;
          pendingText = "";
          phase = "idle";
          lineTrusted = true;
          lineUnsafe = false;
          void writeSession(sessionId, encodeBase64("\r"));
        } else if (data.toLowerCase() === "a") {
          const text = pendingText;
          pendingText = "";
          deferredInput = "";
          phase = "idle";
          void runAnalysis(text);
        } else if (data === "\x1b" || data === "\x03") {
          phase = "idle";
          pendingText = "";
          void writeSession(sessionId, encodeBase64(CTRL_U));
          term.write("\r\n\x1b[90m已取消\x1b[0m\r\n");
          refreshPrompt();
        }
        return;
      }

      const interactive = term.buffer.active.type === "alternate";
      syncInteractive(interactive);
      // vim/tmux/less 等全屏程序内不跟踪本地行。退出后本地缓冲仍是
      // “全屏按键”的残留（旧实现会把 q 带进下一条命令），因此把
      // lineTrusted 置 false，下一次回车只发原生 \r。
      if (interactive && data !== "\r") {
        line = "";
        lineTrusted = false;
        lineUnsafe = false;
        heredocEnd = null;
        historyRecall = false;
        void writeSession(sessionId, encodeBase64(data));
        return;
      }

      if (data === "\r") {
        const text = line;
        line = "";
        // here-doc 正文：整段透传，直到终止符。
        if (heredocEnd) {
          void writeSession(sessionId, encodeBase64("\r"));
          if (text.trim() === heredocEnd) {
            heredocEnd = null;
            lineTrusted = true;
          } else {
            lineTrusted = false;
          }
          lineUnsafe = false;
          return;
        }
        // 方向键召回的历史行：本地 line 不可信，但终端当前行有真实文本。
        // 只对非交互、非秘密提示的 shell 行做一次恢复，再走正常分类。
        if (
          historyRecall &&
          !interactive &&
          aiInputRef.current &&
          !lineUnsafe &&
          !isUnsafeInputPrompt(outputTail)
        ) {
          const recalled = currentInputLine(term);
          historyRecall = false;
          if (recalled) {
            line = recalled;
            lineTrusted = true;
            void classifyAndRoute(recalled);
            return;
          }
        }
        historyRecall = false;
        // 关闭识别，或身处 vim/tmux/less 等全屏程序：完全原生。
        if (!aiInputRef.current || interactive) {
          const isHistoryExpansion = /^!(!|\$|\*|\^|-|\d)/.test(text);
          if (
            !aiInputRef.current &&
            !interactive &&
            text.startsWith("!") &&
            !text.startsWith("! ") &&
            !isHistoryExpansion
          ) {
            // `!cmd` 在关闭 AI 识别时也应剥离 `!`；但 `!!`/`!$`/`!-1`
            // 是 bash 历史展开，不能改写。
            lastSubmittedCommand = text.slice(1);
            void writeSession(sessionId, encodeBase64(CTRL_U + text.slice(1) + "\r"));
          } else {
            lastSubmittedCommand = interactive || !lineTrusted ? "" : text;
            void writeSession(sessionId, encodeBase64("\r"));
          }
          lineUnsafe = false;
          lineTrusted = !interactive;
          return;
        }
        // 本地行不可信（Tab/方向键/全屏退出/粘贴/截断）：只发原生回车，
        // 绝不清远端行、绝不把片段送去分类。
        if (!lineTrusted) {
          lastSubmittedCommand = "";
          void writeSession(sessionId, encodeBase64("\r"));
          lineUnsafe = false;
          lineTrusted = true;
          return;
        }
        // 密码 / REPL 提示：绝不分类、绝不清行、绝不外发。
        // 回车时再读一次 outputTail，覆盖“提示符晚于首个按键到达”的竞态。
        if (lineUnsafe || isUnsafeInputPrompt(outputTail)) {
          lastSubmittedCommand = "";
          void writeSession(sessionId, encodeBase64("\r"));
          lineUnsafe = false;
          return;
        }
        // here-doc 起始行按 Shell 处理，并记住终止符。
        const terminator = heredocTerminator(text);
        if (terminator) {
          heredocEnd = terminator;
          lastSubmittedCommand = text;
          lineTrusted = false;
          void writeSession(sessionId, encodeBase64("\r"));
          return;
        }
        // 语言不限：非 ASCII 文字、句末标点、未知多词都由服务端分类器判断。
        void classifyAndRoute(text);
        return;
      }

      // 多行粘贴：一次 onData 里带 \r 说明不是普通键入。整段原样透传，
      // 清空本地行，避免下一次回车用片段重放第一行。
      if (data.length > 1 && data.includes("\r")) {
        line = "";
        lineTrusted = false;
        lineUnsafe = false;
        heredocEnd = null;
        historyRecall = false;
        void writeSession(sessionId, encodeBase64(data));
        return;
      }

      // 其余按键全部原样交给远端：补全、历史、Ctrl-R、vim、密码提示都由 shell 处理。
      const isControl = /[\x00-\x1f]/.test(data);
      if (data === "\x7f") {
        line = Array.from(line).slice(0, -1).join("");
      } else if (data === "\x03" || data === CTRL_U) {
        line = "";
        lineTrusted = false;
        lineUnsafe = isUnsafeInputPrompt(outputTail);
        historyRecall = false;
        if (data === "\x03") heredocEnd = null;
      } else if (data.startsWith("\x1b")) {
        // 上下键召回 shell 历史；左右键等也会改写远端行，本地行缓冲不再可信。
        line = "";
        lineTrusted = false;
        if (data === "\x1b[A" || data === "\x1b[B" || data === "\x1bOA" || data === "\x1bOB") {
          historyRecall = true;
        }
        // 但仍保留提示符安全性判断：REPL/密码提示里不能因为按了方向键就恢复 AI。
        lineUnsafe = lineUnsafe || isUnsafeInputPrompt(outputTail);
      } else if (isControl) {
        // Tab 补全、Ctrl-W、Ctrl-R、Ctrl-A/E 等 readline 操作会改写远端行，
        // 本地行缓冲不再可信：清空，回车时直接走原生 \r。
        line = "";
        lineTrusted = false;
        historyRecall = false;
      } else {
        if (line.length === 0) {
          lineUnsafe = isUnsafeInputPrompt(outputTail);
        }
        line += data;
        if (line.length > 500) {
          line = line.slice(-500);
          lineTrusted = false;
        }
      }
      void writeSession(sessionId, encodeBase64(data));
    });

    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    const pendingListens = [
      listen<SessionDataEvent>("session:data", (event) => {
        if (event.payload.session_id !== sessionId) return;
        sawData = true;
        const bytes = decodeBase64(event.payload.data);
        let text = "";
        try {
          text = decoder.decode(bytes, { stream: true });
        } catch {
          text = "";
        }
        if (commandActive) {
          // 只留最近 32k 字符：服务端最终只取 80 行/8000 字符，
          // 但命令本身可能持续输出（yes/tail -f），不能无限积累。
          commandOutput = (commandOutput + text).slice(-32_000);
        }
        handleOsc(bytes);
        term.write(bytes);
        syncInteractive(term.buffer.active.type === "alternate");
        if (text) {
          outputTail = stripAnsi(outputTail + text).slice(-4000);
          reportUnsafePrompt();
        }
        if (commandActive && !interactivePromptReported) {
          const reason = taskInteractiveReason(outputTail);
          if (reason) reportInteractive(reason);
        }
        if (visibleRef.current) term.scrollToBottom();
      }),
      listen<SessionClosedEvent>("session:closed", (event) => {
        if (event.payload.session_id !== sessionId) return;
        const code = event.payload.exit_code;
        term.write(`\r\n\x1b[90m[session closed${code === null ? "" : ` · exit ${code}`}]\x1b[0m\r\n`);
        onExit(sessionId, code === null ? "会话已关闭" : `会话结束（exit ${code}）`);
      }),
      listen<SessionErrorEvent>("session:error", (event) => {
        if (event.payload.session_id !== sessionId) return;
        term.write(`\r\n\x1b[31m[error] ${event.payload.message}\x1b[0m\r\n`);
      })
    ];

    void Promise.all(pendingListens).then((fns) => {
      if (disposed) {
        fns.forEach((unlisten) => unlisten());
        return;
      }
      unlisteners.push(...fns);
      void sessionAttach(sessionId)
        .then((backlog) => {
          if (disposed) return;
          if (backlog) {
            sawData = true;
            const bytes = decodeBase64(backlog);
            let text = "";
            try {
              text = decoder.decode(bytes, { stream: true });
            } catch {
              text = "";
            }
            if (commandActive) {
              commandOutput = (commandOutput + text).slice(-32_000);
            }
            handleOsc(bytes);
            term.write(bytes);
            syncInteractive(term.buffer.active.type === "alternate");
            if (text) {
              outputTail = stripAnsi(outputTail + text).slice(-4000);
              reportUnsafePrompt();
            }
            term.scrollToBottom();
          }
          // 兜底：有些登录 shell（或提示符插件）在 attach 前后不重画首屏，
          // 导致必须手动回车。等布局稳定后如果当前行仍是空的，就让远端
          // 重新打印一次提示符；当前行已有内容（正常提示符）则不动。
          window.setTimeout(
            () => {
              if (disposed || userTyped) return;
              term.scrollToBottom();
              const buffer = term.buffer.active;
              const line =
                buffer.getLine(buffer.baseY + buffer.cursorY)?.translateToString(true) ?? "";
              if (line.trim().length === 0) {
                void resizeSession(sessionId, term.cols, term.rows).catch(() => undefined);
                void writeSession(sessionId, encodeBase64("\r")).catch(() => undefined);
              }
            },
            sawData ? 300 : 600
          );
          // 字体/布局稳定后再 fit 一次；某些环境下首次 fit 的列宽会偏，
          // 导致提示符换行或只显示一半。
          requestAnimationFrame(() => {
            if (disposed) return;
            fit.fit();
            term.refresh(0, Math.max(0, term.rows - 1));
            term.scrollToBottom();
            void resizeSession(sessionId, term.cols, term.rows).catch(() => undefined);
          });
        })
        .catch((err) => {
          if (disposed) return;
          term.write(
            `\r\n\x1b[31m[attach 失败] ${describeError(err)}；会话可能已结束，请关闭标签后重连\x1b[0m\r\n`
          );
        });
    });

    const pushSize = () => {
      if (!visibleRef.current || host.clientWidth === 0 || host.clientHeight === 0) return;
      fit.fit();
      void resizeSession(sessionId, term.cols, term.rows);
    };
    const observer = new ResizeObserver(() => pushSize());
    observer.observe(host);
    pushSize();

    return () => {
      disposed = true;
      observer.disconnect();
      input.dispose();
      unlisteners.forEach((unlisten) => unlisten());
      void sessionDetach(sessionId).catch(() => undefined);

      termRef.current = null;
      fitRef.current = null;
      term.dispose();
    };
  }, [sessionId, onExit]);

  useEffect(() => {
    visibleRef.current = visible;
    if (!visible) return;
    // 从 display:none 切回来时，等一帧再 fit，否则尺寸是 0。
    const frame = requestAnimationFrame(() => {
      const term = termRef.current;
      const fit = fitRef.current;
      if (!term || !fit) return;
      fit.fit();
      term.refresh(0, Math.max(0, term.rows - 1));
      void resizeSession(sessionId, term.cols, term.rows).catch(() => undefined);
    });
    const settle = window.setTimeout(() => {
      const term = termRef.current;
      const fit = fitRef.current;
      if (!term || !fit) return;
      fit.fit();
      term.refresh(0, Math.max(0, term.rows - 1));
      term.scrollToBottom();
      void resizeSession(sessionId, term.cols, term.rows).catch(() => undefined);
    }, 150);
    return () => {
      cancelAnimationFrame(frame);
      window.clearTimeout(settle);
    };
  }, [visible, sessionId]);

  useEffect(() => {
    if (!active || !visible) return;
    const frame = requestAnimationFrame(() => {
      termRef.current?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [active, visible]);

  return (
    <section className="terminal-pane" onMouseDown={() => onFocus?.()}>
      <div className="terminal-bar">
        <span />
        <span />
        <span />
        <button
          type="button"
          className={aiInput ? "ghost seg-toggle on" : "ghost seg-toggle"}
          onClick={() => {
            const next = !aiInputRef.current;
            setAiInput(next);
            aiInputRef.current = next;
          }}
          title={
            fullscreen
              ? "当前是全屏程序（tmux/vim/less），按键原样透传；退出后恢复 AI 识别"
              : "开启时中文走 AI；关闭后全部原样发送到远端（vim/REPL/密码输入建议关闭）"
          }
        >
          AI 识别：{aiInput ? (fullscreen ? "开（全屏原生）" : "开") : "关"}
        </button>
        <em>{title}</em>
        {onClose && (
          <button type="button" className="tab-close pane-close" title="关闭这个会话" onClick={onClose}>
            ×
          </button>
        )}
      </div>
      <div className="terminal-mount" ref={hostRef} />
    </section>
  );
}
