import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  closeSession,
  createHost,
  createTask,
  createTaskBatch,
  deleteHost,
  deleteHostPassword,
  deleteHostKeyAuth,
  describeError,
  draftCommand,
  draftTask,
  enableShellIntegration,
  encodeBase64,
  getAppInfo,
  hostCredentialsStatus,
  hostKeyAuthStatus,
  hostTrust,
  isTauri,
  isTerminalTaskStatus,
  listHosts,
  loadModelProvider,
  loadTaskHistorySettings,
  openSession,
  probeHost,
  runSelfCheck,
  saveHostKeyFile,
  saveBatchExport,
  saveHostPrivateKey,
  saveModelProvider,
  saveShortcuts,
  saveTaskHistorySettings,
  taskBatchListActive,
  taskBatchTasks,
  taskBatchUpdate,
  taskBindSession,
  taskCancel,
  taskGet,
  taskHistoryPrune,
  trustHost,
  updateHost,
  writeSession,
  type AppInfo,
  type Host,
  type HostKeyInfo,
  type HostKeyAuthStatus,
  type ProbeResult,
  type ProviderConfig,
  type SelfCheck,
  type ShortcutsConfig,
  type TaskHistorySettings
} from "./api";
import { AboutView } from "./AboutView";
import { HelpView } from "./HelpView";
import { HomeView } from "./HomeView";
import { SessionAuditPanel } from "./SessionAuditPanel";
import { SettingsView } from "./SettingsView";
import { TaskPanel } from "./TaskPanel";
import { BatchTaskPanel, type BatchState } from "./BatchTaskPanel";
import { TerminalPane } from "./TerminalPane";
import { useTaskRunner, type TaskCommandFinished } from "./useTaskRunner";
import { HostForm, EMPTY_HOST_FORM, type HostFormState } from "./HostForm";
import { ModelConfigForm } from "./ModelConfigForm";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";

const DEFAULT_SHORTCUTS: ShortcutsConfig = navigator.userAgent.includes("Mac")
  ? { copy: "Cmd+C", paste: "Cmd+V" }
  : { copy: "Ctrl+Shift+C", paste: "Ctrl+Shift+V" };

const DEFAULT_PROVIDER: ProviderConfig = {
  baseUrl: "https://api.openai.com/v1",
  model: "gpt-4o-mini",
  apiKey: "",
  hasKey: false
};

type AuthMode = "password" | "key-file" | "key-pem";

interface ActiveSession {
  id: string;
  hostId: string;
  title: string;
  label: string;
}

interface SessionAuth {
  username?: string;
  password?: string;
  keyPath?: string;
  keyPem?: string;
  passphrase?: string;
}

type View = "home" | "host" | "settings" | "help" | "about";

export default function App() {
  const tauri = isTauri();
  const [view, setView] = useState<View>("home");
  const [hostDetailOpen, setHostDetailOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem("shellwarden.sidebar") !== "0";
    } catch {
      return true;
    }
  });
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [check, setCheck] = useState<SelfCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState<HostFormState>(EMPTY_HOST_FORM);
  const addHostDetailsRef = useRef<HTMLDetailsElement | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>(() => {
    try {
      const parsed = JSON.parse(localStorage.getItem("shellwarden.hostGroups") ?? "{}");
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  });
  const [newSessionPicker, setNewSessionPicker] = useState(false);

  const [selected, setSelected] = useState<Host | null>(null);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [savedKey, setSavedKey] = useState<HostKeyInfo | null>(null);
  const [savedPassword, setSavedPassword] = useState(false);
  const [keyAuth, setKeyAuth] = useState<HostKeyAuthStatus | null>(null);
  const [probing, setProbing] = useState(false);

  const [authMode, setAuthMode] = useState<AuthMode>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [rememberKey, setRememberKey] = useState(true);
  const [keyPath, setKeyPath] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [passphrase, setPassphrase] = useState("");

  const [sessions, setSessions] = useState<Record<string, ActiveSession>>({});
  const [activeByHost, setActiveByHost] = useState<Record<string, string>>({});
  const [focusedSessionId, setFocusedSessionId] = useState<string | null>(null);
  const sessionsRef = useRef<Record<string, ActiveSession>>({});
  sessionsRef.current = sessions;
  const focusedRef = useRef<string | null>(null);
  focusedRef.current = focusedSessionId;
  const viewRef = useRef<View>("home");
  viewRef.current = view;
  const hostsRef = useRef<Host[]>([]);
  hostsRef.current = hosts;
  // 会话使用顺序（MRU），关闭当前标签时切到最近用过的存活会话。
  const recentRef = useRef<string[]>([]);
  const rememberSession = useCallback((sessionId: string) => {
    recentRef.current = [...recentRef.current.filter((id) => id !== sessionId), sessionId];
  }, []);
  // 本次运行内最近一次成功的连接参数，用于“同一主机再开一个会话”；
  // 只存在内存，不落盘。
  const lastAuth = useRef<Record<string, SessionAuth>>({});
  const [provider, setProvider] = useState<ProviderConfig>(DEFAULT_PROVIDER);
  const [editingHost, setEditingHost] = useState(false);
  const [editForm, setEditForm] = useState<HostFormState>(EMPTY_HOST_FORM);
  const [confirmState, setConfirmState] = useState<{
    message: string;
    action: () => void;
  } | null>(null);
  const [rememberModelKey, setRememberModelKey] = useState(true);
  const [modelSaving, setModelSaving] = useState(false);
  const [modelPromptOpen, setModelPromptOpen] = useState(false);
  const [shortcuts, setShortcuts] = useState<ShortcutsConfig>(DEFAULT_SHORTCUTS);
  const [taskHistorySettings, setTaskHistorySettings] = useState<TaskHistorySettings>({
    keep_days: 30,
    max_terminal: 200
  });
  const [taskHistorySaving, setTaskHistorySaving] = useState(false);
  const [taskPanelOpen, setTaskPanelOpen] = useState(false);
  const [batchPanelOpen, setBatchPanelOpen] = useState(false);
  const [batch, setBatch] = useState<BatchState | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);
  const batchRef = useRef<BatchState | null>(null);
  batchRef.current = batch;
  /** 批次自动推进每个任务只自动开启一次；用户手动关闭后不反复抢回。 */
  const batchAutoAttemptedRef = useRef<Set<string>>(new Set());
  // 是否观察到 OSC 133：决定任务面板提示“自动判断”还是“手动标记”。
  const [oscBySession, setOscBySession] = useState<Record<string, boolean>>({});
  // 全屏程序（vim/tmux/less）中禁止任务执行，避免按键写进程序。
  const [fullscreenBySession, setFullscreenBySession] = useState<Record<string, boolean>>({});
  const fullscreenRef = useRef<Record<string, boolean>>({});
  fullscreenRef.current = fullscreenBySession;
  const [unsafePromptBySession, setUnsafePromptBySession] = useState<Record<string, boolean>>({});
  const unsafePromptRef = useRef<Record<string, boolean>>({});
  unsafePromptRef.current = unsafePromptBySession;

  const hostSessions = selected
    ? Object.values(sessions).filter((item) => item.hostId === selected.id)
    : [];
  const session = selected
    ? hostSessions.find((item) => item.id === activeByHost[selected.id]) ?? hostSessions[0] ?? null
    : null;
  const activeSessionId =
    view === "host" && !hostDetailOpen
      ? focusedSessionId && sessions[focusedSessionId]
        ? focusedSessionId
        : session?.id ?? null
      : null;

  const groupedHosts = (() => {
    const groups = new Map<string, Host[]>();
    for (const host of hosts) {
      const group = host.group_name?.trim() || "未分组";
      const list = groups.get(group) ?? [];
      list.push(host);
      groups.set(group, list);
    }
    return [...groups.entries()].sort(([a], [b]) => {
      if (a === "未分组") return 1;
      if (b === "未分组") return -1;
      return a.localeCompare(b, "zh-CN");
    });
  })();

  const knownGroups = groupedHosts
    .map(([group]) => group)
    .filter((group) => group !== "未分组");
  const allTags = [...new Set(hosts.flatMap((host) => host.tags))].sort((a, b) =>
    a.localeCompare(b, "zh-CN")
  );
  const activeSession = activeSessionId ? sessions[activeSessionId] : null;
  // 主机详情页会隐藏终端（activeSessionId 为 null），任务仍绑定到该会话。
  const taskSessionId =
    focusedSessionId && sessions[focusedSessionId]
      ? focusedSessionId
      : session?.id ?? null;
  const taskRunner = useTaskRunner({
    hostId: selected?.id ?? null,
    sessionId: taskSessionId,
    provider,
    sendCommand: async (targetSessionId, command) => {
      // 复用 writeSession；任务步骤不自己拼 shell，只写当前 PTY。
      await writeSession(targetSessionId, encodeBase64(`\x15${command}\r`));
    },
    integrationEnabled: Boolean(taskSessionId && oscBySession[taskSessionId]),
    beforeSend: (targetSessionId) => {
      if (fullscreenRef.current[targetSessionId]) {
        return "终端当前在全屏程序（vim/tmux/less）中；请先退出，再执行任务步骤";
      }
      if (unsafePromptRef.current[targetSessionId]) {
        return "终端当前在密码/REPL/确认提示符；请先处理完，再执行任务步骤";
      }
      return null;
    },
    onModelRequired: () => setModelPromptOpen(true)
  });
  const taskRunnerRef = useRef(taskRunner);
  taskRunnerRef.current = taskRunner;
  const connectedHostIds = new Set(Object.values(sessions).map((item) => item.hostId));
  const sessionCount = (hostId: string) =>
    Object.values(sessions).filter((item) => item.hostId === hostId).length;
  const trustChanged = probe?.trust.state === "changed";
  const trusted = savedKey !== null && !trustChanged;

  const refresh = useCallback(async () => {
    if (!tauri) return;
    setError(null);
    try {
      const [nextInfo, nextHosts, nextCheck] = await Promise.all([
        getAppInfo(),
        listHosts(),
        runSelfCheck()
      ]);
      setInfo(nextInfo);
      setShortcuts({
        copy: nextInfo.shortcut_copy,
        paste: nextInfo.shortcut_paste
      });
      setHosts(nextHosts);
      setCheck(nextCheck);
      setSelected((current) =>
        current ? nextHosts.find((host) => host.id === current.id) ?? null : null
      );
    } catch (err) {
      setError(describeError(err));
    }
  }, [tauri]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    try {
      localStorage.setItem("shellwarden.sidebar", sidebarOpen ? "1" : "0");
    } catch {
      // localStorage 不可用时忽略
    }
  }, [sidebarOpen]);

  useEffect(() => {
    if (view !== "host") {
      const runningBatchAuto = Boolean(
        batchRef.current &&
          batchRef.current.status === "running" &&
          batchRef.current.autoRun
      );
      if (!runningBatchAuto) taskRunnerRef.current.setAutoRun(false);
      setTaskPanelOpen(false);
    }
  }, [view]);

  useEffect(() => {
    try {
      localStorage.setItem("shellwarden.hostGroups", JSON.stringify(collapsedGroups));
    } catch {
      // localStorage 不可用时忽略
    }
  }, [collapsedGroups]);

  useEffect(() => {
    if (!tauri) return;
    void loadModelProvider()
      .then((stored) => {
        setProvider((current) => ({
          ...current,
          baseUrl: stored.base_url,
          model: stored.model,
          hasKey: stored.has_key
        }));
      })
      .catch(() => undefined);
  }, [tauri]);

  useEffect(() => {
    if (!tauri) return;
    void loadTaskHistorySettings()
      .then(setTaskHistorySettings)
      .catch(() => undefined);
  }, [tauri]);

  useEffect(() => {
    if (!tauri) return;
    let cancelled = false;
    void taskHistoryPrune()
      .then((report) => {
        if (cancelled || report.deleted === 0) return;
        setNotice(
          `已按任务历史策略清理 ${report.deleted} 条终态任务（审计事件保留）`
        );
        void taskRunnerRef.current.refresh();
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [tauri]);

  const selectHost = useCallback((host: Host) => {
    setView("host");
    setHostDetailOpen(false);
    setSelected(host);
    const group = host.group_name?.trim() || "未分组";
    setCollapsedGroups((prev) => ({ ...prev, [group]: false }));
    const list = Object.values(sessionsRef.current).filter((item) => item.hostId === host.id);
    const target =
      list.find((item) => item.id === activeByHost[host.id]) ?? list[0] ?? null;
    setFocusedSessionId(target?.id ?? null);
    if (target) rememberSession(target.id);
    setProbe(null);
    setError(null);
    setNotice(null);
    setSavedKey(null);
    setSavedPassword(false);
    setKeyAuth(null);
    setUsername(host.default_username);
    setEditingHost(false);
    setEditForm({
      name: host.name,
      hostname: host.hostname,
      port: String(host.port),
      username: host.default_username,
      tags: host.tags.join(", "),
      groupName: host.group_name ?? "",
    });
    setPassword("");
    setKeyPem("");
    setPassphrase("");
    setAuthMode("password");
    void hostTrust(host.id)
      .then((key) => setSavedKey(key))
      .catch((err) => setError(describeError(err)));
    void hostCredentialsStatus(host.id)
      .then(setSavedPassword)
      .catch(() => undefined);
    void hostKeyAuthStatus(host.id)
      .then((auth) => {
        setKeyAuth(auth);
        if (auth.key_path) setKeyPath(auth.key_path);
      })
      .catch(() => undefined);
  }, [activeByHost, rememberSession]);

  async function handleAddHost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!tauri) return;
    setBusy(true);
    setError(null);
    try {
      await createHost({
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        port: Number(form.port) || 22,
        default_username: form.username.trim(),
        tags: form.tags
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
        ssh_backend: "auto",
        group_name: form.groupName.trim(),
      });
      setForm(EMPTY_HOST_FORM);
      addHostDetailsRef.current?.removeAttribute("open");
      setHosts(await listHosts());
      setInfo(await getAppInfo());
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(host: Host) {
    if (!tauri) return;
    setConfirmState({
      message: `删除主机「${host.name}」？\n\n会同时删除本机保存的该主机会话记录与凭据；审计事件保留，但删除后不可再从界面回看。`,
      action: () => {
        void performDelete(host);
      }
    });
  }

  async function performDelete(host: Host) {
    const targets = Object.values(sessions).filter((item) => item.hostId === host.id);
    for (const target of targets) {
      await closeSession(target.id).catch(() => undefined);
    }
    if (targets.length > 0) {
      setSessions((prev) => {
        const next = { ...prev };
        for (const [id, item] of Object.entries(next)) {
          if (item.hostId === host.id) delete next[id];
        }
        return next;
      });
      setActiveByHost((prev) => {
        const next = { ...prev };
        delete next[host.id];
        return next;
      });
      delete lastAuth.current[host.id];
    }
    setError(null);
    try {
      await deleteHost(host.id);
      if (selected?.id === host.id) setSelected(null);
      setHosts(await listHosts());
      setInfo(await getAppInfo());
    } catch (err) {
      setError(describeError(err));
      // 删除可能已在后端提交、但审计/关会话返回错误；刷新列表避免界面
      // 一直显示一个实际已不存在的主机。
      try {
        setHosts(await listHosts());
        if (selected?.id === host.id) setSelected(null);
      } catch {
        // 列表刷新失败时保留原错误。
      }
    }
  }

  async function handleProbe() {
    if (!tauri || !selected) return;
    setProbing(true);
    setError(null);
    setNotice(null);
    try {
      const result = await probeHost(selected.id);
      setProbe(result);
      if (result.trust.state === "trusted") setSavedKey(result.host_key);
      if (result.trust.state === "changed") setSavedKey(null);
    } catch (err) {
      setError(describeError(err));
      setProbe(null);
    } finally {
      setProbing(false);
    }
  }

  async function handleTrust() {
    if (!tauri || !selected || !probe) return;
    const run = async () => {
      setError(null);
      try {
        await trustHost(selected.id, probe.probe_id);
        setSavedKey(probe.host_key);
        setProbe((current) =>
          current ? { ...current, trust: { state: "trusted" } } : current
        );
        setNotice("已记录主机指纹，下次连接无需再探测");
      } catch (err) {
        setError(describeError(err));
      }
    };
    if (probe.trust.state === "changed") {
      setConfirmState({
        message: `主机指纹已变化！\n\n已记录：${probe.trust.known.algorithm} ${probe.trust.known.fingerprint}\n本次返回：${probe.host_key.algorithm} ${probe.host_key.fingerprint}\n\n确认主机被重装且没有中间人后，才覆盖信任。`,
        action: () => {
          void run();
        }
      });
      return;
    }
    await run();
  }

  const authPayload = {
    password: authMode === "password" && password ? password : undefined,
    keyPath: authMode === "key-file" && keyPath ? keyPath : undefined,
    keyPem: authMode === "key-pem" && keyPem ? keyPem : undefined,
    passphrase: authMode !== "password" && passphrase ? passphrase : undefined
  };

  async function handleSaveHost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!tauri || !selected) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await updateHost({
        id: selected.id,
        name: editForm.name.trim(),
        hostname: editForm.hostname.trim(),
        port: Number(editForm.port) || 22,
        default_username: editForm.username.trim(),
        tags: editForm.tags
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
        ssh_backend: selected.ssh_backend,
        group_name: editForm.groupName.trim(),
      });
      const addressChanged =
        selected.hostname !== updated.hostname || selected.port !== updated.port;
      setSelected(updated);
      setHosts(await listHosts());
      if (addressChanged) {
        // 地址变了，旧指纹/探测结果不再对应当前目标。
        setProbe(null);
        setSavedKey(null);
      }
      setEditingHost(false);
      setNotice("主机配置已更新");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleClearPassword() {
    if (!tauri || !selected) return;
    try {
      await deleteHostPassword(selected.id);
      delete lastAuth.current[selected.id];
      setSavedPassword(false);
      setPassword("");
      setNotice("已清除本机保存的密码；本次运行内缓存的凭据也已失效");
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleChooseKeyFile() {
    if (!tauri) return;
    setError(null);
    try {
      const selected = await openDialog({
        multiple: false,
        directory: false,
        title: "选择 SSH 私钥文件"
      });
      if (typeof selected === "string") setKeyPath(selected);
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleSaveKeyFile() {
    if (!tauri || !selected) return;
    setError(null);
    try {
      await saveHostKeyFile(selected.id, keyPath.trim(), passphrase || undefined);
      setKeyAuth(await hostKeyAuthStatus(selected.id));
      setNotice("已保存私钥路径与口令；下次连接会自动加载");
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleSavePrivateKey() {
    if (!tauri || !selected) return;
    setError(null);
    try {
      await saveHostPrivateKey(selected.id, keyPem, passphrase || undefined);
      setKeyAuth(await hostKeyAuthStatus(selected.id));
      setKeyPem("");
      setPassphrase("");
      setNotice("已保存私钥与口令；下次连接会自动加载");
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleClearPrivateKey() {
    if (!tauri || !selected) return;
    try {
      await deleteHostKeyAuth(selected.id);
      delete lastAuth.current[selected.id];
      setKeyAuth(null);
      setKeyPem("");
      setKeyPath("");
      setPassphrase("");
      setNotice("已清除本机保存的私钥凭据；下次连接需要重新提供");
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleSaveModel() {
    setModelSaving(true);
    setError(null);
    try {
      await saveModelProvider({
        base_url: provider.baseUrl,
        model: provider.model,
        api_key: provider.apiKey || undefined,
        remember_key: rememberModelKey
      });
      const stored = await loadModelProvider();
      setProvider({
        baseUrl: stored.base_url,
        model: stored.model,
        // 不保存到磁盘时，密钥仍留在内存里供本次运行使用，不能清空。
        apiKey: rememberModelKey ? "" : provider.apiKey,
        hasKey: stored.has_key
      });
      setNotice(stored.has_key ? "模型配置已保存（密钥加密存储）" : "模型配置已保存，密钥只在本次运行有效");
      setModelPromptOpen(false);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setModelSaving(false);
    }
  }

  async function handleSaveShortcuts() {
    setError(null);
    try {
      await saveShortcuts(shortcuts.copy, shortcuts.paste);
      const next = await getAppInfo();
      setInfo(next);
      setShortcuts({
        copy: next.shortcut_copy,
        paste: next.shortcut_paste
      });
      setNotice("快捷键已保存；新终端会话生效");
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleSaveTaskHistory() {
    setTaskHistorySaving(true);
    setError(null);
    try {
      const stored = await saveTaskHistorySettings(
        taskHistorySettings.keep_days,
        taskHistorySettings.max_terminal
      );
      setTaskHistorySettings(stored);
      setNotice("任务历史策略已保存；下次启动或手动清理时生效");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setTaskHistorySaving(false);
    }
  }

  async function handleClearModelKey() {
    setError(null);
    try {
      await saveModelProvider({
        base_url: provider.baseUrl,
        model: provider.model,
        remember_key: false
      });
      setProvider({ ...provider, apiKey: "", hasKey: false });
      setNotice("已清除保存的模型密钥");
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function openHostSession(
    host: Host,
    auth: SessionAuth,
    usernameOverride: string,
    rememberPassword: boolean,
    rememberPrivateKey: boolean
  ): Promise<string | null> {
    if (!tauri) return null;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await openSession({
        host_id: host.id,
        username: usernameOverride.trim() || undefined,
        password: auth.password,
        key_path: auth.keyPath,
        key_pem: auth.keyPem,
        passphrase: auth.passphrase,
        remember_password: rememberPassword,
        remember_key: rememberPrivateKey,
        cols: 120,
        rows: 32
      });
      lastAuth.current[host.id] = {
        ...auth,
        username: usernameOverride.trim() || host.default_username
      };
      setSessions((prev) => {
        const existing = Object.values(prev).filter((item) => item.hostId === host.id);
        let index = existing.length + 1;
        let label = index === 1 ? host.name : `${host.name} #${index}`;
        while (existing.some((item) => item.label === label)) {
          index += 1;
          label = `${host.name} #${index}`;
        }
        return {
          ...prev,
          [result.session_id]: {
            id: result.session_id,
            hostId: host.id,
            title: `${host.name} · ${host.hostname}`,
            label
          }
        };
      });
      setActiveByHost((prev) => ({ ...prev, [host.id]: result.session_id }));
      setFocusedSessionId(result.session_id);
      rememberSession(result.session_id);
      setHostDetailOpen(false);
      setView("host");
      return result.session_id;
    } catch (err) {
      setError(describeError(err));
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function handleConnect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const ok = await openHostSession(
      selected,
      authPayload,
      username,
      authMode === "password" && Boolean(authPayload.password) && remember,
      authMode !== "password" &&
        Boolean(authPayload.keyPem || authPayload.keyPath) &&
        rememberKey
    );
    if (!ok) return;
    setPassword("");
    setKeyPem("");
    setPassphrase("");
    if (authMode === "password" && remember && password) setSavedPassword(true);
    if (authMode !== "password" && rememberKey && (keyPem || keyPath)) {
      setKeyAuth(await hostKeyAuthStatus(selected.id).catch(() => null));
    }
  }

  async function handleNewSession(host: Host) {
    if (!tauri) return;
    const auth = lastAuth.current[host.id] ?? {};
    const [hasPassword, hasPrivateKey] = await Promise.all([
      hostCredentialsStatus(host.id).catch(() => false),
      hostKeyAuthStatus(host.id)
        .then((auth) => Boolean(auth.mode || auth.has_private_key))
        .catch(() => false)
    ]);
    const reusable = Boolean(
      auth.password || auth.keyPath || auth.keyPem || hasPassword || hasPrivateKey
    );
    if (!reusable) {
      selectHost(host);
      setHostDetailOpen(true);
      setNotice("没有可复用的凭据，请在主机详情里填写一次连接信息。");
      return;
    }
    await openHostSession(host, auth, auth.username ?? "", false, false);
  }

  async function handleCloseSession(sessionId: string, ask = true) {
    const label = sessionsRef.current[sessionId]?.label ?? sessionId;
    const run = async () => {
      try {
        await closeSession(sessionId);
      } catch (err) {
        const text = describeError(err);
        // 会话已经结束是幂等的；其他错误保留 UI 并提示，避免连接/进程残留却看不见。
        if (!text.includes("ssh.session.not_found")) {
          setError(text);
          return;
        }
      }
      afterSessionRemoved(sessionId, false);
    };
    if (ask) {
      setConfirmState({
        message: `关闭会话「${label}」？远端进程可能继续运行。`,
        action: () => {
          void run();
        }
      });
      return;
    }
    await run();
  }

  async function handleDisconnect(host: Host) {
    const target =
      Object.values(sessions).find(
        (item) => item.hostId === host.id && item.id === activeByHost[host.id]
      ) ?? Object.values(sessions).find((item) => item.hostId === host.id);
    if (!target) return;
    await handleCloseSession(target.id, false);
    setNotice("已断开会话");
  }

  function afterSessionRemoved(sessionId: string, fromRemote: boolean) {
    const closed = sessionsRef.current[sessionId];
    if (!closed) return;
    const remaining = Object.values(sessionsRef.current).filter(
      (item) => item.id !== sessionId
    );

    setSessions((prev) => {
      const next = { ...prev };
      delete next[sessionId];
      return next;
    });
    setActiveByHost((prev) => {
      const next = { ...prev };
      for (const [hostId, id] of Object.entries(next)) {
        if (id === sessionId) delete next[hostId];
      }
      return next;
    });

    if (focusedRef.current !== sessionId) return;

    if (remaining.length > 0) {
      const ordered = recentRef.current.filter((id) =>
        remaining.some((item) => item.id === id)
      );
      const next =
        remaining.find((item) => item.id === ordered[ordered.length - 1]) ??
        remaining[remaining.length - 1];
      setFocusedSessionId(next.id);
      setActiveByHost((prev) => ({ ...prev, [next.hostId]: next.id }));
      setSelected(hostsRef.current.find((host) => host.id === next.hostId) ?? null);
      if (!fromRemote || viewRef.current === "host") setView("host");
    } else {
      setFocusedSessionId(null);
      setSelected(null);
      if (!fromRemote || viewRef.current === "host") setView("home");
    }
  }

  const handleExit = useCallback((sessionId: string, message: string) => {
    afterSessionRemoved(sessionId, true);
    setNotice(message);
    // afterSessionRemoved 只读 refs，回调保持稳定，避免 xterm 重建。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleDraftCommand = useCallback(
    async (text: string) => {
      if (!selected) throw new Error("未选择主机");
      return draftCommand({
        host_id: selected.id,
        request: text,
        base_url: provider.baseUrl,
        model: provider.model,
        api_key: provider.apiKey
      });
    },
    [selected, provider]
  );

  const handleTaskCommandFinished = useCallback((event: TaskCommandFinished) => {
    taskRunnerRef.current.handleCommandFinished(event);
  }, []);

  const handleTaskInteractive = useCallback((sessionId: string, reason: string) => {
    taskRunnerRef.current.handleInteractive(sessionId, reason);
  }, []);

  const handleShellIntegration = useCallback((sessionId: string) => {
    setOscBySession((prev) =>
      prev[sessionId] ? prev : { ...prev, [sessionId]: true }
    );
  }, []);

  const handleTaskRequest = useCallback((text: string) => {
    setTaskPanelOpen(true);
    void taskRunnerRef.current.createFromGoal(text);
  }, []);

  useEffect(() => {
    if (!tauri) return;
    let cancelled = false;
    void (async () => {
      try {
        const active = (await taskBatchListActive(1))[0];
        if (!active || cancelled || batchRef.current) return;
        const tasks = await taskBatchTasks(active.id);
        const taskIds: Record<string, string> = {};
        const statuses: Record<string, string> = {};
        for (const task of tasks) {
          taskIds[task.host_id] = task.id;
          statuses[task.host_id] = task.status;
        }
        if (cancelled) return;
        setBatch({
          id: active.id,
          goal: active.goal_redacted,
          hostIds: active.host_ids,
          taskIds,
          statuses,
          index: active.current_index,
          status: active.status === "running" ? "paused" : active.status,
          autoRun: false
        });
        setBatchPanelOpen(true);
        setNotice("已恢复上次未完成的批量任务；确认会话后继续。");
      } catch {
        // 没有批次或旧库尚不支持时静默；不影响正常使用。
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tauri]);

  async function handleStartBatch(goal: string, hostIds: string[], autoRun: boolean) {
    setBatchBusy(true);
    setBatchError(null);
    let createdBatchId: string | null = null;
    const createdTaskIds: string[] = [];
    try {
      const targets = hosts.filter((host) => hostIds.includes(host.id));
      if (targets.length === 0) throw new Error("没有选择主机");
      const sessionByHost = new Map<string, string>();
      // 自动打开缺失会话；只使用已保存凭据，缺凭据时明确暂停。
      for (const host of targets) {
        const existing = Object.values(sessions).find((item) => item.hostId === host.id);
        const sessionId =
          existing?.id ??
          (await openHostSession(host, {}, host.default_username, false, false));
        if (!sessionId) {
          throw new Error(
            `${host.name} 无法自动连接；请先连接一次并保存密码/私钥，再创建批次`
          );
        }
        sessionByHost.set(host.id, sessionId);
      }
      const firstDraft = await draftTask({
        host_id: targets[0].id,
        request: goal,
        base_url: provider.baseUrl,
        model: provider.model,
        api_key: provider.apiKey,
        timeout_secs: 60
      });
      const batchRecord = await createTaskBatch({
        goal,
        title: firstDraft.title,
        host_ids: targets.map((host) => host.id)
      });
      createdBatchId = batchRecord.id;
      const taskIds: Record<string, string> = {};
      const statuses: Record<string, string> = {};
      for (const [index, host] of targets.entries()) {
        const draft =
          index === 0
            ? firstDraft
            : await draftTask({
                host_id: host.id,
                request: goal,
                base_url: provider.baseUrl,
                model: provider.model,
                api_key: provider.apiKey,
                timeout_secs: 60
              });
        const task = await createTask({
          host_id: host.id,
          session_id: sessionByHost.get(host.id),
          batch_id: batchRecord.id,
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
        taskIds[host.id] = task.id;
        statuses[host.id] = task.status;
        createdTaskIds.push(task.id);
      }
      setBatch({
        id: batchRecord.id,
        goal,
        hostIds: targets.map((host) => host.id),
        taskIds,
        statuses,
        index: 0,
        status: "running",
        autoRun
      });
      void taskBatchUpdate(batchRecord.id, "running", 0);
      setBatchPanelOpen(false);
      setTaskPanelOpen(true);
      selectHost(targets[0]);
      const firstSession = sessionByHost.get(targets[0].id);
      if (firstSession) {
        setActiveByHost((prev) => ({ ...prev, [targets[0].id]: firstSession }));
        setFocusedSessionId(firstSession);
        rememberSession(firstSession);
      }
      setNotice(`已创建批量任务：${targets.length} 台主机，逐台串行执行`);
    } catch (err) {
      for (const taskId of createdTaskIds) {
        void taskCancel(taskId).catch(() => undefined);
      }
      if (createdBatchId) {
        void taskBatchUpdate(createdBatchId, "cancelled", 0);
      }
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as { code?: string }).code
          : undefined;
      if (code === "model.config_invalid") setModelPromptOpen(true);
      setBatchError(describeError(err));
    } finally {
      setBatchBusy(false);
    }
  }

  async function selectBatchHost(index: number): Promise<boolean> {
    if (!batch) return false;
    const hostId = batch.hostIds[index];
    const host = hosts.find((item) => item.id === hostId);
    if (!host) {
      setBatchError("批次主机已不存在，批次已暂停");
      setBatch((current) =>
        current ? { ...current, index, status: "paused" } : current
      );
      void taskBatchUpdate(batch.id, "paused", index);
      setBatchPanelOpen(true);
      return false;
    }
    let targetSessionId = Object.values(sessions).find((item) => item.hostId === hostId)?.id;
    if (!targetSessionId) {
      // 刷新/重启后会话通常已丢失；继续时尝试用已保存凭据自动恢复。
      targetSessionId =
        (await openHostSession(host, {}, host.default_username, false, false)) ?? undefined;
      if (!targetSessionId) {
        setBatchError(`${host.name} 无法自动连接；请先手动连接并保存凭据`);
        setBatch((current) =>
          current ? { ...current, index, status: "paused" } : current
        );
        void taskBatchUpdate(batch.id, "paused", index);
        setBatchPanelOpen(true);
        return false;
      }
    }
    const batchTaskId = batch.taskIds[hostId];
    if (batchTaskId) {
      try {
        const detail = await taskGet(batchTaskId);
        if (!detail) {
          setBatchError("批次任务不存在或已被删除；批次已暂停");
          setBatch((current) =>
            current ? { ...current, index, status: "paused" } : current
          );
          void taskBatchUpdate(batch.id, "paused", index);
          setBatchPanelOpen(true);
          return false;
        }
        if (
          !isTerminalTaskStatus(detail.status) &&
          detail.session_id !== targetSessionId
        ) {
          // 恢复后旧 session_id 已失效；先绑定到新会话，后续 start_step 的会话校验才通过。
          await taskBindSession(batchTaskId, targetSessionId!, host.id);
        }
      } catch (err) {
        setBatchError(`无法恢复批次任务：${describeError(err)}`);
        setBatch((current) =>
          current ? { ...current, index, status: "paused" } : current
        );
        void taskBatchUpdate(batch.id, "paused", index);
        setBatchPanelOpen(true);
        return false;
      }
    }
    setActiveByHost((prev) => ({ ...prev, [host.id]: targetSessionId! }));
    setFocusedSessionId(targetSessionId!);
    rememberSession(targetSessionId!);
    selectHost(host);
    setTaskPanelOpen(true);
    if (batchTaskId) {
      void taskRunnerRef.current.loadTask(batchTaskId);
    }
    return true;
  }

  async function handleBatchResume() {
    if (!batch) return;
    const next = batch.index + 1;
    if (next >= batch.hostIds.length) {
      setBatch({ ...batch, status: "done" });
      void taskBatchUpdate(batch.id, "done", batch.index);
      setBatchPanelOpen(true);
      return;
    }
    setBatch({ ...batch, index: next, status: "running" });
    void taskBatchUpdate(batch.id, "running", next);
    void selectBatchHost(next);
  }

  async function handleBatchContinueCurrent() {
    if (!batch) return;
    const currentTaskId = batch.taskIds[batch.hostIds[batch.index]];
    if (currentTaskId) batchAutoAttemptedRef.current.delete(currentTaskId);
    setBatch({ ...batch, status: "running" });
    void taskBatchUpdate(batch.id, "running", batch.index);
    await selectBatchHost(batch.index);
  }

  function handleBatchAutoToggle(enabled: boolean) {
    setBatch((current) => (current ? { ...current, autoRun: enabled } : current));
    if (!enabled) {
      taskRunnerRef.current.setAutoRun(false);
      return;
    }
    const current = batchRef.current;
    if (current) {
      const currentTaskId = current.taskIds[current.hostIds[current.index]];
      if (currentTaskId) batchAutoAttemptedRef.current.delete(currentTaskId);
    }
  }

  async function handleExportBatch() {
    if (!batch) return;
    try {
      const selected = await saveDialog({
        defaultPath: `shellwarden-batch-${batch.id}.md`,
        filters: [{ name: "Markdown", extensions: ["md"] }]
      });
      if (!selected) return;
      const target = /\.[a-z0-9]+$/i.test(selected) ? selected : `${selected}.md`;
      await saveBatchExport(batch.id, target);
      setNotice(`批次汇总已导出：${target}`);
    } catch (err) {
      setError(describeError(err));
    }
  }

  function handleBatchNew() {
    setBatch(null);
    setBatchError(null);
  }

  function handleBatchStop() {
    if (batch) {
      void taskRunnerRef.current.cancel();
      for (const taskId of Object.values(batch.taskIds)) {
        void taskCancel(taskId).catch(() => undefined);
      }
      void taskBatchUpdate(batch.id, "cancelled", batch.index);
    }
    setBatch(null);
    setBatchError(null);
    setBatchPanelOpen(false);
    setNotice("批量任务已停止");
  }

  useEffect(() => {
    if (!batch || !taskRunner.task) return;
    const taskId = taskRunner.task.id;
    const status = taskRunner.task.status;
    setBatch((current) => {
      if (!current) return current;
      const hostId = current.hostIds[current.index];
      if (current.taskIds[hostId] !== taskId) return current;
      if (current.statuses[hostId] === status) return current;
      return {
        ...current,
        statuses: { ...current.statuses, [hostId]: status }
      };
    });
    // 这里只同步当前主机的任务状态，不触发步骤执行。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskRunner.task?.id, taskRunner.task?.status]);

  // 批次级自动推进：每台任务加载后自动开启一次，只自动执行 R0/R1。
  useEffect(() => {
    if (!batch || batch.status !== "running" || !batch.autoRun) return;
    if (view !== "host") return;
    const task = taskRunner.task;
    if (!task) return;
    const expectedTaskId = batch.taskIds[batch.hostIds[batch.index]];
    if (task.id !== expectedTaskId) return;
    if (isTerminalTaskStatus(task.status) || task.status === "paused_interactive") return;
    const sessionId = task.session_id ?? taskSessionId;
    if (!sessionId || !oscBySession[sessionId]) return;
    if (fullscreenBySession[sessionId] || unsafePromptBySession[sessionId]) return;
    if (batchAutoAttemptedRef.current.has(task.id)) return;
    batchAutoAttemptedRef.current.add(task.id);
    taskRunner.setAutoRun(true);
  }, [
    batch,
    view,
    taskSessionId,
    oscBySession,
    fullscreenBySession,
    unsafePromptBySession,
    taskRunner.task,
    taskRunner.setAutoRun
  ]);

  useEffect(() => {
    if (!batch || batch.status !== "running" || !taskRunner.task) return;
    const expectedTaskId = batch.taskIds[batch.hostIds[batch.index]];
    if (taskRunner.task.id !== expectedTaskId) return;
    if (!isTerminalTaskStatus(taskRunner.task.status)) return;
    if (
      taskRunner.task.status === "failed" ||
      taskRunner.task.status === "cancelled"
    ) {
      setBatch({
        ...batch,
        status: "paused",
        statuses: { ...batch.statuses, [batch.hostIds[batch.index]]: taskRunner.task.status }
      });
      void taskBatchUpdate(batch.id, "paused", batch.index);
      setBatchPanelOpen(true);
      return;
    }
    const next = batch.index + 1;
    if (next >= batch.hostIds.length) {
      setBatch({ ...batch, status: "done" });
      void taskBatchUpdate(batch.id, "done", batch.index);
      setBatchPanelOpen(true);
      setNotice("批量任务已完成");
      return;
    }
    setBatch({
      ...batch,
      index: next,
      statuses: { ...batch.statuses, [batch.hostIds[batch.index]]: taskRunner.task.status }
    });
    void taskBatchUpdate(batch.id, "running", next);
    setBatchPanelOpen(false);
    void selectBatchHost(next);
    // selectBatchHost uses latest hosts/sessions through the current render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch, taskRunner.task?.id, taskRunner.task?.status, hosts, sessions]);

  const handleTerminalInteractiveState = useCallback(
    (sessionId: string, interactive: boolean) => {
      // 同步更新 ref：beforeSend 在下一次渲染前就要读到最新状态。
      fullscreenRef.current = { ...fullscreenRef.current, [sessionId]: interactive };
      setFullscreenBySession((prev) =>
        prev[sessionId] === interactive ? prev : { ...prev, [sessionId]: interactive }
      );
    },
    []
  );

  const handleUnsafePrompt = useCallback(
    (sessionId: string, unsafe: boolean) => {
      unsafePromptRef.current = { ...unsafePromptRef.current, [sessionId]: unsafe };
      setUnsafePromptBySession((prev) =>
        prev[sessionId] === unsafe ? prev : { ...prev, [sessionId]: unsafe }
      );
    },
    []
  );

  async function handleEnableTaskIntegration() {
    if (!taskSessionId) return;
    if (fullscreenRef.current[taskSessionId] || unsafePromptRef.current[taskSessionId]) {
      setError("终端在全屏程序或密码/REPL 提示符中；先处理完，再启用命令审计");
      return;
    }
    if (
      taskRunnerRef.current.pendingStepId ||
      taskRunnerRef.current.task?.steps.some((step) => step.status === "running")
    ) {
      setError("任务步骤正在执行；先等待完成或取消，再启用命令审计");
      return;
    }
    try {
      await enableShellIntegration(taskSessionId);
      setNotice(
        "已发送 bash/zsh 命令审计脚本；收到 OSC 事件前，任务步骤仍需要手动标记结果"
      );
    } catch (err) {
      setError(describeError(err));
    }
  }

  const focusSession = useCallback(
    (item: ActiveSession) => {
      rememberSession(item.id);
      // 只有真的切换主机时才重载 host-scoped 状态；同一主机内点击终端
      // 不应清掉用户正在填的连接表单。
      if (selected?.id !== item.hostId) {
        const host = hosts.find((candidate) => candidate.id === item.hostId);
        if (host) selectHost(host);
      }
      setHostDetailOpen(false);
      setFocusedSessionId(item.id);
      setActiveByHost((prev) => ({ ...prev, [item.hostId]: item.id }));
    },
    [hosts, rememberSession, selectHost, selected?.id]
  );

  return (
    <div className={sidebarOpen ? "app" : "app sidebar-collapsed"}>
      <aside className={sidebarOpen ? "sidebar" : "sidebar hidden"}>
        <div className="brand">
          <span className="brand-mark">◆</span>
          <div>
            <h1>ShellWarden</h1>
            <p>本地优先 · 命令确认</p>
          </div>
          <button
            type="button"
            className="ghost collapse-btn"
            title="收起侧栏"
            onClick={() => setSidebarOpen(false)}
          >
            ‹
          </button>
        </div>

        <section className="panel hosts">
          <h2>
            主机 <span className="count">{hosts.length}</span>
          </h2>
          {hosts.length === 0 ? (
            <p className="empty">还没有主机。先加一台，再探测指纹。</p>
          ) : (
            <div className="host-groups">
              {groupedHosts.map(([group, hostsInGroup]) => {
                const collapsed = collapsedGroups[group] ?? true;
                return (
                  <section className="host-group" key={group}>
                    <button
                      type="button"
                      className="host-group-title"
                      onClick={() =>
                        setCollapsedGroups((prev) => ({
                          ...prev,
                          [group]: !prev[group]
                        }))
                      }
                    >
                      <span>
                        {collapsed ? "▸" : "▾"} {group}
                      </span>
                      <span className="count">{hostsInGroup.length}</span>
                    </button>
                    {!collapsed && (
                      <ul>
                        {hostsInGroup.map((host) => (
                          <li
                            key={host.id}
                            className={selected?.id === host.id ? "active" : undefined}
                            onClick={() => selectHost(host)}
                          >
                            <div className="host-main">
                              <strong>
                                {sessionCount(host.id) > 0 && (
                                  <>
                                    <i className="online-dot" />
                                    {sessionCount(host.id) > 1 && (
                                      <span className="online-count">
                                        {sessionCount(host.id)}
                                      </span>
                                    )}
                                  </>
                                )}
                                {host.name}
                              </strong>
                              <span>
                                {host.default_username ? `${host.default_username}@` : ""}
                                {host.hostname}:{host.port}
                              </span>
                              {host.tags.length > 0 && (
                                <div className="tags">
                                  {host.tags.map((tag) => (
                                    <em key={tag}>{tag}</em>
                                  ))}
                                </div>
                              )}
                            </div>
                            <button
                              type="button"
                              className="ghost"
                              onClick={(event) => {
                                event.stopPropagation();
                                void handleDelete(host);
                              }}
                              aria-label={`删除 ${host.name}`}
                            >
                              删除
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                );
              })}
            </div>
          )}
        </section>

        <details className="panel" ref={addHostDetailsRef}>
          <summary>添加主机</summary>
          <HostForm
            mode="add"
            value={form}
            onChange={setForm}
            onSubmit={handleAddHost}
            saving={busy}
            disabled={!tauri}
            groups={knownGroups}
            tags={allTags}
          />
        </details>

        <nav className="side-nav">
          {(
            [
              ["home", "工作台"],
              ["settings", "设置"],
              ["help", "帮助"],
              ["about", "关于"]
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={view === key ? "ghost active" : "ghost"}
              onClick={() => setView(key)}
            >
              {label}
            </button>
          ))}
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          {!sidebarOpen && (
            <button
              type="button"
              className="ghost menu-toggle"
              title="展开侧栏"
              onClick={() => setSidebarOpen(true)}
            >
              ☰
            </button>
          )}
          <div>
            <h2>
              {view === "settings"
                ? "设置"
                : view === "help"
                  ? "帮助与诊断"
                  : view === "about"
                    ? "关于"
                      : view === "host" && activeSession
                        ? activeSession.title
                        : view === "host" && selected
                          ? selected.name
                          : "工作台"}
            </h2>
            <p>
              {view === "settings"
                ? "模型与输入路由"
                : view === "help"
                  ? "自检、快捷键与安全边界"
                  : view === "about"
                    ? "版本、数据与隐私"
                        : view === "host" && activeSession
                        ? "PTY 已连接。输入命令直接执行；中文先显示 AI 命令，回车确认。"
                        : view === "host" && selected
                          ? "已信任指纹的主机无需重新探测；密码加密保存在本地。"
                          : "选择左侧主机开始，或先完成模型设置。"}
            </p>
          </div>
          <div className="actions">
            {view === "host" && selected && session && (
              <button
                type="button"
                className="secondary"
                onClick={() => setHostDetailOpen((open) => !open)}
              >
                {hostDetailOpen ? "返回终端" : "主机详情"}
              </button>
            )}
            {view === "host" && taskSessionId && (
              <button
                type="button"
                className={taskPanelOpen ? "secondary active" : "secondary"}
                onClick={() => setTaskPanelOpen((open) => !open)}
              >
                任务
                {taskRunner.task
                  ? ` · ${
                      taskRunner.task.steps.filter((step) =>
                        ["succeeded", "manual", "skipped"].includes(step.status)
                      ).length
                    }/${taskRunner.task.steps.length}`
                  : ""}
              </button>
            )}
            {view === "host" && hosts.length > 0 && (
              <button
                type="button"
                className="secondary"
                onClick={() => setBatchPanelOpen(true)}
              >
                批量任务
                {batch ? ` · ${batch.index + 1}/${batch.hostIds.length}` : ""}
              </button>
            )}
            {view === "host" && activeSession && selected && (
              <button
                type="button"
                className="secondary"
                onClick={() => void handleDisconnect(selected)}
              >
                断开当前会话
              </button>
            )}
            {view === "host" && selected && !session && (
              <button
                type="button"
                className="secondary"
                onClick={() => void handleProbe()}
                disabled={probing}
              >
                {probing ? "探测中…" : "重新探测指纹"}
              </button>
            )}
          </div>
        </header>

        {!tauri && (
          <div className="notice">
            当前在浏览器中预览。请用 <code>npm run tauri dev</code> 启动桌面应用。
          </div>
        )}
        {notice && <div className="notice">{notice}</div>}
        {error && <div className="error">{error}</div>}

        {view === "host" && Boolean(activeSessionId) && Object.values(sessions).length > 0 && (
          <div className="session-tabs">
            {Object.values(sessions).map((item) => (
              <div
                key={item.id}
                className={activeSessionId === item.id ? "session-tab active" : "session-tab"}
              >
                <button
                  type="button"
                  className="tab-label"
                  onClick={() => focusSession(item)}
                >
                  {item.label}
                </button>
                <button
                  type="button"
                  className="tab-close"
                  title="关闭这个会话"
                  onClick={() => void handleCloseSession(item.id)}
                >
                  ×
                </button>
              </div>
            ))}
            {hosts.length > 0 && (
              <button
                type="button"
                className="session-tab add"
                title="选择主机登录"
                onClick={() => setNewSessionPicker(true)}
              >
                ＋
              </button>
            )}
          </div>
        )}

        {Object.values(sessions).map((item) => {
          const visible = view === "host" && activeSessionId === item.id;
          return (
            <div
              key={item.id}
              className="session-slot"
              style={{ display: visible ? "flex" : "none" }}
            >
              <TerminalPane
                sessionId={item.id}
                title={item.label}
                visible={visible}
                active={visible}
                onFocus={() => focusSession(item)}
                onClose={() => void handleCloseSession(item.id)}
                onExit={handleExit}
                onCommand={handleDraftCommand}
                onModelRequired={() => setModelPromptOpen(true)}
                shortcuts={shortcuts}
                onCommandFinished={handleTaskCommandFinished}
                onInteractivePrompt={handleTaskInteractive}
                onShellIntegration={handleShellIntegration}
                onInteractiveState={handleTerminalInteractiveState}
                onTaskRequest={handleTaskRequest}
                onUnsafePrompt={handleUnsafePrompt}
              />
            </div>
          );
        })}

        {activeSessionId ? null : view === "settings" ? (
          <SettingsView
            provider={provider}
            onProviderChange={setProvider}
            rememberKey={rememberModelKey}
            onRememberKeyChange={setRememberModelKey}
            saving={modelSaving}
            onSave={() => void handleSaveModel()}
            onClearKey={() => void handleClearModelKey()}
            shortcuts={shortcuts}
            onShortcutsChange={setShortcuts}
            onSaveShortcuts={() => void handleSaveShortcuts()}
            taskHistory={taskHistorySettings}
            onTaskHistoryChange={setTaskHistorySettings}
            taskHistorySaving={taskHistorySaving}
            onSaveTaskHistory={() => void handleSaveTaskHistory()}
          />
        ) : view === "help" ? (
          <HelpView check={check} onRefresh={() => void refresh()} />
        ) : view === "about" ? (
          <AboutView info={info} />
        ) : view === "host" && selected ? (
          <section className="host-detail">
            <article className="card">
              <h3>
                主机信息
                {!editingHost && (
                  <button type="button" className="ghost" onClick={() => setEditingHost(true)}>
                    编辑
                  </button>
                )}
              </h3>
              {editingHost ? (
                <HostForm
                  mode="edit"
                  value={editForm}
                  onChange={setEditForm}
                  onSubmit={handleSaveHost}
                  saving={busy}
                  groups={knownGroups}
                  tags={allTags}
                  onCancel={() => setEditingHost(false)}
                />
              ) : (
                <dl>
                  <div>
                    <dt>地址</dt>
                    <dd>
                      {selected.hostname}:{selected.port}
                    </dd>
                  </div>
                  <div>
                    <dt>默认用户</dt>
                    <dd>{selected.default_username || "—"}</dd>
                  </div>
                  <div>
                    <dt>后端</dt>
                    <dd>{selected.ssh_backend}</dd>
                  </div>
                  <div>
                    <dt>目录</dt>
                    <dd>{selected.group_name?.trim() || "未分组"}</dd>
                  </div>
                </dl>
              )}
            </article>

            <article className="card wide">
              <h3>
                主机指纹
                <span className={trusted ? "badge ok" : trustChanged ? "badge bad" : "badge"}>
                  {trusted ? "已信任" : trustChanged ? "指纹变化" : "未信任"}
                </span>
              </h3>
              {savedKey && !probe ? (
                <>
                  <code className="fingerprint">
                    {savedKey.algorithm} {savedKey.fingerprint}
                  </code>
                  <p className="muted small">来自本机已知主机记录，连接时无需重新探测。</p>
                </>
              ) : !probe ? (
                <p className="muted">点「重新探测指纹」获取服务端公钥（探测不会发送任何凭证）。</p>
              ) : (
                <>
                  <code className="fingerprint">
                    {probe.host_key.algorithm} {probe.host_key.fingerprint}
                  </code>
                  {probe.trust.state === "changed" && (
                    <p className="danger-text">
                      已记录：{probe.trust.known.algorithm} {probe.trust.known.fingerprint}
                      <br />
                      本次返回的指纹与记录不一致，请先确认主机是否被重装或存在中间人。
                    </p>
                  )}
                  {probe.trust.state !== "trusted" && (
                    <button type="button" onClick={() => void handleTrust()}>
                      {probe.trust.state === "changed" ? "确认无误，覆盖信任" : "信任该指纹"}
                    </button>
                  )}
                </>
              )}
            </article>

            <article className="card wide">
              <h3>建立会话</h3>
              <form className="host-form connect-form" onSubmit={handleConnect}>
                <label>
                  用户名
                  <input
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    placeholder={selected.default_username || "root"}
                  />
                </label>
                <div className="segmented">
                  <button
                    type="button"
                    className={authMode === "password" ? "seg active" : "seg"}
                    onClick={() => setAuthMode("password")}
                  >
                    密码
                  </button>
                  <button
                    type="button"
                    className={authMode === "key-file" ? "seg active" : "seg"}
                    onClick={() => setAuthMode("key-file")}
                  >
                    私钥文件
                  </button>
                  <button
                    type="button"
                    className={authMode === "key-pem" ? "seg active" : "seg"}
                    onClick={() => setAuthMode("key-pem")}
                  >
                    粘贴私钥
                  </button>
                </div>

                {authMode === "password" ? (
                  <>
                    <label>
                      密码
                      <input
                        type="password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        placeholder={savedPassword ? "已保存密码，留空直接连接" : "只用于本次连接"}
                        autoComplete="off"
                      />
                    </label>
                    <label className="confirm">
                      <input
                        type="checkbox"
                        checked={remember}
                        onChange={(event) => setRemember(event.target.checked)}
                      />
                      记住密码（AES-256-GCM 加密保存在本地数据库）
                    </label>
                    {savedPassword && (
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => void handleClearPassword()}
                      >
                        清除已保存的密码
                      </button>
                    )}
                  </>
                ) : authMode === "key-file" ? (
                  <div className="field">
                    <span>私钥路径</span>
                    <div className="combo-row">
                      <input
                        value={keyPath}
                        onChange={(event) => setKeyPath(event.target.value)}
                        placeholder="/Users/you/.ssh/id_ed25519"
                      />
                      <button
                        type="button"
                        className="combo-toggle"
                        onClick={() => void handleChooseKeyFile()}
                      >
                        选择文件
                      </button>
                    </div>
                    <label className="confirm">
                      <input
                        type="checkbox"
                        checked={rememberKey}
                        onChange={(event) => setRememberKey(event.target.checked)}
                      />
                      连接成功后也保存路径与口令
                    </label>
                  </div>
                ) : (
                  <>
                    <label>
                      私钥内容
                      <textarea
                        rows={4}
                        value={keyPem}
                        onChange={(event) => setKeyPem(event.target.value)}
                        placeholder={
                          keyAuth?.has_private_key
                            ? "已保存私钥，留空直接连接；粘贴新私钥可覆盖"
                            : "-----BEGIN OPENSSH PRIVATE KEY-----"
                        }
                      />
                    </label>
                    <label className="confirm">
                      <input
                        type="checkbox"
                        checked={rememberKey}
                        onChange={(event) => setRememberKey(event.target.checked)}
                      />
                      连接成功后也保存私钥与口令
                    </label>
                  </>
                )}

                {authMode !== "password" && (
                  <label>
                    私钥口令（可选）
                    <input
                      type="password"
                      value={passphrase}
                      onChange={(event) => setPassphrase(event.target.value)}
                      placeholder={keyAuth?.has_passphrase ? "已保存口令，可留空" : undefined}
                      autoComplete="off"
                    />
                  </label>
                )}

                {authMode === "key-file" && (
                  <button
                    type="button"
                    className="secondary"
                    disabled={!keyPath.trim()}
                    onClick={() => void handleSaveKeyFile()}
                  >
                    保存路径与口令
                  </button>
                )}
                {authMode === "key-pem" && (
                  <button
                    type="button"
                    className="secondary"
                    disabled={!keyPem.trim()}
                    onClick={() => void handleSavePrivateKey()}
                  >
                    保存私钥与口令
                  </button>
                )}

                {authMode !== "password" && (keyAuth?.mode || keyAuth?.has_private_key) && (
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => void handleClearPrivateKey()}
                  >
                    清除已保存的私钥凭据
                  </button>
                )}

                <button type="submit" disabled={busy || !trusted}>
                  {busy ? "连接中…" : trusted ? "连接并打开终端" : "请先信任主机指纹"}
                </button>
                <p className="muted small">
                  密码与私钥可加密写入本地数据库（密钥在 secret.key）；路径/口令可点「保存」，下次留空自动加载。
                </p>
              </form>
            </article>

            {session && (
              <SessionAuditPanel
                sessionId={session.id}
                terminalBlocked={Boolean(
                  fullscreenBySession[session.id] ||
                    unsafePromptBySession[session.id] ||
                    Boolean(taskRunner.pendingStepId) ||
                    Boolean(
                      taskRunner.task?.steps.some((step) => step.status === "running")
                    )
                )}
              />
            )}
          </section>
        ) : (
          <HomeView
            hostCount={hosts.length}
            onSettings={() => setView("settings")}
            onHelp={() => setView("help")}
            onAbout={() => setView("about")}
          />
        )}
      </main>

      <BatchTaskPanel
        open={batchPanelOpen}
        hosts={hosts}
        connectedHostIds={connectedHostIds}
        tags={allTags}
        batch={batch}
        busy={batchBusy}
        error={batchError}
        onStart={(goal, hostIds, autoRun) => void handleStartBatch(goal, hostIds, autoRun)}
        onToggleAuto={handleBatchAutoToggle}
        onContinueCurrent={handleBatchContinueCurrent}
        onResume={handleBatchResume}
        onStop={handleBatchStop}
        onExport={() => void handleExportBatch()}
        onNew={handleBatchNew}
        onClose={() => setBatchPanelOpen(false)}
      />

      <TaskPanel
        open={taskPanelOpen}
        hostName={selected?.name ?? null}
        sessionId={taskSessionId}
        integrationEnabled={Boolean(taskSessionId && oscBySession[taskSessionId])}
        terminalFullscreen={Boolean(taskSessionId && fullscreenBySession[taskSessionId])}
        unsafePrompt={Boolean(taskSessionId && unsafePromptBySession[taskSessionId])}
        runner={taskRunner}
        onClose={() => {
          const runningBatchAuto = Boolean(
            batchRef.current &&
              batchRef.current.status === "running" &&
              batchRef.current.autoRun
          );
          if (!runningBatchAuto) taskRunner.setAutoRun(false);
          setTaskPanelOpen(false);
        }}
        onEnableIntegration={() => void handleEnableTaskIntegration()}
      />

      {modelPromptOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card">
            <h3>配置大模型</h3>
            <p className="muted small">
              自然语言生成命令需要模型。填写 Base URL、模型和 API Key；保存后回到终端按 Enter 重试。
            </p>
            <ModelConfigForm
              provider={provider}
              onProviderChange={setProvider}
              rememberKey={rememberModelKey}
              onRememberKeyChange={setRememberModelKey}
              saving={modelSaving}
              onSave={() => void handleSaveModel()}
              onCancel={() => setModelPromptOpen(false)}
            />
          </div>
        </div>
      )}

      {newSessionPicker && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card host-picker">
            <h3>选择要登录的主机</h3>
            {hosts.length === 0 ? (
              <p className="muted">还没有主机。先在左侧添加一台。</p>
            ) : (
              <ul className="host-picker-list">
                {groupedHosts.map(([group, list]) => (
                  <li key={group} className="host-picker-group">
                    <div className="host-picker-group-title">{group}</div>
                    {list.map((host) => (
                      <button
                        type="button"
                        key={host.id}
                        className="host-picker-item"
                        onClick={() => {
                          setNewSessionPicker(false);
                          void handleNewSession(host);
                        }}
                      >
                        <span className="host-picker-name">
                          {host.name}
                          {sessionCount(host.id) > 0 && (
                            <em>{sessionCount(host.id)} 个会话</em>
                          )}
                        </span>
                        <span className="host-picker-address">
                          {host.default_username ? `${host.default_username}@` : ""}
                          {host.hostname}:{host.port}
                        </span>
                      </button>
                    ))}
                  </li>
                ))}
              </ul>
            )}
            <div className="row">
              <button
                type="button"
                className="secondary"
                onClick={() => setNewSessionPicker(false)}
              >
                取消
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmState && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card">
            <p>{confirmState.message}</p>
            <div className="row">
              <button
                type="button"
                onClick={() => {
                  const action = confirmState.action;
                  setConfirmState(null);
                  action();
                }}
              >
                确认
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() => setConfirmState(null)}
              >
                取消
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
