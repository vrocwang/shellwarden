import type { ProviderConfig } from "./api";

interface Props {
  provider: ProviderConfig;
  onProviderChange: (provider: ProviderConfig) => void;
  rememberKey: boolean;
  onRememberKeyChange: (value: boolean) => void;
  saving: boolean;
  onSave: () => void;
  onClearKey?: () => void;
  onCancel?: () => void;
  submitLabel?: string;
}

export function ModelConfigForm({
  provider,
  onProviderChange,
  rememberKey,
  onRememberKeyChange,
  saving,
  onSave,
  onClearKey,
  onCancel,
  submitLabel = "保存配置"
}: Props) {
  return (
    <div className="host-form">
      <label>
        Base URL
        <input
          value={provider.baseUrl}
          onChange={(event) =>
            onProviderChange({ ...provider, baseUrl: event.target.value })
          }
        />
      </label>
      <label>
        模型
        <input
          value={provider.model}
          onChange={(event) => onProviderChange({ ...provider, model: event.target.value })}
        />
      </label>
      <label>
        API Key（留空则沿用已保存的密钥）
        <input
          type="password"
          value={provider.apiKey}
          onChange={(event) =>
            onProviderChange({ ...provider, apiKey: event.target.value })
          }
          placeholder={provider.hasKey ? "已保存密钥，留空沿用" : "输入 API Key"}
          autoComplete="off"
        />
      </label>
      <label className="confirm">
        <input
          type="checkbox"
          checked={rememberKey}
          onChange={(event) => onRememberKeyChange(event.target.checked)}
        />
        保存密钥（AES-256-GCM 加密，明文不回传前端）
      </label>
      <div className="row">
        <button type="button" onClick={onSave} disabled={saving}>
          {saving ? "保存中…" : submitLabel}
        </button>
        {provider.hasKey && onClearKey && (
          <button type="button" className="ghost" onClick={onClearKey}>
            清除密钥
          </button>
        )}
        {onCancel && (
          <button type="button" className="secondary" onClick={onCancel}>
            取消
          </button>
        )}
      </div>
    </div>
  );
}
