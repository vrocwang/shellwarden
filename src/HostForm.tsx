import type { FormEvent } from "react";
import { GroupInput, TagsInput } from "./HostFields";

export interface HostFormState {
  name: string;
  hostname: string;
  port: string;
  username: string;
  tags: string;
  groupName: string;
}

export const EMPTY_HOST_FORM: HostFormState = {
  name: "",
  hostname: "",
  port: "22",
  username: "",
  tags: "",
  groupName: ""
};

interface Props {
  mode: "add" | "edit";
  value: HostFormState;
  onChange: (value: HostFormState) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  saving: boolean;
  groups: string[];
  tags: string[];
  disabled?: boolean;
  onCancel?: () => void;
}

export function HostForm({
  mode,
  value,
  onChange,
  onSubmit,
  saving,
  groups,
  tags,
  disabled,
  onCancel
}: Props) {
  const set = <K extends keyof HostFormState>(key: K, next: HostFormState[K]) =>
    onChange({ ...value, [key]: next });

  return (
    <form className="host-form" onSubmit={onSubmit}>
      <label>
        显示名
        <input
          value={value.name}
          onChange={(event) => set("name", event.target.value)}
          placeholder="prod-web-01"
          required
        />
      </label>
      <label>
        地址
        <input
          value={value.hostname}
          onChange={(event) => set("hostname", event.target.value)}
          placeholder="10.0.0.11"
          required
        />
      </label>
      <div className="row">
        <label>
          端口
          <input
            type="number"
            min={1}
            max={65535}
            value={value.port}
            onChange={(event) => set("port", event.target.value)}
          />
        </label>
        <label>
          用户
          <input
            value={value.username}
            onChange={(event) => set("username", event.target.value)}
            placeholder="ops"
          />
        </label>
      </div>
      <div className="field">
        <span>标签</span>
        <TagsInput
          value={value.tags}
          suggestions={tags}
          onChange={(next) => set("tags", next)}
        />
      </div>
      <div className="field">
        <span>目录</span>
        <GroupInput
          value={value.groupName}
          groups={groups}
          onChange={(next) => set("groupName", next)}
        />
      </div>
      <div className="row">
        <button type="submit" disabled={saving || disabled}>
          {saving ? "保存中…" : mode === "add" ? "保存主机" : "保存"}
        </button>
        {onCancel && (
          <button type="button" className="secondary" onClick={onCancel}>
            取消
          </button>
        )}
      </div>
    </form>
  );
}
