import { useEffect, useMemo, useRef, useState } from "react";

interface GroupInputProps {
  value: string;
  groups: string[];
  onChange: (value: string) => void;
}

export function GroupInput({ value, groups, onChange }: GroupInputProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  const filtered = useMemo(() => {
    const query = value.trim().toLowerCase();
    return groups.filter((group) => !query || group.toLowerCase().includes(query));
  }, [groups, value]);

  return (
    <div className="combo" ref={rootRef}>
      <div className="combo-row">
        <input
          value={value}
          onChange={(event) => {
            onChange(event.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          placeholder="选择已有目录或输入新目录"
        />
        <button
          type="button"
          className="combo-toggle"
          aria-label="选择目录"
          onClick={() => setOpen((current) => !current)}
        >
          ▾
        </button>
      </div>
      {open && (
        <div className="combo-menu">
          {filtered.length === 0 ? (
            <div className="combo-empty">没有匹配目录，可直接输入新目录</div>
          ) : (
            filtered.map((group) => (
              <button
                key={group}
                type="button"
                className="combo-option"
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => {
                  onChange(group);
                  setOpen(false);
                }}
              >
                {group}
              </button>
            ))
          )}
          {value.trim() && (
            <button
              type="button"
              className="combo-option muted"
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => {
                onChange("");
                setOpen(false);
              }}
            >
              移到「未分组」
            </button>
          )}
        </div>
      )}
    </div>
  );
}

interface TagsInputProps {
  value: string;
  suggestions: string[];
  onChange: (value: string) => void;
}

function parseTags(value: string): string[] {
  return value
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
    .filter((tag, index, all) => all.indexOf(tag) === index);
}

export function TagsInput({ value, suggestions, onChange }: TagsInputProps) {
  const tags = parseTags(value);
  const [draft, setDraft] = useState("");
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  const add = (raw: string) => {
    const tag = raw.trim();
    if (!tag || tags.includes(tag)) {
      setDraft("");
      return;
    }
    onChange([...tags, tag].join(", "));
    setDraft("");
  };

  const filtered = suggestions.filter(
    (tag) =>
      !tags.includes(tag) &&
      (!draft.trim() || tag.toLowerCase().includes(draft.trim().toLowerCase()))
  );

  return (
    <div className="tag-input" ref={rootRef}>
      {tags.length > 0 && (
        <div className="tag-chips">
          {tags.map((tag) => (
            <button
              key={tag}
              type="button"
              className="tag-chip"
              title={`移除 ${tag}`}
              onClick={() => onChange(tags.filter((item) => item !== tag).join(", "))}
            >
              {tag} ×
            </button>
          ))}
        </div>
      )}
      <div className="combo-row">
        <input
          value={draft}
          onChange={(event) => {
            setDraft(event.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === ",") {
              event.preventDefault();
              add(draft);
            }
            if (event.key === "Backspace" && !draft && tags.length > 0) {
              onChange(tags.slice(0, -1).join(", "));
            }
          }}
          placeholder="选择已有标签或输入新标签"
        />
        <button type="button" className="combo-toggle" onClick={() => add(draft)}>
          添加
        </button>
      </div>
      {open && filtered.length > 0 && (
        <div className="combo-menu">
          {filtered.map((tag) => (
            <button
              key={tag}
              type="button"
              className="combo-option"
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => {
                add(tag);
                setOpen(false);
              }}
            >
              {tag}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
