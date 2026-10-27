import { decodeBase64 } from "./api";

/** 终端里收到的 OSC 133 / 1337 事件。只有命令边界和命令文本，不包含输出。 */
export type OscEvent =
  | { type: "prompt-start" }
  | { type: "prompt-end" }
  | { type: "command-start" }
  | { type: "command-end"; exitCode: number | null }
  | { type: "command"; command: string };

const ESC = 0x1b;
const BEL = 0x07;
const OSC = 0x5d;
const BACKSLASH = 0x5c;

function ascii(bytes: number[]): string {
  return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
}

function decodeCommand(encoded: string): string | null {
  try {
    return new TextDecoder("utf-8").decode(decodeBase64(encoded));
  } catch {
    return null;
  }
}

/**
 * 解析 shell integration 发出的 OSC 133 / 1337。
 *
 * - `OSC 133 ; A/B/C/D`：提示符开始/输入开始/命令开始/命令结束；
 * - `OSC 1337 ; ShellWarden ; cmd ; <base64>`：命令文本（脱敏在服务端做）。
 *
 * 序列可能跨多个 PTY 数据块，因此状态必须保存在闭包里。未知 OSC 原样忽略。
 */
export function createOsc133Parser(): (bytes: Uint8Array) => OscEvent[] {
  let state: "text" | "esc" | "osc" | "oscEsc" = "text";
  let payload: number[] = [];

  const dispatch = (): OscEvent | null => {
    const text = ascii(payload);
    if (text === "133;A") return { type: "prompt-start" };
    if (text === "133;B") return { type: "prompt-end" };
    if (text === "133;C" || text.startsWith("133;C;")) return { type: "command-start" };
    if (text.startsWith("133;D")) {
      const raw = text.split(";")[2];
      const exitCode = raw === undefined || raw === "" ? null : Number(raw);
      return {
        type: "command-end",
        exitCode: Number.isFinite(exitCode) ? exitCode : null,
      };
    }
    if (text.startsWith("1337;ShellWarden;cmd;")) {
      const command = decodeCommand(text.slice("1337;ShellWarden;cmd;".length));
      if (command !== null) return { type: "command", command };
    }
    return null;
  };

  return (bytes: Uint8Array): OscEvent[] => {
    const events: OscEvent[] = [];
    for (const byte of bytes) {
      switch (state) {
        case "text":
          if (byte === ESC) state = "esc";
          break;
        case "esc":
          if (byte === OSC) {
            payload = [];
            state = "osc";
          } else if (byte !== ESC) {
            state = "text";
          }
          break;
        case "osc":
          if (byte === BEL) {
            const event = dispatch();
            if (event) events.push(event);
            state = "text";
          } else if (byte === ESC) {
            state = "oscEsc";
          } else {
            payload.push(byte);
          }
          break;
        case "oscEsc":
          if (byte === BACKSLASH) {
            const event = dispatch();
            if (event) events.push(event);
            state = "text";
          } else if (byte === BEL) {
            payload.push(ESC);
            const event = dispatch();
            if (event) events.push(event);
            state = "text";
          } else {
            payload.push(ESC, byte);
            state = "osc";
          }
          break;
      }
    }
    return events;
  };
}
