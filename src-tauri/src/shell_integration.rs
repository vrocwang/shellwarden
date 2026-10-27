//! 终端命令审计所需的 OSC 133 shell integration。
//!
//! 只对 bash/zsh 生效；由用户显式在一个会话里启用，绝不自动注入未知 shell。

pub const SCRIPT: &str = include_str!("../../scripts/shellwarden-integration.sh");

/// heredoc 终止符；不得出现在脚本正文里（有测试约束）。
pub const INSTALL_EOF: &str = "__SHELLWARDEN_INTEGRATION_EOF__";

/// 第一步：清掉当前输入行并关闭远端输入回显。
/// 调用方需要等 shell 执行完这一行，再发送 [`install_body`]，否则 heredoc
/// 内容仍会被 PTY 在 `stty -echo` 生效前回显出来。
pub fn install_prelude() -> Vec<u8> {
    b"\x15stty -echo\r".to_vec()
}

/// 第二步：用 heredoc 把脚本写到远端临时文件并 source，最后恢复 echo。
///
/// 不再使用单行 base64 eval：1.5KB 的单行在 macOS 等 PTY 的 `MAX_CANON`
/// （常见 1024）下可能被截断，而且会被 shell 整行回显。
pub fn install_body() -> Vec<u8> {
    let mut out = String::with_capacity(SCRIPT.len() + 256);
    out.push_str("__sw_int=\"$(mktemp \"${TMPDIR:-/tmp}/.shellwarden-int.XXXXXX\")\"\r");
    out.push_str(&format!("cat > \"$__sw_int\" <<'{INSTALL_EOF}'\r"));
    out.push_str(SCRIPT);
    if !SCRIPT.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(INSTALL_EOF);
    out.push_str("\r. \"$__sw_int\"\r");
    out.push_str("rm -f \"$__sw_int\"\r");
    out.push_str("stty echo\r");
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_sequence_hides_echo_and_contains_script() {
        let prelude = install_prelude();
        assert!(prelude.starts_with(b"\x15stty -echo"));

        let body = String::from_utf8(install_body()).unwrap();
        assert!(body.contains(SCRIPT.trim_end()));
        assert!(body.contains(&format!("<<'{INSTALL_EOF}'")));
        assert!(body.contains("mktemp"));
        assert!(body.contains("\r. \"$__sw_int\"\r"));
        assert!(body.trim_end().ends_with("stty echo"));
        // 终止符不能出现在脚本正文里，否则 heredoc 会提前结束。
        assert!(!SCRIPT.contains(INSTALL_EOF));
    }
}
